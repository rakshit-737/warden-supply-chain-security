"""npm package lifecycle script analyzer.

npm packages frequently abuse lifecycle hooks (`preinstall`, `install`, `postinstall`,
`prepack`, `prepare`) to run arbitrary code on developer and CI machines during `npm install`.
Notable historical incidents include `ua-parser-js`, `event-stream`, `flatmap-stream`,
`node-ipc`, and `colors`.

This analyzer parses `package.json` statically (never executing anything) and checks for:
- Remote script execution (`curl ... | sh`, `wget ... | bash`)
- Environment variable and token exfiltration (`process.env`, `$AWS_`, `$GITHUB_TOKEN`)
- Obfuscated payloads (base64 decoders, hex blobs, dynamic `eval`/`Function`)
- Reverse shell hooks (`/dev/tcp`, `nc -e`, `bash -i`)
- File system access to sensitive directories (`~/.ssh`, `~/.aws`, `/etc/passwd`)
"""

from __future__ import annotations

import json
import re
from typing import Any

from app.analysis.analyzers.base import BaseAnalyzer, PackageContext
from app.analysis.findings import Finding, Location, Severity
from app.analysis.signals import Category, Code
from app.core.logging import get_logger

log = get_logger("warden.analyzers.npm_scripts")

ANALYZER_NAME = "npm_scripts"
ANALYZER_VERSION = "1.0.0"

# Lifecycle hooks that execute automatically during package installation/preparation
LIFECYCLE_HOOKS = frozenset({
    "preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare",
})

# Suspicious script patterns
_CURL_PIPE_SH_RE = re.compile(r"(?:curl|wget)\s+[^|]+\|\s*(?:sh|bash|zsh|python|node)", re.IGNORECASE)
_REVERSE_SHELL_RE = re.compile(r"(?:/dev/tcp/|nc\s+-[el]|bash\s+-i|mkfifo\s+[^;]+;\s*cat)", re.IGNORECASE)
_ENV_HARVEST_RE = re.compile(
    r"(?:process\.env\.(?:AWS|GITHUB|NPM|TOKEN|SECRET|KEY|PASSWORD|AUTH)|"
    r"\$(?:AWS_SECRET|GITHUB_TOKEN|NPM_TOKEN|SSH_KEY|ENV)|"
    r"~/\.ssh|~/\.aws|/etc/passwd)",
    re.IGNORECASE,
)
_OBFUSCATION_RE = re.compile(
    r"(?:eval\s*\(|new\s+Function\s*\(|Buffer\.from\s*\([^,]+,\s*['\"](?:base64|hex)['\"]\)|\\x[0-9a-f]{2}|\\u[0-9a-f]{4})",
    re.IGNORECASE,
)
_NETWORK_FETCH_RE = re.compile(r"(?:https?://|ftp://|wss?://)", re.IGNORECASE)
_NODE_EVAL_RE = re.compile(r"node\s+(?:-e|--eval)\s+['\"]", re.IGNORECASE)


class NpmScriptsAnalyzer(BaseAnalyzer):
    name = ANALYZER_NAME
    version = ANALYZER_VERSION

    def analyze(self, context: PackageContext) -> list[Finding]:
        findings: list[Finding] = []

        # Find any package.json among files
        pkg_json_files = [f for f in context.files if f.relpath.split("/")[-1].lower() == "package.json"]
        if not pkg_json_files:
            return findings

        for source_file in pkg_json_files:
            try:
                data = json.loads(source_file.text)
            except Exception:
                continue

            if not isinstance(data, dict):
                continue

            scripts = data.get("scripts")
            if not isinstance(scripts, dict):
                continue

            for hook_name, script_content in scripts.items():
                if not isinstance(script_content, str) or not script_content.strip():
                    continue

                is_lifecycle = hook_name.lower() in LIFECYCLE_HOOKS
                cmd = script_content.strip()

                # 1. Critical: curl | sh or reverse shell in lifecycle hook
                if _CURL_PIPE_SH_RE.search(cmd):
                    findings.append(
                        Finding(
                            code=Code.NPM_CURL_PIPE_SHELL,
                            severity=Severity.critical,
                            weight=12.0,
                            confidence=0.95,
                            message=f"Lifecycle script '{hook_name}' pipes remote download to shell: {cmd[:120]}",
                            evidence={"hook": hook_name, "command": cmd[:250]},
                            category=Category.MALICIOUS_BEHAVIOR.value,
                            location=Location(file=source_file.relpath),
                            cwe=["CWE-494"],
                            attack=["T1105", "T1059.004"],
                        )
                    )
                    continue

                if _REVERSE_SHELL_RE.search(cmd):
                    findings.append(
                        Finding(
                            code=Code.NPM_CURL_PIPE_SHELL,
                            severity=Severity.critical,
                            weight=12.0,
                            confidence=0.95,
                            message=f"Lifecycle script '{hook_name}' contains reverse shell pattern",
                            evidence={"hook": hook_name, "command": cmd[:250]},
                            category=Category.MALICIOUS_BEHAVIOR.value,
                            location=Location(file=source_file.relpath),
                            cwe=["CWE-506"],
                            attack=["T1059.004"],
                        )
                    )
                    continue

                # 2. Credential/Environment Harvesting
                if _ENV_HARVEST_RE.search(cmd):
                    findings.append(
                        Finding(
                            code=Code.NPM_ENV_HARVEST,
                            severity=Severity.high,
                            weight=8.0,
                            confidence=0.85,
                            message=f"Lifecycle script '{hook_name}' accesses sensitive credentials or environment keys",
                            evidence={"hook": hook_name, "command": cmd[:250]},
                            category=Category.CREDENTIAL_ACCESS.value,
                            location=Location(file=source_file.relpath),
                            cwe=["CWE-526"],
                            attack=["T1552"],
                        )
                    )

                # 3. Obfuscation / Dynamic Code Evaluation
                if _OBFUSCATION_RE.search(cmd):
                    findings.append(
                        Finding(
                            code=Code.NPM_SUSPICIOUS_SCRIPT,
                            severity=Severity.high,
                            weight=7.0,
                            confidence=0.85,
                            message=f"Lifecycle script '{hook_name}' uses dynamic evaluation or encoded payload",
                            evidence={"hook": hook_name, "command": cmd[:250]},
                            category=Category.OBFUSCATION.value,
                            location=Location(file=source_file.relpath),
                            cwe=["CWE-1027"],
                            attack=["T1027"],
                        )
                    )

                # 4. General Active Lifecycle Script
                if is_lifecycle:
                    # Native build commands like node-gyp rebuild are common, but worth noting
                    is_native_build = bool(re.search(r"\b(?:node-gyp|prebuild-install|cmake-js)\b", cmd, re.IGNORECASE))
                    sev = Severity.medium if is_native_build else Severity.high
                    weight = 3.0 if is_native_build else 6.0
                    conf = 0.5 if is_native_build else 0.75

                    findings.append(
                        Finding(
                            code=Code.NPM_INSTALL_SCRIPT,
                            severity=sev,
                            weight=weight,
                            confidence=conf,
                            message=f"Active lifecycle script '{hook_name}' runs during npm install: {cmd[:120]}",
                            evidence={"hook": hook_name, "command": cmd[:250], "native_build": is_native_build},
                            category=Category.INSTALL_TIME.value,
                            location=Location(file=source_file.relpath),
                            cwe=["CWE-506"],
                            attack=["T1059.004"],
                        )
                    )

        return findings
