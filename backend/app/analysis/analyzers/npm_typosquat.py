"""npm typosquatting and name confusion analyzer.

Detects npm package names that imitate popular packages in the npm ecosystem:
- Scope confusion: e.g. `@malicious/react` or `@fake/express` mimicking core unscoped packages
- Damerau-Levenshtein distance 1 edits (transposition, single letter replacement, deletion)
- Homoglyph and leetspeak substitutions (`0->o`, `1->l`, `rn->m`)
- Combosquats: appending or prepending common affixes like `-js`, `-core`, `-secure`, `-sdk`
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from app.analysis.analyzers.base import BaseAnalyzer, PackageContext
from app.analysis.findings import Finding, Severity
from app.analysis.signals import Category, Code
from app.core.logging import get_logger

log = get_logger("warden.analyzers.npm_typosquat")

ANALYZER_NAME = "npm_typosquat"
ANALYZER_VERSION = "1.0.0"

_DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "popular_npm_packages.txt"

_COMMON_AFFIXES = (
    "-js", "js-", "-core", "node-", "-node", "-sdk", "-api", "-client",
    "-tool", "-tools", "-utils", "-util", "-lib", "-secure", "-new", "-official",
)


@lru_cache(maxsize=1)
def load_popular_npm_packages() -> list[str]:
    """Load bundled popular npm package names."""
    if not _DATA_FILE.is_file():
        return []
    lines: list[str] = []
    with open(_DATA_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip().lower()
            if line and not line.startswith("#"):
                lines.append(line)
    return lines


def _levenshtein(s1: str, s2: str) -> int:
    """Compute standard Levenshtein edit distance."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            ins = prev[j + 1] + 1
            delete = curr[j] + 1
            sub = prev[j] + (c1 != c2)
            curr.append(min(ins, delete, sub))
        prev = curr
    return prev[-1]


def _fold_homoglyphs(name: str) -> str:
    """Fold common visual confusables."""
    s = name.lower()
    return (
        s.replace("0", "o")
        .replace("1", "l")
        .replace("rn", "m")
        .replace("vv", "w")
        .replace("3", "e")
        .replace("4", "a")
        .replace("5", "s")
    )


class NpmTyposquatAnalyzer(BaseAnalyzer):
    name = ANALYZER_NAME
    version = ANALYZER_VERSION

    def analyze(self, context: PackageContext) -> list[Finding]:
        findings: list[Finding] = []

        # Only run if context ecosystem is npm or if a package.json is present
        is_npm = context.ecosystem.lower() in ("npm", "javascript", "node")
        has_pkg_json = any(f.relpath.split("/")[-1].lower() == "package.json" for f in context.files)
        if not is_npm and not has_pkg_json:
            return findings

        popular = load_popular_npm_packages()
        if not popular:
            return findings

        candidate = context.name.lower().strip()
        popular_set = set(popular)

        # If the candidate IS one of the popular packages, it is not a typosquat
        if candidate in popular_set:
            return findings

        # 1. Scope confusion check: e.g. `@attacker/react` or `@fake-scope/express`
        if candidate.startswith("@") and "/" in candidate:
            scope, _, unscoped = candidate.partition("/")
            if unscoped in popular_set:
                findings.append(
                    Finding(
                        code=Code.NPM_TYPOSQUAT,
                        severity=Severity.high,
                        weight=7.0,
                        confidence=0.85,
                        message=f"Scoped package '{candidate}' imitates popular unscoped npm package '{unscoped}'",
                        evidence={"kind": "scope_confusion", "target": unscoped, "scope": scope},
                        category=Category.TYPOSQUAT.value,
                        cwe=["CWE-1357"],
                        attack=["T1195.001"],
                    )
                )
                return findings

        # Strip scope for similarity checks
        base_candidate = candidate.split("/")[-1] if "/" in candidate else candidate
        if base_candidate in popular_set:
            return findings

        folded_candidate = _fold_homoglyphs(base_candidate)

        for rank, target in enumerate(popular, start=1):
            if base_candidate == target:
                continue

            target_base = target.split("/")[-1] if "/" in target else target

            # 2. Homoglyph resemblance: folded strings match
            if folded_candidate == _fold_homoglyphs(target_base):
                findings.append(
                    Finding(
                        code=Code.NPM_TYPOSQUAT,
                        severity=Severity.critical if rank <= 50 else Severity.high,
                        weight=9.0,
                        confidence=0.90,
                        message=(
                            f"npm package '{candidate}' uses homoglyph substitution "
                            f"targeting '{target}' (rank #{rank})"
                        ),
                        evidence={"kind": "homoglyph", "target": target, "rank": rank},
                        category=Category.TYPOSQUAT.value,
                        cwe=["CWE-1357"],
                        attack=["T1195.001"],
                    )
                )
                return findings

            # 3. Edit distance 1 (Levenshtein)
            if len(target_base) >= 4 and abs(len(base_candidate) - len(target_base)) <= 1:
                dist = _levenshtein(base_candidate, target_base)
                if dist == 1:
                    sev = Severity.critical if rank <= 30 else Severity.high
                    findings.append(
                        Finding(
                            code=Code.NPM_TYPOSQUAT,
                            severity=sev,
                            weight=8.0,
                            confidence=0.85,
                            message=(
                                f"npm package '{candidate}' differs by 1 character "
                                f"from popular '{target}' (rank #{rank})"
                            ),
                            evidence={"kind": "typo_d1", "target": target, "rank": rank, "distance": 1},
                            category=Category.TYPOSQUAT.value,
                            cwe=["CWE-1357"],
                            attack=["T1195.001"],
                        )
                    )
                    return findings

            # 4. Combosquats: target + common affix
            for affix in _COMMON_AFFIXES:
                if (
                    base_candidate == f"{target_base}{affix}"
                    or base_candidate == f"{affix}{target_base}"
                ):
                    findings.append(
                        Finding(
                            code=Code.NPM_TYPOSQUAT,
                            severity=Severity.medium,
                            weight=5.0,
                            confidence=0.75,
                            message=(
                                f"npm package '{candidate}' is a combosquat of "
                                f"popular '{target}' with affix '{affix}'"
                            ),
                            evidence={"kind": "combosquat", "target": target, "affix": affix, "rank": rank},
                            category=Category.TYPOSQUAT.value,
                            cwe=["CWE-1357"],
                            attack=["T1195.001"],
                        )
                    )
                    return findings

        return findings
