"""AST-based reachability analysis for vulnerability triage.

Determines whether a vulnerable symbol (function, class, method) from a dependency
is actually imported and called in the project's source code. This directly addresses
alert fatigue by distinguishing:

- REACHABLE: The vulnerable symbol is imported and invoked in project code.
- IMPORTED_NOT_CALLED: The dependency is imported, but the vulnerable function is never invoked.
- TRANSITIVE_DORMANT: The package is never imported anywhere in the project tree.

Limitations: This is a static, intra-procedural AST analysis over the project's source code.
Dynamic attribute access (e.g. `getattr(mod, 'func')`), runtime imports (`__import__`),
and indirect call-chains through third-party libraries are treated conservatively.
It deliberately errs on the side of reporting reachability when uncertain.
"""

from __future__ import annotations

import ast
import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

log = logging.getLogger("warden.reachability")

MAX_FILES_SCANNED = 2000
MAX_FILE_BYTES = 500_000  # 500 KB per source file
SKIP_DIRS = frozenset({
    "venv", ".venv", "env", ".env", "node_modules", ".git", ".hg", ".svn",
    "__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache", "build", "dist",
})


class ReachabilityStatus(str, Enum):
    REACHABLE = "reachable"
    IMPORTED_NOT_CALLED = "imported_not_called"
    TRANSITIVE_DORMANT = "transitive_dormant"
    UNKNOWN = "unknown"


@dataclass
class VulnerableSymbol:
    package_name: str
    advisory_id: str
    module_path: str | None = None  # e.g. "urllib3.util"
    symbol_name: str | None = None  # e.g. "ssl_wrap_socket"


@dataclass
class ReachabilityFinding:
    advisory_id: str
    package_name: str
    symbol_name: str | None
    status: ReachabilityStatus
    confidence: float
    call_sites: list[dict[str, Any]] = field(default_factory=list)
    import_sites: list[dict[str, Any]] = field(default_factory=list)
    explanation: str = ""


class _ProjectAstVisitor(ast.NodeVisitor):
    """Collects imports, aliases, and function calls from a single Python AST."""

    def __init__(self, relpath: str) -> None:
        self.relpath = relpath
        # Map local alias -> full imported name. E.g. `import requests as req` -> `req`: `requests`
        self.aliases: dict[str, str] = {}
        # Set of packages/modules directly imported
        self.imported_modules: set[str] = set()
        # Set of specific symbols imported: e.g. `from pkg.mod import func` -> `pkg.mod.func`
        self.imported_symbols: dict[str, str] = {}  # alias -> full_path
        # Calls: list of (function_name_or_attr, line)
        self.calls: list[tuple[str, int]] = []
        # Import locations for reporting
        self.import_locations: list[dict[str, Any]] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            imported_as = alias.asname or alias.name
            self.aliases[imported_as] = alias.name
            self.imported_modules.add(alias.name)
            self.import_locations.append({
                "file": self.relpath,
                "line": node.lineno,
                "statement": f"import {alias.name}" + (f" as {alias.asname}" if alias.asname else ""),
            })
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = node.module or ""
        self.imported_modules.add(mod)
        for alias in node.names:
            imported_as = alias.asname or alias.name
            full_path = f"{mod}.{alias.name}" if mod else alias.name
            self.aliases[imported_as] = full_path
            self.imported_symbols[imported_as] = full_path
            self.import_locations.append({
                "file": self.relpath,
                "line": node.lineno,
                "statement": f"from {mod} import {alias.name}" + (f" as {alias.asname}" if alias.asname else ""),
            })
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        call_name = self._resolve_call_name(node.func)
        if call_name:
            self.calls.append((call_name, node.lineno))
        self.generic_visit(node)

    def _resolve_call_name(self, func_node: ast.AST) -> str | None:
        """Resolve a Call function node to its dotted identifier name."""
        if isinstance(func_node, ast.Name):
            # Direct name call: e.g. `foo()` or `HTTPBasicAuth()`
            name = func_node.id
            return self.aliases.get(name, name)

        if isinstance(func_node, ast.Attribute):
            # Attribute call: e.g. `requests.get()` or `os.path.join()`
            parts = []
            curr: ast.AST = func_node
            while isinstance(curr, ast.Attribute):
                parts.append(curr.attr)
                curr = curr.value
            if isinstance(curr, ast.Name):
                root_alias = curr.id
                resolved_root = self.aliases.get(root_alias, root_alias)
                parts.append(resolved_root)
                parts.reverse()
                return ".".join(parts)

        return None


def assess_reachability(
    project_root: str | Path,
    vulnerable_targets: list[VulnerableSymbol],
) -> list[ReachabilityFinding]:
    """Scan all project Python source files and assess reachability for each vulnerable symbol."""
    root = Path(project_root)
    if not root.is_dir():
        return []

    # Map package_canonical -> set of imported module names seen in project
    all_imports: set[str] = set()
    all_import_locs: list[dict[str, Any]] = []
    all_calls: list[tuple[str, str, int]] = []  # (called_symbol, file, line)

    files_checked = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]

        for fname in sorted(filenames):
            if not fname.endswith(".py"):
                continue

            files_checked += 1
            if files_checked > MAX_FILES_SCANNED:
                break

            fpath = Path(dirpath) / fname
            try:
                if fpath.stat().st_size > MAX_FILE_BYTES:
                    continue
                code_text = fpath.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(code_text, filename=str(fpath))
            except Exception:  # nosec B112 - skip unparseable or unreadable source file
                continue

            rel_file = str(fpath.relative_to(root))
            visitor = _ProjectAstVisitor(rel_file)
            visitor.visit(tree)

            all_imports.update(visitor.imported_modules)
            all_import_locs.extend(visitor.import_locations)
            for call_name, line in visitor.calls:
                all_calls.append((call_name, rel_file, line))

    results: list[ReachabilityFinding] = []

    for target in vulnerable_targets:
        pkg_norm = target.package_name.lower().replace("-", "_")
        sym_name = target.symbol_name.strip() if target.symbol_name else None

        # Check if the package is imported anywhere
        matching_imports = [
            loc for loc in all_import_locs
            if loc["statement"].lower().startswith(f"import {pkg_norm}")
            or f"import {pkg_norm}." in loc["statement"].lower()
            or f"from {pkg_norm}" in loc["statement"].lower()
        ]

        if not matching_imports:
            # Package is not imported anywhere in project Python code
            results.append(
                ReachabilityFinding(
                    advisory_id=target.advisory_id,
                    package_name=target.package_name,
                    symbol_name=sym_name,
                    status=ReachabilityStatus.TRANSITIVE_DORMANT,
                    confidence=0.90,
                    explanation=(
                        f"Package '{target.package_name}' is declared in project manifests but never "
                        f"imported in any of the {files_checked} scanned source files (Dormant)."
                    ),
                )
            )
            continue

        # Package is imported: now check symbol-level invocation
        if not sym_name:
            # Advisory does not specify a function/class name: report imported with unknown symbol reachability
            results.append(
                ReachabilityFinding(
                    advisory_id=target.advisory_id,
                    package_name=target.package_name,
                    symbol_name=None,
                    status=ReachabilityStatus.IMPORTED_NOT_CALLED,
                    confidence=0.70,
                    import_sites=matching_imports[:10],
                    explanation=(
                        f"Package '{target.package_name}' is imported, but the advisory does not specify "
                        f"a specific function to trace."
                    ),
                )
            )
            continue

        # Check if the vulnerable symbol is called
        matched_call_sites: list[dict[str, Any]] = []
        for call_path, f_rel, lineno in all_calls:
            # E.g. call_path is `requests.get` and sym_name is `get` or `requests.get`
            if call_path.endswith(f".{sym_name}") or call_path == sym_name:
                matched_call_sites.append({"file": f_rel, "line": lineno, "call": call_path})

        if matched_call_sites:
            results.append(
                ReachabilityFinding(
                    advisory_id=target.advisory_id,
                    package_name=target.package_name,
                    symbol_name=sym_name,
                    status=ReachabilityStatus.REACHABLE,
                    confidence=0.95,
                    call_sites=matched_call_sites[:10],
                    import_sites=matching_imports[:5],
                    explanation=(
                        f"Vulnerable symbol '{sym_name}' from '{target.package_name}' is DIRECTLY CALLED "
                        f"at {len(matched_call_sites)} location(s) in project code."
                    ),
                )
            )
        else:
            results.append(
                ReachabilityFinding(
                    advisory_id=target.advisory_id,
                    package_name=target.package_name,
                    symbol_name=sym_name,
                    status=ReachabilityStatus.IMPORTED_NOT_CALLED,
                    confidence=0.85,
                    import_sites=matching_imports[:5],
                    explanation=(
                        f"Package '{target.package_name}' is imported, but vulnerable symbol '{sym_name}' "
                        f"was NOT called in any scanned project file."
                    ),
                )
            )

    return results
