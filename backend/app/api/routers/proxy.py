"""PEP 503-compatible transparent PyPI proxy gateway.

This turns Warden into an active, inline Software Supply-Chain Firewall.
Developers and CI runners can point pip directly at Warden:

    pip install --index-url http://warden:8000/api/v1/proxy/pypi/simple/ requests==2.32.3

Or in pip.conf / environment variables:
    PIP_INDEX_URL=http://warden:8000/api/v1/proxy/pypi/simple/

Endpoints:
- GET /proxy/pypi/simple/             - Package index listing (proxied or cached)
- GET /proxy/pypi/simple/{project}/   - Release file listing (HTML/JSON, with rewritten download URLs)
- GET /proxy/pypi/packages/{project}/{filename} - Artifact download intercepted & gated by Warden policy
"""

from __future__ import annotations

import json
import re
from urllib.parse import quote, unquote, urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse
from packaging.utils import canonicalize_name, parse_sdist_filename, parse_wheel_filename
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.acquisition.pypi import validate_name
from app.analysis.analyzers.base import ScanOptions
from app.analysis.orchestrator import AnalysisResult, Orchestrator
from app.core.config import settings
from app.core.http import SafeHttpClient
from app.core.logging import get_logger
from app.db.models import DEFAULT_ENVIRONMENT, Policy, Scan
from app.db.session import get_db
from app.policy.engine import evaluate
from app.policy.exceptions import load_active_exceptions

log = get_logger("warden.proxy")
router = APIRouter(prefix="/proxy/pypi", tags=["proxy"])
_orchestrator = Orchestrator()

# Safe regex for extracting (name, version) from filename if packaging utils cannot parse
_FALLBACK_FILE_RE = re.compile(
    r"^([A-Za-z0-9_.-]+?)-([0-9][A-Za-z0-9.+!_*-]*)(?:\.tar\.gz|\.zip|-.*\.whl)$",
    re.IGNORECASE,
)


def _parse_pkg_filename(filename: str) -> tuple[str, str | None]:
    """Extract canonical package name and version from wheel or sdist filename."""
    try:
        if filename.endswith(".whl"):
            name, ver, _, _ = parse_wheel_filename(filename)
            return canonicalize_name(name), str(ver)
        if filename.endswith((".tar.gz", ".zip", ".tar.bz2")):
            name, ver = parse_sdist_filename(filename)
            return canonicalize_name(name), str(ver)
    except Exception:  # nosec B110 - fall back to regex on unparseable wheel/sdist name
        pass

    m = _FALLBACK_FILE_RE.match(filename)
    if m:
        return canonicalize_name(m.group(1)), m.group(2)
    return canonicalize_name(filename.split("-")[0]), None


def _get_active_policy(db: Session, environment: str = DEFAULT_ENVIRONMENT) -> Policy | None:
    policy = db.scalar(select(Policy).where(Policy.is_active.is_(True), Policy.environment == environment))
    if policy is None and environment != DEFAULT_ENVIRONMENT:
        policy = db.scalar(
            select(Policy).where(Policy.is_active.is_(True), Policy.environment == DEFAULT_ENVIRONMENT)
        )
    return policy


@router.get("/simple/", response_class=HTMLResponse)
def pypi_simple_root(request: Request) -> Response:
    """PEP 503 root repository index."""
    html_content = (
        "<!DOCTYPE html>\n<html><head><title>Warden PyPI Firewall Index</title></head>\n"
        "<body><h1>Warden Software Supply-Chain Firewall</h1>\n"
        "<p>PEP 503 repository proxy. Query /simple/&lt;package&gt;/ to inspect and resolve packages.</p>\n"
        "</body></html>"
    )
    return HTMLResponse(content=html_content, status_code=200)


@router.get("/simple/{project}/")
def pypi_simple_project(
    project: str,
    request: Request,
    mode: str = Query("audit", description="Firewall mode: 'enforce' or 'audit' (default: allow/audit)"),
    environment: str = Query(DEFAULT_ENVIRONMENT, description="Target policy environment"),
) -> Response:
    """PEP 503 project package page.

    Fetches upstream metadata from PyPI simple index and rewrites artifact download links
    to pass through Warden's inspection firewall gateway.
    """
    clean_name = validate_name(project)
    canonical = canonicalize_name(clean_name)
    upstream_url = f"{settings.PYPI_SIMPLE_BASE.rstrip('/')}/{canonical}/"

    # Request upstream simple index
    headers = {"User-Agent": "Warden-Firewall-Proxy/1.0", "Accept": "application/vnd.pypi.simple.v1+json, text/html"}
    client = SafeHttpClient(
        name="proxy.simple",
        allowed_hosts=settings.REGISTRY_HOST_ALLOWLIST,
        max_response_bytes=10 * 1024 * 1024,
        timeout=15.0,
    )
    try:
        res = client.request("GET", upstream_url, headers=headers)
    except Exception as exc:
        log.warning("proxy_upstream_failed", project=canonical, error=str(exc))
        raise HTTPException(status_code=502, detail=f"Failed to query upstream PyPI for {canonical}") from exc
    finally:
        client.close()

    if res.status == 404:
        raise HTTPException(status_code=404, detail=f"Package '{canonical}' not found on PyPI")
    if res.status != 200:
        raise HTTPException(status_code=res.status, detail=f"Upstream returned HTTP {res.status}")

    content_type = res.headers.get("content-type", "")

    # Base proxy URL for package downloads
    base_proxy_url = str(request.base_url).rstrip("/") + "/api/v1/proxy/pypi/packages"

    # If upstream returned PEP 691 JSON:
    if "json" in content_type:
        try:
            data = res.json()
            if isinstance(data, dict) and "files" in data:
                for file_entry in data["files"]:
                    orig_url = file_entry.get("url", "")
                    filename = file_entry.get("filename", "")
                    if orig_url and filename:
                        encoded_orig = quote(orig_url, safe="")
                        file_entry["url"] = (
                            f"{base_proxy_url}/{canonical}/{filename}"
                            f"?remote_url={encoded_orig}&mode={mode}&environment={environment}"
                        )
                return Response(
                    content=json.dumps(data).encode("utf-8"),
                    media_type="application/vnd.pypi.simple.v1+json",
                    headers={"X-Warden-Firewall": "active"},
                )
        except Exception:  # nosec B110 - fallback to HTML handling if JSON fails
            pass  # Fallback to HTML handling

    # HTML parsing & link rewriting
    html_text = res.text
    # Rewrite href="https://files.pythonhosted.org/packages/.../filename.whl#sha256=..."
    def _rewrite_link(match: re.Match) -> str:
        orig_url = match.group(1)
        # Extract filename from url
        fname = orig_url.split("#")[0].split("/")[-1]
        encoded_orig = quote(orig_url, safe="")
        proxied = (
            f"{base_proxy_url}/{canonical}/{fname}?"
            f"remote_url={encoded_orig}&mode={mode}&environment={environment}"
        )
        return f'href="{proxied}"'

    rewritten_html = re.sub(r'href=["\'](https?://[^"\']+)["\']', _rewrite_link, html_text)

    return HTMLResponse(
        content=rewritten_html,
        status_code=200,
        headers={"Content-Type": "text/html; charset=utf-8", "X-Warden-Firewall": "active"},
    )


@router.get("/packages/{project}/{filename}")
def pypi_download_package(
    project: str,
    filename: str,
    request: Request,
    remote_url: str = Query(..., description="Upstream download URL from PyPI"),
    mode: str = Query("audit", description="Enforce (block downloads) or audit (warn but allow)"),
    environment: str = Query(DEFAULT_ENVIRONMENT, description="Target environment policy"),
    db: Session = Depends(get_db),
) -> Response:
    """Intercept package artifact download, scan against security policy, and gate execution.

    If mode=='enforce' and the package violates policy (decision=='block'), returns HTTP 403.
    If mode=='audit' (default) or decision in ('allow', 'warn'), streams artifact safely.
    """
    clean_name = validate_name(project)
    canonical = canonicalize_name(clean_name)
    file_name, version = _parse_pkg_filename(filename)

    unquoted_remote = unquote(remote_url)
    parsed = urlsplit(unquoted_remote)

    # Strictly validate upstream URL to eliminate SSRF
    allowed_artifact_hosts = set(settings.ARTIFACT_HOST_ALLOWLIST) | {"files.pythonhosted.org"}
    if parsed.scheme != "https":
        raise HTTPException(status_code=400, detail="Only HTTPS upstream artifact URLs are allowed")

    host = (parsed.hostname or "").lower()
    if not host or host not in allowed_artifact_hosts:
        raise HTTPException(status_code=403, detail="Artifact host is not permitted by proxy policy")

    clean_path = parsed.path
    if not clean_path.startswith("/packages/") or not clean_path.endswith(f"/{filename}"):
        raise HTTPException(status_code=400, detail="Invalid PyPI artifact path format")

    target_url = f"https://{host}{clean_path}"

    decision_value = "allow"
    risk_score = 0
    reasons_list: list[str] = []

    if version:
        try:
            # 1. Check existing scan verdict in DB first
            existing_scan = db.scalar(
                select(Scan)
                .where(
                    Scan.package_name == canonical,
                    Scan.version == version,
                    Scan.environment == environment,
                )
                .order_by(Scan.created_at.desc())
                .limit(1)
            )

            if existing_scan:
                decision_value = existing_scan.decision.value
                risk_score = existing_scan.risk_score
                reasons_list = [
                    r.get("detail", str(r.get("rule", "")))
                    for r in (existing_scan.policy_reasons or [])
                    if isinstance(r, dict) and r.get("effect") == "block"
                ]
            else:
                # 2. Synchronous fast-path analysis via Orchestrator
                options = ScanOptions(environment=environment)
                result: AnalysisResult = _orchestrator.analyze("pypi", canonical, version, options=options)
                active_policy = _get_active_policy(db, environment)
                exceptions = load_active_exceptions(db, canonical, environment=environment)
                policy_dec = evaluate(result, active_policy, exceptions=exceptions, environment=environment)

                decision_value = policy_dec.decision.value
                risk_score = result.risk_score
                reasons_list = [
                    r.detail
                    for r in policy_dec.reasons
                    if getattr(r, "effect", "") == "block"
                ]
        except Exception as exc:
            log.warning("proxy_scan_failed", project=canonical, version=version, error=str(exc))
            # By default allow if scan fails to avoid breaking developer builds unexpectedly
            decision_value = "warn"
            reasons_list.append(f"Analysis incomplete: {type(exc).__name__}")

    # Enforce or Audit
    is_blocked = decision_value == "block"
    effective_mode = request.headers.get("X-Warden-Mode", mode).lower()

    if is_blocked and effective_mode == "enforce":
        log.warning("proxy_artifact_blocked", project=canonical, version=version, reasons=reasons_list)
        bullet_reasons = "\n".join(f"  • {r}" for r in reasons_list) or "  • Policy threshold exceeded"
        body = (
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f" [WARDEN SOFTWARE SUPPLY-CHAIN FIREWALL] ARTIFACT BLOCKED\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f" Package:   {canonical}=={version or 'unknown'}\n"
            f" File:      {filename}\n"
            f" Decision:  BLOCKED (Risk Score: {risk_score}/100)\n"
            f" Environment: {environment}\n\n"
            f" Violations:\n{bullet_reasons}\n\n"
            f" To request a time-boxed security exception, consult your security admin.\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        )
        return Response(
            content=body,
            status_code=403,
            media_type="text/plain",
            headers={
                "X-Warden-Decision": "BLOCK",
                "X-Warden-Risk-Score": str(risk_score),
                "X-Warden-Reason": reasons_list[0] if reasons_list else "Policy Block",
            },
        )

    # Safe retrieval of artifact from PyPI via SafeHttpClient with strict host and size bounds
    client = SafeHttpClient(
        name="proxy.artifact",
        allowed_hosts=frozenset(allowed_artifact_hosts),
        max_response_bytes=settings.MAX_DOWNLOAD_BYTES,
        timeout=60.0,
    )
    try:
        upstream_res = client.request("GET", target_url)
    except Exception as exc:
        log.warning("proxy_upstream_download_failed", error=str(exc), package=canonical)
        raise HTTPException(status_code=502, detail="Failed to fetch package from upstream") from exc
    finally:
        client.close()

    if upstream_res.status != 200:
        raise HTTPException(
            status_code=upstream_res.status,
            detail=f"Upstream returned HTTP {upstream_res.status}",
        )

    resp_headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "X-Warden-Decision": decision_value.upper(),
        "X-Warden-Risk-Score": str(risk_score),
        "X-Warden-Firewall": "allowed" if not is_blocked else "audited",
    }
    if is_blocked:
        resp_headers["X-Warden-Notice"] = "Package flagged as high risk (allowed under audit mode)"

    return Response(
        content=upstream_res.content,
        media_type="application/octet-stream",
        headers=resp_headers,
    )
