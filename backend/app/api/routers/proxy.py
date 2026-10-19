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

import hashlib
import hmac
import json
import re

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


def _parse_pkg_filename(filename: str) -> tuple[str, str | None]:
    """Extract canonical package name and version from wheel or sdist filename."""
    if len(filename) > 255:
        filename = filename[:255]
    try:
        if filename.endswith(".whl"):
            name, ver, _, _ = parse_wheel_filename(filename)
            return canonicalize_name(name), str(ver)
        if filename.endswith((".tar.gz", ".zip", ".tar.bz2")):
            name, ver = parse_sdist_filename(filename)
    # Fall back to string parsing on unparseable wheel/sdist name
    except Exception:  # nosec B110
        pass

    base = filename
    for ext in (".tar.gz", ".tar.bz2", ".zip", ".whl"):
        if base.endswith(ext):
            base = base[:-len(ext)]
            break
    parts = base.split("-")
    if len(parts) >= 2:
        return canonicalize_name(parts[0]), parts[1]
    return canonicalize_name(parts[0]), None


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
                    filename = file_entry.get("filename", "")
                    if filename:
                        file_entry["url"] = (
                            f"{base_proxy_url}/{canonical}/{filename}"
                            f"?mode={mode}&environment={environment}"
                        )
                return Response(
                    content=json.dumps(data).encode("utf-8"),
                    media_type="application/vnd.pypi.simple.v1+json",
                    headers={"X-Warden-Firewall": "active"},
                )
        # Fallback to HTML handling if JSON fails
        except Exception:  # nosec B110
            pass

    # HTML parsing & link rewriting
    html_text = res.text

    def _rewrite_link(match: re.Match) -> str:
        orig_url = match.group(1)
        fname = orig_url.split("#")[0].split("/")[-1]
        proxied = f"{base_proxy_url}/{canonical}/{fname}?mode={mode}&environment={environment}"
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

    # Query official PyPI registry JSON to resolve the verified artifact download URL
    meta_client = SafeHttpClient(
        name="proxy.metadata",
        allowed_hosts=settings.REGISTRY_HOST_ALLOWLIST,
        max_response_bytes=settings.MAX_METADATA_BYTES,
        timeout=15.0,
    )
    meta_url = f"{settings.PYPI_JSON_BASE.rstrip('/')}/{canonical}/json"
    try:
        meta_res = meta_client.request("GET", meta_url)
    except Exception as exc:
        log.warning("proxy_metadata_fetch_failed", package=canonical, error=str(exc))
        raise HTTPException(status_code=502, detail=f"Failed to query PyPI metadata for {canonical}") from exc
    finally:
        meta_client.close()

    if meta_res.status == 404:
        raise HTTPException(status_code=404, detail=f"Package '{canonical}' not found on PyPI")
    if meta_res.status != 200:
        raise HTTPException(status_code=meta_res.status, detail=f"PyPI returned HTTP {meta_res.status}")

    meta_data = meta_res.json()
    upstream_file_url: str | None = None
    expected_sha256: str | None = None

    releases = meta_data.get("releases", {})
    if isinstance(releases, dict):
        candidates: list[dict] = []
        if version and version in releases and isinstance(releases[version], list):
            candidates = [f for f in releases[version] if isinstance(f, dict)]
        else:
            candidates = [
                f for files in releases.values() if isinstance(files, list) for f in files if isinstance(f, dict)
            ]

        for item in candidates:
            if item.get("filename") == filename:
                upstream_file_url = item.get("url")
                digests = item.get("digests", {})
                if isinstance(digests, dict):
                    expected_sha256 = digests.get("sha256")
                break

    if not upstream_file_url:
        top_urls = meta_data.get("urls", [])
        if isinstance(top_urls, list):
            for item in top_urls:
                if isinstance(item, dict) and item.get("filename") == filename:
                    upstream_file_url = item.get("url")
                    digests = item.get("digests", {})
                    if isinstance(digests, dict):
                        expected_sha256 = digests.get("sha256")
                    break

    if not upstream_file_url:
        raise HTTPException(
            status_code=404,
            detail=f"Artifact '{filename}' not found for package '{canonical}' on PyPI",
        )

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
    allowed_artifact_hosts = frozenset(settings.ARTIFACT_HOST_ALLOWLIST) | {"files.pythonhosted.org"}
    download_client = SafeHttpClient(
        name="proxy.artifact",
        allowed_hosts=allowed_artifact_hosts,
        max_response_bytes=settings.MAX_DOWNLOAD_BYTES,
        timeout=60.0,
    )
    try:
        upstream_res = download_client.request("GET", upstream_file_url)
    except Exception as exc:
        log.warning("proxy_upstream_download_failed", error=str(exc), package=canonical)
        raise HTTPException(status_code=502, detail="Failed to fetch package from upstream") from exc
    finally:
        download_client.close()

    if upstream_res.status != 200:
        raise HTTPException(
            status_code=upstream_res.status,
            detail=f"Upstream returned HTTP {upstream_res.status}",
        )

    if expected_sha256:
        content_sha = hashlib.sha256(upstream_res.content).hexdigest()
        if not hmac.compare_digest(content_sha, expected_sha256.lower()):
            log.warning("proxy_checksum_mismatch", package=canonical, filename=filename)
            raise HTTPException(status_code=502, detail="Upstream artifact integrity check failed")

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
