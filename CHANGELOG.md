# Changelog

## Unreleased

## 2.1.0

### Projects
- npm manifests: `package.json`, `package-lock.json` (lockfile v1–v3) and `npm-shrinkwrap.json`
  become SBOM components (`pkg:npm` purls, sha512 integrity hashes, dev/optional scopes) with
  dependency edges that follow Node's nested `node_modules` resolution. Unpinned direct npm
  dependencies without a lock file are hygiene findings. Package analysis stays PyPI-only.

### Security
- `redact_url` kept a credential in a stored reference in six cases, each a different way to write
  an authority: without a scheme (`user:token@host/path`), after a corrupted scheme separator
  (`https\x0e//user:token@host`), with a bracket in the userinfo (`//to[[ken@host`), inside a path
  or fragment (`https://host/x//user:token@elsewhere`), separated by a control character that
  Python's `\s` treats as whitespace (`token@\x1fhost`), and one that only becomes visible once the
  value is escaped for display (`http//:sus\x0cer:pw@host`). The stored value reaches SBOMs,
  reports and the console, so each one leaked the credential to everyone who could read a scan.
  Found by the new fuzz harnesses; every case has a regression test.
- PyJWT upgraded to 2.15.0 (PYSEC-2026-4141).
- The web image applies Alpine security updates at build time, which closes libexpat
  CVE-2026-93990 and pcre2 CVE-2026-103111 in the pinned base image.

### Build and CI
- Every Python dependency is installed from a hash-locked requirements file
  (`pip install --require-hashes`) in CI, the Dockerfile and the GitHub Action. Locks are generated
  by `backend/scripts/lock_requirements.sh` and a CI job fails when one drifts from its pins.
- Releases carry Sigstore-signed assets: distributions, the CycloneDX SBOM, `SHA256SUMS` and the
  SLSA provenance bundle, each with a `.sigstore.json`.
- Fuzz harnesses (Atheris) for the layered decoder and the manifest parsers run on every pull
  request, with `fuzz/run_local.py` for machines that have no Atheris wheel.
- CodeQL and gitleaks run on pull requests rather than only after a merge.
- A landing page is published at the root of the documentation site.

## 2.0.0

Warden grows from a package firewall into a supply-chain security platform. Package code is still
never executed.

### Analysis
- Unified `Finding` model: severity and confidence, file and line, CWE and MITRE ATT&CK mappings,
  remediation, provenance; evidence sanitised and secrets redacted on construction.
- Fourteen analyzers, including new secrets, dependency-confusion, provenance (PEP 740), YARA,
  Semgrep, vulnerability (OSV, CISA KEV, FIRST EPSS, optional NVD) and install-vector analyzers
  (`.pth` start-up hooks, in-tree build backends, console scripts that shadow commands).
- Static analysis detects serialised environment dumps, import aliases, socket egress,
  reconstructed `exec` names and reverse shells.
- Attack-chain correlation and Risk Engine 2.0 with separate behavioural and vulnerability risk;
  the ML model can no longer escalate on its own past the medium band.
- Release-to-release behavioural diffs.

### Projects, containers and monitoring
- Project scans from manifests: dependency hygiene, dependency confusion, Dockerfile and Compose
  linting, dependency graph with blast radius, CycloneDX 1.6 and SPDX 2.3 SBOMs.
- Offline container image analysis (`docker save` / OCI) with an optional Trivy pass.
- Continuous monitoring worker for new releases, drift and maintainer changes.

### Platform
- API: packages, projects, diffs, containers, monitoring and vulnerabilities routes; policy-as-code
  with environments and approved exceptions; five-role RBAC; hash-chained audit log; security
  events; Prometheus metrics.
- Console: projects, diffs, containers, monitoring and package views; React 19, React Router 8,
  Vite 8 and Tailwind CSS 4.
- CLI: `project scan`, `sbom generate`, `policy validate`, `diff`, `image scan`, `report`; SARIF
  2.1.0 output.
- GitHub Action (`action.yml`) for project scans with SARIF upload.
- Synthetic detection benchmark with a CI regression gate (`docs/BENCHMARK.md`).

### Security
- Secret redaction can no longer be bypassed with terminal escape sequences or bidi characters.
- Hardened proxy limits, digest-pinned images with applied OS updates, Trivy and CodeQL clean.
- The dynamic sandbox is designed but not built; enabling it is refused (`docs/SANDBOX.md`).

## 1.0.0

Initial release: behavioural package firewall for PyPI with rule and ML scoring, policy engine,
API, console and CI gate.
