# Releasing

Releases are cut from `main` by pushing a `vX.Y.Z` tag. `.github/workflows/publish.yml` then checks that
the tagged commit is on `main` and passed CI, builds the sdist and wheel once, attaches Sigstore build
provenance and an SBOM, and — only when publishing is switched on — uploads to PyPI through Trusted
Publishing (no API token is stored anywhere).

## Already configured in this repository

- Environment `pypi`: deployments need approval from @rakshit-737 and are limited to `v*` tags.
- Tag ruleset "release tags": only repository admins can create, move or delete `v*` tags.
- Branch ruleset "protect main": no force-pushes, no deletion.

## One-time PyPI setup (maintainer, on pypi.org)

1. Sign in as `rakshit-737` and open <https://pypi.org/manage/account/publishing/>.
2. Add a **pending publisher** (GitHub):
   - PyPI project name: `warden-supply-chain-security`
   - Owner: `rakshit-737`
   - Repository name: `warden-supply-chain-security`
   - Workflow name: `publish.yml`
   - Environment name: `pypi`
3. In GitHub → Settings → Secrets and variables → Actions → **Variables**, add `PYPI_PUBLISH` = `true`.

Until step 3, tagged releases build and attest everything but skip the upload.

## Cutting a release

1. Update the version in `pyproject.toml`, `backend/pyproject.toml`, `backend/app/__init__.py`,
   `frontend/package.json` and `frontend/package-lock.json` (both root entries), and add a section
   to `CHANGELOG.md`. The tag must equal `v<version of pyproject.toml>` or the build refuses it.
2. Open a pull request, merge it, and wait for CI on the merge commit to pass. `main` is protected,
   and `verify-release-commit` checks that ci.yml passed for the exact commit the tag points at.
3. `git tag -a vX.Y.Z -m "Warden X.Y.Z" && git push origin vX.Y.Z`
4. The `release-assets` job creates the GitHub release and attaches the distributions, the SBOM,
   `SHA256SUMS` and the SLSA provenance bundle, each with a Sigstore `.sigstore.json` signature.
   Edit the release notes afterwards if the generated ones need the changelog section.
5. Approve the `pypi` deployment in the workflow run (only when `PYPI_PUBLISH` is `true`; without it
   the tag builds, attests and signs everything but uploads nothing).

Verify a published file against its provenance with
`gh attestation verify <file> --repo rakshit-737/warden-supply-chain-security`.
