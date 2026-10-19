# CLI reference

The `warden` command is installed with the package (`pip install warden-supply-chain-security`). From
a source checkout, run `python -m cli.warden_cli` inside `backend/` instead.

- **API commands** (`scan`, `gate`) ask a running Warden server for verdicts and need a token.
- **Local commands** run the engines in-process, need `pip install "warden-supply-chain-security[server]"`,
  no server and no token, and never execute project code.

Exit codes: `0` passed, `2` the check failed (blocked, findings at or above the threshold, drift,
invalid policy), `3` usage or transport error.

## API commands

Options may go before or after the subcommand. `WARDEN_API` and `WARDEN_TOKEN` supply defaults.

| Option | Meaning |
|---|---|
| `--api URL` | Warden API base URL (default `http://localhost:8000`) |
| `--token TOKEN` | Bearer access token |
| `--fail-on {warn,block}` | Lowest decision that fails the command (default `block`) |
| `--no-color` | Plain output |

```bash
warden scan requests==2.32.3
warden gate -r requirements.txt --fail-on warn
```

## `warden run COMMAND...`

Transparent installer gate that intercepts `pip install` or `npm install`, runs package scans, and aborts
installation if policy violations are detected.

```bash
warden run pip install flask requests==2.32.3
warden run npm install lodash
```

| Option | Meaning |
|---|---|
| `--force` | Execute the install command even if policy warns or blocks |

## `warden reachability [PATH] --package PKG`

AST-based reachability engine that determines whether a vulnerable symbol from a dependency is actually
imported and called in the project code. Errs on the side of reporting reachability when uncertain.

```bash
warden reachability ./src --package requests --symbol Session --advisory CVE-2023-32681
```

| Option | Meaning |
|---|---|
| `PATH` | Project source directory to inspect (default `.`) |
| `-p, --package NAME` | Target dependency package name (required) |
| `-s, --symbol NAME` | Vulnerable function, class or method name |
| `-a, --advisory ID` | Advisory identifier (e.g. CVE or GHSA) |

Output statuses:
- **`REACHABLE`** — Symbol is explicitly imported and invoked in project code.
- **`IMPORTED_NOT_CALLED`** — Module is imported, but the vulnerable function/method is not called.
- **`TRANSITIVE_DORMANT`** — Package is never imported anywhere in the project.

## `warden project scan [PATH]`

Dependency hygiene (unpinned, unhashed, ambiguous indexes), dependency confusion, Dockerfile and
Compose checks, and a dependency-graph summary for the manifests under `PATH`.

| Option | Meaning |
|---|---|
| `--format {table,json,sarif}` | Output format (default `table`) |
| `-o, --output FILE` | Write the report to a file |
| `--fail-on {low,medium,high,critical}` | Lowest finding severity that fails (default `high`) |
| `--project-name NAME` | Name used in reports and SBOMs |

## `warden sbom generate [PATH]`

| Option | Meaning |
|---|---|
| `--format {cyclonedx,spdx}` | CycloneDX 1.6 (default) or SPDX 2.3 JSON |
| `-o, --output FILE` | Write to a file instead of stdout |
| `--project-name NAME` | Root component name |

`SOURCE_DATE_EPOCH` makes the output reproducible.

## `warden diff PACKAGE FROM_VERSION TO_VERSION`

Downloads and analyses both releases, then reports risk, capability, finding, file and maintainer
changes.

| Option | Meaning |
|---|---|
| `--format {table,json}` | Output format |
| `--fail-on-drift` | Exit `2` when the newer release escalated |

## `warden image scan ARCHIVE`

Offline analysis of the output of `docker save IMAGE -o image.tar` (or an OCI layout tarball).

| Option | Meaning |
|---|---|
| `--format {table,json,sarif}` | Output format |
| `-o, --output FILE` | Write the report to a file |
| `--sbom-output FILE` | Also write a CycloneDX SBOM of the image packages |
| `--no-vulnerabilities` | Skip the Trivy pass |
| `--offline` | Do not let Trivy update its database |
| `--fail-on {low,medium,high,critical}` | Lowest finding severity that fails (default `high`) |

An image that cannot be read completely always fails, and vulnerabilities that were not assessed are
reported as such.

## `warden report INPUT`

Renders a saved JSON result (from `project scan`, `image scan`, `diff` or `GET /api/v1/scans/{id}`)
as Markdown, self-contained HTML or SARIF. `INPUT` may be `-` for stdin.

| Option | Meaning |
|---|---|
| `--format {markdown,html,sarif}` | Output format (default `markdown`) |
| `-o, --output FILE` | Write to a file |

## `warden policy validate FILE`

Validates a YAML or JSON policy document and prints its hash; `--format json` for machine output.

## GitHub Action

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@<sha>
    with: { persist-credentials: false }
  - uses: rakshit-737/warden-supply-chain-security@<commit-sha>
    with:
      path: .
      fail-on: high          # low | medium | high | critical
      upload-sarif: "true"
```

The action runs `project scan`, uploads the SARIF report to code scanning and only then enforces the
gate, so a failing build still shows its alerts. Outputs: `sarif-file` and `exit-code`.

## Pre-commit integration

Warden includes hooks for the [pre-commit](https://pre-commit.com/) framework. Add Warden to your
`.pre-commit-config.yaml` to scan manifests and validate policies locally on git commit:

```yaml
repos:
  - repo: https://github.com/rakshit-737/warden-supply-chain-security
    rev: v2.1.0
    hooks:
      - id: warden-project-scan
        args: ['--fail-on', 'high']
      - id: warden-policy-validate
```
