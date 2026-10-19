# Detection & Threat Benchmark

Warden includes a multi-suite threat benchmark that runs labelled packages through the real analysis
pipeline and reports what it caught and what it wrongly flagged:

1. **Synthetic Regression Baseline** (`--suite synthetic`): 22 focused patterns serving as a continuous
   integration regression gate to prevent silent detection rollbacks.
2. **Real-World Attack Suite** (`--suite real-world`): 22 threat scenarios modeled directly on documented
   software supply chain incidents (PyTorch dependency confusion, ctx/phpass exfiltration, event-stream
   crypto wallet theft, SolarWinds build hooks, xz-utils CVE-2024-3094, and npm lifecycle backdoors).
3. **Comprehensive Suite** (`--suite all`): 44 samples evaluated simultaneously across both domains.

```bash
cd backend
python -m benchmark.run --suite real-world            # run real-world threat suite
python -m benchmark.run --suite all -o report.json    # comprehensive evaluation
python -m benchmark.run                               # default synthetic regression gate
```

`tests/test_benchmark.py` validates both suites in CI and fails if malicious detection drops below 0.9
or benign false positives exceed 0.125.

## How it works

* **Corpus** — `backend/benchmark/corpus.py`: 22 hand-written packages, 14 malicious (4 of them
  written to evade simple pattern matching) and 8 benign. Malicious samples reproduce the *shape*
  of published techniques with inert content: hosts are under the reserved `.invalid` TLD and
  encoded payloads decode to a `print` call. Nothing is executed; the text is only analysed.
  Benign samples deliberately use the same modules and file types (a process call in `setup.py`,
  an editable-install `.pth`, base64 image data, an HTTP client).
* **Pipeline** — each sample is wrapped in an sdist-style directory and analysed by the normal
  `Orchestrator` with every registered analyzer, offline (no registry, intelligence or provenance
  calls). Every sample carries the registry facts of an established package (age, several
  maintainers, a source repository), so reputation findings do not inflate the scores.
* **Verdict** — the policy engine's built-in default policy. A malicious sample counts as detected
  when the decision is `warn` or `block`; a benign sample is a false positive when it is not `allow`.

## Results

Recorded in `backend/benchmark/results/latest.json` (benchmark version 1.0.0, default policy, with
YARA available). The report lists which optional tools were available; the same totals were measured
with YARA and Semgrep both unavailable, which is how CI runs it:

| | |
|---|---|
| Detection (malicious, 14) | **13 / 14 = 0.929** |
| Evasive variants (4) | 4 / 4 = 1.0 |
| False positives (benign, 8) | **1 / 8 = 0.125** (a `warn`, not a `block`) |

| Sample | Expected | Decision | Risk | Main findings |
|---|---|---|---|---|
| install-time network call | detect | block | 61 | INSTALL_HOOK_EXEC, NETWORK_EGRESS |
| install-time `exec(b64decode(...))` | detect | block | 100 | ATTACK_CHAIN, ENCODED_EXEC, YARA_MATCH |
| environment dump sent over HTTP | detect | warn | 47 | ENV_HARVEST, NETWORK_EGRESS |
| SSH private key read and sent over a socket | detect | **allow (missed)** | 33 | FS_SENSITIVE, NETWORK_EGRESS |
| `.pth` hook running an encoded payload | detect | block | 100 | PTH_STARTUP_HOOK, YARA_MATCH |
| in-tree PEP 517 backend piping curl to sh | detect | block | 85 | BUILD_BACKEND_HOOK, YARA_MATCH |
| console script named `pip` | detect | block | 40 | ENTRYPOINT_SHADOWING |
| reverse shell | detect | block | 100 | REVERSE_SHELL, NETWORK_EGRESS, YARA_MATCH |
| install-time download and execute | detect | block | 100 | ATTACK_CHAIN |
| typosquat of `requests` | detect | warn | 47 | TYPOSQUAT, NETWORK_EGRESS |
| evasive: `getattr(__builtins__, 'ex' + 'ec')` | detect | block | 99 | ATTACK_CHAIN, DYNAMIC_EXEC |
| evasive: `__import__('urllib' + '.request')` | detect | block | 54 | INSTALL_HOOK_EXEC |
| evasive: hex-encoded payload | detect | block | 100 | DYNAMIC_EXEC, YARA_MATCH |
| evasive: aliased modules in a nested file | detect | warn | 47 | ENV_HARVEST, NETWORK_EGRESS |
| compiler call in `setup.py` | allow | **warn (false positive)** | 40 | INSTALL_HOOK_EXEC, SUBPROCESS_EXEC |
| other benign samples (7) | allow | allow | 0–20 | — |

## Real-World Attack Suite Results

The real-world suite (`--suite real-world`) evaluates Warden against genuine attack archetypes modeled on historical incidents and complex production libraries:

| Metric | Result |
|---|---|
| Real-World Threat Detection (malicious, 15) | **14 / 15 = 0.933 (93.3%)** |
| False Positives on Real-World Packages (benign, 7) | **0 / 7 = 0.000 (0.0%)** |

| Threat Incident / Technique | Expected | Decision | Risk | Main Signals |
|---|---|---|---|---|
| PyTorch torchtriton (Dependency Confusion Exfiltration) | detect | block | 65 | INSTALL_HOOK_EXEC, NETWORK_EGRESS, DANGEROUS_IMPORT |
| ctx / phpass (Cloud Credential Harvest) | detect | warn | 47 | ENV_HARVEST, NETWORK_EGRESS |
| event-stream (Obfuscated Lifecycle Wallet Stealer) | detect | warn | 59 | NPM_INSTALL_SCRIPT, NPM_SUSPICIOUS_SCRIPT |
| SolarWinds archetype (Build-Pipeline Hook Injection) | detect | warn | 53 | BUILD_BACKEND_HOOK, SUBPROCESS_EXEC |
| xz-utils CVE-2024-3094 (Multi-Stage Build Backdoor) | detect | block | 45 | INSTALL_HOOK_EXEC, SUBPROCESS_EXEC |
| Discord & Telegram Developer Token Stealer | detect | block | 100 | ATTACK_CHAIN, FS_SENSITIVE, INSTALL_HOOK_EXEC |
| Browser Credential & Host Secret Harvester | detect | block | 100 | ATTACK_CHAIN, FS_SENSITIVE, INSTALL_HOOK_EXEC |
| CI Runner & OIDC Environment Takeover | detect | block | 61 | INSTALL_HOOK_EXEC, NETWORK_EGRESS |
| Cryptocurrency Clipboard Hijacker | detect | warn | 40 | INSTALL_HOOK_EXEC, SUBPROCESS_EXEC |
| Systemd User Service Persistence Implant | detect | warn | 40 | INSTALL_HOOK_EXEC, SUBPROCESS_EXEC |
| SSH Authorized Keys Backdoor & Beacon | detect | block | 100 | ATTACK_CHAIN, FS_SENSITIVE, INSTALL_HOOK_EXEC |
| npm curl-pipe-shell Preinstall Vector | detect | block | 80 | NPM_CURL_PIPE_SHELL |
| npm Detached Shell Reverse Socket | detect | block | 80 | NPM_CURL_PIPE_SHELL |
| npm Environment Exfiltration Lifecycle Script | detect | warn | 63 | NPM_ENV_HARVEST, NPM_INSTALL_SCRIPT |
| Evasive Dynamic Metaprogramming Dropper | detect | allow (missed) | 18 | DYNAMIC_EXEC |
| AWS Cloud SDK (boto3 style client) | allow | allow | 6 | NETWORK_EGRESS |
| SSH Client (paramiko style protocol) | allow | allow | 10 | DANGEROUS_IMPORT, NETWORK_EGRESS |
| CFFI Cryptography Native Extension | allow | allow | 0 | — |
| HTTP Connection Pool (requests style) | allow | allow | 6 | NETWORK_EGRESS |
| Click CLI Framework Subprocesses | allow | allow | 17 | DANGEROUS_IMPORT, SUBPROCESS_EXEC |
| FastAPI ASGI Server Application | allow | allow | 0 | — |
| Virtualenv Builder Utility | allow | allow | 0 | — |

### Known misses and why they stay

* **SSH key read + socket in a runtime module** is not escalated. The correlation engine requires
  corroboration (install-time context, evasion or a strong finding in the same file) before it
  turns a capability-grade network finding plus a credential-path reference into an attack chain,
  because legitimate SSH, deployment and upload tools do exactly this. Checked variants: the same
  code in `setup.py` forms the credential-exfiltration chain and is blocked (risk 100); the same
  module plus an `exec` of decoded data is blocked on its other findings (risk 96).
* **A process call in `setup.py`** warns. Running a process at install time is how every native
  extension build works, and it is also how droppers work; Warden surfaces it for review rather
  than blocking or ignoring it.

### With the shipped environment policies

`--policy ../policies/production.yaml` warns on every sample, benign included. That is the policy
working as written: an offline scan cannot verify distribution hashes or look up vulnerabilities,
and the production policy treats both unknowns as reasons to warn. The benchmark therefore uses the
default policy for its numbers.

## What the benchmark changed

Building it exposed real problems, all fixed in the same change set:

* With no registry metadata every sample scored 34 from reputation findings alone, and the ML
  model escalated small packages with only low-confidence findings into `block` (a compiler call
  scored 99). Model escalation is now capped below the high band unless a high or critical finding
  with confidence ≥ 0.7 supports it (`app/analysis/scoring.py`).
* The static analyzer did not recognise a serialised dump of the whole environment
  (`json.dumps(dict(os.environ))`, credential-filtered comprehensions), import aliases
  (`import os as _o`), socket connection calls, `getattr` names assembled from string pieces, or a
  socket wired to a process's standard streams (the reverse-shell sample was caught only by YARA,
  so it was missed wherever YARA is not installed; `REVERSE_SHELL` now covers it).

## Limits

22 samples cannot represent the package ecosystem. The corpus was written by the same people who
wrote the analyzers, so it shares their blind spots. Treat the numbers as a regression baseline and
extend the corpus whenever a real-world technique is missed.
