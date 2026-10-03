#!/usr/bin/env bash
# Regenerate the hash-locked requirements files from the human-edited pins.
#
#   backend/requirements.txt           ->  requirements.lock.txt          (runtime)
#   backend/requirements-dev.txt       ->  requirements-dev.lock.txt      (runtime + test/lint tooling)
#   ruff/bandit/pip-audit pins         ->  requirements-tools.lock.txt    (CI lint + security jobs)
#   backend/requirements-publish.txt   ->  requirements-publish.lock.txt  (twine, release path)
#
# Edit a version in the .txt file, run this script, commit both files. CI (ci.yml, job
# requirements-lock) re-runs it and fails if the result differs, so a lock can never drift from its
# source pins. Every install in CI, the Dockerfile and action.yml uses `pip install --require-hashes`
# against a lock file: pip then refuses any artifact whose hash is not listed.
#
# Resolution is universal (markers for every platform) and targets the lowest Python version the
# pinned set supports; numpy's pin requires >= 3.12.
#
#   Usage: backend/scripts/lock_requirements.sh   (needs uv: https://docs.astral.sh/uv/)

set -euo pipefail

cd "$(dirname "$0")/.."

PYTHON_VERSION="3.12"
UV_ARGS=(--universal --generate-hashes --no-header --quiet --python-version "${PYTHON_VERSION}")

header() {
  local source="$1"
  printf '# Hash-locked resolution of %s — DO NOT EDIT.\n' "${source}"
  printf '# Regenerate with backend/scripts/lock_requirements.sh (uv, --universal, Python %s).\n' "${PYTHON_VERSION}"
}

compile() {
  local source="$1" output="$2" input="$3"
  local tmp
  tmp="$(mktemp)"
  # shellcheck disable=SC2086  # $input is a path or "-" (stdin), never a word list.
  uv pip compile "${UV_ARGS[@]}" "${input}" -o "${tmp}"
  { header "${source}"; cat "${tmp}"; } > "${output}"
  rm -f "${tmp}"
  echo "wrote ${output}"
}

compile "requirements.txt" "requirements.lock.txt" "requirements.txt"
compile "requirements-dev.txt" "requirements-dev.lock.txt" "requirements-dev.txt"
compile "requirements-publish.txt" "requirements-publish.lock.txt" "requirements-publish.txt"

# The tool-only lock takes its versions from requirements-dev.txt, so the pins exist in one place.
tools="$(mktemp)"
grep -E '^(ruff|bandit|pip-audit)==' requirements-dev.txt > "${tools}"
compile "the ruff, bandit and pip-audit pins in requirements-dev.txt" "requirements-tools.lock.txt" "${tools}"
rm -f "${tools}"
