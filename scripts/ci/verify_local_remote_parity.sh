#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}"

MODE="all"
ONLY_CSV=""
TOKEN_FILE="${ROOT_DIR}/../github.key"
REPO_SLUG="btxchain/btx-node"
POLL_TIMEOUT_SECONDS=3600
POLL_INTERVAL_SECONDS=20
RUN_LOCAL="true"
LOCAL_SUMMARY=""
ALLOW_DIRTY_HEAD="false"

usage() {
  cat <<'USAGE'
Usage: scripts/ci/verify_local_remote_parity.sh [options]

Runs local macOS CI-replica jobs and compares their results against GitHub
Actions job conclusions for the same HEAD commit.

Options:
  --mode <all|ci|readiness>     Local matrix mode (default: all)
  --only <csv>                  Restrict local jobs (job names or targets)
  --token-file <path>           GitHub API token file (default: ../github.key)
  --repo <owner/name>           Repository slug (default: btxchain/btx-node)
  --poll-timeout-seconds <n>    Max wait for remote job conclusions
                                (default: 3600)
  --poll-interval-seconds <n>   Poll interval for remote jobs (default: 20)
  --skip-local                  Skip local run and use --local-summary
  --local-summary <path>        Existing local summary TSV from
                                run_local_mac_matrix.sh
  --allow-dirty-head            Pass through to local runner when running local
  -h, --help                    Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      MODE="$2"
      shift 2
      ;;
    --only)
      ONLY_CSV="$2"
      shift 2
      ;;
    --token-file)
      TOKEN_FILE="$2"
      shift 2
      ;;
    --repo)
      REPO_SLUG="$2"
      shift 2
      ;;
    --poll-timeout-seconds)
      POLL_TIMEOUT_SECONDS="$2"
      shift 2
      ;;
    --poll-interval-seconds)
      POLL_INTERVAL_SECONDS="$2"
      shift 2
      ;;
    --skip-local)
      RUN_LOCAL="false"
      shift
      ;;
    --local-summary)
      LOCAL_SUMMARY="$2"
      shift 2
      ;;
    --allow-dirty-head)
      ALLOW_DIRTY_HEAD="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown option '$1'" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ "${MODE}" != "all" && "${MODE}" != "ci" && "${MODE}" != "readiness" ]]; then
  echo "error: --mode must be all, ci, or readiness" >&2
  exit 1
fi

for val in "${POLL_TIMEOUT_SECONDS}" "${POLL_INTERVAL_SECONDS}"; do
  if ! [[ "${val}" =~ ^[0-9]+$ ]] || [[ "${val}" -lt 1 ]]; then
    echo "error: poll timeout/interval values must be positive integers" >&2
    exit 1
  fi
done

for cmd in curl python3; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "error: required command not found: ${cmd}" >&2
    exit 1
  fi
done

if [[ -n "${GITHUB_TOKEN:-}" ]]; then
  API_TOKEN="${GITHUB_TOKEN}"
elif [[ -f "${TOKEN_FILE}" ]]; then
  API_TOKEN="$(<"${TOKEN_FILE}")"
else
  echo "error: no GitHub token found. Set GITHUB_TOKEN or provide --token-file." >&2
  exit 1
fi

if [[ -z "${API_TOKEN}" ]]; then
  echo "error: GitHub token is empty" >&2
  exit 1
fi

if [[ "${RUN_LOCAL}" == "true" ]]; then
  local_log="$(mktemp "${TMPDIR:-/tmp}/btx-local-parity.XXXXXX.log")"
  local_cmd=(scripts/ci/run_local_mac_matrix.sh "${MODE}")
  if [[ -n "${ONLY_CSV}" ]]; then
    local_cmd+=(--only "${ONLY_CSV}")
  fi
  if [[ "${ALLOW_DIRTY_HEAD}" == "true" ]]; then
    local_cmd+=(--allow-dirty-head)
  fi

  echo "[parity] running local matrix: ${local_cmd[*]}"
  "${local_cmd[@]}" 2>&1 | tee "${local_log}"
  LOCAL_SUMMARY="$(awk '/^\[local-matrix\] summary:/ {print $3}' "${local_log}" | tail -n 1)"
fi

if [[ -z "${LOCAL_SUMMARY}" ]]; then
  echo "error: no local summary available. Run local matrix or provide --local-summary." >&2
  exit 1
fi

if [[ ! -f "${LOCAL_SUMMARY}" ]]; then
  echo "error: local summary file not found: ${LOCAL_SUMMARY}" >&2
  exit 1
fi

HEAD_SHA="$(git rev-parse HEAD)"
echo "[parity] comparing local summary ${LOCAL_SUMMARY} to remote runs for HEAD ${HEAD_SHA}"

export API_TOKEN
python3 - "${LOCAL_SUMMARY}" "${HEAD_SHA}" "${REPO_SLUG}" "${POLL_TIMEOUT_SECONDS}" "${POLL_INTERVAL_SECONDS}" <<'PY'
import csv
import json
import os
import sys
import time
import urllib.parse
import urllib.request

summary_path, head_sha, repo_slug, timeout_s_raw, poll_s_raw = sys.argv[1:]
timeout_s = int(timeout_s_raw)
poll_s = int(poll_s_raw)
api_token = os.environ["API_TOKEN"]

with open(summary_path, newline="", encoding="utf-8") as fh:
    reader = csv.DictReader(fh, delimiter="\t")
    rows = list(reader)

if not rows:
    raise SystemExit("error: summary TSV is empty")

local = {}
for row in rows:
    wf = row.get("workflow", "").strip()
    job_name = row.get("job_name", "").strip()
    status = row.get("status", "").strip()
    if wf and job_name and status in {"PASS", "FAIL"}:
        local.setdefault(wf, {})[job_name] = status

if not local:
    raise SystemExit("error: no comparable local rows found in summary TSV")

workflow_files = {
    "ci": "ci.yml",
    "readiness": "btx-readiness.yml",
}

headers = {
    "Authorization": f"Bearer {api_token}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "btx-local-remote-parity",
}


def gh_get(url: str):
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def list_run_jobs(run_id: int):
    jobs = []
    page = 1
    while True:
        data = gh_get(
            f"https://api.github.com/repos/{repo_slug}/actions/runs/{run_id}/jobs"
            f"?per_page=100&page={page}"
        )
        page_jobs = data.get("jobs", [])
        jobs.extend(page_jobs)
        if not page_jobs or len(jobs) >= data.get("total_count", 0):
            return jobs
        page += 1


all_rows = []
problems = []

for workflow, local_jobs in sorted(local.items()):
    workflow_file = workflow_files.get(workflow)
    if workflow_file is None:
        problems.append(f"unknown workflow key in local summary: {workflow}")
        continue

    encoded_sha = urllib.parse.quote(head_sha, safe="")
    runs_url = (
        f"https://api.github.com/repos/{repo_slug}/actions/workflows/{workflow_file}/runs"
        f"?head_sha={encoded_sha}&per_page=20"
    )
    runs_data = gh_get(runs_url)
    runs = runs_data.get("workflow_runs", [])
    if not runs:
        problems.append(f"{workflow}: no remote workflow run found for HEAD {head_sha}")
        continue

    run = runs[0]
    run_id = run["id"]
    run_url = run.get("html_url", "")
    target_names = set(local_jobs.keys())

    deadline = time.time() + timeout_s
    latest_conclusions = {}
    while True:
        jobs = list_run_jobs(run_id)
        latest_conclusions = {job["name"]: job.get("conclusion") for job in jobs}
        pending = [name for name in target_names if latest_conclusions.get(name) in (None, "")]
        if not pending:
            break
        if time.time() >= deadline:
            problems.append(
                f"{workflow}: timed out waiting for remote jobs on run {run_id}; pending={','.join(sorted(pending))}"
            )
            break
        time.sleep(poll_s)

    for job_name in sorted(target_names):
        local_status = local_jobs[job_name]
        conclusion = latest_conclusions.get(job_name)
        if conclusion == "success":
            remote_status = "PASS"
        elif conclusion in (None, ""):
            remote_status = "MISSING"
        else:
            remote_status = "FAIL"

        match = local_status == remote_status
        all_rows.append(
            (
                workflow,
                job_name,
                local_status,
                conclusion or "pending",
                remote_status,
                "MATCH" if match else "MISMATCH",
                str(run_id),
                run_url,
            )
        )
        if remote_status == "MISSING":
            problems.append(f"{workflow}/{job_name}: remote conclusion missing (run {run_id})")
        elif not match:
            problems.append(
                f"{workflow}/{job_name}: local={local_status} remote={remote_status} (conclusion={conclusion})"
            )

header = (
    "workflow",
    "job_name",
    "local",
    "remote_conclusion",
    "remote_status",
    "parity",
    "run_id",
    "run_url",
)
widths = [len(h) for h in header]
for row in all_rows:
    for i, value in enumerate(row):
        widths[i] = max(widths[i], len(value))

def fmt_row(values):
    return "  ".join(value.ljust(widths[i]) for i, value in enumerate(values))

print(fmt_row(header))
print("  ".join("-" * w for w in widths))
for row in all_rows:
    print(fmt_row(row))

if problems:
    print("")
    print("[parity] mismatches/problems detected:")
    for problem in problems:
        print(f"- {problem}")
    raise SystemExit(1)

print("")
print("[parity] local and remote job conclusions match for selected workflow rows.")
PY

