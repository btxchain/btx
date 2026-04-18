#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_PATH="${ROOT_DIR}/scripts/m24_shielded_external_findings_intake.py"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/btx-m24-intake-test.XXXXXX")"
INTAKE_DIR="${TMP_ROOT}/intake"
SOURCE_PACKET_DIR="${TMP_ROOT}/source_packet"
HOSTED_RUN_DIR="${TMP_ROOT}/hosted_run"
HOSTED_VALIDATION_DIR="${TMP_ROOT}/hosted_validation"
trap 'rm -rf "${TMP_ROOT}"' EXIT

mkdir -p "${SOURCE_PACKET_DIR}/artifacts/hosted_run" "${SOURCE_PACKET_DIR}/artifacts/hosted_validation" "${HOSTED_RUN_DIR}" "${HOSTED_VALIDATION_DIR}"
printf 'source packet fixture\n' > "${SOURCE_PACKET_DIR}/README.txt"
printf 'hosted run fixture\n' > "${HOSTED_RUN_DIR}/README.txt"
printf 'hosted validation fixture\n' > "${HOSTED_VALIDATION_DIR}/README.txt"

python3 - "${SOURCE_PACKET_DIR}/artifacts/hosted_run/manifest.json" "${HOSTED_RUN_DIR}/manifest.json" "${SOURCE_PACKET_DIR}/artifacts/hosted_validation/manifest.json" "${HOSTED_VALIDATION_DIR}/manifest.json" <<'PY'
import json
import pathlib
import sys

payload = {
    "overall_status": "pass",
    "configuration": {
        "ssh_private_key_name": "id_ed25519",
    },
    "steps": [
        {
            "command": [
                "scp",
                "-i",
                "/Users/admin/.ssh/id_ed25519",
                "/private/tmp/btx-m22-old/source.tar.gz",
                "root@198.51.100.8:/root/upload.tar.gz",
            ],
            "cwd": "/Users/admin/Documents/btxchain/btx-node",
            "log": "/private/tmp/btx-m22-old/logs/source_upload.log",
        }
    ],
    "artifacts": {
        "source_archive": {
            "path": "/private/tmp/btx-m22-old/source.tar.gz",
        },
        "remote_extract_dir": "/private/tmp/btx-m22-old/artifacts/remote_artifacts",
    },
}
for target in sys.argv[1:]:
    pathlib.Path(target).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY

python3 "${SCRIPT_PATH}" \
    --output-dir "${INTAKE_DIR}" \
    --source-packet "${SOURCE_PACKET_DIR}" \
    --hosted-run-dir "${HOSTED_RUN_DIR}" \
    --hosted-validation-dir "${HOSTED_VALIDATION_DIR}" \
    >/dev/null

test -f "${INTAKE_DIR}/scripts/m25_shielded_external_closeout_check.py"
test -f "${INTAKE_DIR}/scripts/m24_shielded_external_findings_intake.py"
test -f "${INTAKE_DIR}/scripts/m26_remote_shielded_validation_suite.py"
test -f "${INTAKE_DIR}/doc/btx-shielded-external-review-closeout.md"
test -f "${INTAKE_DIR}/infra/btx-seed-server-spec.md"
test -f "${INTAKE_DIR}/source_refs/m23_packet/artifacts/hosted_run/manifest.json"
test -f "${INTAKE_DIR}/source_refs/m23_packet/artifacts/hosted_validation/manifest.json"
test -f "${INTAKE_DIR}/source_refs/m22_hosted_run/manifest.json"
test -f "${INTAKE_DIR}/source_refs/m26_hosted_validation/manifest.json"
test ! -e "${INTAKE_DIR}/docs/m25_shielded_external_closeout_check.py"

set +e
python3 "${INTAKE_DIR}/scripts/m25_shielded_external_closeout_check.py" \
    --intake-dir "${INTAKE_DIR}" \
    --output "${INTAKE_DIR}/closeout/closeout_summary.json" \
    >"${TMP_ROOT}/m25.stdout" 2>"${TMP_ROOT}/m25.stderr"
status=$?
set -e

if [ "${status}" -eq 0 ]; then
    echo "expected packet-local m25 closeout check to fail on placeholder intake" >&2
    exit 1
fi

python3 - "${INTAKE_DIR}/manifest.json" "${INTAKE_DIR}/closeout/closeout_summary.json" "${INTAKE_DIR}/source_refs/m23_packet/artifacts/hosted_run/manifest.json" "${INTAKE_DIR}/source_refs/m22_hosted_run/manifest.json" "${INTAKE_DIR}/source_refs/m23_packet/artifacts/hosted_validation/manifest.json" "${INTAKE_DIR}/source_refs/m26_hosted_validation/manifest.json" <<'PY'
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
summary = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
source_packet_hosted = json.loads(pathlib.Path(sys.argv[3]).read_text(encoding="utf-8"))
direct_hosted = json.loads(pathlib.Path(sys.argv[4]).read_text(encoding="utf-8"))
source_packet_validation = json.loads(pathlib.Path(sys.argv[5]).read_text(encoding="utf-8"))
direct_validation = json.loads(pathlib.Path(sys.argv[6]).read_text(encoding="utf-8"))

packet_paths = {entry["packet_path"] for entry in manifest["included_sources"]}
required_paths = {
    "doc/btx-shielded-external-review-closeout.md",
    "scripts/m24_shielded_external_findings_intake.py",
    "scripts/m25_shielded_external_closeout_check.py",
    "scripts/m26_remote_shielded_validation_suite.py",
    "infra/btx-seed-server-spec.md",
}
missing_paths = sorted(required_paths - packet_paths)
if missing_paths:
    raise SystemExit(f"missing expected packet paths: {missing_paths}")

if summary["overall_status"] != "fail":
    raise SystemExit("expected placeholder intake summary to fail")
if not any("pending external input" in blocker for blocker in summary["blockers"]):
    raise SystemExit("expected placeholder blockers in packet-local m25 output")

rendered_manifest = json.dumps(manifest)
if "/Users/admin" in rendered_manifest or "/private/tmp/" in rendered_manifest:
    raise SystemExit("intake manifest still leaks creator-machine local paths")

packet_entry = next(
    (entry for entry in manifest["included_sources"] if entry["packet_path"] == "scripts/m25_shielded_external_closeout_check.py"),
    None,
)
if packet_entry is None:
    raise SystemExit("intake manifest missing m25 helper entry")
if packet_entry["source"] != "<repo>/scripts/m25_shielded_external_closeout_check.py":
    raise SystemExit(f"unexpected intake manifest source path: {packet_entry['source']!r}")
if packet_entry["copied_to"] != "scripts/m25_shielded_external_closeout_check.py":
    raise SystemExit(f"unexpected intake manifest copied_to path: {packet_entry['copied_to']!r}")

for hosted_manifest in [source_packet_hosted, direct_hosted]:
    step = hosted_manifest["steps"][0]
    if step["command"][2] != "~/.ssh/id_ed25519":
        raise SystemExit(f"unexpected sanitized ssh key token: {step['command'][2]!r}")
    if step["command"][3] != "source.tar.gz":
        raise SystemExit(f"unexpected sanitized source token: {step['command'][3]!r}")
    if step["cwd"] != "<repo>":
        raise SystemExit(f"unexpected sanitized cwd: {step['cwd']!r}")
    if step["log"] != "logs/source_upload.log":
        raise SystemExit(f"unexpected sanitized log path: {step['log']!r}")
    if hosted_manifest["artifacts"]["source_archive"]["path"] != "source.tar.gz":
        raise SystemExit("hosted manifest source_archive path was not sanitized")
    if hosted_manifest["artifacts"]["remote_extract_dir"] != "artifacts/remote_artifacts":
        raise SystemExit("hosted manifest remote_extract_dir was not sanitized")
    rendered = json.dumps(hosted_manifest)
    if "/Users/admin" in rendered or "/private/tmp/btx-m22-old" in rendered:
        raise SystemExit("hosted manifest still leaks creator-machine local paths")

for hosted_manifest in [source_packet_validation, direct_validation]:
    step = hosted_manifest["steps"][0]
    if step["command"][2] != "~/.ssh/id_ed25519":
        raise SystemExit(f"unexpected sanitized validation ssh key token: {step['command'][2]!r}")
    if hosted_manifest["artifacts"]["source_archive"]["path"] != "source.tar.gz":
        raise SystemExit("hosted validation manifest source_archive path was not sanitized")
    if hosted_manifest["artifacts"]["remote_extract_dir"] != "artifacts/remote_artifacts":
        raise SystemExit("hosted validation manifest remote_extract_dir was not sanitized")
    rendered = json.dumps(hosted_manifest)
    if "/Users/admin" in rendered or "/private/tmp/btx-m22-old" in rendered:
        raise SystemExit("hosted validation manifest still leaks creator-machine local paths")
PY

echo "m24_shielded_external_findings_intake_test: PASS"
