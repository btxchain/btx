#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_PATH="${ROOT_DIR}/scripts/m23_shielded_external_redteam_packet.py"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/btx-m23-packet-test.XXXXXX")"
PACKET_DIR="${TMP_ROOT}/packet"
INTAKE_DIR="${TMP_ROOT}/intake"
AUX_AUDIT_DIR="${TMP_ROOT}/audit_src"
AUX_HOSTED_DIR="${TMP_ROOT}/hosted_src"
AUX_HOSTED_VALIDATION_DIR="${TMP_ROOT}/hosted_validation_src"
trap 'rm -rf "${TMP_ROOT}"' EXIT

mkdir -p "${AUX_AUDIT_DIR}" "${AUX_HOSTED_DIR}" "${AUX_HOSTED_VALIDATION_DIR}"
printf 'audit bundle fixture\n' > "${AUX_AUDIT_DIR}/README.txt"
printf 'hosted run fixture\n' > "${AUX_HOSTED_DIR}/README.txt"
printf 'hosted validation fixture\n' > "${AUX_HOSTED_VALIDATION_DIR}/README.txt"
python3 - "${AUX_HOSTED_DIR}/manifest.json" "${AUX_HOSTED_VALIDATION_DIR}/manifest.json" <<'PY'
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
    --output-dir "${PACKET_DIR}" \
    --audit-bundle "${AUX_AUDIT_DIR}" \
    --hosted-run-dir "${AUX_HOSTED_DIR}" \
    --hosted-validation-dir "${AUX_HOSTED_VALIDATION_DIR}" \
    >/dev/null

test -f "${PACKET_DIR}/scripts/m24_shielded_external_findings_intake.py"
test -f "${PACKET_DIR}/scripts/m25_shielded_external_closeout_check.py"
test -f "${PACKET_DIR}/scripts/m26_remote_shielded_validation_suite.py"
test -f "${PACKET_DIR}/doc/btx-shielded-external-review-closeout.md"
test -f "${PACKET_DIR}/infra/btx-seed-server-spec.md"
test -f "${PACKET_DIR}/artifacts/audit_bundle/README.txt"
test -f "${PACKET_DIR}/artifacts/hosted_run/README.txt"
test -f "${PACKET_DIR}/artifacts/hosted_run/manifest.json"
test -f "${PACKET_DIR}/artifacts/hosted_validation/README.txt"
test -f "${PACKET_DIR}/artifacts/hosted_validation/manifest.json"
test ! -e "${PACKET_DIR}/docs/m24_shielded_external_findings_intake.py"
test ! -e "${PACKET_DIR}/docs/m25_shielded_external_closeout_check.py"

python3 "${PACKET_DIR}/scripts/m24_shielded_external_findings_intake.py" \
    --output-dir "${INTAKE_DIR}" \
    --source-packet "${PACKET_DIR}" \
    --audit-bundle "${PACKET_DIR}/artifacts/audit_bundle" \
    --hosted-run-dir "${PACKET_DIR}/artifacts/hosted_run" \
    --hosted-validation-dir "${PACKET_DIR}/artifacts/hosted_validation" \
    >/dev/null

set +e
python3 "${INTAKE_DIR}/scripts/m25_shielded_external_closeout_check.py" \
    --intake-dir "${INTAKE_DIR}" \
    --output "${INTAKE_DIR}/closeout/closeout_summary.json" \
    >"${TMP_ROOT}/m25.stdout" 2>"${TMP_ROOT}/m25.stderr"
rc=$?
set -e

if [ "${rc}" -eq 0 ]; then
    echo "expected packet-derived m25 closeout check to fail on placeholder intake" >&2
    exit 1
fi

python3 - "${PACKET_DIR}/manifest.json" "${INTAKE_DIR}/manifest.json" "${INTAKE_DIR}/closeout/closeout_summary.json" "${PACKET_DIR}/docs/participant_brief.md" "${PACKET_DIR}/docs/operator_checklist.md" "${PACKET_DIR}/doc/btx-shielded-external-redteam-window.md" "${PACKET_DIR}/artifacts/hosted_run/manifest.json" "${PACKET_DIR}/artifacts/hosted_validation/manifest.json" "${TMP_ROOT}" <<'PY'
import json
import pathlib
import sys

packet_manifest = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
intake_manifest = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
summary = json.loads(pathlib.Path(sys.argv[3]).read_text(encoding="utf-8"))
participant_brief = pathlib.Path(sys.argv[4]).read_text(encoding="utf-8")
operator_checklist = pathlib.Path(sys.argv[5]).read_text(encoding="utf-8")
window_guide = pathlib.Path(sys.argv[6]).read_text(encoding="utf-8")
hosted_manifest = json.loads(pathlib.Path(sys.argv[7]).read_text(encoding="utf-8"))
hosted_validation_manifest = json.loads(pathlib.Path(sys.argv[8]).read_text(encoding="utf-8"))
tmp_root = sys.argv[9]

packet_paths = {entry["packet_path"] for entry in packet_manifest["included_sources"]}
required_packet_paths = {
    "doc/btx-shielded-external-redteam-window.md",
    "doc/btx-shielded-external-review-closeout.md",
    "infra/btx-seed-server-spec.md",
    "scripts/m24_shielded_external_findings_intake.py",
    "scripts/m25_shielded_external_closeout_check.py",
    "scripts/m26_remote_shielded_validation_suite.py",
}
missing_packet_paths = sorted(required_packet_paths - packet_paths)
if missing_packet_paths:
    raise SystemExit(f"missing expected packet paths: {missing_packet_paths}")

intake_paths = {entry["packet_path"] for entry in intake_manifest["included_sources"]}
required_intake_paths = {
    "doc/btx-shielded-external-review-closeout.md",
    "infra/btx-seed-server-spec.md",
    "scripts/m24_shielded_external_findings_intake.py",
    "scripts/m25_shielded_external_closeout_check.py",
}
missing_intake_paths = sorted(required_intake_paths - intake_paths)
if missing_intake_paths:
    raise SystemExit(f"missing expected derived intake paths: {missing_intake_paths}")

if summary["overall_status"] != "fail":
    raise SystemExit("expected placeholder derived intake summary to fail")

rendered_packet_manifest = json.dumps(packet_manifest)
if "/Users/admin" in rendered_packet_manifest or tmp_root in rendered_packet_manifest:
    raise SystemExit("packet manifest still leaks creator-machine local paths")

packet_entry = next(
    (entry for entry in packet_manifest["included_sources"] if entry["packet_path"] == "scripts/m24_shielded_external_findings_intake.py"),
    None,
)
if packet_entry is None:
    raise SystemExit("packet manifest missing m24 helper entry")
if packet_entry["source"] != "<repo>/scripts/m24_shielded_external_findings_intake.py":
    raise SystemExit(f"unexpected packet manifest source path: {packet_entry['source']!r}")
if packet_entry["copied_to"] != "scripts/m24_shielded_external_findings_intake.py":
    raise SystemExit(f"unexpected packet manifest copied_to path: {packet_entry['copied_to']!r}")

required_refs = [
    "Audit handoff bundle: `artifacts/audit_bundle/`",
    "Hosted malformed-proof baseline: `artifacts/hosted_run/`",
    "Hosted simulated-testnet / proof-size / TPS baseline: `artifacts/hosted_validation/`",
    "Review `infra/btx-seed-server-spec.md`",
]
for ref in required_refs:
    if ref not in participant_brief and ref not in operator_checklist:
        raise SystemExit(f"missing expected relative packet reference: {ref}")

for text in [participant_brief, operator_checklist, window_guide]:
    if tmp_root in text or "/Users/admin/Documents/btxchain/infra/" in text:
        raise SystemExit("creator-machine absolute path leaked into packet docs")

if "infra/btx-seed-server-spec.md" not in window_guide:
    raise SystemExit("packet window guide no longer points at bundled infra spec")

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
if "/Users/admin" in json.dumps(hosted_manifest) or "/private/tmp/btx-m22-old" in json.dumps(hosted_manifest):
    raise SystemExit("hosted manifest still leaks creator-machine local paths")

validation_step = hosted_validation_manifest["steps"][0]
if validation_step["command"][2] != "~/.ssh/id_ed25519":
    raise SystemExit(f"unexpected sanitized validation ssh key token: {validation_step['command'][2]!r}")
if hosted_validation_manifest["artifacts"]["source_archive"]["path"] != "source.tar.gz":
    raise SystemExit("hosted validation manifest source_archive path was not sanitized")
if hosted_validation_manifest["artifacts"]["remote_extract_dir"] != "artifacts/remote_artifacts":
    raise SystemExit("hosted validation manifest remote_extract_dir was not sanitized")
if "/Users/admin" in json.dumps(hosted_validation_manifest) or "/private/tmp/btx-m22-old" in json.dumps(hosted_validation_manifest):
    raise SystemExit("hosted validation manifest still leaks creator-machine local paths")
PY

echo "m23_shielded_external_redteam_packet_test: PASS"
