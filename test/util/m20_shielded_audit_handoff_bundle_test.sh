#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_PATH="${ROOT_DIR}/scripts/m20_shielded_audit_handoff_bundle.py"

python3 - "${SCRIPT_PATH}" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text(encoding="utf-8")

required_snippets = [
    "infra/btx-seed-server-spec.md",
    "generate_shielded_matrict_plus_transcript_corpus",
    "shielded_matrict_plus_tests,shielded_proof_adversarial_tests",
    "check_shielded_matrict_plus_transcripts.py",
    "m21_shielded_redteam_campaign.sh",
    "m22_remote_shielded_redteam_campaign.py",
    "m23_shielded_external_redteam_packet.py",
    "m24_shielded_external_findings_intake.py",
    "m25_shielded_external_closeout_check.py",
    "m26_remote_shielded_validation_suite.py",
    "btx-shielded-external-redteam-window.md",
    "btx-shielded-external-review-closeout.md",
    "feature_shielded_v2_proof_redteam_campaign.py",
    "\"redteam_campaign_artifact\"",
    "\"overall_status\": \"pass\"",
    "SHA256SUMS",
    "manifest.json",
    "tar_output_dir(",
    "unsupported source path outside repo root",
]

missing = [snippet for snippet in required_snippets if snippet not in text]
if missing:
    raise SystemExit(f"missing expected m20 handoff bundle logic: {missing}")
PY

python3 - "${SCRIPT_PATH}" <<'PY'
import importlib.util
import pathlib
import tempfile

path = pathlib.Path(__import__("sys").argv[1])
spec = importlib.util.spec_from_file_location("m20_bundle", path)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)

tmp_root = pathlib.Path(tempfile.mkdtemp(prefix="btx-m20-test-"))
output_dir = tmp_root / "bundle"
output_dir.mkdir()
manifest = {
    "repo_root": str(module.REPO_ROOT),
    "build_dir": str(module.REPO_ROOT / "build-btx"),
    "output_dir": str(output_dir),
    "commands": [
        {
            "command": [str(module.REPO_ROOT / "build-btx" / "bin" / "test_btx")],
            "cwd": str(module.REPO_ROOT),
            "log": str(output_dir / "logs" / "proof_suites.log"),
        }
    ],
    "source_files": [
        {
            "source": str(module.REPO_ROOT / "doc" / "btx-production-readiness-matrix.md"),
            "copied_to": str(output_dir / "source_snapshot" / "doc" / "btx-production-readiness-matrix.md"),
        },
        {
            "source": str(module.REPO_ROOT / "infra" / "btx-seed-server-spec.md"),
            "copied_to": str(output_dir / "source_snapshot" / "infra" / "btx-seed-server-spec.md"),
        },
    ],
    "artifacts": {
        "tarball": {
            "path": str(output_dir.parent / "bundle.tar.gz"),
        }
    },
}
sanitized = module.sanitize_manifest_value(output_dir, manifest)
if sanitized["repo_root"] != "<repo>":
    raise SystemExit(f"unexpected sanitized repo_root: {sanitized['repo_root']!r}")
if sanitized["build_dir"] != "<repo>/build-btx":
    raise SystemExit(f"unexpected sanitized build_dir: {sanitized['build_dir']!r}")
if sanitized["output_dir"] != ".":
    raise SystemExit(f"unexpected sanitized output_dir: {sanitized['output_dir']!r}")
command = sanitized["commands"][0]
if command["command"][0] != "<repo>/build-btx/bin/test_btx":
    raise SystemExit(f"unexpected sanitized command path: {command['command'][0]!r}")
if command["cwd"] != "<repo>":
    raise SystemExit(f"unexpected sanitized cwd: {command['cwd']!r}")
if command["log"] != "logs/proof_suites.log":
    raise SystemExit(f"unexpected sanitized log: {command['log']!r}")
if sanitized["source_files"][0]["source"] != "<repo>/doc/btx-production-readiness-matrix.md":
    raise SystemExit("repo snapshot source path was not sanitized")
if sanitized["source_files"][0]["copied_to"] != "source_snapshot/doc/btx-production-readiness-matrix.md":
    raise SystemExit("repo snapshot copied_to path was not relativized")
if sanitized["source_files"][1]["source"] != "<repo>/infra/btx-seed-server-spec.md":
    raise SystemExit("workspace snapshot source path was not sanitized")
if sanitized["source_files"][1]["copied_to"] != "source_snapshot/infra/btx-seed-server-spec.md":
    raise SystemExit("workspace snapshot copied_to path was not relativized")
if not sanitized["artifacts"]["tarball"]["path"].startswith("<tmp>/") or not sanitized["artifacts"]["tarball"]["path"].endswith("/bundle.tar.gz"):
    raise SystemExit(f"unexpected sanitized tarball path: {sanitized['artifacts']['tarball']['path']!r}")
PY

echo "m20_shielded_audit_handoff_bundle_test: PASS"
