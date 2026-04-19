#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_PATH="${ROOT_DIR}/scripts/m22_remote_shielded_redteam_campaign.py"

python3 - "${SCRIPT_PATH}" <<'PY'
import ast
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
module = ast.parse(text, filename=str(path))

source_paths = None
for node in module.body:
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "SOURCE_PATHS":
                source_paths = ast.literal_eval(node.value)
                break
    if source_paths is not None:
        break

if source_paths is None:
    raise SystemExit("SOURCE_PATHS not found")

required_source_paths = {
    "cmake",
    "contrib",
    "doc",
    "scripts",
    "share",
    "src",
    "test",
}
missing_source_paths = sorted(required_source_paths.difference(source_paths))
if missing_source_paths:
    raise SystemExit(f"missing required source paths: {missing_source_paths}")

required_snippets = [
    "https://api.digitalocean.com/v2",
    "api.ipify.org",
    "m21_shielded_redteam_campaign.sh",
    "tarfile.open",
    "load_json_if_present",
    "cmake --build",
    "-DBUILD_CLI=ON",
    "bitcoin-cli",
    "generate_shielded_v2_adversarial_proof_corpus",
    "estimated_cost_usd",
    "remote_campaign_artifact_missing",
    "collection_errors",
    "remote red-team campaign failed after artifact collection",
    "/firewalls/",
    "/droplets/",
    "\"overall_status\": \"pass\"",
    "REPO_ROOT.parent / \"infra\" / \"digitalocean_api.key\"",
    "\"ssh_private_key_name\"",
    "sanitize_manifest_value",
    "manifest_display_path",
]

missing = [snippet for snippet in required_snippets if snippet not in text]
if missing:
    raise SystemExit(f"missing expected m22 remote redteam logic: {missing}")

if "/home/example/btxchain/infra/digitalocean_api.key" in text:
    raise SystemExit("m22 still hard-codes the creator-machine DigitalOcean token path")

if "\"ssh_private_key\"" in text:
    raise SystemExit("m22 still stores the absolute ssh private key path in its manifest")
PY

python3 - "${SCRIPT_PATH}" <<'PY'
import importlib.util
import json
import pathlib
import tempfile

path = pathlib.Path(__import__("sys").argv[1])
spec = importlib.util.spec_from_file_location("m22_remote", path)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)

tmp_root = pathlib.Path(tempfile.mkdtemp(prefix="btx-m22-test-"))
output_dir = tmp_root / "output"
output_dir.mkdir()
manifest = {
    "configuration": {
        "ssh_private_key_name": "id_ed25519",
    },
    "steps": [
        {
            "command": [
                "scp",
                "-i",
                str(pathlib.Path.home() / ".ssh" / "id_ed25519"),
                str(output_dir / "source.tar.gz"),
                "root@198.51.100.8:/root/upload.tar.gz",
            ],
            "cwd": str(module.REPO_ROOT),
            "log": str(output_dir / "logs" / "remote.log"),
        }
    ],
    "artifacts": {
        "source_archive": {
            "path": str(output_dir / "source.tar.gz"),
        },
        "remote_extract_dir": str(output_dir / "artifacts" / "remote_artifacts"),
    },
}
sanitized = module.sanitize_manifest_value(output_dir, manifest)
step = sanitized["steps"][0]
if step["cwd"] != "<repo>":
    raise SystemExit(f"unexpected sanitized cwd: {step['cwd']!r}")
if step["log"] != "logs/remote.log":
    raise SystemExit(f"unexpected sanitized log path: {step['log']!r}")
if step["command"][2] != "~/.ssh/id_ed25519":
    raise SystemExit(f"unexpected sanitized ssh key token: {step['command'][2]!r}")
if step["command"][3] != "source.tar.gz":
    raise SystemExit(f"unexpected sanitized local source token: {step['command'][3]!r}")
if step["command"][4] != "root@198.51.100.8:/root/upload.tar.gz":
    raise SystemExit("remote scp target should remain unchanged")
if sanitized["artifacts"]["source_archive"]["path"] != "source.tar.gz":
    raise SystemExit("artifact path was not relativized to the output dir")
if sanitized["artifacts"]["remote_extract_dir"] != "artifacts/remote_artifacts":
    raise SystemExit("artifact extract dir was not relativized to the output dir")
print(json.dumps(sanitized, indent=2))
PY

echo "m22_remote_shielded_redteam_campaign_test: PASS"
