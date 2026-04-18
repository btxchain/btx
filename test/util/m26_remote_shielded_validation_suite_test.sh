#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_PATH="${ROOT_DIR}/scripts/m26_remote_shielded_validation_suite.py"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/btx-m26-suite-test.XXXXXX")"
trap 'rm -rf "${TMP_ROOT}"' EXIT

python3 - "${SCRIPT_PATH}" <<'PY'
import ast
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
module = ast.parse(text, filename=str(path))

build_targets = None
for node in module.body:
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "BUILD_TARGETS":
                build_targets = ast.literal_eval(node.value)
                break
    if build_targets is not None:
        break

if build_targets is None:
    raise SystemExit("BUILD_TARGETS not found")

required_targets = {
    "btxd",
    "bitcoin-cli",
    "generate_shielded_v2_adversarial_proof_corpus",
    "generate_shielded_relay_fixture_tx",
    "generate_shielded_v2_send_runtime_report",
    "generate_shielded_ingress_proof_runtime_report",
    "generate_shielded_v2_egress_runtime_report",
    "generate_shielded_v2_netting_capacity_report",
    "generate_shielded_v2_chain_growth_projection_report",
}
missing_targets = sorted(required_targets.difference(build_targets))
if missing_targets:
    raise SystemExit(f"missing required build targets: {missing_targets}")

required_snippets = [
    "m19_reset_launch_rehearsal.sh",
    "m21_shielded_redteam_campaign.sh",
    "send_runtime_report",
    "ingress_native_runtime_report",
    "ingress_receipt_capacity_report",
    "egress_runtime_report",
    "netting_capacity_report",
    "chain_growth_projection_report",
    "summarize_suite(",
    "\"estimated_cost_usd\"",
    "\"planned_suite\"",
    "\"proof_size_and_tps\"",
    "M22_REMOTE_MODULE.persist_manifest",
]
missing_snippets = [snippet for snippet in required_snippets if snippet not in text]
if missing_snippets:
    raise SystemExit(f"missing expected m26 hosted suite logic: {missing_snippets}")
PY

python3 "${SCRIPT_PATH}" \
    --output-dir "${TMP_ROOT}/suite" \
    --admin-cidr "0.0.0.0/0" \
    --dry-run \
    >/dev/null

python3 - "${TMP_ROOT}/suite/manifest.json" <<'PY'
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if manifest["overall_status"] != "dry_run":
    raise SystemExit(f"unexpected dry-run status: {manifest['overall_status']!r}")
if manifest["resources"]["droplet_name"] == manifest["resources"]["firewall_name"]:
    raise SystemExit("dry-run manifest should use distinct droplet/firewall names")
planned = set(manifest["planned_suite"])
required = {
    "m19_reset_launch_rehearsal",
    "m21_shielded_redteam_campaign",
    "send_runtime_report",
    "ingress_native_runtime_report",
    "ingress_receipt_capacity_report",
    "egress_runtime_report",
    "netting_capacity_report",
    "chain_growth_projection_report",
}
missing = sorted(required - planned)
if missing:
    raise SystemExit(f"dry-run manifest missing planned suite items: {missing}")
if manifest["configuration"]["send_scenarios"] != "1x2,2x2,2x4":
    raise SystemExit("unexpected default send scenarios in dry-run manifest")
if manifest["configuration"]["ingress_receipt_leaf_counts"] != "100,1000,5000,10000":
    raise SystemExit("unexpected default ingress receipt sweep in dry-run manifest")
PY

python3 - "${SCRIPT_PATH}" <<'PY'
import importlib.util
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("m26_suite", path)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)

summary = module.summarize_suite(
    {
        "overall_status": "pass",
        "launch_rehearsal": {
            "overall_status": "pass",
            "runtime_seconds": 197.441,
            "final_height": 402,
            "bestblockhash": "abc123",
        },
    },
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    {"cadence": {"block_interval_seconds": 90}, "workloads": []},
)

simulated = summary["simulated_testnet"]
if simulated["overall_status"] != "pass":
    raise SystemExit(f"unexpected simulated-testnet status: {simulated['overall_status']!r}")
if simulated["runtime_seconds"] != 197.441:
    raise SystemExit(f"unexpected simulated-testnet runtime: {simulated['runtime_seconds']!r}")
if simulated["final_height"] != 402:
    raise SystemExit(f"unexpected simulated-testnet final_height: {simulated['final_height']!r}")
if simulated["bestblockhash"] != "abc123":
    raise SystemExit(f"unexpected simulated-testnet bestblockhash: {simulated['bestblockhash']!r}")
PY

echo "m26_remote_shielded_validation_suite_test: PASS"
