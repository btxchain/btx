# Bridge View-Grants Readiness

This runbook is the focused production gate for bridge view grants. It covers
the wallet validation layer, RPC defaults, and the live two-container regtest
path that proves planned grants survive settlement and can be decrypted from
the mined transaction.

## Security Model

- Bridge plans without view grants remain byte-for-byte deterministic for the
  same bridge ids, keys, recipient, amount, refund height, and memo.
- Bridge plans with view grants use fresh ML-KEM encapsulation and AEAD nonce
  randomness for each grant. Reviewers should expect grant ciphertext,
  `view_grant_hex`, `ctv_hash`, and `plan_hex` to differ between otherwise
  identical grant-enabled planning calls.
- The decrypted structured-disclosure payload remains stable for equivalent
  requests. Tests must compare decrypted payloads, not ciphertext.
- Resolved operator view-grant requests are canonicalized after legacy pubkey
  expansion, policy grants, and duplicate merging. Equivalent request sets in
  different caller order should expose the same normalized grant order.
- Before the shielded privacy redesign activation, omitted formats and
  `operator_view_pubkeys` default to `legacy_audit`. After activation, omitted
  formats default to `structured_disclosure`, and explicit `legacy_audit`
  requires `allow_legacy_audit_view_grants=true`.

## Local Gate

Run the focused gate from the repository root:

```bash
BTX_BRIDGE_VIEWGRANTS_DOCKER_TIMEOUT_SECONDS=300 scripts/ci/run_ci_target.sh bridge-viewgrants
```

The target builds `btxd`, `btx-cli`, and `test_btx`, then runs:

- `build-btx/bin/test_btx --run_test=bridge_wallet_tests`
- `wallet_bridge_planin.py --descriptors`
- `wallet_bridge_viewgrant.py --descriptors`
- `wallet_bridge_happy_path.py wallet_bridge_batch_in.py --descriptors`
- `scripts/m12_docker_regtest_cluster.sh --build-image --timeout-seconds 300`

## Docker Artifact

The Docker harness writes `.btx-validation/m12-docker-regtest-cluster.json`.
A production-ready local pass should include:

- `overall_status: "pass"`
- bidirectional relay and confirmation phases completed
- `view_grants.status: "pass"`
- structured plan decrypt, mined-chain grant retrieval, and chain decrypt
- non-empty `view_grant_hex`
- a mined settlement txid and block hash
- recipient shielded balance equal to the planned bridge-in amount

If a stale trace log exists from an older failed local run, cite the fresh JSON
artifact and the final command output in the PR update.

## PR Update Checklist

When updating a PR that changes bridge view grants, include:

- the head commit SHA
- whether the branch is up to date with `origin/main`
- the security semantics: fresh grant encryption randomness plus canonicalized
  resolved request order
- the exact local gate command
- the Docker artifact path and the key pass fields above
