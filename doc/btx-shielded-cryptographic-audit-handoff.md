# BTX Shielded Cryptographic Audit Handoff

## Purpose
This document defines reproducible conformance checks and audit entry points for BTX shielded proof code.
It is intended for external lattice-cryptography reviewers.

## Scope
- Ring signature implementation:
  - `src/shielded/ringct/ring_signature.cpp`
- Range proof implementation:
  - `src/shielded/ringct/range_proof.cpp`
- Balance proof implementation:
  - `src/shielded/ringct/balance_proof.cpp`
- Unified proof composition:
  - `src/shielded/ringct/matrict.cpp`

## Deterministic Conformance Vectors
The following vectors are asserted in unit tests.

1. Ring signature vector hash
- Test: `ringct_ring_signature_tests/deterministic_ring_signature_known_answer_vector`
- Expected serialized proof hash:
  - `9a9d71b49091bd82e7f2243e48bb55b19ec96bb8e5d1b46aa9c5d151bebb908a`

2. MatRiCT proof vector hash
- Test: `ringct_matrict_tests/deterministic_matrict_proof_known_answer_vector`
- Expected serialized proof hash:
  - `a8af6a6b2f97c11155300f04b58accec2bd0a3e41129282a4e872e58cf341263`

## Independent Transcript Corpus Checker
The tree now includes an out-of-band transcript checker for the MatRiCT+
Fiat-Shamir path.

- Corpus generator:
  - `src/test/generate_shielded_matrict_plus_transcript_corpus.cpp`
- Checker:
  - `test/reference/check_shielded_matrict_plus_transcripts.py`

The generator emits deterministic and seeded-randomized samples containing the
serialized ring-signature, balance-proof, range-proof, and top-level MatRiCT+
transcript inputs plus their expected challenge hashes. The Python checker
recomputes those transcript hashes without invoking the production verifier.

Reproduction:

```bash
cmake --build build --target generate_shielded_matrict_plus_transcript_corpus -j8
build/bin/gen_shielded_matrict_plus_transcript_corpus --samples=2 --output=/tmp/btx-matrict-plus-transcript-corpus.json
python3 test/reference/check_shielded_matrict_plus_transcripts.py /tmp/btx-matrict-plus-transcript-corpus.json
```

## Malformed-Proof Red-Team Campaign Harness
The tree now includes a reproducible malformed-proof campaign around a real
wallet-originated `v2_send`.

- Corpus generator:
  - `src/test/generate_shielded_v2_adversarial_proof_corpus.cpp`
- Corpus helper/tests:
  - `src/test/shielded_v2_adversarial_proof_corpus.cpp`
  - `src/test/shielded_v2_adversarial_proof_corpus_tests.cpp`
- Live functional:
  - `test/functional/feature_shielded_v2_proof_redteam_campaign.py`
- Operator wrapper:
  - `scripts/m21_shielded_redteam_campaign.sh`

The generator derives a deterministic malformed-proof corpus from the exact
wallet-built base tx, covering truncated payloads, appended junk, out-of-bounds
ring indexes, statement-digest mismatches, and post-parse ring-challenge
tampering. The functional replays those variants across a three-node mesh,
repeats the rejects after a late-joiner restart, and then mines the original
valid tx to prove the malformed campaign leaves no consensus or mempool residue.

Reproduction:

```bash
cmake --build build --target btxd test_btx generate_shielded_v2_adversarial_proof_corpus -j8
python3 test/functional/feature_shielded_v2_proof_redteam_campaign.py --cachedir="${TMPDIR:-/tmp}/btx-functional-manual/cache" --configfile=test/config.ini --tmpdir=/tmp/btx-functional-manual/feature-shielded-v2-proof-redteam --portseed=32260 --artifact=/tmp/btx-functional-manual/feature-shielded-v2-proof-redteam.artifact.json --corpus=/tmp/btx-functional-manual/feature-shielded-v2-proof-redteam.corpus.json
scripts/m21_shielded_redteam_campaign.sh --build-dir build-btx --artifact /tmp/btx-m21-redteam-campaign.json --log-dir /tmp/btx-m21-redteam-logs --cachedir "${TMPDIR:-/tmp}/btx-functional-manual/cache"
```

## Hosted Disposable Campaign Wrapper
The tree now also includes a repo-operated hosted wrapper that replays the same
malformed-proof campaign on disposable DigitalOcean infrastructure instead of a
local workstation.

- Hosted wrapper:
  - `scripts/m22_remote_shielded_redteam_campaign.py`
- Structural regression:
  - `test/util/m22_remote_shielded_redteam_campaign_test.sh`

The wrapper stages a bounded source snapshot, provisions a droplet/firewall,
installs build dependencies, configures a remote build with `btxd`,
`bitcoin-cli`, and `gen_shielded_v2_adversarial_proof_corpus`, runs
`scripts/m21_shielded_redteam_campaign.sh` remotely through its new
`--config-file` override, downloads the inner artifacts, and tears the
resources down. It now keeps collecting artifacts even if the inner `m21`
campaign exits nonzero, which is how the missing-`bitcoin-cli` pivot was
diagnosed and fixed.

Primary hosted reproduction command from repository root:

```bash
python3 scripts/m22_remote_shielded_redteam_campaign.py --output-dir /tmp/btx-m22-remote-redteam --admin-cidr 0.0.0.0/0
```

The default `--do-token-file` now resolves the repo-adjacent
`../infra/digitalocean_api.key` path when the harness is run from the normal
checkout. When running from an unpacked handoff snapshot or another workspace,
pass `--do-token-file` explicitly instead of relying on that default.

The resulting output directory contains:

- `manifest.json` with droplet/firewall ids, per-step timings, estimated cost,
  teardown confirmation, copied artifact paths rewritten relative to the local
  output directory or redacted to `<repo>` / `~/...` where appropriate, and
  only the SSH key basename rather than the creator-machine private-key path;
- `logs/remote_install.log`, `logs/remote_configure.log`,
  `logs/remote_build.log`, `logs/remote_campaign.log`,
  `logs/remote_bundle.log`, and `logs/artifact_download.log`;
- `artifacts/remote_artifacts/m21-remote-redteam.json`;
- `artifacts/remote_artifacts/m21-logs/feature_shielded_v2_proof_redteam_campaign.log`;
- `artifacts/remote_artifacts/m21-logs/feature_shielded_v2_proof_redteam_campaign.artifact.json`;
- `artifacts/remote_artifacts/m21-logs/feature_shielded_v2_proof_redteam_campaign.corpus.json`.

## Hosted Disposable Full Validation Suite
The tree now also includes a repo-operated hosted suite that combines the
simulated reset-network rehearsal, malformed-proof campaign, and the bounded
proof-size / TPS / chain-growth generators on disposable DigitalOcean
infrastructure.

- Hosted suite:
  - `scripts/m26_remote_shielded_validation_suite.py`
- Structural regression:
  - `test/util/m26_remote_shielded_validation_suite_test.sh`

Primary hosted validation command from repository root:

```bash
python3 scripts/m26_remote_shielded_validation_suite.py --output-dir /tmp/btx-m26-remote-validation-run --admin-cidr 0.0.0.0/0 --size s-4vcpu-8gb-amd --build-jobs 4
```

The suite stages a bounded source snapshot, provisions a droplet/firewall,
builds `btxd`, `bitcoin-cli`, and the report generators, runs
`scripts/m19_reset_launch_rehearsal.sh` and
`scripts/m21_shielded_redteam_campaign.sh` remotely, emits the send / ingress /
egress / netting / chain-growth reports, downloads the remote artifact bundle,
and tears the resources down. The first hosted pass exposed a real
`m19` config-path bug; after adding the explicit `--config-file` path, the
rerun passed with `remote_m19_launch_rehearsal=204.903s`,
`remote_m21_redteam_campaign=97.235s`, and `estimated_cost_usd=0.0278` with
both droplet and firewall deletion confirmed.

The resulting output directory contains:

- `manifest.json` with per-step timings, estimated cost, teardown results, and
  a `validation_summary` covering simulated-testnet, security-readiness, and
  proof-size / TPS findings;
- `artifacts/remote_artifacts/m19-reset-launch-rehearsal.json`;
- `artifacts/remote_artifacts/m21-remote-redteam.json`;
- `artifacts/remote_artifacts/reports/send_runtime_report.json`;
- `artifacts/remote_artifacts/reports/ingress_native_runtime_report.json`;
- `artifacts/remote_artifacts/reports/ingress_receipt_capacity_report.json`;
- `artifacts/remote_artifacts/reports/egress_runtime_report.json`;
- `artifacts/remote_artifacts/reports/netting_capacity_report.json`;
- `artifacts/remote_artifacts/reports/chain_growth_projection_report.json`.

## External Window Packet
The tree now also includes an operator/participant packet generator for an
invited external proof-focused red-team window.

- Packet generator:
  - `scripts/m23_shielded_external_redteam_packet.py`
- Structural regression:
  - `test/util/m23_shielded_external_redteam_packet_test.sh`
- Window guide:
  - `doc/btx-shielded-external-redteam-window.md`

Primary packet command from repository root:

```bash
python3 scripts/m23_shielded_external_redteam_packet.py --output-dir /tmp/btx-m23-external-redteam-packet --audit-bundle /tmp/btx-m20-audit-handoff-bundle --hosted-run-dir /tmp/btx-m22-remote-redteam-run9
python3 scripts/m23_shielded_external_redteam_packet.py --output-dir /tmp/btx-m23-external-redteam-packet --audit-bundle /tmp/btx-m20-audit-handoff-bundle --hosted-run-dir /tmp/btx-m22-remote-redteam-run9 --hosted-validation-dir /tmp/btx-m26-remote-validation-run2
```

The packet contains:

- `docs/participant_brief.md`;
- `docs/operator_checklist.md`;
- copied handoff docs, the external closeout guide, and the seed-server spec,
  preserving repo-relative `doc/`, `scripts/`, and `infra/` paths inside the
  unpacked packet;
- copied downstream intake / closeout helpers:
  - `scripts/m24_shielded_external_findings_intake.py`
  - `scripts/m25_shielded_external_closeout_check.py`
- optional copied `m20` audit bundle artifacts;
- optional copied `m22` hosted-run artifacts;
- optional copied `m26` hosted simulated-testnet / proof-size / TPS artifacts;
- `manifest.json`, `SHA256SUMS`, and a sibling `.tar.gz`.

## External Findings Intake And Closeout
The tree now also includes a standard intake/closeout packet generator for the
results that come back from external reviewers or an external proof-focused
campaign.

- Intake generator:
  - `scripts/m24_shielded_external_findings_intake.py`
- Structural regression:
  - `test/util/m24_shielded_external_findings_intake_test.sh`
- Closeout guide:
  - `doc/btx-shielded-external-review-closeout.md`

Primary intake command from repository root:

```bash
python3 scripts/m24_shielded_external_findings_intake.py --output-dir /tmp/btx-m24-external-findings-intake --source-packet /tmp/btx-m23-external-redteam-packet --audit-bundle /tmp/btx-m20-audit-handoff-bundle --hosted-run-dir /tmp/btx-m22-remote-redteam-run9
python3 scripts/m24_shielded_external_findings_intake.py --output-dir /tmp/btx-m24-external-findings-intake --source-packet /tmp/btx-m23-external-redteam-packet --audit-bundle /tmp/btx-m20-audit-handoff-bundle --hosted-run-dir /tmp/btx-m22-remote-redteam-run9 --hosted-validation-dir /tmp/btx-m26-remote-validation-run2
```

The intake packet contains:

- copied handoff / readiness / tracker / external-window / closeout docs,
  preserving repo-relative `doc/`, `scripts/`, and `infra/` paths inside the
  unpacked packet;
- copied downstream closeout validator:
  - `scripts/m25_shielded_external_closeout_check.py`;
- copied hosted baseline references when supplied:
  - malformed-proof `m22` runs under `source_refs/m22_hosted_run/`
  - full hosted `m26` runs under `source_refs/m26_hosted_validation/`
- `templates/finding_template.md`;
- `templates/session_report_template.md`;
- `templates/signoff_checklist.md`;
- `templates/findings_template.json`;
- `received/findings.json`;
- `received/reports/external_cryptographic_review.md`;
- `received/reports/external_redteam_report.md`;
- `closeout/finding_resolution_log.md`;
- `closeout/signoff_record.md`;
- `closeout/signoff_status.json`;
- `received/` for returned external reports, logs, corpora, and traces;
- `manifest.json`, `SHA256SUMS`, and a sibling `.tar.gz`.

## External Closeout Validator
The tree now also includes a deterministic validator for a populated external
findings-intake packet.

- Closeout validator:
  - `scripts/m25_shielded_external_closeout_check.py`
- Structural regression:
  - `test/util/m25_shielded_external_closeout_check_test.sh`

Primary closeout command from repository root:

```bash
python3 scripts/m25_shielded_external_closeout_check.py --intake-dir /tmp/btx-m24-external-findings-intake
```

The validator checks that:

- the required returned-review files exist;
- `received/findings.json` is no longer in the pending placeholder state;
- `closeout/signoff_status.json` marks both external review legs complete;
- no unresolved critical or high-severity findings remain; and
- placeholder closeout markdown has been replaced by real operator sign-off.

## One-Command Handoff Bundle
The tree now includes a single operator-facing bundle generator that packages
the transcript corpus, independent checker results, adversarial proof-suite
logs, malformed-proof red-team campaign evidence, and the exact source/doc
snapshot needed for external review.

- Bundle generator:
  - `scripts/m20_shielded_audit_handoff_bundle.py`
- Structural regression:
  - `test/util/m20_shielded_audit_handoff_bundle_test.sh`

Primary handoff command from repository root:

```bash
python3 scripts/m20_shielded_audit_handoff_bundle.py --build-dir build-btx --output-dir /tmp/btx-m20-audit-handoff-bundle --skip-build --samples=2
```

The output directory and sibling tarball contain:

- `manifest.json` with exact commands, per-step runtimes, copied inputs, and
  final artifact paths;
- `SHA256SUMS` for the emitted corpus, copied snapshot files, and bundle
  tarball;
- `artifacts/matrict_plus_transcript_corpus.json`;
- `artifacts/shielded_v2_proof_redteam_campaign.json`;
- `logs/proof_suites.log`, `logs/transcript_corpus_generation.log`, and
  `logs/transcript_checker.log`;
- `logs/redteam_wrapper.log` plus
  `logs/redteam_campaign/build.log`,
  `logs/redteam_campaign/feature_shielded_v2_proof_redteam_campaign.log`,
  `logs/redteam_campaign/feature_shielded_v2_proof_redteam_campaign.artifact.json`,
  and
  `logs/redteam_campaign/feature_shielded_v2_proof_redteam_campaign.corpus.json`;
- `source_snapshot/` copies of the proof-suite sources, transcript checker,
  malformed-proof campaign sources, the hosted/external packet and closeout
  scripts (`m22` through `m26`), their structural regressions, the audit
  handoff doc, the external red-team window guide, the external closeout
  guide, the production readiness matrix, the seed-server spec under
  `source_snapshot/infra/btx-seed-server-spec.md`, and the tracker entry used
  for the run.

## Reproduction Commands
From repository root:

```bash
cmake --build build --target test_btx -j8
build/bin/test_btx --run_test=ringct_ring_signature_tests/deterministic_ring_signature_known_answer_vector:ringct_matrict_tests/deterministic_matrict_proof_known_answer_vector
```

Full shielded/regression verification:

```bash
build/bin/test_btx --run_test=ringct_ring_signature_tests,ringct_matrict_tests,ringct_range_proof_tests,ringct_balance_proof_tests,shielded_validation_checks_tests,shielded_tx_check_tests,shielded_tx_verify_tests,shielded_mempool_tests,shielded_transaction_tests
python3 build/test/functional/test_runner.py wallet_shielded_send_flow.py wallet_shielded_restart_persistence.py wallet_shielded_reorg_recovery.py wallet_shielded_viewingkey_rescan.py wallet_shielded_encrypted_persistence.py p2p_shielded_relay.py
cd build && ctest --output-on-failure -j8
```

## Required External Review Focus Areas
- Ring-signature security proof alignment versus MatRiCT+/ePrint 2021/545 assumptions.
- Rejection sampling and response-distribution leakage risks.
- Key-image/nullifier linkage soundness and unforgeability assumptions.
- Parameter soundness (`RING_SIZE`, `MODULE_RANK`, `BETA_CHALLENGE`, `GAMMA_RESPONSE`).
- Constant-time behavior and side-channel exposure in proof generation/verification.

## Current Status
- Deterministic conformance vectors are now available and enforced in CI unit tests.
- Independent transcript-corpus generation and transcript-hash checking are now
  available for deterministic and seeded-randomized MatRiCT+ statements
  without reusing the production verifier path.
- A one-command external-review handoff bundle generator is now available to
  package the current transcript, malformed-proof campaign, adversarial-proof,
  and source/doc evidence into a reproducible tarball with checksums and a
  machine-readable manifest.
- A hosted disposable repo-operated malformed-proof campaign wrapper is now
  available to reproduce the same rejection flow on ephemeral DigitalOcean
  infrastructure with machine-readable cost, timing, artifact, and teardown
  evidence.
- An external red-team window packet generator is now available to hand
  external participants a bounded attack brief, operator checklist, copied
  handoff docs, and optional baseline artifacts from the latest `m20` and
  `m22` runs.
- An external findings intake / closeout packet generator is now available to
  normalize returned reports, artifacts, remediation tracking, and the final
  DoD 8 sign-off record once those external processes finish.
- An external closeout validator is now available to turn a populated intake
  packet into a machine-readable pass/fail DoD 8 closeout summary.
- Ring signature witness secrets are now note-bound (`spending_key || real_ring_member`)
  to avoid cross-input signer key reuse under public-key offsets.
- Ring member sets now reject null and duplicate entries during signing and verification.
- Ring challenge decomposition now uses rejection-rehash without fallback modulo mapping.
- Secret coefficient bounds are tightened (`eta=2`) to reduce impossible-response rejection behavior.
- Signing wipes derived witness vectors from memory via `memory_cleanse`.
- External independent cryptographic audit and an externally observed
  proof-focused adversarial testnet / red-team campaign are still required for
  production sign-off; the in-tree harnesses here are prerequisites and
  reviewer aids, not substitutes for those gates.
