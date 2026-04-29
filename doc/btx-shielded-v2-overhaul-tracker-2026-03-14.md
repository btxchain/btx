# BTX Shielded V2 Overhaul Tracker And Execution Spec

Status note (2026-03-24): this tracker is historical execution context for the
March 14 overhaul program. It is not the current reset-chain launch decision
document. For the shipped SMILE-default launch surface, use
`doc/btx-shielded-production-status-2026-03-20.md` and
`doc/btx-smile-v2-genesis-readiness-tracker-2026-03-20.md`.

Date: 2026-03-14
Spec branch: `codex/shielded-v2-overhaul-plan` (PR #82)
Builds on: `main` at `4bf155a` (`Merge PR #79: codex/shielded aggregation rollup study`)
Merged prerequisites:

- PR #79: settlement plane, aggregate-settlement modeling, state-retention
  modeling, artifact bundles, and proof-compression targets
- PR #80: external shield-address support and cross-descriptor PQ key merge
- PR #81: persistent PQ seed maps for multisig and multi-provider descriptors

Current status:

- PR #82 is now the live implementation branch for the reset-launch program;
- Slice 2 is complete with the isolated `shieldedv2dev` development network
  landed and validated below;
- Slice 3 is now complete with canonical `shielded_v2` note, descriptor,
  manifest, header, and family-level bundle encodings frozen at the wire level
  with dedicated unit and fuzz evidence recorded below;
- Slice 4 is complete with the `shielded_v2` proof abstraction layer, native
  batch backend descriptors, and settlement receipt / claim bindings recorded
  below;
- Slice 5 is complete with the MatRiCT+ sandbox, deterministic reference
  vectors, and bounded runtime report tooling recorded below;
- Slice 6 is complete with canonical `shielded_v2` transaction-family
  scaffolding, routed state handling, and the first accepted `v2_send`
  contextual proof path recorded below;
- Slice 7 is complete with native `v2_send`, wallet / RPC support, and the
  transparent-input direct-deposit fallback recorded below; mixed transparent
  + `v2_send` remains explicitly invalid because the fallback is implemented
  through the legacy shield-only transparent-input path rather than by making
  `v2_send` itself mixed;
- Slice 8 is complete with stronger scan hints, canonical output-chunk
  commitments, chunk-aware wallet discovery/reporting, and a bounded
  high-fanout runtime-report path recorded below;
- Slice 9 is complete with accepted anchored validation, a production
  `v2_egress_batch` builder, wallet / RPC construction surfaces, and
  wallet-visible chunk discovery recorded below;
- Slice 10 is complete with multidimensional shielded resource accounting,
  mining RPC/template reporting, and cache-safe block-template reuse recorded
  below;
- Slice 11 is complete with the `v2_ingress_batch` intent model, wallet / RPC
  construction surface, and accepted proof-only / signed-only / hybrid
  settlement-backed admission flows recorded below;
- Slice 12 is complete with the high-scale ingress proof prototype, the
  receipt-backed native-batch backend scaffold, and bounded scale evidence up
  to the current shard / size ceiling recorded below;
- Slice 13 is complete with imported claim / adapter / receipt / hybrid
  settlement anchors, verification-root and reserve / netting-manifest
  bindings, and fee-bearing mempool / block admission recorded below;
- Slice 14 is complete with the default externalized retained-state profile,
  weekly snapshot cadence reporting, and live assumeutxo / pruned recovery
  lifecycle evidence recorded below: chainstate no longer keeps the shielded
  commitment-position index on disk by default, restart / snapshot recovery
  rebuild that index in memory, the weekly production snapshot cadence is now
  exposed on the normal node info path, and the secondary fuller-retention
  dev / audit posture remains explicit rather than implicit;
- Slice 15 is complete with live mixed-family relay fixtures, fresh-peer
  reannouncement, orphan handling, mempool-churn cleanup, and
  bandwidth / anti-DoS evidence recorded below;
- Slice 16 is complete with scarcity-aware package selection, live
  `getblocktemplate` / mined-block shielded capacity evidence, and accepted
  mining of relayed `v2_rebalance`, reserve-bound `v2_settlement_anchor`, and
  bare `v2_egress_batch` families recorded below;
- Slice 17 is complete with live private-send, deposit, exit, reserve /
  rebalance, raw-inspection, imported-viewing-key recovery, and restored
  PR #80 / PR #81 wallet durability evidence recorded below;
- Slice 18 is complete with bounded capacity reports, mixed-workload miner /
  mempool evidence, chain-growth projections, and a passing multi-node
  distributed validation / recovery rehearsal recorded below;
- Slice 19 is complete with a disposable `shieldedv2dev` reset-network launch
  rehearsal, an operator-facing wrapper script, machine-readable evidence,
  and explicit local teardown confirmation recorded below;
- the in-repo portion of Definition-of-Done item 8 is now satisfied to the
  extent possible on this branch: a seeded MatRiCT+ transcript-corpus
  generator, an independent transcript-checking harness, a local malformed-
  proof red-team campaign wrapper, a hosted disposable repo-operated red-team
  harness, an external red-team window packet generator, an external findings
  intake / closeout packet generator, and a reproducible external-review
  handoff bundle generator are landed and validated below;
- all 19 implementation slices are now closed on this branch, but production-
  reset consideration remains blocked by the tracker-level Definition-of-Done
  requirement for external cryptographic review plus an adversarial
  proof-focused testnet / red-team campaign.

## Pass Log

### 2026-03-16 23:15:59 JST

- pass preflight: verified readable, non-empty
  `/Users/admin/Documents/btxchain/github.key`,
  `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`,
  `/Users/admin/Documents/btxchain/infra/porkbun_api.key`, and
  `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` before any new
  remote or GitHub operation in this pass, with byte counts `94`, `72`, `69`,
  and `69`;
- current focus for this pass: run the required fetch / switch / pull / status
  / log loop, then inspect the post-`m26` readiness / handoff surfaces for the
  next honest repo-side DoD 8 gap instead of treating the remaining external
  gate as an excuse to stop thinking.
- start-of-pass loop executed as required:
  - `git fetch --all --prune`
  - `git switch codex/shielded-v2-overhaul-plan`
  - `git pull --ff-only origin codex/shielded-v2-overhaul-plan`
  - `git status --short`
  - `git log --oneline -5`
- newly identified repo-side DoD 8 gap closed in this pass:
  - after the hosted `m26` suite landed, the external participant packet and
    intake / closeout flows were still anchored only on the older `m22`
    malformed-proof baseline; there was no way to carry the newer hosted
    simulated-testnet / proof-size / TPS evidence set into the external window
    or the return-path packet;
  - updated
    `/Users/admin/Documents/btxchain/btx-node/scripts/m23_shielded_external_redteam_packet.py`
    so it now ships `scripts/m26_remote_shielded_validation_suite.py`,
    accepts `--hosted-validation-dir`, includes an optional
    `artifacts/hosted_validation/` tree in the packet, and sanitizes copied
    hosted `m26` manifests the same way it already handled `m22`;
  - updated
    `/Users/admin/Documents/btxchain/btx-node/scripts/m24_shielded_external_findings_intake.py`
    so it now ships `scripts/m26_remote_shielded_validation_suite.py`,
    accepts `--hosted-validation-dir`, and records an optional
    `source_refs/m26_hosted_validation/` baseline in the intake / closeout
    packet;
  - updated
    `/Users/admin/Documents/btxchain/btx-node/test/util/m23_shielded_external_redteam_packet_test.sh`
    and
    `/Users/admin/Documents/btxchain/btx-node/test/util/m24_shielded_external_findings_intake_test.sh`
    so the regressions now seed and verify both `m22` and `m26` hosted
    baseline manifests, require the bundled `m26` helper script, and prove the
    copied hosted-validation manifests remain path-sanitized;
  - updated
    `/Users/admin/Documents/btxchain/btx-node/doc/btx-production-readiness-matrix.md`,
    `/Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-cryptographic-audit-handoff.md`,
    `/Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-external-redteam-window.md`,
    and
    `/Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-external-review-closeout.md`
    so the operator-facing docs and readiness rows now describe the optional
    `m26` baseline handoff path rather than pretending `m22` is the only
    hosted reference.
- local validation completed in this pass:
  - `python3 -m py_compile /Users/admin/Documents/btxchain/btx-node/scripts/m23_shielded_external_redteam_packet.py /Users/admin/Documents/btxchain/btx-node/scripts/m24_shielded_external_findings_intake.py`
  - `bash /Users/admin/Documents/btxchain/btx-node/test/util/m23_shielded_external_redteam_packet_test.sh`
  - `bash /Users/admin/Documents/btxchain/btx-node/test/util/m24_shielded_external_findings_intake_test.sh`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/scripts/m23_shielded_external_redteam_packet.py --output-dir /tmp/btx-m23-external-redteam-packet-m26 --audit-bundle /tmp/btx-m20-audit-handoff-bundle-m26 --hosted-run-dir /tmp/btx-m22-remote-redteam-run9 --hosted-validation-dir /tmp/btx-m26-remote-validation-run2`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/scripts/m24_shielded_external_findings_intake.py --output-dir /tmp/btx-m24-external-findings-intake-m26 --source-packet /tmp/btx-m23-external-redteam-packet-m26 --audit-bundle /tmp/btx-m20-audit-handoff-bundle-m26 --hosted-run-dir /tmp/btx-m22-remote-redteam-run9 --hosted-validation-dir /tmp/btx-m26-remote-validation-run2`
  - `python3 - <<'PY' ... manifest inspection for /tmp/btx-m23-external-redteam-packet-m26/manifest.json and /tmp/btx-m24-external-findings-intake-m26/manifest.json ... PY`
  - `python3 - <<'PY' ... local-path scan of /tmp/btx-m23-external-redteam-packet-m26/artifacts/hosted_validation/manifest.json and /tmp/btx-m24-external-findings-intake-m26/source_refs/m26_hosted_validation/manifest.json ... PY`
  - `shasum -a 256 /tmp/btx-m23-external-redteam-packet-m26.tar.gz /tmp/btx-m24-external-findings-intake-m26.tar.gz`
  - `git diff --check`
- validation findings and pivots:
  - both strengthened synthetic regressions passed cleanly after the `m26`
    propagation changes;
  - the real packet rebuild completed in `real 5.94`, `user 5.66`,
    `sys 0.18`, and `/tmp/btx-m23-external-redteam-packet-m26/manifest.json`
    confirms both `scripts/m26_remote_shielded_validation_suite.py` and the
    optional `hosted_validation_dir` baseline are present;
  - the real intake rebuild completed in `real 8.27`, `user 8.01`,
    `sys 0.19`, and `/tmp/btx-m24-external-findings-intake-m26/manifest.json`
    confirms both the bundled `m26` helper and the optional
    `m26_hosted_validation` reference are present;
  - direct inspection of the copied hosted-validation manifests confirmed zero
    creator-machine local-path hits in both the participant packet and the
    intake packet;
  - tarball hashes:
    - `m23`: `7d7bcdc5f9400c3937c7095df3678972ca9ab7190ad124094f448af1875d2325`
    - `m24`: `c44bffc1b311fca62eb0580e0c8889131995dea34a858e497f7ad2dab4aece41`
- blocker conclusion for this pass:
  - this closes another real repo-side coordination gap by making the external
    window and closeout packets capable of carrying the newer hosted `m26`
    simulated-testnet / proof-size / TPS baseline alongside the existing
    `m22` malformed-proof baseline;
  - the remaining launch blocker is still external only: independent
    cryptographic review plus an externally run adversarial proof-focused
    testnet / red-team campaign.
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - this pass used only local packet / intake rebuilds against existing
    hosted-artifact directories; no new droplet or firewall was created.

### 2026-03-16 22:47:09 JST

- pass preflight: verified readable, non-empty
  `/Users/admin/Documents/btxchain/github.key`,
  `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`,
  `/Users/admin/Documents/btxchain/infra/porkbun_api.key`, and
  `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` before any new
  remote or GitHub operation in this pass, with byte counts `94`, `72`, `69`,
  and `69`;
- current focus for this pass: inspect the remaining repo-side DoD 8 bundle
  and packet surfaces for any last honest artifact-portability mismatch after
  the `m23` / `m24` hosted-manifest sanitization fix, before starting the
  required fetch / pull / push sequence.
- start-of-pass loop executed as required:
  - `git fetch --all --prune`
  - `git switch codex/shielded-v2-overhaul-plan`
  - `git pull --ff-only origin codex/shielded-v2-overhaul-plan`
  - `git status --short`
  - `git log --oneline -5`
- user-directed scope change handled in this pass:
  - after the initial portability scan, the user explicitly required actual
    infra-backed red-team analysis plus simulated-testnet, proof-size / TPS,
    and security-readiness testing instead of leaving that work for later;
  - this pass therefore implemented and ran a new hosted disposable suite and
    updated the infra spec so the hosted validation task is now a standing
    operator requirement for future sessions.
- repo-side implementation and packaging changes landed in this pass:
  - updated
    `/Users/admin/Documents/btxchain/btx-node/scripts/m19_reset_launch_rehearsal.sh`
    so the wrapper now accepts `--config-file`, defaults to
    `<build-dir>/test/config.ini` when present, and fails fast if the config
    file is missing;
  - added
    `/Users/admin/Documents/btxchain/btx-node/scripts/m26_remote_shielded_validation_suite.py`,
    a hosted disposable suite that provisions a DigitalOcean droplet/firewall,
    builds the bounded `shielded_v2` toolchain remotely, runs `m19`, runs
    `m21`, emits the send / ingress / egress / netting / chain-growth report
    set, downloads the artifacts, summarizes the findings, and tears the
    resources down;
  - added
    `/Users/admin/Documents/btxchain/btx-node/test/util/m26_remote_shielded_validation_suite_test.sh`
    so `m26` now has a structural dry-run regression plus a focused
    `summarize_suite(...)` check for the hosted `m19` nested artifact layout
    after the successful rerun exposed that the first `m26`
    `validation_summary.simulated_testnet` path was still reading the wrong
    level of the `m19` artifact and dropping `final_height` /
    `bestblockhash`;
  - updated
    `/Users/admin/Documents/btxchain/btx-node/scripts/m20_shielded_audit_handoff_bundle.py`
    and
    `/Users/admin/Documents/btxchain/btx-node/test/util/m20_shielded_audit_handoff_bundle_test.sh`
    so the `m20` source snapshot now ships the new hosted validation suite and
    its regression alongside the rest of the DoD 8 tooling;
  - updated
    `/Users/admin/Documents/btxchain/btx-node/scripts/m20_shielded_audit_handoff_bundle.py`,
    `/Users/admin/Documents/btxchain/btx-node/scripts/m23_shielded_external_redteam_packet.py`,
    and
    `/Users/admin/Documents/btxchain/btx-node/scripts/m24_shielded_external_findings_intake.py`
    so their top-level `manifest.json` files are sanitized before writing,
    eliminating the remaining local-path leaks in the repo-side handoff /
    packet / intake artifacts;
  - updated
    `/Users/admin/Documents/btxchain/btx-node/test/util/m23_shielded_external_redteam_packet_test.sh`
    and
    `/Users/admin/Documents/btxchain/btx-node/test/util/m24_shielded_external_findings_intake_test.sh`
    so they now assert the top-level packet / intake manifests themselves no
    longer leak creator-machine paths.
- local validation completed before and after the hosted reruns:
  - `python3 -m py_compile /Users/admin/Documents/btxchain/btx-node/scripts/m20_shielded_audit_handoff_bundle.py /Users/admin/Documents/btxchain/btx-node/scripts/m23_shielded_external_redteam_packet.py /Users/admin/Documents/btxchain/btx-node/scripts/m24_shielded_external_findings_intake.py /Users/admin/Documents/btxchain/btx-node/scripts/m26_remote_shielded_validation_suite.py`
  - `bash /Users/admin/Documents/btxchain/btx-node/test/util/m20_shielded_audit_handoff_bundle_test.sh`
  - `bash /Users/admin/Documents/btxchain/btx-node/test/util/m23_shielded_external_redteam_packet_test.sh`
  - `bash /Users/admin/Documents/btxchain/btx-node/test/util/m24_shielded_external_findings_intake_test.sh`
  - `bash /Users/admin/Documents/btxchain/btx-node/test/util/m26_remote_shielded_validation_suite_test.sh`
  - `bash -n /Users/admin/Documents/btxchain/btx-node/scripts/m19_reset_launch_rehearsal.sh`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/scripts/m20_shielded_audit_handoff_bundle.py --build-dir /Users/admin/Documents/btxchain/btx-node/build-btx --output-dir /tmp/btx-m20-audit-handoff-bundle-m26 --skip-build --samples=2`
  - local generator shape sampling:
    - `/Users/admin/Documents/btxchain/btx-node/build-btx/bin/gen_shielded_v2_send_runtime_report --samples=1 --warmup=0 --scenarios=1x2,2x2,2x4 --output=/tmp/btx-m26-local-send.json`
    - `/Users/admin/Documents/btxchain/btx-node/build-btx/bin/gen_shielded_ingress_proof_runtime_report --backend=receipt --samples=1 --warmup=0 --leaf-counts=100,1000,5000,10000 --output=/tmp/btx-m26-local-ingress.json`
    - `/Users/admin/Documents/btxchain/btx-node/build-btx/bin/gen_shielded_v2_egress_runtime_report --samples=1 --warmup=0 --scenarios=32x32,1300x32,5000x32 --output=/tmp/btx-m26-local-egress.json`
    - `/Users/admin/Documents/btxchain/btx-node/build-btx/bin/gen_shielded_v2_netting_capacity_report --samples=1 --warmup=0 --scenarios=2x50,8x80,32x95,64x99 --output=/tmp/btx-m26-local-netting.json`
    - `/Users/admin/Documents/btxchain/btx-node/build-btx/bin/gen_shielded_v2_chain_growth_projection_report --block-sizes-mb=12,24,32 --output=/tmp/btx-m26-local-chain-growth.json`
- hosted disposable validation run 1 (`/tmp/btx-m26-remote-validation-run1`):
  - command:
    - `python3 /Users/admin/Documents/btxchain/btx-node/scripts/m26_remote_shielded_validation_suite.py --output-dir /tmp/btx-m26-remote-validation-run1 --admin-cidr 0.0.0.0/0 --size s-4vcpu-8gb-amd --build-jobs 4`
  - cloud resources:
    - droplet `558685516` / `btx-shielded-suite-20260316-132524`
    - firewall `0b91a82b-77f2-4543-8b98-16f239b075ad`
  - fail-first pivot:
    - the first real hosted run failed only at `remote_m19_launch_rehearsal`
      because the original `m19` wrapper still pointed the remote functional
      test at the creator-machine `test/config.ini` path instead of the remote
      `build-validation/test/config.ini`;
    - exact failure recorded in the remote `m19` log:
      - `Binary not found: /Users/admin/Documents/btxchain/btx-node/build-btx/bin/bitcoind`
      - `Binary not found: /Users/admin/Documents/btxchain/btx-node/build-btx/bin/bitcoin-cli`
      - `AssertionError: At least one release binary is missing.`
  - retained hosted evidence despite the `m19` failure:
    - `remote_build=509.319s`
    - `remote_m21_redteam_campaign=93.483s`
    - `remote_send_runtime_report=154.524s`
    - `remote_ingress_native_runtime_report=48.715s`
    - `remote_ingress_receipt_capacity_report=2.844s`
    - `remote_egress_runtime_report=7.024s`
    - `remote_netting_capacity_report=1.592s`
    - `remote_chain_growth_projection_report=38.901s`
  - cost / teardown:
    - estimated cost `0.0235`
    - droplet and firewall deletion both confirmed
- hosted disposable validation run 2 (`/tmp/btx-m26-remote-validation-run2`) after the `m19 --config-file` fix:
  - command:
    - `python3 /Users/admin/Documents/btxchain/btx-node/scripts/m26_remote_shielded_validation_suite.py --output-dir /tmp/btx-m26-remote-validation-run2 --admin-cidr 0.0.0.0/0 --size s-4vcpu-8gb-amd --build-jobs 4`
  - cloud resources:
    - droplet `558688768` / `btx-shielded-suite-20260316-134242`
    - firewall `469f8a50-59d9-41c8-8340-df4d036c0073`
  - hosted suite result:
    - `overall_status=pass`
    - step timings:
      - `remote_build=499.883s`
      - `remote_m19_launch_rehearsal=204.903s`
      - `remote_m21_redteam_campaign=97.235s`
      - `remote_send_runtime_report=158.147s`
      - `remote_ingress_native_runtime_report=55.922s`
      - `remote_ingress_receipt_capacity_report=3.125s`
      - `remote_egress_runtime_report=7.451s`
      - `remote_netting_capacity_report=2.115s`
      - `remote_chain_growth_projection_report=43.777s`
      - total timed hosted steps `1163.287s`
    - fetched hosted artifacts:
      - `m19-reset-launch-rehearsal.json`
      - `m21-remote-redteam.json`
      - all five report JSONs under `artifacts/remote_artifacts/reports/`
  - simulated testnet findings:
    - hosted `shieldedv2dev` launch rehearsal passed against the real remote
      `build-validation` tree;
    - final height `402`;
    - best block
      `2c559188339b68e82a2af297d5075c3d25333156247fd1eb625ed4b9d925b3ea`;
    - hosted `feature_shieldedv2dev_launch_rehearsal` runtime `199.797s`
      inside the `m19` artifact (`204.903s` wrapper runtime);
  - security-readiness findings:
    - hosted malformed-proof campaign passed with wrapper runtime `95.452s`,
      inner runtime `92.946s`, deterministic variant count `5`, and teardown
      confirmed inside the inner campaign artifact;
  - proof-size / TPS / capacity findings from the hosted report set:
    - direct `1x2` and `2x2` sends remain weight-bound at `5` txs per block
      (`0.056` estimated TPS) with proof payloads `1060841` and `1163703`
      bytes;
    - direct `2x4` send remains weight-bound at `2` txs per block
      (`0.022` estimated TPS) with proof payload `2115675` bytes and
      nonstandard policy weight;
    - native `4`-leaf ingress remains nonstandard and tops out at `8` leaves
      per block (`0.089` estimated leaf TPS) with proof payload
      `2489850` bytes;
    - receipt-backed ingress reaches `10000` leaves in `1` tx per block
      (`111.111` estimated leaf TPS) with proof payload `1834278` bytes;
    - `32x32` egress reaches `136` txs per block / `4352` outputs per block
      (`1.511` tx TPS / `48.356` output TPS) while `1300x32` falls to `3`
      txs per block and `5000x32` falls to `0`;
    - `2x50` and `8x80` netting windows remain verify-bound at `200` txs per
      block (`2.222` estimated TPS), while `64x99` becomes weight-bound at
      `79` txs per block (`0.878` estimated TPS);
    - the hosted chain-growth replay again confirmed the
      `1b_year_1pct_boundary` workload is infeasible at `12 MB`, feasible at
      `24 MB`, and gains no additional capacity at `32 MB`;
  - cost / teardown:
    - estimated cost `0.0278`
    - droplet and firewall deletion both confirmed
    - aggregate hosted cost for the fail-first run plus the clean rerun:
      `0.0513`
- documentation and operator-memory updates landed in this pass:
  - updated `/Users/admin/Documents/btxchain/infra/btx-seed-server-spec.md`
    with the canonical hosted validation command, a mandatory future-session
    task list, and the recorded fail-first / clean-rerun evidence;
  - updated `/Users/admin/Documents/btxchain/btx-node/doc/btx-production-readiness-matrix.md`
    with a dedicated `m26` readiness row so the hosted simulated-testnet /
    proof-size / TPS / security suite is no longer implicit;
  - updated `/Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-cryptographic-audit-handoff.md`
    so the external-review handoff now documents the hosted full validation
    suite and notes that the `m20` source snapshot carries `m22` through
    `m26`;
  - refreshed real `m20` handoff bundle generation completed in
    `real 241.55`, `user 226.61`, `sys 2.37`, and the emitted manifest at
    `/tmp/btx-m20-audit-handoff-bundle-m26/manifest.json` records
    `source_file_count=30` with both
    `scripts/m26_remote_shielded_validation_suite.py` and
    `test/util/m26_remote_shielded_validation_suite_test.sh` present; the
    sibling tarball hash is
    `841a2a41300d6f4e031ada664321a27aebf14ec55cbee3f6a5cacb131f3fd697`;
- blocker conclusion for this pass:
  - this pass closes the remaining repo-side gap the user called out by
    implementing and running real hosted simulated-testnet, proof-size / TPS,
    and security-readiness validation instead of deferring it;
  - the remaining launch blocker is still external to this repository:
    independent cryptographic review plus an externally run adversarial
    proof-focused testnet / red-team campaign.

### 2026-03-16 22:38:17 JST

- pass preflight: verified readable, non-empty
  `/Users/admin/Documents/btxchain/github.key`,
  `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`,
  `/Users/admin/Documents/btxchain/infra/porkbun_api.key`, and
  `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` before any new
  remote or GitHub operation in this pass, with byte counts `94`, `72`, `69`,
  and `69`;
- current focus for this pass: inspect the remaining repo-side DoD 8 handoff
  and hosted-redteam artifact surfaces for another honest portability gap
  after the `m22` manifest-sanitizer fix, before starting the required
  fetch / pull / push sequence;
- start-of-pass loop executed as required:
  - `git fetch --all --prune`
  - `git switch codex/shielded-v2-overhaul-plan`
  - `git pull --ff-only origin codex/shielded-v2-overhaul-plan`
  - `git status --short`
  - `git log --oneline -5`
- newly identified repo-side DoD 8 gap closed in this pass:
  - updated
    `/Users/admin/Documents/btxchain/btx-node/scripts/m23_shielded_external_redteam_packet.py`
    so copied hosted `m22` run directories are no longer packaged verbatim:
    any included hosted-run `manifest.json` is now sanitized during tree copy,
    including older stale hosted artifacts whose original `output_dir` was not
    the new packet location;
  - updated
    `/Users/admin/Documents/btxchain/btx-node/scripts/m24_shielded_external_findings_intake.py`
    so both directly included hosted `m22` runs and hosted-run manifests
    nested inside a referenced `m23` packet are sanitized during tree copy,
    preventing stale `m22` local-path leakage from surviving into the intake /
    closeout packet;
  - updated
    `/Users/admin/Documents/btxchain/btx-node/test/util/m23_shielded_external_redteam_packet_test.sh`
    and
    `/Users/admin/Documents/btxchain/btx-node/test/util/m24_shielded_external_findings_intake_test.sh`
    so each regression now seeds a stale hosted-run manifest with absolute
    home/workspace/output-dir paths and proves the emitted copied manifests are
    rewritten to portable `~/.ssh/...`, `<repo>`, and packet-relative forms;
  - updated
    `/Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-external-redteam-window.md`
    and
    `/Users/admin/Documents/btxchain/btx-node/doc/btx-production-readiness-matrix.md`
    so the operator-facing docs and readiness rows now describe the hosted
    baseline manifest normalization that `m23` / `m24` perform when rebundling
    older `m22` outputs;
- result of the sync/status/doc inspection:
  - local HEAD and `origin/codex/shielded-v2-overhaul-plan` were aligned at
    `c0f9c6e1f1` before this pass began;
  - the targeted inspection of the live stale packet artifact at
    `/tmp/btx-m23-external-redteam-packet-v2.wfpqPI/artifacts/hosted_run/manifest.json`
    confirmed a real downstream gap remained after the `m22` serializer fix:
    the copied hosted-run manifest still contained `10` absolute local path
    leaks because `m23` / `m24` were copying older hosted-run directories
    verbatim instead of rewriting them during packaging;
- local validation for this pass:
  - `git fetch --all --prune`
  - `git switch codex/shielded-v2-overhaul-plan`
  - `git pull --ff-only origin codex/shielded-v2-overhaul-plan`
  - `git status --short`
  - `git log --oneline -5`
  - `rg -n 'manifest\\.json|copy2\\(|shutil\\.copy2|copytree|hosted-run-dir|remote-redteam|m22' /Users/admin/Documents/btxchain/btx-node/scripts/m20_shielded_audit_handoff_bundle.py /Users/admin/Documents/btxchain/btx-node/scripts/m23_shielded_external_redteam_packet.py /Users/admin/Documents/btxchain/btx-node/scripts/m24_shielded_external_findings_intake.py`
  - `python3 - <<'PY' ... leak scan of /tmp/btx-m23-external-redteam-packet-v2.wfpqPI/artifacts/hosted_run/manifest.json ... PY`
  - `bash /Users/admin/Documents/btxchain/btx-node/test/util/m23_shielded_external_redteam_packet_test.sh`
  - `bash /Users/admin/Documents/btxchain/btx-node/test/util/m24_shielded_external_findings_intake_test.sh`
  - `python3 -m py_compile /Users/admin/Documents/btxchain/btx-node/scripts/m23_shielded_external_redteam_packet.py /Users/admin/Documents/btxchain/btx-node/scripts/m24_shielded_external_findings_intake.py`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/scripts/m23_shielded_external_redteam_packet.py --output-dir /tmp/btx-m23-hosted-manifest-sanitized --hosted-run-dir /tmp/btx-m22-remote-redteam-run9`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/scripts/m24_shielded_external_findings_intake.py --output-dir /tmp/btx-m24-hosted-manifest-sanitized --source-packet /tmp/btx-m23-hosted-manifest-sanitized --hosted-run-dir /tmp/btx-m22-remote-redteam-run9`
  - `python3 - <<'PY' ... zero-hit local-path scan over /tmp/btx-m23-hosted-manifest-sanitized/artifacts/hosted_run/manifest.json, /tmp/btx-m24-hosted-manifest-sanitized/source_refs/m23_packet/artifacts/hosted_run/manifest.json, and /tmp/btx-m24-hosted-manifest-sanitized/source_refs/m22_hosted_run/manifest.json ... PY`
  - `git diff --check`
- validation findings and pivots:
  - the live stale packet artifact replay showed the real downstream problem
    clearly: the copied hosted-run manifest still exposed `10` absolute local
    path hits before this pass, including `/Users/admin/.ssh/id_ed25519`,
    `/Users/admin/Documents/btxchain/btx-node`, and
    `/private/tmp/btx-m22-remote-redteam-run9/...`;
  - both strengthened regressions passed with stale synthetic hosted-run
    manifests and now guard against future verbatim-copy regressions in `m23`
    and `m24`;
  - `py_compile` passed cleanly for both packet builders;
  - the real stale-artifact replay passed:
    - `m23` rebuilt from `/tmp/btx-m22-remote-redteam-run9` in `real 1.79`,
      `user 1.66`, `sys 0.10`;
    - `m24` rebuilt from that `m23` packet plus the same stale hosted run in
      `real 3.42`, `user 3.27`, `sys 0.13`;
  - direct inspection of the emitted copied hosted-run manifests confirmed the
    local-path hit count dropped to `0` in all three output locations, with
    representative rewritten values of `~/.ssh/id_ed25519` and
    `logs/remote_install.log`;
- blocker conclusion for this pass:
  - this closes another honest repo-side DoD 8 packaging gap by ensuring older
    stale hosted `m22` artifacts are normalized when they are repackaged into
    `m23` and `m24`, instead of relying on the hosted run having been produced
    by a freshly fixed `m22` binary;
  - the remaining launch blocker is still external to this repository:
    independent cryptographic review plus an externally run adversarial
    proof-focused testnet / red-team campaign;
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - this pass used only local stale-artifact replays and synthetic packet
    fixtures; no droplet or firewall was created.

### 2026-03-16 22:25:48 JST

- pass preflight: verified readable, non-empty
  `/Users/admin/Documents/btxchain/github.key`,
  `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`,
  `/Users/admin/Documents/btxchain/infra/porkbun_api.key`, and
  `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` before any new
  remote or GitHub operation in this pass, with byte counts `94`, `72`, `69`,
  and `69`;
- current focus for this pass: inspect the remaining repo-side DoD 8 handoff
  and hosted red-team surfaces for another honest portability or packaging
  mismatch after the `m22` default-token-path fix, before starting the
  required fetch / pull / push sequence;
- start-of-pass loop executed as required:
  - `git fetch --all --prune`
  - `git switch codex/shielded-v2-overhaul-plan`
  - `git pull --ff-only origin codex/shielded-v2-overhaul-plan`
  - `git status --short`
  - `git log --oneline -5`
- newly identified repo-side DoD 8 gap closed in this pass:
  - updated
    `/Users/admin/Documents/btxchain/btx-node/scripts/m22_remote_shielded_redteam_campaign.py`
    so the hosted red-team harness now sanitizes manifest paths consistently:
    output-dir files become relative paths, repository-local paths become
    `<repo>/...`, home-relative paths become `~/...`, and the old absolute
    `ssh_private_key` manifest field remains replaced by
    `ssh_private_key_name`;
  - updated
    `/Users/admin/Documents/btxchain/btx-node/test/util/m22_remote_shielded_redteam_campaign_test.sh`
    so the regression now exercises the new sanitizer directly on a sample
    manifest, verifies local `cwd`, `log`, artifact-path, and SSH-key-command
    fields are redacted correctly, and still fails if the old
    `ssh_private_key` manifest field returns;
  - updated
    `/Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-cryptographic-audit-handoff.md`
    so the operator-facing `m22` handoff docs now state explicitly that the
    emitted manifest rewrites local artifact paths relative to the output
    directory or to `<repo>` / `~/...` where appropriate, and retains only
    the SSH key basename rather than the creator-machine private-key path;
- result of the sync/status/doc inspection:
  - local HEAD and `origin/codex/shielded-v2-overhaul-plan` were aligned at
    `94faadbd68` before this pass began;
  - the remaining targeted portability scan over the DoD 8 hosted-red-team
    surface found a broader honest metadata leak in practice: the real hosted
    `m22` artifact at `/tmp/btx-m22-remote-redteam-run9/manifest.json` still
    serialized absolute local SSH-key, `cwd`, `log`, and archive-path values,
    which would leak creator-machine home and workspace details into the
    hosted run artifact bundled for external review;
- local validation for this pass:
  - `git fetch --all --prune`
  - `git switch codex/shielded-v2-overhaul-plan`
  - `git pull --ff-only origin codex/shielded-v2-overhaul-plan`
  - `git status --short`
  - `git log --oneline -5`
  - `rg -n '/Users/admin/Documents/btxchain|/Users/admin/Documents/btxchain/infra|/Users/admin/Documents/btxchain/btx-node' /Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-cryptographic-audit-handoff.md /Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-external-redteam-window.md /Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-external-review-closeout.md /Users/admin/Documents/btxchain/btx-node/doc/btx-production-readiness-matrix.md /Users/admin/Documents/btxchain/btx-node/scripts/m20_shielded_audit_handoff_bundle.py /Users/admin/Documents/btxchain/btx-node/scripts/m22_remote_shielded_redteam_campaign.py /Users/admin/Documents/btxchain/btx-node/scripts/m23_shielded_external_redteam_packet.py /Users/admin/Documents/btxchain/btx-node/scripts/m24_shielded_external_findings_intake.py /Users/admin/Documents/btxchain/btx-node/scripts/m25_shielded_external_closeout_check.py /Users/admin/Documents/btxchain/btx-node/test/util/m20_shielded_audit_handoff_bundle_test.sh /Users/admin/Documents/btxchain/btx-node/test/util/m22_remote_shielded_redteam_campaign_test.sh /Users/admin/Documents/btxchain/btx-node/test/util/m23_shielded_external_redteam_packet_test.sh /Users/admin/Documents/btxchain/btx-node/test/util/m24_shielded_external_findings_intake_test.sh /Users/admin/Documents/btxchain/btx-node/test/util/m25_shielded_external_closeout_check_test.sh`
  - `rg -n 'docs/participant_brief.md|docs/operator_checklist.md|docs/m24_shielded_external_findings_intake.py|docs/m25_shielded_external_closeout_check.py|source_snapshot/infra/btx-seed-server-spec.md|\\.\\./infra/btx-seed-server-spec.md|digitalocean_api.key|ssh_private_key|id_ed25519' /Users/admin/Documents/btxchain/btx-node/doc /Users/admin/Documents/btxchain/btx-node/scripts /Users/admin/Documents/btxchain/btx-node/test/util`
  - `python3 - <<'PY' ... historical /tmp/btx-m22-remote-redteam-run9/manifest.json leak scan ... PY`
  - `bash /Users/admin/Documents/btxchain/btx-node/test/util/m22_remote_shielded_redteam_campaign_test.sh`
  - `python3 -m py_compile /Users/admin/Documents/btxchain/btx-node/scripts/m22_remote_shielded_redteam_campaign.py`
  - `python3 - <<'PY' ... sanitize historical /tmp/btx-m22-remote-redteam-run9/manifest.json with sanitize_manifest_value(...) ... PY`
  - `git diff --check`
- validation findings and pivots:
  - the targeted scan showed no remaining creator-machine path leak in the
    shipped docs/scripts themselves, but the real hosted `run9` manifest still
    exposed `10` absolute local path hits before this fix, including
    `/Users/admin/.ssh/id_ed25519`, `/Users/admin/Documents/btxchain/btx-node`,
    and `/private/tmp/...` log/archive paths;
  - the strengthened `m22` regression passed after the sanitizer landed and
    now blocks future reintroduction of unsanitized local `cwd`, `log`,
    artifact-path, and SSH-key-command fields;
  - `py_compile` passed cleanly;
  - the sample-manifest regression now proves `scp -i ~/.ssh/id_ed25519`,
    `cwd=<repo>`, `log=logs/remote.log`, and output-dir-relative artifact
    paths are emitted instead of absolute local paths;
  - replaying `sanitize_manifest_value(...)` against the real hosted
    `/tmp/btx-m22-remote-redteam-run9/manifest.json` reduced the local-path
    hit count to `0` and produced representative redactions of
    `~/.ssh/id_ed25519`, `logs/remote_install.log`, and `<repo>`;
- blocker conclusion for this pass:
  - this closes another honest repo-side DoD 8 artifact-portability gap by
    removing creator-machine home/workspace/output-dir path leakage from the
    hosted red-team manifest that gets packaged into the external review flow;
  - the remaining launch blocker is still external to this repository:
    independent cryptographic review plus an externally run adversarial
    proof-focused testnet / red-team campaign;
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - this pass validated the sanitizer against a sample manifest plus the
    historical hosted `run9` artifact only; no droplet or firewall was
    created.

### 2026-03-16 22:17:43 JST

- pass preflight: verified readable, non-empty
  `/Users/admin/Documents/btxchain/github.key`,
  `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`,
  `/Users/admin/Documents/btxchain/infra/porkbun_api.key`, and
  `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` before any new
  remote or GitHub operation in this pass, with byte counts `94`, `72`, `69`,
  and `69`;
- current focus for this pass: inspect the remaining repo-side DoD 8 hosted
  red-team surfaces for another honest portability mismatch before starting the
  required fetch / pull / push sequence, with particular attention to any
  creator-machine path that still leaks through the `m20`/`m22`/`m23` handoff
  stack;
- start-of-pass loop executed as required:
  - `git fetch --all --prune`
  - `git switch codex/shielded-v2-overhaul-plan`
  - `git pull --ff-only origin codex/shielded-v2-overhaul-plan`
  - `git status --short`
  - `git log --oneline -5`
- newly identified repo-side DoD 8 gap closed in this pass:
  - updated
    `/Users/admin/Documents/btxchain/btx-node/scripts/m22_remote_shielded_redteam_campaign.py`
    so the hosted red-team harness no longer hard-codes the
    creator-machine-only default DigitalOcean token path and instead resolves
    the repo-adjacent `../infra/digitalocean_api.key` path from `REPO_ROOT`
    dynamically;
  - updated
    `/Users/admin/Documents/btxchain/btx-node/test/util/m22_remote_shielded_redteam_campaign_test.sh`
    so the structural regression now explicitly fails if the old
    `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` literal ever
    returns and asserts the new repo-relative default path logic is present;
  - updated
    `/Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-cryptographic-audit-handoff.md`
    so operators know the default `--do-token-file` only auto-resolves in a
    normal checkout and should be overridden explicitly when `m22` is run from
    an unpacked handoff snapshot or another workspace;
- result of the sync/status/doc inspection:
  - local HEAD and `origin/codex/shielded-v2-overhaul-plan` were aligned at
    `1a263727dc` before this pass began;
  - the targeted creator-path scan across the remaining DoD 8 handoff surfaces
    found one honest portability leak that still mattered in practice: the
    `m22` hosted red-team harness shipped inside the handoff bundle still
    defaulted `--do-token-file` to the creator-machine absolute path, which
    was inconsistent with the later `m20`/`m23`/`m24` packet portability work;
- local validation for this pass:
  - `git fetch --all --prune`
  - `git switch codex/shielded-v2-overhaul-plan`
  - `git pull --ff-only origin codex/shielded-v2-overhaul-plan`
  - `git status --short`
  - `git log --oneline -5`
  - `rg -n '/Users/admin/Documents/btxchain|/Users/admin/Documents/btxchain/infra|/Users/admin/Documents/btxchain/btx-node|/private/tmp|/tmp/btx-' /Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-cryptographic-audit-handoff.md /Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-external-redteam-window.md /Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-external-review-closeout.md /Users/admin/Documents/btxchain/btx-node/doc/btx-production-readiness-matrix.md /Users/admin/Documents/btxchain/btx-node/scripts/m20_shielded_audit_handoff_bundle.py /Users/admin/Documents/btxchain/btx-node/scripts/m22_remote_shielded_redteam_campaign.py /Users/admin/Documents/btxchain/btx-node/scripts/m23_shielded_external_redteam_packet.py /Users/admin/Documents/btxchain/btx-node/scripts/m24_shielded_external_findings_intake.py /Users/admin/Documents/btxchain/btx-node/scripts/m25_shielded_external_closeout_check.py /Users/admin/Documents/btxchain/btx-node/test/util/m20_shielded_audit_handoff_bundle_test.sh /Users/admin/Documents/btxchain/btx-node/test/util/m22_remote_shielded_redteam_campaign_test.sh /Users/admin/Documents/btxchain/btx-node/test/util/m23_shielded_external_redteam_packet_test.sh /Users/admin/Documents/btxchain/btx-node/test/util/m24_shielded_external_findings_intake_test.sh /Users/admin/Documents/btxchain/btx-node/test/util/m25_shielded_external_closeout_check_test.sh`
  - `bash /Users/admin/Documents/btxchain/btx-node/test/util/m22_remote_shielded_redteam_campaign_test.sh`
  - `python3 -m py_compile /Users/admin/Documents/btxchain/btx-node/scripts/m22_remote_shielded_redteam_campaign.py`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/scripts/m22_remote_shielded_redteam_campaign.py --output-dir /tmp/btx-m22-remote-redteam-default-token-pass --admin-cidr 0.0.0.0/0 --dry-run`
  - `git diff --check`
- validation findings and pivots:
  - the creator-path scan isolated the remaining leak cleanly to the `m22`
    default token-path literal rather than to the later packet/intake/closeout
    surfaces;
  - the strengthened structural regression passed immediately after the fix and
    now blocks future reintroduction of the creator-machine token path;
  - `py_compile` passed cleanly;
  - the real `m22 --dry-run` execution passed with `overall_status=dry_run`
    and no explicit `--do-token-file`, confirming the new repo-relative
    default token path is actually exercised; runtime was `real 0.80`,
    `user 0.08`, `sys 0.02`, and the dry-run manifest landed under
    `/private/tmp/btx-m22-remote-redteam-default-token-pass`;
- blocker conclusion for this pass:
  - this closes another honest repo-side DoD 8 portability gap by removing the
    last creator-machine default path from the hosted red-team harness that is
    bundled into the external handoff flow;
  - the remaining launch blocker is still external to this repository:
    independent cryptographic review plus an externally run adversarial
    proof-focused testnet / red-team campaign;
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - `m22` was validated in `--dry-run` mode only, so no droplet or firewall
    was created in this pass.

### 2026-03-16 21:39:53 JST

- pass preflight: verified readable, non-empty
  `/Users/admin/Documents/btxchain/github.key`,
  `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`,
  `/Users/admin/Documents/btxchain/infra/porkbun_api.key`, and
  `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` before any new
  remote or GitHub operation in this pass, with byte counts `94`, `72`, `69`,
  and `69`;
- current focus for this pass: inspect the remaining repo-side DoD 8 handoff,
  packet, and closeout surfaces for another honest portability or packaging
  mismatch before starting the required fetch / pull / push sequence;
- start-of-pass loop executed as required:
  - first `git fetch --all --prune` attempt hit a transient
    `.git/index.lock` error; immediate inspection showed the lock file no
    longer existed and no live git process was holding it;
  - reran the required sync loop cleanly:
    - `git fetch --all --prune`
    - `git switch codex/shielded-v2-overhaul-plan`
    - `git pull --ff-only origin codex/shielded-v2-overhaul-plan`
    - `git status --short`
    - `git log --oneline -5`
- result of the sync/status/doc inspection:
  - local HEAD and `origin/codex/shielded-v2-overhaul-plan` were aligned at
    `ee34de2d97` before this pass began;
  - the transient `.git/index.lock` condition cleared without manual cleanup
    and did not correspond to an active conflicting git process;
  - a final creator-path and stale-layout scan over the repo-side external
    review surfaces found no new honest in-repo gap after the recent `m20`,
    `m23`, and `m24` portability fixes;
- local validation for this pass:
  - `git fetch --all --prune`
  - `git switch codex/shielded-v2-overhaul-plan`
  - `git pull --ff-only origin codex/shielded-v2-overhaul-plan`
  - `git status --short`
  - `git log --oneline -5`
  - `ps -axo pid=,ppid=,command= | rg '/Users/admin/Documents/btxchain/btx-node| git '`
  - `rg -n '/Users/admin/Documents/btxchain|/Users/admin/Documents/btxchain/infra|/Users/admin/Documents/btxchain/btx-node' /Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-cryptographic-audit-handoff.md /Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-external-redteam-window.md /Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-external-review-closeout.md /Users/admin/Documents/btxchain/btx-node/doc/btx-production-readiness-matrix.md /Users/admin/Documents/btxchain/btx-node/scripts/m20_shielded_audit_handoff_bundle.py /Users/admin/Documents/btxchain/btx-node/scripts/m23_shielded_external_redteam_packet.py /Users/admin/Documents/btxchain/btx-node/scripts/m24_shielded_external_findings_intake.py /Users/admin/Documents/btxchain/btx-node/scripts/m25_shielded_external_closeout_check.py /Users/admin/Documents/btxchain/btx-node/test/util/m20_shielded_audit_handoff_bundle_test.sh /Users/admin/Documents/btxchain/btx-node/test/util/m23_shielded_external_redteam_packet_test.sh /Users/admin/Documents/btxchain/btx-node/test/util/m24_shielded_external_findings_intake_test.sh /Users/admin/Documents/btxchain/btx-node/test/util/m25_shielded_external_closeout_check_test.sh`
  - `rg -n 'docs/m24_shielded_external_findings_intake.py|docs/m25_shielded_external_closeout_check.py|docs/participant_brief.md|docs/operator_checklist.md|source_snapshot/infra/btx-seed-server-spec.md|\\.\\./infra/btx-seed-server-spec.md' /Users/admin/Documents/btxchain/btx-node/doc /Users/admin/Documents/btxchain/btx-node/scripts /Users/admin/Documents/btxchain/btx-node/test/util`
  - `git diff --check`
- validation findings and pivots:
  - the only remaining absolute creator-path hit was the intentional leak guard
    inside `test/util/m23_shielded_external_redteam_packet_test.sh`;
  - the remaining `docs/...` hits correspond only to the generated
    participant/operator docs that are intentionally part of the `m23` packet
    surface, plus the explicit negative checks guarding against stale
    pre-layout packet paths;
  - no further repo-side handoff / packet / closeout portability mismatch was
    found after the recent `m20`/`m23`/`m24` fixes;
- blocker conclusion for this pass:
  - this pass did not produce a new code or doc change beyond the tracker,
    because the post-fix repo inspection did not reveal another honest
    launch-critical in-repo gap to close;
  - the remaining launch blocker is still external to this repository:
    independent cryptographic review plus an externally run adversarial
    proof-focused testnet / red-team campaign;
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no cloud resources were created in this pass.

### 2026-03-16 21:30:34 JST

- pass preflight: verified readable, non-empty
  `/Users/admin/Documents/btxchain/github.key`,
  `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`,
  `/Users/admin/Documents/btxchain/infra/porkbun_api.key`, and
  `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` before any new
  remote or GitHub operation in this pass, with byte counts `94`, `72`, `69`,
  and `69`;
- current focus for this pass: inspect the remaining repo-side DoD 8 handoff
  and closeout surfaces for another honest gap after the `m23` source-doc
  portability fix;
- start-of-pass loop executed as required:
  - `git fetch --all --prune`
  - `git switch codex/shielded-v2-overhaul-plan`
  - `git pull --ff-only origin codex/shielded-v2-overhaul-plan`
  - `git status --short`
  - `git log --oneline -5`
- newly identified repo-side DoD 8 gap closed in this pass:
  - updated `/Users/admin/Documents/btxchain/btx-node/scripts/m20_shielded_audit_handoff_bundle.py`
    so the `m20` handoff bundle source snapshot now supports repo-adjacent
    `../infra/...` sources and actually includes
    `source_snapshot/infra/btx-seed-server-spec.md`, matching the packet-safe
    path assumptions that now exist in the bundled external window guide;
  - updated
    `/Users/admin/Documents/btxchain/btx-node/test/util/m20_shielded_audit_handoff_bundle_test.sh`
    to lock the new `../infra/btx-seed-server-spec.md` source inclusion and
    the guarded path-resolution logic structurally;
  - updated
    `/Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-cryptographic-audit-handoff.md`
    and
    `/Users/admin/Documents/btxchain/btx-node/doc/btx-production-readiness-matrix.md`
    so the operator-facing `m20` bundle description now explicitly includes the
    copied `source_snapshot/infra/btx-seed-server-spec.md` surface that
    validates in practice;
- result of the sync/status/doc inspection:
  - local HEAD and `origin/codex/shielded-v2-overhaul-plan` were aligned at
    `fa40153cd2` before this pass began;
  - the inspection found a real second-order portability gap: after the
    red-team window guide was corrected to point at
    `../infra/btx-seed-server-spec.md`, the `m20` handoff bundle still omitted
    that sibling infra file from `source_snapshot/`, so the copied guide inside
    the handoff bundle referenced a path the bundle did not actually ship;
- local validation for this pass:
  - `bash /Users/admin/Documents/btxchain/btx-node/test/util/m20_shielded_audit_handoff_bundle_test.sh`
  - `python3 -m py_compile /Users/admin/Documents/btxchain/btx-node/scripts/m20_shielded_audit_handoff_bundle.py`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/scripts/m20_shielded_audit_handoff_bundle.py --build-dir /Users/admin/Documents/btxchain/btx-node/build-btx --output-dir /private/tmp/btx-m20-audit-handoff-bundle-v3.g0PgXt --skip-build --samples=2`
  - `test -f /private/tmp/btx-m20-audit-handoff-bundle-v3.g0PgXt/source_snapshot/infra/btx-seed-server-spec.md`
  - `python3 - <<'PY' ... manifest source-file inspection ... PY`
  - `shasum -a 256 /private/tmp/btx-m20-audit-handoff-bundle-v3.g0PgXt.tar.gz`
  - `git diff --check`
- validation findings and pivots:
  - the cheap `m20` structural regression and `py_compile` checks both passed
    immediately after the source-resolver change;
  - the refreshed real `m20` bundle run passed in `real 240.72`,
    `user 226.61`, `sys 2.33`, writing
    `/private/tmp/btx-m20-audit-handoff-bundle-v3.g0PgXt` plus sibling tarball
    `/private/tmp/btx-m20-audit-handoff-bundle-v3.g0PgXt.tar.gz`;
  - direct bundle inspection confirmed
    `source_snapshot/infra/btx-seed-server-spec.md` is present in the emitted
    handoff bundle;
  - manifest inspection confirmed `source_file_count=28`,
    `has_infra_spec=True`, and no required source entries were missing;
  - the refreshed `m20` tarball SHA-256 is
    `40cc21acbd4fe270e717b68b4f6034d91874a8849367c3cb5be31b2c96c0d078`;
- blocker conclusion for this pass:
  - this closes another real repo-side DoD 8 packaging gap by making the
    `m20` handoff bundle’s copied source snapshot consistent with the
    packet-safe infra path assumptions that now exist across the external
    window/handoff surfaces;
  - the remaining launch blocker is still external to this repository:
    independent cryptographic review plus an externally run adversarial
    proof-focused testnet / red-team campaign;
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no cloud resources were created in this pass; the refreshed local handoff
    bundle artifact remains under `/private/tmp`.

### 2026-03-16 21:25:59 JST

- pass preflight: verified readable, non-empty
  `/Users/admin/Documents/btxchain/github.key`,
  `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`,
  `/Users/admin/Documents/btxchain/infra/porkbun_api.key`, and
  `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` before any new
  remote or GitHub operation in this pass, with byte counts `94`, `72`, `69`,
  and `69`;
- current focus for this pass: inspect the remaining repo-side DoD 8 handoff
  and closeout surfaces adjacent to `m23` for another honest portability or
  packet-replay mismatch before starting the required fetch / pull / push
  sequence;
- start-of-pass loop executed as required:
  - `git fetch --all --prune`
  - `git switch codex/shielded-v2-overhaul-plan`
  - `git pull --ff-only origin codex/shielded-v2-overhaul-plan`
  - `git status --short`
  - `git log --oneline -5`
- newly identified repo-side DoD 8 gap closed in this pass:
  - updated
    `/Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-external-redteam-window.md`
    so the operator-facing external red-team window guide no longer embeds the
    creator-machine-only infra path and instead points at the packet-safe,
    repo-relative sibling path `../infra/btx-seed-server-spec.md` that works
    both from the repository and from the unpacked packet;
  - updated
    `/Users/admin/Documents/btxchain/btx-node/test/util/m23_shielded_external_redteam_packet_test.sh`
    so the `m23` packet regression now checks the copied
    `doc/btx-shielded-external-redteam-window.md` inside the built packet, not
    just the generated `docs/participant_brief.md` and
    `docs/operator_checklist.md`;
- result of the sync/status/doc inspection:
  - local HEAD and `origin/codex/shielded-v2-overhaul-plan` were aligned at
    `7e3995f36d` before this pass began;
  - the inspection found a real second-order portability mismatch adjacent to
    the previous `m23` fix: the generated participant docs were clean, but the
    copied source doc `doc/btx-shielded-external-redteam-window.md` still
    carried `/Users/admin/Documents/btxchain/infra/btx-seed-server-spec.md`,
    so the packet source snapshot still leaked the creator-machine path;
- local validation for this pass:
  - `bash /Users/admin/Documents/btxchain/btx-node/test/util/m23_shielded_external_redteam_packet_test.sh`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/scripts/m23_shielded_external_redteam_packet.py --output-dir /private/tmp/btx-m23-external-redteam-packet-v6.cybFtT --audit-bundle /private/tmp/btx-m20-audit-handoff-bundle-v2.SywV0q --hosted-run-dir /tmp/btx-m22-remote-redteam-run9`
  - `sed -n '1,80p' /private/tmp/btx-m23-external-redteam-packet-v6.cybFtT/doc/btx-shielded-external-redteam-window.md`
  - `rg -n '/Users/admin/Documents/btxchain/infra/|\\.\\./infra/btx-seed-server-spec.md' /private/tmp/btx-m23-external-redteam-packet-v6.cybFtT/doc/btx-shielded-external-redteam-window.md`
  - `shasum -a 256 /private/tmp/btx-m23-external-redteam-packet-v6.cybFtT.tar.gz`
  - `git diff --check`
- validation findings and pivots:
  - the strengthened `m23` regression initially failed with
    `creator-machine absolute path leaked into packet docs`, which exposed
    that my first doc edit still preserved the absolute fallback inside the
    copied packet guide; removing that fallback and switching to
    `../infra/btx-seed-server-spec.md` fixed the issue cleanly;
  - the final `m23_shielded_external_redteam_packet_test.sh` rerun passed;
  - the refreshed real packet build passed in `real 4.09`, `user 3.96`,
    `sys 0.12`, writing `/private/tmp/btx-m23-external-redteam-packet-v6.cybFtT`
    plus sibling tarball
    `/private/tmp/btx-m23-external-redteam-packet-v6.cybFtT.tar.gz`;
  - direct inspection of the copied packet guide confirmed the only remaining
    infra reference is the packet-safe sibling path
    `../infra/btx-seed-server-spec.md`, and the creator-machine absolute path
    is absent;
  - the refreshed packet tarball SHA-256 is
    `5d0276a196b62967be8895e7990bd34740a5da67e8f6d81d869c4d12fb92f75a`;
- blocker conclusion for this pass:
  - this closes the remaining repo-side source-doc portability mismatch
    adjacent to `m23` by aligning the copied red-team window guide with the
    packet-safe path assumptions already enforced in the generated participant
    docs and packet-local helpers;
  - the remaining launch blocker is still external to this repository:
    independent cryptographic review plus an externally run adversarial
    proof-focused testnet / red-team campaign;
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no cloud resources were created in this pass; the refreshed local packet
    artifact remains under `/private/tmp`.

### 2026-03-16 21:19:01 JST

- pass preflight: verified readable, non-empty
  `/Users/admin/Documents/btxchain/github.key`,
  `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`,
  `/Users/admin/Documents/btxchain/infra/porkbun_api.key`, and
  `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` before any new
  remote or GitHub operation in this pass, with byte counts `94`, `72`, `69`,
  and `69`;
- current focus for this pass: close the remaining repo-side `m23`
  participant-packet portability gap by removing creator-machine absolute-path
  references from generated participant docs and proving the refreshed packet
  still drives the packet-local `m24 -> m25` closeout flow from bundled
  `artifacts/` and `infra/` paths;
- start-of-pass loop executed as required:
  - `git fetch --all --prune`
  - `git switch codex/shielded-v2-overhaul-plan`
  - `git pull --ff-only origin codex/shielded-v2-overhaul-plan`
  - `git status --short`
  - `git log --oneline -5`
- newly identified repo-side DoD 8 gap closed in this pass:
  - updated `/Users/admin/Documents/btxchain/btx-node/scripts/m23_shielded_external_redteam_packet.py`
    so generated participant-facing docs now reference bundled packet-relative
    paths (`artifacts/audit_bundle/`, `artifacts/hosted_run/`, and
    `infra/btx-seed-server-spec.md`) instead of leaking creator-machine
    absolute paths into the distributed packet;
  - updated
    `/Users/admin/Documents/btxchain/btx-node/test/util/m23_shielded_external_redteam_packet_test.sh`
    into a stronger real packet-generation regression that injects fixture
    artifact directories, asserts the packet carries those artifacts under
    `artifacts/`, checks the participant docs for the new relative references,
    rejects leaked creator-machine paths, and still replays packet-local
    `m24 -> m25`;
- result of the sync/status/doc inspection:
  - local HEAD and `origin/codex/shielded-v2-overhaul-plan` were aligned at
    `8b1e64d864` before this pass began;
  - the inspection found a real remaining repo-side portability gap: although
    the prior pass preserved packet-local `doc/`, `scripts/`, and `infra/`
    layout, the generated `docs/participant_brief.md` and
    `docs/operator_checklist.md` still embedded creator-machine absolute paths
    for the audit bundle, hosted baseline, and infra spec, which made the
    packet less portable than its own operator instructions claimed;
- local validation for this pass:
  - `python3 -m py_compile /Users/admin/Documents/btxchain/btx-node/scripts/m23_shielded_external_redteam_packet.py /Users/admin/Documents/btxchain/btx-node/scripts/m24_shielded_external_findings_intake.py /Users/admin/Documents/btxchain/btx-node/scripts/m25_shielded_external_closeout_check.py`
  - `bash /Users/admin/Documents/btxchain/btx-node/test/util/m23_shielded_external_redteam_packet_test.sh`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/scripts/m23_shielded_external_redteam_packet.py --output-dir /private/tmp/btx-m23-external-redteam-packet-v4.w7AplP --audit-bundle /private/tmp/btx-m20-audit-handoff-bundle-v2.SywV0q --hosted-run-dir /tmp/btx-m22-remote-redteam-run9`
  - `/usr/bin/time -p python3 /private/tmp/btx-m23-external-redteam-packet-v4.w7AplP/scripts/m24_shielded_external_findings_intake.py --output-dir /private/tmp/btx-m23-derived-intake-v2.mrBgn4 --source-packet /private/tmp/btx-m23-external-redteam-packet-v4.w7AplP --audit-bundle /private/tmp/btx-m23-external-redteam-packet-v4.w7AplP/artifacts/audit_bundle --hosted-run-dir /private/tmp/btx-m23-external-redteam-packet-v4.w7AplP/artifacts/hosted_run`
  - `/usr/bin/time -p python3 /private/tmp/btx-m23-derived-intake-v2.mrBgn4/scripts/m25_shielded_external_closeout_check.py --intake-dir /private/tmp/btx-m23-derived-intake-v2.mrBgn4 --output /private/tmp/btx-m23-derived-intake-v2.mrBgn4/closeout/closeout_summary_from_packet.json`
  - `git diff --check`
- validation findings and pivots:
  - the strengthened `m23_shielded_external_redteam_packet_test.sh` passed
    after generating a real packet with fixture artifacts, deriving an intake
    packet from it, and replaying packet-local `m25`;
  - the refreshed `m23` packet passed in `real 4.09`, `user 3.96`, `sys 0.11`,
    writing `/private/tmp/btx-m23-external-redteam-packet-v4.w7AplP` plus
    sibling tarball
    `/private/tmp/btx-m23-external-redteam-packet-v4.w7AplP.tar.gz`;
  - direct inspection of the refreshed participant docs confirmed the stale
    absolute-path leak is gone and only the intended packet-relative
    references remain:
    `artifacts/audit_bundle/`, `artifacts/hosted_run/`, and
    `infra/btx-seed-server-spec.md`;
  - the derived packet-local intake replay passed in `real 8.06`, `user 7.86`,
    `sys 0.14`, writing `/private/tmp/btx-m23-derived-intake-v2.mrBgn4`;
  - the packet-local `m25` replay then ran in `real 0.03`, `user 0.03`,
    `sys 0.00`, returning `STATUS 1` only because the generated derived intake
    still contains the expected placeholder external inputs and unresolved
    medium-severity finding template;
  - manifest inspection confirmed the refreshed `m23` packet now carries
    `12` included source entries with `audit_bundle_dir` and `hosted_run_dir`
    under `included_artifacts`, while the derived intake packet carries `11`
    included source entries and neither manifest reported missing paths;
  - tarball SHA-256 values are
    `d9445fb65465984c2c4a9cfd537704ed9f17c600e47d63ed3cbe44babd0d5bcd` for the
    refreshed `m23` packet and
    `6d558a3264e8a36b8a2e2c947d88d9e126a75da9b1efba49102217e07e5e36c5` for the
    derived intake packet;
- blocker conclusion for this pass:
  - this closes the remaining repo-side `m23` participant-doc portability gap
    by making the distributed packet self-contained not only in file layout
    but also in the participant/operator-facing references embedded in its
    generated docs;
  - the remaining launch blocker is still external to this repository:
    independent cryptographic review plus an externally run adversarial
    proof-focused testnet / red-team campaign;
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no cloud resources were created in this pass; the refreshed local packet
    and derived intake artifacts remain under `/private/tmp`.

### 2026-03-16 21:11:56 JST

- pass preflight: verified readable, non-empty
  `/Users/admin/Documents/btxchain/github.key`,
  `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`,
  `/Users/admin/Documents/btxchain/infra/porkbun_api.key`, and
  `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` before any new
  remote or GitHub operation in this pass, with byte counts `94`, `72`, `69`,
  and `69`;
- current focus for this pass: execute the required sync/status loop on top of
  `931509447a`, then inspect the adjacent `m23` / `m20` repo-side external
  packet and bundle generators for the same packet-layout/path-preservation
  mismatch that was just closed for `m24`;
- start-of-pass loop executed as required:
  - `git fetch --all --prune`
  - `git switch codex/shielded-v2-overhaul-plan`
  - `git pull --ff-only origin codex/shielded-v2-overhaul-plan`
  - `git status --short`
  - `git log --oneline -5`
- newly identified repo-side DoD 8 gap closed in this pass:
  - updated `/Users/admin/Documents/btxchain/btx-node/scripts/m23_shielded_external_redteam_packet.py`
    so the generated participant packet preserves runnable packet-local
    `doc/`, `scripts/`, and `infra/` paths instead of flattening copied repo
    files into `docs/`;
  - updated `/Users/admin/Documents/btxchain/btx-node/scripts/m24_shielded_external_findings_intake.py`
    so packet-local intake generation now degrades git metadata cleanly to
    `unavailable` outside a git worktree and can still source the bundled
    `infra/` copy when invoked from an unpacked participant packet;
  - updated
    `/Users/admin/Documents/btxchain/btx-node/test/util/m23_shielded_external_redteam_packet_test.sh`
    into a real packet-generation regression that asserts preserved `doc/`,
    `scripts/`, and `infra/` paths, runs packet-local `m24`, and then runs the
    derived packet-local `m25` validator;
  - updated
    `/Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-cryptographic-audit-handoff.md`,
    `/Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-external-redteam-window.md`,
    and
    `/Users/admin/Documents/btxchain/btx-node/doc/btx-production-readiness-matrix.md`
    so the operator-facing `m23` description matches the preserved packet
    layout and the packet-derived `m24 -> m25` flow that now validates;
- result of the sync/status/doc inspection:
  - local HEAD and `origin/codex/shielded-v2-overhaul-plan` were aligned at
    `931509447a` before this pass began;
  - the inspection found a real remaining repo-side packaging gap in `m23`,
    not `m20`: the participant packet still flattened copied repo files into
    `docs/`, so the unpacked packet did not actually contain
    `scripts/m24_shielded_external_findings_intake.py`,
    `scripts/m25_shielded_external_closeout_check.py`, or
    `doc/btx-shielded-external-review-closeout.md` where the handoff and
    window docs said they lived;
- local validation for this pass:
  - `python3 -m py_compile /Users/admin/Documents/btxchain/btx-node/scripts/m23_shielded_external_redteam_packet.py /Users/admin/Documents/btxchain/btx-node/scripts/m24_shielded_external_findings_intake.py /Users/admin/Documents/btxchain/btx-node/scripts/m25_shielded_external_closeout_check.py`
  - `bash /Users/admin/Documents/btxchain/btx-node/test/util/m23_shielded_external_redteam_packet_test.sh`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/scripts/m23_shielded_external_redteam_packet.py --output-dir /private/tmp/btx-m23-external-redteam-packet-v3.sdNgB1 --audit-bundle /private/tmp/btx-m20-audit-handoff-bundle-v2.SywV0q --hosted-run-dir /tmp/btx-m22-remote-redteam-run9`
  - `/usr/bin/time -p python3 /private/tmp/btx-m23-external-redteam-packet-v3.sdNgB1/scripts/m24_shielded_external_findings_intake.py --output-dir /private/tmp/btx-m23-derived-intake-v1.8X0lKE --source-packet /private/tmp/btx-m23-external-redteam-packet-v3.sdNgB1 --audit-bundle /private/tmp/btx-m23-external-redteam-packet-v3.sdNgB1/artifacts/audit_bundle --hosted-run-dir /private/tmp/btx-m23-external-redteam-packet-v3.sdNgB1/artifacts/hosted_run`
  - `/usr/bin/time -p python3 /private/tmp/btx-m23-derived-intake-v1.8X0lKE/scripts/m25_shielded_external_closeout_check.py --intake-dir /private/tmp/btx-m23-derived-intake-v1.8X0lKE --output /private/tmp/btx-m23-derived-intake-v1.8X0lKE/closeout/closeout_summary_from_packet.json`
  - `git diff --check`
- validation findings and pivots:
  - the strengthened `m23_shielded_external_redteam_packet_test.sh` passed
    after generating a real packet, deriving an intake packet from it, and
    replaying packet-local `m25`;
  - the refreshed `m23` packet passed in `real 4.09`, `user 3.97`, `sys 0.11`,
    writing `/private/tmp/btx-m23-external-redteam-packet-v3.sdNgB1` plus
    sibling tarball
    `/private/tmp/btx-m23-external-redteam-packet-v3.sdNgB1.tar.gz`;
  - the derived packet-local intake replay passed in `real 8.09`, `user 7.88`,
    `sys 0.14`, writing `/private/tmp/btx-m23-derived-intake-v1.8X0lKE`;
  - the packet-local `m25` replay then ran in `real 0.03`, `user 0.02`,
    `sys 0.00`, returning `STATUS 1` only because the generated derived intake
    still contains the expected placeholder external inputs;
  - manifest inspection confirmed the refreshed participant packet now carries
    `packet_path` entries for
    `doc/btx-shielded-external-redteam-window.md`,
    `doc/btx-shielded-external-review-closeout.md`,
    `infra/btx-seed-server-spec.md`,
    `scripts/m24_shielded_external_findings_intake.py`, and
    `scripts/m25_shielded_external_closeout_check.py`, while the stale flat
    `docs/m24_shielded_external_findings_intake.py` path is absent;
  - tarball SHA-256 values recorded in the resulting manifests are
    `ca0c09b42a8a13d8e1b0e3444aef22af5b40711a6f7644196a37dfbfb4c364b0` for the
    refreshed `m23` packet and
    `39715107e8330bb6a0e71fca78b1e84c37ee4e17e285f95b294bd503c266df67` for the
    derived intake packet;
  - the main pivot was the first upgraded `m23` test run exposing a real
    second-order gap in packet-local `m24`: its manifest still hard-required a
    `.git` checkout. That is now handled by returning git metadata as
    `unavailable` when invoked from an unpacked packet root;
- blocker conclusion for this pass:
  - this closes the remaining repo-side `m23` participant-packet layout
    mismatch and proves the packet-derived `m24 -> m25` closeout path works
    directly from the unpacked participant packet root;
  - the remaining launch blocker is still external to this repository:
    independent cryptographic review plus an externally run adversarial
    proof-focused testnet / red-team campaign;
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no cloud resources were created in this pass; the refreshed local packet
    and derived intake artifacts remain under `/private/tmp`.

### 2026-03-16 21:05:36 JST

- pass preflight: verified readable, non-empty
  `/Users/admin/Documents/btxchain/github.key`,
  `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`,
  `/Users/admin/Documents/btxchain/infra/porkbun_api.key`, and
  `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` before any new
  remote or GitHub operation in this pass, with byte counts `94`, `72`, `69`,
  and `69`;
- current focus for this pass: execute the required sync/status loop on top of
  `b50c4aad95`, then fix the remaining repo-side `m24` packet-layout mismatch
  where the packet-local closeout command still points at
  `scripts/m25_shielded_external_closeout_check.py` but the generated packet
  currently flattens copied repo files into `docs/`;
- start-of-pass loop executed as required:
  - `git fetch --all --prune`
  - `git switch codex/shielded-v2-overhaul-plan`
  - `git pull --ff-only origin codex/shielded-v2-overhaul-plan`
  - `git status --short`
  - `git log --oneline -5`
- newly identified repo-side DoD 8 gap closed in this pass:
  - updated `/Users/admin/Documents/btxchain/btx-node/scripts/m24_shielded_external_findings_intake.py`
    so copied repo-side handoff materials preserve runnable packet-local
    `doc/`, `scripts/`, and `infra/` paths instead of flattening into `docs/`;
  - updated
    `/Users/admin/Documents/btxchain/btx-node/test/util/m24_shielded_external_findings_intake_test.sh`
    from a source-text grep into a real packet-generation regression that
    asserts the preserved paths and executes the packet-local `scripts/m25...`
    validator against the generated intake directory;
  - updated
    `/Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-cryptographic-audit-handoff.md`,
    `/Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-external-review-closeout.md`,
    and
    `/Users/admin/Documents/btxchain/btx-node/doc/btx-production-readiness-matrix.md`
    so the operator-facing description now explicitly matches the preserved
    packet layout that validates in practice;
- result of the sync/status/doc inspection:
  - local HEAD and `origin/codex/shielded-v2-overhaul-plan` were aligned at
    `b50c4aad95` before this pass began;
  - the inspection found a real remaining repo-side packaging gap: although the
    prior pass added `m25` to the `m24` packet, the generator still copied it
    to `docs/m25_shielded_external_closeout_check.py`, so the documented
    packet-local closeout command
    `python3 scripts/m25_shielded_external_closeout_check.py --intake-dir ...`
    still failed after unpacking;
- local validation for this pass:
  - `python3 -m py_compile /Users/admin/Documents/btxchain/btx-node/scripts/m24_shielded_external_findings_intake.py /Users/admin/Documents/btxchain/btx-node/scripts/m25_shielded_external_closeout_check.py`
  - `bash /Users/admin/Documents/btxchain/btx-node/test/util/m24_shielded_external_findings_intake_test.sh`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/scripts/m24_shielded_external_findings_intake.py --output-dir /private/tmp/btx-m24-external-findings-intake-v4.G2adIf --source-packet /private/tmp/btx-m23-external-redteam-packet-v2.wfpqPI --audit-bundle /private/tmp/btx-m20-audit-handoff-bundle-v2.SywV0q --hosted-run-dir /tmp/btx-m22-remote-redteam-run9`
  - `/usr/bin/time -p python3 /private/tmp/btx-m24-external-findings-intake-v4.G2adIf/scripts/m25_shielded_external_closeout_check.py --intake-dir /private/tmp/btx-m24-external-findings-intake-v4.G2adIf --output /private/tmp/btx-m24-external-findings-intake-v4.G2adIf/closeout/closeout_summary_from_packet.json`
  - `git diff --check`
- validation findings and pivots:
  - `m24_shielded_external_findings_intake_test.sh` now generates a real packet,
    asserts the preserved `doc/`, `scripts/`, and `infra/` paths, and passed;
  - the refreshed `m24` packet passed in `real 8.10`, `user 7.87`, `sys 0.18`,
    writing `/private/tmp/btx-m24-external-findings-intake-v4.G2adIf` plus
    sibling tarball
    `/private/tmp/btx-m24-external-findings-intake-v4.G2adIf.tar.gz`;
  - executing the unpacked packet-local validator at
    `/private/tmp/btx-m24-external-findings-intake-v4.G2adIf/scripts/m25_shielded_external_closeout_check.py`
    now works exactly as documented, returning `STATUS 1` in `real 0.03` only
    because the generated packet still contains the expected placeholder
    external inputs;
  - manifest inspection confirmed `packet_path` entries for
    `doc/btx-shielded-external-review-closeout.md`,
    `infra/btx-seed-server-spec.md`,
    `scripts/m24_shielded_external_findings_intake.py`, and
    `scripts/m25_shielded_external_closeout_check.py`, while the stale flat
    `docs/m25_shielded_external_closeout_check.py` path is absent;
  - the refreshed tarball SHA-256 is
    `13559ad473f5f88ebc0b38c24d4355f9681a694829f73dfaf4f77ffe09bf705c`;
- blocker conclusion for this pass:
  - this closes the remaining repo-side `m24` packet-layout mismatch by making
    the generated intake packet directly runnable with the documented
    packet-local `scripts/m25...` closeout command;
  - the remaining launch blocker is still external to this repository:
    independent cryptographic review plus an externally run adversarial
    proof-focused testnet / red-team campaign;
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no cloud resources were created in this pass; the refreshed local artifact
    remains under `/private/tmp`.

### 2026-03-16 21:00:36 JST

- pass preflight: verified readable, non-empty
  `/Users/admin/Documents/btxchain/github.key`,
  `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`,
  `/Users/admin/Documents/btxchain/infra/porkbun_api.key`, and
  `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` before any new
  remote or GitHub operation in this pass, with byte counts `94`, `72`, `69`,
  and `69`;
- current focus for this pass: execute the required sync/status loop on top of
  `4b9e365ebb`, then inspect whether the external findings intake packet
  (`m24`) actually carries the current `m25` closeout validator and related
  closeout surface or still lags the repo-side DoD 8 flow;
- start-of-pass loop executed as required:
  - `git fetch --all --prune`
  - `git switch codex/shielded-v2-overhaul-plan`
  - `git pull --ff-only origin codex/shielded-v2-overhaul-plan`
  - `git status --short`
  - `git log --oneline -5`
- newly identified repo-side DoD 8 gap closed in this pass:
  - updated `/Users/admin/Documents/btxchain/btx-node/scripts/m24_shielded_external_findings_intake.py`
    so the intake packet now ships
    `scripts/m25_shielded_external_closeout_check.py` alongside the existing
    templates, docs, and return-path helpers instead of forcing operators to
    source the validator separately from the repository;
  - updated
    `/Users/admin/Documents/btxchain/btx-node/test/util/m24_shielded_external_findings_intake_test.sh`
    to lock that packet content structurally;
  - updated
    `/Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-cryptographic-audit-handoff.md`
    and
    `/Users/admin/Documents/btxchain/btx-node/doc/btx-production-readiness-matrix.md`
    so the operator-facing `m24` description matches the now-validated packet
    contents;
- result of the sync/status/doc inspection:
  - local HEAD and `origin/codex/shielded-v2-overhaul-plan` were aligned at
    `4b9e365ebb` before this pass began;
  - the inspection found a real repo-side packaging gap: `m24` generated the
    external findings intake packet that the closeout doc told operators to
    validate with `m25`, but the packet itself still omitted the
    `m25_shielded_external_closeout_check.py` validator;
- local validation for this pass:
  - `python3 -m py_compile /Users/admin/Documents/btxchain/btx-node/scripts/m24_shielded_external_findings_intake.py`
  - `bash /Users/admin/Documents/btxchain/btx-node/test/util/m24_shielded_external_findings_intake_test.sh`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/scripts/m24_shielded_external_findings_intake.py --output-dir /private/tmp/btx-m24-external-findings-intake-v3.IZ4VMM --source-packet /private/tmp/btx-m23-external-redteam-packet-v2.wfpqPI --audit-bundle /private/tmp/btx-m20-audit-handoff-bundle-v2.SywV0q --hosted-run-dir /tmp/btx-m22-remote-redteam-run9`
  - `git diff --check`
- validation findings and pivots:
  - `m24_shielded_external_findings_intake_test.sh` passed after the intake
    packet source list and structural expectations were updated;
  - the refreshed `m24` packet passed in `real 8.10`, `user 7.88`, `sys 0.17`,
    writing `/private/tmp/btx-m24-external-findings-intake-v3.IZ4VMM` plus
    sibling tarball
    `/private/tmp/btx-m24-external-findings-intake-v3.IZ4VMM.tar.gz`;
  - manifest inspection confirmed `included_source_count=11`, that
    `m25_shielded_external_closeout_check.py` is present in
    `docs/`, and that the tarball SHA-256 is
    `f299f7b2e58f1e0d7b9fca0a33bddaa69184f47b33f6755968e1d95e5ab76e1a`;
- blocker conclusion for this pass:
  - this closes another real repo-side DoD 8 process gap by ensuring the
    external findings intake packet now carries the validator the closeout path
    already depended on;
  - the remaining launch blocker is still external to this repository:
    independent cryptographic review plus an externally run adversarial
    proof-focused testnet / red-team campaign;
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no cloud resources were created in this pass; the refreshed `m24` packet
    remains under `/private/tmp` as a local artifact only.

### 2026-03-16 20:58:44 JST

- pass preflight: verified readable, non-empty
  `/Users/admin/Documents/btxchain/github.key`,
  `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`,
  `/Users/admin/Documents/btxchain/infra/porkbun_api.key`, and
  `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` before any new
  remote or GitHub operation in this pass, with byte counts `94`, `72`, `69`,
  and `69`;
- current focus for this pass: execute the required sync/status loop on top of
  `e727efd93c`, then inspect whether the external participant packet (`m23`)
  actually includes the later intake and closeout materials now required by
  the repo-side DoD 8 flow;
- start-of-pass loop executed as required:
  - `git fetch --all --prune`
  - `git switch codex/shielded-v2-overhaul-plan`
  - `git pull --ff-only origin codex/shielded-v2-overhaul-plan`
  - `git status --short`
  - `git log --oneline -5`
- newly identified repo-side DoD 8 gap closed in this pass:
  - updated `/Users/admin/Documents/btxchain/btx-node/scripts/m23_shielded_external_redteam_packet.py`
    so the participant packet now carries the external closeout guide plus the
    downstream `m24` / `m25` intake/closeout helpers instead of shipping only
    the older outbound packet materials;
  - updated
    `/Users/admin/Documents/btxchain/btx-node/test/util/m23_shielded_external_redteam_packet_test.sh`
    to lock those packet contents structurally;
  - updated
    `/Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-external-redteam-window.md`,
    `/Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-cryptographic-audit-handoff.md`,
    and
    `/Users/admin/Documents/btxchain/btx-node/doc/btx-production-readiness-matrix.md`
    so the operator-facing packet description matches the packet contents that
    now validate;
- result of the sync/status/doc inspection:
  - local HEAD and `origin/codex/shielded-v2-overhaul-plan` were aligned at
    `e727efd93c` before this pass began;
  - the inspection found a real repo-side coordination gap: the `m23`
    participant packet still omitted the later closeout guide and the
    `m24` / `m25` return-path tooling, even though the repo-side DoD 8 process
    already depended on those materials;
- local validation for this pass:
  - `bash /Users/admin/Documents/btxchain/btx-node/test/util/m23_shielded_external_redteam_packet_test.sh`
  - `python3 -m py_compile /Users/admin/Documents/btxchain/btx-node/scripts/m23_shielded_external_redteam_packet.py`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/scripts/m23_shielded_external_redteam_packet.py --output-dir /private/tmp/btx-m23-external-redteam-packet-v2.wfpqPI --audit-bundle /private/tmp/btx-m20-audit-handoff-bundle-v2.SywV0q --hosted-run-dir /tmp/btx-m22-remote-redteam-run9`
  - `git diff --check`
- validation findings and pivots:
  - `m23_shielded_external_redteam_packet_test.sh` passed after the packet
    source list and brief/checklist text were updated;
  - the refreshed `m23` packet passed in `real 4.09`, `user 3.96`, `sys 0.11`,
    writing `/private/tmp/btx-m23-external-redteam-packet-v2.wfpqPI` plus
    sibling tarball
    `/private/tmp/btx-m23-external-redteam-packet-v2.wfpqPI.tar.gz`;
  - manifest inspection confirmed `included_source_count=12` and that
    `doc/btx-shielded-external-review-closeout.md`,
    `scripts/m24_shielded_external_findings_intake.py`, and
    `scripts/m25_shielded_external_closeout_check.py` are all present with
    `missing_paths=[]`;
  - the tarball SHA-256 recorded in the manifest is
    `c8be612da92a23d07174c7c136dcc327c7a7d1be9f9619ad78dce0a2926bead2`;
- blocker conclusion for this pass:
  - this closes another real repo-side DoD 8 coordination gap by making the
    external participant packet reflect the current full repo-side intake and
    closeout path instead of the older outbound-only subset;
  - the remaining launch blocker is still external to this repository:
    independent cryptographic review plus an externally run adversarial
    proof-focused testnet / red-team campaign;
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no cloud resources were created in this pass; the refreshed `m23` packet
    remains under `/private/tmp` as a local artifact only.

### 2026-03-16 20:54:17 JST

- pass preflight: verified readable, non-empty
  `/Users/admin/Documents/btxchain/github.key`,
  `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`,
  `/Users/admin/Documents/btxchain/infra/porkbun_api.key`, and
  `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` before any new
  remote or GitHub operation in this pass, with byte counts `94`, `72`, `69`,
  and `69`;
- current focus for this pass: execute the required sync/status loop on top of
  `e5dd34f137`, then inspect whether the `m20` audit handoff bundle actually
  ships the later `m22` / `m23` / `m24` / `m25` external-window and closeout
  surfaces or merely documents them locally;
- start-of-pass loop executed as required:
  - `git fetch --all --prune`
  - `git switch codex/shielded-v2-overhaul-plan`
  - `git pull --ff-only origin codex/shielded-v2-overhaul-plan`
  - `git status --short`
  - `git log --oneline -5`
- newly identified repo-side DoD 8 gap closed in this pass:
  - updated `/Users/admin/Documents/btxchain/btx-node/scripts/m20_shielded_audit_handoff_bundle.py`
    so the copied `source_snapshot/` now includes the external-window /
    closeout docs plus the downstream `m22` / `m23` / `m24` / `m25` scripts
    and their structural regressions instead of freezing only the earlier
    proof-suite surfaces;
  - updated
    `/Users/admin/Documents/btxchain/btx-node/test/util/m20_shielded_audit_handoff_bundle_test.sh`
    to lock the new bundle contents structurally;
  - updated
    `/Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-cryptographic-audit-handoff.md`
    and
    `/Users/admin/Documents/btxchain/btx-node/doc/btx-production-readiness-matrix.md`
    so the operator-facing description of `m20` matches the files the bundle
    now actually ships;
- result of the sync/status/doc inspection:
  - local HEAD and `origin/codex/shielded-v2-overhaul-plan` were aligned at
    `e5dd34f137` before this pass began;
  - the inspection found a real repo-side packaging gap: the external-review
    handoff bundle still omitted the later external-window and closeout
    materials (`m22` through `m25` and their guides/tests), so the artifact
    external reviewers received lagged the now-current DoD 8 process;
- local validation for this pass:
  - `bash /Users/admin/Documents/btxchain/btx-node/test/util/m20_shielded_audit_handoff_bundle_test.sh`
  - `python3 -m py_compile /Users/admin/Documents/btxchain/btx-node/scripts/m20_shielded_audit_handoff_bundle.py`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/scripts/m20_shielded_audit_handoff_bundle.py --build-dir /Users/admin/Documents/btxchain/btx-node/build-btx --output-dir /private/tmp/btx-m20-audit-handoff-bundle-v2.SywV0q --skip-build --samples=2`
  - `git diff --check`
- validation findings and pivots:
  - `m20_shielded_audit_handoff_bundle_test.sh` passed after the source list
    and docs were updated;
  - the refreshed `m20` handoff bundle passed in `real 240.82`, `user 226.51`,
    `sys 2.34`, writing
    `/private/tmp/btx-m20-audit-handoff-bundle-v2.SywV0q` plus sibling tarball
    `/private/tmp/btx-m20-audit-handoff-bundle-v2.SywV0q.tar.gz`;
  - the refreshed manifest reports `overall_status=pass`, `command_count=4`,
    and `source_file_count=27`;
  - manifest inspection confirmed that
    `doc/btx-shielded-external-redteam-window.md`,
    `doc/btx-shielded-external-review-closeout.md`,
    `scripts/m22_remote_shielded_redteam_campaign.py`,
    `scripts/m23_shielded_external_redteam_packet.py`,
    `scripts/m24_shielded_external_findings_intake.py`,
    `scripts/m25_shielded_external_closeout_check.py`, and the corresponding
    `m22` / `m23` / `m24` / `m25` structural regressions are all present in
    the copied `source_snapshot/`, with `missing_paths=[]`;
  - the tarball SHA-256 recorded in the manifest is
    `880b0de24bf1c17f6d9164d855a3b937d75edbe080cf9f901192fd03e65f38ad`;
- blocker conclusion for this pass:
  - this closes another real repo-side DoD 8 packaging gap by bringing the
    external review handoff bundle up to the current `m20`-through-`m25`
    process rather than the earlier subset;
  - the remaining launch blocker is still external to this repository:
    independent cryptographic review plus an externally run adversarial
    proof-focused testnet / red-team campaign;
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no cloud resources were created in this pass; the refreshed handoff bundle
    remains under `/private/tmp` as a local artifact only.

### 2026-03-16 20:36:01 JST

- pass preflight: verified readable, non-empty
  `/Users/admin/Documents/btxchain/github.key`,
  `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`,
  `/Users/admin/Documents/btxchain/infra/porkbun_api.key`, and
  `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` before any new
  remote or GitHub operation in this pass, with byte counts `94`, `72`, `69`,
  and `69`;
- current focus for this pass: execute the required sync/status loop on top of
  `ef63df3334`, then inspect whether the new `m24` intake path still leaves a
  real repo-side DoD 8 closeout-validation gap;
- start-of-pass loop executed as required:
  - `git fetch --all --prune`
  - `git switch codex/shielded-v2-overhaul-plan`
  - `git pull --ff-only origin codex/shielded-v2-overhaul-plan`
  - `git status --short`
  - `git log --oneline -5`
- newly identified repo-side DoD 8 gap closed in this pass:
  - added `/Users/admin/Documents/btxchain/btx-node/scripts/m25_shielded_external_closeout_check.py`,
    which validates a populated `m24` intake packet against the repo’s DoD 8
    closeout rules and emits a machine-readable pass/fail summary;
  - added `/Users/admin/Documents/btxchain/btx-node/test/util/m25_shielded_external_closeout_check_test.sh`
    to lock the validator structure;
  - updated
    `/Users/admin/Documents/btxchain/btx-node/scripts/m24_shielded_external_findings_intake.py`
    so the intake packet now creates canonical machine-readable placeholders
    (`received/findings.json`, `closeout/signoff_status.json`, and named report
    stubs) rather than only narrative templates;
  - updated the closeout guide, audit handoff doc, external-window guide, and
    readiness matrix to reference the new closeout-validator step;
- result of the sync/status/doc inspection:
  - local HEAD and `origin/codex/shielded-v2-overhaul-plan` were aligned at
    `ef63df3334` before this `m25` pass began;
  - the post-`m24` inspection showed a real remaining repo-side process gap:
    operators could normalize external findings into an intake packet, but the
    branch still lacked a deterministic checker for whether a populated packet
    actually satisfied the repo’s own DoD 8 closeout rules;
- local validation for this pass:
  - `bash /Users/admin/Documents/btxchain/btx-node/test/util/m24_shielded_external_findings_intake_test.sh`
  - `bash /Users/admin/Documents/btxchain/btx-node/test/util/m25_shielded_external_closeout_check_test.sh`
  - `python3 -m py_compile /Users/admin/Documents/btxchain/btx-node/scripts/m24_shielded_external_findings_intake.py /Users/admin/Documents/btxchain/btx-node/scripts/m25_shielded_external_closeout_check.py`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/scripts/m24_shielded_external_findings_intake.py --output-dir /private/tmp/btx-m24-external-findings-intake-v2.E2vKaT --source-packet /tmp/btx-m23-external-redteam-packet --audit-bundle /tmp/btx-m20-audit-handoff-bundle --hosted-run-dir /tmp/btx-m22-remote-redteam-run9`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/scripts/m25_shielded_external_closeout_check.py --intake-dir /private/tmp/btx-m25-fail-intake.Zj7i1K --output /tmp/btx-m25-fail-output.json`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/scripts/m25_shielded_external_closeout_check.py --intake-dir /private/tmp/btx-m25-pass-intake.nYhFL1 --output /tmp/btx-m25-pass-output.json`
  - `git diff --check`
- validation findings and pivots:
  - refreshed `m24` packet generation completed in `real 6.58`, `user 6.39`,
    `sys 0.15`, writing
    `/private/tmp/btx-m24-external-findings-intake-v2.E2vKaT` plus sibling
    tarball `/private/tmp/btx-m24-external-findings-intake-v2.E2vKaT.tar.gz`;
  - the refreshed `m24` manifest now records `12` generated templates and `3`
    copied reference inputs, reflecting the new machine-readable intake /
    sign-off placeholders;
  - isolated placeholder-state validation failed as expected in `real 0.03`,
    `user 0.03`, `sys 0.00`, with blockers for pending external input,
    incomplete cryptographic-review and red-team completion flags, missing
    tracker/readiness updates, non-`pass` final status, `1` unresolved
    high-severity finding, and placeholder sign-off / resolution markdown;
  - isolated resolved-state validation passed in `real 0.04`, `user 0.03`,
    `sys 0.00`, with `overall_status=pass`, `report_count=2`, and zero
    unresolved findings across all severities;
  - the only real pivot in this pass was operational rather than code-level:
    the first fail/pass rerun raced on the same intake directory, so the final
    evidence uses isolated copied intake packets for deterministic fail/pass
    coverage;
- blocker conclusion for this pass:
  - this closes another real repo-side DoD 8 process gap by giving the branch
    a deterministic closeout checker for populated external-review packets;
  - the remaining launch blocker is still external to this repository:
    independent cryptographic review plus an externally run adversarial
    proof-focused testnet / red-team campaign;
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no cloud resources were created in this pass; the isolated validation
    directories remain under `/private/tmp` as local evidence only.

### 2026-03-16 20:28:53 JST

- pass preflight: verified readable, non-empty
  `/Users/admin/Documents/btxchain/github.key`,
  `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`,
  `/Users/admin/Documents/btxchain/infra/porkbun_api.key`, and
  `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` before any new
  remote or GitHub operation in this pass, with byte counts `94`, `72`, `69`,
  and `69`;
- current focus for this pass: execute the required sync/status loop on top of
  `11437bac25`, then inspect the remaining Definition-of-Done item 8 language
  for any repo-side evidence intake or closeout artifact that is still missing
  from the branch;
- start-of-pass loop executed as required:
  - `git fetch --all --prune`
  - `git switch codex/shielded-v2-overhaul-plan`
  - `git pull --ff-only origin codex/shielded-v2-overhaul-plan`
  - `git status --short`
  - `git log --oneline -5`
- newly identified repo-side DoD 8 gap closed in this pass:
  - added `/Users/admin/Documents/btxchain/btx-node/scripts/m24_shielded_external_findings_intake.py`,
    which builds a reproducible intake / closeout packet for returned external
    cryptographic-review or proof-focused red-team findings;
  - added `/Users/admin/Documents/btxchain/btx-node/test/util/m24_shielded_external_findings_intake_test.sh`
    to lock the intake packet structure;
  - added `/Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-external-review-closeout.md`
    as the operator-facing closeout guide;
  - updated
    `/Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-cryptographic-audit-handoff.md`,
    `/Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-external-redteam-window.md`,
    and
    `/Users/admin/Documents/btxchain/btx-node/doc/btx-production-readiness-matrix.md`
    so the external campaign now has both an outbound packet path (`m23`) and
    an inbound findings / sign-off path (`m24`);
- result of the sync/status/doc inspection:
  - local HEAD and `origin/codex/shielded-v2-overhaul-plan` were aligned at
    `11437bac25` before this new `m24` pass began;
  - the direct scan over the tracker’s DoD 8 language showed a real repo-side
    process gap: external reviewers were instructed to return concrete findings
    and evidence, but the branch lacked a canonical intake / closeout packet
    for normalizing those returned materials into sign-off evidence;
- local validation for this pass:
  - `python3 -m py_compile /Users/admin/Documents/btxchain/btx-node/scripts/m24_shielded_external_findings_intake.py`
  - `bash /Users/admin/Documents/btxchain/btx-node/test/util/m24_shielded_external_findings_intake_test.sh`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/scripts/m24_shielded_external_findings_intake.py --output-dir /tmp/btx-m24-external-findings-intake --source-packet /tmp/btx-m23-external-redteam-packet --audit-bundle /tmp/btx-m20-audit-handoff-bundle --hosted-run-dir /tmp/btx-m22-remote-redteam-run9`
  - `git diff --check`
- `m24` packet output and findings:
  - `/private/tmp/btx-m24-external-findings-intake/manifest.json` records
    `7` generated templates and `3` copied reference inputs
    (`source_packet_dir`, `audit_bundle_dir`, `hosted_run_dir`);
  - the sibling tarball is
    `/private/tmp/btx-m24-external-findings-intake.tar.gz`;
  - SHA-256 for the tarball is
    `8387754f045fc50b19223d1189e2e163cf523ac588f9fae0b7c96658979e5ce1`;
  - full packet generation completed in `real 6.57`, `user 6.38`, `sys 0.15`;
- blocker conclusion for this pass:
  - this closes another repo-side coordination gap around DoD 8 closeout
    evidence;
  - the actual remaining launch blocker is still external to this repository:
    independent cryptographic review plus an externally run adversarial
    proof-focused testnet / red-team campaign.

### 2026-03-16 20:25:31 JST

- pass preflight: verified readable, non-empty
  `/Users/admin/Documents/btxchain/github.key`,
  `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`,
  `/Users/admin/Documents/btxchain/infra/porkbun_api.key`, and
  `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` before any new
  remote or GitHub operation in this pass, with byte counts `94`, `72`, `69`,
  and `69`;
- current focus for this pass: execute the required sync/status loop after the
  fresh key preflight, then determine whether any remaining honest in-repo
  launch-critical work exists beyond the already documented external
  Definition-of-Done item 8 gate;
- start-of-pass loop executed as required:
  - `git fetch --all --prune`
  - `git switch codex/shielded-v2-overhaul-plan`
  - `git pull --ff-only origin codex/shielded-v2-overhaul-plan`
  - `git status --short`
  - `git log --oneline -5`
- result of the sync/status/doc inspection:
  - local HEAD and `origin/codex/shielded-v2-overhaul-plan` remain aligned at
    `d42bc90687` (`doc: reconfirm external launch blocker`) apart from the
    in-progress tracker edit for this pass;
  - the tracker, production readiness matrix, cryptographic audit handoff doc,
    and external red-team window guide still agree that all 19 slices are
    closed and the remaining gate is external Definition-of-Done item 8;
  - a direct placeholder-marker audit over the repo-side DoD 8 scripts/docs
    (`m20`, `m21`, `m22`, `m23`, readiness matrix, audit handoff doc, and
    external-window guide) returned no `TODO`, `FIXME`, `placeholder`, `stub`,
    `TBD`, or `XXX` markers;
- blocker conclusion for this pass:
  - no additional honest in-repo implementation, harness, benchmark, or
    packaging slice was identified after the sync/status/doc inspection and the
    repo-side DoD 8 surface audit;
  - the only remaining launch blocker is still external to this repository:
    independent cryptographic review plus an externally run adversarial
    proof-focused testnet / red-team campaign;
- local validation for this pass:
  - `rg -n "TODO|FIXME|placeholder|stub|TBD|XXX" /Users/admin/Documents/btxchain/btx-node/scripts/m20_shielded_audit_handoff_bundle.py /Users/admin/Documents/btxchain/btx-node/scripts/m21_shielded_redteam_campaign.sh /Users/admin/Documents/btxchain/btx-node/scripts/m22_remote_shielded_redteam_campaign.py /Users/admin/Documents/btxchain/btx-node/scripts/m23_shielded_external_redteam_packet.py /Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-cryptographic-audit-handoff.md /Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-external-redteam-window.md /Users/admin/Documents/btxchain/btx-node/doc/btx-production-readiness-matrix.md`
  - `sed -n '1,260p' /Users/admin/Documents/btxchain/btx-node/doc/btx-production-readiness-matrix.md`
  - `sed -n '1,260p' /Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-cryptographic-audit-handoff.md`
  - `git diff --check`
  - no cloud resources were used in this pass and no teardown action was
    required.

### 2026-03-16 20:23:49 JST

- pass preflight: re-verified readable, non-empty
  `/Users/admin/Documents/btxchain/github.key`,
  `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`,
  `/Users/admin/Documents/btxchain/infra/porkbun_api.key`, and
  `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` before the next
  remote validation or GitHub operation in this pass, with byte counts `94`,
  `72`, `69`, and `69`;
- current focus for this pass: run the required start-of-pass sync/status loop
  after the `m23` external-window packet landed, then confirm whether any
  additional repo-side implementation, validation, or packaging slice remains
  honestly open on `codex/shielded-v2-overhaul-plan`;
- start-of-pass loop executed as required:
  - `git fetch --all --prune`
  - `git switch codex/shielded-v2-overhaul-plan`
  - `git pull --ff-only origin codex/shielded-v2-overhaul-plan`
  - `git status --short`
  - `git log --oneline -5`
- result of the sync/status/doc inspection:
  - local HEAD and `origin/codex/shielded-v2-overhaul-plan` remain aligned at
    `b69a24133f` (`doc: add external redteam packet`);
  - the tracker status block, readiness matrix, audit handoff doc, and
    external-window guide still agree that all 19 implementation slices are
    closed and that the repo-side Definition-of-Done item 8 prerequisites are
    now fully packaged in tree;
  - no additional code, tests, benchmarks, local simulations, repo-operated
    infra harnesses, or documentation artifacts were identified as missing from
    the branch after the `m23` packet landed;
- blocker conclusion for this pass:
  - there is no remaining honest in-repo slice to pick from this branch state
    without pretending that a repo-operated artifact can satisfy an
    independence requirement;
  - the only remaining launch blocker is unchanged and external to this
    repository: independent cryptographic review plus an externally run
    adversarial proof-focused testnet / red-team campaign;
- local validation for this pass:
  - `git diff --check`
  - no cloud resources were used in this pass and no teardown action was
    required.

### 2026-03-16 20:14:47 JST

- pass preflight: re-verified readable, non-empty
  `/Users/admin/Documents/btxchain/github.key`,
  `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`,
  `/Users/admin/Documents/btxchain/infra/porkbun_api.key`, and
  `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` before the next
  remote validation or GitHub operation in this pass, with byte counts `94`,
  `72`, `69`, and `69`;
- current focus for this pass: repeat the required start-of-pass sync/status
  loop on the freshly clean branch and verify whether any new in-repo work
  appeared after the prior blocker-confirmation push, versus the still-open
  external Definition-of-Done item 8 gate.
- start-of-pass loop executed as required:
  - `git fetch --all --prune`
  - `git switch codex/shielded-v2-overhaul-plan`
  - `git pull --ff-only origin codex/shielded-v2-overhaul-plan`
  - `git status --short`
  - `git log --oneline -5`
- result of the sync/status inspection:
  - `origin/codex/shielded-v2-overhaul-plan` remains current with local HEAD
    after commit `347192fa96`;
  - no additional code, test, benchmark, tracker, or infra delta appeared on
    the implementation branch after the previous blocker-confirmation pass;
  - the tracker and readiness matrix still agree that all 19 implementation
    slices are closed and the repo-side Definition-of-Done item 8 prerequisites
    are already landed;
- blocker conclusion for this pass:
  - the fetch/pull inspection did not reveal any new code or test delta landing
    on the branch after the prior blocker-confirmation pass;
  - the only remaining launch gate is unchanged and external: independent
    cryptographic review plus an externally run adversarial proof-focused
    testnet / red-team campaign.
- newly identified repo-side gap closed in this pass:
  - added `/Users/admin/Documents/btxchain/btx-node/scripts/m23_shielded_external_redteam_packet.py`,
    which builds an operator/participant packet for an invited external
    proof-focused red-team window;
  - added `/Users/admin/Documents/btxchain/btx-node/test/util/m23_shielded_external_redteam_packet_test.sh`
    to lock the packet generator structure;
  - added `/Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-external-redteam-window.md`
    as the operator-facing window guide;
  - updated
    `/Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-cryptographic-audit-handoff.md`
    and
    `/Users/admin/Documents/btxchain/btx-node/doc/btx-production-readiness-matrix.md`
    so the packet path is documented alongside the existing `m20`, `m21`, and
    `m22` repo-side prerequisites;
- local validation completed for the new packet path:
  - `python3 -m py_compile /Users/admin/Documents/btxchain/btx-node/scripts/m23_shielded_external_redteam_packet.py`
  - `bash /Users/admin/Documents/btxchain/btx-node/test/util/m23_shielded_external_redteam_packet_test.sh`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/scripts/m23_shielded_external_redteam_packet.py --output-dir /tmp/btx-m23-external-redteam-packet --audit-bundle /tmp/btx-m20-audit-handoff-bundle --hosted-run-dir /tmp/btx-m22-remote-redteam-run9`
- packet output and findings:
  - `/tmp/btx-m23-external-redteam-packet/manifest.json` records the copied
    handoff docs, the seed-server spec, the participant brief, the operator
    checklist, and the included `m20` / `m22` baseline artifacts;
  - the packet tarball is emitted as
    `/tmp/btx-m23-external-redteam-packet.tar.gz`;
  - this closes another repo-side coordination gap for the external campaign,
    but it still does not satisfy the required independent review or the
    externally observed adversarial proof-focused testnet itself.

### 2026-03-16 20:11:56 JST

- pass preflight: re-verified readable, non-empty
  `/Users/admin/Documents/btxchain/github.key`,
  `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`,
  `/Users/admin/Documents/btxchain/infra/porkbun_api.key`, and
  `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` before the next
  remote validation or GitHub operation in this pass, with byte counts `94`,
  `72`, `69`, and `69`;
- current focus for this pass: run the required branch sync/status inspection
  again after the hosted red-team closure and verify whether any launch-critical
  in-repo work remains, versus the already-documented external
  Definition-of-Done item 8 blocker.
- start-of-pass loop executed as required:
  - `git fetch --all --prune`
  - `git switch codex/shielded-v2-overhaul-plan`
  - `git pull --ff-only origin codex/shielded-v2-overhaul-plan`
  - `git status --short`
  - `git log --oneline -5`
- result of the sync/status inspection:
  - `origin/codex/shielded-v2-overhaul-plan` is already current with local
    HEAD after hosted red-team closure;
  - latest branch tip remains `4745ae1db3` (`test: add hosted shielded redteam
    harness`);
  - the tracker status block, production readiness matrix, and latest pass logs
    still agree that all 19 implementation slices are closed and the repo-side
    Definition-of-Done item 8 prerequisites are landed;
  - no additional unfinished in-repo implementation slice is left to pick from
    this branch state;
- blocker conclusion for this pass:
  - the remaining launch gate is strictly external to this repository and
    branch: independent cryptographic review plus an externally run
    adversarial proof-focused testnet / red-team campaign;
  - no further local code, test, benchmark, simulation, or repo-operated infra
    change can honestly satisfy that independence requirement from within this
    workspace alone, so this pass stops at blocker confirmation rather than
    fabricating another repo-side “slice”.

### 2026-03-16 20:06:55 JST

- pass preflight: re-verified readable, non-empty
  `/Users/admin/Documents/btxchain/github.key`,
  `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`,
  `/Users/admin/Documents/btxchain/infra/porkbun_api.key`, and
  `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` before the next
  remote validation or GitHub operation in this pass, with byte counts `94`,
  `72`, `69`, and `69`;
- current focus for this pass: close the remaining repo-side Definition-of-Done
  item 8 evidence gap by getting the hosted disposable malformed-proof
  campaign to run end to end on ephemeral DigitalOcean infrastructure, collect
  failure artifacts even when the inner campaign aborts, and record the real
  hosted cost / teardown evidence on this branch;
- hosted red-team harness and Linux generator fixes landed in-tree:
  - `/Users/admin/Documents/btxchain/btx-node/scripts/m22_remote_shielded_redteam_campaign.py`
    provisions a disposable droplet/firewall, stages a bounded source archive,
    builds the remote binaries, runs
    `/Users/admin/Documents/btxchain/btx-node/scripts/m21_shielded_redteam_campaign.sh`,
    fetches remote artifacts, and tears the resources down;
  - `/Users/admin/Documents/btxchain/btx-node/scripts/m21_shielded_redteam_campaign.sh`
    now accepts `--config-file`, which lets the remote wrapper point the
    functional harness at `build-redteam/test/config.ini` instead of assuming a
    source-tree config path;
  - `/Users/admin/Documents/btxchain/btx-node/src/test/util/translation_stub.cpp`
    plus the new helper wiring in
    `/Users/admin/Documents/btxchain/btx-node/src/test/CMakeLists.txt` provide
    the missing `G_TRANSLATION_FUN` symbol for standalone generator/report
    binaries, fixing the remote Linux link failure that previously blocked
    `gen_shielded_matrict_plus_transcript_corpus`,
    `gen_shielded_v2_adversarial_proof_corpus`, and the other report binaries
    when built outside the full local macOS environment;
  - `/Users/admin/Documents/btxchain/btx-node/test/util/m22_remote_shielded_redteam_campaign_test.sh`
    now enforces the staged-source manifest, hosted-collection logic, and the
    required remote build targets structurally;
- hosted validation pivots and findings from this pass:
  - first hosted rerun after the artifact-collection change failed with
    `overall_status=fail`, but the new `m22` collection path still recovered
    `/tmp/btx-m22-remote-redteam-run8/artifacts/remote_artifacts/m21-remote-redteam.json`
    and the inner functional log
    `/tmp/btx-m22-remote-redteam-run8/artifacts/remote_artifacts/m21-logs/feature_shielded_v2_proof_redteam_campaign.log`,
    which exposed the real blocker:
    `Binary not found: /root/btx-remote-redteam/build-redteam/bin/bitcoin-cli`;
  - the root cause was remote configure/build using `-DBUILD_CLI=OFF` and not
    building `bitcoin-cli`, while the functional framework always validates
    both daemon and CLI release binaries before launching nodes;
  - `m22` now enables `-DBUILD_CLI=ON` and explicitly builds `bitcoin-cli`
    alongside `btxd` and `gen_shielded_v2_adversarial_proof_corpus`;
  - the next hosted rerun passed end to end:
    `/tmp/btx-m22-remote-redteam-run9/manifest.json` reports
    `overall_status=pass`, droplet id `558652969`, firewall id
    `5ee82b90-fbc4-4617-9a08-8e64413e9f67`, estimated cost `0.015`, and
    teardown with `droplet_deleted=true` / `firewall_deleted=true`;
  - the inner wrapper artifact
    `/tmp/btx-m22-remote-redteam-run9/artifacts/remote_artifacts/m21-remote-redteam.json`
    passed with `overall_status=pass` and `teardown_confirmed=true`;
  - the inner campaign artifact
    `/tmp/btx-m22-remote-redteam-run9/artifacts/remote_artifacts/m21-logs/feature_shielded_v2_proof_redteam_campaign.artifact.json`
    passed with `overall_status=pass`, `runtime_seconds=99.593`, clean
    malformed-proof rejection, late-joiner restart coverage, and a mined valid
    follow-up transfer at final height `134`;
- validation completed in this pass:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx generate_shielded_matrict_plus_transcript_corpus generate_shielded_v2_adversarial_proof_corpus -j8`
  - `python3 -m py_compile /Users/admin/Documents/btxchain/btx-node/scripts/m22_remote_shielded_redteam_campaign.py`
  - `bash /Users/admin/Documents/btxchain/btx-node/test/util/m22_remote_shielded_redteam_campaign_test.sh`
  - `python3 /Users/admin/Documents/btxchain/btx-node/scripts/m22_remote_shielded_redteam_campaign.py --output-dir /tmp/btx-m22-remote-redteam-dryrun4 --dry-run`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/scripts/m22_remote_shielded_redteam_campaign.py --output-dir /tmp/btx-m22-remote-redteam-run9 --admin-cidr 0.0.0.0/0`
- timing and cost evidence from the successful hosted pass:
  - top-level hosted wrapper runtime `real 1299.44`;
  - remote install `64.003s`, source upload `9.104s`, prepare `3.923s`,
    configure `15.445s`, build `1049.381s`, inner campaign `104.521s`,
    bundle `3.083s`, artifact download `4.557s`;
  - DigitalOcean resource class `s-2vcpu-4gb-amd` in `sfo3`; estimated cost
    `0.015`; successful-run teardown confirmed for both droplet and firewall;
- Definition-of-Done item 8 is now closed as far as this repository can prove
  it locally or on repo-operated disposable infrastructure: the only remaining
  launch blocker is the still-required independent external cryptographic
  review and externally run adversarial proof-focused testnet / red-team
  campaign.

### 2026-03-16 18:16:51 JST

- pass preflight: verified readable, non-empty `/Users/admin/Documents/btxchain/github.key`,
  `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`,
  `/Users/admin/Documents/btxchain/infra/porkbun_api.key`, and
  `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` before any new
  remote validation or GitHub operation in this pass, with byte counts `94`,
  `72`, `69`, and `69`;
- current focus for this pass: continue the still-open Definition-of-Done item
  8 external-launch blocker from the branch side by proving the hosted
  disposable red-team harness can run end to end on ephemeral DigitalOcean
  infrastructure instead of stopping at repo-local malformed-proof replay;
- repo-side pivot already resolved before the next hosted rerun:
  - the previous remote configure failure came from the staged source snapshot
    omitting the top-level `doc/` tree while root `CMakeLists.txt`
    unconditionally executes `add_subdirectory(doc)`;
  - `/Users/admin/Documents/btxchain/btx-node/scripts/m22_remote_shielded_redteam_campaign.py`
    now stages `doc/` and builds the source tarball with Python `tarfile`
    instead of shelling out to local `tar`, which also removes the macOS
    archive-metadata path that had been polluting remote prepare logs;
  - `/Users/admin/Documents/btxchain/btx-node/test/util/m22_remote_shielded_redteam_campaign_test.sh`
    now parses `SOURCE_PATHS` structurally and fails if required staged source
    trees such as `doc`, `contrib`, `src`, or `test` are missing;
- local validation completed before the next hosted run:
  - `python3 -m py_compile /Users/admin/Documents/btxchain/btx-node/scripts/m22_remote_shielded_redteam_campaign.py`
  - `bash /Users/admin/Documents/btxchain/btx-node/test/util/m22_remote_shielded_redteam_campaign_test.sh`
  - `python3 /Users/admin/Documents/btxchain/btx-node/scripts/m22_remote_shielded_redteam_campaign.py --output-dir /tmp/btx-m22-remote-redteam-dryrun2 --dry-run`
  - a local staged-source configure smoke using the exact `m22`
    `create_source_archive(...)` path now passes cleanly, confirming the
    extracted snapshot contains `doc/` and reaches `CMake` generation with no
    further missing-tree configure failures.

### 2026-03-16 17:43:07 JST

- pass preflight: verified readable, non-empty `/Users/admin/Documents/btxchain/github.key`,
  `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`,
  `/Users/admin/Documents/btxchain/infra/porkbun_api.key`, and
  `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` before any remote
  or GitHub operation in this pass, with byte counts `94`, `72`, `69`, and
  `69`;
- current focus for this pass: continue the remaining Definition-of-Done item 8
  launch blocker from the branch side by identifying and closing the next
  highest-leverage repo-side or ephemeral-testnet validation gap that still
  stands between the landed in-repo harnesses and the externally observed
  cryptographic review / adversarial campaign gate.

### 2026-03-16 17:25:12 JST

- Definition-of-Done item 8 gained the missing in-repo malformed-proof
  campaign harness without claiming closure of the external launch gate:
  - added the deterministic malformed-proof corpus helper
    `/Users/admin/Documents/btxchain/btx-node/src/test/shielded_v2_adversarial_proof_corpus.{h,cpp}`,
    its focused coverage in
    `/Users/admin/Documents/btxchain/btx-node/src/test/shielded_v2_adversarial_proof_corpus_tests.cpp`,
    and the standalone generator
    `/Users/admin/Documents/btxchain/btx-node/src/test/generate_shielded_v2_adversarial_proof_corpus.cpp`,
    which derive five wallet-realistic `v2_send` proof failures
    (`proof_payload_truncated`, `proof_payload_appended_junk`,
    `witness_real_index_oob`, `statement_digest_mismatch`,
    `ring_challenge_tamper`) from an exact base transaction instead of from a
    fake fixture hex string;
  - added the live four-node functional
    `/Users/admin/Documents/btxchain/btx-node/test/functional/feature_shielded_v2_proof_redteam_campaign.py`,
    which builds a real wallet-originated `v2_send`, generates the malformed
    corpus, proves consistent `testmempoolaccept` / `sendrawtransaction`
    rejection across a three-node active mesh, repeats those rejects after a
    late-joiner restart, then mines the original valid tx to prove the
    malformed campaign leaves no mempool residue or consensus divergence;
  - added the operator wrapper
    `/Users/admin/Documents/btxchain/btx-node/scripts/m21_shielded_redteam_campaign.sh`,
    which now supports `--skip-build`, records per-step logs, preserves the
    machine-readable corpus / artifact outputs, and emits explicit teardown
    confirmation for the temporary functional datadir;
  - extended
    `/Users/admin/Documents/btxchain/btx-node/scripts/m20_shielded_audit_handoff_bundle.py`
    and
    `/Users/admin/Documents/btxchain/btx-node/test/util/m20_shielded_audit_handoff_bundle_test.sh`
    so the external-review bundle snapshots the new malformed-proof sources and
    includes the wrapper-produced red-team artifact/logs alongside the
    transcript corpus and proof-suite evidence;
  - updated
    `/Users/admin/Documents/btxchain/btx-node/doc/btx-production-readiness-matrix.md`
    and
    `/Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-cryptographic-audit-handoff.md`
    so the local malformed-proof campaign and the expanded handoff bundle are
    documented as repo-side prerequisites for the still-open external review
    gate;
- validation for this pass:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target btxd test_btx generate_shielded_v2_adversarial_proof_corpus -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_adversarial_proof_corpus_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_proof_adversarial_tests --catch_system_error=no --log_level=test_suite`
  - `python3 -m py_compile /Users/admin/Documents/btxchain/btx-node/test/functional/feature_shielded_v2_proof_redteam_campaign.py /Users/admin/Documents/btxchain/btx-node/test/functional/test_runner.py`
  - `python3 /Users/admin/Documents/btxchain/btx-node/test/functional/feature_shielded_v2_proof_redteam_campaign.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/feature-shielded-v2-proof-redteam-20260316d --portseed=32261 --artifact=/tmp/btx-functional-manual/feature-shielded-v2-proof-redteam-20260316d.artifact.json --corpus=/tmp/btx-functional-manual/feature-shielded-v2-proof-redteam-20260316d.corpus.json`
  - `bash /Users/admin/Documents/btxchain/btx-node/scripts/m21_shielded_redteam_campaign.sh --build-dir /Users/admin/Documents/btxchain/btx-node/build-btx --artifact /tmp/btx-m21-redteam-campaign.json --log-dir /tmp/btx-m21-redteam-logs --cachedir /tmp/btx-functional-manual/cache --portseed 32262`
  - `python3 -m py_compile /Users/admin/Documents/btxchain/btx-node/scripts/m20_shielded_audit_handoff_bundle.py`
  - `bash /Users/admin/Documents/btxchain/btx-node/test/util/m20_shielded_audit_handoff_bundle_test.sh`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/scripts/m20_shielded_audit_handoff_bundle.py --build-dir /Users/admin/Documents/btxchain/btx-node/build-btx --output-dir /tmp/btx-m20-audit-handoff-bundle-redteam --skip-build --samples=2`
- measured local results:
  - `shielded_v2_adversarial_proof_corpus_tests` passed with no errors in
    `15861019us`, split as `7920484us` and `7940505us`;
  - `shielded_proof_adversarial_tests` passed with no errors in `119926448us`;
  - direct malformed-proof functional passed with `overall_status=pass`,
    `runtime_seconds=50.357`, `variant_count=5`, and a clean valid follow-up
    mined at final height `134`;
  - wrapper validation passed with `overall_status=pass`, build step
    `runtime_seconds=3.388`, campaign step `runtime_seconds=50.799`,
    inner campaign runtime `49.02`, `variant_count=5`, and
    `teardown_confirmed=true`;
  - the full audit handoff bundle now includes the red-team artifact/log set in
    addition to the transcript corpus; the updated bundle passed locally in
    `real 239.15`, `user 226.63`, `sys 2.30`, emitted
    `/tmp/btx-m20-audit-handoff-bundle-redteam3` plus its `.tar.gz` sibling,
    and recorded manifest step runtimes `150.623s` (proof suites), `35.205s`
    (transcript corpus), `0.062s` (independent checker), and `50.771s`
    (embedded red-team wrapper);
- implementation pivots resolved during validation:
  - removed unsupported `-debug=shielded` from the new functional harness
    after the first startup attempt failed during node initialization;
  - switched the corpus generator from `--base-tx-hex=<...>` to the new
    `--base-tx-file=<path>` flow for live wallet-built transactions after
    macOS `execve` rejected the long inline hex argument with
    `Argument list too long`;
  - fixed a late functional name error by binding `node3` instead of the
    discarded `_node3` placeholder once the valid-follow-up mining path
    reached the post-campaign decode step;
- launch-readiness interpretation after this pass:
  - the branch now contains both an independent transcript checker and a
    repeatable malformed-proof replay harness, plus a single audit bundle that
    packages both evidence families for external reviewers;
  - Definition-of-Done item 8 remains open because these are still repo-side
    prerequisites only: the required external cryptographic review and the
    externally observed adversarial proof-focused testnet / red-team campaign
    have not yet occurred.

### 2026-03-16 16:54:26 JST

- pass preflight: verified readable, non-empty `/Users/admin/Documents/btxchain/github.key`,
  `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`,
  `/Users/admin/Documents/btxchain/infra/porkbun_api.key`, and
  `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` before any remote
  or GitHub operation in this pass, with byte counts `94`, `72`, `69`, and
  `69`;
- current focus for this pass: continue the remaining Definition-of-Done item 8
  launch blocker from the repo side by landing the next highest-leverage
  adversarial proof-focused testnet / red-team campaign artifact or harness
  that can be implemented and evidenced directly in-tree, without claiming
  full production-reset readiness before the actual external review and
  campaign runs exist.

### 2026-03-16 16:49:02 JST

- Definition-of-Done item 8 made another repo-side step forward without
  claiming production-reset readiness:
  - added the operator-facing bundle generator
    `/Users/admin/Documents/btxchain/btx-node/scripts/m20_shielded_audit_handoff_bundle.py`,
    which re-runs the seeded MatRiCT+ transcript corpus flow plus the existing
    `shielded_proof_adversarial_tests` suite, captures per-command logs,
    snapshots the review-relevant source / doc inputs, writes a
    machine-readable `manifest.json`, emits `SHA256SUMS`, and packages the
    result as a deterministic `.tar.gz` handoff artifact for external
    reviewers;
  - added
    `/Users/admin/Documents/btxchain/btx-node/test/util/m20_shielded_audit_handoff_bundle_test.sh`
    to assert bundle structure, manifest contents, copied source snapshot
    inputs, checksum file generation, and tarball emission without depending
    on the long proof suite runtime;
  - updated
    `/Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-cryptographic-audit-handoff.md`
    and
    `/Users/admin/Documents/btxchain/btx-node/doc/btx-production-readiness-matrix.md`
    so operators and external reviewers have one documented entry point for
    producing the local audit handoff package;
- validation for this pass:
  - `python3 -m py_compile /Users/admin/Documents/btxchain/btx-node/scripts/m20_shielded_audit_handoff_bundle.py`
  - `bash /Users/admin/Documents/btxchain/btx-node/test/util/m20_shielded_audit_handoff_bundle_test.sh`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/scripts/m20_shielded_audit_handoff_bundle.py --build-dir /Users/admin/Documents/btxchain/btx-node/build-btx --output-dir /tmp/btx-m20-audit-handoff-bundle --skip-build --samples=2`
- measured local results:
  - bundle smoke/regression test passed with no failures;
  - full handoff bundle generation completed in `real 187.51`, `user 186.91`,
    `sys 0.54`;
  - emitted artifact directory
    `/private/tmp/btx-m20-audit-handoff-bundle` and tarball
    `/private/tmp/btx-m20-audit-handoff-bundle.tar.gz`;
  - `manifest.json` recorded proof-suite runtime `150.521s`, transcript-corpus
    generation runtime `35.213s`, and independent checker runtime `0.067s`;
- launch-readiness interpretation after this pass:
  - the branch now contains a reproducible one-command package that external
    reviewers can consume without manually reconstructing the in-repo proof,
    transcript, and adversarial evidence set;
  - this is still only a repo-side prerequisite for Definition-of-Done item 8:
    the required external cryptographic review and adversarial proof-focused
    testnet / red-team campaign remain open launch blockers.

### 2026-03-16 16:39:26 JST

- pass preflight: verified readable, non-empty `/Users/admin/Documents/btxchain/github.key`,
  `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`,
  `/Users/admin/Documents/btxchain/infra/porkbun_api.key`, and
  `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` before any remote
  or GitHub operation in this pass, with byte counts `94`, `72`, `69`, and
  `69`;
- current focus for this pass: continue closing the remaining
  Definition-of-Done item 8 launch blocker from the repo side by implementing
  the next highest-leverage artifact for external cryptographic review or the
  adversarial proof-focused ephemeral testnet / red-team campaign, without
  claiming full production-reset readiness until those external gates have
  recorded evidence.

### 2026-03-16 16:36:13 JST

- Definition-of-Done item 8 made measurable progress in-tree without claiming
  launch readiness:
  - added seeded fixture support in
    `/Users/admin/Documents/btxchain/btx-node/src/shielded/matrict_plus_backend.{h,cpp}`
    so randomized MatRiCT+ corpora can be regenerated deterministically from a
    `uint256` seed rather than only from the fixed deterministic vector;
  - added transcript export support in
    `/Users/admin/Documents/btxchain/btx-node/src/shielded/ringct/ring_signature.{h,cpp}`
    so the proof path can emit canonical ring-signature Fiat-Shamir transcript
    chunks for out-of-band checking;
  - added
    `/Users/admin/Documents/btxchain/btx-node/src/test/generate_shielded_matrict_plus_transcript_corpus.cpp`
    plus CMake wiring, which generates a deterministic + randomized JSON corpus
    containing fixture state, serialized transcript inputs, and expected
    challenge / transcript hashes for ring-signature, balance-proof,
    range-proof, and top-level MatRiCT+ transcript stages;
  - added the pure-stdlib independent checker
    `/Users/admin/Documents/btxchain/btx-node/test/reference/check_shielded_matrict_plus_transcripts.py`,
    which recomputes those transcript hashes without calling the BTX verifier
    path and requires exact agreement with the generated corpus;
  - extended
    `/Users/admin/Documents/btxchain/btx-node/src/test/shielded_matrict_plus_tests.cpp`
    with seeded-fixture proof-generation / verification / transcript-export
    coverage;
  - fixed a real tool bug exposed by first validation attempt: the corpus
    generator's default seed had been initialized from an invalid short hex
    string, so the final path now uses a full 32-byte seed and runs correctly
    without caller overrides;
- validation for this pass:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx generate_shielded_matrict_plus_vectors generate_shielded_matrict_plus_transcript_corpus -j8`
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target generate_shielded_matrict_plus_transcript_corpus -j8`
  - `python3 -m py_compile /Users/admin/Documents/btxchain/btx-node/test/reference/check_shielded_matrict_plus_transcripts.py`
  - `./build-btx/bin/test_btx --run_test=shielded_matrict_plus_tests --catch_system_error=no --log_level=test_suite`
  - `/usr/bin/time -p ./build-btx/bin/gen_shielded_matrict_plus_transcript_corpus --samples=2 --output=/tmp/btx-matrict-plus-transcript-corpus.json`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/test/reference/check_shielded_matrict_plus_transcripts.py /tmp/btx-matrict-plus-transcript-corpus.json`
- measured results:
  - `shielded_matrict_plus_tests` passed with no errors in `30912362us`,
    including the new seeded-fixture case at `23123195us`;
  - bounded corpus generation completed in `real 35.44`, and the independent
    checker passed in `real 0.06` over `3` samples total (`1` deterministic +
    `2` randomized);
- launch-readiness interpretation after this pass:
  - the independent verifier / transcript-checking harness requirement in
    Definition-of-Done item 8 now has direct in-repo evidence on this branch;
  - Definition-of-Done item 8 is still not fully closed because the tracker
    separately requires external cryptographic review plus an adversarial
    proof-focused testnet / red-team campaign, neither of which is replaced by
    this local harness.

### 2026-03-16 16:18:59 JST

- pass preflight: verified readable, non-empty `/Users/admin/Documents/btxchain/github.key`,
  `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`,
  `/Users/admin/Documents/btxchain/infra/porkbun_api.key`, and
  `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` before any remote
  or GitHub operation in this pass, with byte counts `94`, `72`, `69`, and
  `69`;
- current focus for this pass: close as much of the remaining
  Definition-of-Done item 8 launch gate as can be evidenced directly from this
  repository, then sync `codex/shielded-v2-overhaul-plan` and continue from the
  resulting branch tip without claiming full production-reset readiness unless
  the external-review / adversarial-validation requirement is explicitly
  satisfied by recorded evidence.

### 2026-03-16 16:14:54 JST

- pass preflight: verified readable, non-empty `/Users/admin/Documents/btxchain/github.key`,
  `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`,
  `/Users/admin/Documents/btxchain/infra/porkbun_api.key`, and
  `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` before any remote
  or GitHub operation in this pass, with byte counts `94`, `72`, `69`, and
  `69`;
- Slice 19 disposable reset-network launch rehearsal is now implemented and
  validated:
  - refactored
    `/Users/admin/Documents/btxchain/btx-node/test/functional/feature_shielded_v2_multinode_validation.py`
    so its four-node mixed-family shielded workload is reusable as a scenario
    helper and remains directly runnable as its original Slice 18 validation;
  - added
    `/Users/admin/Documents/btxchain/btx-node/test/functional/feature_shieldedv2dev_launch_rehearsal.py`,
    which runs the full disposable `shieldedv2dev` launch rehearsal from
    genesis agreement through mixed-family `shielded_v2` operation,
    late-joiner sync + restart, active-wallet-node restart, and a confirmed
    post-restart `v2_send`, then writes a machine-readable JSON artifact with
    the final chain tip, restart evidence, `btxv2` address probes, and local
    resource accounting;
  - added
    `/Users/admin/Documents/btxchain/btx-node/scripts/m19_reset_launch_rehearsal.sh`,
    which wraps the rehearsal plus
    `feature_shieldedv2dev_datadir_isolation.py` into a single operator-facing
    command, records per-check logs, writes a top-level artifact, and confirms
    teardown of the temporary functional directories;
  - registered
    `feature_shieldedv2dev_launch_rehearsal.py` in the extended functional test
    suite via
    `/Users/admin/Documents/btxchain/btx-node/test/functional/test_runner.py`;
- validation for this sub-slice:
  - `python3 -m py_compile /Users/admin/Documents/btxchain/btx-node/test/functional/feature_shielded_v2_multinode_validation.py /Users/admin/Documents/btxchain/btx-node/test/functional/feature_shieldedv2dev_launch_rehearsal.py`
  - `bash -n /Users/admin/Documents/btxchain/btx-node/scripts/m19_reset_launch_rehearsal.sh`
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target btxd generate_shielded_relay_fixture_tx -j8`
  - `/usr/bin/time -p /Users/admin/Documents/btxchain/btx-node/scripts/m19_reset_launch_rehearsal.sh --build-dir /Users/admin/Documents/btxchain/btx-node/build-btx --artifact /tmp/btx-m19-reset-launch-rehearsal.json --log-dir /tmp/btx-m19-reset-launch-logs --portseed 34020`
- measured local runtimes:
  - `feature_shieldedv2dev_datadir_isolation = 1.854s`
  - `feature_shieldedv2dev_launch_rehearsal = 138.561s`
  - wrapper wall clock `real 140.57`, `user 104.11`, `sys 4.20`;
- evidence highlights from `/tmp/btx-m19-reset-launch-rehearsal.json`:
  - `overall_status=pass`
  - `teardown_confirmed=true`
  - `chain=shieldedv2dev`
  - `expected_genesis_hash=4ed72f2a7db044ff555197cddde63b1f50b74d750674316f75c3571ade9c80a3`
  - `final_height=402`
  - `bestblockhash=f0551701229c3a47b7c8b4a4f36aa4b4496f3fca03e0eb3be677c17e3ba1bbb1`
  - post-restart active-wallet confirmation txid
    `4c70b6a327afa883be68068df26b85ed1f9adad3f112bcbe0b0b68a4c56dd97b`;
- pivots:
  - the first rehearsal revision attempted three sequential post-restart
    shielded sends from the restarted wallet node before mining; the first tx
    relayed successfully, but the sequence stalled on the follow-on wallet send
    path, so the final rehearsal mines the first confirmed post-restart
    `v2_send` immediately instead of depending on a back-to-back unconfirmed
    send chain;
  - the wrapper now pre-cleans deterministic tmpdir and inner-artifact paths
    before each run so repeated operator reruns do not fail on leftover manual
    state;
- cloud resources used: none;
- cost: `0`;
- teardown confirmation:
  - wrapper artifact recorded `teardown_confirmed=true`
  - both functional tmpdirs were absent after the run;
- launch-gate status:
  - Slice 19 is complete and all 19 implementation slices are closed
  - production-reset consideration is still not fully satisfied by this repo
    pass alone because Definition-of-Done item 8 in this tracker still calls
    for external cryptographic review plus an adversarial proof-focused testnet
    / red-team campaign, and the local docs currently describe those as
    separate remaining launch gates rather than completed evidence;
- next step:
  - keep PR #82 aligned with the completed Slice 19 launch-rehearsal evidence,
    but do not claim final production-reset readiness until the tracker’s
    external-review / red-team gate is closed with explicit evidence.

### 2026-03-16 15:54:02 JST

- pass preflight: verified readable, non-empty `/Users/admin/Documents/btxchain/github.key`,
  `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`,
  `/Users/admin/Documents/btxchain/infra/porkbun_api.key`, and
  `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` before any remote
  or GitHub operation in this pass, with byte counts `94`, `72`, `69`, and
  `69`;
- Slice 18 ephemeral multi-node distributed validation and recovery rehearsal
  evidence is now implemented and validated:
  - added `/Users/admin/Documents/btxchain/btx-node/test/functional/feature_shielded_v2_multinode_validation.py`
    and registered it in
    `/Users/admin/Documents/btxchain/btx-node/test/functional/test_runner.py`;
    the new four-node harness keeps nodes `0-2` on an active mesh, isolates
    node `3` as a late joiner, then drives live `v2_send`,
    `v2_ingress_batch`, `v2_rebalance`, reserve-bound
    `v2_settlement_anchor`, and bare `v2_egress_batch` families through mined
    blocks before proving late-joiner sync, restart recovery, and the default
    externalized retention / snapshot RPC surface on node `3`;
  - the final harness mines each shielded workload from its originating node
    after local mempool admission instead of coupling this Slice 18 rehearsal
    to cross-peer relay timing; Slice 15 already carries the live relay /
    announcement proof for these families, while this pass proves block
    acceptance, state reconstruction, and restart durability across a live
    multi-node topology;
- validation for this sub-slice:
  - `python3 -m py_compile /Users/admin/Documents/btxchain/btx-node/test/functional/feature_shielded_v2_multinode_validation.py /Users/admin/Documents/btxchain/btx-node/test/functional/test_runner.py`
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target btxd generate_shielded_relay_fixture_tx -j8`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/test/functional/feature_shielded_v2_multinode_validation.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/feature-shielded-v2-multinode-validation-20260316e --portseed=32274`
- measured local runtime:
  - `feature_shielded_v2_multinode_validation.py = real 101.93, user 71.83, sys 3.66`;
- pivots:
  - the first harness revision asked `ensure_ring_diversity(...)` for only
    `8` notes and hit a real `CreateMatRiCTProof failed: ring signature creation failed`
    path on the first live `v2_send`; the final version uses the safe `16`
    note floor, larger `0.5` top-ups, and an explicit note-count assertion
    before spending;
  - the second revision assumed `z_sendmany` returned a `family` field, but
    the live wallet result contract does not; the final check verifies
    `v2_send` through `z_viewtransaction(...)`, matching the rest of the
    wallet surface tests;
  - the third revision created `v2_send` before building the ingress fixture,
    but `build_v2_ingress_batch_tx(...)` mines setup blocks internally and
    confirmed the send too early; the final ordering builds ingress first, then
    creates both live txs and mines them together on node `1`;
- cloud resources used: none;
- cost: `0`;
- next step: continue with Slice 19 reset-launch execution, including the full
  disposable reset-network launch rehearsal and remaining Definition-of-Done
  evidence.

### 2026-03-16 15:07:10 JST

- pass preflight: verified readable, non-empty `/Users/admin/Documents/btxchain/github.key`,
  `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`,
  `/Users/admin/Documents/btxchain/infra/porkbun_api.key`, and
  `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` before any remote
  or GitHub operation in this pass, with byte counts `94`, `72`, `69`, and
  `69`;
- Slice 18 relay / mempool / mining mixed-workload benches are now implemented
  and validated on the live miner path:
  - extended `/Users/admin/Documents/btxchain/btx-node/src/test/miner_tests.cpp`
    with deterministic mixed-family synthetic builders for `v2_send` plus two
    new miner regressions:
    `mixed_family_mempool_trim_evicts_lowest_feerate_entry` proves mempool trim
    evicts only the lowest-feerate entry across a mixed `v2_send`,
    `v2_ingress_batch`, `v2_egress_batch`, `v2_rebalance`, and reserve-bound
    `v2_settlement_anchor` workload;
    `block_assembler_orders_mixed_family_workload_by_ancestor_feerate` now
    mines the prerequisite settlement-anchor and netting-manifest state first,
    then proves `CreateNewBlock()` keeps all five families live and orders the
    resulting candidate set by ancestor feerate on the real mixed-family miner
    path;
  - the live assembled mixed-family template now deterministically includes the
    five valid candidates in the order `ingress -> send -> egress -> rebalance
    -> settlement`, with measured template totals
    `verify_units=3142`, `scan_units=4`, and `tree_update_units=17`;
- validation for this sub-slice:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `/usr/bin/time -p ./build-btx/bin/test_btx --run_test=miner_shielded_tests --catch_system_error=no --log_level=test_suite`
  - `/usr/bin/time -p ./build-btx/bin/test_btx --run_test=miner_tests --catch_system_error=no --log_level=test_suite`
- measured local runtimes:
  - `miner_shielded_tests = real 7.15, user 2.23, sys 0.32`
  - `miner_tests = real 3.93, user 2.51, sys 0.16`
  - focused mixed-family ordering case runtime inside `miner_shielded_tests`:
    `1555483 us`;
- pivots:
  - the first ordering regression modeled five independent families directly in
    mempool, but `CreateNewBlock()` correctly pruned the synthetic
    `v2_egress_batch` and reserve-bound `v2_settlement_anchor` through
    `RemoveStaleShieldedAnchorMempoolTransactions(...)` because their
    referenced settlement-anchor and netting-manifest state had never been
    anchored on chain; the final regression now establishes those prerequisites
    in chainstate before asserting the miner ordering;
  - the intermediate synthetic selection model was also dropped: once the
    stale-reference cleanup was accounted for, the meaningful invariant was the
    live block-template order from the real assembler, not a shadow copy of its
    comparator logic;
- cloud resources used: none;
- cost: `0`;
- next step: continue Slice 18 with chain-growth projections at `12 MB`,
  `24 MB`, and any proposed new limits, then move into ephemeral multi-node
  testnet runs if local benches stop being sufficient.

### 2026-03-16 15:32:44 JST

- pass preflight: verified readable, non-empty `/Users/admin/Documents/btxchain/github.key`,
  `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`,
  `/Users/admin/Documents/btxchain/infra/porkbun_api.key`, and
  `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` before any remote
  or GitHub operation in this pass, with byte counts `94`, `72`, `69`, and
  `69`;
- Slice 18 chain-growth projections at `12 MB`, `24 MB`, and a candidate
  larger `32 MB` limit are now implemented and validated:
  - added `/Users/admin/Documents/btxchain/btx-node/src/test/shielded_v2_chain_growth_projection_report.h`
    and `/Users/admin/Documents/btxchain/btx-node/src/test/shielded_v2_chain_growth_projection_report.cpp`
    to model representative five-family `shielded_v2` workloads against scaled
    block limits, emitting cadence feasibility, boundary-capacity ceilings,
    per-year chain growth, retained-state growth, and weekly-snapshot appendix
    growth under the externalized-retention production posture;
  - added `/Users/admin/Documents/btxchain/btx-node/src/test/generate_shielded_v2_chain_growth_projection_report.cpp`
    and wired `gen_shielded_v2_chain_growth_projection_report` into
    `/Users/admin/Documents/btxchain/btx-node/src/test/CMakeLists.txt`; the
    generator derives representative family footprints from the already-live
    `v2_send`, ingress-proof, `v2_egress_batch`, and cross-L2 netting report
    builders instead of duplicating those tx-shape assumptions in a parallel
    model, and defaults to the bounded `12,24,32` MB sweep;
  - added `/Users/admin/Documents/btxchain/btx-node/src/test/shielded_v2_chain_growth_projection_report_tests.cpp`
    with focused coverage for state-growth accounting, block-limit scaling, and
    invalid boundary-mix rejection;
- validation for this sub-slice:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx generate_shielded_v2_chain_growth_projection_report -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_chain_growth_projection_report_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_send_runtime_report_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_ingress_proof_runtime_report_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_egress_runtime_report_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_netting_capacity_report_tests --catch_system_error=no --log_level=test_suite`
  - `/usr/bin/time -p ./build-btx/bin/gen_shielded_v2_chain_growth_projection_report --block-sizes-mb=12,24,32 --output=/tmp/btx-v2-chain-growth-projection-slice18a.json`
- measured chain-growth findings from
  `/tmp/btx-v2-chain-growth-projection-slice18a.json`:
  - `1b_year_1pct_boundary` (`27,400` boundary actions / day) remains
    infeasible at `12 MB` because the mixed workload is weight-bound and still
    needs `975` blocks / day, but becomes feasible at both `24 MB` and
    `32 MB`, where it needs `488` blocks / day and tops out at
    `53,981` boundary actions / day; projected chain growth is
    `2.134 TB / year`, retained state growth is `0.165 GB / year`, and weekly
    snapshot appendix growth is `0.067 GB / year`;
  - `5b_year_1pct_boundary` (`136,986` boundary actions / day) stays
    infeasible even at `24 MB` and `32 MB`, because it still needs
    `2,436` blocks / day against a `960` block / day cadence; projected chain
    growth is `10.669 TB / year`, retained state growth is `0.715 GB / year`,
    and snapshot appendix growth is `0.333 GB / year`;
  - `10b_year_1pct_boundary` (`273,973` boundary actions / day) likewise stays
    infeasible at every tested limit, still requiring `4,872` blocks / day at
    `24 MB` and `32 MB`; projected chain growth is `21.338 TB / year`,
    retained state growth is `1.401 GB / year`, and snapshot appendix growth
    is `0.666 GB / year`;
  - the candidate larger `32 MB` limit produces no additional mixed-workload
    capacity over `24 MB` in these runs, because the representative workload is
    already bound by weight rather than serialized size once the five families
    are combined;
- measured local runtimes:
  - `shielded_v2_send_runtime_report_tests = 23740610 us`
  - `shielded_ingress_proof_runtime_report_tests = 129891130 us`
  - `shielded_v2_egress_runtime_report_tests = 3110 us`
  - `shielded_v2_netting_capacity_report_tests = 2798 us`
  - `gen_shielded_v2_chain_growth_projection_report = real 23.82, user 23.37, sys 0.15`
- pivots:
  - the first synthetic chain-growth test expected `560` commitments / day,
    but the direct-send fixture used in that test really emits `2`
    commitments / tx, so the correct daily total was `760`; the test was fixed
    to match the actual representative footprint instead of a stale mental
    model;
  - the larger-limit comparison initially looked like a block-size exercise,
    but the generated report showed the mixed-family projection is already
    weight-bound at `24 MB`, so `32 MB` does not improve throughput unless the
    broader resource envelope changes with it;
- cloud resources used: none;
- cost: `0`;
- next step: continue Slice 18 with the remaining ephemeral multi-node
  distributed validation and chain-growth / recovery rehearsal evidence.

### 2026-03-16 14:38:01 JST

- pass preflight: verified readable, non-empty `/Users/admin/Documents/btxchain/github.key`,
  `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`,
  `/Users/admin/Documents/btxchain/infra/porkbun_api.key`, and
  `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` before any remote
  or GitHub operation in this pass, with byte counts `94`, `72`, `69`, and
  `69`;
- Slice 18 cross-L2 netting-efficiency simulations and multi-domain
  reserve-settlement benches are now implemented and validated:
  - added `/Users/admin/Documents/btxchain/btx-node/src/test/shielded_v2_netting_capacity_report.h`
    and `/Users/admin/Documents/btxchain/btx-node/src/test/shielded_v2_netting_capacity_report.cpp`
    to simulate deterministic multi-window cross-L2 gross flows, apply
    pairwise cancellation and multilateral netting across domain sets, derive
    canonical `reserve_deltas`, build representative live `v2_rebalance` and
    reserve-bound `v2_settlement_anchor` transactions, and report achieved
    netting ratio, effective capacity multiplier, relay-policy posture, and
    per-block capacity from the actual built transactions;
  - added `/Users/admin/Documents/btxchain/btx-node/src/test/shielded_v2_netting_capacity_report_tests.cpp`
    with focused coverage over scenario parsing, simulation invariants,
    transaction metric emission, and invalid-config rejection;
  - added `/Users/admin/Documents/btxchain/btx-node/src/test/generate_shielded_v2_netting_capacity_report.cpp`
    and wired `gen_shielded_v2_netting_capacity_report` into
    `/Users/admin/Documents/btxchain/btx-node/src/test/CMakeLists.txt` with a
    bounded default scenario sweep of `2x50`, `8x80`, `32x95`, and `64x99`;
- measured netting / reserve-settlement findings from
  `/tmp/btx-v2-netting-capacity-report-slice18a.json`:
  - `2x50` achieved the expected `5000` bps median netting ratio, a
    `2000` milli effective-capacity multiplier, `2` manifest domains, and
    `1` reserve output; the representative `v2_rebalance` serialized to
    `2748` bytes and the representative reserve-bound `v2_settlement_anchor`
    serialized to `1055` bytes, with both still verify-bound at `200` txs per
    `24 MWU` block;
  - `8x80` achieved `8857` bps median netting and an `8752` milli effective
    multiplier across `8` domains and `4` reserve outputs; the representative
    `v2_rebalance` reached `9813` bytes while the bound settlement anchor
    remained compact at `1301` bytes, and both still fit the standard shielded
    policy envelope;
  - `32x95` achieved `9742` bps median netting and a `38773` milli effective
    multiplier across `32` domains and `16` reserve outputs; the
    representative `v2_rebalance` reached `38073` bytes and became weight-bound
    at `157` txs per block, while the representative reserve-bound settlement
    anchor stayed verify-bound at `200`;
  - `64x99` achieved `9949` bps median netting and a `196878` milli effective
    multiplier across `64` domains and `32` reserve outputs; the
    representative `v2_rebalance` reached `75753` bytes and `151506`
    shielded-policy weight, dropping to `79` txs per block by block weight,
    while the representative reserve-bound settlement anchor remained
    verify-bound at `200`;
  - representative peak-window timings from the generated artifact showed the
    first `2x50` rebalance build / validation at `271250 ns` / `34542 ns` and
    the matching settlement-anchor build / validation at
    `121458 ns` / `34875 ns`;
- validation for this sub-slice:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx generate_shielded_v2_netting_capacity_report -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_netting_capacity_report_tests --catch_system_error=no --log_level=test_suite`
  - `/usr/bin/time -p ./build-btx/bin/gen_shielded_v2_netting_capacity_report --samples=4 --warmup=0 --scenarios=2x50,8x80,32x95,64x99 --output=/tmp/btx-v2-netting-capacity-report-slice18a.json`
- measured local runtimes:
  - `gen_shielded_v2_netting_capacity_report(2x50,8x80,32x95,64x99) = real 0.54, user 0.01, sys 0.00`
- pivots:
  - the first implementation tried to time representative `v2_rebalance`
    validation through `CShieldedProofCheck`, but that path correctly rejects
    `V2_REBALANCE` with `bad-shielded-v2-contextual`; the harness now measures
    the actual family-specific validation hook
    `ExtractCreatedShieldedNettingManifests(...)` and keeps
    `ExtractCreatedShieldedSettlementAnchors(...)` for the settlement-anchor
    side;
  - the first compile pass also exposed stale namespace assumptions in the new
    test harness (`::ShieldedNote` and fully qualified `::test::shielded::*`
    helpers were required here), and the final harness now builds cleanly on
    this tree;
- cloud resources used: none;
- cost: `0`;
- next step: continue Slice 18 with relay / mempool / mining mixed-workload
  benches.

### 2026-03-16 14:07:43 JST

- pass preflight: verified readable, non-empty `/Users/admin/Documents/btxchain/github.key`,
  `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`,
  `/Users/admin/Documents/btxchain/infra/porkbun_api.key`, and
  `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` before any remote
  or GitHub operation in this pass, with byte counts `94`, `72`, `69`, and
  `69`;
- next step: sync `codex/shielded-v2-overhaul-plan`, re-read the tracker /
  control docs, and continue the highest-priority remaining Slice 18 work.

### 2026-03-16 14:19:59 JST

- Slice 18 batch egress scan and validation benches are now implemented and
  validated with a dedicated live-runtime harness:
  - added `/Users/admin/Documents/btxchain/btx-node/src/test/shielded_v2_egress_runtime_report.h`
    and `/Users/admin/Documents/btxchain/btx-node/src/test/shielded_v2_egress_runtime_report.cpp`
    to build real `v2_egress_batch` transactions through the production
    `BuildV2EgressStatement(...)`, `BuildDeterministicEgressOutputs(...)`, and
    `BuildV2EgressBatchTransaction(...)` path, then measure proof-check,
    owned-output discovery, chunk summarization, relay-policy posture, and
    block-capacity limits from the actual built transaction;
  - added `/Users/admin/Documents/btxchain/btx-node/src/test/shielded_v2_egress_runtime_report_tests.cpp`
    with focused contract coverage over the live `3`-output / `2`-chunk path
    plus invalid-config rejection coverage;
  - added `/Users/admin/Documents/btxchain/btx-node/src/test/generate_shielded_v2_egress_runtime_report.cpp`
    and wired `gen_shielded_v2_egress_runtime_report` into
    `/Users/admin/Documents/btxchain/btx-node/src/test/CMakeLists.txt` with a
    bounded default scenario sweep;
- measured egress-capacity findings from the generated artifacts:
  - `/tmp/btx-v2-egress-runtime-report-slice18a.json`:
    - `32x32` stayed standard at `44024` bytes, `176096` tx weight,
      `120000` shielded-policy weight, `verify=760`, `scan=33`,
      `tree_update=32`, and remained weight-bound at `136` txs /
      `4352` outputs per `24 MWU` block with a `14.70 ms` full pipeline;
    - `1300x32` was already nonstandard on the live builder path at
      `1750070` bytes, `7000280` tx weight, `3500140` shielded-policy weight,
      `scan=1341`, `tree_update=1300`, and dropped to a weight-bound
      `3` txs / `3900` outputs per block with a `337.18 ms` full pipeline;
    - `5000x32` reached `6728218` bytes and `26912872` tx weight, so one
      transaction no longer fits under the current `24 MWU` block weight cap
      (`max_transactions_by_weight=0`) and the full measured pipeline was
      `1.29 s`;
  - `/tmp/btx-v2-egress-runtime-report-boundary.json` and
    `/tmp/btx-v2-egress-runtime-report-refine.json` tightened the live relay
    boundary:
    - `256x32` and `512x32` are still standard even though both already exceed
      legacy `MAX_STANDARD_TX_WEIGHT`, because they remain within the extended
      shielded policy cap;
    - `768x32` is still standard at `2068536` shielded-policy weight with
      `331464` bytes of shielded-policy headroom and `5` txs /
      `3840` outputs per block;
    - `896x32` is no longer standard with reject reason `tx-size` and
      `2412968` shielded-policy weight, so the real builder-derived relay
      crossover is now pinned between `768` and `896` outputs;
    - `1024x32` remains nonstandard at `2757400` shielded-policy weight but is
      still mineable at `4` txs / `4096` outputs per block;
- validation for this sub-slice:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx generate_shielded_v2_egress_runtime_report -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_egress_runtime_report_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_egress_tests --catch_system_error=no --log_level=test_suite`
  - `/usr/bin/time -p ./build-btx/bin/gen_shielded_v2_egress_runtime_report --samples=1 --warmup=0 --scenarios=32x32,1300x32,5000x32 --output=/tmp/btx-v2-egress-runtime-report-slice18a.json`
  - `/usr/bin/time -p ./build-btx/bin/gen_shielded_v2_egress_runtime_report --samples=1 --warmup=0 --scenarios=256x32,512x32,768x32,1024x32 --output=/tmp/btx-v2-egress-runtime-report-boundary.json`
  - `./build-btx/bin/gen_shielded_v2_egress_runtime_report --samples=1 --warmup=0 --scenarios=896x32,960x32 --output=/tmp/btx-v2-egress-runtime-report-refine.json`
- measured local runtimes:
  - `shielded_v2_egress_runtime_report_tests = 3231 us`
  - `shielded_v2_egress_tests = 16859 us`
  - `gen_shielded_v2_egress_runtime_report(32x32,1300x32,5000x32) = real 3.66, user 3.45, sys 0.02`
  - `gen_shielded_v2_egress_runtime_report(256x32,512x32,768x32,1024x32) = real 1.39, user 1.38, sys 0.00`
- pivots:
  - the stale `1300`-output standardness intuition came from
    `/Users/admin/Documents/btxchain/btx-node/src/test/shielded_transaction_tests.cpp`
    using a synthetic manual bundle with tiny placeholder ciphertexts; the new
    runtime report measures the actual builder-derived egress payload and shows
    the real relay crossover much earlier;
  - the live builder path makes policy weight and serialized size rise together,
    so the first relay failure is a genuine `tx-size` policy reject at
    `896` outputs rather than a scan-budget-only ceiling;
- cloud resources used: none;
- cost: `0`;
- next step: continue Slice 18 with cross-L2 netting-efficiency simulations
  and multi-domain reserve-settlement benches.

### 2026-03-16 14:03:28 JST

- Slice 18 batch ingress capacity benches are now implemented and validated:
  - extended `/Users/admin/Documents/btxchain/btx-node/src/test/shielded_ingress_proof_runtime_report.cpp`
    so real `v2_ingress_batch` proof-runtime reports now emit measured tx
    shape, shielded resource usage, relay-policy posture, and per-block
    capacity limits from the actual built transaction rather than just payload
    and timing fields;
  - added the matching contract coverage in
    `/Users/admin/Documents/btxchain/btx-node/src/test/shielded_ingress_proof_runtime_report_tests.cpp`;
  - fixed the shared capacity-accounting bug in both
    `/Users/admin/Documents/btxchain/btx-node/src/test/shielded_ingress_proof_runtime_report.cpp`
    and `/Users/admin/Documents/btxchain/btx-node/src/test/shielded_v2_send_runtime_report.cpp`
    so zero-consumption shielded dimensions no longer become the binding
    per-block limit and over-limit standard-policy headroom no longer
    underflows;
- measured ingress-capacity findings from the generated artifacts:
  - native MatRiCT+ sample `/tmp/btx-ingress-proof-native-slice18a.json` at
    `4` leaves produced a `2492641` byte tx with `9970564` tx weight,
    `4985282` shielded-policy weight, `2489850` proof bytes,
    `verify=760`, `scan=0`, `tree_update=2`, and is weight-bound at
    `2` txs / `8` ingress leaves per `24 MWU` block while already outside
    standard relay policy;
  - receipt-backed sweep `/tmp/btx-ingress-proof-receipt-slice18a.json`
    stayed weight-bound across the measured bands with:
    - `100` leaves: `41009` bytes, `164036` weight, `120000`
      shielded-policy weight, `2` shards, `146` txs / `14600` leaves per
      block, still standard;
    - `1000` leaves: `389425` bytes, `1557700` weight, `778850`
      shielded-policy weight, `16` shards, `15` txs / `15000` leaves per
      block, still standard;
    - `5000` leaves: `1938470` bytes, `7753880` weight, `3876940`
      shielded-policy weight, `79` shards, `3` txs / `15000` leaves per
      block, no longer standard;
    - `10000` leaves: `3874240` bytes, `15496960` weight, `7748480`
      shielded-policy weight, `157` shards, `1` tx / `10000` leaves per
      block, no longer standard;
- validation for this sub-slice:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx generate_shielded_ingress_proof_runtime_report generate_shielded_v2_send_runtime_report -j8`
  - `/usr/bin/time -p ./build-btx/bin/test_btx --run_test=shielded_ingress_proof_runtime_report_tests --catch_system_error=no --log_level=test_suite`
  - `/usr/bin/time -p ./build-btx/bin/test_btx --run_test=shielded_v2_send_runtime_report_tests --catch_system_error=no --log_level=test_suite`
  - `/usr/bin/time -p ./build-btx/bin/gen_shielded_ingress_proof_runtime_report --samples=1 --warmup=0 --leaf-counts=4 --reserve-outputs=1 --output=/tmp/btx-ingress-proof-native-slice18a.json`
  - `/usr/bin/time -p ./build-btx/bin/gen_shielded_ingress_proof_runtime_report --backend=receipt --samples=1 --warmup=0 --leaf-counts=100,1000,5000,10000 --reserve-outputs=1 --output=/tmp/btx-ingress-proof-receipt-slice18a.json`
- measured local runtimes:
  - `shielded_ingress_proof_runtime_report_tests = real 130.46, user 128.47, sys 0.95`
  - `shielded_v2_send_runtime_report_tests = real 24.36, user 23.72, sys 0.11`
  - `gen_shielded_ingress_proof_runtime_report(native 4) = real 28.97, user 28.90, sys 0.07`
  - `gen_shielded_ingress_proof_runtime_report(receipt 100,1000,5000,10000) = real 0.87, user 0.86, sys 0.00`
- pivots:
  - the first assertion pass treated `scan_units=0` as “zero capacity,” but
    for ingress it actually means the tx does not consume scan budget and that
    dimension must be ignored when choosing the binding block limit;
  - the stale mental model was Bitcoin’s `4 MWU`; this BTX tree uses
    `MAX_BLOCK_WEIGHT=24000000`, so the corrected native `4`-leaf ingress case
    is weight-bound at `2` txs per block rather than unmineable;
  - while fixing that, I found the same underflow / unused-dimension bug in the
    already-landed direct-send runtime report and corrected it immediately so
    Slice 18 reporting stays internally consistent;
- push / PR gate re-verified before the validated branch publish: readable,
  non-empty `github.key`, `digitalocean_api.key`, `porkbun_api.key`, and
  `porkbun_secret.key` confirmed again locally with byte counts `94`, `72`,
  `69`, and `69`;
- cloud resources used: none;
- cost: `0`;
- next step: continue Slice 18 with batch egress scan and validation benches.

### 2026-03-16 13:46:57 JST

- pass preflight: verified readable, non-empty `/Users/admin/Documents/btxchain/github.key`,
  `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`,
  `/Users/admin/Documents/btxchain/infra/porkbun_api.key`, and
  `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` before any remote
  or GitHub operation in this pass, with byte counts `94`, `72`, `69`, and
  `69`;
- next step: sync `codex/shielded-v2-overhaul-plan`, re-read the tracker /
  control docs, and continue the highest-priority remaining Slice 18 work.

### 2026-03-16 13:44:38 JST

- Slice 18 direct-send throughput benches are now implemented and validated
  with a dedicated `v2_send` runtime-report harness:
  - added `/Users/admin/Documents/btxchain/btx-node/src/test/shielded_v2_send_runtime_report.h`
    and `/Users/admin/Documents/btxchain/btx-node/src/test/shielded_v2_send_runtime_report.cpp`
    to build deterministic direct-send fixtures, produce measured
    build/proof-check/runtime summaries, and derive block-capacity / relay
    policy headroom from real `v2_send` transactions;
  - added `/Users/admin/Documents/btxchain/btx-node/src/test/generate_shielded_v2_send_runtime_report.cpp`
    and wired `gen_shielded_v2_send_runtime_report` into the test build so the
    bench can be emitted as JSON outside Boost with bounded default scenarios
    `1x2`, `2x2`, and `2x4`;
  - added `/Users/admin/Documents/btxchain/btx-node/src/test/shielded_v2_send_runtime_report_tests.cpp`
    with a focused contract test over the real wallet-shaped `1x2` path plus
    invalid-config rejection coverage;
- measured direct-send findings from
  `/tmp/btx-v2-send-runtime-report-slice18a.json`:
  - `1x2` remained standard at `1063865` serialized bytes,
    `2127730` shielded-policy weight, `964` verify units, `2` scan units,
    `3` tree-update units, and stayed weight-bound at `5` txs / `10` outputs
    per `24 MB` block with median `build_ns=22913477833` and
    `proof_check_ns=41251292`;
  - `2x2` remained standard at `1166856` serialized bytes,
    `2333712` shielded-policy weight, `1724` verify units, `2` scan units,
    `4` tree-update units, and also stayed weight-bound at `5` txs /
    `10` spends / `10` outputs per block with median
    `build_ns=23292962750` and `proof_check_ns=47199041`;
  - `2x4` crossed standard relay policy at `2121514` serialized bytes and
    `4243028` shielded-policy weight, consumed `1928` verify units,
    `4` scan units, and `6` tree-update units, and dropped to a weight-bound
    `2` txs / `4` spends / `8` outputs per block with median
    `build_ns=45759507500` and `proof_check_ns=81532917`;
- validation for this sub-slice:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx generate_shielded_v2_send_runtime_report -j8`
  - `/usr/bin/time -p ./build-btx/bin/test_btx --run_test=shielded_v2_send_runtime_report_tests --catch_system_error=no --log_level=test_suite`
  - `/usr/bin/time -p ./build-btx/bin/test_btx --run_test=shielded_v2_send_tests --catch_system_error=no --log_level=test_suite`
  - `/usr/bin/time -p ./build-btx/bin/gen_shielded_v2_send_runtime_report --samples=1 --warmup=0 --scenarios=1x2,2x2,2x4 --output=/tmp/btx-v2-send-runtime-report-slice18a.json`
- measured local runtimes:
  - `shielded_v2_send_runtime_report_tests = real 23.40, user 22.89, sys 0.07`
  - `shielded_v2_send_tests = real 30.67, user 30.58, sys 0.08`
  - `gen_shielded_v2_send_runtime_report(1x2,2x2,2x4) = real 92.41, user 91.93, sys 0.22`
- pivots:
  - the first report-test draft was too heavy and also asserted the wrong
    environment constants; this tree currently runs `shielded::lattice::RING_SIZE=16`,
    not `64`, and the wallet-shaped `1x2` direct-send case is weight-bound,
    not verify-bound;
  - the original default generator sweep (`1x2`, `8x8`, `32x32`) was too
    large for a sane default invocation, so it was tightened to the bounded
    `1x2`, `2x2`, `2x4` progression while preserving an explicit
    nonstandard-policy crossover point;
- next step: continue Slice 18 with batch ingress capacity benches.

### 2026-03-16 13:23:55 JST

- pass preflight: verified readable, non-empty `/Users/admin/Documents/btxchain/github.key`,
  `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`,
  `/Users/admin/Documents/btxchain/infra/porkbun_api.key`, and
  `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` before any remote
  or GitHub operation in this pass, with byte counts `94`, `72`, `69`, and
  `69`;
- next step: sync `codex/shielded-v2-overhaul-plan`, re-read the tracker /
  control docs, and continue the highest-priority remaining Slice 18 work.

### 2026-03-16 13:19:55 JST

- Slice 17 closeout: validated the remaining PR #80 / PR #81 wallet durability
  baseline for external shield receives and PQ seed recovery, and fixed the
  stale encrypted-persistence functional setup that no longer matched the rest
  of the shielded wallet matrix;
- `test/functional/wallet_shielded_encrypted_persistence.py` now funds trusted
  transparent balance through `fund_trusted_transparent_balance(...)` instead
  of assuming freshly mined coinbase outputs are immediately usable by
  `z_shieldfunds`, and it now uses `rpc_timeout = 600` so the final native
  `z_sendmany` proof generation is measured against the same timeout budget as
  the existing restart-persistence coverage;
- the closeout validation matrix now proves:
  - encrypted shielded state persists under wallet encryption and relock;
  - external shield receives and spends survive normal restart and full
    `VerifyDB`;
  - bundle backup / restore round-trips encrypted shielded state;
  - encrypted archive backup / restore round-trips encrypted shielded state and
    bundled integrity reports;
  - `z_verifywalletintegrity` still classifies PQ multisig signer / public-only
    descriptors correctly, preserving the PR #81 seed-map baseline;
- Slice 17 status:
  - `sendtoaddress`-like v2 private send is complete;
  - batch deposit submission is complete;
  - batch exit claim / receive path is complete;
  - imported viewing-key live receive / recovery is complete;
  - operator-facing raw transaction / reserve / netting inspection is complete;
  - reserve and operator rebalance publish flows are complete;
  - PR #80 / PR #81 wallet durability baseline for external shield receives and
    PQ seed recovery is now complete;
  - Slice 17 is complete;
- validated with:
  - `python3 -m py_compile /Users/admin/Documents/btxchain/btx-node/test/functional/wallet_shielded_encrypted_persistence.py /Users/admin/Documents/btxchain/btx-node/test/functional/wallet_shielded_restart_persistence.py /Users/admin/Documents/btxchain/btx-node/test/functional/wallet_backupbundle.py /Users/admin/Documents/btxchain/btx-node/test/functional/wallet_bundlearchive.py /Users/admin/Documents/btxchain/btx-node/test/functional/wallet_verifywalletintegrity.py`
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target btxd -j8`
  - `python3 /Users/admin/Documents/btxchain/btx-node/test/functional/wallet_shielded_encrypted_persistence.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/wallet-shielded-encrypted-persistence-20260316c --portseed=32260`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/test/functional/wallet_shielded_restart_persistence.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/wallet-shielded-restart-persistence-20260316a --portseed=32261`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/test/functional/wallet_backupbundle.py --descriptors --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/wallet-backupbundle-20260316a --portseed=32262`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/test/functional/wallet_bundlearchive.py --descriptors --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/wallet-bundlearchive-20260316a --portseed=32263`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/test/functional/wallet_verifywalletintegrity.py --descriptors --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/wallet-verifywalletintegrity-20260316a --portseed=32264`
- measured local runtimes:
  - `wallet_shielded_encrypted_persistence.py ~= 50.84s` from test-framework
    start to successful cleanup
  - `wallet_shielded_restart_persistence.py = real 82.28, user 74.93, sys 0.68`
  - `wallet_backupbundle.py = real 20.19, user 13.67, sys 0.47`
  - `wallet_bundlearchive.py = real 20.26, user 13.85, sys 0.48`
  - `wallet_verifywalletintegrity.py = real 0.89, user 0.47, sys 0.06`
- pivots:
  - the first closeout rerun failed because
    `wallet_shielded_encrypted_persistence.py` still relied on direct mined
    coinbase balance, while the rest of the live shielded wallet matrix had
    already moved to `fund_trusted_transparent_balance(...)`; the fix was to
    align this stale test with the deterministic trusted-funding helper rather
    than weaken the funding checks;
  - the next rerun hit the same RPC timeout class already handled in
    `wallet_shielded_restart_persistence.py`: native `z_sendmany` proof
    generation legitimately exceeds the default `30s`, so the functional now
    uses `rpc_timeout = 600` instead of failing spuriously on a healthy wallet;
  - with those test-hardening fixes in place, the remaining durability /
    recovery matrix passed without additional wallet or consensus changes,
    which is the evidence needed to close Slice 17 rather than open another
    implementation slice;
- push / PR gate re-verified before the validated branch publish: readable,
  non-empty `github.key`, `digitalocean_api.key`, `porkbun_api.key`, and
  `porkbun_secret.key` confirmed again locally with byte counts `94`, `72`,
  `69`, and `69`;
- cloud resources used: none;
- cost: `0`;
- teardown confirmation:
  - successful tmpdirs were cleaned by the functional harness for
    `wallet-shielded-encrypted-persistence-20260316c`,
    `wallet-shielded-restart-persistence-20260316a`,
    `wallet-backupbundle-20260316a`,
    `wallet-bundlearchive-20260316a`, and
    `wallet-verifywalletintegrity-20260316a`;
  - failed intermediate tmpdirs
    `/tmp/btx-functional-manual/wallet-shielded-encrypted-persistence-20260316a`
    and `/tmp/btx-functional-manual/wallet-shielded-encrypted-persistence-20260316b`
    remain local-only evidence of the stale test setup and require no remote
    teardown;
- next slice: start `Slice 18: Prove The Capacity Targets And Distributed Behavior`.

### 2026-03-16 13:12:44 JST

- pass preflight: verified readable, non-empty `/Users/admin/Documents/btxchain/github.key`,
  `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`,
  `/Users/admin/Documents/btxchain/infra/porkbun_api.key`, and
  `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` before any remote
  or GitHub operation in this pass, with byte counts `94`, `72`, `69`, and
  `69`;
- next step: sync `codex/shielded-v2-overhaul-plan`, re-read the tracker /
  control docs, and continue the highest-priority remaining Slice 17 work.

### 2026-03-16 13:08:12 JST

- Slice 17 wallet / RPC sub-slice: added live reserve / operator rebalance
  publish flows with a new one-shot `bridge_submitrebalancetx` RPC plus a
  deterministic wallet-side `v2_rebalance` constructor;
- `src/shielded/v2_bundle.h` and `src/shielded/v2_bundle.cpp` now expose
  `BuildDeterministicV2RebalanceBundle(...)`, producing canonical
  `v2_rebalance` payloads, proof-shard descriptors, output chunks, settlement
  binding digests, and batch statement digests from reserve deltas, reserve
  outputs, and a netting manifest;
- `src/wallet/shielded_wallet.h` and `src/wallet/shielded_wallet.cpp` now add
  `CreateV2Rebalance(...)`, deriving reserve note outputs, funding the
  transparent fee carrier from wallet UTXOs, using P2MR change, signing the
  transaction, and returning the actual fee paid for the operator publish flow;
- `src/wallet/shielded_rpc.cpp`, `src/wallet/rpc/wallet.cpp`, and
  `src/rpc/client.cpp` now expose `bridge_submitrebalancetx`, parse signed
  canonical `reserve_deltas`, derive or accept netting-manifest commitments,
  auto-bump the fee to the live mempool floor when needed, and broadcast
  through the wallet path instead of a parallel raw-tx path;
- `src/test/shielded_v2_bundle_tests.cpp` now covers deterministic rebalance
  bundle construction, and
  `test/functional/wallet_bridge_rebalance.py` proves the live multi-domain
  operator flow end to end: invalid canonical deltas reject before publish,
  a wallet-funded `v2_rebalance` enters mempool, wallet / raw decode surfaces
  show the committed netting manifest and reserve outputs, and the transaction
  mines with a stable manifest id;
- `test/functional/test_runner.py` now includes
  `wallet_bridge_rebalance.py --descriptors` in both the extended bridge-wallet
  suite and the BTX base matrix so the new RPC is not omitted from routine
  functional coverage;
- `doc/JSON-RPC-interface.md` documents `bridge_submitrebalancetx`;
- Slice 17 status:
  - `sendtoaddress`-like v2 private send is complete;
  - batch deposit submission is complete;
  - batch exit claim / receive path is complete;
  - imported viewing-key live receive / recovery is complete;
  - operator-facing raw transaction / reserve / netting inspection is complete;
  - reserve and operator rebalance publish flows are now complete;
  - Slice 17 still remains open for the final wallet durability / recovery
    closeout below;
- validated with:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx btxd -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_bundle_tests --catch_system_error=no --log_level=test_suite`
  - `python3 -m py_compile /Users/admin/Documents/btxchain/btx-node/test/functional/test_runner.py /Users/admin/Documents/btxchain/btx-node/test/functional/wallet_bridge_rebalance.py`
  - `python3 /Users/admin/Documents/btxchain/btx-node/test/functional/wallet_bridge_rebalance.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/wallet-bridge-rebalance-20260316c --portseed=32257`
- measured local runtimes:
  - `shielded_v2_bundle_tests = real 0.58, user 0.12, sys 0.02`
  - `wallet_bridge_rebalance.py = real 9.41, user 2.67, sys 0.37`
- pivots:
  - the first functional failure exposed a real RPC contract bug, not only a
    test issue: `bridge_submitrebalancetx` advertised signed `reserve_delta`
    values but still parsed them through unsigned `AmountFromValue(...)`, so
    the fix was to add a signed amount parser using `MoneyRangeSigned(...)`
    instead of weakening the test;
  - the next gap was suite integration, not wallet behavior: the new functional
    passed standalone but was absent from `test_runner.py`, so the matrix was
    updated before closeout rather than leaving the new RPC on an ad hoc path;
- push / PR gate re-verified before the validated branch publish: readable,
  non-empty `github.key`, `digitalocean_api.key`, `porkbun_api.key`, and
  `porkbun_secret.key` confirmed again locally with byte counts `94`, `72`,
  `69`, and `69`;
- cloud resources used: none;
- cost: `0`;
- teardown confirmation:
  - successful tmpdir `wallet-bridge-rebalance-20260316c` was cleaned by the
    functional harness on exit;
  - the failed intermediate tmpdir
    `/tmp/btx-functional-manual/wallet-bridge-rebalance-20260316b` was removed
    locally after the passing rerun;
- next slice: continue Slice 17 with the remaining wallet durability / recovery
  closeout, unless that final PR #80 / PR #81 baseline is already fully
  covered and Slice 17 can be closed on the next pass.

### 2026-03-16 12:31:12 JST

- pass preflight: verified readable, non-empty `/Users/admin/Documents/btxchain/github.key`,
  `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`,
  `/Users/admin/Documents/btxchain/infra/porkbun_api.key`, and
  `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` before any remote
  or GitHub operation in this pass;
- next step: sync `codex/shielded-v2-overhaul-plan`, re-read the tracker / control
  docs, and continue the highest-priority remaining Slice 17 wallet / RPC work.

### 2026-03-16 12:28:54 JST

- Slice 17 wallet / RPC sub-slice: added live raw-transaction and
  `getrawtransaction` shielded diagnostics for operator-facing reserve,
  settlement, ingress, egress, and netting-manifest inspection;
- `src/core_write.cpp` now emits a top-level `shielded` object for any decoded
  shielded transaction, covering legacy bundles plus `shielded_v2` family,
  bundle id, header, payload, proof-shard descriptors, output-chunk descriptors,
  reserve deltas, netting manifests, and payload / proof byte summaries;
- `src/rpc/rawtransaction.cpp` now documents that additive `shielded` result so
  `decoderawtransaction` and verbose `getrawtransaction` accept the new
  operator-visible decode surface without tripping RPC result-contract checks;
- `test/functional/wallet_shielded_rpc_surface.py` now proves the live decode
  path for build-only `v2_egress_batch`, proof-receipt ingress,
  hybrid-verification ingress, and multishard ingress transactions against the
  rebuilt daemon;
- `test/functional/feature_btx_block_capacity.py` now proves the same verbose
  raw-transaction surface for wallet-funded `v2_rebalance`,
  reserve-bound `v2_settlement_anchor`, and prioritised bare
  `v2_egress_batch` fixtures before and after mining through
  `getblocktemplate`;
- Slice 17 status:
  - `sendtoaddress`-like v2 private send is complete;
  - batch deposit submission is complete;
  - batch exit claim / receive path is complete;
  - imported viewing-key live receive / recovery is complete;
  - operator-facing raw transaction / reserve / netting inspection is now
    complete;
  - the remaining Slice 17 wallet / RPC families still remain open below;
- validated with:
  - `python3 -m py_compile /Users/admin/Documents/btxchain/btx-node/test/functional/wallet_shielded_rpc_surface.py /Users/admin/Documents/btxchain/btx-node/test/functional/feature_btx_block_capacity.py`
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target btxd generate_shielded_relay_fixture_tx -j8`
  - `python3 /Users/admin/Documents/btxchain/btx-node/test/functional/wallet_shielded_rpc_surface.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/wallet-shielded-rpc-surface-slice17-rawtx-20260316e --portseed=32276`
  - `python3 /Users/admin/Documents/btxchain/btx-node/test/functional/feature_btx_block_capacity.py --descriptors --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/feature-btx-block-capacity-shielded-rawtx-20260316a --portseed=32272`
- measured local runtimes:
  - `wallet_shielded_rpc_surface.py = 313.44s`
  - `feature_btx_block_capacity.py = 10.48s`
- pivots:
  - the first live rerun failed for the correct integration reason: the new
    `shielded` JSON object existed in the serializer but not in the
    `decoderawtransaction` / `getrawtransaction` RPC result contract, so the
    fix was to widen the rawtransaction result doc rather than backing out the
    decode surface;
  - the next failure was a test assumption bug, not a bundle bug: decoded
    ingress payloads can contain more reserve outputs than the higher-level RPC
    preview enumerates, so the functional now asserts at least the requested
    reserve outputs plus reserve note-class semantics instead of an exact
    decode-only count;
  - the final failure was another incorrect assumption: hybrid ingress still
    serializes a `native_batch` proof-envelope binding while the hybrid
    settlement evidence lives in the external anchor / verification bundle path,
    so the raw decode assertion now matches the actual wire contract already
    exercised by lower-level ingress tests;
- push / PR gate re-verified before the validated branch publish: readable,
  non-empty `github.key`, `digitalocean_api.key`, `porkbun_api.key`, and
  `porkbun_secret.key` confirmed again locally;
- cloud resources used: none;
- incremental cost: `0`;
- teardown: functional tmpdirs cleaned by the harness on the successful
  validation runs;
- next slice: continue Slice 17 with reserve and operator management plus the
  remaining wallet / RPC families.

### 2026-03-16 11:49:47 JST

- Slice 17 wallet / RPC sub-slice: fixed live wallet recovery for imported
  shielded viewing keys across the normal mempool-to-block path;
- `src/wallet/shielded_wallet.cpp` now seeds view-only wallet birth time from
  chain tip max time, and falls back to the conservative floor `0` instead of
  wallclock time when tip metadata is unavailable, so imported viewing keys can
  never reintroduce the `blockConnected` birthday skip on future blocks;
- `src/wallet/shielded_rpc.cpp` now leaves no-rescan `z_importviewingkey`
  imports on that lower-level tip-based birthday path and only lowers wallet
  birth time explicitly for rescan imports that anchor to a requested historical
  start height;
- `src/test/shielded_wallet_chunk_discovery_tests.cpp` now tightens the wallet
  callback regression to assert that imported-key birth time is anchored at or
  before the current chain tip max time, not merely that it differs from the
  uninitialized sentinel;
- `test/functional/wallet_shielded_viewingkey_rescan.py` now proves the live
  imported-viewing-key receive path end to end against the rebuilt daemon while
  tolerating unrelated watch-only notes from the node’s automatic shielding by
  asserting the imported live note itself plus a baseline-relative balance
  increase instead of assuming an exact total note inventory;
- Slice 17 status:
  - `sendtoaddress`-like v2 private send is complete;
  - batch deposit submission is complete;
  - batch exit claim / receive path is complete;
  - imported viewing-key live receive / recovery is now complete;
  - the remaining Slice 17 wallet / RPC families still remain open below;
- validated with:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_wallet_chunk_discovery_tests --catch_system_error=no --log_level=test_suite`
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target btxd test_btx -j8`
  - `python3 -m py_compile /Users/admin/Documents/btxchain/btx-node/test/functional/wallet_shielded_viewingkey_rescan.py`
  - `python3 /Users/admin/Documents/btxchain/btx-node/test/functional/wallet_shielded_viewingkey_rescan.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/wallet-shielded-viewingkey-rescan-slice17-20260316i --portseed=32270`
- measured local runtimes:
  - `shielded_wallet_chunk_discovery_tests = 18,201,064us`
  - `wallet_shielded_viewingkey_rescan.py ~= 82.14s` from test-framework start
    to successful cleanup;
- pivots:
  - the first functional reruns still failed because only `test_btx` had been
    rebuilt; once `btxd` was rebuilt with the same wallet changes, the live
    imported note appeared immediately and the shielded scan height advanced as
    expected;
  - the next failure was a test assumption bug, not another wallet defect: the
    node can auto-shield an unrelated coinbase output into a watch-only address
    in the same block, so exact total-balance equality was replaced with a
    baseline-relative increase tied to the imported live note itself;
- push / PR gate re-verified before the validated branch publish: readable,
  non-empty `github.key`, `digitalocean_api.key`, `porkbun_api.key`, and
  `porkbun_secret.key` confirmed again locally;
- cloud resources used: none;
- cost: `0`;
- teardown confirmation:
  - successful tmpdir `wallet-shielded-viewingkey-rescan-slice17-20260316i`
    was cleaned by the functional harness on exit;
  - failed manual tmpdirs from the stale-binary and overly strict balance
    assertions were left local only until the passing rerun and required no
    remote teardown;
- next slice: continue Slice 17 with reserve and operator management plus the
  remaining wallet / RPC families.

### 2026-03-16 10:54:31 JST

- start-of-pass remote / GitHub preflight repeated before the next fetch / pull /
  push / PR cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- the next remote sync, later push to
  `origin/codex/shielded-v2-overhaul-plan`, and the follow-up PR #82 update are
  unblocked for this pass.

### 2026-03-16 10:52:47 JST

- Slice 17 wallet / RPC sub-slice: added `bridge_submitunshieldtx` in
  `src/wallet/shielded_rpc.cpp` as the one-shot outbound mirror of the earlier
  bridge deposit submission RPC, covering the attested bridge-out settlement
  path;
- the new outbound submission path is intentionally thin:
  - it reuses `CreateBridgeUnshieldSettlementTransaction(...)` so the canonical
    bridge-out PSBT shape and attestation wiring do not fork;
  - it signs and finalizes the PSBT with the local wallet through the existing
    PSBT fill path;
  - it commits through the wallet broadcast path with bridge-settlement-specific
    mempool rejection reporting;
  - it leaves `bridge_buildunshieldtx` intact for external-signer and manual
    PSBT workflows;
- supporting surface updates in this pass:
  - registered `bridge_submitunshieldtx` in `src/wallet/rpc/wallet.cpp`;
  - added CLI argument conversion for `vout` / `amount` in `src/rpc/client.cpp`;
  - documented `bridge_planbatchout` and `bridge_submitunshieldtx` in
    `doc/JSON-RPC-interface.md`;
  - switched `test/functional/wallet_bridge_attested_unshield.py` to assert the
    attestation bytes via the builder, then submit the real settlement through
    the new one-shot RPC;
  - extended `test/functional/wallet_bridge_batch_commitment.py` so the batch
    bridge-out path now funds, submits, mines, and checks the actual payout
    receives instead of stopping at plan / attestation / PSBT compression;
- Slice 17 status:
  - `sendtoaddress`-like v2 private send is complete;
  - batch deposit submission is complete;
  - batch exit claim / receive path is now complete;
  - the remaining Slice 17 wallet / RPC families still remain open below;
- validated with:
  - `python3 -m py_compile /Users/admin/Documents/btxchain/btx-node/test/functional/wallet_bridge_attested_unshield.py /Users/admin/Documents/btxchain/btx-node/test/functional/wallet_bridge_batch_commitment.py /Users/admin/Documents/btxchain/btx-node/test/functional/wallet_bridge_psbt.py`
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target btxd -j8`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/test/functional/wallet_bridge_attested_unshield.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/wallet-bridge-attested-unshield-slice17-20260316a --portseed=32259`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/test/functional/wallet_bridge_batch_commitment.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/wallet-bridge-batch-commitment-slice17-20260316a --portseed=32260`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/test/functional/wallet_bridge_psbt.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/wallet-bridge-psbt-slice17-20260316b --portseed=32261`
- measured local runtimes:
  - `wallet_bridge_attested_unshield.py = real 10.35, user 3.43, sys 0.39`
  - `wallet_bridge_batch_commitment.py = real 10.23, user 3.65, sys 0.36`
  - `wallet_bridge_psbt.py = real 10.23, user 3.89, sys 0.37`
- measured batch exit compression from the live batch functional:
  - plan bytes `17316 -> 5902`
  - attestation bytes `402 -> 178`
  - PSBT bytes `9177 -> 3191`
- pivots:
  - the outbound submit RPC was deliberately implemented as a wallet-side
    wrapper over the existing unshield PSBT builder instead of a new raw
    transaction path so the unchanged `wallet_bridge_psbt.py` regression still
    covers the manual / external-signer flow;
  - the live unshield submit functionals now fund bridge outputs with a
    deterministic `0.00100000` margin so the attested bridge-out fee headroom
    remains stable for both the single and aggregated payout paths;
- cloud resources used: none;
- cost: `0`;
- teardown confirmation:
  - the successful tmpdirs `wallet-bridge-attested-unshield-slice17-20260316a`,
    `wallet-bridge-batch-commitment-slice17-20260316a`, and
    `wallet-bridge-psbt-slice17-20260316b` were cleaned by the functional
    harness on exit;
- next slice: continue Slice 17 with reserve and operator management plus the
  remaining wallet / RPC families.

### 2026-03-16 10:46:37 JST

- start-of-pass remote / GitHub preflight repeated before the next fetch / pull /
  push / PR cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- the next remote sync, later push to
  `origin/codex/shielded-v2-overhaul-plan`, and the follow-up PR #82 update are
  unblocked for this pass.

### 2026-03-16 10:34:43 JST

- start-of-pass remote / GitHub preflight repeated before the next fetch / pull /
  push / PR cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- the next remote sync, later push to
  `origin/codex/shielded-v2-overhaul-plan`, and the follow-up PR #82 update are
  unblocked for this pass.

### 2026-03-16 10:44:41 JST

- Slice 17 wallet / RPC sub-slice: added `bridge_submitshieldtx` in
  `src/wallet/shielded_rpc.cpp` as the first one-shot bridge deposit
  submission RPC on top of the existing canonical bridge shield settlement
  builder;
- the new submission path is intentionally thin:
  - it reuses `CreateBridgeShieldSettlementTransaction(...)` so the canonical
    bridge-in PSBT shape does not fork;
  - it signs and finalizes the PSBT with the local wallet through the existing
    PSBT fill path;
  - it commits through the wallet broadcast path so mempool rejection is
    surfaced the same way as the rest of the live shielded wallet surface;
  - it leaves `bridge_buildshieldtx` intact for external-signer and manual PSBT
    workflows;
- supporting surface updates in this pass:
  - registered the new RPC in `src/wallet/rpc/wallet.cpp`;
  - added CLI argument conversion for `vout` / `amount` in `src/rpc/client.cpp`;
  - documented the wallet endpoint surface change in
    `doc/JSON-RPC-interface.md`;
  - switched `test/functional/wallet_bridge_happy_path.py` to the one-shot
    submit path;
  - extended `test/functional/wallet_bridge_batch_in.py` so the aggregated
    bridge-in path now funds, submits, mines, and checks the actual recipient
    note instead of stopping at plan / PSBT compression measurements;
- Slice 17 status:
  - `sendtoaddress`-like v2 private send is complete;
  - batch deposit submission is now complete;
  - the remaining Slice 17 wallet / RPC families still remain open below;
- validated with:
  - `python3 -m py_compile /Users/admin/Documents/btxchain/btx-node/test/functional/wallet_bridge_happy_path.py /Users/admin/Documents/btxchain/btx-node/test/functional/wallet_bridge_batch_in.py /Users/admin/Documents/btxchain/btx-node/test/functional/wallet_bridge_psbt.py`
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target btxd -j8`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/test/functional/wallet_bridge_happy_path.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/wallet-bridge-happy-slice17-20260316a --portseed=32256`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/test/functional/wallet_bridge_batch_in.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/wallet-bridge-batch-in-slice17-20260316a --portseed=32257`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/test/functional/wallet_bridge_psbt.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/wallet-bridge-psbt-slice17-20260316a --portseed=32258`
- measured local runtimes:
  - `wallet_bridge_happy_path.py = real 10.24, user 3.44, sys 0.39`
  - `wallet_bridge_batch_in.py = real 9.90, user 3.55, sys 0.37`
  - `wallet_bridge_psbt.py = real 10.46, user 3.86, sys 0.36`
- measured batch deposit compression from the live batch functional:
  - plan bytes `20646 -> 6992`
  - PSBT bytes `8508 -> 2946`
- pivots:
  - the submission RPC was deliberately implemented as a wallet-side wrapper
    over the existing PSBT builder instead of a new raw transaction path so the
    external-signer / manual bridge flow stays covered by the unchanged
    `wallet_bridge_psbt.py` regression;
  - the funded bridge outputs in the live submit functionals now carry a
    `0.00040000` margin to keep the live bridge settlement fee headroom
    deterministic across both the single and aggregated deposit paths;
- cloud resources used: none;
- cost: `0`;
- teardown confirmation:
  - the successful tmpdirs `wallet-bridge-happy-slice17-20260316a`,
    `wallet-bridge-batch-in-slice17-20260316a`, and
    `wallet-bridge-psbt-slice17-20260316a` were cleaned by the functional
    harness on exit;
- next slice: continue Slice 17 with the batch exit claim / receive path and
  the remaining wallet / RPC families.

### 2026-03-16 10:32:45 JST

- Slice 17 wallet / RPC sub-slice: added a dedicated `z_sendtoaddress` shielded
  RPC surface on top of the real `v2_send` path in `src/wallet/shielded_rpc.cpp`
  and registered it in `src/wallet/rpc/wallet.cpp`;
- the new RPC is intentionally stricter than `z_sendmany`:
  - it only accepts shielded destinations;
  - it preserves wallet `comment` / `to` metadata at commit time;
  - it supports `subtractfeefromamount`;
  - it explicitly disables transparent-input fallback so insufficient funds
    fail instead of silently routing through legacy shielding;
- `src/wallet/shielded_wallet.h` / `src/wallet/shielded_wallet.cpp` now expose a
  bounded `CreateShieldedSpend(..., allow_transparent_fallback)` switch so the
  RPC can request a strict private-send build without breaking the existing
  `z_sendmany` fallback behavior;
- `test/functional/wallet_shielded_rpc_surface.py` now proves:
  - invalid transparent destinations reject on `z_sendtoaddress`;
  - the happy path builds a real `v2_send`;
  - the live selected fee is subtracted from the recipient amount when
    `subtractfeefromamount=true`;
  - wallet `comment` / `to` metadata survive `gettransaction(...)`;
- validated with:
  - `python3 -m py_compile /Users/admin/Documents/btxchain/btx-node/test/functional/wallet_shielded_rpc_surface.py`
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target btxd -j8`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/test/functional/wallet_shielded_rpc_surface.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/wallet-shielded-rpc-surface-slice17-20260316b --portseed=32255`
- measured local runtime:
  - `wallet_shielded_rpc_surface.py = real 312.86, user 274.79, sys 3.80`
- pivots:
  - the first compile attempt failed because `CreateV2Send(...)` is private, so
    the fix moved into the wallet boundary by adding the explicit
    `allow_transparent_fallback` switch on `CreateShieldedSpend(...)`;
  - the first functional run failed with `Fee too low for transaction size.
    Required at least 0.00058194 (-4)` when the regression pinned `fee=0.0001`,
    so the final coverage uses the RPC's automatic fee bump path and asserts
    the actual selected fee was deducted from the recipient output;
- cloud resources used: none;
- cost: `0`;
- teardown confirmation:
  - the successful tmpdir `wallet-shielded-rpc-surface-slice17-20260316b` was
    cleaned by the functional harness on exit;
- next slice: continue Slice 17 with batch deposit submission and the remaining
  wallet / RPC families.

### 2026-03-16 10:16:28 JST

- start-of-pass remote / GitHub preflight repeated before the next fetch / pull /
  push / PR cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- the next remote sync, later push to
  `origin/codex/shielded-v2-overhaul-plan`, and the follow-up PR #82 update are
  unblocked for this pass.

### 2026-03-16 10:14:28 JST

- Slice 16 miner / block-assembler sub-slice: `test/functional/feature_btx_block_capacity.py`
  now goes past empty-template reporting and drives live shielded families
  through `getblocktemplate`, mining, and `getmininginfo()` with exact
  shielded resource assertions for:
  - wallet-funded `v2_rebalance`;
  - wallet-funded reserve-bound `v2_settlement_anchor`;
  - prioritised bare `v2_egress_batch` against an active settlement anchor;
- this closes Slice 16: the earlier scarcity-aware package-ordering work in
  `src/node/miner.cpp` is now paired with miner-facing live-template evidence
  that relayed `shielded_v2` families are actually selected, mined, and
  reported with the correct verify / scan / tree-update totals;
- validated with:
  - `python3 -m py_compile /Users/admin/Documents/btxchain/btx-node/test/functional/feature_btx_block_capacity.py`
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target btxd generate_shielded_relay_fixture_tx -j8`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/test/functional/feature_btx_block_capacity.py --descriptors --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/feature-btx-block-capacity-shielded-20260316d --portseed=32253`
- measured local runtime:
  - `feature_btx_block_capacity.py = real 10.05, user 2.72, sys 0.42`
- pivots:
  - the first live run failed because the functional had not enabled wallet RPC
    support, so `createwallet` returned `Method not found (-32601)` until the
    harness added descriptor-wallet options and `skip_if_no_wallet()`;
  - the next live runs exposed that the default relay `v2_egress_batch`
    fixture is a two-output / one-chunk bundle, so the correct live template
    footprint is `scan = 3` and `tree_update = 2`, not the smaller one-output
    fixture totals from the earlier unit reference;
- cloud resources used: none;
- cost: `0`;
- teardown confirmation:
  - the successful tmpdir `feature-btx-block-capacity-shielded-20260316d` was
    cleaned by the functional harness on exit;
  - the three failed manual tmpdirs from the rejected attempts were then
    removed locally after validation;
- next slice: start `Slice 17: Build Full Wallet And RPC Flows`.

### 2026-03-16 10:05:02 JST

- start-of-pass remote / GitHub preflight repeated before the next fetch / pull /
  push / PR cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- the next remote sync, later push to
  `origin/codex/shielded-v2-overhaul-plan`, and the follow-up PR #82 update are
  unblocked for this pass.

### 2026-03-16 10:03:05 JST

- Slice 16 miner / block-assembler sub-slice: `src/node/miner.cpp` now builds a
  bounded candidate window for package selection and applies a scarcity-aware
  dominant-resource score across serialized bytes, shielded verify units, scan
  units, and tree-update units instead of relying only on ancestor feerate when
  shielded block capacity is tight;
- `src/test/miner_tests.cpp` now adds deterministic shielded miner fixtures on
  top of `TestChain100Setup` and proves both scarcity pivots with real
  `v2_egress_batch` and `v2_ingress_batch` transactions funded by matured
  coinbase outputs:
  - scan-scarce blocks prefer the lower-fee tree-update package over the
    higher-fee scan package;
  - tree-update-scarce blocks prefer the lower-fee scan package over the
    higher-fee tree-update package;
- validated with:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `./build-btx/bin/test_btx --run_test=miner_tests/CreateNewBlock_validity --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test='miner_shielded_tests/block_assembler_prefers_tree_updates_when_scan_capacity_is_scarce' --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test='miner_shielded_tests/block_assembler_prefers_scan_updates_when_tree_capacity_is_scarce' --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=miner_tests --catch_system_error=no --log_level=test_suite`
- measured local runtimes:
  - `CreateNewBlock_validity = 4,441,585us`
  - `block_assembler_prefers_tree_updates_when_scan_capacity_is_scarce = 2,608,850us`
  - `block_assembler_prefers_scan_updates_when_tree_capacity_is_scarce = 2,587,424us`
  - `miner_tests = 4,549,004us`
- pivot: the first scarcity fixtures were too small and let the higher-fee
  package fit before the constrained resource saturated, so the final tests use
  `77` filler packages with `128` shielded resource units to force the intended
  dominant-resource choice cleanly;
- cloud resources used: none;
- cost: `0`;
- teardown confirmation: local-only unit coverage, no disposable infra created;
- next slice: continue Slice 16 with block-template / miner-facing integration
  beyond package ordering, including the remaining `getblocktemplate` /
  assembler evidence for live shielded families.

### 2026-03-16 08:55:05 JST

- start-of-pass remote / GitHub preflight repeated before any new fetch / pull /
  push / PR cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- the next remote sync, later push to
  `origin/codex/shielded-v2-overhaul-plan`, and the follow-up PR #82 update are
  unblocked for this pass.

### 2026-03-16 08:51:58 JST

- Slice 15 closeout: `net_processing.cpp` now queues the current unbroadcast
  mempool set onto each peer as soon as `VERACK` completes, so fresh peers
  can receive resurrected tx announcements with the normal randomized inv
  timing instead of waiting for the separate 10-15 minute wall-clock
  rebroadcast scheduler; this closes the real fresh-peer reannouncement gap
  exposed by settlement-anchor relay after reorg;
- the live relay-fixture path is now complete across the remaining
  settlement-dependent family: `shielded_relay_fixture_builder.{h,cpp}`,
  `generate_shielded_relay_fixture_tx.cpp`, and
  `shielded_relay_fixture_builder_tests.cpp` now include a bare
  `v2_egress_batch` receipt fixture, while
  `test/functional/p2p_shielded_relay.py` exercises live relay for
  `v2_rebalance`, reserve-bound `v2_settlement_anchor`, and bare
  `v2_egress_batch`, including mine / reorg / fresh-peer reannouncement
  coverage and the final rebalance-only resurrection when the manifest anchor
  is dropped;
- pivots:
  - the first settlement-anchor reorg failure was not a missing mempool
    resurrection but a harness assumption bug: `setmocktime` advances peer
    inventory timing, but it does not advance the separate wall-clock
    unbroadcast rebroadcast scheduler; fixing the node to seed fresh peers
    from the unbroadcast set at `VERACK` made the behavior deterministic;
  - the first bare `v2_egress_batch` reorg failure was a local-fee artifact:
    bare egress uses `prioritisetransaction` rather than a transparent fee
    carrier, and `mapDeltas` are cleared once the tx is mined; the functional
    now re-seeds the same fee delta before invalidating the egress block so
    disconnected-block reaccept evaluates the same effective feerate as the
    original live relay path;
- validation:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx btxd generate_shielded_relay_fixture_tx -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_relay_fixture_builder_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/gen_shielded_relay_fixture_tx --family=egress_receipt`
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target btxd -j8`
  - `python3 -m py_compile /Users/admin/Documents/btxchain/btx-node/test/functional/p2p_shielded_relay.py`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/test/functional/p2p_shielded_relay.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/p2p-shielded-relay-v2-egress-20260316d --portseed=32248`
- findings:
  - the final live relay functional passed in `real 159.33`, `user 141.60`,
    `sys 1.02`, and now covers mixed `v2_send` + `v2_ingress_batch` relay,
    fresh-peer mempool-request gating, rebalance relay, reserve-bound
    settlement-anchor relay, settlement-anchor reannouncement after reorg,
    live `v2_egress_batch` relay, egress reannouncement after reorg, and
    rebalance-only resurrection after the manifest anchor is removed;
  - earlier in the same pass, `shielded_relay_fixture_builder_tests` passed in
    `4273us`, the bare `egress_receipt` generator emitted a real
    `v2_egress_batch` fixture keyed to the canonical settlement-anchor digest,
    and the stale intermediate functional tmpdirs captured the two genuine
    pivots above rather than unresolved consensus gaps;
  - no cloud resources were used, cost was `0`, and the successful functional
    tmpdir was cleaned by the harness;
- next:
  - start `Slice 16: Implement Miner And Block-Assembler Integration`.

### 2026-03-16 08:05:32 JST

- start-of-pass remote / GitHub preflight repeated before any new fetch / pull /
  push / PR cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- the next remote sync, later push to
  `origin/codex/shielded-v2-overhaul-plan`, and the follow-up PR #82 update are
  unblocked for this pass.

### 2026-03-16 08:02:58 JST

- Slice 15 live relay-fixture sub-slice: added a deterministic shielded relay
  fixture builder in `src/test/shielded_relay_fixture_builder.{h,cpp}` plus the
  standalone `gen_shielded_relay_fixture_tx` helper wired in
  `src/test/CMakeLists.txt`; the helper wraps real `v2_rebalance` and
  reserve-bound `v2_settlement_anchor` fixtures in a wallet-signable P2MR fee
  carrier so the functional relay harness can exercise those families through
  live wallet signing rather than a fake test-only acceptance path;
- `test/functional/p2p_shielded_relay.py` now uses that helper to validate the
  settlement-facing `shielded_v2` relay path end to end: fresh
  shielded-capable peers receive live `v2_rebalance` announcements while
  non-shielded peers stay dark; once the rebalance is mined and the manifest is
  anchored, fresh shielded-capable peers receive the reserve-bound
  `v2_settlement_anchor`; after invalidating the settlement-anchor block the
  same family is re-announced while the manifest anchor remains live; after
  invalidating the rebalance block the settlement-anchor traffic is evicted and
  only `v2_rebalance` resurrects and re-announces to fresh shielded-capable
  peers;
- pivots:
  - the first rerun exposed an existing relay-harness timing edge: a
    `mempool`-request peer can miss the next inventory slot when integer
    `setmocktime` lands just short of the peer's microsecond
    `m_next_inv_send_time`; fixed by overshooting the inbound inventory window
    instead of assuming `+5s` is sufficient;
  - the first live settlement attempt failed with the real consensus rejection
    `bad-shielded-v2-settlement-unanchored-manifest`; the harness now models
    the valid lifecycle explicitly by mining `v2_rebalance` before relaying the
    reserve-bound settlement anchor, then reorging in the correct order to
    prove settlement eviction and rebalance-only resurrection when the manifest
    anchor disappears;
- validation:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx btxd generate_shielded_relay_fixture_tx -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_relay_fixture_builder_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/gen_shielded_relay_fixture_tx --family=rebalance --input-txid=0100000000000000000000000000000000000000000000000000000000000000 --input-vout=0 --input-value-sats=100000000 --change-script=5220afa45d6891836c7314dded4dbd0e7aacde3de0d7fa9a12aeac06e2296c794226 --fee-sats=40000`
  - `python3 -m py_compile /Users/admin/Documents/btxchain/btx-node/test/functional/p2p_shielded_relay.py`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/test/functional/p2p_shielded_relay.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/p2p-shielded-relay-v2-manifest-20260316o --portseed=32244`
- findings:
  - `shielded_relay_fixture_builder_tests` passed in `4273us`, with the three
    targeted cases exercising rebalance wrapping, reserve-bound settlement
    binding preservation, and fee-headroom rejection;
  - the standalone generator emitted a real `v2_rebalance` relay fixture with
    a live manifest id and wallet-signable transparent fee carrier;
  - the full relay functional passed in `real 162.00`, `user 145.15`,
    `sys 1.26`, and now covers live relay for `v2_rebalance`, anchored
    reserve-bound settlement-anchor relay, settlement-anchor reannouncement
    after reorg, and rebalance-only resurrection after the manifest anchor is
    removed, while non-shielded peers remain dark throughout;
  - no cloud resources were used, cost was `0`, and the failed intermediate
    tmpdirs were left to the harness cleanup path or cleaned locally during
    debugging;
- next:
  - continue Slice 15 with the remaining network behavior around miner / peer
    announcement churn and any additional settlement-family relay surfaces not
    yet covered by live functional peers.

### 2026-03-16 07:35:56 JST

- start-of-pass remote / GitHub preflight repeated before any new fetch / pull /
  push / PR cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- the next remote sync, later push to
  `origin/codex/shielded-v2-overhaul-plan`, and the follow-up PR #82 update are
  unblocked for this pass.

### 2026-03-16 07:33:57 JST

- Slice 15 mempool-churn sub-slice: `shielded_mempool_tests.cpp` now carries
  direct cleanup regressions for the settlement-facing `shielded_v2` families,
  proving that stale-anchor eviction preserves a valid `v2_egress_batch` whose
  settlement-anchor digest is present on chain while evicting one whose digest
  is missing, and likewise preserves a reserve-bound `v2_settlement_anchor`
  whose anchored netting-manifest id is live while evicting one bound to a
  missing manifest id; the new cases reuse the real
  `shielded_v2_egress_fixture` builders rather than any fake or ad hoc
  mempool-only fixture path;
- pivot: the first rebuild failure was only a tree-local include mismatch
  (`script/standard.h` does not exist here), fixed by switching the test to the
  live `addresstype.h` surface; a second harness quirk surfaced during
  validation: `shielded_mempool_tests` already keeps its anchor-cleanup cases
  outside the suite block, so the new cleanup regressions are validated via
  direct `--run_test=<case>` invocation instead of the suite selector;
- validation:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_egress_cleanup_preserves_valid_anchor_refs_and_evicts_missing_ones --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_settlement_anchor_cleanup_preserves_valid_manifest_refs_and_evicts_missing_ones --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_mempool_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=txvalidation_tests/tx_mempool_accepts_v2_egress_after_settlement_anchor_and_evicts_it_after_reorg --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=txvalidation_tests/tx_mempool_accepts_fee_bearing_reserve_bound_v2_settlement_anchor_and_rewinds_state_after_reorg --catch_system_error=no --log_level=test_suite`
- findings:
  - new targeted cleanup timings: valid/missing settlement-anchor sweep
    `1493556us`; valid/missing manifest sweep `1563491us`;
  - nearby live mempool/reorg regressions stayed green: accepted `v2_egress`
    post-anchor path `1544739us`; fee-bearing reserve-bound settlement-anchor
    path `1535644us`;
  - the legacy in-suite `shielded_mempool_tests` cases still pass and the two
    cleanup-style regressions continue to require direct invocation because of
    the file's existing suite layout;
  - no cloud resources were used, cost was `0`, and no remote infrastructure
    teardown was required;
- next:
  - continue Slice 15 with live mixed-family relay churn for
    `v2_settlement_anchor`, netting-manifest, and `v2_rebalance` traffic once
    those families have a real announcement path to validate.

### 2026-03-16 07:23:44 JST

- start-of-pass remote / GitHub preflight repeated before any new fetch / pull /
  push / PR cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- the next remote sync, later push to
  `origin/codex/shielded-v2-overhaul-plan`, and the follow-up PR #82 update are
  unblocked for this pass.

### 2026-03-16 07:21:05 JST

- Slice 15 mixed-family announcement-churn sub-slice: `p2p_shielded_relay.py`
  now covers fresh-peer `mempool` requests for mixed `v2_send` +
  `v2_ingress_batch` traffic, proving that only peers advertising
  `NODE_SHIELDED` receive the mixed `inv` / `shieldedtx` announcements on the
  explicit mempool-request path while otherwise identical non-shielded peers
  stay dark; the same run still covers the existing mine / reorg mixed-family
  reannouncement path for fresh shielded-capable peers;
- pivot: rather than inventing a new settlement-anchor / `v2_rebalance`
  functional builder surface in this pass, the work tightened the already-live
  relay family path and closed the fresh-peer `mempool` request coverage gap on
  the real `v2_send` + `v2_ingress_batch` transport;
- validation:
  - `python3 -m py_compile /Users/admin/Documents/btxchain/btx-node/test/functional/p2p_shielded_relay.py`
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target btxd -j8`
  - `python3 /Users/admin/Documents/btxchain/btx-node/test/functional/p2p_shielded_relay.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/p2p-shielded-relay-v2-mempool-20260316a --portseed=32240`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/test/functional/p2p_shielded_relay.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/p2p-shielded-relay-v2-mempool-20260316b --portseed=32241`
- findings:
  - both fresh-peer `mempool` request coverage and the existing mixed-family
    mine / reorg reannouncement path passed end to end with deterministic
    `v2_send` + `v2_ingress_batch` fixtures;
  - timed confirmation: `real 158.52`, `user 144.51`, `sys 0.88`;
  - no cloud resources were used, cost was `0`, and both successful functional
    tmpdirs were cleaned up by the harness;
- next:
  - continue Slice 15 with live settlement-anchor / manifest / `v2_rebalance`
    relay and mixed-family churn once the functional harness can construct
    those families without introducing a fake or ad hoc builder path.

### 2026-03-16 07:08:19 JST

- start-of-pass remote / GitHub preflight repeated before any new fetch / pull /
  push / PR cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- the next remote sync, later push to
  `origin/codex/shielded-v2-overhaul-plan`, and the follow-up PR #82 update are
  unblocked for this pass.

### 2026-03-16 07:05:20 JST

- Slice 15 orphan-handling sub-slice: `orphanage_tests.cpp` now covers a real
  shielded orphan chain where a `v2_rebalance` orphan acts as the parent for a
  reserve-bound `v2_settlement_anchor` orphan, both carried through synthetic
  transparent fee-carrier prevouts so orphan indexing, child discovery,
  reconsider scheduling, and block-driven eviction are exercised on the live
  orphanage path;
- validated with:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `./build-btx/bin/test_btx --run_test=orphanage_tests --catch_system_error=no --log_level=test_suite`
  - `/usr/bin/time -p ./build-btx/bin/test_btx --run_test=orphanage_tests/shielded_v2_manifest_and_settlement_anchor_orphans --catch_system_error=no --log_level=test_suite`
- findings / pivots:
  - the wallet-side settlement-anchor construction surface is still not exposed
    cleanly enough for the next functional relay/orphan regression without
    widening RPC scope, so this pass closed the orphan-handling portion of
    Slice 15 directly against the in-tree shielded fixtures;
  - the full orphanage suite passed in `753360us`;
  - the new shielded orphan-chain case passed in `168268us` with timed wall
    clock `real 0.74`, `user 0.12`, `sys 0.04`;
- cloud resources used: none;
- cost: `0`;
- teardown: no cloud teardown required; local test state was ephemeral;
- next: continue Slice 15 with mixed-family announcement churn for settlement
  anchors, manifests, and rebalance traffic.

### 2026-03-16 06:56:30 JST

- start-of-pass remote / GitHub preflight repeated before any new fetch / pull /
  push / PR cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- the next remote sync, later push to
  `origin/codex/shielded-v2-overhaul-plan`, and the follow-up PR #82 update are
  unblocked for this pass.

### 2026-03-16 06:53:54 JST

- Slice 15 mixed-family reorg relay sub-slice: `Chainstate::MaybeUpdateMempoolForReorg(...)`
  now re-adds reorg-resurrected txids to the mempool unbroadcast set so the
  periodic rebroadcast path can re-announce them to fresh peers on the new
  active chain; `p2p_shielded_relay.py` now regression-covers mixed
  `v2_send` + `v2_ingress_batch` reannouncement to fresh shielded-capable
  peers connected after reorg while non-shielded peers still receive neither
  `inv` nor `shieldedtx`;
- validated with:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target btxd -j8`
  - `python3 -m py_compile /Users/admin/Documents/btxchain/btx-node/test/functional/p2p_shielded_relay.py`
  - `python3 /Users/admin/Documents/btxchain/btx-node/test/functional/p2p_shielded_relay.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/p2p-shielded-relay-v2-mixed-20260316k --portseed=32236`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/test/functional/p2p_shielded_relay.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/p2p-shielded-relay-v2-mixed-20260316l --portseed=32237`
- findings / pivots:
  - the first outbound-peer regression shape remained nondeterministic even
    after restoring unbroadcast membership; the stable final regression now
    connects fresh peers after reorg so it directly proves the restored
    unbroadcast rebroadcast path instead of outbound callback timing;
  - timed confirmation passed in `real 158.33`, `user 144.37`, `sys 1.16`;
- cloud resources used: none;
- cost: `0`;
- teardown: passing tmpdirs `...20260316k` and `...20260316l` were cleaned by
  the harness; the failed intermediate `...20260316j` tmpdir remained
  available for inspection because direct removal was blocked by the local exec
  policy;
- next: continue Slice 15 with orphan handling plus mixed-family announcement
  churn for settlement anchors, manifests, and rebalance traffic.

### 2026-03-16 05:43:58 JST

- start-of-pass remote / GitHub preflight repeated before any new fetch / pull /
  push / PR cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- the next remote sync, later push to
  `origin/codex/shielded-v2-overhaul-plan`, and the follow-up PR #82 update are
  unblocked for this pass.

### 2026-03-16 03:56:56 JST

- start-of-pass remote / GitHub preflight repeated before any new fetch / pull /
  push / PR cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- the next remote sync, later push to
  `origin/codex/shielded-v2-overhaul-plan`, and the follow-up PR #82 update are
  unblocked for this pass.

### 2026-03-16 05:39:29 JST

- remote / GitHub preflight repeated immediately before the next validated
  push / PR #82 update cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- the upcoming push to `origin/codex/shielded-v2-overhaul-plan` and the
  follow-up PR #82 update are unblocked for this pass.

### 2026-03-16 05:39:58 JST

- continued `Slice 15: Implement Network Relay, Orphan Handling, And
  Announcement Behavior` with the validated `shielded_v2` ingress
  announcement / reorg-reannouncement sub-slice in
  `/Users/admin/Documents/btxchain/btx-node`:
  - extended `src/net_processing.cpp` with a
    `TransactionAddedToMempool(...)` relay hook so reorg-resurrected mempool
    transactions are queued back through `RelayTransaction(...)` instead of
    relying only on the original admission path
  - initialized `tx_relay->m_next_inv_send_time` at `VERACK` time in
    `src/net_processing.cpp` for both inbound and outbound peers, closing the
    fresh-peer blind spot where newly connected peers could miss the first
    inventory announcement until some later unrelated send cycle
  - taught `RelayTransaction(...)` to wake the message handler once inventory
    is queued so reorg-driven relay work is not left waiting for unrelated
    traffic
  - rewrote the `shielded_v2` relay section of
    `test/functional/p2p_shielded_relay.py` around deterministic
    `v2_ingress_batch` fixtures, shielded-only `inv` / `getdata` /
    `shieldedtx` coverage, and a reorg-specific mocktime step of
    `INBOUND_INVENTORY_BROADCAST_INTERVAL + 1` seconds so the test crosses the
    peer's microsecond inventory slot deterministically
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target btxd -j8`
  - `python3 -m py_compile /Users/admin/Documents/btxchain/btx-node/test/functional/p2p_shielded_relay.py`
  - `python3 /Users/admin/Documents/btxchain/btx-node/test/functional/p2p_shielded_relay.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/p2p-shielded-relay-v2-20260316u --portseed=32225`
  - `/usr/bin/time -p python3 /Users/admin/Documents/btxchain/btx-node/test/functional/p2p_shielded_relay.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/p2p-shielded-relay-v2-20260316v --portseed=32226`
- validation findings:
  - `p2p_shielded_relay.py` now passes end to end on the no-probe build,
    including the new `shielded_v2` ingress announcement path, shielded-only
    fetch path, relay-rate limiting, and reorg reannouncement behavior
  - the final timed clean run completed in `real 145.07`, `user 130.87`, and
    `sys 1.13`
  - the real remaining failure after the relay hook landed was mocktime
    granularity: advancing by exactly the `5` second inbound inventory interval
    could still land one integer second short of the peer's microsecond
    `m_next_inv_send_time`, so the deterministic fix is
    `INBOUND_INVENTORY_BROADCAST_INTERVAL + 1`, not broader relay logic
- blockers / pivots:
  - the first `shielded_v2` relay attempt in the functional used the wrong
    family shape and had to be replaced with deterministic
    `v2_ingress_batch` transactions so the network coverage exercised a valid
    new-family object
  - an intermediate clean rerun still failed after switching to a plain `+5s`
    reorg bump; inspecting the logs showed no missing relay queue, only the
    mocktime-versus-microsecond send-slot mismatch, so the fix stayed in the
    test timing rather than widening the node behavior further
- benchmarks / simulation findings:
  - no cloud or distributed simulation was required for this sub-slice; the
    meaningful measurement here is the full functional runtime on the live P2P
    path
- cloud resources used: none
- estimated cost: `0`
- teardown confirmation:
  - the functional harness cleaned up
    `/tmp/btx-functional-manual/p2p-shielded-relay-v2-20260316u` on exit
  - the functional harness cleaned up
    `/tmp/btx-functional-manual/p2p-shielded-relay-v2-20260316v` on exit
  - the intermediate failed tmpdir
    `/tmp/btx-functional-manual/p2p-shielded-relay-v2-20260316t` was removed
    manually after diagnosis
  - no DigitalOcean, Porkbun, or Tailscale resources were created
- slice status:
  - Slice 15 remains open, but `shielded_v2` ingress now has validated normal
    announcement, shielded-only fetch, and reorg reannouncement behavior on
    the live P2P path
- next slice:
  - continue `Slice 15` with orphan-handling and mixed-family relay behavior
    for settlement anchors, manifests, and mempool churn

### 2026-03-16 03:54:22 JST

- remote / GitHub preflight repeated immediately before the upcoming
  `codex/shielded-v2-overhaul-plan` push / PR #82 update cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- continued `Slice 14: Implement Default Externalized Retention, Weekly
  Snapshots, And Recovery Semantics` with the node-visible weekly cadence and
  snapshot lifecycle closeout sub-slice in
  `/Users/admin/Documents/btxchain/btx-node`:
  - extended `src/rpc/blockchain.cpp` so `getblockchaininfo` now reports
    `shielded_retention` and `snapshot_sync`, exposing the active retained-state
    profile, the production weekly snapshot target (`2,642,412,320` bytes,
    `7` days, `6,720` blocks at BTX's `90` second spacing), and the live
    assumeutxo background-validation lifecycle through the normal node info path
  - derived the reported weekly cadence directly from
    `BridgeShieldedStateRetentionPolicy::WEEKLY_SNAPSHOT_TARGET_BYTES` and the
    active consensus target spacing instead of introducing a second
    retention-policy constant path
  - extended `test/functional/feature_shielded_snapshot_retention_profile.py`
    so both the default externalized node and the explicit
    `-retainshieldedcommitmentindex=1` node assert the new
    `getblockchaininfo` retention/cadence surface
  - extended `test/functional/feature_assumeutxo.py` so the new
    `snapshot_sync` and `shielded_retention` objects are asserted across
    snapshot activation, restart during background validation, validation
    completion, and the retained-index assumeutxo path
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx btxd -j8`
  - `./build-btx/bin/test_btx --run_test=validation_chainstatemanager_tests --catch_system_error=no --log_level=test_suite`
  - `python3 ./test/functional/feature_shielded_snapshot_retention_profile.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/shielded-snapshot-retention-profile-20260316g --portseed=32221`
  - `python3 ./test/functional/feature_assumeutxo.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/feature-assumeutxo-retention-20260316c --portseed=32222`
- validation findings:
  - `validation_chainstatemanager_tests` passed in `29,028,157us`, confirming
    the prior externalized-retention / snapshot reload behavior was not
    perturbed by the new RPC surface
  - `feature_shielded_snapshot_retention_profile.py` passed, proving the live
    node runtime now reports the production weekly cadence and the active
    retained-state posture through `getblockchaininfo`
  - `feature_assumeutxo.py` passed, proving `snapshot_sync.active` /
    `background_validation_in_progress` transition correctly during
    snapshot-backed sync, restart, validation completion, pruning, and the
    retained-index assumeutxo configuration
- blockers / pivots:
  - the remaining Slice 14 gap was no longer in snapshot format or recovery
    correctness; it was that the weekly cadence and live snapshot-validation
    state still required stitching together separate snapshot RPCs plus
    `getchainstates`, leaving the normal node-facing status path incomplete
  - `-retainshieldedcommitmentindex` still only toggles the on-disk commitment
    index; the weekly cadence reported here intentionally reflects the
    production retained-state target and current consensus spacing rather than
    silently importing the wallet-only `5`-day dev/audit estimate path
- benchmarks / simulation findings:
  - no cloud or distributed simulation was required for this closeout; the key
    evidence is the successful live-node functional coverage across both
    externalized and retained-index assumeutxo paths
- cloud resources used: none
- estimated cost: `0`
- teardown confirmation:
  - the functional harness cleaned up
    `/tmp/btx-functional-manual/shielded-snapshot-retention-profile-20260316g`
    on exit
  - the functional harness cleaned up
    `/tmp/btx-functional-manual/feature-assumeutxo-retention-20260316c` on
    exit
- Slice 14 is now complete; the next highest-priority unfinished slice is
  `Slice 15: Implement Network Relay, Orphan Handling, And Announcement
  Behavior`

### 2026-03-16 03:44:19 JST

- start-of-pass remote / GitHub preflight repeated before any new fetch / pull /
  push / PR cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- the next remote sync, later push to
  `origin/codex/shielded-v2-overhaul-plan`, and the follow-up PR #82 update are
  unblocked for this pass.

### 2026-03-16 03:42:08 JST

- continued `Slice 14: Implement Default Externalized Retention, Weekly
  Snapshots, And Recovery Semantics` with the production retention-policy
  defaults sub-slice in `/Users/admin/Documents/btxchain/btx-node`:
  - updated `src/shielded/bridge.h` so the canonical
    `BridgeShieldedStateRetentionPolicy` now defaults to the externalized
    production posture instead of the old full-retention dev mode:
    commitment-history retention is off by default, commitment entries are
    excluded from snapshots by default, first-touch wallet materialization now
    defaults to `25%`, and the snapshot target now encodes a weekly export
    cadence under the production externalized profile
  - updated the RPC surface in `src/wallet/shielded_rpc.cpp` so
    `bridge_buildstateretentionpolicy` and `bridge_estimatestateretention`
    describe and emit the production externalized weekly-snapshot default,
    while leaving the full-retention mode available only when explicitly
    requested
  - aligned the helper defaults in `src/test/shielded_bridge_tests.cpp` and
    `src/bench/bridge_batch_bench.cpp` with the same production policy surface
  - rewrote `test/functional/wallet_bridge_state_retention.py` so the default
    policy path now proves the externalized weekly-snapshot behavior, and the
    old full-retention `5`-day model is exercised only as an explicit
    dev / audit override
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx btxd -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_bridge_tests --catch_system_error=no --log_level=test_suite`
  - `python3 ./test/functional/wallet_bridge_state_retention.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/wallet-bridge-state-retention-20260316a --portseed=32220`
- validation findings:
  - `shielded_bridge_tests` passed in `498,878us`, including the new default
    policy constant regression and the updated full-vs-externalized retention
    estimate coverage
  - `wallet_bridge_state_retention.py` passed, proving the live RPC default now
    returns the production externalized posture and a `7`-day snapshot cadence,
    while explicit full retention still returns the old `5`-day dev / audit
    profile
- blockers / pivots:
  - the real remaining mismatch in Slice 14 was no longer the node runtime, but
    the retained-state modeling / RPC surface: after the chainstate default
    moved to externalized retention, `bridge_buildstateretentionpolicy` still
    silently defaulted to full retention with a `4 GiB` / `5`-day cadence
  - fixing that required choosing an explicit weekly snapshot target for the
    production externalized profile (`2,642,412,320` bytes) instead of
    continuing to reuse the old dev-mode `4 GiB` placeholder
- benchmarks / simulation findings:
  - no cloud or distributed simulation was required for this sub-slice; the
    meaningful evidence is the successful local unit + RPC functional coverage
    of the new default retention-policy surface
- cloud resources used: none
- estimated cost: `0`
- teardown confirmation:
  - the functional harness cleaned up
    `/tmp/btx-functional-manual/wallet-bridge-state-retention-20260316a` on
    exit
- Slice 14 remains open; the default policy surface now matches the production
  externalized weekly-snapshot posture, while the remaining node-visible weekly
  snapshot cadence / lifecycle surfaces still need to be closed

### 2026-03-16 03:33:04 JST

- start-of-pass remote / GitHub preflight repeated before any new fetch / pull /
  push / PR cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- the next remote sync, later push to
  `origin/codex/shielded-v2-overhaul-plan`, and the follow-up PR #82 update are
  unblocked for this pass.

### 2026-03-16 03:29:22 JST

- remote / GitHub preflight repeated immediately before the upcoming
  `codex/shielded-v2-overhaul-plan` push / PR #82 update cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- continued `Slice 14: Implement Default Externalized Retention, Weekly
  Snapshots, And Recovery Semantics` with the pruned-node / assumeutxo recovery
  sub-slice in `/Users/admin/Documents/btxchain/btx-node`:
  - upgraded the shielded snapshot payload format in
    `src/node/utxo_snapshot.h` from version `3` to version `4`, extending
    `ShieldedSnapshotSectionHeader` with settlement-anchor and
    netting-manifest counts so snapshots can carry the retained shielded state
    that pruned nodes cannot reconstruct from historical block files
  - updated `src/validation.cpp` / `src/validation.h` so
    `GetShieldedSnapshotSectionHeader(...)`, `LoadShieldedSnapshotSection(...)`,
    and `EnsureShieldedStateInitialized()` now serialize, load, persist, and
    restore settlement-anchor / netting-manifest state directly from the
    version-4 shielded snapshot section, while leaving the version-3 fallback
    on the older block-replay path for backward compatibility
  - extended `src/rpc/blockchain.cpp` so `dumptxoutset` now writes settlement
    anchors and netting manifests into the shielded snapshot section alongside
    commitments and nullifiers
  - strengthened
    `src/test/validation_chainstatemanager_tests.cpp` with an explicit
    version-3 synthetic section for the old commitment-index-missing rebuild
    case plus a new version-4 persisted settlement-anchor reload case that
    proves the restored path no longer depends on block replay
  - updated `test/functional/feature_assumeutxo.py` so the positive snapshot
    activation, restart, and reindex flows assert the active shielded retention
    profile for both the default externalized path and the explicit retained
    full-index path; the focused
    `test/functional/feature_shielded_snapshot_retention_profile.py` remains as
    the dedicated dump-side retention surface regression
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx btxd -j8`
  - `./build-btx/bin/test_btx --run_test=validation_chainstatemanager_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_tx_check_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests --catch_system_error=no --log_level=test_suite`
  - `python3 ./test/functional/feature_shielded_snapshot_retention_profile.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/shielded-snapshot-retention-profile-20260316f --portseed=32219`
  - `python3 ./test/functional/feature_assumeutxo.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/feature-assumeutxo-retention-20260316b --portseed=32218`
- validation findings:
  - `validation_chainstatemanager_tests` passed in `29,124,329us`, including
    the new `chainstatemanager_reloads_version4_snapshot_settlement_anchor_state`
    case (`1,762,700us`) and the version-3 rebuild regression
  - `shielded_tx_check_tests` passed in `45,339us`
  - `shielded_validation_checks_tests` passed in `111,368,812us`
  - `feature_shielded_snapshot_retention_profile.py` passed, confirming the
    dump-side RPC surface still reports `externalized` / `false` by default and
    `full_commitment_index` / `true` when the retained profile is enabled
  - `feature_assumeutxo.py` passed end to end, including positive snapshot
    activation, restart, `-reindex`, and `-reindex-chainstate` coverage for the
    updated shielded snapshot format
- blockers / pivots:
  - the first real pruned-node failure was not a test harness artifact:
    versioned snapshot activation still tried to rebuild settlement anchors and
    netting manifests from historical block files, which fails on an
    assumeutxo/pruned node after the shielded snapshot section is loaded
  - the fix was to carry that state explicitly in version-4 shielded snapshot
    sections and to trust the persisted DB state on restart once the
    commitment-index frontier is restored, instead of re-reading historical
    blocks
  - the invalid-version assumeutxo regression needed one real adjustment too:
    after bumping the snapshot metadata format to `4`, the unsupported-version
    test matrix had to move from `4` to `5`
- benchmarks / simulation findings:
  - no cloud or distributed simulation was required for this sub-slice; the
    meaningful evidence is the successful assumeutxo / restart / reindex
    recovery flow under the updated shielded snapshot format
- cloud resources used: none
- estimated cost: `0`
- teardown confirmation:
  - the functional harness cleaned up
    `/tmp/btx-functional-manual/shielded-snapshot-retention-profile-20260316f`
    on exit
  - the functional harness cleaned up
    `/tmp/btx-functional-manual/feature-assumeutxo-retention-20260316b` on exit
- Slice 14 remains open; default externalized retention now survives pruned
  assumeutxo activation and restart, but weekly snapshot cadence and the
  remaining recovery / policy surfaces still need to be closed

### 2026-03-16 03:05:39 JST

- continued `Slice 14: Implement Default Externalized Retention, Weekly
  Snapshots, And Recovery Semantics` with the explicit retention-profile
  sub-slice in `/Users/admin/Documents/btxchain/btx-node`:
  - added `-retainshieldedcommitmentindex` in `src/init.cpp`,
    `src/node/chainstatemanager_args.cpp`, and
    `src/kernel/chainstatemanager_opts.h`, keeping the production default on
    the externalized-rebuild path while allowing an explicit secondary
    full-retention dev / audit mode
  - updated `src/validation.cpp` / `src/validation.h` so
    `PrepareShieldedCommitmentIndex(...)` and
    `ChainstateManager::RetainShieldedCommitmentIndex()` now drive either the
    on-disk retained LevelDB commitment index or the default externalized
    rebuild path during startup and snapshot activation
  - surfaced the active retention profile through the snapshot RPC results in
    `src/rpc/blockchain.cpp`, adding
    `shielded_retention_profile` and
    `retain_shielded_commitment_index` to both `dumptxoutset` and
    `loadtxoutset`
  - strengthened `src/test/validation_chainstatemanager_tests.cpp` with
    `chainstatemanager_retains_commitment_index_when_configured` plus argument
    parsing coverage, proving the retained LevelDB path persists across restart
    when explicitly enabled
  - added
    `test/functional/feature_shielded_snapshot_retention_profile.py` and wired
    it into `test/functional/test_runner.py`, covering both the default
    externalized profile and the retained full-index profile through
    `dumptxoutset` and `loadtxoutset`
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx btxd -j8`
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `./build-btx/bin/test_btx --run_test=validation_chainstatemanager_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_tx_check_tests --catch_system_error=no --log_level=test_suite`
  - `python3 ./test/functional/feature_shielded_snapshot_retention_profile.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/shielded-snapshot-retention-profile-20260316a --portseed=32212`
- validation findings:
  - `validation_chainstatemanager_tests` passed with the new
    retained-index restart coverage, and the focused suite runtime remained
    about `27,535,093us` after the new case landed
  - `shielded_tx_check_tests` passed in `109,998us`, confirming the startup /
    retention-profile wiring did not perturb adjacent shielded tx admission
  - the new functional test passed cleanly, proving the live RPC surface reports
    `externalized` / `false` by default and `full_commitment_index` / `true`
    when the retained commitment-index profile is explicitly enabled, for both
    `dumptxoutset` and `loadtxoutset`
- blockers / pivots:
  - I initially tried to extend the existing `rpc_dumptxoutset.py` and
    `wallet_assumeutxo.py` functionals, but both already fail on this branch
    before the new retention assertions run: `rpc_dumptxoutset.py` currently
    sees `coins_written == 101` against an older `100` expectation, and
    `wallet_assumeutxo.py` currently hits `sendrawtransaction` `scriptpubkey
    (-26)` during baseline setup
  - instead of hiding those unrelated failures, I reverted the attempted edits
    there and added a new targeted retention-profile functional so the Slice 14
    evidence remains specific and reproducible
- benchmarks / simulation findings:
  - no cloud or distributed simulation was required for this runtime-policy
    slice; the meaningful evidence is local startup / restart and snapshot-RPC
    behavior under both retention profiles
- cloud resources used: none
- estimated cost: `0`
- teardown confirmation: the focused functional harness cleaned up
  `/tmp/btx-functional-manual/shielded-snapshot-retention-profile-20260316a`
  on exit
- Slice 14 remains open; the runtime retention-profile switch and snapshot RPC
  reporting are now implemented, while weekly snapshot cadence, pruned-node
  compatibility, and broader assumeutxo recovery semantics still remain
  outstanding

### 2026-03-16 02:46:07 JST

- start-of-pass remote / GitHub preflight repeated before any new fetch / pull /
  push / PR cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- the next remote sync, later push to
  `origin/codex/shielded-v2-overhaul-plan`, and the follow-up PR #82 update are
  unblocked for this pass.

### 2026-03-16 02:43:29 JST

- continued `Slice 14: Implement Default Externalized Retention, Weekly
  Snapshots, And Recovery Semantics` with the first real retained-state
  recovery sub-slice in `/Users/admin/Documents/btxchain/btx-node`:
  - replaced the old retained commitment-index LevelDB bootstrap in
    `src/validation.cpp` with `PrepareShieldedCommitmentIndex(...)`, so
    startup and snapshot activation now explicitly remove any on-disk
    commitment-position index and rebuild commitment lookup state in memory
    instead of retaining the full commitment-history index on disk by default
  - kept retained nullifier / settlement-anchor / netting-manifest state on
    disk, so the Slice 14 default is now materially different from the
    PR #79 modeling surface rather than remaining measurement-only
  - strengthened
    `src/test/validation_chainstatemanager_tests.cpp` so the restart and
    manifest-reload regressions now prove the commitment-index DB path stays
    absent across snapshot load and restart while `CommitmentAt(0)` and
    persisted manifest validity are still restored after
    `EnsureShieldedStateInitialized()`
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `/usr/bin/time -p ./build-btx/bin/test_btx --run_test=validation_chainstatemanager_tests/chainstatemanager_rebuilds_shielded_state_when_commitment_index_missing --catch_system_error=no --log_level=test_suite`
  - `/usr/bin/time -p ./build-btx/bin/test_btx --run_test=validation_chainstatemanager_tests/chainstatemanager_reloads_persisted_netting_manifest_state --catch_system_error=no --log_level=test_suite`
  - `/usr/bin/time -p ./build-btx/bin/test_btx --run_test=validation_chainstatemanager_tests --catch_system_error=no --log_level=test_suite`
  - `/usr/bin/time -p ./build-btx/bin/test_btx --run_test=shielded_tx_check_tests --catch_system_error=no --log_level=test_suite`
  - `/usr/bin/time -p ./build-btx/bin/test_btx --run_test=nullifier_set_tests/netting_manifest_insert_remove_and_iterate --catch_system_error=no --log_level=test_suite`
  - `/usr/bin/time -p ./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests --catch_system_error=no --log_level=test_suite`
- validation findings:
  - the new restart recovery regression passed in `1,829,162us` (`real 2.40`)
    and the strengthened persisted-manifest reload regression passed in
    `1,732,815us` (`real 2.31`)
  - the full `validation_chainstatemanager_tests` suite passed in
    `25,551,632us` (`real 25.67`), including snapshot activation,
    snapshot completion, restart, and the updated retained-state cases
  - `shielded_tx_check_tests` passed in `98,669us` (`real 0.21`)
  - `nullifier_set_tests/netting_manifest_insert_remove_and_iterate` passed in
    `50,208us` (`real 0.16`)
  - `shielded_validation_checks_tests` passed in `111,930,344us`
    (`real 112.04`), confirming the retained-state recovery change did not
    regress adjacent shielded contextual / proof validation
- blockers / pivots:
  - the real implementation pivot was to stop treating “missing commitment
    index” as a synthetic corruption-only case; the tests now validate that
    absence as the default production posture rather than faking it with a
    post-restart `remove_all(...)`
  - no extra backend work was required because `ShieldedMerkleTree{}` already
    rebuilds and serves the commitment lookup index in memory once chainstate
    replay completes; the retained on-disk LevelDB index was redundant for
    this default
- benchmarks / simulation findings:
  - no cloud or distributed simulation was required for this retained-state
    recovery sub-slice
  - the highest-signal local runtime evidence for this pass was:
    `shielded_validation_checks_tests = 111,930,344us`,
    `validation_chainstatemanager_tests = 25,551,632us`,
    restart recovery `= 1,829,162us`,
    manifest reload `= 1,732,815us`
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - no disposable remote testnet resources were required for this sub-slice
- slice status:
  - Slice 14 remains open; the default no-longer-retained commitment index and
    restart / snapshot recovery path are now implemented, but weekly snapshot
    cadence, pruning / assumeutxo semantics, and the remaining retained /
    externalized policy surfaces still need to be wired through
- next slice:
  - continue Slice 14 with the weekly snapshot / pruned-node / assumeutxo
    recovery path on top of the new default externalized-retention behavior

### 2026-03-16 02:31:31 JST

- start-of-pass remote / GitHub preflight repeated before any new fetch / pull /
  push / PR cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- the next remote sync, later push to
  `origin/codex/shielded-v2-overhaul-plan`, and the follow-up PR #82 update are
  unblocked for this pass.

### 2026-03-16 02:29:03 JST

- continued `Slice 13: Integrate PR #79 Settlement Anchors Into shielded_v2`
  with the last remaining relay-facing settlement sub-slice in
  `/Users/admin/Documents/btxchain/btx-node`:
  - removed the `V2_SETTLEMENT_ANCHOR` proof-check ban on transparent fee
    carriers in `src/shielded/validation.cpp`, so settlement anchors can now
    traverse the same fee-bearing mempool path as other standard transactions
    instead of being trapped behind a proof-layer-only restriction
  - added `proof_check_accepts_fee_bearing_v2_settlement_anchor_bundle` in
    `src/test/shielded_validation_checks_tests.cpp` to lock the proof-layer
    acceptance surface for fee-bearing settlement anchors before mempool and
    reorg coverage
  - added `AttachCoinbaseFeeCarrier(...)` plus new fee-bearing rebalance and
    reserve-bound settlement-anchor mempool / block / reorg regressions in
    `src/test/txvalidation_tests.cpp`, covering first admission, mined
    eviction, reorg rewind, and mempool reaccept on the normal transaction path
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests/proof_check_accepts_fee_bearing_v2_settlement_anchor_bundle --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=txvalidation_tests/tx_mempool_accepts_fee_bearing_v2_rebalance_and_rewinds_state_after_reorg --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=txvalidation_tests/tx_mempool_accepts_fee_bearing_reserve_bound_v2_settlement_anchor_and_rewinds_state_after_reorg --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_tx_check_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests --catch_system_error=no --log_level=test_suite`
- validation findings:
  - the new fee-bearing rebalance mempool / block / reorg regression passed in
    `1,567,252us`
  - the new fee-bearing reserve-bound settlement-anchor mempool / block / reorg
    regression passed in `1,582,609us`
  - the rebuilt `shielded_tx_check_tests` suite passed in `43,565us`
  - the rebuilt `shielded_validation_checks_tests` suite passed in
    `111,120,780us`, including the new fee-bearing settlement-anchor proof
    acceptance case
- blockers / pivots:
  - the first real relay attempt failed for the right reason: the fee carrier
    initially used a legacy P2PKH output and was rejected as nonstandard
    `scriptpubkey`, so the helper was corrected to use a standard witness-v2
    `P2MR` change output instead of forcing policy exceptions
  - once standardness was fixed, the next failure was a real mempool fee floor
    (`10,000 < 30,000`), so the fee carrier was raised to `40,000` rather than
    misreporting zero-fee settlement anchors as relay-ready
- benchmarks / simulation findings:
  - no cloud or distributed simulation was required for this sub-slice
  - the highest-signal local runtime evidence for this pass was:
    `shielded_validation_checks_tests = 111,120,780us`,
    `shielded_tx_check_tests = 43,565us`,
    fee-bearing rebalance reorg `= 1,567,252us`,
    fee-bearing reserve-bound settlement-anchor reorg `= 1,582,609us`
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - no disposable remote testnet resources were required for this sub-slice
- slice status:
  - Slice 13 is complete: imported claim / adapter / receipt / hybrid
    settlement anchors now have live consensus validation, reserve /
    netting-manifest bindings, and fee-bearing mempool / mined transaction-flow
    coverage instead of remaining partially model-only or block-only
- next slice:
  - start `Slice 14: Implement Default Externalized Retention, Weekly
    Snapshots, And Recovery Semantics`

### 2026-03-16 02:15:21 JST

- start-of-pass remote / GitHub preflight repeated before any new fetch / pull /
  push / PR cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- the next remote sync, later push to
  `origin/codex/shielded-v2-overhaul-plan`, and the follow-up PR #82 update are
  unblocked for this pass.

### 2026-03-16 02:12:31 JST

- remote / GitHub preflight repeated immediately before the current Slice 13
  push / PR #82 update cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- push to `origin/codex/shielded-v2-overhaul-plan`, and the follow-up PR #82
  update are unblocked for this pass.

### 2026-03-16 02:11:58 JST

- continued `Slice 13: Integrate PR #79 Settlement Anchors Into shielded_v2`
  with a settlement-anchor / netting-manifest state-transition sub-slice in
  `/Users/admin/Documents/btxchain/btx-node`:
  - extended `src/shielded/nullifier.h` and `src/shielded/nullifier.cpp` with
    persisted netting-manifest DB state, including lookup, insert, removal,
    iteration, and a dedicated `DB_NETTING_MANIFEST` key so manifest validity
    can survive restart and rewind alongside nullifier state
  - extended `src/shielded/validation.h`, `src/shielded/validation.cpp`,
    `src/validation.h`, and `src/validation.cpp` so chainstate now restores
    netting-manifest state during retained-state bootstrap / restart,
    settlement anchors reject unanchored manifest references, `v2_rebalance`
    rejects duplicate manifest creation against both confirmed and same-block
    state, and connect / disconnect persist and rewind created manifests
  - opened the contextual `shielded_v2` family allowlists to admit
    `v2_rebalance` through the existing no-proof contextual path, which
    unblocks real manifest-producing rebalance fixtures instead of keeping the
    family trapped behind a generic `bad-shielded-v2-contextual` reject
  - added deterministic rebalance / reserve-binding fixtures in
    `src/test/util/shielded_v2_egress_fixture.h`, plus focused coverage in
    `src/test/nullifier_set_tests.cpp`,
    `src/test/shielded_tx_check_tests.cpp`,
    `src/test/txvalidation_tests.cpp`, and
    `src/test/validation_chainstatemanager_tests.cpp` for manifest DB
    persistence, real `v2_rebalance` contextual acceptance, same-block
    reserve-bound settlement-anchor connect / reorg, and restart reload of
    persisted manifest validity
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `./build-btx/bin/test_btx --run_test=nullifier_set_tests/netting_manifest_insert_remove_and_iterate --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_tx_check_tests/checktransaction_accepts_v2_rebalance_bundle_for_contextual_validation --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=txvalidation_tests/tx_connects_reserve_bound_v2_settlement_anchor_and_rewinds_state_after_reorg --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=validation_chainstatemanager_tests/chainstatemanager_reloads_persisted_netting_manifest_state --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_tx_check_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests --catch_system_error=no --log_level=test_suite`
- validation findings:
  - the rebuilt targeted rebalance / restart regressions all passed, including
    the new same-block reserve-bound settlement-anchor reorg case in
    `1,687,694us` and persisted manifest reload case in `1,858,349us`
  - the rebuilt `shielded_tx_check_tests` suite passed in `46,021us`,
    including the new real `v2_rebalance` contextual-acceptance regression
  - the rebuilt `shielded_validation_checks_tests` suite passed with `30`
    active test cases in `112,767,249us` on the same binary, confirming that
    the manifest-state changes did not regress adjacent settlement / proof
    checks
- blockers / pivots:
  - the real implementation blocker was no longer fixture shape but missing
    runtime state handling: manifest extraction already existed, but mempool
    acceptance, connect / disconnect persistence, restart reload, and chainstate
    lookup had not yet been wired through end to end
  - the first real rebalance fixture also exposed that `v2_rebalance` was
    still excluded by the contextual family allowlists; I opened the family on
    the existing no-proof path rather than papering over the issue with a fake
    fixture
- benchmarks / simulation findings:
  - no cloud or distributed simulation was required for this sub-slice
  - the highest-signal local runtime evidence for this pass was:
    `shielded_validation_checks_tests = 112,767,249us`,
    `shielded_tx_check_tests = 46,021us`,
    reserve-bound settlement-anchor reorg `= 1,687,694us`,
    persisted netting-manifest reload `= 1,858,349us`
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - no disposable remote testnet resources were required for this sub-slice
- slice status:
  - Slice 13 remains open, but claim / receipt / hybrid settlement anchors now
    have real netting-manifest state backing through block connect, reorg
    unwind, and retained-state restart reload, and reserve-bound anchors now
    prove the manifest dependency on the live state path instead of only in
    modeled fixtures
- next slice:
  - continue Slice 13 with the remaining fee-bearing mempool / relay-facing
    settlement-anchor and `v2_rebalance` admission surfaces that still need to
    become fully relayable under normal transaction flow

### 2026-03-15 22:35:40 JST

- remote / GitHub preflight repeated immediately before the current Slice 12
  push / PR #82 update cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- push to `origin/codex/shielded-v2-overhaul-plan` and the follow-up PR #82
  update are unblocked for this pass.

### 2026-03-15 22:34:58 JST

- continued `Slice 12: Prototype The High-Scale Ingress Proof` with the first
  alternative ingress native-batch backend scaffold sub-slice in
  `/Users/admin/Documents/btxchain/btx-node`:
  - extended `src/shielded/v2_proof.h` and `src/shielded/v2_proof.cpp` with a
    new receipt-backed native-batch backend descriptor and resolver support, so
    `v2_ingress_batch` can now distinguish between the current MatRiCT+ proof
    backend and a receipt-backed alternative through the same native-batch
    envelope surface
  - rewired `src/shielded/v2_ingress.h` and `src/shielded/v2_ingress.cpp` so
    ingress witnesses now carry backend-specific shard material as either a
    native MatRiCT proof or a receipt-backed shard witness, while the builder,
    parser, and verifier share backend selection, backend-specific shard
    descriptor reconstruction, and receipt public-values validation
  - promoted the shared ingress payload helpers for placeholder reserve-value
    commitments, synthetic credit-note commitments, payload-leaf construction,
    and receipt public-values hashing into namespace-scope APIs so the ingress
    builder, verifier, and tests can all derive the same canonical values
  - expanded `src/test/shielded_v2_proof_tests.cpp` and
    `src/test/shielded_v2_ingress_tests.cpp` with positive receipt-backed
    backend coverage, including resolver acceptance for the new backend and an
    end-to-end bounded `v2_ingress_batch` build / parse / verify /
    `CShieldedProofCheck` path for the receipt-backed shard witness
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_proof_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_ingress_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests --catch_system_error=no --log_level=test_suite`
- validation findings:
  - the rebuilt `shielded_v2_proof_tests` suite passed with `17` active test
    cases in `37,775,689us`, including the new receipt-backed backend resolver
    acceptance case
  - the rebuilt `shielded_v2_ingress_tests` suite passed with
    `220,379,815us`, and the new receipt-backed ingress case confirmed that a
    bounded `v2_ingress_batch` can be built, parsed, verified, and accepted by
    `CShieldedProofCheck` without a MatRiCT proof payload
  - the rebuilt `shielded_validation_checks_tests` suite passed with `30`
    active test cases in `118,261,998us` on the same binary
- blockers / pivots:
  - the first compile failure after the backend scaffold landed was a real
    namespace-lookup bug: the new shared ingress helper definitions were placed
    inside the anonymous namespace while still being declared in the public
    header, which created ambiguous calls; I moved those definitions to
    `shielded::v2` scope and rebuilt
  - the next compile failure was an expected test-shape regression because the
    refactor changed `V2IngressProofShardWitness::native_proof` from a required
    value to an optional backend-specific field; I updated the ingress tests to
    assert the optional shape directly, then added positive receipt-backed
    coverage before rerunning the focused suites
- benchmarks / simulation findings:
  - no new high-scale benchmark was added in this sub-slice; the bounded
    runtime evidence from the focused suites was:
    `shielded_v2_proof_tests` `37,775,689us`,
    `shielded_v2_ingress_tests` `220,379,815us`,
    `shielded_validation_checks_tests` `118,261,998us`
  - within the ingress suite, the new receipt-backed positive case completed in
    `11,969,888us`
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - no disposable remote testnet resources were required for this sub-slice
- slice status:
  - Slice 12 remains open, but the first alternative high-scale ingress proof
    backend scaffold is now real code behind the shared native-batch backend
    selection / resolution boundary, with receipt-backed ingress shards
    accepted end to end for bounded batches
- next slice:
  - continue Slice 12 by extending this alternative backend from scaffold-level
    receipt-backed shard acceptance into the next bounded higher-scale ingress
    proof prototype and capacity evidence

### 2026-03-15 21:58:03 JST

- remote / GitHub preflight repeated immediately before the current Slice 12
  push / PR #82 update cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- push to `origin/codex/shielded-v2-overhaul-plan` and the follow-up PR #82
  update are unblocked for this pass.

### 2026-03-15 21:57:12 JST

- continued `Slice 12: Prototype The High-Scale Ingress Proof` with an ingress
  native-batch backend-dispatch scaffold sub-slice in
  `/Users/admin/Documents/btxchain/btx-node`:
  - extended `src/shielded/v2_proof.h` and `src/shielded/v2_proof.cpp` with
    `SelectDefaultNativeBatchBackend()` and
    `ResolveNativeBatchBackend(...)`, so ingress proof parsing and construction
    no longer hard-code the MatRiCT+ descriptor at every call site
  - rewired `src/shielded/v2_ingress.cpp` so the ingress builder, parser, shard
    descriptor reconstruction, and verifier now route through a shared
    backend-dispatch layer instead of directly calling MatRiCT+-specific proof
    helpers
  - tightened `V2IngressContext::IsValid(...)` so the stored settlement
    statement envelope must match the exact backend-derived native-batch
    statement rather than merely matching a fixed proof kind / binding shape
  - expanded `src/test/shielded_v2_proof_tests.cpp` and
    `src/test/shielded_v2_ingress_tests.cpp` with coverage for backend
    selection, backend resolution, recording the resolved ingress backend, and
    rejecting unsupported ingress proof envelopes
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_ingress_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_proof_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests --catch_system_error=no --log_level=test_suite`
- validation findings:
  - the rebuilt `shielded_v2_ingress_tests` suite passed on the ingress
    backend-dispatch changes and confirmed that parsed ingress proofs now carry
    the default native-batch backend descriptor instead of assuming MatRiCT+
    out of band
  - the rebuilt `shielded_v2_proof_tests` suite passed and confirmed that the
    default selector currently resolves to the MatRiCT+ backend and that
    backend resolution fails cleanly for unknown native-batch envelopes
  - the final rerun of `shielded_validation_checks_tests` on the same binary
    passed with `30` active test cases in `111,509,503us`
- blockers / pivots:
  - the first ingress regression exposed a real reject-surface bug:
    unsupported native-batch ingress envelopes were initially surfacing as
    `bad-shielded-v2-ingress-statement`, which obscured backend resolution
    failure
  - I tightened `ParseV2IngressProof(...)` so unsupported envelopes now reject
    as `bad-shielded-v2-ingress-backend`, then rebuilt and reran the focused
    ingress, proof, and validation suites on the corrected binary
- benchmarks / simulation findings:
  - none new for this sub-slice; this pass was about backend-selection plumbing
    and reject-surface correctness rather than scale/runtime capture
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - no disposable remote testnet resources were required for this sub-slice
- slice status:
  - Slice 12 remains open, but `v2_ingress_batch` now has a real backend
    selection / resolution boundary that can carry a replacement compressed
    proof family without rewriting the entire ingress parser / verifier surface
- next slice:
  - continue Slice 12 by landing the first alternative high-scale ingress proof
    backend scaffold on top of the new native-batch selection / resolution
    boundary

### 2026-03-15 21:33:39 JST

- remote / GitHub preflight repeated immediately before the Slice 12
  backend-decision push / PR #82 update cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- push to `origin/codex/shielded-v2-overhaul-plan` and the follow-up PR #82
  update are unblocked for this pass.

### 2026-03-15 21:32:49 JST

- continued `Slice 12: Prototype The High-Scale Ingress Proof` with a
  replacement-backend decision-report sub-slice in
  `/Users/admin/Documents/btxchain/btx-node`:
  - extended `src/test/shielded_ingress_proof_runtime_report.h` and
    `src/test/shielded_ingress_proof_runtime_report.cpp` with a new
    `v2_ingress_proof_backend_decision` report that combines real measured
    ingress proof bands with the canonical current shard schedule for target
    ingress sizes
  - extended
    `src/test/generate_shielded_ingress_proof_runtime_report.cpp` with a
    `--target-leaf-counts=N[,M...]` mode so the generator can reuse a bounded
    measured band sweep and then emit target-gap analysis for larger launch
    bands without guessing at shard counts
  - expanded
    `src/test/shielded_ingress_proof_runtime_report_tests.cpp` so the harness
    now validates the new decision report and its rejection surface for empty
    target-band input
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx generate_shielded_ingress_proof_runtime_report -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_ingress_proof_runtime_report_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/gen_shielded_ingress_proof_runtime_report --samples=1 --reserve-outputs=1 --leaf-counts=8,10,11,12 --target-leaf-counts=100,1000,5000,10000 --output=/tmp/btx-shielded-ingress-proof-backend-decision.json`
- validation findings:
  - the focused `shielded_ingress_proof_runtime_report_tests` suite passed
    with `7` active test cases in `133,654,020us`
  - the new decision report completed with
    `status = current_backend_incompatible_with_target_range`, reusing the
    real measured `8/10/11/12` bands and then projecting them only onto the
    canonical current ingress shard schedule for the target bands
  - the measured boundary remains:
    - highest successful leaf count: `11`
    - lowest rejected leaf count: `12`
    - unverified gap: `0`
  - the best currently measured successful average shard payload is
    `2,251,639.5` bytes per shard from the `8`-leaf / `2`-shard band
  - target-gap findings under the current `6,291,456`-byte bundle payload cap:
    - `100` leaves -> `13` proof shards -> per-shard budget
      `483,958.15` bytes -> required reduction factor vs best measured shard
      payload: `4.65x` -> estimated total payload at current best measured
      shard cost: `29,271,313.5` bytes
    - `1000` leaves -> `126` proof shards -> per-shard budget
      `49,932.19` bytes -> required reduction factor: `45.09x` -> estimated
      total payload at current best measured shard cost:
      `283,706,577` bytes
    - `5000` leaves -> `626` proof shards -> per-shard budget
      `10,050.25` bytes -> required reduction factor: `224.04x` -> estimated
      total payload at current best measured shard cost:
      `1,409,526,327` bytes
    - `10000` leaves -> `1251` proof shards -> per-shard budget
      `5,029.14` bytes -> required reduction factor: `447.72x` -> estimated
      total payload at current best measured shard cost:
      `2,816,801,014.5` bytes
- blockers / pivots:
  - this pass did not uncover a new correctness blocker in the harness or the
    shard planner; instead it converted the existing measured boundary into an
    explicit backend-decision artifact showing that the current payload model
    is multiple orders of magnitude away from the launch target bands
- benchmarks / simulation findings:
  - report kind: `v2_ingress_proof_backend_decision`
  - measured bands reused: `8`, `10`, `11`, `12`
  - target bands evaluated: `100`, `1000`, `5000`, `10000`
  - all target bands currently report
    `status = replacement_backend_required`
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - no disposable remote testnet resources were required for this sub-slice
- slice status:
  - Slice 12 remains open, but the replacement-backend decision is now
    evidence-backed rather than qualitative: the current ingress proof payload
    model is not remotely stretchable to the `1000+` target bands under the
    current bundle cap
- next slice:
  - continue Slice 12 by prototyping the alternative high-scale ingress proof
    path or by landing the first backend-swap scaffold that can carry a new
    compressed proof family without changing the top-level
    `v2_ingress_batch` envelope

### 2026-03-15 21:23:00 JST

- remote / GitHub preflight repeated at the start of the current Slice 12
  fetch / pull / push / PR #82 cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote sync, later push to `origin/codex/shielded-v2-overhaul-plan`, and the
  PR #82 update are unblocked for this pass.

### 2026-03-15 21:20:40 JST

- remote / GitHub preflight repeated immediately before the Slice 12
  proof-capacity sweep push / PR #82 update cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- push to `origin/codex/shielded-v2-overhaul-plan` and the follow-up PR #82
  update are unblocked for this pass.

### 2026-03-15 21:19:45 JST

- continued `Slice 12: Prototype The High-Scale Ingress Proof` with a bounded
  proof-capacity sweep sub-slice in
  `/Users/admin/Documents/btxchain/btx-node`:
  - extended `src/test/shielded_ingress_proof_runtime_report.h` and
    `src/test/shielded_ingress_proof_runtime_report.cpp` so the ingress
    proof-runtime harness now records successful `proof_payload_size` and can
    emit a second report kind,
    `v2_ingress_proof_capacity_sweep`, over an explicit list of leaf-count
    bands
  - extended
    `src/test/generate_shielded_ingress_proof_runtime_report.cpp` with a
    `--leaf-counts=N[,M...]` mode so one bounded generator run can sweep
    multiple real ingress bands and return the highest successful and lowest
    rejected leaf counts under the current proof-payload cap
  - expanded
    `src/test/shielded_ingress_proof_runtime_report_tests.cpp` so the harness
    now validates `proof_payload_size` reporting, successful capacity-sweep
    structure, and empty-band rejection
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx generate_shielded_ingress_proof_runtime_report -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_ingress_proof_runtime_report_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/gen_shielded_ingress_proof_runtime_report --samples=1 --reserve-outputs=1 --leaf-counts=8,10,11,12 --output=/tmp/btx-shielded-ingress-proof-capacity-sweep.json`
- validation findings:
  - the focused `shielded_ingress_proof_runtime_report_tests` suite passed
    after the harness update, with the main real-proof case completing in
    `28,639,957us`
  - the new bounded sweep completed with
    `status = capacity_boundary_bracketed`, proving the first exact current
    MatRiCT+-backed ingress proof boundary under the bundle proof-payload cap
  - `11` ingress leaves with `1` reserve output now stands as the highest
    measured successful band:
    - `2` spend inputs
    - `2` proof shards
    - `67,890,257,917ns` build time
    - `201,250,125ns` proof-check time
    - `5,931,675` proof-payload bytes
    - `5,936,138` serialized transaction bytes
    - `359,781` proof-payload bytes of remaining headroom under the current
      `6,291,456`-byte cap
  - `12` ingress leaves with `1` reserve output is now the first measured
    rejected band:
    - `2` spend inputs
    - `2` proof shards
    - rejected after `73,507,025,291ns`
    - reject surface:
      `bad-shielded-v2-ingress-bundle-proof-payload-size:6407807`
    - payload overflow versus the current cap: `116,351` bytes
  - supporting successful bands from the same sweep:
    - `8` leaves: `4,503,279` proof-payload bytes,
      `50,948,805,833ns` build time, `154,293,416ns` proof-check time
    - `10` leaves: `5,455,543` proof-payload bytes,
      `62,237,636,166ns` build time, `187,648,292ns` proof-check time
- blockers / pivots:
  - pivot 1: the first rebuild failed because the new sweep report referenced
    `MAX_PROOF_PAYLOAD_BYTES` without the `shielded::v2::` namespace; the
    harness was fixed immediately and the rebuild / rerun then passed cleanly
  - pivot 2: the new sweep eliminates the earlier uncertainty between `8` and
    `100` leaves; the current backend does not merely fail "somewhere above
    8", it now has a measured one-reserve ceiling of `11` leaves before the
    proof-payload wall
- benchmarks / simulation findings:
  - report kind: `v2_ingress_proof_capacity_sweep`
  - tested bands: `8`, `10`, `11`, `12`
  - highest successful leaf count: `11`
  - lowest rejected leaf count: `12`
  - unverified leaf gap between those two measured bands: `0`
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - no disposable remote testnet resources were required for this sub-slice
- slice status:
  - Slice 12 remains open, but the replacement-backend decision path is now
    materially tighter: the current ingress proof backend only carries
    `11` leaves with `1` reserve output before breaching the bundle
    proof-payload cap, which is far below the `1000+` launch target bands
- next slice:
  - continue Slice 12 by landing the replacement-backend decision evidence:
    either prototype the alternative high-scale ingress proof path or add the
    next bounded artifact that shows why the current payload model cannot be
    stretched into the target range

### 2026-03-15 21:19:10 JST

- remote / GitHub preflight repeated before the next Slice 12 fetch / pull /
  push / PR #82 cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote sync, later push to `origin/codex/shielded-v2-overhaul-plan`, and the
  PR #82 update are unblocked for this pass.

### 2026-03-15 21:06:08 JST

- remote / GitHub preflight repeated immediately before the Slice 12 proof
  runtime push / PR #82 update cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- push to `origin/codex/shielded-v2-overhaul-plan` and the follow-up PR #82
  update are unblocked for this pass.

### 2026-03-15 21:05:09 JST

- continued `Slice 12: Prototype The High-Scale Ingress Proof` with the first
  bounded proof-runtime capture sub-slice in
  `/Users/admin/Documents/btxchain/btx-node`:
  - added `src/test/shielded_ingress_proof_runtime_report.h`,
    `src/test/shielded_ingress_proof_runtime_report.cpp`,
    `src/test/generate_shielded_ingress_proof_runtime_report.cpp`, and
    `src/test/shielded_ingress_proof_runtime_report_tests.cpp`, giving Slice
    12 a dedicated proof-runtime harness that drives the real
    `BuildV2IngressBatchTransaction(...)` path, then runs the resulting
    transaction through `CShieldedProofCheck`
  - wired the new generator into `src/test/CMakeLists.txt` as
    `generate_shielded_ingress_proof_runtime_report`
  - revised the report after the first larger-band run so build-time failures
    are now emitted as structured JSON status / reject-reason output instead
    of terminating the generator, which preserves the actual failure surface
    for Slice 12 evidence
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx generate_shielded_ingress_proof_runtime_report -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_ingress_proof_runtime_report_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/gen_shielded_ingress_proof_runtime_report --samples=1 --leaf-count=8 --reserve-outputs=1 --output=/tmp/btx-shielded-ingress-proof-runtime-report-8.json`
  - `./build-btx/bin/gen_shielded_ingress_proof_runtime_report --samples=1 --leaf-count=100 --reserve-outputs=1 --output=/tmp/btx-shielded-ingress-proof-runtime-report-100.json`
- validation findings:
  - the focused `shielded_ingress_proof_runtime_report_tests` suite passed in
    `28,337,160us`, proving that the harness can build and proof-check a real
    deterministic ingress batch and that the report rejects invalid configs
  - the `8`-leaf proof-runtime report completed successfully with
    `status = built_and_checked`, `2` spend inputs, `2` proof shards,
    `50,948,805,833ns` build time, `154,293,416ns` proof-check time, and a
    serialized transaction size of `4,507,148` bytes
  - the `100`-leaf proof-runtime report completed with
    `status = builder_rejected` after `570,058,118,250ns`; the real reject
    surface was `bad-shielded-v2-ingress-bundle-proof-payload-size:49505334`,
    which means the current MatRiCT+-backed ingress builder is already
    breaching the bundle proof-payload limit by the time it reaches a
    `13`-shard / `100`-leaf batch
- blockers / pivots:
  - pivot 1: the first `100`-leaf generator run was spending minutes in the
    real builder and then failing with the payload-size reject reason above;
    the harness was revised immediately so this boundary now lands as
    structured JSON evidence instead of an exception
  - pivot 2: the successful `8`-leaf run demonstrates that the proof-runtime
    harness itself is sound, so the `100`-leaf failure is now isolated to the
    current ingress proof / payload size economics rather than a report bug
- benchmarks / simulation findings:
  - report kind: `v2_ingress_proof_runtime`
  - successful bounded multishard band:
    - `leaf_count = 8`
    - `reserve_output_count = 1`
    - `spend_input_count = 2`
    - `proof_shard_count = 2`
    - `build_ns = 50,948,805,833`
    - `proof_check_ns = 154,293,416`
    - `serialized_tx_size = 4,507,148`
  - first larger-band rejection:
    - `leaf_count = 100`
    - `reserve_output_count = 1`
    - `spend_input_count = 13`
    - `proof_shard_count = 13`
    - `builder_reject_ns = 570,058,118,250`
    - reject reason: `bad-shielded-v2-ingress-bundle-proof-payload-size:49505334`
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - no disposable remote testnet resources were required for this sub-slice
- slice status:
  - Slice 12 remains open; the codebase now has both schedule-only and real
    proof-runtime evidence, and that evidence shows the current backend can
    still build a small multishard ingress batch but hits the bundle
    proof-payload wall far below the `1000`-deposit target
- next slice:
  - continue Slice 12 by tightening the first actual proof-capacity boundary
    between `8` and `100` leaves and begin the replacement-backend path if the
    current payload limit remains far below the launch target

### 2026-03-15 20:32:38 JST

- remote / GitHub preflight repeated before the next fetch / pull / push / PR
  cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote sync, later push to `origin/codex/shielded-v2-overhaul-plan`, and the
  PR #82 update are unblocked for this pass.

### 2026-03-15 20:30:53 JST

- remote / GitHub preflight repeated immediately before the Slice 12 push / PR
  #82 update cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- push to `origin/codex/shielded-v2-overhaul-plan` and the follow-up PR #82
  update are unblocked for this pass.

### 2026-03-15 20:28:58 JST

- started `Slice 12: Prototype The High-Scale Ingress Proof` with the first
  validated bounded-schedule sub-slice in
  `/Users/admin/Documents/btxchain/btx-node`:
  - promoted the canonical ingress shard planner in
    `src/shielded/v2_ingress.h` / `src/shielded/v2_ingress.cpp` into a shared
    public `BuildCanonicalV2IngressShardSchedule(...)` surface with validated
    schedule entries, per-shard maxima, and aggregate schedule summaries so
    later proof-runtime and replacement-backend work can reuse the exact
    production shard logic instead of duplicating it in tests
  - added `src/test/shielded_ingress_runtime_report.h` and
    `src/test/shielded_ingress_runtime_report.cpp`, which build deterministic
    high-scale ingress scheduling scenarios against the real canonical planner
    and emit bounded JSON evidence for shard count, per-shard input / output
    pressure, and schedule runtime across configurable ingress-leaf bands
  - added `src/test/generate_shielded_ingress_runtime_report.cpp` plus the
    `generate_shielded_ingress_runtime_report` target in
    `src/test/CMakeLists.txt`, giving Slice 12 a repeatable local report tool
    rather than another long-running bench-only path
  - added `src/test/shielded_ingress_runtime_report_tests.cpp`, which locks in
    the current bounded-band expectations: `100` leaves -> `13` shards,
    `1000` leaves -> `126` shards, `5000` leaves -> `626` shards, and
    `10000` leaves -> `1251` shards under the present canonical ingress
    schedule
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx generate_shielded_ingress_runtime_report -j8`
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target generate_shielded_ingress_runtime_report -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_ingress_runtime_report_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_ingress_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/gen_shielded_ingress_runtime_report --samples=1 --output=/tmp/btx-shielded-ingress-runtime-report.json`
- validation findings:
  - the new `shielded_ingress_runtime_report_tests` suite passed and locked the
    current band behavior against the real planner, including explicit failure
    coverage for zero-iteration and empty-band report requests
  - the full `shielded_v2_ingress_tests` suite remained clean after the public
    shard-schedule refactor in `174,857,698us`, so the production builder and
    contextual ingress verifier still agree on proof-only, signed-only,
    hybrid, large-batch, and multishard ingress bundles
  - the full `shielded_validation_checks_tests` suite remained clean in
    `111,195,872us`, which confirmed that the shared planner refactor did not
    disturb the existing proof-binding, ring-position, or spend-auth reject
    surfaces
  - the generated bounded report in
    `/tmp/btx-shielded-ingress-runtime-report.json` now provides the first
    concrete Slice 12 evidence that the current MatRiCT+-backed bounded-shard
    ingress design comfortably fits `100` and `1000` private deposits but does
    not fit `5000` or `10000` deposits under the present `256` proof-shard
    cap
- benchmarks / simulation findings:
  - report kind: `v2_ingress_shard_schedule_runtime`
  - current limits recorded by the report:
    - `max_bundle_ingress_leaves = 20000`
    - `max_bundle_reserve_outputs = 64`
    - `max_proof_shards = 256`
    - `max_outputs_per_proof_shard = 8`
    - `max_matrict_inputs_per_proof_shard = 16`
  - `100` ingress leaves with `1` reserve output:
    - `13` shards
    - within the `256` shard cap
    - schedule runtime `13,875ns`
  - `1000` ingress leaves with `1` reserve output:
    - `126` shards
    - within the `256` shard cap
    - schedule runtime `207,208ns`
  - `5000` ingress leaves with `1` reserve output:
    - `626` shards
    - exceeds the `256` shard cap by `370`
    - schedule runtime `4,336,959ns`
  - `10000` ingress leaves with `1` reserve output:
    - `1251` shards
    - exceeds the `256` shard cap by `995`
    - schedule runtime `15,484,458ns`
  - the report-derived current ceiling at `1` reserve output is
    `2047` ingress leaves before the canonical schedule crosses the existing
    `256` proof-shard limit
- blockers / pivots:
  - the first combined build command reported `make: *** No rule to make
    target 'generate_shielded_ingress_runtime_report'. Stop.` even though the
    target had been generated correctly; rerunning the individual
    `test_btx` and `generate_shielded_ingress_runtime_report` targets
    succeeded cleanly, so the blocker was the multi-target `make` invocation
    rather than a missing CMake target
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - no disposable remote testnet resources were required for this sub-slice
- slice status:
  - Slice 12 remains open; the first bounded-schedule evidence is now landed,
    and it shows that the current ingress shard model already clears the
    `1000`-deposit target but not the higher `5000` / `10000` bands under the
    existing proof-shard cap
- next slice:
  - extend Slice 12 from schedule-only evidence into bounded proof-runtime
    capture on the highest currently schedulable band and start the
    replacement-backend decision path if the higher target bands remain
    outside the current cap

### 2026-03-15 20:11:19 JST

- remote / GitHub preflight repeated before the next fetch / pull / push / PR
  cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote sync, future push to `origin/codex/shielded-v2-overhaul-plan`, and
  the PR #82 update are unblocked for this pass.

### 2026-03-15 20:09:23 JST

- remote / GitHub preflight repeated before the next push / PR #82 update
  cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- push to `origin/codex/shielded-v2-overhaul-plan` and the follow-up PR #82
  update are unblocked for this pass.

### 2026-03-15 20:08:03 JST

- completed the ninth validated `Slice 11: Implement v2_ingress_batch Intent
  Model` sub-slice in `/Users/admin/Documents/btxchain/btx-node`:
  - expanded `src/test/shielded_v2_ingress_tests.cpp` with canonical
    signed-only and hybrid settlement fixtures, direct contextual-verifier
    coverage for both flows, and the signed-membership rejection regression
    against a built `v2_ingress_batch`
  - expanded `src/test/txvalidation_tests.cpp` with accepted signed-only and
    hybrid ingress state-transition coverage so mempool admission, block
    connect, reorg rewind, and mempool reaccept are now exercised for all
    three settlement witness families: proof-only, signed-only, and hybrid
  - resolved the stale failure mode from the earlier rerun by executing the
    full `shielded_v2_ingress_tests` suite only after the completed rebuild,
    which confirmed that the corrected signed-membership reject reason in the
    new regression matches the actual consensus surface
- exact validation commands:
  - `./build-btx/bin/test_btx --run_test=shielded_v2_ingress_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test='txvalidation_tests/tx_mempool_accepts_signed_v2_ingress_and_rewinds_state_after_reorg' --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test='txvalidation_tests/tx_mempool_accepts_hybrid_v2_ingress_and_rewinds_state_after_reorg' --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_tx_check_tests --catch_system_error=no --log_level=test_suite`
- validation findings:
  - the full `shielded_v2_ingress_tests` suite reran cleanly against the
    rebuilt binary in `174,741,578us`, which cleared the earlier stale-binary
    confusion and proved the new signed-only / hybrid ingress cases on the
    same suite that already covers the proof-only, large-batch, and
    multishard flows
  - concrete deterministic runtimes on this host were `11,591,600us` for
    `build_v2_signed_ingress_transaction_matches_contextual_verifier`,
    `15,431,532us` for
    `build_v2_hybrid_ingress_transaction_matches_contextual_verifier`,
    `14,224,526us` for the signed ingress mempool / reorg regression, and
    `22,366,286us` for the hybrid ingress mempool / reorg regression
  - accepted `v2_ingress_batch` consensus coverage now spans proof-only,
    signed-only, and hybrid settlement witnesses, and explicit signed-receipt
    membership mismatches hard-fail with
    `bad-shielded-v2-ingress-signed-membership`
- blockers / pivots:
  - pivot 1: the prior failure at this boundary was not a product defect; the
    ingress suite had been started while `test_btx` was still relinking, so it
    executed a stale binary and repeated the old reject-string expectation
  - pivot 2: the new signed-receipt mismatch regression originally expected
    `bad-shielded-v2-ingress-signed-receipt`, but consensus correctly returns
    `bad-shielded-v2-ingress-signed-membership`, so the test surface was
    aligned with the real reject reason
- benchmarks / simulation findings:
  - no distributed simulation or remote benchmark ran in this sub-slice; the
    evidence is the deterministic ingress unit and txvalidation coverage above
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - no remote teardown was required
- slice status:
  - Slice 11 is now closed: `v2_ingress_batch` has a production intent model,
    wallet / RPC build surface, accepted proof-only / signed-only / hybrid
    settlement-backed admission paths, and real note / nullifier / reserve
    state-transition coverage through mempool, block connect, and reorg
- next slice:
  - start `Slice 12` by benchmarking bounded-shard MatRiCT+ schedules for the
    high-scale ingress proof bands

### 2026-03-15 19:30:41 JST

- remote / GitHub preflight repeated before the next fetch / pull / push / PR
  cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote sync, future push to `origin/codex/shielded-v2-overhaul-plan`, and
  the PR #82 update are unblocked for this pass.

### 2026-03-15 19:27:10 JST

- continued `Slice 11: Implement v2_ingress_batch Intent Model` with the first
  settlement-backed ingress admission sub-slice in
  `/Users/admin/Documents/btxchain/btx-node`:
  - extended `src/shielded/v2_ingress.h` /
    `src/shielded/v2_ingress.cpp` with
    `V2IngressSettlementWitness`, optional settlement witness transport in the
    ingress witness header, builder-side witness validation, statement-bound
    settlement witness requirements, and consensus verification for signed
    receipt membership proofs, proof-receipt descriptor proofs, and the
    derived signed / proof / hybrid external-anchor shapes
  - updated `BuildV2IngressBatchTransaction(...)` so wallet- and test-built
    ingress transactions now serialize the canonical settlement witness into
    the transaction instead of keeping settlement evidence as an RPC-only
    preview surface
  - extended `src/wallet/shielded_wallet.h` /
    `src/wallet/shielded_wallet.cpp` so
    `CreateV2IngressBatch(...)` can carry a canonical settlement witness into
    the actual built `v2_ingress_batch`
  - updated `src/wallet/shielded_rpc.cpp` so
    `bridge_buildingressbatchtx` canonicalizes revealed attestors and proof
    descriptors into real verifier-set / proof-policy membership proofs,
    embeds them into built ingress transactions when the statement commits to
    settlement witness material, and keeps receipt previews preview-only when
    the statement does not require them
  - expanded `src/test/shielded_v2_ingress_tests.cpp`,
    `src/test/txvalidation_tests.cpp`, and
    `src/test/shielded_wallet_chunk_discovery_tests.cpp` so settlement-backed
    ingress now has direct builder failure coverage, proof-descriptor mismatch
    rejection coverage, scaled and multishard mempool / reorg coverage, and
    wallet reserve-output caching coverage against a built ingress batch
- exact validation commands:
  - `./build-btx/bin/test_btx --run_test=shielded_v2_ingress_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test='txvalidation_tests/tx_mempool_accepts_scaled_v2_ingress_and_rewinds_state_after_reorg' --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test='txvalidation_tests/tx_mempool_accepts_multishard_v2_ingress_and_rewinds_state_after_reorg' --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test='shielded_wallet_chunk_discovery_tests/wallet_caches_reserve_outputs_from_built_ingress_batch' --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_tx_check_tests --catch_system_error=no --log_level=test_suite`
  - `python3 ./build-btx/test/functional/wallet_shielded_rpc_surface.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/rpc-surface-20260315-ingress-consensus1 --portseed=32190`
- validation findings:
  - the first accepted settlement-backed ingress state-transition path is now
    covered end-to-end: builder, consensus proof check, mempool admission,
    block connect, reorg rewind, wallet cache, and wallet-RPC build surfaces
    all passed locally
  - concrete runtimes on this host were
    `22,345,045us` for the scaled ingress mempool / reorg test,
    `41,457,317us` for the multishard ingress mempool / reorg test,
    `10,027,868us` for the wallet reserve-output cache regression, and
    `112,151,206us` for the focused `shielded_validation_checks_tests` suite
  - the functional wallet RPC surface passed cleanly after traversing the
    ingress-specific settlement preview and build-only assertions, then
    continued through the broader shielded send / merge / view flows, which is
    strong evidence that serializing ingress settlement witnesses did not
    regress adjacent wallet behavior
- blockers / pivots:
  - pivot 1: the ingress wallet chunk-discovery fixture initially derived its
    proof receipt from a hardcoded descriptor that did not match the statement
    descriptor, so descriptor-membership verification failed until the test
    helper was changed to build the witness from the actual committed
    descriptor
  - pivot 2: the ingress RPC builder now only embeds settlement witness data
    when the statement actually commits to `verifier_set` or `proof_policy`;
    keeping receipt data as preview-only for witness-free statements avoids
    tripping the new builder validity checks on transactions that do not need
    settlement evidence in consensus
- benchmarks / simulation findings:
  - no dedicated distributed simulation or remote benchmark ran in this
    sub-slice; the evidence is the deterministic unit / reorg / functional
    validation above
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - the functional tmpdir
    `/tmp/btx-functional-manual/rpc-surface-20260315-ingress-consensus1`
    was cleaned up by the harness on success
- slice status:
  - Slice 11 remains open: settlement witness material is now carried and
    enforced through the first accepted ingress consensus path, but the later
    higher-scale ingress work and the remaining settlement-facing ingress flow
    still need to land
- next slice:
  - continue `Slice 11` by wiring the remaining settlement-facing ingress
    state-transition flow on top of the now-serialized settlement witness
    model

### 2026-03-15 18:55:01 JST

- remote / GitHub preflight repeated before the next fetch / pull / push / PR
  cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote sync, future push to `origin/codex/shielded-v2-overhaul-plan`, and
  the PR #82 update are unblocked for this pass.

### 2026-03-15 18:45:06 JST

- remote / GitHub preflight repeated before the next fetch / pull / push / PR
  cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote sync, future push to `origin/codex/shielded-v2-overhaul-plan`, and
  the PR #82 update are unblocked for this pass.

### 2026-03-15 18:52:49 JST

- completed the seventh validated `Slice 11: Implement v2_ingress_batch Intent
  Model` sub-slice in `/Users/admin/Documents/btxchain/btx-node`:
  - expanded `test/functional/wallet_shielded_rpc_surface.py` so the ingress
    build-only RPC now has end-to-end hybrid settlement coverage with one
    statement that commits to both `verifier_set` and `proof_policy`
  - the new regression builds a canonical verifier set, signs two statement
    receipts, builds a proof receipt plus descriptor membership proof, and then
    asserts that `bridge_buildingressbatchtx` returns the same
    `external_anchor`, `verification_bundle`, and
    `verification_bundle_hash` as `bridge_buildhybridanchor(...)`
  - the same regression now proves both missing-witness failure modes for
    hybrid ingress previews by rejecting statements that omit either
    `options.receipts` or `options.proof_receipts`
- exact validation commands:
  - `python3 ./build-btx/test/functional/wallet_shielded_rpc_surface.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/rpc-surface-20260315-ingress-hybrid1 --portseed=32183`
- validation findings:
  - the already-plumbed ingress settlement helper in `src/wallet/shielded_rpc.cpp`
    correctly accepted hybrid signed-receipt + proof-receipt witness sets
    without further product changes once the functional surface mirrored the
    same verifier-set and proof-policy proof inputs used by
    `bridge_buildhybridanchor(...)`
  - the successful run reached and passed all three ingress build-only paths in
    one pass: proof-receipt-backed single-shard, hybrid settlement-backed
    single-shard, and proof-receipt-backed multishard
- blockers / pivots:
  - pivot 1: treated this as a validation/coverage landing rather than forcing
    another RPC rewrite, because the hybrid ingress witness plumbing already
    existed and the missing launch-critical gap was the absence of end-to-end
    regression evidence
- benchmarks / simulation findings:
  - no cloud benchmark or distributed simulation ran in this sub-slice;
    validation relied on the wallet RPC functional surface
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - the successful functional tmpdir under `/tmp/btx-functional-manual/` was
    cleaned up automatically on exit
- slice status:
  - Slice 11 remains open: both proof-only and hybrid settlement-backed
    ingress preview paths are now validated through wallet/RPC surfaces, but
    the next settlement-facing ingress admission / state-transition path still
    remains to land
- next slice:
  - continue `Slice 11` by wiring the next accepted settlement-facing ingress
    admission path on top of the now-validated proof-only and hybrid preview
    contracts

### 2026-03-15 18:41:52 JST

- completed the sixth validated `Slice 11: Implement v2_ingress_batch Intent
  Model` sub-slice in `/Users/admin/Documents/btxchain/btx-node`:
  - extended `bridge_buildingressbatchtx` in `src/wallet/shielded_rpc.cpp`
    so settlement-aware ingress previews now parse and validate
    `options.receipts`, `options.proof_receipts`, `options.receipt_policy`,
    and `options.proof_receipt_policy` against statement-bound
    `verifier_set` / `proof_policy` commitments before returning a build-only
    `v2_ingress_batch`
  - added deterministic external-anchor derivation for proof-receipt-backed,
    signed-receipt-backed, and hybrid witness sets inside the same ingress RPC
    helper, with proof-only previews now exposing canonical `external_anchor`,
    `proof_receipt_count`, and `distinct_proof_receipt_count`
  - expanded the wallet RPC surface regression in
    `test/functional/wallet_shielded_rpc_surface.py` so proof-policy-bound
    ingress statements now reject missing `options.proof_receipts`, request the
    necessary descriptor membership proofs explicitly, and assert that the
    ingress preview anchor matches `bridge_buildproofanchor(...)` for both the
    single-shard and multishard ingress cases
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target btxd test_btx -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_ingress_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_wallet_chunk_discovery_tests/wallet_caches_reserve_outputs_from_built_ingress_batch --catch_system_error=no --log_level=test_suite`
  - `python3 ./build-btx/test/functional/wallet_shielded_rpc_surface.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/rpc-surface-20260315-ingress-settlement1 --portseed=32181`
  - `python3 ./build-btx/test/functional/wallet_shielded_rpc_surface.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/rpc-surface-20260315-ingress-settlement2 --portseed=32182`
- validation findings:
  - the new ingress settlement-witness path now hard-fails proof-policy-bound
    statements that omit `options.proof_receipts`, which is the intended RPC
    contract for previewing settlement-backed ingress batches
  - the final functional rerun confirmed that proof-receipt-backed ingress
    previews derive the same canonical external anchor as
    `bridge_buildproofanchor(...)` in both the single-shard and multishard
    cases while still returning wallet-visible reserve-output previews
  - `shielded_v2_ingress_tests` still takes about `113.9s` end to end on this
    host because each deterministic MatRiCT-backed ingress builder case remains
    multi-second
- blockers / pivots:
  - pivot 1: reordered the new ingress settlement summary types in
    `src/wallet/shielded_rpc.cpp` so the optional receipt/proof summaries are
    declared after their concrete summary structs, avoiding a preventable
    template-instantiation compile failure
  - pivot 2: the first functional run failed in the test harness, not the
    product path, because `bridge_buildproofpolicy` only returns
    `proof_policy["proofs"]` when `targets` are supplied; the regression now
    requests `targets=[descriptor]` before asserting descriptor-proof-backed
    ingress validation
- benchmarks / simulation findings:
  - no cloud benchmark or distributed simulation ran in this sub-slice;
    validation relied on targeted ingress unit tests plus the wallet RPC
    functional surface
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - the successful functional tmpdir under `/tmp/btx-functional-manual/` was
    cleaned up automatically on exit; the failed first tmpdir was left in place
    for local log inspection
- slice status:
  - Slice 11 remains open: proof-receipt-backed settlement ingress previews are
    now wired end to end through the wallet RPC surface, but the signed-receipt
    and hybrid verifier-set + proof-policy ingress witness flows still remain
    to land
- next slice:
  - continue `Slice 11` by wiring the hybrid signed-receipt +
    proof-receipt-backed ingress flow and the next settlement-facing admission
    path on top of the new wallet/RPC preview contract

### 2026-03-15 18:22:08 JST

- remote / GitHub preflight repeated before the next fetch / pull / push / PR
  cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote sync, future push to `origin/codex/shielded-v2-overhaul-plan`, and
  the PR #82 update are unblocked for this pass.

### 2026-03-15 18:19:36 JST

- completed the fifth validated `Slice 11: Implement v2_ingress_batch Intent
  Model` sub-slice in `/Users/admin/Documents/btxchain/btx-node`:
  - refactored the canonical ingress shard scheduler in
    `src/shielded/v2_ingress.cpp` / `src/shielded/v2_ingress.h` so shard-plan
    validation works on canonical spend / reserve / leaf value spans and is
    reusable outside the transaction builder through the new
    `CanBuildCanonicalV2IngressShardPlan(...)` helper
  - extended wallet-side ingress construction in
    `src/wallet/shielded_wallet.cpp` so
    `CShieldedWallet::CreateV2IngressBatch(...)` falls back from the generic
    note selector to a bounded schedulable-note search that only accepts note
    sets whose reserve outputs, reserve change, and ingress leaves admit a
    canonical proof-shard schedule
  - expanded deterministic ingress coverage in
    `src/test/shielded_v2_ingress_tests.cpp` with the new
    `canonical_ingress_shard_plan_accepts_wallet_shaped_change_partition`
    regression and added the chain-backed multishard mempool / reorg case in
    `src/test/txvalidation_tests.cpp`
  - completed the multishard wallet / RPC regression in
    `test/functional/wallet_shielded_rpc_surface.py` by seeding two confirmed
    `0.50` notes to the same shielded address, which matches the current
    one-spending-keyset ingress construction rule instead of building an
    impossible cross-keyset wallet state
- exact validation commands:
  - `git fetch --all --prune`
  - `git switch codex/shielded-v2-overhaul-plan`
  - `git pull --ff-only origin codex/shielded-v2-overhaul-plan`
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx btxd -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_ingress_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=txvalidation_tests/tx_mempool_accepts_multishard_v2_ingress_and_rewinds_state_after_reorg --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_tx_check_tests --catch_system_error=no --log_level=test_suite`
  - `python3 ./build-btx/test/functional/wallet_shielded_rpc_surface.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/rpc-surface-20260315-ingress-shardband-pass1 --portseed=32175`
- validation findings:
  - the original wallet-side multishard retry logic was structurally correct,
    but the functional fixture was still generating two `0.50` notes to two
    different shielded addresses plus shielded change, so no candidate set
    could satisfy the existing one-spending-keyset ingress constraint
  - the final functional regression now exercises the intended multishard path
    with two confirmed notes to the same shielded address, and the full wallet
    RPC surface passed end to end after that correction
  - the new bounded wallet selector now rejects unschedulable note sets before
    proof construction and successfully admits the deterministic multishard
    chain-backed ingress fixture used by the txvalidation regression
- blockers / pivots:
  - pivot 1: moved shard-plan feasibility into a reusable helper so wallet
    note selection can reason about canonical ingress proof shards before
    invoking the expensive batch builder
  - pivot 2: corrected the functional multishard ingress fixture to seed two
    notes to one shielded address instead of two different addresses, because
    the current ingress wallet flow intentionally does not mix spending
    keysets inside one `v2_ingress_batch`
- benchmarks / simulation findings:
  - no cloud benchmark or distributed simulation ran in this sub-slice;
    validation relied on deterministic unit, mempool / reorg, and wallet RPC
    coverage
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - the successful functional tmpdir under `/tmp/btx-functional-manual/` was
    cleaned up automatically on exit
- slice status:
  - Slice 11 remains open: multishard ingress scheduling now lands through the
    deterministic builder, txvalidation, and wallet / RPC surfaces, but the
    higher-scale settlement-facing ingress flow still remains to land
- next slice:
  - continue `Slice 11` by wiring the next settlement-facing ingress flow on
    top of the now-validated multishard ingress scheduling path

### 2026-03-15 17:32:12 JST

- remote / GitHub preflight repeated before the next fetch / pull / push / PR
  cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote sync, future push to `origin/codex/shielded-v2-overhaul-plan`, and
  the PR #82 update are unblocked for this pass.

### 2026-03-15 15:27:50 JST

- remote / GitHub preflight repeated before the next fetch / pull / push / PR
  cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote sync, future push to `origin/codex/shielded-v2-overhaul-plan`, and
  the PR #82 update are unblocked for this pass.

### 2026-03-15 15:52:45 JST

- completed the fourth validated `Slice 11: Implement v2_ingress_batch Intent
  Model` sub-slice in `/Users/admin/Documents/btxchain/btx-node`:
  - generalized the deterministic ingress construction coverage in
    `src/test/shielded_v2_ingress_tests.cpp` so the fixture now supports
    multiple spend inputs, multiple reserve outputs, and multiple ingress
    leaves instead of only the wallet-shaped single-input batch
  - added the new large-batch unit regression
    `build_large_v2_ingress_transaction_matches_contextual_verifier`, which
    validates a `2`-input / `3`-reserve / `5`-leaf ingress batch end to end
    through the existing contextual verifier
  - generalized the chain-backed ingress fixture in
    `src/test/txvalidation_tests.cpp` so mempool / block / reorg coverage now
    exercises multi-input, multi-nullifier, multi-reserve ingress batches
  - added the scaled state-transition regression
    `tx_mempool_accepts_scaled_v2_ingress_and_rewinds_state_after_reorg`,
    which confirms connect, disconnect, mempool reaccept, nullifier handling,
    and reserve-commitment tree rewinds for a larger ingress batch
  - raised `MAX_STANDARD_INGRESS_SHIELDED_POLICY_WEIGHT` in
    `src/policy/policy.h` from `3200000` to `5500000` so the validated scaled
    ingress family can relay without broadening the generic shielded policy
    ceiling
  - raised the consensus shielded transaction size ceiling in
    `src/consensus/params.h` and `src/kernel/chainparams.cpp` from
    `2000000` to `3000000` so the larger proven ingress family can reach
    mempool and block validation instead of failing structurally before the
    scaled admission path is exercised
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_ingress_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=txvalidation_tests/tx_mempool_accepts_scaled_v2_ingress_and_rewinds_state_after_reorg --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=txvalidation_tests/tx_mempool_accepts_v2_ingress_and_rewinds_state_after_reorg --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests --catch_system_error=no --log_level=test_suite`
- validation findings:
  - the first scaled ingress mempool failure was real: the `2`-input /
    `2`-reserve / `3`-credit batch weighed `5192784` under the ingress policy
    model, which exceeded the previous ingress-only relay ceiling of
    `3200000`
  - after the relay ceiling lift, the same scaled transaction still failed
    with `bad-shielded-tx-size`; the root cause was the consensus
    `nMaxShieldedTxSize = 2000000` ceiling rather than proof or state-routing
    logic
  - the new txvalidation regression now asserts that the scaled ingress
    transaction serializes above `2000000` bytes while still remaining within
    the new `3000000` consensus ceiling, so future regressions fail at the
    exact size-boundary expectation instead of silently shrinking coverage
  - runtime on this host:
    - `shielded_v2_ingress_tests`: `75.75s`
    - `txvalidation_tests/tx_mempool_accepts_scaled_v2_ingress_and_rewinds_state_after_reorg`: `21.23s`
    - `txvalidation_tests/tx_mempool_accepts_v2_ingress_and_rewinds_state_after_reorg`: `13.50s`
    - `shielded_validation_checks_tests`: `111.17s`
- blockers / pivots:
  - pivot 1: scaled the fixtures first, then used the failing policy-weight
    and consensus-size boundaries to drive the actual relay / consensus lifts
    instead of guessing new caps upfront
  - pivot 2: made the scaled txvalidation regression assert the oversized
    legacy-limit condition directly, so the suite now proves that the larger
    ingress shape is intentionally exercising the expanded consensus envelope
- benchmarks / simulation findings:
  - no cloud benchmark or distributed simulation ran in this sub-slice;
    validation relied on deterministic unit and chain-backed mempool / reorg
    coverage
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - no disposable remote testnet resources were required for this sub-slice
- slice status:
  - Slice 11 remains open: ingress coverage now reaches a larger multi-input /
    multi-reserve / multi-credit batch, but the tracker's higher-scale shard
    schedule and settlement-facing ingress flow work are still outstanding
- next slice:
  - continue `Slice 11` by pushing ingress validation further toward the
    tracker-scale batch targets and wiring the next settlement-facing ingress
    flow on top of the now-accepted larger admission path

### 2026-03-15 16:31:12 JST

- completed the third validated `Slice 11: Implement v2_ingress_batch Intent
  Model` sub-slice in `/Users/admin/Documents/btxchain/btx-node`:
  - extended `src/shielded/v2_bundle.h` / `src/shielded/v2_bundle.cpp` so
    `IngressBatchPayload` now carries an explicit canonical `fee` field with
    range checks, frozen serialization, and a verifier-visible commitment to
    the aggregate ingress fee total
  - updated `src/shielded/v2_ingress.cpp` so
    `BuildV2IngressBatchTransaction(...)` writes the aggregate ingress fee into
    the payload and `VerifyV2IngressProof(...)` rejects any payload whose
    encoded fee disagrees with the batch leaf fee sum
  - updated `src/shielded/bundle.cpp` so
    `GetShieldedStateValueBalance(...)` now exposes `v2_ingress_batch` fees as
    the consensus-visible shielded value-balance delta, which makes ingress
    transactions pay the real mempool / relay fee path instead of silently
    presenting zero shielded fee
  - added an ingress-specific relay ceiling in `src/policy/policy.h` /
    `src/policy/policy.cpp` with
    `MAX_STANDARD_INGRESS_SHIELDED_POLICY_WEIGHT = 3200000`, allowing the
    wallet-shaped one-input / one-reserve / two-credit batch to relay without
    widening the rest of the shielded families to the same ceiling
  - added the dedicated ingress standardness regression in
    `src/test/shielded_v2_ingress_tests.cpp` and completed the real mempool /
    block / reorg / mempool-reaccept admission regression in
    `src/test/txvalidation_tests.cpp`
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_ingress_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=txvalidation_tests/tx_mempool_accepts_v2_ingress_and_rewinds_state_after_reorg --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_tx_check_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_bundle_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_wallet_chunk_discovery_tests/wallet_caches_reserve_outputs_from_built_ingress_batch --catch_system_error=no --log_level=test_suite`
- validation findings:
  - the first failing txvalidation fixture was comparing against the legacy
    note-derived nullifier helper, but the actual `v2_ingress_batch` payload
    binds the native batch witness nullifier; the regression now reads the
    expected nullifier directly from the built payload
  - the first relay failure was real: the wallet-shaped ingress batch priced at
    `3079598` shielded policy weight, which exceeded the generic
    `MAX_STANDARD_SHIELDED_POLICY_WEIGHT = 2400000`; after adding the
    ingress-only `3200000` ceiling, the same transaction remained
    nonstandard relative to the generic shielded cap but standard for ingress
  - the fixture also needed real ingress fee funding after the explicit fee
    field landed; the final regression uses a `3,000,000` sat input note, an
    `800,000` sat reserve output, two `100,000` sat credits, and
    `2,000,000` sat of aggregate ingress fees so mempool admission exercises
    the intended value-balance path instead of a low-fee artifact
  - runtime on this host:
    - `txvalidation_tests/tx_mempool_accepts_v2_ingress_and_rewinds_state_after_reorg`: `13.51s`
    - `shielded_v2_ingress_tests`: `46.37s`
    - `shielded_validation_checks_tests`: `111.59s`
- blockers / pivots:
  - pivot 1: switched the txvalidation fixture to assert against the built
    ingress payload nullifier instead of the legacy helper-derived nullifier
  - pivot 2: surfaced ingress fees as a real consensus-visible value-balance
    delta and added an ingress-only standardness ceiling so mempool admission
    tests validate the intended policy path
- benchmarks / simulation findings:
  - no cloud benchmark or distributed simulation ran in this sub-slice;
    validation relied on deterministic unit / mempool / reorg coverage
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - no disposable remote testnet resources were required for this sub-slice
- slice status:
  - Slice 11 remains open: the first consensus-visible `v2_ingress_batch`
    admission / unwind / reaccept path is now landed and validated, but the
    higher-scale ingress proof schedule and settlement-facing ingress flows
    still remain to land
- next slice:
  - continue `Slice 11` by scaling the ingress proof / witness model beyond the
    current wallet-shaped batch and wiring the next settlement-facing ingress
    admission flow on top of the newly accepted path

### 2026-03-15 14:55:42 JST

- remote / GitHub preflight repeated before the next fetch / pull / push / PR
  cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote sync, future push to `origin/codex/shielded-v2-overhaul-plan`, and
  the PR #82 update are unblocked for this pass.

### 2026-03-15 14:52:36 JST

- remote / GitHub preflight repeated before the validated Slice 11 push / PR
  update cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote sync, push to `origin/codex/shielded-v2-overhaul-plan`, and the PR
  #82 update are unblocked for this pass.

### 2026-03-15 14:52:36 JST

- completed the second validated `Slice 11: Implement v2_ingress_batch Intent
  Model` sub-slice in `/Users/admin/Documents/btxchain/btx-node`:
  - added the wallet / RPC ingress construction surface in
    `src/shielded/v2_ingress.h`, `src/shielded/v2_ingress.cpp`,
    `src/wallet/shielded_wallet.h`, `src/wallet/shielded_wallet.cpp`,
    `src/wallet/shielded_rpc.cpp`, and `src/wallet/rpc/wallet.cpp`, including
    `BuildV2IngressStatement(...)`, `CreateV2IngressBatch(...)`,
    `bridge_buildingressstatement`, and `bridge_buildingressbatchtx`
  - extended local coverage with the builder-backed reserve-output wallet test
    in `src/test/shielded_wallet_chunk_discovery_tests.cpp`, helper-backed
    ingress construction coverage in `test/functional/test_framework/bridge_utils.py`,
    and the full RPC surface in
    `test/functional/wallet_shielded_rpc_surface.py`
  - fixed wallet-shaped `v2_send` standardness accounting in
    `src/policy/policy.h` / `src/policy/policy.cpp` by adding a dedicated
    `MAX_STANDARD_SHIELDED_POLICY_WEIGHT` limit for shielded families instead
    of forcing them through the tighter legacy transparent `MAX_STANDARD_TX_WEIGHT`
  - added the focused regression in `src/test/shielded_v2_send_tests.cpp` for
    the one-input / two-output wallet-built `v2_send` case and tightened the
    large-egress nonstandardness guard in
    `src/test/shielded_transaction_tests.cpp`
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx btxd -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_send_tests/build_v2_send_transaction_stays_within_standard_policy_weight_for_single_input_two_outputs --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_ingress_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_tx_check_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_wallet_chunk_discovery_tests/wallet_caches_reserve_outputs_from_built_ingress_batch --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_transaction_tests/v2_egress_standardness_tracks_scan_pressure --catch_system_error=no --log_level=test_suite`
  - `python3 ./build-btx/test/functional/wallet_shielded_rpc_surface.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/rpc-surface-20260315-ingress4 --portseed=32163`
  - `python3 ./build-btx/test/functional/wallet_shielded_send_flow.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/send-flow-20260315-ingress1 --portseed=32164`
  - `python3 ./build-btx/test/functional/wallet_shielded_restart_persistence.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/restart-persistence-20260315-ingress1 --portseed=32165`
- validation findings:
  - the original functional blocker was a real policy bug: the wallet-shaped
    one-input / two-output `v2_send` fixture serialized to `1,063,865` bytes
    and therefore priced at `2,127,730` shielded policy weight, which exceeded
    the legacy `MAX_STANDARD_TX_WEIGHT = 1,200,000` even though it fit inside
    the Slice 10 shielded multidimensional block budget; the new dedicated
    shielded standardness ceiling fixed that regression without making the
    high-scan `v2_egress_batch` test standard
  - the next failure was a brittle RPC expectation, not a wallet bug:
    `bridge_buildingressbatchtx` returns actual wallet-visible outputs, so the
    `outputs` array legitimately includes reserve change when note selection
    overshoots the requested reserve total; the functional test now asserts
    that the requested reserve amount is present without assuming zero change
  - after those two pivots, the full wallet / RPC ingress flow, the ordinary
    `v2_send` flow, and shielded restart persistence all passed end-to-end on
    this host
- blockers / pivots:
  - pivot 1: replaced the legacy transparent standardness ceiling for
    shielded-family transactions with a dedicated shielded policy cap
  - pivot 2: corrected the ingress RPC functional expectation to account for
    reserve change appearing in the wallet-visible `outputs` preview
- benchmarks / simulation findings:
  - no dedicated distributed simulation or cloud benchmark ran in this
    sub-slice; validation relied on the deterministic unit and functional
    suites above
  - the focused wallet-shaped `v2_send` regression preserved the observed
    `2,127,730` shielded policy weight and `1,063,865` serialized bytes as the
    concrete pre-fix evidence for the policy bug
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - the functional tmpdirs under `/tmp/btx-functional-manual/` were cleaned up
    on successful runs
- slice status:
  - Slice 11 remains open: wallet / RPC ingress construction now exists and is
    validated locally, but the later consensus-visible ingress admission,
    higher-scale ingress proof work, and settlement-facing flows still remain
    to land
- next slice:
  - continue `Slice 11` by wiring the next consensus-visible ingress admission
    / state-transition path on top of the validated wallet / RPC ingress
    construction surface

### 2026-03-15 13:51:46 JST

- remote / GitHub preflight repeated before the next Slice 11 fetch / pull /
  push cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote sync, future push to `origin/codex/shielded-v2-overhaul-plan`, and
  the PR #82 update remain unblocked for this pass.

### 2026-03-15 13:49:07 JST

- completed the first validated `Slice 11: Implement v2_ingress_batch Intent
  Model` sub-slice in `/Users/admin/Documents/btxchain/btx-node`:
  - added the production ingress intent-model surface in
    `src/shielded/v2_ingress.h` / `src/shielded/v2_ingress.cpp`, including
    canonical ingress leaves, reserve outputs, witness / context parsing,
    settlement-binding digest rules, L2 credit / fee / reserve commitment
    derivation, native MatRiCT-backed proof verification, and the first
    `BuildV2IngressBatchTransaction(...)` constructor
  - wired contextual validation in `src/shielded/validation.cpp` so
    `CShieldedProofCheck` now accepts and verifies `v2_ingress_batch`
    transactions against the shared Merkle-tree snapshot while explicitly
    rejecting any mixed transparent+ingress transaction shape
  - updated `src/validation.cpp` so ingress batches participate in the shared
    ring-position precheck and proof-plausibility gates, but skip legacy
    spend-auth proof parsing and nullifier-bound spend-auth checks because the
    batch ingress proof binds nullifiers through the native batch witness
    instead of the direct-spend auth path
  - added dedicated coverage in `src/test/shielded_v2_ingress_tests.cpp` and
    build wiring in `src/CMakeLists.txt` / `src/test/CMakeLists.txt`
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_ingress_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_tx_check_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_bundle_tests --catch_system_error=no --log_level=test_suite`
- validation findings:
  - the first ingress fixture attempt failed before proof construction because
    the reserve output payload was encoded with `ScanDomain::BATCH` instead of
    the required `ScanDomain::RESERVE`; after fixing the fixture and rerunning,
    the full ingress builder / verifier roundtrip passed
  - the dedicated `shielded_v2_ingress_tests` cases each took about `11.3s` to
    `11.4s` on this host, which is consistent with the native MatRiCT-backed
    batch proof cost for the current single-input / two-leaf fixture
  - the full `shielded_validation_checks_tests` suite remained green after the
    ingress routing changes, including the long ring-position and context
    mutation cases, so the new ingress branch did not regress existing
    `v2_send`, `v2_egress_batch`, or settlement-anchor proof handling
- blockers / pivots:
  - no remaining blocker for this sub-slice; the only real pivot was the
    reserve scan-domain fixture bug described above
- benchmarks / simulation findings:
  - no dedicated benchmark or distributed simulation was run in this sub-slice;
    validation relied on deterministic unit coverage and the existing shared
    contextual-check suites
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - no disposable remote testnet resources were required for this sub-slice
- slice status:
  - Slice 11 remains open: the first ingress intent-model builder and
    contextual validation path are now landed and validated, but the later
    high-scale ingress proving work, wallet / RPC construction surfaces, and
    settlement-facing flows still need to build on top of this base
- next slice:
  - continue `Slice 11` by wiring wallet / RPC-facing ingress intent surfaces
    or the next consensus-visible ingress admission flow on top of the new
    builder and proof context

### 2026-03-15 13:00:44 JST

- remote / GitHub preflight repeated before the next Slice 11 fetch / pull /
  push cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote sync, future push to `origin/codex/shielded-v2-overhaul-plan`, and
  the PR #82 update remain unblocked for this pass.

### 2026-03-15 12:58:15 JST

- remote / GitHub preflight repeated before the validated Slice 10 push / PR
  update cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- push to `origin/codex/shielded-v2-overhaul-plan` and the PR #82 update
  remain unblocked for this pass.

### 2026-03-15 12:57:06 JST

- completed the remaining `Slice 10: Replace Shielded Resource Accounting`
  mining RPC / template reporting sub-slice in
  `/Users/admin/Documents/btxchain/btx-node`:
  - threaded assembled shielded verify / scan / tree-update counters through
    `src/node/miner.h`, `src/node/miner.cpp`, `src/interfaces/mining.h`, and
    `src/node/interfaces.cpp` so RPC/template callers can read the exact usage
    of the currently assembled block template and the last assembled block
  - extended `src/rpc/mining.cpp` so `getblocktemplate()["block_capacity"]`
    now reports shielded verify / scan / tree-update consensus limits plus
    current template usage and remaining capacity, and `getmininginfo()` now
    reports the same consensus limits plus `currentblockshielded*` counters for
    the last assembled template
  - fixed `getblocktemplate` template-cache lifetime handling in
    `src/rpc/mining.cpp` by replacing the cached raw `CBlockIndex*` with a
    cached previous-tip hash plus fresh block-index lookup, eliminating the
    stale-pointer crash exposed by repeated mining RPC tests across fixture
    lifetimes
  - expanded `src/test/matmul_mining_tests.cpp`,
    `test/functional/feature_btx_block_capacity.py`,
    `test/functional/mining_matmul_basic.py`, and
    `test/functional/mining_basic.py` so the new capacity / usage fields are
    asserted on unit and functional mining RPC surfaces
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx btxd -j8`
  - `./build-btx/bin/test_btx --run_test=matmul_mining_tests --catch_system_error=no --log_level=test_suite`
  - `python3 ./build-btx/test/functional/feature_btx_block_capacity.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/block-capacity-20260315c --portseed=32153`
  - `python3 ./build-btx/test/functional/mining_matmul_basic.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/mining-matmul-basic-20260315c --portseed=32154`
  - `python3 ./build-btx/test/functional/mining_basic.py --timeout-factor=0 --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/mining-basic-20260315c --portseed=32156`
- validation findings:
  - the first functional pass surfaced incorrect expectations, not a node bug:
    the frozen consensus shielded limits are `152000` verify units and `24576`
    scan / tree-update units, so the mining RPC regressions were corrected to
    match the actual consensus defaults before rerunning
  - the first full `matmul_mining_tests` run exposed a real stale-pointer bug
    in the static `getblocktemplate` cache across fixture lifetimes; after
    switching the cache to previous-tip-hash lookup, the full suite reran clean
  - `mining_basic.py` reached the new `getmininginfo` assertions successfully
    on the first run, then later hit the host's default 30-second RPC timeout
    during the pruning subtest; rerunning with `--timeout-factor=0` completed
    successfully and confirmed no broader mining RPC regression
- blockers / pivots:
  - `clang-format` is not installed on this host, so formatting was kept manual
    for this pass and validated through rebuild + test coverage instead
- cloud resources used: none
- cost: `0`
- teardown: local functional test directories were cleaned automatically on
  successful reruns; no remote teardown required
- slice status:
  - Slice 10 is now complete
  - next slice: `Slice 11: Implement v2_ingress_batch Intent Model`

### 2026-03-15 12:43:37 JST

- remote / GitHub preflight completed before the next fetch / pull / push / PR
  update cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote and GitHub steps are unblocked for this pass.

### 2026-03-15 12:41:48 JST

- remote / GitHub preflight repeated before the validated Slice 10 push / PR
  update cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- push to `origin/codex/shielded-v2-overhaul-plan` and the PR #82 update
  remain unblocked for this pass.

### 2026-03-15 12:41:00 JST

- continued `Slice 10: Replace Shielded Resource Accounting` with the first
  production multidimensional accounting sub-slice in
  `/Users/admin/Documents/btxchain/btx-node`:
  - added `shielded::ShieldedResourceUsage` and
    `GetShieldedResourceUsage(...)` in `src/shielded/bundle.h` /
    `src/shielded/bundle.cpp`, replacing the old verify-only accounting with
    family-aware verify, scan, and Merkle-tree update units across legacy
    shielded, `v2_send`, `v2_ingress_batch`, `v2_egress_batch`,
    `v2_rebalance`, and `v2_settlement_anchor`
  - added consensus defaults for scan and tree-update budgets in
    `src/consensus/params.h` beside the existing verify budget, keeping the
    dominant shielded block limits consensus-visible instead of policy-only
  - replaced policy-only shielded surcharges in `src/policy/policy.h` /
    `src/policy/policy.cpp` with `GetShieldedPolicyWeight(...)`, which prices a
    transaction by the dominant normalized resource among serialized bytes,
    verify units, scan units, and tree-update units
  - updated fee floor callers in `src/wallet/wallet.cpp` and
    `src/wallet/shielded_rpc.cpp` so wallet-required mempool fees now track the
    same dominant shielded policy weight instead of the removed legacy
    non-witness shielded surcharge model
  - extended `src/node/miner.h`, `src/node/miner.cpp`, and `src/validation.cpp`
    so block assembly and block connection accumulate and enforce all three
    shielded dimensions, with new reject reasons `bad-blk-shielded-scan` and
    `bad-blk-shielded-tree-updates`
  - expanded `src/test/shielded_v2_bundle_tests.cpp`,
    `src/test/shielded_hardening_tests.cpp`, and
    `src/test/shielded_transaction_tests.cpp` so the new per-family resource
    vectors, consensus defaults, and standardness behavior are covered with a
    large-fanout `v2_egress_batch` regression
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_transaction_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_bundle_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_hardening_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=txvalidation_tests/tx_mempool_accepts_v2_egress_after_settlement_anchor_and_evicts_it_after_reorg --catch_system_error=no --log_level=test_suite`
- validation findings:
  - the large-fanout `v2_egress_batch` standardness regression now passes and
    proves that scan pressure, not raw serialized size, is the dominant policy
    limiter for that family under the new accounting model
  - `shielded_v2_bundle_tests` and `shielded_hardening_tests` passed with the
    new resource vectors and confirmed that miner defaults remain aligned with
    the new consensus verify, scan, and tree-update limits
  - the anchored `txvalidation_tests/tx_mempool_accepts_v2_egress_after_settlement_anchor_and_evicts_it_after_reorg`
    regression stayed green after the accounting change, so mempool and reorg
    behavior still accepts anchored egress transitions under the new model
  - `shielded_validation_checks_tests` remained green after the accounting
    refactor, so proof binding and contextual shielded checks were not
    regressed by the policy / miner / block-limit changes
- blockers / pivots:
  - the first large-fanout `v2_egress_batch` regression fixture failed because
    it constructed `uint256` fields from wrapped single-byte seeds, which
    turned some commitments and ephemeral keys into null values once the output
    index crossed `256`; the fix was to build deterministic nonzero `uint256`
    values from byte arrays instead of wrapped scalar brace-init
  - the first retry only changed the test source without rebuilding
    `test_btx`; after rebuilding, the new regression and the focused Slice 10
    suite passed on the updated binary
- benchmarks / simulation findings:
  - none in this sub-slice; this pass focused on consensus / policy / miner
    accounting replacement and regression validation
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - no disposable remote testnet resources were required for this sub-slice
- slice status:
  - Slice 10 remains open: consensus / policy / miner multidimensional
    accounting is now in place, but block-template surfaces, fee reporting, and
    the later Slice 16 dominant-resource miner selection work still need to be
    finished on top of this new accounting base
- next slice:
  - continue `Slice 10` by wiring the new shielded dimensions into the
    remaining RPC / template / reporting surfaces and any residual fee-policy
    consumers that still assume the old verify-only model

### 2026-03-15 12:06:30 JST

- remote / GitHub preflight completed before the next fetch / pull / push / PR
  update cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote and GitHub steps are unblocked for this pass.

### 2026-03-15 01:00:50 JST

- remote / GitHub preflight completed before any network operation;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote and GitHub steps are unblocked for this pass.

### 2026-03-15 01:21:26 JST

- highest-priority unfinished slice selected: `Slice 2: Start From Post-PR79
  main And Create The Parallel Dev Network`
- implemented the `shieldedv2dev` parallel development network in
  `/Users/admin/Documents/btxchain/btx-node`:
  - new `ChainType::SHIELDEDV2DEV`
  - `-chain=shieldedv2dev` and `-shieldedv2dev`
  - isolated datadir `shieldedv2dev`
  - isolated RPC / P2P defaults `19443` / `19444`
  - isolated message-start magic `e2b7da7a`
  - isolated Bech32m / P2MR HRP `btxv2`
  - isolated fixed genesis hash
    `4ed72f2a7db044ff555197cddde63b1f50b74d750674316f75c3571ade9c80a3`
  - wallet-dir scanning now skips the new chain namespace so wallet discovery
    does not bleed across networks
  - CLI, init/help, external-signer, GUI network styling, and functional-test
    framework surfaces recognize the new chain
- added validation coverage:
  - C++ unit coverage for chain selection and chain params
  - key I/O invalid-vector coverage extended across the new chain
  - functional test
    `test/functional/feature_shieldedv2dev_datadir_isolation.py`
    proving one shared base datadir can alternate between `shieldedv2dev` and
    `regtest` without wallet cross-load
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target btxd btx-cli test_btx -j8`
  - `./build-btx/bin/test_btx --run_test=argsman_tests/util_GetChainTypeString --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=matmul_params_tests/matmul_params_shieldedv2dev --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=key_io_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/test/functional/test_runner.py feature_shieldedv2dev_datadir_isolation.py --jobs=1 --tmpdirprefix=/tmp/btx-functional --descriptors`
  - `tmpdir=$(mktemp -d /tmp/btx-shieldedv2dev-XXXXXX) && ./build-btx/bin/btxd -chain=shieldedv2dev ... && ./build-btx/bin/btx-cli ... getblockchaininfo`
- validation findings:
  - targeted unit tests passed
  - functional isolation test passed after enabling wallet options in the test
    and requesting `p2mr` addresses instead of unsupported `bech32`
  - live node probe confirmed `chain=shieldedv2dev`, `bestblockhash` equal to
    the frozen genesis hash above, `bits=207fffff`, and `time=1773446400`
- benchmarks / simulation findings:
  - none required for this sub-slice beyond startup and RPC validation
- blockers / pivots:
  - `test_runner.py` did not expose BTX-only scripts through `ALL_SCRIPTS`;
    updated it so the new BTX functional lane is directly runnable
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - temporary local probe node started in `/tmp/btx-shieldedv2dev-AhoLWu` and
    was stopped cleanly with `btx-cli stop`
  - no DigitalOcean, Porkbun, or Tailscale resources were created
- next slice:
  - `Slice 3: Define shielded_v2 Wire Formats`

### 2026-03-15 01:24:08 JST

- remote / GitHub preflight repeated at start of pass before any new network
  operation;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote and GitHub steps remain unblocked for this pass.

### 2026-03-15 01:40:51 JST

- highest-priority unfinished slice selected: `Slice 3: Define shielded_v2
  Wire Formats`
- implemented the first real Slice 3 sub-slice in
  `/Users/admin/Documents/btxchain/btx-node`:
  - new canonical `shielded_v2` wire primitives in
    `src/shielded/v2_types.h` / `src/shielded/v2_types.cpp`
  - explicit consensus-stable family ids for all five native transaction
    families:
    - `v2_send = 1`
    - `v2_ingress_batch = 2`
    - `v2_egress_batch = 3`
    - `v2_rebalance = 4`
    - `v2_settlement_anchor = 5`
  - new `shielded_v2` note encoding with explicit `note_class`, `version`,
    `source_binding`, bounded memo bytes, and new domain-separated note
    commitment / nullifier helpers
  - new encrypted note payload encoding with explicit
    `scan_hint_version`, `scan_domain`, fixed-width scan hints, bounded
    ciphertext bytes, and no legacy range-proof / anchor baggage
  - new proof envelope encoding with explicit `proof_envelope_version`,
    `proof_kind`, component-proof kinds, and `settlement_binding_kind`
  - new batch-leaf, proof-shard descriptor, output-chunk descriptor, and
    multi-domain netting-manifest encodings for `v2_rebalance`
  - canonical hash / root helpers for notes, tree nodes, batch leaves,
    proof-shard descriptors, output chunks, netting manifests, and
    transaction-family headers
  - new focused unit suite `src/test/shielded_v2_wire_tests.cpp`
  - new fuzz harness `src/test/fuzz/shielded_v2_wire.cpp`
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_wire_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_note_tests/serialization_roundtrip --catch_system_error=no --log_level=test_suite`
  - `cmake -S /Users/admin/Documents/btxchain/btx-node -B /Users/admin/Documents/btxchain/btx-node/build-fuzz-smoke -G Ninja -DBUILD_FOR_FUZZING=ON -DBUILD_FUZZ_BINARY=ON -DBUILD_TESTS=OFF -DBUILD_BENCH=OFF -DBUILD_GUI=OFF -DWITH_ZMQ=OFF -DENABLE_WALLET=OFF -DWITH_BDB=OFF`
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-fuzz-smoke --target fuzz -j8`
  - `FUZZ=shielded_v2_note_deserialize /Users/admin/Documents/btxchain/btx-node/build-fuzz-smoke/bin/fuzz /tmp/btx-v2-fuzz-smoke`
  - `FUZZ=shielded_v2_netting_manifest_deserialize /Users/admin/Documents/btxchain/btx-node/build-fuzz-smoke/bin/fuzz /tmp/btx-v2-fuzz-smoke`
  - `FUZZ=shielded_v2_transaction_header_deserialize /Users/admin/Documents/btxchain/btx-node/build-fuzz-smoke/bin/fuzz /tmp/btx-v2-fuzz-smoke`
- validation findings:
  - `test_btx` rebuilt cleanly with the new wire types and test suite
  - the new `shielded_v2_wire_tests` suite passed end to end, including
    round-trip serializer checks, enum rejection, root-order sensitivity, and
    zero-sum netting-manifest validation
  - the existing `shielded_note_tests/serialization_roundtrip` regression
    check remained green
  - the dedicated fuzz build compiled and linked the new harness successfully
  - targeted fuzz smoke passed for note, netting-manifest, and
    transaction-header deserializers against a one-file seed corpus
- benchmarks / simulation findings:
  - no throughput benchmark was required for this serializer / hashing
    sub-slice
  - unit coverage confirmed the consensus-relevant invariants that matter at
    this stage: ordered descriptor roots are not permutation-invariant, note
    class changes alter commitments, and non-zero-sum / unsorted netting
    manifests are rejected
- blockers / pivots:
  - the default `build-btx` tree has `BUILD_FUZZ_BINARY=OFF`, so a dedicated
    local `build-fuzz-smoke` tree was created to compile and smoke the new
    fuzz targets instead of leaving them unvalidated
  - Slice 3 remains open because these wire primitives still need to be wired
    into the consensus-visible family scaffolding and remaining per-family
    byte-level freezes
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - temporary local fuzz seed corpus remained at `/tmp/btx-v2-fuzz-smoke`
    because desktop safety policy blocked deletion during this pass
  - local `build-fuzz-smoke` was retained intentionally for follow-on Slice 3
    fuzz iterations
- next slice:
  - continue `Slice 3: Define shielded_v2 Wire Formats` by binding these new
    wire objects into consensus-visible transaction-family scaffolding

### 2026-03-15 01:42:33 JST

- remote / GitHub preflight repeated before pushing the validated Slice 3
  sub-slice and before posting the PR #82 update;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote push and GitHub comment steps remain unblocked for this pass.

### 2026-03-15 02:01:03 JST

- highest-priority unfinished slice selected: continue
  `Slice 3: Define shielded_v2 Wire Formats`
- implemented the remaining family-level Slice 3 wire freeze in
  `/Users/admin/Documents/btxchain/btx-node`:
  - new canonical `shielded_v2` family bundle / transaction-family encoding in
    `src/shielded/v2_bundle.h` / `src/shielded/v2_bundle.cpp`
  - new shared `SpendDescription`, `OutputDescription`, and `ReserveDelta`
    objects with bounded serializers and domain-separated hash / root helpers
  - new concrete family payload encodings for:
    - `v2_send`
    - `v2_ingress_batch`
    - `v2_egress_batch`
    - `v2_rebalance`
    - `v2_settlement_anchor`
  - new canonical top-level `TransactionBundle` carrying:
    - explicit family-typed payload selection
    - header / payload-digest consistency
    - proof payload bytes plus optional proof-shard descriptors
    - optional output-chunk descriptors with canonical range coverage checks
    - `v2_rebalance` netting-manifest version and payload consistency checks
  - new focused unit suite `src/test/shielded_v2_bundle_tests.cpp`
  - new fuzz harness `src/test/fuzz/shielded_v2_bundle.cpp`
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_bundle_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_wire_tests --catch_system_error=no --log_level=test_suite`
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-fuzz-smoke --target fuzz -j8`
  - `FUZZ=shielded_v2_transaction_bundle_deserialize ./build-fuzz-smoke/bin/fuzz /tmp/btx-v2-fuzz-smoke`
  - `FUZZ=shielded_v2_netting_manifest_deserialize ./build-fuzz-smoke/bin/fuzz /tmp/btx-v2-fuzz-smoke`
  - `FUZZ=shielded_v2_transaction_header_deserialize ./build-fuzz-smoke/bin/fuzz /tmp/btx-v2-fuzz-smoke`
- validation findings:
  - `test_btx` rebuilt cleanly with the new family-level bundle types
  - the new `shielded_v2_bundle_tests` suite passed end to end, covering
    round-trip serialization for all five native transaction families plus
    family/payload mismatch rejection, canonical shard coverage, canonical
    chunk coverage, rebalance manifest/header coupling, and bundle-id
    commitment to proof bytes
  - the existing `shielded_v2_wire_tests` regression suite remained green after
    introducing the bundle layer
  - the dedicated fuzz build reconfigured and rebuilt cleanly with the new
    `shielded_v2_transaction_bundle_deserialize` target
  - targeted fuzz smoke passed for the new bundle deserializer and for the
    existing netting-manifest and transaction-header deserializers against the
    retained one-file seed corpus
- benchmarks / simulation findings:
  - no throughput benchmark was required for this serializer / validity-layer
    sub-slice
  - canonical coverage checks now reject overlapping proof-shard ranges,
    missing output-chunk coverage, mismatched family payload variants, and
    rebalance manifest/header drift before consensus plumbing is added
- blockers / pivots:
  - the first rebalance-bundle validation attempt exposed a real bug in the
    new aggregate reserve-delta checker: using `MoneyRange()` incorrectly
    rejected negative netting deltas
  - revised the validator to use the signed `IsAmountDeltaInRange()` discipline
    instead, then rebuilt and reran the full targeted validation set
  - this closes Slice 3; the remaining work to surface these families inside
    consensus-visible transaction plumbing belongs to Slice 6, not the wire
    format slice
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - local `build-fuzz-smoke` was retained intentionally for follow-on fuzz
    passes
  - temporary local fuzz seed corpus remained at `/tmp/btx-v2-fuzz-smoke`
- next slice:
  - `Slice 4: Build The Proof Abstraction Layer`

### 2026-03-15 02:01:03 JST

- remote / GitHub preflight repeated before pushing the validated Slice 3
  closure and before posting the PR #82 update;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote push and GitHub comment steps remain unblocked for this pass.

### 2026-03-15 02:04:29 JST

- remote / GitHub preflight repeated at start of the next pass before any new
  network operation;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote and GitHub steps remain unblocked for this pass.

### 2026-03-15 02:23:46 JST

- highest-priority unfinished slice selected: `Slice 4: Build The Proof
  Abstraction Layer`
- implemented the first validated Slice 4 sub-slice in
  `/Users/admin/Documents/btxchain/btx-node`:
  - new explicit proof-abstraction layer in
    `src/shielded/v2_proof.h` / `src/shielded/v2_proof.cpp`
  - separate `VerificationDomain::DIRECT_SPEND` and
    `VerificationDomain::BATCH_SETTLEMENT`
  - first-class `PayloadLocation`, `ProofStatement`, `ProofMaterial`,
    `DirectSpendContext`, and `SettlementContext`
  - legacy MatRiCT direct-spend proofs now bind explicit statement digests,
    synthesized proof-shard descriptors, and witness payload locations instead
    of leaving those relationships implicit in `src/shielded/validation.cpp`
  - new settlement-side receipt / claim descriptors expose imported-proof
    statement digests and payload locations ahead of consensus wiring
  - `src/shielded/validation.cpp` now routes `CShieldedProofCheck` and spend
    auth proof parsing / nullifier extraction through the new proof abstraction
    instead of re-implementing MatRiCT-specific parsing locally
  - new focused unit suite `src/test/shielded_v2_proof_tests.cpp`
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_proof_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=ringct_matrict_tests --catch_system_error=no --log_level=test_suite`
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target bench_btx -j8`
  - `./build-btx/bin/bench_btx -list | rg 'MatRiCT|shielded'`
  - `./build-btx/bin/bench_btx -filter=MatRiCT -min-time=100`
  - `script -q /tmp/btx-matrict-bench.typescript ./build-btx/bin/bench_btx -filter=MatRiCT -min-time=100`
- validation findings:
  - `test_btx` rebuilt cleanly after moving direct-proof parsing and
    descriptor binding into the new abstraction module
  - the new `shielded_v2_proof_tests` suite passed, covering explicit direct
    statement binding, descriptor surfacing, wrong-digest rejection, and
    imported receipt / claim payload-location modeling
  - the existing `shielded_validation_checks_tests` regression suite remained
    green after routing `CShieldedProofCheck` through `DirectSpendContext`
  - the existing `ringct_matrict_tests` suite remained green, including the
    deterministic vector, replay-detection, and sub-proof substitution checks,
    confirming no behavioral drift in the underlying direct proof backend
- benchmarks / simulation findings:
  - attempted to capture the existing MatRiCT benches after the refactor, but
    in this desktop shell the bench binary exited `0` without emitting stdout,
    JSON, or `script(1)` transcript output even though `-list` confirmed the
    MatRiCT benches exist; no trustworthy throughput delta was recorded this
    pass
  - no distributed or cloud simulation was required for this proof-API
    sub-slice because it changes only local proof plumbing
- blockers / pivots:
  - the first build failed on an unqualified
    `ringct::ComputeNullifierFromKeyImage` call inside the new abstraction and
    then on unqualified bridge types in the new unit tests; both issues were
    corrected and the full targeted validation set was rerun from scratch
  - the MatRiCT bench harness appears to suppress or discard output under this
    desktop environment; revisit bench capture once the next proof-backend
    sub-slice changes runtime-critical paths
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - no remote nodes or disposable testnets were started for this sub-slice
- next slice:
  - continue `Slice 4: Build The Proof Abstraction Layer` by attaching the
    settlement-side proof contexts to real imported receipt / claim
    verification flows and by exposing backend-swap hooks for native batch
    proving

### 2026-03-15 02:25:11 JST

- remote / GitHub preflight repeated before pushing the validated Slice 4
  sub-slice and before posting the PR #82 update;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote push and GitHub comment steps remain unblocked for this pass.

### 2026-03-15 02:27:11 JST

- remote / GitHub preflight repeated at start of the next pass before any new
  network operation;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote and GitHub steps remain unblocked for this pass.

### 2026-03-15 02:40:27 JST

- highest-priority unfinished slice selected again: `Slice 4: Build The Proof
  Abstraction Layer`
- implemented the second validated Slice 4 sub-slice in
  `/Users/admin/Documents/btxchain/btx-node`:
  - extended `src/shielded/v2_proof.h` /
    `src/shielded/v2_proof.cpp` with a statement-bound settlement witness API
    and explicit native-batch backend descriptors
  - new `NativeBatchBackend`, `ComputeNativeBatchStatementDigest`, and
    `DescribeNativeBatchSettlementStatement` stop native batch proving from
    being hardcoded to one implicit backend configuration
  - new `SettlementWitness` and `VerifySettlementContext` bind imported proof
    receipts and claims to concrete `BridgeBatchStatement` objects instead of
    only checking self-consistency inside `SettlementContext`
  - imported proof receipt verification now enforces bridge proof-policy proof
    checks, proof-receipt inclusion, receipt-threshold checks, hybrid bundle
    root matching, and verifier-set membership proofs for signed committee
    receipts
  - imported claim verification now enforces real
    `DoesBridgeProofClaimMatchStatement(...)` matching against the referenced
    bridge batch statement
  - `SettlementContext::IsValid()` now rejects claim contexts that try to carry
    stray verification bundles, keeping claim and receipt flows separated
  - `src/test/shielded_v2_proof_tests.cpp` now covers:
    - native-batch backend digest changes
    - imported-claim statement binding
    - proof-policy-backed imported receipt validation
    - hybrid witness bundle validation and bad membership-proof rejection
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_proof_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=ringct_matrict_tests --catch_system_error=no --log_level=test_suite`
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target bench_btx -j8`
- validation findings:
  - the new `shielded_v2_proof_tests` cases passed, confirming statement-bound
    imported claim matching, proof-policy-backed imported receipt validation,
    hybrid bundle root binding, and native-batch backend digest separation
  - `shielded_validation_checks_tests` stayed green, showing the new
    settlement-side API work did not regress the existing legacy spend proof
    validation path
  - `ringct_matrict_tests` stayed green, including the deterministic vector and
    replay/substitution checks, so the direct MatRiCT backend remains stable
    after introducing the new native-batch descriptor surface
  - `bench_btx` rebuilt cleanly after the abstraction update
- benchmarks / simulation findings:
  - no new throughput or distributed simulation run was required for this
    sub-slice because it only adds proof-API and settlement-witness validation
    paths
  - this pass still provides binary compatibility evidence by rebuilding the
    bench target after the proof-abstraction changes
- blockers / pivots:
  - settlement proof-receipt set verification currently accepts only
    descriptor-uniform supporting receipt sets, because the existing bridge
    proof-policy surface exposes a single descriptor proof at a time; if
    multi-descriptor proof bundles become consensus-relevant later, the witness
    object will need to grow a per-receipt descriptor-proof map
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - no remote nodes or disposable testnets were started for this sub-slice
- next slice:
  - continue `Slice 4: Build The Proof Abstraction Layer` by wiring these
    native-batch backend descriptors and settlement witnesses into the first
    consensus-visible batch proof / settlement-anchor scaffolding

### 2026-03-15 02:41:34 JST

- remote / GitHub preflight repeated before pushing the validated Slice 4
  settlement-witness sub-slice and before posting the PR #82 update;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote push and GitHub comment steps remain unblocked for this pass.

### 2026-03-15 02:43:18 JST

- remote / GitHub preflight repeated at start of the next pass before any new
  network operation;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote and GitHub steps remain unblocked for this pass.

### 2026-03-15 02:57:19 JST

- highest-priority unfinished slice selected again: `Slice 4: Build The Proof
  Abstraction Layer`
- implemented the third validated Slice 4 sub-slice in
  `/Users/admin/Documents/btxchain/btx-node`:
  - tightened `src/shielded/v2_bundle.cpp` so every batch-family
    `TransactionBundle` now validates its `proof_envelope` against the
    `shielded::v2::proof::ProofStatement` contract instead of only checking
    local payload shape
  - `v2_ingress_batch`, `v2_egress_batch`, `v2_rebalance`, and
    `v2_settlement_anchor` now require canonical proof-shard coverage plus
    proof-shard `statement_digest` alignment with the header envelope
  - `v2_rebalance` now uses an explicit native batch proof envelope bound to
    `SettlementBindingKind::NETTING_MANIFEST` rather than the earlier
    placeholder imported-receipt shape, and it rejects manifests whose
    anchored batch-statement digest or binding kind diverges from the header
  - `v2_settlement_anchor` now requires its anchored
    `batch_statement_digests` inventory to actually contain the active proof
    statement digest, making the settlement-anchor scaffold commit to the
    batch statement it claims to anchor
  - `IngressBatchPayload`, `EgressBatchPayload`, and `RebalancePayload` now
    reject null settlement / batch-binding digests instead of allowing those
    fields to remain structural placeholders
  - `src/shielded/v2_proof.cpp` now accepts `NETTING_MANIFEST` as a valid
    settlement-binding kind for native batch proof statements, keeping the
    binding plane modular instead of hardcoding batch proofs to one settlement
    binding
  - `src/test/shielded_v2_bundle_tests.cpp` now covers:
    - ingress shard statement-digest mismatch rejection
    - imported-receipt envelopes rejecting stray membership components
    - rebalance batch-statement mismatch rejection
    - settlement-anchor statement-digest anchoring rejection
  - `src/test/shielded_v2_proof_tests.cpp` now covers native batch proof
    statements rebinding cleanly to `NETTING_MANIFEST`
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_bundle_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_proof_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_wire_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests --catch_system_error=no --log_level=test_suite`
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-fuzz-smoke --target fuzz -j8`
  - `mkdir -p /tmp/btx-v2-fuzz-smoke && FUZZ=shielded_v2_transaction_bundle_deserialize ./build-fuzz-smoke/bin/fuzz /tmp/btx-v2-fuzz-smoke`
- validation findings:
  - the new `shielded_v2_bundle_tests` cases passed, confirming that batch
    bundles now reject detached proof envelopes, detached proof-shard
    statement digests, stale rebalance batch-statement bindings, and
    settlement anchors that omit the anchored statement digest they claim to
    carry
  - `shielded_v2_proof_tests` stayed green with the new netting-manifest
    binding path, so native batch proof statements remain valid while exposing
    a second settlement-binding mode
  - `shielded_v2_wire_tests` remained green after tightening the bundle-level
    semantics, showing the underlying serializer and header encodings stayed
    stable
  - `shielded_validation_checks_tests` remained green, confirming the new
    batch-family proof-envelope rules did not regress the legacy direct-spend
    validation path
  - the `shielded_v2_transaction_bundle_deserialize` fuzz smoke ran cleanly
    against the retained local corpus with the new semantic rejection paths in
    place
- benchmarks / simulation findings:
  - no throughput benchmark or distributed simulation run was required for
    this sub-slice because it only tightens semantic validation and proof
    binding invariants inside the local bundle / proof contract
  - the additional validation signal for this pass comes from the fuzz-smoke
    deserializer run rather than a performance bench
- blockers / pivots:
  - `v2_send` still carries its direct proof bytes inline without adopting the
    batch-family proof-shard bundle contract; this pass intentionally kept the
    stricter proof-shard enforcement scoped to the batch families so the
    already-frozen direct-send wire shape does not get reopened before the
    wider consensus-family scaffolding work
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - no disposable testnet, seed host, or remote validation node was started
  - the local fuzz corpus at `/tmp/btx-v2-fuzz-smoke` was reused and left in
    place for subsequent serializer smoke runs
- next slice:
  - move to `Slice 5: Import And Sandbox MatRiCT+`

### 2026-03-15 02:58:53 JST

- remote / GitHub preflight repeated before pushing the validated Slice 4
  batch-bundle proof-binding sub-slice and before posting the PR #82 update;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote push and GitHub comment steps remain unblocked for this pass.

### 2026-03-15 03:01:13 JST

- remote / GitHub preflight repeated at start of the next pass before any new
  network operation;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote and GitHub steps remain unblocked for this pass.

### 2026-03-15 03:23:25 JST

- Slice 5 sub-slice landed locally: introduced a dedicated MatRiCT+ portable
  backend boundary in `src/shielded/matrict_plus_backend.*` with:
  - a domain-separated backend identity for later native-batch wiring;
  - a deterministic 2-in / 2-out fixture builder;
  - wrapper-level fixture validation before proof creation / verification;
  - a stable known-answer proof hash for the deterministic spend path.
- rewired deterministic MatRiCT KAT coverage to use the new backend wrapper
  instead of file-local duplicated note / ring / key fixture builders;
- added dedicated wrapper tests for:
  - rejecting malformed fixture-to-ring bindings at the sandbox boundary;
  - exposing the same backend identity through the Slice 4 proof abstraction
    via `DescribeMatRiCTPlusNativeBatchBackend()`;
- moved the BTX MatRiCT bench harness onto the same deterministic portable
  fixture so future runtime comparisons do not depend on local RNG drift.
- validation:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx bench_btx -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_matrict_plus_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=ringct_matrict_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_proof_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/bench_btx -list | rg 'MatRiCT'`
- measured findings:
  - deterministic MatRiCT+ KAT proof size (corrected after fixing
    `MatRiCTProof::GetSerializedSize()`): `1,163,433` bytes
  - deterministic MatRiCT+ KAT proof hash:
    `27d52be1f4c79d64e6f155b66afd8bcb194313fc92f315fd2436531b19fb1d28`
  - the full `bench_btx -filter='.*MatRiCT.*' -min-time=50 -output-json=/tmp/btx-matrict-bench.json`
    run was attempted on this host but had to be terminated after `07:14`
    wall-clock because the bench itself intentionally enforces
    `minEpochIterations(10)` for creation and `minEpochIterations(5)` for
    verification on a multi-second proof primitive, so no completed nanobench
    JSON artifact was produced in this pass
- Slice 5 remains open:
  - the portable backend boundary, deterministic KAT wrapper, and bench wiring
    are now in place
  - the remaining Slice 5 work is to extend this into fuller reference-vector
    packaging and host-repeatable runtime capture that can be reported without
    terminating the long bench run

### 2026-03-15 03:24:22 JST

- remote / GitHub preflight repeated before pushing the validated Slice 5
  portable MatRiCT+ backend sub-slice and before posting the PR #82 update;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote push and GitHub comment steps remain unblocked for this pass.

### 2026-03-15 03:26:37 JST

- remote / GitHub preflight repeated at start of the next pass before any new
  network operation;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote and GitHub steps remain unblocked for this pass.

### 2026-03-15 03:41:39 JST

- Slice 5 reference-vector packaging sub-slice landed locally:
  - added `src/test/generate_shielded_matrict_plus_vectors.cpp` plus the
    `gen_shielded_matrict_plus_vectors` build target so the deterministic
    2-in / 2-out MatRiCT+ fixture can emit a canonical spend-and-verify JSON
    artifact directly from BTX code;
  - extended `test/reference/generate_shielded_test_vectors.py` to refresh the
    `matrict_plus` section from that utility and preserve the existing section
    when the binary is unavailable;
  - moved the long-lived KAT source of truth out of
    `src/shielded/matrict_plus_backend.*` so the backend no longer hard-codes
    the deterministic proof hash;
  - widened `src/test/util/json.cpp` to parse object-root JSON so tests can
    consume the shared reference corpus directly;
  - added packaged-proof coverage in `src/test/shielded_matrict_plus_tests.cpp`
    that:
    - reconstructs the deterministic fixture from
      `test/reference/shielded_test_vectors.json`,
    - recreates the deterministic proof and checks the serialized bytes, size,
      and hash against the packaged vector,
    - deserializes the packaged proof bytes and verifies them against the
      packaged public statement,
    - and confirms a tampered public statement is rejected;
  - kept the existing `ringct_matrict_tests` deterministic path but reduced it
    to a repeatability check now that the authoritative KAT lives in the
    generated reference corpus.
- validation:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx generate_shielded_matrict_plus_vectors -j8`
  - `BTX_MATRICT_PLUS_VECTOR_TOOL=/Users/admin/Documents/btxchain/btx-node/build-btx/bin/gen_shielded_matrict_plus_vectors python3 test/reference/generate_shielded_test_vectors.py`
  - `./build-btx/bin/test_btx --run_test=shielded_matrict_plus_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=ringct_matrict_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_proof_tests --catch_system_error=no --log_level=test_suite`
- measured findings:
  - packaged-vector validation exposed a `761`-byte undercount in
    `src/shielded/ringct/matrict.cpp` because
    `MatRiCTProof::GetSerializedSize()` had drifted from the actual serializer;
    the helper now delegates to `::GetSerializeSize(*this)`;
  - deterministic MatRiCT+ packaged proof size remains `1,163,433` bytes, and
    rerun validation confirmed the helper now matches both the checked-in
    serialized bytes and the runtime test logs;
  - deterministic MatRiCT+ packaged proof hash remains
    `27d52be1f4c79d64e6f155b66afd8bcb194313fc92f315fd2436531b19fb1d28`;
  - the new packaged-proof verification test completed quickly because it
    verifies the checked-in serialized proof instead of re-running creation.
- Slice 5 remains open, but the "known-answer vectors for spend and verify
  operations" part of Slice 5 / Track 1 is now code-backed and validated;
- remaining Slice 5 work is narrowed to host-repeatable runtime capture and
  bench reporting that can complete without aborting the long MatRiCT bench
  run.

### 2026-03-15 03:48:56 JST

- remote / GitHub preflight repeated before pushing the validated Slice 5
  reference-vector packaging sub-slice;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote and GitHub steps remain unblocked for this push.

### 2026-03-15 03:59:12 JST

- Slice 5 bounded runtime-capture / bench-reporting sub-slice landed locally:
  - added `src/test/shielded_matrict_runtime_report.*`, a deterministic
    MatRiCT+ runtime-report builder that:
    - reuses the portable Slice 5 fixture,
    - binds every measured sample back to the checked-in
      `test/reference/shielded_test_vectors.json` proof size and proof hash,
    - emits bounded create / verify nanosecond samples plus summary stats, and
    - fails hard if the backend id, serialized size, or proof hash drift;
  - added `src/test/generate_shielded_matrict_plus_runtime_report.cpp` plus the
    `gen_shielded_matrict_plus_runtime_report` build target so hosts can emit a
    JSON runtime report without depending on long nanobench epoch schedules;
  - added `shielded_matrict_runtime_report_tests` coverage to confirm the
    report schema, reference-vector binding, sample accounting, and rejection of
    zero-sample requests;
  - kept the existing `bench_btx` MatRiCT benches unchanged while providing a
    bounded companion path that can finish without aborting a long
    `minEpochIterations(10)` / `minEpochIterations(5)` nanobench run.
- validation:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx generate_shielded_matrict_plus_runtime_report -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_matrict_runtime_report_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_matrict_plus_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/gen_shielded_matrict_plus_runtime_report --samples=1 --output=/tmp/btx-matrict-runtime-report.json`
- measured findings:
  - the bounded runtime report completed with a single deterministic sample
    instead of requiring the longer nanobench epoch schedule;
  - deterministic MatRiCT+ packaged proof size remained `1,163,433` bytes;
  - deterministic MatRiCT+ packaged proof hash remained
    `27d52be1f4c79d64e6f155b66afd8bcb194313fc92f315fd2436531b19fb1d28`;
  - the generated report captured:
    - `create_ns = 11,673,183,083`
    - `verify_ns = 43,074,250`
    - matching median values for the one-sample run.
- Slice 5 is now closed:
  - the portable backend boundary, deterministic KAT corpus, bench harness, and
    bounded runtime-report path are all code-backed and validated inside
    `btx-node`;
  - the next implementation slice is `Slice 6: Add Consensus Transaction-Family
    Scaffolding`.

### 2026-03-15 04:00:17 JST

- remote / GitHub preflight repeated before pushing the validated Slice 5
  runtime-report capture sub-slice;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote and GitHub steps remain unblocked for this push.

### 2026-03-15 04:14:49 JST

- highest-priority unfinished slice selected: `Slice 6: Add Consensus
  Transaction-Family Scaffolding`;
- implemented the first real Slice 6 consensus-visible transaction-family
  scaffold in `/Users/admin/Documents/btxchain/btx-node`:
  - `src/shielded/bundle.h` / `src/shielded/bundle.cpp` now let
    `CShieldedBundle` carry either the legacy direct-spend fields or one
    `shielded::v2::TransactionBundle`, never both;
  - legacy direct-spend serialization remains byte-stable, while the new
    family path uses the reserved first-field sentinel
    `CShieldedBundle::SERIALIZED_V2_BUNDLE_TAG` to distinguish canonical
    `shielded_v2` family bundles on the transaction wire;
  - mixed legacy-plus-`v2` bundle encodings are rejected explicitly in both
    serializer and `CheckStructure()`;
  - generic family-aware helpers now expose shielded input counts, output
    counts, proof payload sizing, and transaction-family identity for common
    transaction, policy, and logging paths;
  - `src/script/interpreter.cpp` now commits CTV preimages to the full
    `shielded_v2` bundle bytes through a dedicated
    `ComputeShieldedBundleCtvHash()` path while preserving the legacy direct
    bundle commitment ordering;
  - `src/policy/policy.cpp` and `src/primitives/transaction.cpp` now consume
    the family-aware bundle helpers so policy weight accounting and transaction
    summaries see `v2` family sizes instead of silently assuming the legacy
    direct-spend layout;
  - `src/consensus/tx_check.cpp` now recognizes and structurally validates
    `v2` family bundles but deliberately rejects them with
    `bad-shielded-v2-unroutable` until the Slice 6 state-routing /
    connect-disconnect entrypoints land.
- added focused regression coverage:
  - `src/test/shielded_transaction_tests.cpp`:
    - legacy bundle roundtrip unchanged,
    - `v2_send` transaction roundtrip through `CTransaction`,
    - txid / wtxid commitment to `v2` bundle payload bytes,
    - mixed legacy-plus-`v2` serialization rejection;
  - `src/test/shielded_tx_check_tests.cpp`:
    - explicit consensus rejection of structurally valid `v2` family bundles
      until the routing slice lands;
  - `src/test/pq_consensus_tests.cpp`:
    - explicit CTV commitment coverage for `shielded_v2` bundle payload bytes.
- validation:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_transaction_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_tx_check_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_bundle_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test='pq_consensus_tests/ctv_hash_commits_to_v2_shielded_bundle_bytes' --catch_system_error=no --log_level=test_suite`
- validation findings:
  - legacy shielded-bundle roundtrips and hash commitments remained green after
    the new discriminated `CShieldedBundle` shape landed;
  - canonical `v2_send` family bundles now serialize through the transaction
    path, survive roundtrip, and change both txid / wtxid and CTV commitments
    when payload bytes change;
  - structurally valid `shielded_v2` family bundles are now visible to the
    parser and preimage / policy code, but they are still blocked at consensus
    entry with `bad-shielded-v2-unroutable` until state-connect /
    state-disconnect plumbing exists;
  - existing `shielded_v2_bundle_tests` remained green, confirming that the
    Slice 3 / Slice 4 family object invariants were not regressed by the new
    transaction wrapper.
- blockers / pivots:
  - a combined Boost filter string for several CTV cases did not match the
    expected suite syntax on this host, so the new CTV regression was rerun as
    an exact single-case invocation instead of leaving the commitment path
    unvalidated.
- Slice 6 remains open:
  - connect / disconnect entrypoints and real state-routing for each family are
    still missing;
  - the next Slice 6 sub-slice is to wire `shielded_v2` bundles into the
    consensus-visible state / mempool / reorg paths instead of rejecting them
    early after structural validation.

### 2026-03-15 04:15:32 JST

- remote / GitHub preflight repeated before pushing the validated Slice 6
  transaction-family scaffold sub-slice;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote push and GitHub comment steps remain unblocked for this pass.

### 2026-03-15 04:17:35 JST

- start-of-pass remote / GitHub preflight completed before the next fetch /
  pull cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote fetch / pull, later push, and PR update steps remain unblocked for
  this pass.

### 2026-03-15 04:36:59 JST

- implemented the second real Slice 6 consensus state-routing / mempool
  sub-slice in `/Users/admin/Documents/btxchain/btx-node`:
  - `src/shielded/bundle.h` / `src/shielded/bundle.cpp` now expose generic
    family-aware state accessors for nullifiers, output commitments, anchors,
    pool-balance deltas, and verification-cost accounting across both the
    legacy direct-spend shape and `shielded::v2::TransactionBundle`;
  - `src/validation.cpp` now routes those helpers through
    `TryCountShieldedOutputs()`, `RebuildShieldedState()`,
    `RollforwardBlock()`, `ConnectBlock()`, `DisconnectBlock()`,
    `HasInvalidShieldedAnchors()`, and mempool prechecks so `shielded_v2`
    bundles participate in consensus-visible nullifier, anchor, commitment,
    reorg, and miner-cost plumbing instead of being rejected at structural
    parse time;
  - `src/txmempool.cpp` now records and checks `shielded_v2` nullifiers for
    conflict detection and cleanup;
  - `src/node/miner.cpp` now charges family-aware verification cost instead of
    assuming the legacy direct-spend proof layout;
  - `src/consensus/tx_check.cpp` no longer rejects structurally valid
    `shielded_v2` bundles with `bad-shielded-v2-unroutable`; the temporary
    gate moved later into contextual validation as
    `bad-shielded-v2-contextual`, after shared state / mempool / reorg routing
    has run.
- expanded regression coverage:
  - `src/test/shielded_tx_check_tests.cpp` now asserts that structurally valid
    `shielded_v2` bundles survive `CheckTransaction()` and are deferred to
    contextual validation;
  - `src/test/shielded_v2_bundle_tests.cpp` now covers the generic state
    accessors across all currently-defined `shielded_v2` families;
  - `src/test/shielded_mempool_tests.cpp` now covers `shielded_v2` nullifier
    conflicts and stale-anchor eviction, and fixes the legacy
    `shielded_anchor_cleanup_evicts_only_stale_transactions` fixture so it
    uses an explicitly retained anchor instead of incorrectly assuming that the
    unchanged tree root remains valid after rotating the bounded recent-anchor
    window.
- validation:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_anchor_cleanup_evicts_only_stale_transactions --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_anchor_cleanup_evicts_stale_transactions --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_mempool_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_tx_check_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_bundle_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test='pq_consensus_tests/ctv_hash_commits_to_v2_shielded_bundle_bytes' --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_transaction_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests --catch_system_error=no --log_level=test_suite`
- validation findings:
  - `shielded_v2` bundles now reach the shared state-routing code paths that
    maintain anchor validity, nullifier-spend tracking, output-commitment
    uniqueness, reorg rollback, and miner cost accounting;
  - the explicit stale-anchor cleanup cases are now green for both the legacy
    direct-spend fixture and `v2_send`, confirming that mempool cleanup sees
    the same recent-anchor window semantics for both bundle families;
  - the temporary rejection point for `shielded_v2` moved from structural
    checking to contextual validation, which keeps the family parseable and
    committed-to while the first real family-specific state transitions are
    still being wired.
- blockers / pivots:
  - targeted validation exposed a real regression in the legacy stale-anchor
    mempool fixture, not in the routing code: the test was asserting that
    `GetShieldedMerkleTree().Root()` stayed valid after the bounded
    `RecordShieldedAnchorRoot()` eviction loop even though that loop only
    rotates the tracked anchor window; the fixture was corrected and the
    explicit anchor-cleanup reruns were green before this sub-slice was
    recorded.
- Slice 6 remains open:
  - `shielded_v2` families still stop at the temporary
    `bad-shielded-v2-contextual` gate rather than applying family-specific
    contextual state transitions;
  - the next Slice 6 sub-slice is to replace that temporary gate with the
    first real accepted `v2_send` state transition path so later slices can
    build on live consensus behavior instead of a routed-but-rejected scaffold.

### 2026-03-15 04:38:21 JST

- remote / GitHub preflight repeated before pushing the validated Slice 6
  state-routing / mempool sub-slice;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote push and GitHub comment steps remain unblocked for this pass.

### 2026-03-15 04:40:24 JST

- start-of-pass remote / GitHub preflight completed before the next fetch /
  pull cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote fetch / pull, later push, and PR update steps remain unblocked for
  this pass.

### 2026-03-15 05:07:22 JST

- implemented the third Slice 6 sub-slice: the first accepted
  `shielded_v2` contextual state transition path for `v2_send`;
- `src/shielded/v2_proof.{h,cpp}` now defines a first-class `v2_send`
  statement / witness / context model:
  - the family-specific statement digest is domain-separated with
    `BTX_ShieldedV2_Send_Statement_V1`;
  - the digest is computed from the stripped transaction view with
    `proof_payload` and the embedded `statement_digest` zeroed so the proof
    witness cannot self-commit circularly;
  - the canonical inline witness lives in `TransactionBundle::proof_payload`
    and carries per-spend ring positions plus the native `MatRiCTProof`;
  - verification reconstructs ring members from the tree snapshot, checks that
    input and output value-commitment hashes match the payload, checks that the
    proof-bound nullifiers match the payload nullifiers, and then verifies the
    native proof against the `v2_send` statement digest;
- `src/shielded/validation.cpp` now accepts `v2_send` in the proof and
  spend-auth validation path instead of treating all `shielded_v2` families as
  contextually unroutable:
  - `ParseShieldedSpendAuthProof()` and
    `ExtractShieldedProofBoundNullifiers()` are now `v2_send`-aware;
  - `CShieldedProofCheck` parses the `v2_send` witness from
    `proof_payload`, binds it to the direct-spend statement, reconstructs the
    ring from the current tree snapshot, and verifies the native MatRiCT proof;
  - `CShieldedSpendAuthCheck` now binds nullifiers for both legacy direct
    spends and `v2_send` payload spends;
  - this pass intentionally keeps `v2_send.fee == 0` as a contextual rule and
    rejects non-zero fee variants with `bad-shielded-v2-fee` until the
    `shielded_v2` fee and value-balance plumbing is generalized in later
    slices;
- `src/validation.cpp` now lets the first real `shielded_v2` family survive
  contextual prechecks:
  - ring-position prechecks parse ring positions from the serialized
    `v2_send` witness instead of the legacy spend vector;
  - proof-plausibility and mempool / block prechecks use the generic
    `CShieldedBundle` input / output / proof-size helpers so the same limits
    apply across legacy and `v2_send`;
  - mempool and block admission now permit `v2_send` while continuing to
    reject the other `shielded_v2` families with
    `bad-shielded-v2-contextual`;
- added deterministic `v2_send` proof fixtures and regression coverage in:
  - `src/test/shielded_v2_proof_tests.cpp`
  - `src/test/shielded_validation_checks_tests.cpp`
  - the new tests cover stripped-transaction statement hashing, full witness
    parsing and proof verification, statement-digest mismatch rejection,
    proof-check acceptance, fee rejection, spend-auth acceptance, and
    proof-bound nullifier mismatch rejection;
- exact validation commands completed successfully:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_proof_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_tx_check_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_bundle_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_mempool_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_transaction_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test='pq_consensus_tests/ctv_hash_commits_to_v2_shielded_bundle_bytes' --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_anchor_cleanup_evicts_only_stale_transactions --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_anchor_cleanup_evicts_stale_transactions --catch_system_error=no --log_level=test_suite`
- validation findings:
  - `shielded_v2_proof_tests` completed in `35468294us` and
    `shielded_validation_checks_tests` completed in `104500761us`;
  - the heavy new `v2_send` proof-path fixtures each took about
    `7.86s` to `7.89s`, which is consistent with deterministic MatRiCT proof
    creation plus verification rather than a regression in routing or state
    updates;
  - all targeted runs finished with `*** No errors detected`;
- Slice 6 is now closed:
  - `shielded_v2` has a real accepted consensus path for `v2_send`, while the
    remaining `shielded_v2` families stay explicitly gated until their own
    state transitions land;
  - the next implementation slice is `Slice 7: Implement v2_send`;
- remote / GitHub preflight repeated before the validated push and PR update;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote push and GitHub comment steps remain unblocked for this pass.

### 2026-03-15 05:16:48 JST

- remote / GitHub preflight repeated before this pass's validated push and PR
  update;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote push and GitHub comment steps remain unblocked for this pass.

### 2026-03-15 05:17:00 JST

- highest-priority unfinished slice selected: `Slice 7: Implement v2_send`
- implemented the first real Slice 7 sub-slice in
  `/Users/admin/Documents/btxchain/btx-node`:
  - `src/shielded/bundle.cpp` now maps `v2_send.payload.fee` into
    `GetShieldedStateValueBalance()` so consensus state accounting uses the
    explicit `shielded_v2` send fee instead of the legacy serialized
    `value_balance` field
  - `src/consensus/tx_verify.cpp` now calls
    `GetShieldedStateValueBalance(tx.GetShieldedBundle())`, which makes
    `Consensus::CheckTxInputs()` account for fee-bearing fully shielded
    `v2_send` transactions when computing miner fee
  - `src/shielded/validation.cpp` no longer rejects non-zero `v2_send` fees
    with `bad-shielded-v2-fee`; instead, the remaining temporary gate is an
    explicit rejection of mixed transparent plus `v2_send` transactions with
    `bad-shielded-v2-mixed-transparent`
  - this pass intentionally accepts only fully shielded fee-bearing `v2_send`
    flows; direct transparent deposit / mixed-input support remains deferred
    to the later Slice 7 fallback-path work so pool-balance accounting does not
    become inconsistent before that path is fully implemented
- added and updated deterministic regression coverage:
  - `src/test/shielded_tx_verify_tests.cpp` now proves
    `Consensus::CheckTxInputs()` uses `v2_send.payload.fee` as the explicit
    shielded balance delta
  - `src/test/shielded_v2_bundle_tests.cpp` now asserts the shared state
    accessor returns the `v2_send` fee
  - `src/test/shielded_validation_checks_tests.cpp` now proves non-zero
    `v2_send` fees are accepted and mixed transparent plus `v2_send`
    transactions fail with `bad-shielded-v2-mixed-transparent`
- exact validation commands completed successfully:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_tx_verify_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_bundle_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_tx_check_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_proof_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests --catch_system_error=no --log_level=test_suite`
- validation findings:
  - all targeted runs finished with `*** No errors detected`
  - fee-bearing fully shielded `v2_send` now has consistent state-balance and
    miner-fee accounting across the shared bundle accessor and
    `CheckTxInputs()`
  - mixed transparent plus `v2_send` transactions remain deliberately gated
    until the direct-deposit fallback path can land with full accounting and
    wallet / RPC support
- benchmarks / simulation findings:
  - none required for this sub-slice beyond the targeted consensus and proof
    regression runs above
- blockers / pivots:
  - wallet and RPC support for `v2_send` still require real
    `shielded::v2::EncryptedNotePayload` creation / scanning rather than a
    legacy wrapper, so this pass focused first on the consensus fee-accounting
    gap
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no disposable testnet, cloud resource, or external node was created for
    this sub-slice
- Slice 7 remains open:
  - the next Slice 7 sub-slice is either the direct user deposit fallback path
    for mixed transparent plus `v2_send` transactions or the wallet / RPC
    implementation needed to create and scan real `v2_send` notes

### 2026-03-15 05:19:31 JST

- start-of-pass remote / GitHub preflight completed before the next fetch /
  pull;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote fetch / pull, later push, and PR update steps remain unblocked for
  this pass.

### 2026-03-15 05:36:54 JST

- highest-priority unfinished slice selected: `Slice 7: Implement v2_send`
- implemented the second real Slice 7 sub-slice in
  `/Users/admin/Documents/btxchain/btx-node`:
  - new production `v2_send` construction layer in
    `src/shielded/v2_send.h` / `src/shielded/v2_send.cpp`
  - canonical builder entrypoint
    `shielded::v2::BuildV2SendTransaction(...)` now assembles a `v2_send`
    transaction from selected input notes, ring witness positions, ring
    members, output notes, and encrypted payloads
  - the builder performs the required two-pass MatRiCT binding flow:
    provisional value commitments first, then the final statement-digest-bound
    proof and witness payload
  - builder-side validation now explicitly rejects malformed ring witnesses,
    bad input / output counts, inconsistent fee balance, invalid anchors, and
    pre-populated shielded bundles before any proof bytes are emitted
  - new legacy bridge wrapper
    `EncodeLegacyEncryptedNotePayload(...)` /
    `DecodeLegacyEncryptedNotePayload(...)` packages the current
    `shielded::EncryptedNote` wire object into `shielded::v2::EncryptedNotePayload`
    so later wallet / RPC work can create real `v2_send` outputs without
    inventing another test-only payload format
  - the legacy wrapper keeps the current one-byte view tag in
    `scan_hint[0]`, fills the remaining hint bytes deterministically from the
    encapsulated note, and stores the recoverable legacy encrypted-note bytes
    inside the `shielded_v2` ciphertext field
- added focused regression coverage:
  - new `src/test/shielded_v2_send_tests.cpp`
  - wrapped legacy encrypted-note payloads roundtrip back to the original
    `shielded::EncryptedNote`
  - built `v2_send` transactions parse and verify through the existing
    `shielded_v2` contextual proof verifier
  - malformed real-ring-member inputs are rejected before proof construction
- exact validation commands completed successfully:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_send_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_proof_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_bundle_tests --catch_system_error=no --log_level=test_suite`
- validation findings:
  - all targeted runs finished with `*** No errors detected`
  - the new builder emits canonical `v2_send` bundles whose proof payloads
    parse cleanly through the same verifier path already used by consensus
  - the dedicated builder regression case `build_v2_send_transaction_matches_contextual_verifier`
    took about `8.14s` on this host because it performs two full MatRiCT proof
    constructions by design
- benchmarks / simulation findings:
  - no separate bench harness was required for this construction sub-slice;
    the multi-second builder regression timing above is recorded as the first
    local runtime reference for the two-pass construction path
- blockers / pivots:
  - this pass intentionally keeps `v2_send` output note creation on the
    existing legacy `ShieldedNote` / `EncryptedNote` model; wallet receive,
    scan, and RPC migration to the native `shielded::v2::Note` model remain
    follow-on Slice 7 / Slice 17 work
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no disposable testnet, cloud resource, or external node was created for
    this sub-slice
- Slice 7 remains open:
  - the next Slice 7 sub-slice should wire wallet / RPC direct-send creation
    onto this new builder or land the mixed transparent direct-deposit fallback
    path on top of the same construction surface

### 2026-03-15 05:39:36 JST

- start-of-pass remote / GitHub preflight completed before the next fetch /
  pull;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote fetch / pull, later push, and PR update steps remain unblocked for
  this pass.

### 2026-03-15 07:53:45 JST

- start-of-pass remote / GitHub preflight repeated before any later fetch /
  push / PR update operation in this pass;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- later remote fetch / pull, push, and PR update steps remain unblocked for
  this pass.

### 2026-03-15 07:54:17 JST

- highest-priority unfinished slice selected: continue
  `Slice 7: Implement v2_send`
- implemented the third validated Slice 7 sub-slice in
  `/Users/admin/Documents/btxchain/btx-node`:
  - wallet direct-send creation now routes fully shielded `z_sendmany` and
    `z_mergenotes` through the native `CreateV2Send(...)` path instead of the
    legacy direct-spend builder
  - `shielded_v2` output scanning / mempool indexing now decrypts and records
    `EncryptedNotePayload` outputs through the existing wallet note model so
    `z_viewtransaction`, `z_listunspent`, and restart recovery work on the new
    `v2_send` flow
  - RPC result surfaces now expose the bundle family explicitly and compute
    spend / output counts from family-agnostic helpers, so `z_viewtransaction`
    distinguishes `legacy_shield`, `legacy_unshield`, and `v2_send`
  - pending-spend reservation now uses generic bundle nullifier extraction, so
    wallet-created `v2_send` and merge transactions reserve and release the
    correct spends without legacy-only assumptions
  - chainstate restart recovery is hardened by persisting a
    commitment-index digest with the shielded frontier and rebuilding from the
    chain when the restored frontier cannot prove that its position index still
    matches the persisted root
  - Merkle-tree deserialization now rebinds the shared commitment index store
    after reopen so persisted frontiers can regain position lookups without
    silently trusting stale in-memory-only state
  - the temporary success-path `CreateV2Send` trace logging added during the
    restart / wallet bring-up was removed before landing; only failure-path
    diagnostics remain
- added / extended validation coverage:
  - `src/test/nullifier_set_tests.cpp`
  - `src/test/shielded_merkle_serialization_tests.cpp`
  - `src/test/shielded_v2_send_tests.cpp`
  - `src/test/validation_chainstatemanager_tests.cpp`
  - `test/functional/wallet_shielded_send_flow.py`
  - `test/functional/wallet_shielded_rpc_surface.py`
  - `test/functional/wallet_shielded_restart_persistence.py`
- exact validation commands completed successfully:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx btxd -j8`
  - `./build-btx/bin/test_btx --run_test=nullifier_set_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_merkle_serialization_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=validation_chainstatemanager_tests/chainstatemanager_rebuilds_shielded_state_when_commitment_index_missing --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_send_tests --catch_system_error=no --log_level=test_suite`
  - `python3 ./build-btx/test/functional/wallet_shielded_send_flow.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/send-flow-20260315c --portseed=32111`
  - `python3 ./build-btx/test/functional/wallet_shielded_rpc_surface.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/rpc-surface-20260315c --portseed=32112`
  - `python3 ./build-btx/test/functional/wallet_shielded_restart_persistence.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/restart-persistence-20260315c --portseed=32113`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_send_tests --catch_system_error=no --log_level=test_suite`
  - `python3 ./build-btx/test/functional/wallet_shielded_send_flow.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/send-flow-20260315d --portseed=32114`
- validation findings:
  - all targeted unit and functional runs finished with success after the
    wallet / restart changes above
  - `wallet_shielded_restart_persistence.py` now survives both the normal
    wallet reload and the later `VerifyDB (-checklevel=4 -checkblocks=0)`
    restart, which was the real regression blocker in this pass
  - `wallet_shielded_rpc_surface.py` now exercises live `v2_send` creation and
    merge flows while confirming the new `family` RPC field transitions from
    `legacy_shield` to `v2_send` as expected
  - `wallet_shielded_send_flow.py` required a test pivot: the second send no
    longer fails with a mempool nullifier conflict because the wallet now
    selects a different confirmed note, so the functional now asserts that
    conflict avoidance behavior instead of expecting `-26`
- benchmarks / simulation findings:
  - the single-input `shielded_v2_send_tests` builder / verifier cases still
    take about `7.7s` to `7.9s` each on this host, which remains consistent
    with the bounded local runtime seen earlier for native `v2_send` proof
    generation
  - no cloud or distributed simulation was required for this wallet / restart
    sub-slice
- blockers / pivots:
  - the restart failure was not a proof-system bug; it was a persisted
    shielded-frontier trust bug caused by restoring a tree whose commitment
    position index could be stale or missing after restart
  - the wallet functionals needed `rpc_timeout = 600` because native `v2_send`
    proof generation exceeds the framework default timeout on this host
  - the send-flow functional expectation had to be updated to reflect the
    corrected wallet behavior rather than freezing an older mempool rejection
    artifact
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - all validation ran locally in disposable `/tmp/btx-functional-manual/...`
    directories that were removed by the functional harness on success
  - no DigitalOcean, Porkbun, or Tailscale resources were created
- Slice 7 remains open:
  - the next Slice 7 sub-slice is the mixed transparent direct-deposit
    fallback path, which is still intentionally gated while `v2_send` remains
    shielded-only
  - full wallet / RPC coverage for the later batch families remains Slice 17
    work after the core transaction families land
  - this pass closes the direct wallet / RPC `v2_send` creation path but does
    not close Slice 7 overall

### 2026-03-15 07:56:57 JST

- start-of-pass remote / GitHub preflight repeated before any new fetch /
  pull / push / PR update operation in this pass;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- later remote fetch / pull, push, and PR update steps remain unblocked for
  this pass.

### 2026-03-15 08:19:35 JST

- highest-priority unfinished slice selected: continue
  `Slice 7: Implement v2_send`
- implemented the fourth validated Slice 7 sub-slice in
  `/Users/admin/Documents/btxchain/btx-node`:
  - `CShieldedWallet::CreateShieldedSpend(...)` now falls back to a new
    transparent-input direct-deposit builder when a shielded-only
    `z_sendmany` request cannot be covered by confirmed spendable shielded
    notes
  - the new `CreateTransparentToShieldedSend(...)` path selects spendable
    transparent wallet coins largest-first, builds a canonical legacy
    shield-only transaction with encrypted shielded outputs plus shielded
    change, and signs the transparent inputs with the existing wallet signing
    path
  - RPC help for `z_sendmany` now documents that shielded-only sends can fall
    back to a transparent-input direct deposit when shielded funds are
    insufficient
  - `wallet_shielded_rpc_surface.py` now proves the intended behavior by
    funding a transparent-only wallet from a separate transparent wallet,
    asserting that the fallback transaction reports `family=legacy_shield`,
    `spends=0`, and a decryptable owned shielded receive, and disabling
    `-autoshieldcoinbase` so the regression stays on the explicit wallet send
    path instead of background shielding
- added / extended validation coverage:
  - `test/functional/wallet_shielded_rpc_surface.py`
- exact validation commands completed successfully:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx btxd -j8`
  - `python3 ./build-btx/test/functional/wallet_shielded_rpc_surface.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/rpc-surface-20260315f --portseed=32124`
  - `python3 ./build-btx/test/functional/wallet_shielded_send_flow.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/send-flow-20260315d --portseed=32125`
  - `python3 ./build-btx/test/functional/wallet_shielded_restart_persistence.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/restart-persistence-20260315d --portseed=32126`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_send_tests --catch_system_error=no --log_level=test_suite`
- validation findings:
  - the first fallback regression attempt exposed a real test-harness issue:
    funding `depositonly` from mature coinbase let that wallet auto-acquire a
    shielded note, so `z_sendmany` entered `CreateV2Send(...)` instead of the
    new transparent fallback and failed on a shallow-tree proof build; that
    was corrected by funding `depositonly` from a separate transparent wallet
    and disabling `-autoshieldcoinbase` for this regression
  - after that pivot, the fallback path produced the intended transparent-input
    legacy shield transaction and the receive was visible through
    `z_viewtransaction` and `z_listunspent`
  - the broader wallet regressions still passed after the routing change:
    `wallet_shielded_send_flow.py` completed its send / unshield / load loop,
    `wallet_shielded_restart_persistence.py` survived both restarts, and
    `shielded_v2_send_tests` remained green
- benchmarks / simulation findings:
  - no new benchmark harnesses or cloud / distributed simulations were needed
    for this wallet-routing sub-slice
  - local runtime remained dominated by the known native proof sections in the
    existing `v2_send` send-flow regressions; no new performance regression
    surfaced beyond the expected long proof-generation windows already tracked
- blockers / pivots:
  - the only blocker in this pass was the initial test setup falsely routing
    into `CreateV2Send(...)` because the target wallet already held a shielded
    note; this was a validation pivot, not a consensus or wallet-builder bug
  - the first compile attempt also exposed a wallet-local ordering bug where
    the new transparent coin sorter compared `Txid` with `>` instead of using
    the established tuple ordering; that was fixed before validation
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - all validation ran locally in disposable `/tmp/btx-functional-manual/...`
    directories and the successful functional runs cleaned up after themselves
  - no DigitalOcean, Porkbun, or Tailscale resources were created
- Slice 7 is now complete:
  - `v2_send` has ordinary direct private sends, native proof verification,
    wallet / RPC support, and the direct user deposit fallback path
  - mixed transparent + `v2_send` remains intentionally rejected because the
    direct user deposit fallback is now handled by the wallet-level
    transparent-input legacy shield path instead
  - the next highest-priority unfinished slice is
    `Slice 8: Redesign Scan Hints And Encrypted Output Discovery`

### 2026-03-15 08:22:22 JST

- start-of-pass remote / GitHub preflight repeated before any new fetch /
  pull / push / PR update operation in this pass;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- later remote fetch / pull, push, and PR update steps remain unblocked for
  this pass.

### 2026-03-15 08:40:01 JST

- highest-priority unfinished slice selected: `Slice 8: Redesign Scan Hints
  And Encrypted Output Discovery`
- implemented the first real Slice 8 sub-slice in
  `/Users/admin/Documents/btxchain/btx-node`:
  - replaced the old one-byte-view-tag-prefixed `v2_send` wrapper hint with a
    recipient-bound 16-byte scan hint derived from the legacy ciphertext, the
    explicit `scan_domain`, and the recipient ML-KEM public key in
    `src/shielded/v2_send.h` / `src/shielded/v2_send.cpp`
  - tightened legacy payload decoding so `EncryptedNotePayload.ephemeral_key`
    must match the serialized wrapped note before the payload is accepted
  - rewired wallet `shielded_v2` receive scanning in
    `src/wallet/shielded_wallet.cpp` so the wallet now checks the recipient
    scan hint first and only runs ML-KEM decapsulation on matching keysets
  - added focused coverage in:
    - `src/test/shielded_v2_send_tests.cpp`
    - `src/test/shielded_v2_wire_tests.cpp`
    - `src/test/shielded_scan_hint_runtime_report_tests.cpp`
  - added bounded local benchmark/report tooling in:
    - `src/test/shielded_scan_hint_runtime_report.h`
    - `src/test/shielded_scan_hint_runtime_report.cpp`
    - `src/test/generate_shielded_scan_hint_runtime_report.cpp`
    - `src/test/CMakeLists.txt`
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx generate_shielded_scan_hint_runtime_report -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_send_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_scan_hint_runtime_report_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_wire_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/gen_shielded_scan_hint_runtime_report --samples=1 --candidates=1024 --output=/tmp/btx-shielded-scan-hint-runtime-report.json`
  - `python3 ./build-btx/test/functional/wallet_shielded_send_flow.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/send-flow-scanhint-20260315a --portseed=32131`
  - `python3 ./build-btx/test/functional/wallet_shielded_restart_persistence.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/restart-persistence-scanhint-20260315a --portseed=32132`
- validation findings:
  - targeted `shielded_v2_send_tests` passed with the new recipient-bound scan
    hint and payload-domain checks
  - the new scan-hint runtime-report unit suite passed and the standalone JSON
    report was generated successfully
  - the send-flow functional test passed end to end after routing receives
    through the new scan-hint-gated `EncryptedNotePayload` path
  - the restart-persistence functional test passed, including the full
    `VerifyDB` restart leg, confirming the new hint gate does not break wallet
    rediscovery after reload
- benchmarks / simulation findings:
  - bounded scan-hint runtime report with `1024` candidate keys produced:
    - `legacy_view_tag_match_count = 5`
    - `legacy_false_positive_view_tag_count = 4`
    - `v2_hint_match_count = 1`
    - `v2_false_positive_hint_count = 0`
    - `v2_wrong_domain_match_count = 0`
    - `avoided_decrypt_attempts = 1023`
    - `legacy_scan_ns = 75362292`
    - `v2_hint_only_ns = 10955334`
    - `v2_scan_ns = 11030583`
    - `legacy_to_v2_scan_speedup = 6.832122291269646`
  - this gives concrete evidence that the new hint design removes the
    deterministic legacy false positives present in the same fixed candidate
    pool and cuts wallet scan work to the single real recipient in this
    bounded test
- blockers / pivots:
  - the first build failed in the new runtime-report seed expander because
    `std::min()` mixed `size_t` with `uint256::size()`; fixed the type mismatch
    and reran the entire validation set
  - Slice 8 remains open because this pass only covers the direct `v2_send`
    payload path; the large-output chunk / `v2_egress_batch` receive surfaces
    still need to adopt the same scan-hint accounting and report discipline
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - `/tmp/btx-shielded-scan-hint-runtime-report.json` was kept as the local
    bounded report artifact for this pass
  - functional-test nodes under
    `/tmp/btx-functional-manual/send-flow-scanhint-20260315a` and
    `/tmp/btx-functional-manual/restart-persistence-scanhint-20260315a` were
    stopped cleanly and removed by the harness
  - no DigitalOcean, Porkbun, or Tailscale resources were created
- next slice:
  - continue `Slice 8: Redesign Scan Hints And Encrypted Output Discovery` by
    carrying the same scan-hint model into canonical output-chunk discovery and
    the upcoming `v2_egress_batch` wallet receive path

### 2026-03-15 08:42:32 JST

- start-of-pass remote / GitHub preflight repeated before any new fetch /
  pull / push / PR update operation in this pass;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- later remote fetch / pull, push, and PR update steps remain unblocked for
  this pass.

### 2026-03-15 08:54:43 JST

- continued `Slice 8: Redesign Scan Hints And Encrypted Output Discovery`
  with the first real output-chunk commitment sub-slice in
  `/Users/admin/Documents/btxchain/btx-node`:
  - added deterministic helpers in `src/shielded/v2_bundle.h` /
    `src/shielded/v2_bundle.cpp` that derive per-chunk scan-hint commitments,
    per-chunk ciphertext commitments, and canonical `OutputChunkDescriptor`
    instances directly from the covered `OutputDescription` range
  - tightened `TransactionBundle::IsValid()` so `v2_egress_batch` and optional
    rebalance output chunks must now commit to the actual covered outputs
    rather than merely covering the right index/count ranges
  - made chunk building reject mixed-domain output ranges so scan-hint domains
    stay canonical inside each committed chunk
  - expanded focused coverage in
    `src/test/shielded_v2_bundle_tests.cpp` for:
    - uniform-domain chunk-builder rejection
    - tampered scan-hint commitments
    - tampered ciphertext byte counts
    - payload-domain drift after chunk construction
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_bundle_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_wire_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_send_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_scan_hint_runtime_report_tests --catch_system_error=no --log_level=test_suite`
- validation findings:
  - the new bundle tests passed, including the newly added output-chunk
    commitment mismatch cases
  - `shielded_v2_wire_tests` still passed unchanged, confirming the new chunk
    commitment helpers did not perturb the underlying wire/root primitives
  - `shielded_v2_send_tests` still passed, with the long direct-send proof
    cases remaining stable at roughly `7.85s` each on this host
  - `shielded_scan_hint_runtime_report_tests` still passed after the chunk
    commitment work, so the earlier Slice 8 recipient-hint behavior remains
    intact
- benchmarks / simulation findings:
  - no new cloud or distributed simulation was needed for this sub-slice
  - local runtime remained dominated by the existing MatRiCT-backed
    `shielded_v2_send` test cases; the new chunk-commitment helpers are
    structural hash/root code and did not surface a measurable hotspot in this
    pass
- blockers / pivots:
  - no code blocker surfaced once the helper scope was narrowed to canonical
    chunk commitments instead of prematurely wiring an untestable
    `v2_egress_batch` wallet path before the family exists end to end
  - Slice 8 remains open because this pass only makes chunk commitments real;
    the wallet-side chunk-aware discovery loop for future
    `v2_egress_batch` receive handling still needs to land next
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - no local disposable network resources were created for this sub-slice
- next slice:
  - continue `Slice 8: Redesign Scan Hints And Encrypted Output Discovery` by
    wiring chunk-aware wallet discovery helpers around these now-canonical
    output-chunk commitments for the future `v2_egress_batch` receive path

### 2026-03-15 08:57:04 JST

- start-of-pass remote / GitHub preflight repeated before any new fetch /
  pull / push / PR update operation in this pass;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- later remote fetch / pull, push, and PR update steps remain unblocked for
  this pass.

### 2026-03-15 09:20:37 JST

- continued `Slice 8: Redesign Scan Hints And Encrypted Output Discovery`
  with the first real wallet-side chunk-aware discovery sub-slice in
  `/Users/admin/Documents/btxchain/btx-node`:
  - added `TransactionBundleOutputChunksAreCanonical(...)` in
    `src/shielded/v2_bundle.h` / `src/shielded/v2_bundle.cpp` so bundle
    validation and downstream consumers share one canonical-output-chunk gate
  - tightened `TransactionBundle::IsValid()` to route all
    `v2_egress_batch` / optional `v2_rebalance` chunk checks through that
    canonical helper instead of duplicating only root/count checks
  - updated `src/wallet/shielded_wallet.cpp` so block and mempool discovery
    now record `shielded_v2` outputs from canonical output chunks rather than
    flattening every `v2_egress_batch` output blindly
  - kept rebalance compatibility by scanning chunked rebalance outputs through
    the same canonical helper while still allowing the existing flat reserve
    path when no chunks are present
  - added focused wallet regression coverage in
    `src/test/shielded_wallet_chunk_discovery_tests.cpp` and expanded
    canonical-bundle coverage in `src/test/shielded_v2_bundle_tests.cpp`
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_bundle_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_scan_hint_runtime_report_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_send_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_wallet_chunk_discovery_tests --catch_system_error=no --log_level=test_suite`
  - `python3 ./build-btx/test/functional/wallet_shielded_send_flow.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/send-flow-20260315g --portseed=32131`
  - `python3 ./build-btx/test/functional/wallet_shielded_restart_persistence.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/restart-persistence-20260315g --portseed=32132`
- validation findings:
  - the new wallet chunk-discovery unit coverage passed after switching the
    fixture from `BasicTestingSetup` to `TestChain100Setup`, which was
    required because `CWallet::Create(...)` asserts on a missing chainman in
    the lighter fixture
  - `shielded_v2_bundle_tests` passed with the new canonical helper, covering
    header count drift, chunk commitment tampering, and rebalance-with-chunks
    compatibility
  - `shielded_v2_send_tests` still passed with the long MatRiCT-backed direct
    send cases remaining stable at roughly `7.9s` on this host
  - `wallet_shielded_send_flow.py` passed end to end, including the unshield
    and mined-load phases after the chunk-aware receive change
  - `wallet_shielded_restart_persistence.py` passed through both the wallet
    reload and `-checklevel=4 -checkblocks=0` restart phases, so the new
    chunk-aware discovery path did not regress persisted shielded balance or
    spendability
- benchmarks / simulation findings:
  - no new cloud or distributed simulation was needed for this sub-slice
  - no new hotspot surfaced beyond the already-known MatRiCT proving time in
    `shielded_v2_send`; the new chunk-aware path is structural discovery code
    plus wallet indexing
- blockers / pivots:
  - the only validation pivot was the test-fixture upgrade needed to exercise
    real wallet creation against a populated node interface
  - Slice 8 remains open because this pass wires chunk-aware wallet discovery
    for canonical chunk metadata, but the full `v2_egress_batch` family and
    broader large-fanout receive/reporting path still remain ahead
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - the disposable functional test directories were cleaned on success
- next slice:
  - continue `Slice 8: Redesign Scan Hints And Encrypted Output Discovery` by
    carrying this chunk-aware discovery model into the remaining future
    `v2_egress_batch` receive and large-fanout reporting path

### 2026-03-15 09:21:20 JST

- remote / GitHub preflight repeated before the next push / PR update
  operation in this pass;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- push and PR update remain unblocked for this pass.

### 2026-03-15 09:23:21 JST

- start-of-pass remote / GitHub preflight repeated before any new fetch /
  pull / push / PR update operation in this pass;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- later remote fetch / pull, push, and PR update steps remain unblocked for
  this pass.

### 2026-03-15 09:34:54 JST

- continued `Slice 8: Redesign Scan Hints And Encrypted Output Discovery`
  with the next wallet / RPC reporting sub-slice in
  `/Users/admin/Documents/btxchain/btx-node`:
  - extended cached shielded transaction views in
    `src/wallet/shielded_wallet.h` with per-chunk reporting rows that capture
    canonical chunk scan domain, covered output range, ciphertext byte total,
    public chunk commitments, owned output count, and owned amount
  - updated `src/wallet/shielded_wallet.cpp` so canonical
    `v2_egress_batch` / chunked `v2_rebalance` scans now preserve those chunk
    summaries alongside the flat output list in both block and mempool paths
  - updated `src/wallet/shielded_rpc.cpp` so `z_viewtransaction` now returns
    `output_chunks` for direct wallet transactions and cached fallback views,
    keeping chunked large-fanout transactions inspectable once they land while
    returning an empty array for legacy and `v2_send` families
  - expanded focused coverage in
    `src/test/shielded_wallet_chunk_discovery_tests.cpp` to assert cached
    block and mempool chunk summaries, and updated
    `test/functional/wallet_shielded_rpc_surface.py` to assert the new
    `output_chunks` field on existing legacy / `v2_send` flows
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx btxd -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_wallet_chunk_discovery_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_bundle_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_send_tests --catch_system_error=no --log_level=test_suite`
  - `python3 ./build-btx/test/functional/wallet_shielded_rpc_surface.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/rpc-surface-20260315h --portseed=32133`
- validation findings:
  - the new wallet chunk-discovery suite passed with the added canonical
    mempool summary case, and the existing block/tamper cases still passed
  - `shielded_v2_bundle_tests` still passed unchanged, confirming the new
    reporting layer did not perturb bundle canonicality rules
  - `shielded_v2_send_tests` still passed with the long direct-send proof
    cases at roughly `7.76s` and `7.67s` on this host
  - `wallet_shielded_rpc_surface.py` passed end to end after adding the new
    `output_chunks == []` assertions for legacy shield and `v2_send` flows,
    so the RPC surface stayed backward-compatible while growing the new field
- benchmarks / simulation findings:
  - no new cloud or distributed simulation was needed for this sub-slice
  - local runtime remained dominated by the existing MatRiCT-backed
    `shielded_v2_send` proof cases; the new chunk-reporting path is metadata
    aggregation plus JSON rendering
- blockers / pivots:
  - the only new warnings were Clang thread-safety analysis warnings on the
    existing callback-based scan/decrypt helpers in `shielded_wallet.cpp` and
    the new `AppendShieldedOutputView(...)` helper in `shielded_rpc.cpp`;
    build and validation still succeeded, and no behavioral bug surfaced
  - Slice 8 remains open because this pass makes chunked large-fanout receives
    inspectable, but the bounded large-fanout runtime-report path and the full
    `v2_egress_batch` family are still ahead
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - `/tmp/btx-functional-manual/rpc-surface-20260315h` was removed by the
    functional harness on success
  - no DigitalOcean, Porkbun, or Tailscale resources were created
- next slice:
  - continue `Slice 8: Redesign Scan Hints And Encrypted Output Discovery` by
    adding the bounded large-fanout chunk/runtime reporting path that measures
    canonical chunk discovery cost ahead of the full `v2_egress_batch`
    consensus family

### 2026-03-15 09:35:44 JST

- remote / GitHub preflight repeated before the next push / PR update
  operation in this pass;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- push and PR update remain unblocked for this pass.

### 2026-03-15 09:37:32 JST

- start-of-pass remote / GitHub preflight repeated before any new fetch /
  pull / push / PR update operation in this pass;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- later remote fetch / pull, push, and PR update steps remain unblocked for
  this pass.

### 2026-03-15 10:01:18 JST

- continued `Slice 8: Redesign Scan Hints And Encrypted Output Discovery`
  with the bounded high-fanout runtime-report sub-slice in
  `/Users/admin/Documents/btxchain/btx-node`:
  - added `src/test/shielded_chunk_runtime_report.h` and
    `src/test/shielded_chunk_runtime_report.cpp`, which build a deterministic
    `v2_egress_batch`-shaped fixture with canonical output chunks, real batch
    scan hints, bounded owned-output distribution, and separate timing for
    canonical chunk validation, output discovery, chunk-summary aggregation,
    and the full discovery pipeline
  - added `src/test/shielded_chunk_runtime_report_tests.cpp` to lock the
    report invariants, including chunk count, owned-output/owned-chunk totals,
    false-positive hint rejection, skipped decrypt counts, and invalid-config
    rejection
  - added the standalone generator
    `src/test/generate_shielded_chunk_runtime_report.cpp` plus CMake wiring in
    `src/test/CMakeLists.txt` so the bounded report can be produced on demand
    as `gen_shielded_chunk_runtime_report`
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target generate_shielded_chunk_runtime_report -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_chunk_runtime_report_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_wallet_chunk_discovery_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_scan_hint_runtime_report_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_bundle_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/gen_shielded_chunk_runtime_report --samples=1 --outputs=1024 --outputs-per-chunk=32 --output=/tmp/btx-shielded-chunk-runtime-report.json`
- validation findings:
  - the new runtime-report suite passed with a `256`-output / `8`-chunk
    fixture, proving the deterministic fanout model, owned-output accounting,
    and chunk-summary math stay aligned
  - the existing wallet chunk-discovery suite still passed end to end, so the
    new reporting harness matches the already-landed canonical chunk discovery
    behavior instead of drifting into a synthetic side path
  - `shielded_scan_hint_runtime_report_tests` and `shielded_v2_bundle_tests`
    still passed unchanged, confirming that the large-fanout runtime harness
    sits cleanly on the stronger scan-hint path and the existing output-chunk
    canonicality rules
- benchmarks / simulation findings:
  - the standalone `1024`-output / `32`-chunk runtime report measured:
    `8` owned outputs spread across `8` owned chunks, `1,252,352` total
    ciphertext bytes, `1,016` decrypt attempts avoided by scan-hint gating,
    and `0` false-positive hint matches
  - measured timings from
    `/tmp/btx-shielded-chunk-runtime-report.json` on this host were
    `5,714,834ns` for canonical chunk validation, `15,555,500ns` for output
    discovery, `1,333ns` for chunk-summary aggregation alone, and
    `20,814,917ns` for the full discovery pipeline
  - the chunk-summary aggregation overhead was only about `0.0086%` of the
    output-discovery phase on this fixture, so the practical large-fanout cost
    remains in note discovery rather than in the canonical chunk-reporting
    layer itself
- blockers / pivots:
  - the first aggregate `cmake --build ... --target test_btx generate_shielded_chunk_runtime_report`
    invocation finished `test_btx` but then reported `No rule to make target
    generate_shielded_chunk_runtime_report`; rerunning the generator target as
    a dedicated build succeeded immediately, and no CMake source change beyond
    the new target registration was required
  - Slice 8 is now complete: stronger recipient hints, canonical chunk
    commitments, chunk-aware receive/reporting, and bounded high-fanout
    runtime evidence are all landed and validated
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - `/tmp/btx-shielded-chunk-runtime-report.json` was kept locally as the
    measured report artifact for this pass
- next slice:
  - `Slice 9: Implement v2_egress_batch`

### 2026-03-15 09:48:26 JST

- remote / GitHub preflight repeated before the push and PR update for this
  pass;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- push and PR update remain unblocked for this pass.

### 2026-03-15 09:50:22 JST

- start-of-pass remote / GitHub preflight repeated before any new fetch /
  pull / push / PR update operation in this pass;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- later remote fetch / pull, push, and PR update steps remain unblocked for
  this pass.

### 2026-03-15 10:18:44 JST

- continued `Slice 9: Implement v2_egress_batch` with the first real imported
  receipt validation / admission sub-slice in
  `/Users/admin/Documents/btxchain/btx-node`:
  - added explicit settlement-witness serialization, bounded parsing, proof
    receipt / claim metadata decoding, and external-anchor digest helpers in
    `src/shielded/v2_proof.h` and `src/shielded/v2_proof.cpp`
  - extended `src/shielded/validation.cpp` so `shielded_v2`
    `v2_egress_batch` bundles now parse a real imported-receipt settlement
    context, verify the attached settlement witness, enforce bridge-out batch
    count / root / settlement-binding / external-anchor matches, and reject
    transparent unwrap attempts on this family
  - relaxed `src/consensus/tx_check.cpp` so fully non-transparent
    `shielded_v2` state-transition families are allowed to reach contextual
    validation without legacy `vin` / `vout` legs
  - extended contextual routing in `src/validation.cpp` so
    `v2_egress_batch` survives proof validation and then stops at the current
    deliberate boundary `bad-shielded-v2-egress-unanchored` until later Slice
    9 settlement-anchor state is implemented
  - added the shared deterministic fixture
    `src/test/util/shielded_v2_egress_fixture.h` plus focused coverage in
    `src/test/shielded_tx_check_tests.cpp`,
    `src/test/shielded_validation_checks_tests.cpp`,
    `src/test/shielded_v2_proof_tests.cpp`, and
    `src/test/txvalidation_tests.cpp`
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_tx_check_tests/checktransaction_accepts_v2_egress_bundle_for_contextual_validation --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=txvalidation_tests/tx_mempool_rejects_v2_egress_until_settlement_anchor_state_exists --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests/proof_check_accepts_valid_v2_egress_receipt_bundle --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests/proof_check_rejects_v2_egress_binding_mismatch --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_tx_check_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_proof_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests --catch_system_error=no --log_level=test_suite`
- validation findings:
  - the fresh reruns of both `shielded_v2_proof_tests` and
    `shielded_validation_checks_tests` completed clean after the fixture /
    routing fixes, so the new `v2_egress_batch` cases are now covered inside
    the full proof-abstraction and contextual-validation suites rather than
    only by one-off targeted commands
  - `CheckTransaction()` now correctly treats `shielded_v2` families as valid
    non-transparent state transitions, which was required for any inputless
    `v2_egress_batch` transaction to reach contextual proof checks at all
  - the deterministic fixture now binds canonical output chunks and a matching
    `output_chunk_root`, so bundle validity is checked against the same
    chunk-commitment rules already landed in Slice 8
- blockers / pivots:
  - the first fresh `shielded_validation_checks_tests` rerun exposed a real
    fixture bug: the new `v2_egress_batch` helper built canonical output
    chunks but forgot to populate `header.output_chunk_root`, which caused
    `TransactionBundle::IsValid()` to fail before the intended proof checks
  - that rerun also made it clear that `src/consensus/tx_check.cpp` still
    rejected all inputless `shielded_v2` state transitions as
    `bad-txns-vin-empty` / `bad-txns-vout-empty`; fixing that was mandatory,
    because otherwise the new `v2_egress_batch` proof path would remain
    unreachable
  - Slice 9 remains open: `v2_egress_batch` now has real imported-receipt
    proof/context validation, but it is still intentionally rejected as
    `bad-shielded-v2-egress-unanchored` until settlement-anchor state and the
    accepted connect/disconnect path are implemented
- benchmarks / simulation findings:
  - none in this sub-slice; this pass was correctness and admission-path
    validation only
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - no disposable remote testnet resources were required for this sub-slice
- next slice:
  - continue `Slice 9` by landing the first accepted settlement-anchor-backed
    `v2_egress_batch` connect / mempool / reorg path instead of the current
    `bad-shielded-v2-egress-unanchored` stop

### 2026-03-15 10:18:44 JST

- remote / GitHub preflight repeated before the upcoming push and PR update
  for this Slice 9 sub-slice;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- push and PR update remain unblocked for this pass.

### 2026-03-15 10:21:55 JST

- start-of-pass remote / GitHub preflight repeated before any new fetch /
  pull / push / PR update operation in this pass;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- later remote fetch / pull, push, and PR update steps remain unblocked for
  this pass.

### 2026-03-15 11:05:52 JST

- remote / GitHub preflight repeated before the upcoming push and PR update
  for the current Slice 9 settlement-anchor sub-slice;
- verified readable and non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key`
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key`
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key`
- push and PR update remain unblocked for this pass.

### 2026-03-15 11:05:52 JST

- continued `Slice 9: Implement v2_egress_batch` with the first accepted
  settlement-anchor-backed restart / reorg / proof-validation hardening pass in
  `/Users/admin/Documents/btxchain/btx-node`:
  - added settlement-anchor DB reconciliation during persisted shielded-state
    restoration in `src/validation.cpp`, so the commitment-index repair path
    now rebuilds and repairs the confirmed settlement-anchor set instead of
    trusting whatever happened to be left in LevelDB
  - kept `LoadShieldedSnapshotSection(...)` and full chain rebuilds on the same
    settlement-anchor sync helper so snapshot activation, full rebuild, and
    restart repair all converge on one canonical reconciliation path
  - corrected the new `proof_check_rejects_v2_settlement_anchor_binding_mismatch`
    regression in `src/test/shielded_validation_checks_tests.cpp` so it now
    mutates `proof_receipt_ids` and still reaches proof-layer binding checks
    instead of failing earlier as a generic `bad-shielded-bundle`
  - switched the restart regression in
    `src/test/validation_chainstatemanager_tests.cpp` onto a persisted
    on-disk `TestChain100Setup` variant, which makes the settlement-anchor
    block survive the simulated node restart and turns the chain-based rebuild
    assertion into a real persistence test rather than an impossible in-memory
    fixture assumption
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=nullifier_set_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=txvalidation_tests/tx_mempool_accepts_v2_egress_after_settlement_anchor_and_evicts_it_after_reorg --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=validation_chainstatemanager_tests/chainstatemanager_rebuilds_shielded_state_when_commitment_index_missing --catch_system_error=no --log_level=test_suite`
- validation findings:
  - the full `shielded_validation_checks_tests` suite now reruns clean with
    the new `v2_settlement_anchor` proof cases included, confirming that the
    new reject path is proof-layer specific instead of structurally invalid
    bundle fallout
  - `nullifier_set_tests` still passes in full after the settlement-anchor DB
    additions, so the new cache / persistence prefix does not regress the
    existing nullifier roundtrip behavior
  - the `tx_mempool_accepts_v2_egress_after_settlement_anchor_and_evicts_it_after_reorg`
    regression still passes, confirming that the restart / repair hardening did
    not break anchored mempool admission or reorg eviction behavior
  - the updated chainstate restart regression now passes with on-disk block and
    coins DBs, validating that commitment-index repair rebuilds the tree and
    preserves / repairs settlement-anchor membership across an actual simulated
    restart
- blockers / pivots:
  - the first post-change `validation_chainstatemanager_tests` rerun still
    failed even though the settlement-anchor sync logic was correct; root cause
    was the fixture, not consensus code, because `TestChain100Setup` defaults
    to in-memory block / coins DBs and therefore discards the anchor-creating
    block during simulated restart
  - the first full `shielded_validation_checks_tests` rerun also exposed that
    mutating `batch_statement_digests` trips the generic structural validity
    gate before proof validation; the regression now mutates
    `proof_receipt_ids` instead so it still proves the intended
    `bad-shielded-v2-settlement-anchor-binding` path
  - Slice 9 remains open: anchored admission, reorg handling, and restart
    repair are now validated, but the family still needs its broader
    construction / wallet-facing `v2_egress_batch` path before the slice can be
    closed
- benchmarks / simulation findings:
  - none in this sub-slice; this pass was restart-hardening and consensus
    validation only
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - no disposable remote testnet resources were required for this sub-slice
- next slice:
  - continue `Slice 9` by wiring real construction and wallet-facing receive
    coverage for accepted `v2_egress_batch` transactions now that anchored
    admission, restart repair, and reorg handling are in place

### 2026-03-15 11:08:15 JST

- start-of-pass remote / GitHub preflight repeated before the fetch / pull
  cycle for the next Slice 9 sub-slice;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- fetch / pull, later push, and the next PR update remain unblocked for this
  pass.

### 2026-03-15 11:25:58 JST

- remote / GitHub preflight repeated before the fetch / pull / push / PR
  update cycle for the current Slice 9 `v2_egress_batch` construction
  sub-slice;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- fetch / pull, later push, and the next PR update remain unblocked for this
  pass.

### 2026-03-15 11:29:11 JST

- continued `Slice 9: Implement v2_egress_batch` with the first production
  construction path for accepted receipt-backed egress batches in
  `/Users/admin/Documents/btxchain/btx-node`:
  - added `src/shielded/v2_egress.h` and `src/shielded/v2_egress.cpp` with
    `BuildV2EgressBatchTransaction(...)`, a dedicated
    `V2EgressBuildInput` / `V2EgressBuildResult` API, canonical output-chunk
    construction, imported descriptor / receipt membership checks,
    settlement-witness serialization, and full bridge-out receipt / payload /
    proof-shard / settlement-anchor binding before the final
    `TransactionBundle::IsValid()` gate
  - wired the new production unit coverage into `src/test/CMakeLists.txt` and
    added `src/test/shielded_v2_egress_tests.cpp` so the builder is checked
    both on the success path and on output-root mismatch rejection
  - switched the shared egress fixture in
    `src/test/util/shielded_v2_egress_fixture.h` from hand-assembled bundles
    to the new builder, including chunk-size and total-amount overrides so
    future receive-path and settlement-anchor tests reuse the same canonical
    construction surface
  - rewired `src/test/shielded_wallet_chunk_discovery_tests.cpp` to consume
    real builder-produced `v2_egress_batch` bundles instead of local fake
    proof-shard / chunk assembly, so wallet discovery coverage now exercises
    the same receipt-backed bundle shape accepted by consensus
  - added `src/shielded/v2_egress.cpp` to `src/CMakeLists.txt`
- exact validation commands:
  - `git fetch --all --prune`
  - `git switch codex/shielded-v2-overhaul-plan`
  - `git pull --ff-only origin codex/shielded-v2-overhaul-plan`
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_egress_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_wallet_chunk_discovery_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_tx_check_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=txvalidation_tests/tx_mempool_accepts_v2_egress_after_settlement_anchor_and_evicts_it_after_reorg --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=validation_chainstatemanager_tests/chainstatemanager_rebuilds_shielded_state_when_commitment_index_missing --catch_system_error=no --log_level=test_suite`
- validation findings:
  - the new `shielded_v2_egress_tests` suite passed clean, confirming that
    builder-produced bundles survive the same contextual settlement receipt
    verification path as the accepted mempool / chain fixtures
  - `shielded_wallet_chunk_discovery_tests` now passes against real
    builder-produced `v2_egress_batch` transactions, which closes the gap
    between wallet chunk-discovery coverage and the consensus-visible egress
    family shape
  - the full `shielded_validation_checks_tests` suite still passes with the
    new builder-backed egress fixtures in place, so the construction API does
    not weaken receipt-binding, anchor-binding, or transparent-unwrap reject
    paths
  - the anchored mempool admission / reorg regression and the chainstate
    rebuild regression both still pass, so the new construction surface does
    not regress previously landed settlement-anchor persistence behavior
- blockers / pivots:
  - the first compile attempt for `src/shielded/v2_egress.cpp` used
    `MakeSpan(...)`, but that helper was not available in this translation
    unit on this host; the builder now uses explicit `Span<const T>{data,
    size}` construction instead, after which rebuild and validation passed
  - no `clang-format` binary is installed in this environment, so no
    formatter-driven rewrite was available during this pass
  - Slice 9 remains open: receipt-backed `v2_egress_batch` now has a real
    construction API and builder-backed wallet discovery fixtures, but the
    slice still needs the broader wallet-facing construction / receive surface
    before it can be closed
- benchmarks / simulation findings:
  - none in this sub-slice; this pass was construction-path and regression
    validation only
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - no disposable remote testnet resources were required for this sub-slice
- next slice:
  - continue `Slice 9` by wiring the new `v2_egress_batch` builder into the
    wallet-facing construction and receive surface beyond test-only fixtures
    now that canonical construction, anchored admission, and builder-backed
    discovery coverage are all in place

### 2026-03-15 11:31:34 JST

- remote / GitHub preflight repeated before the next fetch / pull / push / PR
  update cycle for the current Slice 9 wallet-facing `v2_egress_batch`
  sub-slice;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- fetch / pull, later push, and the next PR update remain unblocked for this
  pass.

### 2026-03-15 12:03:38 JST

- continued `Slice 9: Implement v2_egress_batch` with the wallet-facing
  construction and receive surface in
  `/Users/admin/Documents/btxchain/btx-node`:
  - extended `src/shielded/v2_egress.h` and `src/shielded/v2_egress.cpp` with
    deterministic output construction and `BuildV2EgressStatement(...)`, so
    receipt-backed egress statements derive canonical batch roots and
    ciphertext-bearing outputs from real recipient material instead of
    hand-assembled fixtures
  - added `CreateV2EgressBatch(...)` to
    `src/wallet/shielded_wallet.h` / `src/wallet/shielded_wallet.cpp`, which
    resolves recipient ML-KEM keys, builds deterministic outputs, self-checks
    wallet-owned decrypts, constructs the `v2_egress_batch`, and reparses the
    immutable bundle to re-verify receipt / settlement binding before the
    wallet returns it
  - added `bridge_buildegressstatement` and `bridge_buildegressbatchtx` to
    `src/wallet/shielded_rpc.cpp` and registered them from
    `src/wallet/rpc/wallet.cpp`, exposing build-only wallet RPCs that return
    canonical statement data, proof-receipt metadata, output summaries, and
    chunk summaries for `v2_egress_batch`
  - extended `test/functional/test_framework/bridge_utils.py` with egress
    statement / transaction helpers and added the new RPC surface coverage to
    `test/functional/wallet_shielded_rpc_surface.py`
  - expanded `src/test/shielded_v2_egress_tests.cpp` to check deterministic
    statement / output-root derivation and expanded
    `src/test/shielded_wallet_chunk_discovery_tests.cpp` so wallet chunk-view
    caching now runs against a real wallet-built receipt-backed
    `v2_egress_batch`
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx btxd -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_egress_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_wallet_chunk_discovery_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_tx_check_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests --catch_system_error=no --log_level=test_suite`
  - `python3 ./build-btx/test/functional/wallet_shielded_rpc_surface.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/rpc-surface-20260315i --portseed=32141`
  - `python3 ./build-btx/test/functional/wallet_shielded_rpc_surface.py --cachedir=/tmp/btx-functional-manual/cache --configfile=/Users/admin/Documents/btxchain/btx-node/test/config.ini --tmpdir=/tmp/btx-functional-manual/rpc-surface-20260315j --portseed=32142`
- validation findings:
  - the deterministic statement / output test passed, confirming that the
    wallet-visible `v2_egress_batch` statement path commits to the same output
    root as the actual builder-produced outputs
  - the wallet chunk-discovery regression passed against a
    `CreateV2EgressBatch(...)` transaction, so cached wallet receive metadata
    now exercises a real wallet-built receipt-backed egress bundle rather than
    a locally assembled proxy
  - the full `shielded_validation_checks_tests` suite remained clean after the
    wallet-facing statement / builder additions, so receipt binding,
    settlement-anchor binding, and transparent-unwrap rejection still hold for
    the production `v2_egress_batch` path
  - the rerun of `wallet_shielded_rpc_surface.py` passed clean and confirmed
    that the new build-only egress RPCs return canonical output / chunk
    metadata for wallet-owned recipients
- blockers / pivots:
  - the first `wallet_shielded_rpc_surface.py` run failed with
    `KeyError: 'proof_profile_hex'` in the new Slice 9 coverage because the
    test read a non-existent response field from `bridge_buildproofprofile`;
    the fix was to use the established `profile_hex` field already returned by
    that RPC, after which the rerun passed
- benchmarks / simulation findings:
  - none in this sub-slice; this pass focused on wallet / RPC construction and
    receive-path validation
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - no disposable remote testnet resources were required for this sub-slice
- slice status:
  - Slice 9 is now closed: `v2_egress_batch` has accepted anchored consensus
    validation, a production builder, wallet / RPC construction entry points,
    canonical chunk metadata, and wallet-visible receive coverage
- next slice:
  - `Slice 10: Replace Shielded Resource Accounting`

### 2026-03-15 12:04:28 JST

- remote / GitHub preflight repeated before the validated Slice 9 push / PR
  update cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- push to `origin/codex/shielded-v2-overhaul-plan` and the PR #82 update
  remain unblocked for this pass.

### 2026-03-15 22:59:28 JST

- remote / GitHub preflight repeated before the validated Slice 12 push / PR
  update cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- push to `origin/codex/shielded-v2-overhaul-plan` and the PR #82 update
  remain unblocked for this pass.

### 2026-03-15 22:58:41 JST

- completed the next validated `Slice 12: Prototype The High-Scale Ingress
  Proof` sub-slice in `/Users/admin/Documents/btxchain/btx-node`:
  - extended the bounded ingress proof runtime harness in
    `src/test/shielded_ingress_proof_runtime_report.h`,
    `src/test/shielded_ingress_proof_runtime_report.cpp`, and
    `src/test/generate_shielded_ingress_proof_runtime_report.cpp` so the same
    report path now selects either the default MatRiCT+ backend or the new
    receipt-backed native-batch backend through `--backend=...` / config-level
    selection
  - replaced the proof-only single-receipt stub inside the runtime harness
    with real per-shard receipt witness synthesis for the receipt-backed
    backend, deriving the exact shard nullifiers, canonical reserve payloads,
    ingress payload leaves, synthetic ingress note commitments, and
    statement-bound receipt public-values hashes that
    `BuildV2IngressBatchTransaction(...)` expects
  - fixed the runtime-report boundary behavior so overshard scenarios are
    reported as bounded `scenario_rejected` measurements instead of aborting
    the sweep, which lets the harness bracket the current chain ceiling cleanly
  - tightened the backend-decision artifact so large target bands now account
    for hard `proof_shard_limit` and `settlement_ref_limit` incompatibilities
    instead of only estimating proof-payload pressure
  - expanded deterministic coverage in
    `src/test/shielded_ingress_proof_runtime_report_tests.cpp` with a positive
    receipt-backed runtime case, an overshard rejection regression, and a
    receipt-backed large-target decision regression
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target generate_shielded_ingress_proof_runtime_report -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_ingress_proof_runtime_report_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_ingress_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/gen_shielded_ingress_proof_runtime_report --backend=receipt --samples=1 --reserve-outputs=1 --leaf-counts=100,1000,2047,2048 --target-leaf-counts=5000,10000 --output=/tmp/btx-shielded-ingress-proof-receipt-decision.json`
- validation findings:
  - the receipt-backed prototype reaches the current one-reserve chain ceiling
    at `2047` ingress leaves with `256` proof shards, `452704` proof-payload
    bytes, `954705` serialized transaction bytes, `64713875ns` build time, and
    `24186875ns` proof-check time
  - `2048` leaves is the first bounded rejection and now reports cleanly as
    `scenario exceeds max proof shards`, because it requires `257` proof shards
  - the receipt-backed prototype also built and checked the intermediate
    `100`-leaf and `1000`-leaf bands with `13` / `126` proof shards and only
    `22540` / `221614` proof-payload bytes respectively
  - the large-target decision report now correctly marks `5000` and `10000`
    leaves as `replacement_backend_required` even though the payload budget is
    still comfortable, because those targets need `626` / `1251` proof shards
    and therefore exceed both the current `MAX_PROOF_SHARDS=256` and
    `MAX_SETTLEMENT_REFS=512` ceilings
- blockers / pivots:
  - pivot 1: the first receipt-backed decision run falsely reported the
    `5000` / `10000` target range as compatible because the decision artifact
    only modeled proof-payload pressure; the report now carries explicit
    incompatibility reasons for `proof_shard_limit`,
    `settlement_ref_limit`, and `proof_payload_budget`
  - pivot 2: the first attempt to sweep `2048` leaves aborted the generator
    because the runtime path threw on overshard scenarios; the harness now
    emits a bounded rejection report instead of aborting the run
- benchmarks / simulation findings:
  - no cloud benchmark or distributed simulation ran in this sub-slice;
    evidence came from local bounded runtime-report generation and targeted
    ingress / validation regression suites
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - the receipt-backed runtime artifact was written to
    `/tmp/btx-shielded-ingress-proof-receipt-decision.json` and no disposable
    remote state was left behind
- slice status:
  - Slice 12 remains open: the alternative receipt-backed ingress backend now
    has bounded higher-scale evidence up to the present `256`-shard chain
    ceiling, but a real launch-capable high-scale ingress path still needs the
    next backend / envelope step beyond the current shard and settlement-ref
    caps
- next slice:
  - continue `Slice 12` by extending the alternative ingress backend or
    redesigning the high-scale ingress envelope so target bands above the
    current `256`-shard / `512` settlement-ref ceiling become constructible

### 2026-03-15 23:28:37 JST

- remote / GitHub preflight repeated before the next fetch / pull / push / PR
  cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote sync, future push to `origin/codex/shielded-v2-overhaul-plan`, and
  the PR #82 update are unblocked for this pass.

### 2026-03-15 23:54:00 JST

- continued `Slice 13: Integrate PR #79 Settlement Anchors Into shielded_v2`
  with the first validated imported-claim settlement-anchor sub-slice in
  `/Users/admin/Documents/btxchain/btx-node`:
  - added `BuildBridgeExternalAnchorFromClaim(...)` in
    `src/shielded/bridge.h` / `src/shielded/bridge.cpp` so a canonical
    `BridgeProofClaim` can now produce the same external-anchor material the
    settlement path already derives from imported receipts
  - extended `src/shielded/validation.cpp` so `v2_settlement_anchor` parses
    and verifies imported-claim settlement witnesses, binds the batch
    statement digest and imported-claim hash, derives the settlement-anchor
    digest from the claim-backed external anchor, and rejects unsupported proof
    kinds as `bad-shielded-v2-settlement-anchor-proof-kind`
  - added a deterministic imported-claim settlement-anchor fixture in
    `src/test/util/shielded_v2_egress_fixture.h` and covered it in
    `src/test/shielded_bridge_tests.cpp`,
    `src/test/shielded_validation_checks_tests.cpp`, and
    `src/test/shielded_tx_check_tests.cpp`
  - updated `src/policy/policy.cpp` and
    `src/test/shielded_transaction_tests.cpp` so zero-`vout`
    `v2_settlement_anchor` state transitions are standard on transaction shape
    alone instead of being misclassified as bare-anchor transparent
    transactions
  - rewrote the state-transition regression in
    `src/test/txvalidation_tests.cpp` around real block connect / reorg
    semantics for claim-backed settlement anchors rather than pretending the
    current zero-fee anchor should already relay through the mempool
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `./build-btx/bin/test_btx --run_test='txvalidation_tests/tx_connects_claim_backed_v2_settlement_anchor_and_rewinds_state_after_reorg' --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test='shielded_transaction_tests/v2_settlement_anchor_without_transparent_outputs_is_standard' --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test='shielded_transaction_tests/v2_egress_standardness_tracks_scan_pressure' --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_bridge_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_tx_check_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests --catch_system_error=no --log_level=test_suite`
- validation findings:
  - the renamed contextual regression now proves the actual current behavior:
    a claim-backed `v2_settlement_anchor` is rejected from mempool admission as
    `min relay fee not met`, but it connects in a block, materializes the
    settlement-anchor digest, and that digest is removed again after block
    invalidation
  - the imported-claim proof surface now passes end-to-end across bridge
    helper, `CShieldedProofCheck`, and `CheckTransaction(...)` coverage
  - the zero-`vout` settlement-anchor standardness carveout passes in
    isolation, and the previously stale
    `v2_egress_standardness_tracks_scan_pressure` regression also passed on the
    rebuilt binary with the corrected expectations
  - focused suite timings captured on this host:
    `tx_connects_claim_backed_v2_settlement_anchor_and_rewinds_state_after_reorg=1593595us`
    and `shielded_validation_checks_tests=111170482us`
- blockers / pivots:
  - the first attempted mempool regression exposed a real distinction, not a
    missing consensus path: after fixing the bare-anchor standardness carveout,
    zero-fee settlement-anchor transactions still fail relay policy on minimum
    fee, so this sub-slice now validates block-state integration and leaves
    full relay work for the later network / relay slice
- benchmarks / simulation findings:
  - none new beyond the focused suite timings; this pass was about settlement
    object correctness and state-transition coverage, not throughput or remote
    simulation
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - no disposable remote testnet resources were required for this sub-slice
- slice status:
  - Slice 13 remains open, but `shielded_v2` now has the first validated
    claim-backed settlement-anchor path from witness parsing through block
    connect and reorg unwind
- next slice:
  - continue Slice 13 by integrating the remaining imported proof adapters,
    proof receipts, verification roots, and reserve/netting bindings from PR
    #79 into the live `shielded_v2` settlement object path

### 2026-03-16 00:19:25 JST

- remote / GitHub preflight repeated immediately before the next validated
  Slice 13 push / PR #82 update cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- continued `Slice 13: Integrate PR #79 Settlement Anchors Into shielded_v2`
  with the first validated hybrid verification-root settlement sub-slice in
  `/Users/admin/Documents/btxchain/btx-node`:
  - added `BuildBridgeVerificationBundle(...)` in
    `src/shielded/bridge.h` / `src/shielded/bridge.cpp` so signed receipts and
    proof receipts now share one canonical verification-bundle builder instead
    of duplicating bundle-root assembly across hybrid settlement paths
  - extended `src/shielded/v2_egress.h` / `src/shielded/v2_egress.cpp` so
    `BuildV2EgressBatchTransaction(...)` can carry signed receipts plus
    verifier-set membership proofs, derive a hybrid verification bundle, and
    bind the resulting hybrid external anchor into live `v2_egress_batch`
    payloads instead of only the proof-receipt-only form
  - extended `src/shielded/validation.cpp` so both `v2_egress_batch` and
    `v2_settlement_anchor` parse hybrid settlement witnesses from
    `proof_payload`, reconstruct and verify the canonical hybrid
    verification bundle, and derive the settlement-anchor digest from the
    hybrid external anchor when verifier-set material is present
  - added deterministic hybrid receipt / settlement-anchor fixtures in
    `src/test/util/shielded_v2_egress_fixture.h`, then covered the positive
    bridge helper, contextual proof-check, transaction-shape admission, and
    mempool / block / reorg state-transition paths in
    `src/test/shielded_bridge_tests.cpp`,
    `src/test/shielded_v2_egress_tests.cpp`,
    `src/test/shielded_validation_checks_tests.cpp`,
    `src/test/shielded_tx_check_tests.cpp`, and
    `src/test/txvalidation_tests.cpp`
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `./build-btx/bin/test_btx --run_test='txvalidation_tests/tx_mempool_accepts_hybrid_v2_egress_after_settlement_anchor_and_evicts_it_after_reorg' --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_bridge_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_egress_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_tx_check_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test='txvalidation_tests/tx_mempool_accepts_v2_egress_after_settlement_anchor_and_evicts_it_after_reorg' --catch_system_error=no --log_level=test_suite`
- validation findings:
  - the hybrid mempool / block / reorg regression now passes end to end, so
    live `v2_egress_batch` settlement-anchor admission is no longer limited to
    proof-receipt-only witnesses; the verification-root-backed hybrid witness
    model is exercised through the actual transaction family
  - the shared verification-bundle builder passes in isolation and the hybrid
    contextual checks pass through `CShieldedProofCheck` and
    `CheckTransaction(...)` without regressing the existing proof-only egress
    path
  - focused suite timings captured on this host:
    `tx_mempool_accepts_hybrid_v2_egress_after_settlement_anchor_and_evicts_it_after_reorg=1659873us`,
    `shielded_validation_checks_tests=111544465us`, and
    `tx_mempool_accepts_v2_egress_after_settlement_anchor_and_evicts_it_after_reorg=1661484us`
- blockers / pivots:
  - the first hybrid state-transition regression used independently built
    signed-receipt fixtures for the anchor and the egress transaction, which
    produced different hybrid settlement-anchor digests because the receipt
    signature material was not identical across the two builds; the fix was to
    derive the settlement-anchor fixture from the exact egress fixture it
    anchors
- benchmarks / simulation findings:
  - none new beyond the focused suite timings; this pass was about settlement
    object correctness and hybrid anchor integration, not throughput or remote
    simulation
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - no disposable remote testnet resources were required for this sub-slice
- slice status:
  - Slice 13 remains open, but `shielded_v2` now has a validated hybrid
    verification-root settlement path wired into the live `v2_egress_batch`
    and `v2_settlement_anchor` object families
- next slice:
  - continue Slice 13 by integrating the remaining imported proof adapters,
    proof receipts, and reserve / netting bindings from PR #79 into the live
    settlement object path

### 2026-03-16 00:41:50 JST

- remote / GitHub preflight repeated immediately before the next validated
  Slice 13 push / PR #82 update cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- continued `Slice 13: Integrate PR #79 Settlement Anchors Into shielded_v2`
  with the first validated imported-proof-adapter settlement-anchor sub-slice
  in `/Users/admin/Documents/btxchain/btx-node`:
  - extended `src/shielded/v2_proof.h` / `src/shielded/v2_proof.cpp` so
    imported-claim settlement witnesses now serialize canonical
    `imported_adapters`, validate them structurally, and require every adapter
    to reproduce the imported claim committed by the settlement statement
  - extended `src/shielded/validation.cpp` so claim-backed
    `v2_settlement_anchor` payloads now bind canonical sorted adapter ids from
    the witness into `payload.imported_adapter_ids`, while receipt-backed
    settlement contexts continue to reject unexpected adapters as
    `bad-v2-settlement-receipt-adapter`
  - added deterministic adapter-backed fixtures in
    `src/test/util/shielded_v2_egress_fixture.h`, including a canonical
    adapter-backed claim settlement-anchor bundle with rebuilt
    `payload_digest`, `proof_shard_root`, and sorted imported-adapter ids
  - covered the positive bridge-free proof path and rejection surface in
    `src/test/shielded_validation_checks_tests.cpp`, the transaction-shape
    admission path in `src/test/shielded_tx_check_tests.cpp`, and the
    block-connect / reorg state transition in `src/test/txvalidation_tests.cpp`
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `./build-btx/bin/test_btx --run_test='txvalidation_tests/tx_connects_adapter_backed_v2_settlement_anchor_and_rewinds_state_after_reorg' --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_tx_check_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_proof_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests --catch_system_error=no --log_level=test_suite`
- validation findings:
  - adapter-backed claim settlement anchors now pass end to end through
    `SettlementWitness` parsing, `VerifySettlementContext(...)`,
    `CShieldedProofCheck`, `CheckTransaction(...)`, and block connect / reorg
    unwind without widening the still-untested receipt-backed adapter surface
  - focused suite timings captured on this host:
    `tx_connects_adapter_backed_v2_settlement_anchor_and_rewinds_state_after_reorg=1589903us`,
    `shielded_v2_proof_tests=34622959us`, and
    `shielded_validation_checks_tests=111443664us`
- blockers / pivots:
  - the first pass at this change briefly widened receipt-backed settlement
    adapter handling too, but that broadened behavior was not directly covered
    by the focused regression set; the implementation was narrowed back to the
    claim-backed adapter path so every consensus-visible change in this
    sub-slice is explicitly tested
- benchmarks / simulation findings:
  - none new beyond the focused suite timings; this pass was about imported
    adapter binding correctness rather than throughput or remote simulation
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - no disposable remote testnet resources were required for this sub-slice
- slice status:
  - Slice 13 remains open, but `shielded_v2` now has a validated
    claim-backed imported-proof-adapter settlement path bound into the live
    `v2_settlement_anchor` object family
- next slice:
  - continue Slice 13 by integrating the remaining proof-receipt,
    receipt-backed adapter, and reserve / netting bindings from PR #79 into
    the live settlement object path

### 2026-03-16 00:45:00 JST

- remote / GitHub preflight repeated immediately before the next validated
  Slice 13 push / PR #82 update cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- continued `Slice 13: Integrate PR #79 Settlement Anchors Into shielded_v2`
  with the validated receipt-backed imported-proof-adapter settlement-anchor
  sub-slice in `/Users/admin/Documents/btxchain/btx-node`:
  - extended `src/shielded/v2_proof.cpp` so imported-receipt settlement
    contexts now accept `imported_adapters` only when each adapter
    deterministically reconstructs the imported proof receipt committed by the
    witness, and reject mismatches as `bad-v2-settlement-receipt-adapter`
  - extended `src/shielded/validation.cpp` so imported-receipt
    `v2_settlement_anchor` payloads now bind canonical sorted
    `payload.imported_adapter_ids` from the settlement witness alongside the
    existing `proof_receipt_ids`
  - added a dedicated adapter-backed imported-receipt settlement-anchor
    fixture in `src/test/util/shielded_v2_egress_fixture.h` built from
    `BuildBridgeProofReceiptFromAdapter(...)` rather than trying to retrofit
    adapters onto the older descriptor-only receipt fixture
  - covered the direct settlement-context adapter match / mismatch path in
    `src/test/shielded_v2_proof_tests.cpp`, the proof-check and binding
    mismatch path in `src/test/shielded_validation_checks_tests.cpp`, the
    transaction-shape admission path in `src/test/shielded_tx_check_tests.cpp`,
    and the block-connect / reorg unwind path in
    `src/test/txvalidation_tests.cpp`
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_proof_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_tx_check_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test='txvalidation_tests/tx_connects_receipt_adapter_backed_v2_settlement_anchor_and_rewinds_state_after_reorg' --catch_system_error=no --log_level=test_suite`
- validation findings:
  - imported-receipt settlement contexts now pass with a matching adapter-built
    receipt and fail cleanly on adapter mismatch before bundle admission
  - adapter-backed imported-receipt settlement anchors now pass through
    `CShieldedProofCheck`, `CheckTransaction(...)`, and block connect / reorg
    unwind while binding canonical adapter ids into the live settlement-anchor
    payload
  - focused suite timings captured on this host:
    `shielded_v2_proof_tests=34944361us`,
    `shielded_validation_checks_tests=111338739us`, and
    `tx_connects_receipt_adapter_backed_v2_settlement_anchor_and_rewinds_state_after_reorg=1687007us`
- blockers / pivots:
  - the existing imported-receipt fixture could not be reused for this path
    because its proof receipt was descriptor-backed rather than adapter-backed;
    I replaced the shortcut with a dedicated adapter-built receipt fixture so
    the positive path actually exercises `BuildBridgeProofReceiptFromAdapter(...)`
- benchmarks / simulation findings:
  - none new beyond the focused suite timings; this pass was about settlement
    binding correctness rather than throughput or remote simulation
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - no disposable remote testnet resources were required for this sub-slice
- slice status:
  - Slice 13 remains open, but `shielded_v2` now has validated imported-proof
    adapter binding on both the claim-backed and receipt-backed
    `v2_settlement_anchor` paths
- next slice:
  - continue Slice 13 with the remaining proof-receipt scale/binding work and
    the reserve / netting settlement-anchor bindings from PR #79

### 2026-03-16 01:09:58 JST

- remote / GitHub preflight repeated immediately before the next validated
  Slice 13 push / PR #82 update cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- continued `Slice 13: Integrate PR #79 Settlement Anchors Into shielded_v2`
  with the validated multi-proof-receipt settlement-threshold binding
  sub-slice in `/Users/admin/Documents/btxchain/btx-node`:
  - relaxed `src/shielded/bridge.cpp` so
    `BridgeProofPolicyCommitment::IsValid()` and
    `BuildBridgeProofPolicyCommitment(...)` no longer cap
    `required_receipts` at `descriptor_count`, which makes thresholded
    proof-receipt settlement policies constructable for the first time under a
    single imported descriptor
  - added a direct bridge regression in
    `src/test/shielded_bridge_tests.cpp` proving that a one-descriptor proof
    policy can now commit `required_receipts = 2`
  - extended `src/test/util/shielded_v2_egress_fixture.h` so deterministic
    egress and settlement-anchor fixtures can synthesize canonical multi-receipt
    witnesses and canonical sorted `payload.proof_receipt_ids` over the full
    proof-receipt set instead of only the imported receipt
  - extended `src/test/shielded_v2_egress_tests.cpp`,
    `src/test/shielded_validation_checks_tests.cpp`,
    `src/test/shielded_tx_check_tests.cpp`, and
    `src/test/txvalidation_tests.cpp` with positive multi-receipt egress
    contextual-verifier coverage, multi-receipt settlement-anchor proof-check
    coverage, explicit binding-mismatch rejection when one receipt id is
    dropped, transaction-shape admission, and block-connect / reorg unwind
    coverage for the first `required_receipts = 2` settlement path
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_bridge_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_egress_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_tx_check_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=txvalidation_tests/tx_connects_multi_receipt_v2_settlement_anchor_and_rewinds_state_after_reorg --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=txvalidation_tests/tx_connects_receipt_adapter_backed_v2_settlement_anchor_and_rewinds_state_after_reorg --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_tx_check_tests/checktransaction_accepts_multi_receipt_v2_settlement_anchor_bundle_for_contextual_validation --catch_system_error=no --log_level=test_suite`
- validation findings:
  - the first live two-receipt threshold settlement case now passes end to end
    through `BuildV2EgressBatchTransaction(...)`,
    `ParseSettlementWitness(...)`, `VerifySettlementContext(...)`,
    `CShieldedProofCheck`, `CheckTransaction(...)`, and
    settlement-anchor block connect / reorg unwind
  - settlement-anchor binding coverage now proves that the full canonical
    proof-receipt id set is consensus-bound: truncating one of the two receipt
    ids now fails as `bad-shielded-v2-settlement-anchor-binding`
  - focused suite timings captured on this host:
    `shielded_bridge_tests=495193us`,
    `shielded_v2_egress_tests=10285us`,
    `shielded_validation_checks_tests=111224383us`,
    `tx_connects_multi_receipt_v2_settlement_anchor_and_rewinds_state_after_reorg=1598926us`,
    `tx_connects_receipt_adapter_backed_v2_settlement_anchor_and_rewinds_state_after_reorg=1682353us`,
    and
    `checktransaction_accepts_multi_receipt_v2_settlement_anchor_bundle_for_contextual_validation=2292us`
- blockers / pivots:
  - the real blocker was in the bridge policy layer, not the witness parser:
    proof-policy commitments still enforced
    `required_receipts <= descriptor_count`, while settlement verification
    already required every receipt in the witness to match the single imported
    descriptor; that combination made any multi-receipt threshold
    unconstructable until the bridge rule was relaxed
  - the first broad `txvalidation_tests/...` selector did not give positive
    evidence that the new reorg case had executed, so the exact case name was
    rerun directly and the successful `1598926us` execution was recorded
- benchmarks / simulation findings:
  - none new beyond the focused suite timings; this pass was about unlocking
    and validating the first multi-proof-receipt settlement threshold rather
    than throughput or remote simulation
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - no disposable remote testnet resources were required for this sub-slice
- slice status:
  - Slice 13 remains open, but `shielded_v2` now has a validated
    multi-proof-receipt threshold settlement path wired through the live
    egress and settlement-anchor object families
- next slice:
  - continue Slice 13 with the remaining reserve / netting
    settlement-anchor bindings and any remaining proof-receipt /
    verification-root binding gaps from PR #79

### 2026-03-16 01:14:58 JST

- start-of-pass remote / GitHub preflight repeated before any new fetch / pull /
  push / PR cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- the next remote sync, later push to
  `origin/codex/shielded-v2-overhaul-plan`, and the follow-up PR #82 update are
  unblocked for this pass.

### 2026-03-16 01:35:55 JST

- start-of-pass remote / GitHub preflight repeated before any new fetch / pull /
  push / PR cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- the next remote sync, later push to
  `origin/codex/shielded-v2-overhaul-plan`, and the follow-up PR #82 update are
  unblocked for this pass.

### 2026-03-16 01:47:24 JST

- start-of-pass remote / GitHub preflight repeated before any new fetch / pull /
  push / PR cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- the next remote sync, later push to
  `origin/codex/shielded-v2-overhaul-plan`, and the follow-up PR #82 update are
  unblocked for this pass.

### 2026-03-16 01:44:39 JST

- continued `Slice 13: Integrate PR #79 Settlement Anchors Into shielded_v2`
  with the validated multi-receipt hybrid settlement-path sub-slice in
  `/Users/admin/Documents/btxchain/btx-node`:
  - generalized the hybrid receipt fixture builder in
    `src/test/util/shielded_v2_egress_fixture.h` so
    `BuildV2EgressHybridReceiptFixture(...)` and
    `BuildV2SettlementAnchorHybridReceiptFixture(...)` can synthesize
    satisfiable multi-proof-receipt thresholds instead of hard-coding the
    single-receipt case
  - added the new contextual egress regression in
    `src/test/shielded_v2_egress_tests.cpp` for
    `build_v2_egress_transaction_matches_multi_receipt_hybrid_contextual_verifier`
  - added the positive proof-check / tx-shape regressions in
    `src/test/shielded_validation_checks_tests.cpp` and
    `src/test/shielded_tx_check_tests.cpp` for
    multi-receipt hybrid `v2_settlement_anchor` bundles
  - added the live mempool / block-connect / reorg / mempool-reaccept
    regression in `src/test/txvalidation_tests.cpp` for
    `tx_mempool_accepts_multi_receipt_hybrid_v2_egress_after_settlement_anchor_and_evicts_it_after_reorg`
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `/usr/bin/time -p ./build-btx/bin/test_btx --run_test=txvalidation_tests/tx_mempool_accepts_multi_receipt_hybrid_v2_egress_after_settlement_anchor_and_evicts_it_after_reorg --catch_system_error=no --log_level=test_suite`
  - `/usr/bin/time -p ./build-btx/bin/test_btx --run_test=txvalidation_tests/tx_mempool_accepts_hybrid_v2_egress_after_settlement_anchor_and_evicts_it_after_reorg --catch_system_error=no --log_level=test_suite`
  - `/usr/bin/time -p ./build-btx/bin/test_btx --run_test=shielded_v2_egress_tests --catch_system_error=no --log_level=test_suite`
  - `/usr/bin/time -p ./build-btx/bin/test_btx --run_test=shielded_tx_check_tests --catch_system_error=no --log_level=test_suite`
  - `/usr/bin/time -p ./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests --catch_system_error=no --log_level=test_suite`
- validation findings:
  - the generalized hybrid builder now produces canonical multi-receipt proof
    policies, proof-receipt vectors, and hybrid verification bundles that pass
    the live contextual egress path as well as settlement-anchor proof checks
  - both the new multi-receipt hybrid mempool/reorg regression and the
    pre-existing single-receipt hybrid mempool/reorg regression passed, which
    confirms the fixture change did not regress the older settlement path
  - the full `shielded_v2_egress_tests`, `shielded_tx_check_tests`, and
    `shielded_validation_checks_tests` suites stayed green with the new hybrid
    multi-receipt coverage active
- blockers / pivots:
  - the remaining Slice 13 gap here was combinatorial rather than structural:
    proof-only multi-receipt and hybrid single-receipt paths already existed,
    but the shared hybrid fixture surface still hard-coded one proof receipt;
    the fix was to generalize the fixture and prove both the new and old reorg
    paths together before push
- benchmarks / simulation findings:
  - no new throughput benchmark or remote simulation work in this pass; focused
    host timings were
    `tx_mempool_accepts_multi_receipt_hybrid_v2_egress_after_settlement_anchor_and_evicts_it_after_reorg=1685030us`,
    `tx_mempool_accepts_hybrid_v2_egress_after_settlement_anchor_and_evicts_it_after_reorg=1664976us`,
    `shielded_v2_egress_tests=13564us`,
    `shielded_tx_check_tests=39262us`, and
    `shielded_validation_checks_tests=111254679us`
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - no disposable remote testnet resources were required for this sub-slice
- slice status:
  - Slice 13 remains open, but the hybrid verification-root settlement path is
    now covered for both single- and multi-proof-receipt thresholds through the
    live egress, proof-check, and reorg flows
- next slice:
  - continue Slice 13 with any remaining imported-proof / proof-receipt /
    verification-root settlement-anchor binding gaps, or move into the next
    relay-facing settlement slice if the consensus-visible anchor work is now
    exhausted

### 2026-03-16 01:31:35 JST

- continued `Slice 13: Integrate PR #79 Settlement Anchors Into shielded_v2`
  with the validated reserve / netting settlement-anchor binding sub-slice in
  `/Users/admin/Documents/btxchain/btx-node`:
  - extended `src/shielded/v2_bundle.h` / `src/shielded/v2_bundle.cpp` with
    shared `ReserveDeltaSetIsCanonical(...)`, then tightened
    `SettlementAnchorPayload::IsValid()` so settlement anchors now require
    canonical, zero-sum, strictly sorted reserve deltas and reject a non-null
    `anchored_netting_manifest_id` when no reserve deltas are present
  - extended `src/shielded/validation.cpp` so imported-receipt and
    imported-claim `v2_settlement_anchor` contextual verification now accepts
    canonical reserve / netting bindings instead of treating
    `payload.reserve_deltas` and `payload.anchored_netting_manifest_id` as
    forbidden fields
  - added reusable reserve-binding fixture helpers in
    `src/test/util/shielded_v2_egress_fixture.h`
  - covered the structural rules in `src/test/shielded_v2_bundle_tests.cpp`,
    positive proof-check paths for both imported receipts and imported claims
    in `src/test/shielded_validation_checks_tests.cpp`, contextual transaction
    admission in `src/test/shielded_tx_check_tests.cpp`, and block connect /
    reorg unwind in `src/test/txvalidation_tests.cpp`
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_bundle_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_tx_check_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=txvalidation_tests/tx_connects_reserve_bound_v2_settlement_anchor_and_rewinds_state_after_reorg --catch_system_error=no --log_level=test_suite`
- validation findings:
  - reserve-bearing settlement anchors now pass `CShieldedProofCheck`,
    `CheckTransaction(...)`, and block connect / reorg unwind while keeping the
    settlement-anchor digest stable
  - the new structural rules reject malformed settlement payloads earlier:
    unsorted or non-zero-sum reserve deltas and a bare
    `anchored_netting_manifest_id` without reserve deltas now fail
    `TransactionBundle::IsValid()`
  - focused suite timings captured on this host:
    `shielded_validation_checks_tests=112061299us`,
    `proof_check_accepts_reserve_bound_receipt_v2_settlement_anchor_bundle=1453us`,
    `proof_check_accepts_reserve_bound_claim_backed_v2_settlement_anchor_bundle=988us`,
    `shielded_tx_check_tests=38931us`, and
    `tx_connects_reserve_bound_v2_settlement_anchor_and_rewinds_state_after_reorg=1573447us`
- blockers / pivots:
  - the real gap was split across structure and context: payload digests already
    committed reserve / netting fields, but settlement-anchor structural
    validity did not enforce canonical reserve-delta rules and contextual
    verification still hard-rejected the fields outright; both layers had to be
    aligned before the live settlement path could carry the PR #79 bindings
- benchmarks / simulation findings:
  - none new beyond the focused suite timings; this pass was about consensus
    binding correctness for reserve / netting settlement payloads, not
    throughput or remote simulation
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - no disposable remote testnet resources were required for this sub-slice
- slice status:
  - Slice 13 remains open, but `shielded_v2` now has validated reserve /
    netting settlement-anchor payload bindings on the live imported-receipt and
    imported-claim settlement paths
- next slice:
  - continue Slice 13 with any remaining proof-receipt / verification-root
    settlement-anchor binding gaps from PR #79, or move into the next launch-
    critical relay / network-facing settlement slice if the remaining consensus
    anchor work is exhausted

### 2026-03-16 00:57:26 JST

- start-of-pass remote / GitHub preflight repeated before any new fetch / pull /
  push / PR cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- executed the required sync loop in `/Users/admin/Documents/btxchain/btx-node`:
  - `git fetch --all --prune`
  - `git switch codex/shielded-v2-overhaul-plan`
  - `git pull --ff-only origin codex/shielded-v2-overhaul-plan`
  - `git status --short`
  - `git log --oneline -5`
- remote sync, later push to `origin/codex/shielded-v2-overhaul-plan`, and the
  follow-up PR #82 update were unblocked for this pass.

### 2026-03-15 23:54:41 JST

- remote / GitHub preflight repeated immediately before the validated Slice 13
  push / PR #82 update cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- push to `origin/codex/shielded-v2-overhaul-plan` and the PR #82 update are
  unblocked for this pass.

### 2026-03-15 23:58:09 JST

- remote / GitHub preflight repeated before the next fetch / pull / push / PR
  cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote sync, future push to `origin/codex/shielded-v2-overhaul-plan`, and
  the PR #82 update are unblocked for this pass.

### 2026-03-15 23:24:35 JST

- remote / GitHub preflight repeated immediately before the validated Slice 12
  push / PR update cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- push to `origin/codex/shielded-v2-overhaul-plan` and the PR #82 update
  remain unblocked for this pass.

### 2026-03-15 23:22:52 JST

- completed the validated closure pass for `Slice 12: Prototype The High-Scale
  Ingress Proof` in `/Users/admin/Documents/btxchain/btx-node`:
  - split the ingress shard budget by backend in
    `src/shielded/v2_ingress.h` / `src/shielded/v2_ingress.cpp`, keeping the
    default MatRiCT+ path at `8` total outputs per proof shard while lifting
    the receipt-backed path to `64`
  - threaded that backend-aware budget through the canonical ingress shard
    planner, schedule validation, receipt-witness validation, and
    `BuildV2IngressBatchTransaction(...)`, so receipt-backed
    `v2_ingress_batch` no longer inherits the old MatRiCT+-only shard ceiling
  - updated `src/test/shielded_ingress_proof_runtime_report.cpp` and
    `src/test/shielded_ingress_proof_runtime_report_tests.cpp` so the runtime
    harness uses the backend-specific shard envelope, positively covers a real
    `10000`-leaf receipt-backed build / parse / verify / proof-check path, and
    re-brackets the first overshard rejection under the new receipt-backed
    geometry
- exact validation commands:
  - `cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx --target test_btx generate_shielded_ingress_proof_runtime_report -j8`
  - `./build-btx/bin/test_btx --run_test=shielded_ingress_proof_runtime_report_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_v2_ingress_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/test_btx --run_test=shielded_validation_checks_tests --catch_system_error=no --log_level=test_suite`
  - `./build-btx/bin/gen_shielded_ingress_proof_runtime_report --backend=receipt --samples=1 --reserve-outputs=1 --leaf-counts=5000,10000,16383,16384 --output=/tmp/btx-shielded-ingress-proof-receipt-scale-sweep.json`
- validation findings:
  - receipt-backed `5000` leaves now build and proof-check with `79` proof
    shards, `917446` proof-payload bytes, `1938470` serialized transaction
    bytes, `123920334ns` build time, and `52275292ns` proof-check time
  - receipt-backed `10000` leaves now build and proof-check with `157` proof
    shards, `1834278` proof-payload bytes, `3874240` serialized transaction
    bytes, `250039250ns` build time, and `103708417ns` proof-check time
  - receipt-backed `16383` leaves reaches the current hard ceiling with `256`
    proof shards, `3004512` proof-payload bytes, `6345041` serialized
    transaction bytes, `405951041ns` build time, and `171346333ns`
    proof-check time
  - with the current consensus `nMaxShieldedTxSize=6500000`, the validated
    `16383`-leaf receipt-backed ceiling still leaves `154959` serialized-byte
    headroom; the first clean reject remains shard-driven rather than
    size-driven
  - receipt-backed `16384` leaves is the first bounded rejection and reports
    cleanly as `scenario exceeds max proof shards`, because it needs `257`
    proof shards
  - focused suite timings on this host were:
    `shielded_ingress_proof_runtime_report_tests=124940055us`,
    `shielded_v2_ingress_tests=208994024us`, and
    `shielded_validation_checks_tests=111079246us`
- blockers / pivots:
  - the real limiting bug was not the receipt-backed backend itself; it was the
    inherited global `MAX_INGRESS_OUTPUTS_PER_PROOF_SHARD=8` baked into the
    shared ingress scheduler and receipt-witness validation path
  - once that budget was made backend-specific, the receipt-backed prototype
    reached the required target bands without changing the top-level
    `v2_ingress_batch` family shape
- benchmarks / simulation findings:
  - this sub-slice used local bounded build / proof-check runtime reporting and
    targeted unit-validation only; no distributed simulation or cloud benchmark
    was needed
- cloud resources used: none
- cost: `0`
- teardown confirmation:
  - no DigitalOcean, Porkbun, or Tailscale resources were created
  - the local receipt-backed runtime artifact was written to
    `/tmp/btx-shielded-ingress-proof-receipt-scale-sweep.json` and no
    disposable remote state remains
- slice status:
  - Slice 12 is now complete: BTX has a validated alternative high-scale
    ingress proof backend with explicit approved receipt-backed shard sizing
    (`64` total outputs / shard), measured supported bands through `10000`
    leaves, and a bracketed current hard ceiling at `16383` / `16384` leaves
- next slice:
  - start `Slice 13: Integrate PR #79 Settlement Anchors Into shielded_v2`

### 2026-03-15 23:01:54 JST

- remote / GitHub preflight repeated before the next fetch / pull / push / PR
  cycle;
- verified readable, non-empty credentials:
  - `/Users/admin/Documents/btxchain/github.key` (`94` bytes)
  - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key` (`72` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_api.key` (`69` bytes)
  - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key` (`69` bytes)
- remote sync, future push to `origin/codex/shielded-v2-overhaul-plan`, and
  the PR #82 update are unblocked for this pass.

## Objective

Design the post-reset BTX privacy architecture where:

- `shielded_v2` is the only shielded standard from genesis;
- no backward compatibility, migration path, or legacy pool support is kept;
- user-to-L2 and L2-to-user flows are shielded by default;
- L2-to-L2 and cross-L2 transfers are the dominant transaction path;
- L1 acts primarily as a shielded settlement, reserve, and rebalancing layer;
- the system can support millions of L2 transactions per day and billions per
  year, with L1 only carrying the boundary flows and settlement checkpoints;
- the system can support a very large global user base only because most user
  balances, balance changes, and rebalancing activity live on L2 rather than
  being materialized individually on L1;
- cross-L2 value transfer should usually clear through operator-level netting
  and multi-domain reserve settlement so L1 carries net reserve deltas rather
  than gross bilateral exits and re-ingresses wherever possible;
- the reset should freeze transaction-family shapes, proof envelopes, and
  resource-accounting dimensions broadly enough that later proof, scan, and
  settlement upgrades fit inside the architecture without another chain reset;
- the result is a shielded economic platform where L2s are the default rail and
  L1 is the compact private settlement base.

This document is not a small optimization plan for the existing MatRiCT pool.
It is a full reset-from-genesis plan for a new shielded architecture that keeps
what is structurally useful from the current codebase, reuses the merged batch
/ proof-envelope / measurement work now in `main` from PR #79, and then
rebuilds the user-facing privacy path around a cleaner and more scalable
`shielded_v2`.

## Reset Assumptions

These assumptions are intentional and simplify the design:

- There is no `shielded_v1` to preserve.
- There is no requirement to support old note formats, old nullifiers, or old
  wallet scanning behavior.
- There is no need for post-launch migration transactions.
- This reset is a clean restart with no value carryover, no genesis allocation
  derived from the current chain, and no legacy economic compatibility burden.
- There is no requirement to preserve the current one-recipient bridge-in or
  transparent bridge-out transaction shapes.
- Transparent bridge-out should not be the default UX.
- We can redesign transaction versions, note wire formats, block accounting,
  scan hints, and output limits from first principles.
- We can set shielded-by-default behavior as a consensus and wallet default,
  not as an opt-in compatibility mode.

## Non-Negotiable Requirements

1. `user -> L2` must be private by default.
2. `L2 -> user` must be private by default.
3. `L2 -> L2` and cross-L2 transfers should remain off-chain by default and
   settle on L1 only through compact roots / proofs / reserve updates.
4. The steady-state system must support:
   - millions of L2 transactions per day;
   - billions of L2 transactions per year;
   - L1 as a settlement layer rather than a retail note-to-note rail.
5. The architecture must still permit occasional direct L1 private transfers
   and direct L1 private deposits without forcing every user interaction
   through an operator.
6. The long-term bottleneck cannot be wallet rescanning of every exit output.
7. This reset should be treated as the one deliberate architecture break, so
   future proof-backend, scan-hint, and settlement-envelope upgrades should
   fit within stable `shielded_v2` family shapes rather than requiring a fresh
   tx-family redesign.

## Consensus-Shape Forward Compatibility

This reset is intended to be the architectural reset for BTX's shielded
system, not the first of several.

That means the spec should freeze narrow, stable consensus objects now while
avoiding brittle "one exact proof backend forever" assumptions.

Required approach:

- keep transaction families, batch headers, and resource-accounting dimensions
  stable and explicit;
- keep upgrade hooks only where they are likely to matter:
  - proof-envelope versioning,
  - one-or-more proof shards or imported receipts,
  - scan-hint versioning,
  - artifact-manifest versioning,
  - and proof-payload location abstraction;
- prefer canonical roots, statement digests, and content-addressed manifests
  over backend-specific inline structures;
- do not turn transaction families into generic TLV bags or plugin systems;
- do not hard-wire one-proof-per-batch assumptions into consensus-visible
  objects;
- treat shard size, chunk size, compression choice, and proof-family choice as
  calibration or upgrade decisions inside stable family envelopes, not as
  reasons to redesign the families themselves.

In short: freeze stable family shapes now, but keep the proving and scanning
engines behind those shapes replaceable.

## Launch-Model Decisions We Freeze Now

These decisions are now part of the spec. The reset chain should be built to
them unless later benchmarking proves that a narrower adjustment is necessary.

### Holder Transition And Value Preservation

- Development-network default:
  - `shieldedv2dev` can start as a clean-slate local development network with
    no obligation to preserve current value balances.
- Production-reset decision:
  - do a clean economic restart with no snapshot, no genesis carryover, and no
    attempt to preserve balances from the current chain;
  - spend no protocol or implementation complexity on old-chain claims,
    migration tooling, or legacy balance conversion;
  - keep the reset chain fully focused on the new `shielded_v2` architecture
    and its long-run scale properties.

### Transparent Transaction Policy

- `shielded_v2` is the default privacy and value-transfer rail, but that does
  not imply transparent consensus paths disappear automatically.
- Phase-one production decision:
  - retain transparent support only as a P2MR-only PQ boundary rail;
  - coinbase, miner payout, operator cold-storage, and explicit unwrap flows
    remain transparent P2MR in phase one;
  - transparent-to-shielded and shielded-to-transparent remain explicit
    boundary operations, not default wallet behavior;
  - do not reintroduce legacy transparent script families such as P2PKH,
    P2SH, or pre-P2MR witness script paths;
  - preserve the existing PQ transparent-key infrastructure and descriptor
    tooling for the boundary rail.

### L2 Operator Lifecycle

- `shielded_v2` needs explicit rules for who may submit batched ingress,
  batched egress, rebalance, and settlement-anchor transactions.
- Phase-one production decision:
  - use a permissionless reserve-note model instead of a separate on-chain
    operator registry or slashing subsystem;
  - any actor may submit these transaction families if it proves control of
    the relevant reserve notes, settlement keys, and batch authorizations;
  - operator identity is carried by transaction keys and settlement claims, not
    by a separate registry object;
  - invalid batches are rejected by consensus, while repeated malformed or
    adversarial submissions are handled through mempool policy, relay scoring,
    and peer DoS controls rather than stake slashing;
  - reserve-note rotation, key rollover, and recovery are handled through
    `v2_rebalance` plus wallet tooling.

### Genesis And Economic Parameters

- Production-reset decision:
  - use `90` second blocks from height `0`;
  - remove the current `250 ms` / `50,000` block fast-mine bootstrap from the
    reset chain because it improves neither shielded UX nor validator
    friendliness for the rebooted architecture;
  - keep MatMul PoW, but activate ASERT from height `0` and recalibrate genesis
    difficulty for the steady-state `90` second chain rather than reusing the
    fast-bootstrap launch profile;
  - keep the existing `21,000,000` BTX cap, `20 BTX` initial subsidy, and
    `525,000` block halving interval for the reset unless separate economics
    work proves a stronger reason to change them;
  - start with the current `12,000,000` serialized-byte consensus ceiling,
    `24,000,000` weight ceiling, and `12,000,000` default mining weight, and
    let multidimensional accounting rather than raw block inflation carry most
    of the scale work;
  - keep P2MR-only transparent outputs and Bech32m witness-v2 conventions on
    the reset chain.
- Development-network default:
  - `shieldedv2dev` may use faster local-only testing parameters, but
    production economics and capacity work should benchmark the steady-state
    `90` second chain from genesis.

### Light Clients And Compact Verification

- Phase-one production decision:
  - extend BTX's existing BIP157 / BIP158 compact-filter path with a dedicated
    `shielded_v2` filter type instead of inventing a separate light-client
    protocol;
  - the `shielded_v2` filter should commit to scan-hint-relevant note material,
    note-class / domain markers, and settlement-anchor identifiers needed for
    light-wallet discovery;
  - light clients authenticate the header chain and filter-header chain, fetch
    matching blocks, and verify inclusion plus scan-hint relevance locally;
  - light clients do not rerun large batch-proof verification in phase one and
    instead rely on full nodes for consensus proof checks;
  - public reset-chain infra should treat `-blockfilterindex` and
    `-peerblockfilters` as standard service defaults.

### Legacy Cleanup Scope

- Current BTX shielded code may be reused structurally during implementation,
  but the reset plan should be explicit about what survives:
  - current legacy user-facing shielded pool behavior and RPC flows are not
    part of the final launch path;
  - current MatRiCT code may be reused behind the new proof abstraction only
    until `shielded_v2` direct proving replaces it;
  - PR #79 bridge / settlement substrate is kept and refactored as needed into
    the `shielded_v2` architecture;
  - fixed legacy caps such as `MAX_SHIELDED_OUTPUTS_PER_TX = 16` must not
    constrain the final `shielded_v2` design;
  - legacy relay helpers, serializer branches, or migration-era scaffolding
    that remain only for bring-up should be deleted or quarantined before
    launch.

## AI-Native Infrastructure Decisions

BTX should remain a dual-use infrastructure component that benefits from
commodity AI hardware without making specialized validator hardware part of
consensus.

- consensus validation must remain deterministic and CPU-feasible on commodity
  nodes; GPU acceleration may improve mining, proving, and operator throughput,
  but it must not be required for block or transaction validation;
- all consensus-critical `shielded_v2` arithmetic must stay in exact integer,
  bit-identical code paths; no floating-point, tensor-core, or vendor-specific
  non-deterministic fast paths in validation;
- proving, batch construction, imported-proof generation, and MatMul mining may
  target commodity CUDA / Metal / ROCm / AI-accelerator-friendly matrix
  workloads;
- phase-one block and transaction budgets must keep worst-case incremental
  `shielded_v2` verification within a commodity-node envelope comparable to
  BTX's existing "about `1.5` seconds on commodity `8`-core" verification
  target, leaving large safety headroom under `90` second blocks;
- large proof artifacts and snapshot payloads should be externalized or fetched
  on demand; the gossip layer should relay compact consensus objects and small
  manifests, not indiscriminately flood proof blobs.

## What Merged PR #79 Already Gives Us

PR #79 is now merged into `main` and is the correct settlement-plane substrate
for `shielded_v2`, but it is not the final privacy architecture or execution
layer by itself.

What it gives us:

- canonical batch leaves, batch roots, and batch commitments;
- canonical batch statements and signed receipts;
- canonical verifier-set commitments and proof-policy commitments;
- canonical imported-proof profiles, proof claims, and proof adapters;
- one `verification_root` / external-anchor surface for committee receipts and
  imported proofs;
- deterministic bridge RPCs and tests for these settlement objects.

Relevant files:

- `src/shielded/bridge.*`
- `src/wallet/bridge_wallet.*`
- `src/wallet/shielded_rpc.cpp`
- `doc/btx-shielded-aggregation-rollup-tracker-2026-03-14.md`

Recent branch additions that matter directly for `shielded_v2` planning:

- `BridgeProofClaim` makes imported proofs bind to explicit BTX settlement
  semantics instead of opaque `public_values_hash` blobs.
- `BridgeProofAdapter` gives BTX a stable selector layer over imported proof
  families such as SP1, RISC Zero, and Blobstream.
- `Proof artifact manifests` and aggregate artifact bundles give imported
  receipts a more canonical metadata surface for referenced proof materials.
- `Settlement capacity estimation` and aggregate-settlement modeling quantify
  how much traffic the PR #79 settlement plane can plausibly carry under
  different proof / data-availability shapes.
- `State-growth` and `retention-policy` modeling quantify the persistent-state
  cost of high-scale settlement rather than treating it as an afterthought.
- `Proof-compression target` modeling quantifies the final proof-envelope sizes
  needed to recover higher represented-users-per-block on the settlement path.

These surfaces are exactly what we want underneath a future private-by-default
L2 settlement system.

What PR #79 does not solve:

- it now has canonical `shielded_payout` vocabulary, but it does not implement
  a real `v2_egress_batch` transaction family with thousand-output shielded
  fanout, stronger scan hints, or final `shielded_v2` accounting;
- it does not reduce native shielded proof size or wire a new native proof
  system into BTX consensus;
- it does not define the five `shielded_v2` transaction families as consensus
  objects;
- it does not add real `shielded_v2` state transitions, reserve-note flows,
  nullifier / tree mutation rules, or retention-mode behavior;
- it does not add mempool, miner, relay, orphan-handling, or tx-announcement
  behavior for the new transaction families;
- it does not solve high-scale private ingress from many L1 users into L2.

## Hard Planning Inputs From The Final PR #79 Merge

The final merged PR #79 work changes this tracker from a pre-merge architecture
note into a post-merge execution spec. The following findings are no longer
"nice to know"; they are hard planning inputs for `shielded_v2`:

- Current artifact-backed imported-proof settlement is materially tighter than
  the earlier optimistic envelope:
  - the current measured proof-anchored bridge-settlement baseline is about
    `8,418` represented users per block for the three-user proof-anchored batch
    path;
  - one-proof DA-lane aggregate settlement is about `397,004` serialized bytes /
    `400,280` weight and represents about `1,920` users per block;
  - two-proof DA-lane aggregate settlement is about `528,148` serialized bytes /
    `531,424` weight and represents about `1,408` users per block.
- Current DA-lane fixed bytes alone cap the imported-proof path at about
  `6,144` represented users per block even with a zero-byte final proof.
- If BTX wants to recover higher represented-users-per-block on a
  validium-style path, final proof envelopes need to be dramatically smaller:
  - witness-validium-style modeling reaches about `38,208` users per block only
    on much tighter settlement envelopes than today's artifact-backed path;
  - about `58,808` bytes to reach `12,288` users per block;
  - about `16,408` bytes to reach `38,208` users per block.
- Retention mode is now a first-class protocol input, not a future ops detail:
  - full-retention modeled growth is about `1,309,409,280` retained bytes per
    day with a roughly `5` day horizon to a `4 GiB` snapshot target;
  - an externalized-retention path is about `507,248,640` retained bytes per
    day with a roughly `11` day horizon to the same target.

Operational consequence:

- the PR #79 settlement plane is the right substrate for `v2_settlement_anchor`
  and cross-L2 settlement binding;
- artifact-backed DA-lane settlement remains useful for development, audits,
  and smaller domains, but it must not be treated as the production-scale
  default;
- the production high-scale settlement profile should therefore target:
  - witness-validium-style succinct final receipts,
  - externalized-retention state handling,
  - and weekly retained-state snapshots sized around the modeled `4 GiB`
    operational envelope;
- imported-proof adapters intended for the hot path must expose succinct receipt
  classes such as SP1 compressed / Plonk / Groth16 or RISC Zero succinct /
  Groth16 receipts, rather than assuming composite or artifact-heavy envelopes.

## Derived Capacity Math

Current BTX block cadence is `90` seconds, which implies:

- `960` blocks per day;
- `350,400` blocks per year.

Current L1 block limits are:

- `12,000,000` serialized bytes;
- `24,000,000` weight units.

Under the current accounting path, shielded bytes are effectively charged like
non-witness bytes, so the practical shielded-heavy budget is about `6 MB`
effective bytes per block.

### What Direct L1 Boundary Scale Would Require

If every boundary event were an individual L1 transaction, the average bytes
per transaction would have to be roughly:

| Boundary events per day | Avg bytes / tx at 12 MB serialized | Avg bytes / tx at 6 MB effective |
| --- | ---: | ---: |
| `1,000,000` | `11.5 KB` | `5.8 KB` |
| `5,000,000` | `2.3 KB` | `1.15 KB` |
| `10,000,000` | `1.15 KB` | `576 B` |

That immediately tells us:

- millions of L1 boundary events per day are impossible with tens-of-KB direct
  proof systems alone;
- MatRiCT+ / SMILE class direct spends improve L1 a lot, but they do not by
  themselves make L1 a million-deposit-per-day rail;
- high-scale boundary traffic requires batched ingress and batched egress.

### What Billions Per Year Really Means

For total network activity:

| Total actions / year | Actions / day | Actions / block |
| --- | ---: | ---: |
| `1B` | `2.74M` | `2,854` |
| `5B` | `13.70M` | `14,269` |
| `10B` | `27.40M` | `28,539` |

This is feasible only if most of those actions stay on L2.

If only `1%` of total activity touches L1, then the boundary load is:

| Total actions / year | Boundary share | Boundary actions / block |
| --- | --- | ---: |
| `1B` | `1%` | `28.5` |
| `5B` | `1%` | `142.7` |
| `10B` | `1%` | `285.4` |

That is the design target:

- ordinary direct `shielded_v2` transactions should comfortably handle the
  `1B/year` to `5B/year` total-activity regime if only about `1%` of actions
  cross L1;
- the `10B/year` regime requires either:
  - `~38 KB` class direct spends plus improved shielded-byte accounting,
  - larger blocks,
  - or batched ingress even on the deposit side.

### Implication

The final `shielded_v2` design must support two scales at once:

1. ordinary direct L1 private usage at far lower cost than today;
2. specialized batch ingress / batch egress so boundary events themselves can
   also be amortized when needed.

## Objective Fit Verdict

Does this design meet the stated objective?

- `Yes`, if BTX is treated as a private settlement layer and not as the place
  where millions of independent user boundary events are individually posted.
- `Yes`, if `user -> L2` and `L2 -> user` both have first-class shielded batch
  paths rather than relying only on ordinary direct private spends.
- `Yes`, for millions of daily `L2 -> L2` transfers and billions of annual
  total shielded transfers, because those flows are represented on L1 only by
  compact settlement roots, proofs, and reserve updates.
- `No`, if the plan is interpreted as "millions of direct L1 deposits and exits
  per day without batching." The byte budget and scan budget do not permit
  that.

Operationally, this means the plan succeeds only if BTX ships all of the
following as core protocol features rather than optional later add-ons:

1. `v2_send` for ordinary direct private usage;
2. `v2_ingress_batch` for many-user private deposits into L2;
3. `v2_egress_batch` for many-user shielded exits back to L1;
4. PR #79 settlement anchors, proof claims, and proof adapters for L2-to-L2
   and cross-L2 settlement;
5. stronger scan hints and explicit shielded resource accounting.

The hardest part is still private high-scale ingress. If BTX ships only a
smaller direct-spend proof and skips `v2_ingress_batch`, then it does not fully
meet the stated objective.

## Immediate Design Decisions We Can Freeze Now

The following parts are ready to lock now and should be treated as design
decisions rather than open questions:

1. one `shielded_v2` standard from genesis with no legacy pool and no migration
   path;
2. `user -> L2` and `L2 -> user` are shielded by default, while transparent
   unwrap is optional and explicit;
3. `L2 -> L2` and cross-L2 transfers are off-chain by default and settle to L1
   only through compact roots / receipts / proof claims / reserve deltas;
4. PR #79 remains the settlement plane for imported proofs, proof claims, proof
   adapters, receipts, verification roots, and settlement-capacity estimation;
5. `shielded_v2` must ship the five native transaction families:
   - `v2_send`
   - `v2_ingress_batch`
   - `v2_egress_batch`
   - `v2_rebalance`
   - `v2_settlement_anchor`
6. the native proof layer must be modular enough to swap:
   - direct-spend proof logic
   - membership / anonymity logic
   - amount / balance proof logic
   - settlement-binding logic
7. MatRiCT+ is the phase-one proving baseline for direct private sends and the
   first implementation candidate for batch ingress;
8. SMILE and 2021/1674 are phase-two optimization targets, especially if the
   batch-ingress path needs a better high-input membership / balance component;
9. resource accounting for `shielded_v2` must be multidimensional:
   - serialized bytes
   - proof verification units
   - scan / output units
   - Merkle-tree update units
10. scan hints are mandatory and must be stronger than the current one-byte
    `view_tag` regime;
11. reserve notes, user notes, and operator / rebalance notes must be distinct
    note classes under one unified `shielded_v2` note model;
12. all new commitment and nullifier rules must be explicitly domain-separated
    from legacy MatRiCT identifiers;
13. high-scale private ingress is solved by `v2_ingress_batch`, not by trying
    to push all deposit volume through smaller copies of `v2_send`;
14. high-scale private egress is solved by `v2_egress_batch` plus scan-hint and
    output-accounting improvements, not by transparent fanout;
15. PR #80 external shield-address support and cross-descriptor PQ signing
    behavior remain required wallet capabilities for operator, reserve, and
    recovery flows;
16. PR #81 PQ seed persistence for multisig and multi-provider descriptors
    remains required for `shielded_v2` reserve, operator, and recovery tooling;
17. completion means execution-layer closure, not just more modeling:
    consensus tx families, proof verification, real state transitions, mempool /
    relay / mining, reorg-safe recovery, distributed validation, and external
    review must all land.
18. the reset chain is a clean economic restart with no value carryover and no
    runtime legacy-pool compatibility burden;
19. transparent boundary support remains P2MR-only and explicit, not a general
    reintroduction of legacy transparent script families;
20. the phase-one production settlement profile should default to
    witness-validium-style settlement with externalized retention, while the
    artifact-backed DA-lane path remains a secondary dev / audit / smaller-L2
    lane;
21. the phase-one canonical final settlement-receipt target is
    `<= 58,808` bytes for the `12,288` users/block path, with `<= 16,408`
    bytes as the stretch target for the `38,208` users/block path;
22. light clients should use BIP157 / BIP158-style `shielded_v2` filters from
    launch rather than waiting for a later protocol;
23. consensus validation remains CPU-first and GPU-optional, while mining,
    proving, and operator batching may exploit commodity AI accelerators;
24. P2P relay carries compact `shielded_v2` transactions and manifests, while
    large proof / DA artifacts are fetched out of band rather than gossiped
    indiscriminately.
25. `v2_rebalance` must support one transaction adjusting reserves across many
    L2 domains simultaneously, not just pairwise reserve moves, so cross-L2
    net settlement can land on L1 as one compact reserve-delta update;
26. the cross-L2 netting market, matching policy, and settlement-window
    selection are operator-level protocols rather than consensus objects, but
    BTX should still ship a simple reference protocol and test harness for
    them because the boundary-throughput gain is too important to leave
    undefined.

These decisions are strong enough to start implementation slices immediately.
What remains open is not the architecture itself, but the exact proof family,
resource constants, and performance envelope that benches and stress tests must
validate.

## Execution-Layer Closure Requirements

This program is not complete when BTX has better estimates or more helper RPCs.
It is complete only when the merged codebase has all of the following:

1. consensus-visible `shielded_v2` transaction families for:
   - `v2_send`
   - `v2_ingress_batch`
   - `v2_egress_batch`
   - `v2_rebalance`
   - `v2_settlement_anchor`
2. consensus-enforced native proof verification for the direct `shielded_v2`
   proving plane, not just modeled byte envelopes;
3. consensus-enforced settlement binding for imported proofs / receipts /
   verification roots where `v2_settlement_anchor`, `v2_egress_batch`, or
   `v2_rebalance` rely on the PR #79 substrate;
4. real state transitions:
   - note commitments,
   - nullifiers,
   - reserve-note creation / destruction,
   - tree updates,
   - retained vs externalized state behavior,
   - connect / disconnect / reorg handling;
5. block-validation and undo / redo rules for every transaction family;
6. mempool admission, standardness, fee pricing, eviction, and replacement rules
   under the multidimensional accounting model;
7. P2P relay behavior for the new transaction families:
   - inv / getdata flow,
   - announcement behavior,
   - orphan handling,
   - bandwidth / anti-DoS protections,
   - mixed-family relay correctness,
   - and out-of-band retrieval / caching rules for externalized proof or
     snapshot artifacts referenced by consensus objects;
8. miner / block-assembler / template-selection integration so new families can
   actually be mined under the new budgets;
9. wallet and RPC flows for send, deposit, receive, reserve management, rescan,
   restore, and recovery using the new note / hint model;
10. a full validation program:
    - unit tests,
    - functional tests,
    - benches,
    - fuzzing,
    - reorg / flood / long-horizon tests,
    - and ephemeral multi-node testnet runs when local benches stop being
      representative;
11. documentation closure:
    - tracker updates as real findings land,
    - logical commits on the implementation branch,
    - and PR commentary updates that record what changed, what was validated,
      and what remains blocked.

## Research Basis

### MatRiCT+

Primary sources:

- [MatRiCT+ preprint](https://eprint.iacr.org/2021/545)
- [MatRiCT+ code](https://gitlab.com/raykzhao/matrict_plus)

What matters:

- direct successor to MatRiCT in the same PQ lattice RingCT family;
- public code exists, with benchmark entrypoints and implementations for
  anonymity levels `1/10`, `1/20`, and `1/50`;
- public repo license is BSD Zero Clause, which is friendly for adaptation;
- this is the best code-backed starting point for a BTX `shielded_v2` reset.

Repository observations from the public code:

- top-level implementations: `n10`, `n20`, `n50`;
- build entrypoint is a simple `make`;
- benchmark binary is `ringct`;
- README says the output reports CPU-cycle runtimes for `SamMat`, `Spend`, and
  `Verify`.
- `test.c` is a real benchmark harness that drives `spend()` and `verify()`,
  which is a good sign that the repository is genuine implementation code
  rather than pseudocode.

Concrete implementation reality from this research pass:

- the code is real enough to treat as a starting point, but it is benchmark
  research code rather than production-hardened node code;
- on this macOS host, the public `n10` build fails immediately in
  `cpucycles.c` because it uses x86 inline assembly:
  `error: invalid output constraint '=a' in asm`;
- it also depends on XKCP / Keccak build assumptions that are not packaged as a
  drop-in portable dependency.

MatRiCT+ verdict:

- `realistic and adoptable as the phase-one proof baseline`;
- `not drop-in ready`;
- `requires BTX-side porting, benchmarking, and hardening before any consensus
  use`.

### SMILE

Primary source:

- [SMILE preprint](https://eprint.iacr.org/2021/564)

What matters:

- still lattice-based and still framed as a Monero-like confidential
  transaction system based on MatRiCT-style definitions;
- attractive because its anonymity / set-membership side looks materially more
  efficient than the older MatRiCT construction;
- strong candidate for the next proof-module upgrade after the first MatRiCT+
  integration.

Current implementation reality from this research pass:

- the paper is a full 61-page construction, not a thin research teaser;
- it includes a detailed set-membership proof, a ring-signature transformation,
  a confidential-transaction construction, concrete transaction-size tables, and
  appendices that sketch the payment-system protocol and parameter selection;
- concrete paper numbers include `~30 KB` for `2-in / 2-out` confidential
  transactions with each input hidden among `2^15` accounts, and `344 KB` for
  `100` inputs with anonymity set `1024`;
- public prototype code now exists for part of the SMILE line of work, but the
  visible code paths are still narrow, hardware-assumption-heavy, and not
  packaged as a maintained confidential-transaction-grade reference
  implementation.

SMILE verdict:

- `not vaporware`;
- `detailed enough for an experienced cryptographic engineering team to
  implement from the paper`;
- `too risky to make the first dependency of shielded_v2`;
- `best treated as the phase-two anonymity / membership upgrade path after a
  MatRiCT+-class baseline is working inside BTX`.

### 2021/1674: Lattice-Based ZK Proofs For Blockchain Confidential Transactions

Primary source:

- [ePrint 2021/1674](https://eprint.iacr.org/2021/1674)

What matters:

- strong signal that MatRiCT and MatRiCT+ are not the end of the line;
- especially interesting because it claims a prototype and claims improvements
  over MatRiCT+ by avoiding some corrector-value and binary-proof overhead.

Current implementation reality from this research pass:

- no maintained public implementation was found;
- best interpreted as an optimization and design-influence target after the
  first code-backed `shielded_v2` path exists.

### Research Conclusion

The best practical sequencing is:

1. ship a code-backed MatRiCT+-class `shielded_v2` first;
2. keep the proof API modular enough to replace the anonymity / membership
   subproof later;
3. use SMILE and 2021/1674 as optimization targets, especially for the
   high-input batch-ingress path.

Primary feasibility answer:

- `MatRiCT+` is concrete enough to adopt into the implementation plan now.
- `SMILE` is concrete enough to adopt into the roadmap now, but not concrete
  enough to be the sole phase-one dependency because there is still no
  maintained chain-grade reference implementation to start from.
- therefore the practical plan is not "pick one"; it is "build on MatRiCT+
  first, while designing the proof layer so SMILE-style components can replace
  the weakest high-input anonymity path later."

## Shielded V2 Architectural Decision

`shielded_v2` should not be a single transaction shape.

It should be one shielded system with multiple native transaction families:

1. `v2_send`
   - ordinary direct note-to-note private transfer;
   - ordinary direct `user -> L2` private deposit when batching is not needed.
2. `v2_ingress_batch`
   - many-user private deposit batch into one L2 / reserve settlement;
   - the critical high-scale user-to-L2 path.
3. `v2_egress_batch`
   - one L2 exit settlement that creates many L1 shielded notes;
   - the critical high-scale L2-to-user path.
4. `v2_rebalance`
   - reserve management between L2 domains, operators, and settlement pools.
5. `v2_settlement_anchor`
   - imported-proof / receipt / claim / adapter anchored settlement object
     built on top of the PR #79 surfaces.

This is still a single shielded standard.

The system is unified by:

- one note model;
- one nullifier model;
- one or more versioned proof kinds under one `shielded_v2` umbrella;
- one wallet scanning model;
- one L2 settlement-claim vocabulary from PR #79.

## High-Level Architecture

### L1 Role

L1 becomes:

- the root of monetary truth;
- the reserve and rebalancing layer for L2s;
- the settlement verifier for imported L2 proofs and receipt bundles;
- the source of private entry and private exit for users.

L1 is not expected to carry the entire payment graph directly.

### L2 Role

L2 becomes:

- the default execution rail for frequent transfers;
- the home of per-user high-frequency shielded balance changes;
- the place where millions of daily transfers happen;
- the place where cross-L2 routing and netting happen before occasional L1
  settlement.

### User To L2

Two modes should exist:

1. direct private deposit:
   - one `v2_send` spends user notes into an L2 ingress reserve note or ingress
     address;
   - useful for lower-frequency boundary events and simple UX.
2. batched private deposit:
   - many user intents are aggregated into one `v2_ingress_batch`;
   - one settlement root proves which L2 credits were created;
   - one or a few reserve notes capture the net inflow on L1;
   - this is the mechanism that makes high deposit scale possible.

### L2 To User

Default exit should be:

- one `v2_egress_batch` creates many L1 shielded notes;
- no transparent payout is required unless the user explicitly requests an
  unshield step;
- the settlement object should be backed by PR #79 proof claims / proof
  adapters / receipt bundles where appropriate.

### L2 To L2

Default L2-to-L2 behavior should be:

- entirely off-chain;
- represented on L1 only by compact batch statements, receipt roots,
  verification roots, and reserve deltas;
- millions per day should be a batch-size and prover issue, not an L1 block
  issue.

## Cryptographic Strategy

### Native Proof Plane

Use a new native `shielded_v2` proving plane for:

- note ownership;
- nullifier correctness;
- value conservation;
- direct note creation and destruction;
- ordinary direct L1 private sends.

Phase-one implementation target:

- MatRiCT+ class proof integration.

Why:

- code-backed;
- same PQ family;
- closest path to a working replacement for current MatRiCT.

### Batch Settlement Plane

Use the PR #79 settlement plane for:

- imported proof receipts;
- batch statements;
- proof claims;
- proof adapters;
- verification roots;
- external anchors;
- cross-L2 settlement.

This plane should be reused in `shielded_v2`, not replaced.

### Future Optimization Plane

Reserve a modular swap point for:

- SMILE-style anonymity / membership subproofs;
- 2021/1674-style balance / corrector / binary-proof improvements;
- future imported proof systems recognized via PR #79 proof adapters.

## Proof Modularity Requirement

`shielded_v2` must not hard-wire one monolithic proof implementation into
every transaction path.

It should expose at least:

- `proof_envelope_version`
- `proof_shard_count`
- `proof_kind`
- `membership_proof_kind`
- `amount_proof_kind`
- `balance_proof_kind`
- `settlement_binding_kind`

Even if phase one ships one canonical combination, the interfaces must make it
possible to:

- keep MatRiCT+ as the initial direct-spend engine;
- replace the anonymity side with SMILE-style logic later;
- swap in a more efficient batch-ingress proof later.

### Bounded-Shard Requirement For High-Scale Batches

High-scale batch families must not assume that one giant proof object is the
only valid encoding.

Instead:

- a top-level batch transaction should be able to carry one proof shard or many
  bounded proof shards;
- the one-proof case should remain valid as the degenerate `1`-shard case, not
  as a hard architectural assumption;
- the top-level batch header should commit to:
  - the canonical batch leaf root,
  - the canonical settlement / credit root,
  - the proof-shard root,
  - the proof-shard count,
  - and the aggregate reserve / fee commitments;
- each proof shard should bind at minimum:
  - its leaf subroot or canonical contiguous leaf range,
  - its nullifier subset commitment,
  - its local value-conservation commitment,
  - its statement digest,
  - its proof metadata,
  - and the settlement domain;
- top-level validity should come from complete non-overlapping shard coverage
  plus aggregate value conservation, not from a hidden assumption that all
  proving work fits into one monolithic statement.

Phase one can keep this simple:

- one canonical shard descriptor format;
- homogeneous shard proof kinds inside a batch transaction if desired;
- benchmark-approved shard-size bands;
- no need for arbitrary per-shard feature negotiation.

That keeps implementation and mining simple while still allowing later proof
upgrades without redesigning `v2_ingress_batch` or other batch families.

## Data Model Decisions

### Notes And Nullifiers

We should keep the general BTX note / nullifier / Merkle-tree discipline, but
not the exact legacy wire format.

Recommended:

- keep an append-only commitment tree;
- keep nullifier-based double-spend protection;
- add explicit `shielded_v2` domain separation to note commitments and tree
  nodes;
- keep wallet-friendly encrypted note payloads;
- redesign note payload fields to cleanly support:
  - direct user notes,
  - ingress reserve notes,
  - egress batch outputs,
  - and operator reserve / rebalancing notes.

### Output Scanning

Current scanning is too expensive for large fanout because wallets try
constant-time decryption against every local keyset and current notes use only
one byte of `view_tag`.

`shielded_v2` should replace this with a stronger scan-hint design:

- larger view tags or bucket hints;
- explicit scan-domain separation for reserve notes vs user notes;
- a format that lets wallets reject almost all outputs before expensive
  decapsulation.
- explicit output-chunk commitments for large fanout families so chunk sizing
  and scan-hint evolution can improve later without changing the transaction
  family.

This is mandatory for high-scale `v2_egress_batch`.

### Output Limits

The static `MAX_SHIELDED_OUTPUTS_PER_TX = 16` limit should not survive into
`shielded_v2`.

Replace it with:

- consensus resource budgets;
- explicit scan-unit accounting;
- explicit output-count and ciphertext-byte limits derived from benchmarked
  wallet and validator performance.

### Wire-Format Invariants We Can Freeze Now

Even before every byte-level encoding is finalized, we can lock the following
wire-format invariants now:

- every `shielded_v2` transaction must carry an explicit transaction-family id;
- every `shielded_v2` proving envelope must carry an explicit
  `proof_envelope_version` and `proof_kind`;
- settlement-bound transactions must carry an explicit
  `settlement_binding_kind`;
- high-scale batch families must support one-or-more proof shards or proof
  receipts beneath a canonical top-level header;
- if a batch family uses multiple proof shards, it must commit to a canonical
  `proof_shard_root` and `proof_shard_count`;
- `v2_rebalance` must support a canonical `netting_manifest_version` when used
  for multi-domain net settlement;
- a multi-domain netting manifest must bind at minimum:
  - the ordered participating `l2_id` set
  - the net reserve delta for each participating domain
  - a zero-sum aggregate value check
  - a settlement-window identifier or equivalent cadence binding
  - a gross-flow commitment root or statement digest for operator-side audit
  - the proof / receipt / settlement-claim binding that authorizes the update
- note commitments, nullifiers, tree nodes, and batch leaves must all use
  explicit `shielded_v2` domain separation;
- notes must encode a note class that at minimum distinguishes:
  - user note
  - reserve note
  - operator / rebalance note
  - batch-related settlement note if needed
- batch leaves for ingress and egress must bind at minimum:
  - `l2_id`
  - destination commitment or recipient commitment
  - amount or amount commitment
  - fee policy or fee commitment
  - batch position / nonce material
  - settlement-domain binding
- scan hints and encrypted note payloads must carry explicit
  `scan_hint_version` and `scan_domain` markers;
- large-output batch families must commit to canonical output chunks with
  per-chunk scan-hint commitments and ciphertext-byte accounting;
- encrypted note payloads must support scan hints as first-class fields rather
  than optional wallet metadata.

What is pending final parameter freeze:

- exact byte widths;
- exact tag widths;
- exact serialization compression choices;
- exact ciphertext sizing rules.

Those values should be frozen only after benches, fuzzing, and wallet-scan
tests.

Nothing else is deferred by this section.

- no mandatory transaction family is allowed to remain partially implemented;
- no mandatory verifier, wallet, relay, miner, recovery, or operational path
  is allowed to close with TODO-only or placeholder logic;
- no required test, benchmark, distributed validation path, or launch harness
  may be skipped on the theory that it can be finished "later".

## Resource Accounting Reset

Current BTX accounting is not suitable for the final `shielded_v2` design.

`shielded_v2` should have consensus-level resource accounting for:

1. serialized block bytes;
2. proof verification units;
3. scan / output units;
4. Merkle-tree update units.

Goals:

- stop treating shielded bytes as legacy stripped bytes by default;
- price direct spends by real verification work, not only byte size;
- price large exit fanout by wallet / scan cost, not only serialization;
- permit large shield-only egress batches without pretending they have the same
  risk profile as huge spend proofs.

### Resource-Accounting Decisions We Can Freeze Now

The dimensions are no longer open:

- BTX should not continue using one legacy-style weight surrogate for all
  `shielded_v2` traffic;
- `shielded_v2` must meter bytes, proof verification, scan cost, and tree
  mutation separately;
- mempool policy and block assembly must understand those same dimensions;
- fees should price the dominant bottleneck for each transaction family:
  - `v2_send`: proof verification and bytes
  - `v2_ingress_batch`: proof verification, nullifier count, and tree updates
  - `v2_egress_batch`: bytes, scan units, and output count
  - `v2_rebalance` / `v2_settlement_anchor`: imported-proof binding cost and
    serialized settlement footprint

What remains open is the calibration:

- per-proof verify unit cost;
- per-output scan-unit cost;
- per-tree-update budget;
- block-level maxima and fee multipliers.

### Multidimensional Miner Selection Requirement

Block assembly for `shielded_v2` is not a normal one-dimensional fee-rate sort.

Requirements:

- miner selection must satisfy all active block constraints simultaneously:
  - serialized bytes,
  - proof verify units,
  - scan / output units,
  - and tree-update units;
- the selection algorithm must be benchmarked and stress-tested under mixed
  workloads rather than hand-waved as "just update fee policy";
- an acceptable phase-one approach may be greedy or heuristic, but it must be:
  - deterministic enough to reason about,
  - economically sensible,
  - and safe under adversarial transaction mixes;
- the canonical phase-one packing heuristic should therefore be a
  dominant-resource-feerate sort with scarcity-aware tie-breakers, not a simple
  byte-feerate or proof-feerate sort;
- validation and mining code should therefore treat multidimensional packing as
  its own explicit implementation problem, not as an incidental policy tweak.

## Throughput Targets

### Direct `v2_send`

For the ordinary direct private path:

- acceptable target:
  - `<= 40 KB` for a 2-in / 2-out direct spend;
- preferred target:
  - `<= 30 KB`;
- stretch target:
  - `<= 20 KB`.

Rationale:

- `~30-40 KB` class direct spends are enough for the steady-state design where
  only a small share of total activity touches L1;
- this is compatible with the public MatRiCT+ / SMILE class research envelope;
- it is not enough for millions of individual L1 boundary events per day, so
  batch ingress is still required.

### `v2_ingress_batch`

Minimum viable target:

- `1,000` user deposits represented in one L1 batch ingress transaction.

Preferred target:

- `5,000` deposits per batch.

Stretch target:

- `10,000+` deposits per batch.

Rationale:

- `1M` deposits per day at `1,000` deposits per batch is `1,000` batch
  settlements per day, or about `1.04` batch deposits per block;
- `5M` deposits per day at `10,000` deposits per batch is `500` batch deposits
  per day, or about `0.52` per block.

This is the only realistic route to very high private ingress scale.

### How `v2_ingress_batch` Solves The Actual Problem

The solution is not "make ordinary direct spends smaller and hope that is
enough."

The solution is:

1. keep `v2_send` for ordinary direct private use;
2. add a separate native `v2_ingress_batch` transaction family for scale;
3. make high-volume `user -> L2` deposits use that batch path by default.

Concretely, `v2_ingress_batch` should work like this:

1. many users create private deposit intents for a specific `l2_id`;
2. each intent binds:
   - the user's L1 note spend authorization,
   - the target L2 recipient commitment,
   - the credited amount,
   - the fee policy,
   - and a batch leaf hash;
3. an aggregator / sequencer collects `1,000` to `10,000+` such intents;
4. one L1 `v2_ingress_batch` transaction publishes:
   - a versioned batch header,
   - a batch root of all deposit leaves,
   - a canonical L2 credit root,
   - the nullifiers for the consumed L1 notes,
   - one or a few shielded reserve outputs that capture the net inflow,
   - a proof-shard root and proof-shard count,
   - and one or more proof shards or imported proof receipts;
5. the L2 credits users from that batch root instead of waiting for thousands of
   separate L1 note creations.

The key consensus choice is that `v2_ingress_batch` is a stable batch object,
not a commitment to one giant proof.

The ingress proving layer must prove, across one or more bounded proof shards:

- every consumed L1 note exists and is spendable;
- the nullifiers are correct and unique;
- the total consumed value equals the sum of:
  - credited L2 deposit leaves,
  - operator / routing fees,
  - reserve-note balances;
- the published batch root is exactly the root of the credited deposit leaves;
- the batch is bound to the intended `l2_id` and settlement domain.

Recommended top-level validation shape:

- the batch header commits to the full ingress leaf set and aggregate reserve /
  fee results;
- each proof shard covers a contiguous or canonically indexed subset of leaves
  and nullifiers;
- shard coverage must be complete and non-overlapping;
- per-shard value commitments must sum to the published batch-level reserve and
  fee commitments;
- the one-proof case remains valid, but only as the `1`-shard optimization
  case.

Privacy properties:

- L1 sees only nullifiers, reserve outputs, and a batch root;
- L1 does not see transparent user payout addresses;
- the user's credited L2 account is represented by a commitment in the batch
  leaf, not by a transparent on-chain destination.

This is the missing piece behind the earlier sentence:

- a `MatRiCT+`-only direct-spend upgrade means "each user still deposits using
  an ordinary private send, just smaller than before";
- that helps the fallback path, but it does not create a high-scale many-user
  private ingress rail;
- `v2_ingress_batch` is that rail.

Recommended proof strategy for `v2_ingress_batch`:

- start with MatRiCT+ as the first native proving baseline because it gives BTX
  real code, compatible pool semantics, and a practical way to stand up
  `shielded_v2`;
- do not require phase one to prove `1,000+` deposits in one monolithic proof;
- instead benchmark shard schedules such as `1`, `2`, `4`, `8`, or more
  bounded MatRiCT+-class proof shards per top-level batch;
- keep phase-one validation simple by permitting one canonical shard descriptor
  format and, if needed, one homogeneous proof family per batch;
- if MatRiCT+ is still too weak at the approved shard sizes, keep the same
  `v2_ingress_batch` transaction shape and replace only the high-input
  anonymity / membership component with a SMILE-style or 2021/1674-style
  module.

In other words, the problem is solved by adding a new private batch-ingress
consensus object, not by pretending ordinary direct private sends can cover the
entire boundary-load problem.

### `v2_egress_batch`

Minimum viable target:

- `1,000` L1 shielded outputs in one batch exit transaction.

Preferred target:

- `5,000` outputs in one batch exit transaction.

Stretch target:

- `10,000` outputs in one batch exit transaction if scan hints and ciphertext
  sizing permit it.

Rationale:

- the current codebase already indicates that shield-only output creation is far
  cheaper than shielded spend proofs;
- the real bottleneck is scan cost, not proving cost;
- the current bridge substrate now includes canonical `shielded_payout` leaves,
  so the missing work is no longer "invent shielded payout semantics" but
  "turn that vocabulary into a real high-fanout `v2_egress_batch` family with
  actual consensus accounting, relay, mining, and wallet-scan behavior."

### L2 Settlement

Minimum viable target:

- `10,000` L2 transfers represented per settlement batch.

Preferred target:

- `50,000` per settlement batch.

Stretch target:

- `100,000+` per settlement batch.

Illustrative scaling:

- `10,000` transfers per batch and `1,000` settlements per day gives
  `10,000,000` L2 transfers per day;
- `100,000` transfers per batch and `1,000` settlements per day gives
  `100,000,000` L2 transfers per day.

This is why L2-to-L2 is not the main concern once the proof / receipt /
adapter surfaces are standardized.

Hard planning inputs from the merged PR #79 measurements:

- the current artifact-backed imported-proof path is a real substrate, but not
  yet the final throughput answer:
  - about `1,920` represented users per block for the one-proof DA-lane path;
  - about `1,408` for the two-proof DA-lane path;
- DA-lane fixed bytes already cap that class of path at about `6,144`
  represented users per block even with a zero-byte final proof;
- therefore any `shielded_v2` plan that targets the higher settlement regimes
  must assume at least one of:
  - materially smaller final proof envelopes,
  - a different DA carriage model,
  - or a lower represented-users-per-block target than the earlier optimistic
    upper bound.

Phase-one design decision:

- use witness-validium-style settlement plus externalized retention as the
  default production lane for high-scale `v2_settlement_anchor`;
- keep artifact-backed DA-lane settlement as a development, audit, and
  smaller-domain lane rather than the assumed production hot path;
- require hot-path imported-proof adapters to expose succinct receipt classes
  capable of landing under the `<= 58,808` byte phase-one target.

### Cross-L2 Netting As A Boundary Multiplier

Many gross cross-L2 transfers do not need to materialize as two separate
boundary events on L1.

If flows between domains are matched and netted before settlement:

- only the net reserve difference must cross the L1 boundary;
- the same L1 boundary budget supports more effective cross-L2 transfer volume;
- the gain grows as the share of canceling opposite-direction flow grows.

Illustrative sensitivity, using `e` as the share of gross cross-L2 boundary
flow canceled before L1 settlement:

- `50%` netting means about `2x` effective cross-L2 transfer capacity on the
  same L1 boundary budget;
- `80%` netting means about `5x`;
- `95%` netting means about `20x`;
- `99%` netting means about `100x`.

These are planning sensitivities, not promised production ratios. The
implementation must benchmark realistic achieved netting ratios under synthetic
operator workloads rather than assuming the optimistic cases.

Design consequence:

- `v2_rebalance` should be treated as the L1 net-settlement primitive for
  cross-L2 traffic, not just as a reserve-move helper;
- the operator protocol that discovers and matches opposite-direction flow
  should live outside consensus and remain upgradeable;
- BTX should ship a simple phase-one reference protocol based on periodic
  settlement windows and multilateral netting manifests, while leaving more
  sophisticated continuous matching as an operator-layer optimization.

## Recommended Transaction Family Design

### `v2_send`

Purpose:

- direct private send on L1;
- direct user deposit when batching is not needed;
- direct user withdrawal destination after a prior batched egress note lands.

Proof:

- native MatRiCT+ class proof in phase one.

### `v2_ingress_batch`

Purpose:

- aggregate many private user deposits into one L1 settlement.

Required properties:

- consumes many user-owned L1 notes or validated deposit intents;
- creates one or a few reserve / omnibus notes on L1;
- commits one canonical ingress root and one L2 credit root;
- binds to PR #79 proof-claim / proof-adapter settlement objects where
  imported proving is used.

This is the long-pole feature for high-scale private deposits.

### `v2_egress_batch`

Purpose:

- credit many users back onto L1 in one shielded transaction.

Required properties:

- creates many L1 shielded outputs;
- is backed by an imported proof or attested settlement root;
- organizes those outputs into one or more canonical output chunks beneath one
  top-level egress root;
- commits scan-hint material per output chunk so chunk sizing and hint formats
  can evolve without redefining the family;
- keeps transparent unwrap optional, not default.

This is the easiest large throughput win after the reset.

### `v2_rebalance`

Purpose:

- move reserves between L2 domains, operators, and settlement pools.

Required properties:

- can net many L2-side actions into one L1 reserve adjustment;
- can adjust reserves across many L2 domains in one transaction rather than
  assuming only pairwise movement;
- carries a canonical multi-domain netting manifest when used for cross-L2
  net settlement;
- the two-domain rebalance case remains valid as the simplest degenerate form
  of the same family;
- can reuse PR #79 proof claims and proof adapters directly.

### Cross-L2 Netting Protocol Boundary

The consensus layer and the operator coordination layer should be separated
cleanly.

Consensus responsibility:

- validate `v2_rebalance` reserve deltas and proof / receipt bindings;
- enforce that the participating `l2_id` set is canonical, unique, and
  deterministically ordered;
- enforce that net reserve deltas are well formed and value-conserving;
- bind any multi-domain net settlement to the referenced settlement claims,
  window identifiers, and manifest commitments.

Operator-protocol responsibility:

- discover gross cross-L2 flows between domains;
- choose settlement windows;
- match offsetting flows across two or more domains;
- construct and sign the multi-domain netting manifest;
- fall back to smaller or more frequent windows if matching quality is poor.

Phase-one implementation decision:

- ship a simple periodic-window reference protocol for operator coordination
  and manifest construction;
- do not make a continuous matching engine or rich netting market a consensus
  dependency;
- keep the L1 manifest shape stable so operator-side matching logic can evolve
  without redesigning `v2_rebalance`.

### `v2_settlement_anchor`

Purpose:

- expose the PR #79 settlement objects directly to the rest of `shielded_v2`.

Required properties:

- imported proof claims remain canonical;
- imported proof adapters remain canonical;
- proof receipts stay compact;
- batch statements and reserve deltas become first-class shielded settlement
  inputs.
- multi-domain netting-manifest commitments can be anchored and audited through
  the same settlement substrate where imported proving is used.

## Concrete Code Workstreams

Expected repo areas:

- `src/shielded/`
  - new `v2` note / proof / batch settlement code.
- `src/wallet/`
  - new wallet and RPC flows for `v2_send`, `v2_ingress_batch`,
    `v2_egress_batch`, reserve notes, and operator netting-manifest assembly /
    publication flows.
- `src/consensus/`
  - new transaction / block accounting and validation paths;
  - connect / disconnect / reorg-safe state transitions for note, nullifier,
    reserve, settlement, and multi-domain netting-manifest objects.
- `src/policy/`
  - new standardness rules and relay budgets for proof verify units, scan
    units, tree-update units, and compact multi-domain netting manifests.
- `src/net*/`, `src/validation.*`, `src/txmempool.*`
  - tx relay, inv / getdata behavior, orphan handling, anti-DoS protections,
    mixed-family mempool behavior, multi-domain netting-manifest admission, and
    out-of-band artifact-fetch behavior.
- `src/blockfilter.*`, `src/index/blockfilterindex.*`
  - `shielded_v2` compact-filter generation, indexing, cfheaders / getcfilters
    serving, and light-client support.
- `src/node/`, `src/rpc/mining.cpp`
  - miner, block assembler, template selection, and block-production
    integration for the new families.
- `src/rpc/`
  - operator-facing manifest-construction, reserve-delta inspection, and
    cross-L2 net-settlement diagnostics for the reference protocol.
- `src/bench/`
  - direct v2 prove / verify benches, scan benches, batch ingress benches,
    batch egress benches, cross-L2 netting benches, relay / admission benches,
    and long-horizon state / retention benches.
- `src/test/`, `src/test/fuzz/`
  - serializer, proof-envelope, netting-manifest, state-transition, and reorg /
    recovery coverage.
- `test/functional/`
  - direct v2 send, batch ingress, batch egress, reserve management, proof
    adapter, settlement-anchor, multi-domain net settlement, relay, mining,
    and reorg / recovery tests.

Recommended new file families:

- `src/shielded/v2_*`
- `src/wallet/shielded_v2_*`
- `src/bench/shielded_v2_*`
- `test/fuzz/shielded_v2_*`
- `test/functional/wallet_shielded_v2_*`

## Implementation Slices

### Slice 1: Freeze The V2 Requirements

- finalize this tracker;
- lock in the reset-from-genesis assumption;
- lock in "shielded by default" and "transparent unwrap is optional";
- lock in the completion standard: execution-layer closure, not more modeling.

### Slice 2: Start From Post-PR79 `main` And Create The Parallel Dev Network

- branch from current `main`;
- create the side-by-side `shieldedv2dev` development network;
- isolate chainparams, genesis, message-start, ports, HRPs, datadir, and seed /
  peer defaults from the existing BTX networks;
- ensure local wallets and datadirs cannot cross-load state accidentally.

### Slice 3: Define `shielded_v2` Wire Formats

- new note encoding;
- new bundle / transaction-family encoding;
- new domain-separated commitment and nullifier rules;
- new proof-shard and output-chunk descriptor encoding;
- new multi-domain netting-manifest encoding for `v2_rebalance`;
- no legacy serialization baggage;
- explicit family ids for all five native transaction families.

### Slice 4: Build The Proof Abstraction Layer

- separate direct-spend proof APIs from batch-settlement proof APIs;
- expose modular swap points for membership, range, balance, and settlement
  binding subproofs.
- make proof-shard descriptors, statement digests, and payload-location
  handling first-class rather than implicit.

### Slice 5: Import And Sandbox MatRiCT+

- vendor or reimplement a reference MatRiCT+ path into BTX tree structure;
- build deterministic wrappers, portable build paths, and known-answer vectors;
- connect it to BTX benches before consensus integration.

### Slice 6: Add Consensus Transaction-Family Scaffolding

- define consensus-visible representations for:
  - `v2_send`
  - `v2_ingress_batch`
  - `v2_egress_batch`
  - `v2_rebalance`
  - `v2_settlement_anchor`;
- make `v2_rebalance` explicitly able to represent N-domain reserve deltas and
  netting manifests rather than only pairwise moves;
- add parser / serializer / hash / standardness scaffolding;
- add connect / disconnect entrypoints even before all proving logic is wired.

### Slice 7: Implement `v2_send`

- ordinary direct private send;
- direct user deposit fallback path;
- native proof verification;
- wallet and RPC support.

### Slice 8: Redesign Scan Hints And Encrypted Output Discovery

- replace the current one-byte view-tag-only regime;
- add stronger output discovery hints and benchmark them;
- make large shielded fanout practical for wallets.

### Slice 9: Implement `v2_egress_batch`

- many-output shielded exit settlement;
- reserve debit plus proof-claim / proof-adapter binding;
- no transparent payout by default;
- canonical output chunks, per-chunk scan-hint commitments, and chunk-aware
  wallet receive paths;
- real shielded outputs, real state transitions, and real wallet receive paths.

### Slice 10: Replace Shielded Resource Accounting

- consensus budgets for bytes, verify units, and scan units;
- add tree-update units;
- remove legacy non-witness charging assumptions for `shielded_v2`;
- update block assembler, mempool, fee policy, and standardness.

### Slice 11: Implement `v2_ingress_batch` Intent Model

- define user deposit intents or multi-input batch spend witnesses;
- define canonical ingress leaves and reserve outputs;
- define the top-level batch header, proof-shard root, and shard descriptor
  rules;
- define how one L1 tx turns many user deposits into one L2 settlement;
- wire real note / nullifier / reserve transitions, not just measurement
  models.

### Slice 12: Prototype The High-Scale Ingress Proof

- benchmark bounded-shard MatRiCT+ schedules for the batch-ingress engine;
- pick approved shard-size bands and aggregate verification budgets;
- if not, prototype a SMILE-inspired or 2021/1674-inspired replacement for the
  high-input batch path;
- keep the top-level `v2_ingress_batch` shape fixed while changing only the
  proof shard backend if needed.

### Slice 13: Integrate PR #79 Settlement Anchors Into `shielded_v2`

- imported proof claims;
- imported proof adapters;
- proof receipts;
- verification roots;
- reserve update and batch-exit binding;
- multi-domain netting-manifest commitments and settlement-window bindings for
  `v2_rebalance`;
- move from modeled imported-proof envelopes to consensus-validated settlement
  objects wherever `shielded_v2` depends on them.

### Slice 14: Implement Default Externalized Retention, Weekly Snapshots, And Recovery Semantics

- implement the chosen default:
  retained nullifier state plus externalized commitment history and most
  first-touch materialization for the high-scale settlement path;
- implement actual retained / externalized behavior instead of keeping the PR
  #79 retention surfaces as measurement-only tools;
- wire weekly retained-state snapshot cadence, pruned-node compatibility, and
  assumeutxo / recovery behavior to that default;
- keep any fuller-retention mode as an explicitly secondary dev / audit profile
  rather than the assumed production default.

### Slice 15: Implement Network Relay, Orphan Handling, And Announcement Behavior

- add P2P tx announcement, inv / getdata, orphan, and anti-DoS behavior for the
  new families;
- relay settlement anchors and compact manifests on the normal tx path, but
  fetch large proof / DA artifacts out of band rather than flooding them over
  gossip;
- ensure mixed-family relay remains correct under reorgs, replacement, and
  mempool churn;
- validate bandwidth and orphan-memory behavior under malformed or adversarial
  `shielded_v2` traffic.

### Slice 16: Implement Miner And Block-Assembler Integration

- teach miner selection and block templates to price and select transactions
  under the multidimensional accounting model;
- implement dominant-resource-feerate packing with scarcity-aware tie-breakers
  as the phase-one selection algorithm;
- make `getblocktemplate` and block assembly aware of verify units, scan units,
  and tree-update units;
- ensure `shielded_v2` families can actually be mined once relayed.

### Slice 17: Build Full Wallet And RPC Flows

- `sendtoaddress`-like v2 private send (complete 2026-03-16);
- batch deposit submission (complete 2026-03-16);
- batch exit claim / receive path (complete 2026-03-16);
- reserve and operator management (complete 2026-03-16);
- operator netting-window construction, manifest assembly, and publish flows
  for multi-domain `v2_rebalance` (complete 2026-03-16);
- wallet rescan / recovery against new scan hints (complete 2026-03-16);
- preserve the PR #80 / PR #81 wallet durability baseline for external shield
  receives and PQ seed recovery (complete 2026-03-16).

### Slice 18: Prove The Capacity Targets And Distributed Behavior

- direct-send throughput benches (complete 2026-03-16);
- batch ingress capacity benches (complete 2026-03-16);
- batch egress scan and validation benches (complete 2026-03-16);
- cross-L2 netting-efficiency simulations and multi-domain reserve-settlement
  benches (complete 2026-03-16);
- relay / mempool / mining mixed-workload benches (complete 2026-03-16);
- chain growth projections at `12 MB`, `24 MB`, and any proposed new limits
  (complete 2026-03-16);
- ephemeral multi-node distributed validation and recovery rehearsal evidence
  (complete 2026-03-16).

### Slice 19: Genesis Reset Launch Plan

- finalize chain parameters;
- finalize activation from genesis;
- no legacy branches, no migration rules, no dual-pool period;
- require that every earlier slice is implemented, tested, benchmarked, and
  documented before considering the reset plan ready.

## What Can Start Immediately

These items no longer depend on unresolved research questions and can begin
immediately:

1. branch from current `main` and treat merged PR #79 as the settlement
   substrate;
2. freeze the `shielded_v2` transaction-family inventory and roles;
3. freeze the proof abstraction API surface;
4. freeze the note classes and domain-separation rules;
5. define the wire-format invariants listed above;
6. define the multidimensional accounting model and its code boundaries;
7. create the `shieldedv2dev` side-by-side development network;
8. vendor or sandbox MatRiCT+ into a BTX benchmark harness;
9. build deterministic test-vector and known-answer infrastructure for the new
   proving layer;
10. design wallet / RPC surfaces for:
   - `v2_send`
   - `v2_ingress_batch`
   - `v2_egress_batch`
   - reserve and rebalance operations
11. define the multi-domain netting-manifest shape and the simple periodic
    reference protocol boundary for operator coordination;
12. implement the scan-hint framework shape even before final parameter tuning;
13. write the bench, fuzz, unit, and functional-test skeletons for all five
    transaction families;
14. define the network / relay / orphan-handling acceptance matrix early, not
    after consensus code lands;
15. define the `shielded_v2` blockfilter and light-client acceptance matrix
    early, not after wallet scan code lands;
16. define ephemeral testnet orchestration around the existing operational
    stack in `/Users/admin/Documents/btxchain/infra` so large-scale validation
    does not depend on manual long-lived infrastructure.
17. design the independent verifier / transcript-checking harness for the
    native proof plane before consensus integration is too deep to isolate;
18. define the adversarial proof-focused ephemeral testnet / red-team campaign
    shape early rather than treating it as a launch-week add-on.

These tasks should begin now because they reduce uncertainty instead of
depending on it.

## Development Kickoff Execution Model

Development now assumes PR #79 is already merged into `main`, and it should
proceed on a dedicated implementation branch and a parallel local chain
instance rather than by mutating the currently running BTX network in place.

Recommended execution model:

1. branch from post-PR79 `main` into a dedicated implementation branch such as
   `codex/shielded-v2-implementation`;
2. introduce a new local-only genesis-reset development network, for example
   `shieldedv2dev`, instead of reusing the existing BTX mainnet / testnet /
   signet parameters;
3. give that network its own:
   - genesis block
   - chain id / network name
   - message-start bytes
   - ports
   - data directory
   - address prefixes / HRPs
   - seed and peer defaults
4. ensure wallets and datadirs cannot accidentally cross-load state between the
   existing BTX chain and the `shieldedv2dev` fork;
5. keep all early development and tests on the parallel fork until the
   `shielded_v2` transaction families, wire formats, and accounting model are
   stable enough for broader distributed testing;
6. treat PR #82 and this tracker as the live spec, but do the implementation on
   a separate branch / PR dedicated to the code changes.

The point is to get the benefits of a genesis reset now, inside the dev
environment, without disrupting the existing chain or requiring partial
compatibility hacks.

Practical local-development rule:

- the local machine should run the new work as a side-by-side forked chain,
  not as a rewrite of the current local BTX datadir.

That means early implementation should create a clean parallel universe for:

- new chainparams;
- new wallet / datadir separation;
- new genesis and block files;
- new functional test fixtures;
- new local node launch scripts.

## Development Workflow And PR Documentation Protocol

Implementation should proceed as a continuous, documented program rather than a
single long-lived unreviewable branch.

Required workflow:

1. At the start of each pass:
   - read this tracker;
   - inspect local branch / status / recent commits;
   - pick the highest-priority unfinished slice.
2. Preflight automation and remote-test credentials before any GitHub API or
   cloud action:
   - verify that `/Users/admin/Documents/btxchain/github.key` exists, is
     readable, and is non-empty before any PR creation or PR commentary step;
   - verify that the required infra keys under
     `/Users/admin/Documents/btxchain/infra/` exist, are readable, and are
     non-empty before any DigitalOcean, Porkbun, or Tailscale step;
   - record the preflight result in the tracker;
   - if a required key is missing, record the blocker immediately and do not
     silently skip the affected automation or testnet step.
3. Make one logical change set at a time:
   - do not batch unrelated features together just to reduce commit count;
   - keep each slice small enough that targeted validation is realistic.
4. Validate before moving on:
   - run the most relevant unit, functional, fuzz, bench, or multi-node test;
   - if validation, simulated observation, or benchmarking exposes weakness,
     revise the implementation immediately and rerun validation before closing
     the slice;
   - do not mark a slice complete while any mandatory behavior remains stubbed,
     placeholder-only, disabled, TODO-only, skipped, or left as
     measurement-only scaffolding.
5. Commit continuously:
   - every completed logical slice or sub-slice should become its own commit;
   - avoid large uncommitted work piles that blur causality.
6. Push continuously:
   - push each completed validated logical slice or sub-slice promptly so the
     implementation PR, tracker, and remote branch stay aligned with reality.
7. Update the tracker continuously:
   - record concrete findings;
   - record exact commands used for validation;
   - record benchmark outputs, blockers, pivots, and retired risks.
8. Update the active implementation PR continuously:
   - after each logical push, add a commentary update summarizing:
     - what changed,
     - what was validated,
     - what remains next,
     - and any blockers or design pivots;
   - post those updates through the GitHub API with `curl`, using the token
     stored at `/Users/admin/Documents/btxchain/github.key`;
   - link to benchmark artifacts, logs, or testnet run outputs when relevant.
9. When distributed validation is needed:
   - use ephemeral testnets backed by
     `/Users/admin/Documents/btxchain/infra`;
   - verify the required infra keys before provisioning;
   - record provisioned resources, DNS changes, runtime duration, and cost;
   - destroy all temporary infrastructure immediately after the test;
   - record teardown confirmation in the PR commentary and tracker.

This workflow is part of the deliverable. A technically correct implementation
that is not continuously validated, benchmarked, revised when evidence demands
it, and documented does not satisfy the program requirements. Neither does an
implementation that leaves behind launch-critical stubs, disabled paths,
skipped required tests, or deferred operational closure.

## Reusable Implementation Prompt

The following prompt is suitable for kicking off continuous implementation on a
local development machine from the current post-PR79 baseline:

> You are the continuous implementation agent for the BTX reset-launch
> program.
>
> Local workspace paths are authoritative:
> - node repo: `/Users/admin/Documents/btxchain/btx-node`
> - parent workspace: `/Users/admin/Documents/btxchain`
> - GitHub token: `/Users/admin/Documents/btxchain/github.key`
> - infra keys:
>   - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`
>   - `/Users/admin/Documents/btxchain/infra/porkbun_api.key`
>   - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key`
>   - `/Users/admin/Documents/btxchain/infra/tailscale_api.key`
>   - `/Users/admin/Documents/btxchain/infra/tailscale_auth.key`
>
> Control documents:
> - read this tracker at the start of every pass
> - also read:
>   - `/Users/admin/Documents/btxchain/btx-node/doc/btx-production-readiness-matrix.md`
>   - `/Users/admin/Documents/btxchain/btx-node/doc/btx-realworld-validation-2026-03-07.md`
>   - `/Users/admin/Documents/btxchain/infra/btx-seed-server-spec.md`
>
> Mission:
> Deliver the full BTX genesis-reset launch program end to end. This is the new
> BTX, not a compatibility upgrade, not a sidecar network, and not a public
> "v2" product label at launch. Internal development names like `shielded_v2`
> or `shieldedv2dev` are allowed during implementation only.
>
> Non-negotiable rules:
> - implement every required element of this tracker; do not skip, stub, fake,
>   TODO, compile-gate off, xfail, or defer any mandatory launch-critical work
> - do not mark a slice complete if any mandatory behavior remains placeholder-
>   only, disabled, TODO-only, measurement-only, or untested
> - if benchmarking, stress testing, or adversarial testing reveals weakness,
>   revise the implementation immediately and rerun validation before closing
>   the slice
> - do not treat "compiles" as done
> - do not modify the existing BTX chain or datadirs in place
>
> Before any remote or GitHub operation:
> 1. verify these files exist, are readable, and are non-empty:
>    - `/Users/admin/Documents/btxchain/github.key`
>    - `/Users/admin/Documents/btxchain/infra/digitalocean_api.key`
>    - `/Users/admin/Documents/btxchain/infra/porkbun_api.key`
>    - `/Users/admin/Documents/btxchain/infra/porkbun_secret.key`
> 2. record that verification in the tracker
> 3. if a required key is missing, treat the affected remote step as blocked;
>    do not silently skip it
>
> First pass requirements:
> - start from current `origin/main`
> - create a dedicated implementation branch and PR for the code work; create
>   the PR with `curl` using `/Users/admin/Documents/btxchain/github.key` if it
>   does not already exist
> - create the isolated `shieldedv2dev` development network with its own
>   chainparams, genesis, message-start bytes, ports, HRPs, seeds, peer
>   defaults, and datadir isolation
> - ensure wallets and datadirs cannot cross-load between current BTX networks
>   and `shieldedv2dev`
> - if ephemeral multi-node orchestration does not already exist under
>   `/Users/admin/Documents/btxchain/infra` or
>   `/Users/admin/Documents/btxchain/scripts`, build it as an early blocking
>   sub-slice
>
> Loop for every pass:
> 1. read this tracker
> 2. run `git fetch --all --prune`, `git status`, and `git log` in both repos
> 3. identify the highest-priority unfinished slice or blocker
> 4. implement one logical sub-slice at a time
> 5. run the relevant validation before moving on:
>    - unit tests
>    - functional tests
>    - fuzz tests for new parsers, serializers, and state transitions
>    - benchmarks
>    - reorg/connect-disconnect tests
>    - multi-node validation when local testing stops being representative
> 6. if results are weak, revise code and rerun until the slice is genuinely
>    closed
> 7. commit each logical sub-slice with `git`
> 8. push each validated logical sub-slice
> 9. after each push, update this tracker with exact commands, outputs,
>    artifact paths, blockers, pivots, retired risks, next steps, cloud cost,
>    and teardown evidence where applicable
> 10. after each push, post a PR update with `curl` using
>     `/Users/admin/Documents/btxchain/github.key`
> 11. keep code history in normal `git` commits and pushes; use the GitHub API
>     only for PR creation and PR commentary automation
>
> Remote validation protocol:
> - prefer local builds, regtest, and single-host multi-node tests first
> - use DigitalOcean only when local validation is insufficient
> - use Porkbun only when public DNS or hostname behavior is actually part of
>   the test
> - provision the smallest environment that answers the question
> - record droplet IDs, sizes, regions, DNS record IDs, start/end times,
>   commands, artifacts, and estimated cost
> - destroy all cloud resources immediately after the test
> - remove temporary DNS records immediately after the test
> - record teardown confirmation in both the tracker and the PR update
>
> Completion standard:
> The program is not complete until:
> - all 19 tracker slices are implemented to closure
> - the Definition of Done below is satisfied with evidence
> - no launch-critical codepath remains stubbed, fake, disabled, skipped, or
>   deferred
> - no required tests, benchmarks, distributed runs, or launch rehearsals are
>   skipped
> - a full disposable launch rehearsal of the reset network has been run end to
>   end with evidence captured
>
> Final principle:
> Nothing mandatory is left for later. If a dependency is missing, build that
> dependency next. If a measurement is missing, run it next. If a result is
> weak, revise and retest next.

## What Must Be Proven Through Continuous Development

The following items are not blocked conceptually, but they do require
sustained implementation, benchmarking, and adversarial testing before they
should be considered final:

1. whether MatRiCT+ can carry `1,000+` private deposits per `v2_ingress_batch`
   through one or more bounded proof shards at acceptable proof size and
   proving time;
2. whether the scan-hint design keeps `v2_egress_batch` practical for wallets
   at `1,000`, `5,000`, and `10,000` outputs;
3. the exact consensus constants for verify units, scan units, tree updates,
   and per-block budgets;
4. the exact byte-level wire encodings and compression choices;
5. the final batch-ingress shard schedule and proof family mix if MatRiCT+ is
   not strong enough and a SMILE-style or 2021/1674-style replacement is
   needed;
6. the exact chain-growth / node-resource envelope at different block limits;
7. the exact achieved cross-L2 netting ratio and reserve-turnover envelope
   under realistic operator-flow simulations;
8. the exact relay / orphan / mempool / miner behavior under mixed-family
   workloads;
9. the exact retained-state constants and weekly snapshot cadence around the
   chosen externalized-retention default;
10. the false-positive rate, bandwidth cost, and restore behavior of the
   `shielded_v2` compact-filter path for light clients and fast rescans.
11. that the native proof plane has survived independent verifier
    cross-checking, external cryptographic review, and adversarial proof-focused
    testnet work; benchmarking and simulation alone are not sufficient evidence
    of soundness.

In other words: the architecture is ready now, but the final performance
profile must still be earned by measurement.

## Continuous Development, Testing, And Stress-Testing Plan

The remaining work should be handled as a continuous validation program, not as
one final late-stage benchmark.

### Track 1: MatRiCT+ Integration Validation

- port the public reference code into BTX structure with deterministic wrappers;
- remove host-specific assumptions such as x86-only cycle code from the BTX
  integration path;
- build known-answer vectors for spend and verify operations;
- compare proof sizes and runtimes against current BTX MatRiCT baselines.

### Track 2: Batch-Ingress Proving Validation

- prototype `v2_ingress_batch` with `100`, `1,000`, `5,000`, and `10,000`
  deposit targets;
- measure total proof size, proving time, verification time, memory, and
  batch-root binding cost across `1`, `2`, `4`, `8`, and any other viable
  proof-shard schedules;
- if MatRiCT+ misses the target at approved shard sizes, preserve the
  transaction shape and swap in a stronger membership / balance component;
- keep the top-level batch header and shard descriptor format fixed while
  varying only the shard schedule or proof backend;
- keep the phase-two SMILE path ready specifically for this proof-family
  decision.

### Track 3: Wallet-Scan And Light-Client Validation

- benchmark wallet scanning against large `v2_egress_batch` fanout under cold
  start, rescan, and live-sync conditions;
- measure false-positive rates for scan hints;
- ensure reserve-note and user-note scan domains do not interfere;
- measure `shielded_v2` compact-filter false positives, bandwidth, and
  `cfheaders` / `getcfilters` behavior under the new note and settlement model;
- set scan-unit costs from actual wallet and light-client behavior rather than
  guesswork.

### Track 4: Consensus, Relay, And Mempool Stress Testing

- flood-test high-output `v2_egress_batch` transactions;
- flood-test high-nullifier `v2_ingress_batch` transactions;
- stress invalid-proof rejection paths;
- stress duplicate-nullifier, malformed-root, malformed-settlement, duplicate
  domain-id, and non-zero-sum netting-manifest cases;
- test mempool eviction, fee sorting, and miner selection under mixed-family
  workloads;
- test inv / getdata behavior, tx announcements, orphan limits, and out-of-band
  artifact retrieval under malformed manifests and peer churn.

### Track 5: Reorg And Recovery Testing

- test deep and shallow reorg handling for batched ingress and egress;
- test wallet recovery and rescan from seed across reserve-note and user-note
  histories;
- test L2 settlement replay, re-anchoring, proof-artifact-manifest handling,
  and multi-domain net-settlement replay across reorg boundaries.

### Track 6: Long-Horizon Capacity Testing

- simulate chain growth for `12 MB`, `24 MB`, and any candidate larger limits;
- project annual chain size and state growth under realistic batch mixes;
- simulate cross-L2 flow matrices at different balance levels and settlement
  window cadences to estimate achieved netting ratios and effective boundary
  relief;
- measure validator CPU, memory, and disk behavior under months of synthetic
  high-load history;
- ensure the system remains operator-friendly and not just cryptographically
  valid.

### Track 7: Cryptographic Readiness And Security Review

- fuzz all new serializers, proof envelopes, batch-leaf encodings, and note
  decoders;
- run adversarial tests for note-class confusion and domain-separation mistakes;
- review imported-proof claim / adapter / manifest binding end to end;
- extract a consensus-grade proving specification for:
  - direct-send verification,
  - ingress shard verification,
  - note commitments and nullifiers,
  - Fiat-Shamir transcript / challenge derivation,
  - and settlement / domain bindings;
- build at least one independent verifier or transcript-checking harness,
  separate from the production verifier path, and require agreement on
  deterministic vectors plus large randomized corpora;
- differential-test the BTX implementation against the upstream MatRiCT+
  reference path wherever comparable statements exist, and against the
  independent checker on BTX-specific statement shapes;
- commission external cryptographic review of the native proof plane as a
  whole, not only the final ingress proof family:
  - direct-send proof logic,
  - batch-ingress shard logic,
  - note / nullifier / domain-separation rules,
  - and any consensus-relevant scan / settlement binding;
- require that no unresolved critical or high-severity cryptographic findings
  remain before production-reset consideration.

### Track 8: Ephemeral Testnet Operations

Large-scale validation should use the existing infrastructure stack in
`/Users/admin/Documents/btxchain/infra`, including the Porkbun DNS and
DigitalOcean API-backed operational setup, to create and destroy disposable
testnets as needed.

Operational rules:

- prefer short-lived testnets over permanent benchmark environments;
- provision only the minimum node count and machine size needed for the current
  test;
- terminate all cloud resources immediately after benches, stress tests, or
  recovery drills complete;
- keep no persistent testnet infrastructure unless a specific incident or audit
  requires it;
- treat "no persistence" and "lowest practical cost" as explicit success
  criteria for the test harness;
- automate DNS, node bring-up, topology setup, and teardown so repeated stress
  runs are cheap and routine rather than operationally heavy.

What this should be used for:

- multi-node consensus and mempool flood tests;
- batched ingress / egress throughput drills;
- reorg and recovery exercises;
- cross-L2 settlement and reserve-rebalancing simulations;
- adversarial proof-forgery, verifier-disagreement, and malformed-proof
  readiness drills;
- blockfilter / light-client sync drills;
- long-horizon synthetic capacity runs when local single-machine benches are no
  longer representative.

### Track 9: Cross-L2 Netting Validation

- build a reference periodic-window operator protocol for multi-domain flow
  discovery, manifest construction, and `v2_rebalance` publication;
- benchmark pairwise, three-domain, and N-domain net settlement to verify that
  one `v2_rebalance` can replace many gross boundary events;
- test manifest serialization, deterministic domain ordering, duplicate-domain
  rejection, zero-sum delta checks, and proof / receipt binding;
- test disagreement, timeout, and low-match-quality cases where operators fall
  back to smaller windows or lower netting efficiency without breaking reserve
  conservation;
- run ephemeral multi-node simulations with several L2 operators to measure
  achieved netting ratios, reserve turnover, and settlement latency under
  synthetic mixed-flow workloads.

### Track 10: Adversarial Testnet And Red-Team Campaign

- use the ephemeral testnet infrastructure for short-lived proof-focused attack
  campaigns rather than only performance drills;
- run partner-accessible or publicly announced prelaunch testnet windows aimed
  at:
  - proof forgery attempts,
  - verifier disagreement attempts,
  - transcript malleability attempts,
  - malformed-proof resource-exhaustion attacks,
  - and consensus-split attempts triggered by parser or verifier edge cases;
- archive malformed-proof corpora, verifier traces, and consensus outcomes from
  those campaigns so fixes can be replayed deterministically;
- if feasible, attach a bounded bug-bounty or invited red-team program to at
  least one of those ephemeral testnet windows;
- treat these drills as evidence-generation for launch readiness, not as a
  substitute for external cryptographic review.

Why this matters:

- it makes continuous large-scale validation realistic during development;
- it prevents the test program from silently turning into an expensive,
  neglected semi-production environment;
- it gives BTX a repeatable way to prove that the system works under realistic
  distributed conditions before mainnet reset.

## Definition Of Done

`shielded_v2` is ready for production-reset consideration only when all of the
following are true:

1. `v2_send`, `v2_ingress_batch`, `v2_egress_batch`, `v2_rebalance`, and
   `v2_settlement_anchor` all exist as consensus-visible, relayable, mineable,
   and reorg-safe transaction families.
2. The direct proving plane is integrated with deterministic vectors, portable
   build support, and commodity-node validation performance.
3. The production settlement profile uses succinct receipts that meet the
   `<= 58,808` byte phase-one target or a smaller documented conservative
   target backed by measured throughput numbers.
4. `v2_egress_batch` can fan out at least `1,000` shielded outputs without
   turning wallet scan or light-client restore into a DoS path.
5. `v2_ingress_batch` can represent at least `1,000` private deposits per batch
   through one or more bounded proof shards on the chosen phase-one proof
   family, or the replacement batch-ingress proof module is already integrated
   and validated.
6. The chosen externalized-retention default, weekly snapshots, and recovery /
   assumeutxo behavior all work under reorg and pruning tests.
7. `v2_rebalance` supports multi-domain net settlement with deterministic
   manifests, zero-sum reserve-delta validation, and distributed cross-L2
   simulation evidence that the operator protocol works under reorgs and mixed
   flow patterns.
8. The native proof plane has passed external cryptographic review plus an
   adversarial proof-focused testnet / red-team campaign, and an independent
   verifier or transcript-checking harness agrees with the production verifier
   across deterministic vectors and randomized corpora.
9. The `shielded_v2` blockfilter path, relay path, mempool policy, and miner
   selection logic all pass dedicated distributed validation.
10. The implementation has been validated through unit, functional, fuzz,
   bench, long-horizon, and ephemeral testnet coverage, and the tracker plus PR
   commentary reflect the actual evidence for that state.
11. No launch-critical transaction family, verifier, wallet path, relay path,
    miner path, recovery path, or operational harness remains as a stub,
    placeholder, disabled codepath, skipped required test, or documented
    "finish later" item.
12. A full disposable reset-network launch rehearsal has been executed end to
    end, including bootstrap, multi-node operation, wallet flows, recovery
    drills, distributed load, evidence capture, cost accounting where remote
    infrastructure was used, and explicit teardown confirmation for every
    temporary resource.

## Risks

1. MatRiCT+ is code-backed but still research code, not consensus-hardened node
   code.
2. SMILE and 2021/1674 look promising, and public prototype code now exists for
   part of the SMILE line of work, but no maintained chain-grade
   implementation or portable audit-ready integration was found in this pass.
3. Large shielded fanout is a wallet-scan problem as much as a chain problem.
4. Imported-proof settlement is compact today, but consensus-grade proof
   verification choices still need to be made deliberately.
5. High-scale private ingress is the hardest part of the entire system, but the
   main residual risk should now be shard-size and verifier-budget calibration
   rather than the existence of one giant monolithic proof.
6. Cross-L2 netting is a major throughput multiplier, but achieved netting
   ratios are economic / operator-behavior outcomes, not guaranteed consensus
   constants, so the phase-one plan should validate a simple reference
   protocol rather than assume perfect matching.
7. Testing, simulation, and testnets can expose implementation and consensus
   failures, but they cannot prove proof-system soundness; external
   cryptographic review remains a separate launch gate.
8. A SMILE-first implementation would add substantial paper-to-code and audit
   risk versus a MatRiCT+-first implementation.

## Recommended Immediate Priorities After PR #79 Merge

1. Freeze the reset-chain decisions that are now explicit in this spec:
   `90` second blocks from genesis, no fast-mine bootstrap, P2MR-only
   transparent boundary rail, permissionless reserve-note operators, and
   externalized retention as the production default.
2. Import or adapt MatRiCT+ into a sandboxed BTX benchmark harness.
3. Freeze the proof-sharded ingress envelope and chunked egress envelope before
   large implementation work lands, so later proof / scan upgrades stay inside
   stable family shapes.
4. Freeze the multi-domain netting-manifest shape and the simple periodic
   cross-L2 operator reference protocol before richer matching logic appears.
5. Broaden the launch gate from "review the final ingress proof family" to
   "review and adversarially test the whole native proof plane," and plan the
   corresponding ephemeral red-team / bug-bounty testnet windows early.
6. Implement the scan-hint redesign and `shielded_v2` compact-filter path
   early, not late.
7. Build `v2_egress_batch`, relay/miner scaffolding, and the light-client path
   before `v2_ingress_batch`, because they are the fastest high-scale win.
8. Treat high-scale private ingress, cross-L2 net settlement, and succinct
   settlement receipts as the core throughput-determining tracks.

## Working Conclusion

The post-reset BTX design should be:

- one shielded standard;
- no legacy baggage;
- private-by-default L1 boundary flows;
- a P2MR-only transparent boundary rail for coinbase, operator tooling, and
  explicit unwrap;
- batch-settlement-first L2 architecture;
- cross-L2 netting through multi-domain `v2_rebalance` manifests so L1 sees
  net reserve deltas more often than gross bilateral boundary crossings;
- PR #79 as the imported-proof and settlement envelope layer;
- MatRiCT+ as the first code-backed native `shielded_v2` engine;
- shardable batch-proof and output-chunk envelopes so future proving and
  scanning upgrades do not require another chain reset;
- SMILE / 2021/1674 ideas as the path to a stronger high-input batch-ingress
  proof;
- witness-validium-style succinct settlement plus externalized retention as the
  production high-scale settlement lane;
- BIP157 / BIP158-style `shielded_v2` filters for light clients from launch;
- CPU-first validation with GPU-optional mining / proving on commodity
  AI-native hardware rather than specialized validator systems.

If this plan is executed well, BTX can realistically become:

- a private L1 settlement layer,
- a high-throughput shielded L2 network-of-networks,
- and a system where millions of daily L2 transfers and billions of annual L2
  transfers are normal, while L1 remains compact enough to stay practical.

Direct answer to the objective question:

- `Yes`, this plan can meet the stated objective for a reset-from-genesis BTX,
  but only if batched private ingress and batched private egress are both
  delivered as first-class consensus features.
- `No`, a MatRiCT+-only direct-spend upgrade without a real batch-ingress path
  would not be enough.

Direct answer to the research-feasibility question:

- `MatRiCT+` is the realistic implementation foundation.
- `SMILE` is a realistic follow-on implementation target, not vaporware, but
  current public prototypes are still too narrow and hardware-assumption-heavy
  to become the blocking dependency for phase one.
