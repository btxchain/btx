# BTX Post-Launch Optimization Roadmap

This is the stable roadmap for post-launch size, throughput, and proof/runtime
optimization work. It replaces the temporary wave-specific optimization
trackers previously used during branch development.

## Scope

This roadmap is for performance and envelope-efficiency work that remains after
the `61000` shielded hardening program.

It is intentionally separate from the security closeout docs in
[doc/security/README.md](security/README.md):

- security docs answer whether mapped bugs are mitigated
- this roadmap answers what still needs to improve before the branch is
  honestly performance-ready for merge

## Current Readiness Caveat

Current branch measurements have recovered the earlier post-fork structural
regressions. The remaining open question is now mostly about operator-path
wallet benchmarking, not postfork consensus/wire capacity.

- explicit postfork direct `1x2` report:
  `62,105` bytes, `386 tx/block`, `6.84 s` build, `264 ms` proof check
- explicit postfork egress `32x32` report:
  `468,653` bytes, `51 tx/block`, recovered size/block-fit envelope
- explicit prefork proofless deposit compatibility report:
  `29,407` bytes, `816 tx/block`, `162.80 ms` build, `0.77 ms` proof check

The runtime generator now carries an explicit validation surface
(`prefork`/`postfork`), which matters because some historical wallet figures
are not valid post-`61000` merge signals:

- prefork proofless deposits remain measurable for compatibility
- prefork wallet `mixed unshield v2_send` remains measurable for compatibility
- postfork direct mixed unshield is intentionally disabled and therefore is not
  part of merge signoff for the hardening fork

So this branch no longer carries a broad postfork size/capacity regression. The
remaining readiness caveat is whether the operator-facing wallet cold-start
direct-send sample still needs one more documentation/benchmark cleanup pass.

## Main Follow-On Workstreams

### 1. Direct-SMILE Prover Runtime Recovery

Targets:

- wallet-facing direct-send sample prove time
- wallet-facing cold-start direct-send variance
- direct-send runtime-report build time
- visibility into retry/padding/self-verify cost split
- clear separation of prefork compatibility benchmarks from postfork
  merge-readiness metrics

Primary surfaces:

- `src/shielded/smile2/ct_proof.cpp`
- `src/shielded/smile2/wallet_bridge.cpp`
- `src/test/shielded_v2_send_runtime_report.cpp`
- `test/functional/wallet_smile_v2_benchmark.py`
- `src/test/smile2_proof_redesign_harness.cpp`

Latest branch movement:

- deterministic public/account/transcript setup for `TryProveCT()` is now
  hoisted out of the prover rejection-retry loop, which materially reduced the
  synthetic direct-send build sample (`44.96 s` to `28.35 s`) without changing
  proof bytes or verification semantics
- the wallet-path immutable self-check now revalidates statement / extension /
  payload digests and witness bytes instead of rebuilding rings and re-running
  proof verification that `BuildV2SendTransaction()` already completed; that
  reduced the latest wallet direct-send first-prove sample from `131.14 s` to
  `27.67 s`, mixed unshield from `72.01 s` to `23.72 s`, and the chained
  direct-send average from `34.88 s` to `6.26 s`
- BDLOP commitment keys now cache the NTT form of their static rows and the CT
  prover/verifier hot paths reuse those cached rows instead of recomputing
  `NttForward()` on every opening/commitment multiply; on the latest host-local
  run this reduced the direct runtime-report build sample from `28.35 s` to
  `6.67 s`, mixed unshield from `23.72 s` to `6.69 s`, and the wallet first
  direct-send sample from `27.67 s` to `24.65 s`
- the send runtime report now carries an explicit validation surface
  (`--validation-surface=prefork|postfork`), which keeps proofless deposits on
  a prefork compatibility lane and keeps the default postfork report focused on
  live `61000` direct-SMILE capacity
- the remaining direct-send delta is now mostly a cold-start wallet-path
  question rather than a structural CT-prover throughput problem

### 2. Generic V2 Envelope Overhead Recovery

Targets:

- postfork direct-send serialized size residual (`62,105` vs `60,110` on the
  latest explicit postfork runtime sample)
- proof payload framing overhead
- post-fork generic placeholder and payload occupancy costs

Primary surfaces:

- `src/shielded/v2_bundle.cpp`
- `src/shielded/v2_send.cpp`
- runtime report generators/tests

### 3. Egress Envelope Stewardship

Targets:

- preserve the recovered `32x32` egress serialized size / block fit
- recover the remaining egress runtime gap
- prevent reintroduction of redundant generic output carriage

Current state:

- the branch now avoids serializing redundant generic-output key material and
  is effectively back at the README size/capacity envelope
- measured `32x32` egress is now `468,653` bytes / `51 tx-block`
- follow-on work should focus on runtime, not serialized size, unless a later
  change reopens the envelope gap

Primary surfaces:

- `src/shielded/v2_egress.cpp`
- `src/test/shielded_v2_egress_runtime_report.cpp`
- `src/test/generate_shielded_v2_egress_runtime_report.cpp`

### 4. Mixed-Family Capacity Signoff

Targets:

- chain-growth projection on the live SMILE ingress backend
- reproducible capacity tables for `24 MB` and `32 MB`
- updated operator-facing launch numbers only after measurements are stable

Primary surfaces:

- `src/test/generate_shielded_v2_chain_growth_projection_report.cpp`
- `src/test/shielded_v2_chain_growth_projection_report.cpp`
- `README.md`

### 5. Future PQ-128 Upgrade Costing

The future PQ-128 upgrade remains a security-margin program, but it also needs
its own measured size/runtime envelope before activation.

See [doc/security/findings/l12-pq128-parameter-upgrade.md](security/findings/l12-pq128-parameter-upgrade.md).
