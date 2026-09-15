# Reciprocity (v1.1)

Normative: root addendum §6 (D05). Local scheduler only. Not CSV PASS.

Local observed-service accounting and work-conserving scheduling. **No**
mining, issuance, monetary-peer, or consensus advantage (v1.1 D05).

A node may prefer a peer that recently served verified bytes to it, within
configured caps. That preference:

- does not change fork choice or block-download slots
- does not write BanMan / NoBan / ForceRelay
- does not create a transferable credit or a public reputation token

Classes named `PREFERRED`, `RECIPROCAL`, or `PRESERVATION` are **model-plane
schedulers only**. They must not flow into work, fee policy, or validation.

The reference 20/60/20 lanes in the spec package are design examples, not
measured optima. Do not treat service receipts or self-trades as
independent economic activity.

This tree ships unit-level reciprocity/planner coverage. A bounded
persistent production ledger with crash recovery is still a capabilities
gap (`coverage: incomplete` on `listmodels`).
