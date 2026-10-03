# Pay With Compute (PWC/1)

PWC/1 lets a resource operator quote access in normalized BTX compute rather
than money. One **P1E** is one complete execution of the frozen Profile-1
ExactReplay workload `btx-rc-p1e-v1`. Accounting uses integer
**p1e_microunits**. 1 P1E = 1,000,000 microunits. There is no dollar peg, no
transferable compute token, and no automatic BTX spend.

This is an application layer on BTX 0.34.13rc1. It does not change block
validity, chainwork, difficulty, issuance, activation heights, or wallets.
`automatic_spend_atoms` stays 0. A ComputeAccessGrant is not a
LocalCapabilityGrant and is not permission to execute local model code.

## Why this workload

Profile-1 ExactReplay is a deterministic transformer-like integer workload:
operand generation, attention, the dominant FFN projections, residual chaining,
a transcript, and exact int8 × int8 → integer semantics. GPU and other
accelerators qualify by matching that output, not by brand. The harness records
wall-clock samples, CPU fallback, device MAC coverage, backend resolution, and
build provenance. A p99 rate is claimable only at 100 or more samples.

P1E is a common barter denominator. It is not a universal description of AI
hardware. It does not stand in for HBM capacity or bandwidth, KV-cache
capacity, FP16/BF16/FP8/FP4 throughput, inter-GPU fabric, storage bandwidth,
CPU preprocessing, or model-specific kernels. The scalar prices an agreement.
A Compute Passport keeps the richer capability vector. Do not collapse a
machine to one opaque score.

The profile id is SHA-384 of the canonical semantic descriptor. A git revision
is implementation provenance. Changing semantics requires a new profile name
and a new id. There is no implicit conversion between profiles.

## Planes

`btxd` owns the frozen work profiles, local qualification challenges, exact
verification, and the replay-protected registry. That work never enters fork
choice, peer scoring, BanMan, or AddrMan.

`btx-modeld` owns signed offers, agreements, jobs, results, receipts, derived
balances, quotes, and access grants. Those records live under the model
directory, not in the wallet, chainstate, or blocks.

Useful AI jobs run in an operator-chosen external runtime. `btxd` and
`btx-modeld` do not execute job strings. The only in-tree runner is
`contrib/compute/reference-job-runner.py`, and it accepts only the regtest
class `REGTEST_DETERMINISTIC`.

## Compute Passport

A passport is a self-attested snapshot of samples against one profile. Integer
microseconds only. The public rate is

```
floor(sample_count * 1000000 * 3600000000 / total_wall_us)
```

`p99_claimable` is true only when `sample_count >= 100`. A public passport
omits hostname, username, absolute paths, and device serials. Signing one
does not prove the machine still has that throughput. Settlement uses
receipts, not the passport.

```
btx-compute benchmark \
  --profile btx-rc-p1e-v1 \
  --backend cpu \
  --episodes 100 \
  --passport-out passport.json
```

Production Profile-1 is large. Leave it off unless a campaign is intended.
Regtest uses `btx-rc-p1e-toy-v1` and must be labeled **REGTEST TEST ONLY**.
Toy units do not settle mainnet agreements. There is no toy-to-production ratio.

## Qualification

`issuecomputequalification` binds a fresh random nonce, the subject digest,
the profile, the episode count (1 through 16), an expiry, and an anchor.
Each episode header is derived from the challenge id and the episode index.
The solver runs the real ExactReplay implementation for that frozen profile.
`cpu` uses the integer reference. `auto`, `cuda`, `hip`, `metal`, and
`ascend` run `RecomputeResidentCurriculumAccelerated` only after that device
self-qualifies; otherwise the solve is rejected. The issuer always
recomputes on the CPU reference. Any digest mismatch fails. Sampled
acceptance is not used. Client wall time is advisory. The issuer's observed
elapsed time, from
issue to redeem, is the conservative rate. A challenge redeems once.
`<netdir>/compute_qualifications.dat` persists that fact across restart.
A corrupt registry is quarantined and is not reset, so a redeemed challenge
cannot be replayed by deleting the issuer's memory. `-computequalificationfile`
may point at another file. Relative paths stay under the network datadir.

Production solve is off unless `-enablecomputeproductionwork=1`. The toy
profile requires `-enablecomputetestprofiles=1` and regtest. Setting that flag
on any other chain stops `btxd` at startup.

Qualification proves the subject can run the workload now. It does not prove
legal identity, an account elsewhere, a GPU model, Sybil resistance, consensus
participation, or BTX ownership. A CPU that finishes the exact workload is
valid compute.

## Offers, agreements, jobs, receipts

A **ComputeOffer** prices one opaque `resource_ref` for a period and a list of
rights. Settlement names one profile id, an integer requirement, `PREPAID` or
`PRO_RATA`, and the modes `USEFUL_JOB_RECEIPTS` and/or `DIRECT_COMPUTE`.
Useful-job receipts are the preferred mode: the work can be useful to someone.
Direct compute is available for qualification, small admission, and bootstrap,
but the issuer repeats the same work and that work is not otherwise useful.
PWC/1 policy is closed: not transferable, not cash-redeemable, no
cross-agreement credit, and no carryover.

A **ComputeAgreement** freezes those terms for one subject public key. Later
edits to the offer do not rewrite the agreement. Schedulers and receipt
issuers are explicit key lists. A third party can assign work whose
`beneficiary_ref` names a different model, then sign a receipt that credits
this agreement only. An unlisted key cannot schedule or receipt. There is no
global P1E balance and no `sendcompute`.

A **ComputeJob** is a description: class, credit, input commitment, execution
spec commitment, result schema commitment, and verification method. It is not
a command. Credit is frozen. A result carries an output commitment, not the
model output. The issuer accepts it and signs a **ComputeReceipt** for exactly
that credit. The same job cannot be settled twice. An identical receipt
imports once. The same id with different bytes is rejected. Sums use checked
integer arithmetic.

Balance is derived from the receipt set. Status is `OPEN`, `IN_GOOD_STANDING`,
`SATISFIED`, `EXPIRED`, or `CANCELLED`. Outstanding job credit is reserved
locally and cannot exceed the remaining obligation.

**PREPAID** access is eligible when credited units reach the requirement.

**PRO_RATA** access stays in good standing while credited units cover

```
ceil(required * elapsed / period_length)
```

with elapsed clamped to the agreement window. There is no hidden grace. A
pro-rata grant window is at most 24 hours and never past the agreement end.
A prepaid grant may cover the remaining agreement period.

`quotecomputeaccess` estimates full-duty and calendar time from a passport
rate and a duty cycle in basis points (10000 = 100%). Profile mismatch does
not convert. Duty cycle 0 is rejected. The estimate is advisory.
`estimate_only` and `settlement_requires_receipts` stay true.

## Access grant

When the agreement is satisfied, or pro-rata and in good standing, the issuer
may sign a **ComputeAccessGrant**. It is subject-bound, resource-bound, and
time-bound. An external service checks it with `verifycomputeaccessgrant` or
`contrib/compute/reference-access-gate.py`. Verification requires
`trusted_issuer_pubkey`, the resource provider's application public key, and
rejects a grant signed by anyone else. `now_ms` is accepted only on regtest.
The grant does not acquire a
model, does not authorize local execution, and does not move BTX.

## Trust and safety

Records are canonical, domain-separated ML-DSA application signatures
(`BTX/ComputeOffer/v1` and the matching names for the other types). Callers
cannot set `signed_ok`. Mainnet, testnet, and regtest records do not import
across networks. Unknown profiles, toy profiles on mainnet, expired offers,
expired jobs, unauthorized issuers, credit mismatches, and overflows fail
closed with stable `COMPUTE_*` codes. Job fields are data. The daemons do not
call a shell. Public passports omit host identity. Qualification episode
counts, JSON sizes, outstanding jobs, and registry size are bounded. The
caller picks a registered profile. The profile, not the request, chooses the
matrix dimensions.

If `btx-modeld` is down, economy RPCs fail closed and `btxd` keeps serving
the chain. A build without modelnet still runs the monetary node. Qualification
RPCs stay on `btxd`. Economy RPCs are absent from that build.

## Regtest tutorial

**REGTEST TEST ONLY.** Start `btxd -regtest -enablecomputetestprofiles=1
-modelnet=1`.

```
btx-cli -regtest getcomputeworkprofiles

challenge=$(btx-cli -regtest issuecomputequalification \
  "<32-byte-subject-hex>" "btx-rc-p1e-toy-v1" 1 300)

response=$(btx-cli -regtest solvecomputequalification "$challenge" "cpu")

btx-cli -regtest redeemcomputequalification "$challenge" "$response"
```

Economy calls take one JSON object named `request`:

```
`now_ms` below is a regtest test clock. Mainnet and testnet reject a caller clock (`COMPUTE_RECORD_INVALID`) and use local time.

btx-cli -regtest createcomputeoffer '{"offer": { ... }, "now_ms": 1000}'
btx-cli -regtest issuecomputeagreement '{"offer_id":"...","subject_pubkey":"...","period_start_ms":1000,"period_end_ms":5000,"now_ms":1000}'
btx-cli -regtest createcomputejob '{"agreement_id":"...","subject_pubkey":"...","job_class":"REGTEST_DETERMINISTIC","credit_p1e_microunits":1000000,"input_commitment":"11","executor_spec_commitment":"22","expires_at_ms":4000,"now_ms":1500}'
```

The worker runs `contrib/compute/reference-job-runner.py` on the job's
`input_commitment`, then `submitcomputejobresult`. The provider calls
`acceptcomputejobresult`, `getcomputebalance`, and, once satisfied,
`issuecomputeaccessgrant`. The access gate prints `DENIED` before a valid
grant and `ALLOWED` after.

`contrib/compute/e2e-pay-with-compute-regtest.py` runs the isolated functional
scenarios: useful-job settlement, direct compute, third-party clearing,
pro-rata pace, restart, and replay rejection.

## Production example

A model developer offers 30 days of access for N P1E, where the developer
chooses N. The user runs a 100-sample `btx-rc-p1e-v1` benchmark. The passport
reports `p1e_microunits_per_hour = R`. `quotecomputeaccess` estimates wall
time at full duty and calendar time at a chosen duty cycle. The user answers
a fresh qualification. A scheduler sends useful jobs. Receipts accumulate
until the agreement is satisfied. The provider issues an access grant. This
document does not set N and does not claim a universal GPU score.

## What this is for

A developer can have a model, software, and users, and still lack GPUs,
budget, or serving capacity. The usual path is to charge money and then rent
hardware. PWC lets access be the thing that draws contributed compute, and
lets that compute land on whichever authorized project currently needs it.
That is a compute barter and clearing substrate. It is not a second
cryptocurrency.

Hardware earns the unit by doing the workload. The protocol does not publish
a table that says one accelerator brand is worth a fixed number of another.

Later profiles can name memory-heavy, low-precision, or multi-node work.
PWC/1 matches profile ids exactly. A future offer may list more than one id.
This version ships the frozen Profile-1 denominator only. It does not add a
P2P service bit or a discovery protocol. Signed records can move by file,
API, or any later transport without changing the accounting.

The previous MatMul service challenge stays as it was. PWC does not reuse
that challenge type, so a later consensus-profile change cannot reprice an
existing compute agreement.
