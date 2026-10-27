# BTX Swarm 0.35 — Evolution evaluation and adoption

Document: **BTX-SWARM-SPEC-09**, revision **0.1.0**, 19 October 2026.

**Implementation scope:** The node cycle records 12 in-process stages and leaves generation at 0. `passed()` stays false. Nothing is adopted as a release. Candidate frontiers, paired evidence, certificates, channel transitions, and local activation remain design. Public evaluator independence and automatic production-runtime adoption remain unqualified.

## Population model

**EVO-001.** A family contains immutable candidates and persistent channels, not one mandatory global model. Candidate types include base, adapter, distillation, merge and architecture changes. Parents must belong to the family and remain available as history. A new head may supersede its parents on the visible frontier without deleting them. Different niches preserve distinct useful descendants.

The specified Pareto-frontier helper maximizes declared quality and novelty and minimizes cost within each niche. Research allocation reserves an exploration fraction rather than assigning every slot to the current top score. These helpers are design for niche allocation. They are not a release adoption. Declared fitness must be independently derived from accepted evidence before it controls funded capacity.

## Predeclared evaluation

**EVO-002.** Commit the candidate's objective, suite, holdout/sample policy, allowed trial count, primary metric, regression ceilings, required evaluator domains and canary policy before scoring. Candidate submission consumes a persistent trial budget. Repeating the same candidate cannot reset it; exceeding the budget requires an explicitly new approved evaluation campaign, not arbitrary resubmission.

The specified metric is paired binary task success. Counts `00`, `01`, `10`, `11` mean parent/candidate failure/success on the same distinct cases; `01` is an improvement, `10` a regression. Let `n` be the number of distinct cases and `d=(n01−n10)/n`. For family error budget `alpha` and maximum trials `K`, the conservative radius is `sqrt(2 log(K/alpha)/n)` for differences bounded in [-1,1]. Lower and upper bounds are scaled and rounded conservatively using high-precision Decimal arithmetic.

**EVO-003.** The rule requires enough cases, a minimum observed gain, a strictly positive lower bound, complete regression metrics under their ceilings, exact suite and holdout bindings, and a reproducibility assertion. A positive bound does not prove the absence of backdoors, contamination, or catastrophic forgetting.

Evaluator signatures are not extra samples. Reports on the same sample commitment may independently attest the test execution, but their sample counts must not be added together to shrink uncertainty. Each report contributes its qualified bound under one shared sample commitment.

## Independent evidence and certification

**EVO-004.** Evaluators must hold an admitted evaluator role, not be the declared candidate author, and span the configured number of policy-assigned trust domains. Reports preserve negative outcomes. A certificate references a unique report set, candidate, family, niche-specific channel and policy epoch. Neither 51% of arbitrary identities nor a raw quorum of signatures establishes quality.

The specified certificate check covers declared roots and labels. It does not establish real administrative independence, exclude every undisclosed contributor behind a publisher, or prove that raw counts correspond to correct hidden-test execution. Public qualification needs full contributor and provenance closure, independently maintained attestor trust, reproducible evaluation environments, protected challenge pools, and audits against evaluator collusion.

Original ML-DSA signatures are retained with evaluation records. The specified local certificate verification recomputes candidate and certificate IDs, binds reports to the signed bodies, checks eligible roots and revocations, validates sample agreement, and reruns the quality rule. Expired transport authentication does not erase archival research evidence. Revocation eligibility is checked separately.

## Graduation, channel and activation are different

**EVO-005.** Graduation certifies a candidate for a defined niche. Native Lab admission determines whether that artifact may be served under a native assurance policy. A channel proposes deployment. A local runtime chooses whether to activate it. Each is a separate gate; a certificate must not smuggle new code execution, additional data access or a broader financial mandate.

Channel lifecycle: previous generation → CANARY → ACTIVE, or explicit rollback. Stage uses expected sequence and refuses overlapping canaries. Observations are bound to channel generation. Activation rechecks evaluator revocation. Rollback increments the channel sequence and retains both old and replaced checkpoint references.

The specified local adopter verifies checkpoint bytes, loads the supported reference decoder, and performs a bounded runtime smoke before staging. `adoption.sqlite3` is authoritative; exported pointer JSON is explicitly advisory. Activation requires a matching verified certificate result and local canary result. Repeated delivery repairs advisory output without losing the previous generation. Rollback binds the expected active checkpoint and is idempotent. That adopter remains design. This process leaves generation at 0 and adopts nothing.

**EVO-006.** A production automatic follower must fetch and verify the complete certificate/evidence closure, obtain sufficiently fresh policy/revocation state, preserve a rollback checkpoint, enforce runtime/license compatibility, and activate only the locally subscribed channel. Changing the community baseline cannot forcibly replace a user's pinned local model. The automatic production follow loop and native engine-generation binding are not wired in this package.

## Canary quality and conflicts

A canary count of unique peer or receipt observations is not proof of distinct independent deployment sites. Public policies must also bind a predetermined workload, eligible canary panel, minimum duration/load and independent failure reporting; otherwise one participant can fabricate many claimed checks. Conflicting signed observations remain evidence and should pause deployment rather than silently choose a favorable subset.

A specialist that improves coding while harming broad reasoning may graduate under `coding/stable`, not automatically `general/stable`. Merges and distillation require their own evaluation campaign; preserving family ancestry does not make parameters algebraically compatible.

## Evolution qualification still required

A later qualification trains a new checkpoint, recomputes paired evaluations under separately signed identities, creates a graduation certificate, rejects altered evidence and revoked evaluators, stages the tensors, and activates a local generation only after those checks. One host does not stand in for separate organizations. That qualification is not evidence that independent organizations certified a useful model.

## What btxd runs now

The node cycle records 12 in-process stages and leaves generation at 0. `passed()` stays false. Nothing is adopted as a release.

An integer replay checks 8 pairs in-process. It is not a second process replaying a trained model. The one CPU AdamW step and the one-host 4-byte exchange are not a graduated descendant, a staged channel, or an adopted release. `qualified_v41()` stays false.

## Later releases

Toward a fully autonomous network, a participant acquires a verified model from another participant. Compatible state can move to an admitted machine. A qualified machine trains an authorized recipe and a second machine checks it. Evaluated descendants can be staged and adopted under a local policy. A private defensive case runs under an explicit customer grant.

Verifications required first: two physical hosts, a second GPU, Windows, macOS, a linked remote execution engine, an offline release image, the hardware profiles, and the sealed acceptance catalogue. The 12 in-process stages, generation 0, and `passed()` false are not that adoption. EVO-001 through EVO-006 stay design until evaluated descendants are staged and adopted under a local policy after those verifications.
