# Bounty RPC reference

Normative names and roles for the 0.34.7 model bounty plane. Machine-readable
inventory:
[contrib/modelnet/bounty/schemas/rpc-catalog.json](../contrib/modelnet/bounty/schemas/rpc-catalog.json).
Payload shapes:
[contrib/modelnet/bounty/schemas/](../contrib/modelnet/bounty/schemas/).

`btxd` with `-DWITH_MODELNET=ON` proxies model-plane methods to `btx-modeld`
when `-modelrpcsocket` is set; wallet-side methods execute in the wallet.
If the helper is down, proxied calls **fail closed**. `CLIENT_VERSION_IS_RELEASE`
remains **false** — catalog status is `PROPOSED_CONTRACTS_NOT_IMPLEMENTATION_CLAIM`
until evidence rows pass.

**Authentication:** write paths require caller authentication and caller-scoped
`idempotency_key` where marked in the catalog. **Bridge:** public HTTP routes are
read-only allowlisted views; never wallet, evaluation-run, recovery import, or
mandate writes. **Money:** new amounts are canonical decimal strings (atoms).
`prepare`, `approve`, `sign`, and `submit` are distinct authorities.

Overview: [bounties.md](bounties.md). Model-plane baseline RPCs:
[modelnet/rpc.md](modelnet/rpc.md).

## Catalog (`rpc-catalog.json`)

60 methods: `searchbounties, getmodelbounties, getmodelfeed, gettrendingmodels, getbounty, getbountyeconomy, getbountyterms, getmodeleconomyentry, getmodeldirectoryentry, getbountycapabilities, createbountydraft, validatebountyterms, publishbounty, revisebounty, nominatebountyevaluator, acceptbountyappointment, listbountyevaluators, pledgebounty, withdrawbountypledge, freezebountyfundinground, preparebountyfunding, inspectbountytransaction, signbountyfunding, submitbountyfunding, getbountyfunding, exportbountyrecovery, commitbountysubmission, revealbountysubmission, getbountysubmission, listbountysubmissions, withdrawbountysubmission, preparebountyevaluation, runbountyevaluation, getbountyevaluationjob, cancelbountyevaluation, publishbountyevaluation, listbountyevaluations, createbountychallenge, listbountychallenges, resolvebountychallenge, proposebountyaward, inspectbountyaward, approvebountyaward, signbountyaward, submitbountyaward, getbountyaward, preparebountyclaim, signbountyclaim, submitbountyclaim, preparebountyrefund, signbountyrefund, submitbountyrefund, getbountyevents, watchbounty, unwatchbounty, getagentmandate, createagentmandate, revokeagentmandate, getagentactivity, importbountyrecovery`.

## Method reference

All write actions require caller authentication and caller-scoped idempotency. Public bridge routes are read-only allowlisted views. New monetary amounts are canonical decimal strings. `prepare`, `approve`, `sign` and `submit` are distinct authorities/actions.

## `searchbounties`
Role: **READER** · Process boundary: **MODEL** · Effect: **READ**

| Argument | Contract |
|---|---|
| `query` | Structured query: text, object kinds, filters, scope, sort, page limit, opaque cursor. No global-completeness claim. |

Result: `BountyResultPage`.
Network work is bounded and cancellable. LOCAL scope must send no network requests.

## `getmodelbounties`
Role: **READER** · Process boundary: **MODEL** · Effect: **READ**

| Argument | Contract |
|---|---|
| `query` | Structured query: text, object kinds, filters, scope, sort, page limit, opaque cursor. No global-completeness claim. |

Result: `BountyResultPage`.
Network work is bounded and cancellable. LOCAL scope must send no network requests.

## `getmodelfeed`
Role: **READER** · Process boundary: **MODEL** · Effect: **READ**

| Argument | Contract |
|---|---|
| `query` | Structured query: text, object kinds, filters, scope, sort, page limit, opaque cursor. No global-completeness claim. |

Result: `FeedPage`.
Network work is bounded and cancellable. LOCAL scope must send no network requests.

## `gettrendingmodels`
Role: **READER** · Process boundary: **MODEL** · Effect: **READ**

| Argument | Contract |
|---|---|
| `query` | Structured query: text, object kinds, filters, scope, sort, page limit, opaque cursor. No global-completeness claim. |

Result: `DiscoveryResultPage`.
Network work is bounded and cancellable. LOCAL scope must send no network requests.

## `getbounty`
Role: **READER** · Process boundary: **MODEL+READ_ONLY_CHAIN** · Effect: **READ**

| Argument | Contract |
|---|---|
| `ref` | Typed URI or explicit kind/id reference; never auto-interpret as payment destination. |

Result: `BountyEntry`.
Unknown chain facts are null/UNKNOWN; no wallet-specific data on public interface.

## `getbountyeconomy`
Role: **READER** · Process boundary: **MODEL+READ_ONLY_CHAIN** · Effect: **READ**

| Argument | Contract |
|---|---|
| `ref` | Typed URI or explicit kind/id reference; never auto-interpret as payment destination. |

Result: `BountyEconomy`.
Unknown chain facts are null/UNKNOWN; no wallet-specific data on public interface.

## `getbountyterms`
Role: **READER** · Process boundary: **MODEL+READ_ONLY_CHAIN** · Effect: **READ**

| Argument | Contract |
|---|---|
| `ref` | Typed URI or explicit kind/id reference; never auto-interpret as payment destination. |

Result: `SignedBountyTerms`.
Unknown chain facts are null/UNKNOWN; no wallet-specific data on public interface.

## `getmodeleconomyentry`
Role: **READER** · Process boundary: **MODEL+READ_ONLY_CHAIN** · Effect: **READ**

| Argument | Contract |
|---|---|
| `ref` | Typed URI or explicit kind/id reference; never auto-interpret as payment destination. |

Result: `ModelEconomyEntry`.
Unknown chain facts are null/UNKNOWN; no wallet-specific data on public interface.

## `getmodeldirectoryentry`
Role: **READER** · Process boundary: **MODEL+READ_ONLY_CHAIN** · Effect: **READ**

| Argument | Contract |
|---|---|
| `ref` | Typed URI or explicit kind/id reference; never auto-interpret as payment destination. |

Result: `ModelDirectoryEntry`.
Unknown chain facts are null/UNKNOWN; no wallet-specific data on public interface.

## `getbountycapabilities`
Role: **READER** · Process boundary: **MODEL** · Effect: **READ**

| Argument | Contract |
|---|---|
| None | No arguments. |

Result: `CapabilityObject`.
Return supported record/schema/script/evaluation profiles and implementation version; do not advertise unexecuted features.

## `createbountydraft`
Role: **REQUESTER_DRAFTER** · Process boundary: **MODEL** · Effect: **LOCAL_WRITE**

| Argument | Contract |
|---|---|
| `terms` | BountyTerms payload |
| `idempotency_key` | caller-scoped unique string |

Result: `DraftResult`.
Local only; no publication or deposit.

## `validatebountyterms`
Role: **REQUESTER_DRAFTER** · Process boundary: **MODEL+READ_ONLY_CHAIN** · Effect: **LOCAL_READ**

| Argument | Contract |
|---|---|
| `terms` | BountyTerms payload |

Result: `ValidationReport`.
Checks timeline, bounds, capability and script profile; does not validate future quality.

## `publishbounty`
Role: **REQUESTER_DRAFTER** · Process boundary: **MODEL_SIGNER** · Effect: **PUBLICATION**

| Argument | Contract |
|---|---|
| `draft_id` | local draft id |
| `expected_terms_id` | digest of user-reviewed immutable terms |
| `idempotency_key` | caller-scoped |

Result: `PublicationResult`.
Signs exact terms with research key; no wallet spend. Validates current public-record capability.

## `revisebounty`
Role: **REQUESTER_DRAFTER** · Process boundary: **MODEL_SIGNER** · Effect: **PUBLICATION**

| Argument | Contract |
|---|---|
| `bounty_id` | old bounty id |
| `terms` | new full terms |
| `idempotency_key` | caller-scoped |

Result: `PublicationResult`.
Creates a distinct bounty/terms id; old deposits never migrate implicitly.

## `nominatebountyevaluator`
Role: **CONTRIBUTOR_SIGNER** · Process boundary: **MODEL** · Effect: **PUBLICATION**

| Argument | Contract |
|---|---|
| `bounty_id` | id |
| `nominee_identity` | PQ identity |
| `nominee_key` | full PQ key or authenticated reference |
| `pledge_ref` | nonbinding nomination basis |
| `idempotency_key` | caller-scoped |

Result: `NominationResult`.
No seat or spending authority yet; eligibility validated at frozen funding transaction.

## `acceptbountyappointment`
Role: **EVALUATOR_REPORT_SIGNER** · Process boundary: **MODEL_SIGNER** · Effect: **PUBLICATION**

| Argument | Contract |
|---|---|
| `terms_id` | immutable id |
| `appointment` | scope/conflicts/deadlines/roster acceptance |
| `idempotency_key` | caller-scoped |

Result: `SignedAppointment`.
Does not authorize spending or establish independent identity.

## `listbountyevaluators`
Role: **READER** · Process boundary: **MODEL** · Effect: **READ**

| Argument | Contract |
|---|---|
| `bounty_id` | id |
| `cursor` | optional |
| `limit` | 1..100 |

Result: `EvaluatorPage`.
Apply common bounds, errors, versioning, provenance and role rules.

## `pledgebounty`
Role: **REQUESTER_DRAFTER** · Process boundary: **MODEL_SIGNER** · Effect: **PUBLICATION**

| Argument | Contract |
|---|---|
| `bounty_id` | id |
| `principal_atoms` | decimal string |
| `idempotency_key` | caller-scoped |

Result: `SignedPledge`.
Nonbinding; must never be presented as confirmed funding.

## `withdrawbountypledge`
Role: **REQUESTER_DRAFTER** · Process boundary: **MODEL_SIGNER** · Effect: **PUBLICATION**

| Argument | Contract |
|---|---|
| `pledge_id` | id |
| `idempotency_key` | caller-scoped |

Result: `PledgeResult`.
Withdraws a pledge, not money already deposited.

## `freezebountyfundinground`
Role: **REQUESTER_DRAFTER** · Process boundary: **MODEL** · Effect: **LOCAL_WRITE**

| Argument | Contract |
|---|---|
| `terms_id` | id |
| `round` | complete proposed contributors, council and funding transaction |
| `idempotency_key` | caller-scoped |

Result: `FrozenRound`.
No output mutation after signatures. Nomination percentages derive from exact principal outputs.

## `preparebountyfunding`
Role: **CONTRIBUTOR_SIGNER** · Process boundary: **WALLET** · Effect: **PREPARE**

| Argument | Contract |
|---|---|
| `round_id` | id |
| `lot_id` | own lot id |
| `principal_atoms` | exact user-selected decimal amount |
| `fee_reserve_atoms` | approved ceiling |
| `idempotency_key` | caller-scoped |

Result: `FundingPlan`.
Derive own refund key; validate full tree, all outputs, fee allocation, ownership and authorization.

## `inspectbountytransaction`
Role: **CONTRIBUTOR_SIGNER|COUNCIL_TX_SIGNER|RECOVERY_SIGNER** · Process boundary: **WALLET** · Effect: **LOCAL_READ**

| Argument | Contract |
|---|---|
| `proposal_id` | known proposal or plan |
| `transaction` | PSBT/raw tx in existing BTX-supported format |

Result: `TransactionInspection`.
No signing. Returns full authorized/unauthorized diff, scripts, fee and spend branches.

## `signbountyfunding`
Role: **CONTRIBUTOR_SIGNER** · Process boundary: **WALLET** · Effect: **SIGN**

| Argument | Contract |
|---|---|
| `plan_id` | id |
| `expected_transaction_id` | exact inspected transaction fingerprint |
| `authorization_ref` | approval or finite mandate |
| `idempotency_key` | caller-scoped |

Result: `PartiallySignedTransaction`.
Existing supported SIGHASH_ALL only; no implicit ANYONECANPAY.

## `submitbountyfunding`
Role: **CONTRIBUTOR_SIGNER** · Process boundary: **WALLET** · Effect: **BROADCAST**

| Argument | Contract |
|---|---|
| `plan_id` | id |
| `signed_transaction` | supported serialized transaction |
| `authorization_ref` | approved policy scope |
| `idempotency_key` | caller-scoped |

Result: `BroadcastResult`.
Live revalidation; duplicate retries return same outcome.

## `getbountyfunding`
Role: **READER** · Process boundary: **READ_ONLY_CHAIN** · Effect: **READ**

| Argument | Contract |
|---|---|
| `bounty_id` | id |
| `round_id` | optional |
| `cursor` | optional |
| `limit` | 1..100 |

Result: `FundingPage`.
Public outpoints and attributed chain completeness. Private ownership requires separate authorized context.

## `exportbountyrecovery`
Role: **RECOVERY_SIGNER** · Process boundary: **WALLET** · Effect: **LOCAL_READ**

| Argument | Contract |
|---|---|
| `bounty_id` | id |
| `lot_ids` | owned lots |

Result: `RecoveryManifest`.
No seed/private keys; includes complete scripts, control data and lineage.

## `commitbountysubmission`
Role: **CREATOR** · Process boundary: **MODEL_SIGNER** · Effect: **PUBLICATION**

| Argument | Contract |
|---|---|
| `bounty_id` | id |
| `commitment` | salted submission commitment |
| `payout_binding` | authenticated payout key/script reference |
| `idempotency_key` | caller-scoped |

Result: `SubmissionCommitment`.
An artifact digest is not an originality/ownership proof.

## `revealbountysubmission`
Role: **CREATOR** · Process boundary: **MODEL_SIGNER** · Effect: **PUBLICATION**

| Argument | Contract |
|---|---|
| `commitment_id` | id |
| `submission` | Submission payload |
| `nonce_ref` | authorized local secret reference or explicit value |
| `idempotency_key` | caller-scoped |

Result: `SignedSubmission`.
Must match commitment. Public model ID, ciphertext/secret hash when sealed.

## `getbountysubmission`
Role: **READER** · Process boundary: **MODEL** · Effect: **READ**

| Argument | Contract |
|---|---|
| `submission_id` | id |

Result: `SubmissionEntry`.
Apply common bounds, errors, versioning, provenance and role rules.

## `listbountysubmissions`
Role: **READER** · Process boundary: **MODEL** · Effect: **READ**

| Argument | Contract |
|---|---|
| `bounty_id` | id |
| `cursor` | optional |
| `limit` | 1..100 |

Result: `SubmissionPage`.
Apply common bounds, errors, versioning, provenance and role rules.

## `withdrawbountysubmission`
Role: **CREATOR** · Process boundary: **MODEL_SIGNER** · Effect: **PUBLICATION**

| Argument | Contract |
|---|---|
| `submission_id` | id |
| `reason` | inert text |
| `idempotency_key` | caller-scoped |

Result: `SubmissionUpdate`.
Cannot erase already public bytes or rewrite a settled award.

## `preparebountyevaluation`
Role: **EVALUATOR_RUNNER** · Process boundary: **EVALUATION** · Effect: **PREPARE**

| Argument | Contract |
|---|---|
| `submission_id` | id |
| `profile_id` | installed approved harness profile |
| `resources` | bounded device/time/memory/disk request |
| `idempotency_key` | caller-scoped |

Result: `EvaluationPlan`.
No execution yet; refuse unknown or unsafe harness capability.

## `runbountyevaluation`
Role: **EVALUATOR_RUNNER** · Process boundary: **EVALUATION** · Effect: **EXECUTE**

| Argument | Contract |
|---|---|
| `plan_id` | id |
| `execution_approval_ref` | explicit local approval |
| `idempotency_key` | caller-scoped |

Result: `EvaluationJob`.
Asynchronous isolated process. No wallet/signing keys or arbitrary network.

## `getbountyevaluationjob`
Role: **EVALUATOR_RUNNER** · Process boundary: **EVALUATION** · Effect: **LOCAL_READ**

| Argument | Contract |
|---|---|
| `job_id` | id |

Result: `EvaluationJobStatus`.
Apply common bounds, errors, versioning, provenance and role rules.

## `cancelbountyevaluation`
Role: **EVALUATOR_RUNNER** · Process boundary: **EVALUATION** · Effect: **LOCAL_WRITE**

| Argument | Contract |
|---|---|
| `job_id` | id |
| `idempotency_key` | caller-scoped |

Result: `EvaluationJobStatus`.
Must cancel actual worker and descendants, not only change JSON state.

## `publishbountyevaluation`
Role: **EVALUATOR_REPORT_SIGNER** · Process boundary: **MODEL_SIGNER** · Effect: **PUBLICATION**

| Argument | Contract |
|---|---|
| `job_id` | locally verified execution evidence |
| `report` | EvaluationReport payload |
| `idempotency_key` | caller-scoped |

Result: `SignedEvaluationReport`.
Result signature is not an award transaction signature.

## `listbountyevaluations`
Role: **READER** · Process boundary: **MODEL** · Effect: **READ**

| Argument | Contract |
|---|---|
| `submission_id` | id |
| `cursor` | optional |
| `limit` | 1..100 |

Result: `EvaluationPage`.
Apply common bounds, errors, versioning, provenance and role rules.

## `createbountychallenge`
Role: **CREATOR|CONTRIBUTOR_SIGNER|EVALUATOR_REPORT_SIGNER** · Process boundary: **MODEL_SIGNER** · Effect: **PUBLICATION**

| Argument | Contract |
|---|---|
| `bounty_id` | id |
| `submission_id` | id |
| `challenge` | bounded typed evidence/claim |
| `idempotency_key` | caller-scoped |

Result: `SignedChallenge`.
Apply common bounds, errors, versioning, provenance and role rules.

## `listbountychallenges`
Role: **READER** · Process boundary: **MODEL** · Effect: **READ**

| Argument | Contract |
|---|---|
| `bounty_id` | id |
| `cursor` | optional |
| `limit` | 1..100 |

Result: `ChallengePage`.
Apply common bounds, errors, versioning, provenance and role rules.

## `resolvebountychallenge`
Role: **COUNCIL_POLICY_APPROVER** · Process boundary: **MODEL_SIGNER** · Effect: **PUBLICATION**

| Argument | Contract |
|---|---|
| `challenge_id` | id |
| `resolution` | precommitted-policy result/evidence |
| `idempotency_key` | caller-scoped |

Result: `ChallengeResolution`.
Cannot revoke a released transaction signature or confirmed payment.

## `proposebountyaward`
Role: **COUNCIL_POLICY_APPROVER** · Process boundary: **WALLET+MODEL** · Effect: **PREPARE**

| Argument | Contract |
|---|---|
| `bounty_id` | id |
| `submission_id` | id |
| `acceptance_id` | id |
| `lot_ids` | exact covered lots |
| `mode` | PUBLIC_PAYOUT or STAGED_RELEASE |
| `idempotency_key` | caller-scoped |

Result: `AwardProposal`.
Complete transaction binding; no payment yet.

## `inspectbountyaward`
Role: **COUNCIL_TX_SIGNER** · Process boundary: **WALLET** · Effect: **LOCAL_READ**

| Argument | Contract |
|---|---|
| `award_id` | id |

Result: `AwardInspection`.
Recompute inputs, principal, reserves, output keys, exact tree, fees and deadlines.

## `approvebountyaward`
Role: **COUNCIL_POLICY_APPROVER** · Process boundary: **MODEL_SIGNER** · Effect: **PUBLICATION**

| Argument | Contract |
|---|---|
| `award_id` | id |
| `decision` | APPROVE or REJECT |
| `evidence_ids` | exact reports/challenge resolutions |
| `idempotency_key` | caller-scoped |

Result: `SignedPolicyApproval`.
Explicitly not a transaction signature.

## `signbountyaward`
Role: **COUNCIL_TX_SIGNER** · Process boundary: **WALLET** · Effect: **SIGN**

| Argument | Contract |
|---|---|
| `award_id` | id |
| `expected_transaction_id` | exact fingerprint |
| `authorization_ref` | council signer approval |
| `idempotency_key` | caller-scoped |

Result: `CouncilTransactionSignature`.
Refuse before challenge/deadline/approval gates; fixed key order, actual threshold witness policy.

## `submitbountyaward`
Role: **COUNCIL_TX_SIGNER** · Process boundary: **WALLET** · Effect: **BROADCAST**

| Argument | Contract |
|---|---|
| `award_id` | id |
| `signed_transaction` | actual fully signed transaction |
| `idempotency_key` | caller-scoped |

Result: `BroadcastResult`.
No atomicity claim across separate transactions/rounds.

## `getbountyaward`
Role: **READER** · Process boundary: **MODEL+READ_ONLY_CHAIN** · Effect: **READ**

| Argument | Contract |
|---|---|
| `award_id` | id |

Result: `AwardEntry`.
Apply common bounds, errors, versioning, provenance and role rules.

## `preparebountyclaim`
Role: **CREATOR** · Process boundary: **WALLET** · Effect: **PREPARE**

| Argument | Contract |
|---|---|
| `lot_ids` | staged winner outputs |
| `secret_ref` | claim only: restricted local preimage handle |
| `fee_ceiling_atoms` | decimal maximum |
| `idempotency_key` | caller-scoped |

Result: `SpendPlan`.
Revalidate current chain, branch, maturity, own keys and fee policy; do not log preimages.

## `signbountyclaim`
Role: **CREATOR** · Process boundary: **WALLET** · Effect: **SIGN**

| Argument | Contract |
|---|---|
| `plan_id` | id |
| `expected_transaction_id` | exact fingerprint |
| `authorization_ref` | explicit approval/mandate |
| `idempotency_key` | caller-scoped |

Result: `SignedSpend`.
Signature release is a consequential action; no read API may call it.

## `submitbountyclaim`
Role: **CREATOR** · Process boundary: **WALLET** · Effect: **BROADCAST**

| Argument | Contract |
|---|---|
| `plan_id` | id |
| `signed_transaction` | actual transaction |
| `idempotency_key` | caller-scoped |

Result: `BroadcastResult`.
Timelock is earliest spend; show any conflicting transaction.

## `preparebountyrefund`
Role: **RECOVERY_SIGNER** · Process boundary: **WALLET** · Effect: **PREPARE**

| Argument | Contract |
|---|---|
| `lot_ids` | contributor-owned outputs |
| `secret_ref` | claim only: restricted local preimage handle |
| `fee_ceiling_atoms` | decimal maximum |
| `idempotency_key` | caller-scoped |

Result: `SpendPlan`.
Revalidate current chain, branch, maturity, own keys and fee policy; do not log preimages.

## `signbountyrefund`
Role: **RECOVERY_SIGNER** · Process boundary: **WALLET** · Effect: **SIGN**

| Argument | Contract |
|---|---|
| `plan_id` | id |
| `expected_transaction_id` | exact fingerprint |
| `authorization_ref` | explicit approval/mandate |
| `idempotency_key` | caller-scoped |

Result: `SignedSpend`.
Signature release is a consequential action; no read API may call it.

## `submitbountyrefund`
Role: **RECOVERY_SIGNER** · Process boundary: **WALLET** · Effect: **BROADCAST**

| Argument | Contract |
|---|---|
| `plan_id` | id |
| `signed_transaction` | actual transaction |
| `idempotency_key` | caller-scoped |

Result: `BroadcastResult`.
Timelock is earliest spend; show any conflicting transaction.

## `getbountyevents`
Role: **READER** · Process boundary: **MODEL** · Effect: **READ**

| Argument | Contract |
|---|---|
| `bounty_id` | optional |
| `cursor` | opaque snapshot/change cursor |
| `limit` | 1..100 |

Result: `BountyEventPage`.
Node-local cursor, epoch/gap detection, explicit event authority.

## `watchbounty`
Role: **READER** · Process boundary: **MODEL** · Effect: **LOCAL_WRITE**

| Argument | Contract |
|---|---|
| `bounty_id` | id |
| `policy` | local polling/notification filter only |
| `idempotency_key` | caller-scoped |

Result: `WatchResult`.
Watching does not download, evaluate or spend.

## `unwatchbounty`
Role: **READER** · Process boundary: **MODEL** · Effect: **LOCAL_WRITE**

| Argument | Contract |
|---|---|
| `watch_id` | id |
| `idempotency_key` | caller-scoped |

Result: `WatchResult`.
Apply common bounds, errors, versioning, provenance and role rules.

## `getagentmandate`
Role: **OPERATOR** · Process boundary: **WALLET** · Effect: **LOCAL_READ**

| Argument | Contract |
|---|---|
| `mandate_id` | id |

Result: `MandateView`.
Authenticated owner-only; no public explorer access.

## `createagentmandate`
Role: **OPERATOR** · Process boundary: **WALLET** · Effect: **AUTHORIZE**

| Argument | Contract |
|---|---|
| `mandate` | AgentMandate payload |
| `owner_approval_ref` | explicit secure approval |
| `idempotency_key` | caller-scoped |

Result: `MandateView`.
No unbounded/all-recipient mandate by default.

## `revokeagentmandate`
Role: **OPERATOR** · Process boundary: **WALLET** · Effect: **AUTHORIZE**

| Argument | Contract |
|---|---|
| `mandate_id` | id |
| `idempotency_key` | caller-scoped |

Result: `MandateView`.
Blocks new signatures, not already released signatures/broadcasts.

## `getagentactivity`
Role: **OPERATOR** · Process boundary: **WALLET** · Effect: **LOCAL_READ**

| Argument | Contract |
|---|---|
| `mandate_id` | optional owned id |
| `cursor` | opaque |
| `limit` | 1..100 |

Result: `AgentActivityPage`.
Redacted local audit data, never central telemetry.

## `importbountyrecovery`
Role: **RECOVERY_SIGNER** · Process boundary: **WALLET** · Effect: **LOCAL_WRITE**

| Argument | Contract |
|---|---|
| `manifest` | bounded RecoveryManifest object, not an arbitrary host path |
| `idempotency_key` | caller-scoped |

Result: `RecoveryImportResult`.
Revalidates network, scripts and outpoint lineage; no automatic broadcast.
