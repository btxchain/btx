# Pay With Compute RPCs

PWC/1 methods are off-consensus. They do not spend BTX. Economy methods are
proxied to `btx-modeld` and fail closed when the helper is down. Each economy
method takes one JSON object, parameter name `request`. Qualification methods
on `btxd` stay positional. Catalogue:
[../contrib/compute/schemas/rpc-catalog.json](../contrib/compute/schemas/rpc-catalog.json).
Narrative: [pay-with-compute.md](pay-with-compute.md).

## btxd

| Method | Role |
|---|---|
| `getcomputeworkprofiles` | Production profiles. Toy profile only on regtest with `-enablecomputetestprofiles=1`. |
| `getcomputeworkprofile "name-or-id"` | Canonical descriptor and profile id. |
| `issuecomputequalification "subject" "profile" episode_count expires_in_s ( max_elapsed_ms )` | Fresh challenge. Subject is 32-byte hex. Episodes are 1..16. |
| `solvecomputequalification challenge ( "backend" time_budget_ms )` | Local exact replay on `cpu`, or on a self-qualified `auto`/`cuda`/`hip`/`metal`/`ascend` backend. A device that is not self-qualified is rejected. Client timing is advisory. The issuer recomputes on the CPU reference. |
| `verifycomputequalification challenge response` | Recompute. Does not redeem. |
| `redeemcomputequalification challenge response` | Verify and mark single-use. |
| `getcomputequalificationstatus "challenge_id"` | `unknown`, `issued`, `expired`, or `redeemed`. |
| `getcomputestatus` | Registry health. No wallet fields. |
| `buildcomputepassport samples` | Self-attested passport from integer `wall_us`. Not a qualification. |

`-computequalificationfile=<file>` overrides the registry path.
`-enablecomputeproductionwork=1` is required before a production Profile-1
solve. It is off by default.

## btx-modeld (via btxd)

Offers: `createcomputeoffer`, `importcomputeoffer`, `getcomputeoffer`,
`listcomputeoffers`, `getcomputeoffersforresource`.

Quote: `quotecomputeaccess`.

Agreements: `issuecomputeagreement`, `importcomputeagreement`,
`getcomputeagreement`, `listcomputeagreements`.

Jobs: `createcomputejob`, `importcomputejob`, `getcomputejob`, `listcomputejobs`.

Results: `submitcomputejobresult`, `importcomputejobresult`, `getcomputejobresult`.

Receipts: `acceptcomputejobresult`, `issuecomputereceipt`, `importcomputereceipt`,
`getcomputereceipt`, `listcomputereceipts`.

Balance and access: `getcomputebalance`, `issuecomputeaccessgrant`,
`importcomputeaccessgrant`, `getcomputeaccessgrant`, `verifycomputeaccessgrant`.

`getcomputesigningidentity` returns the application public key. It does not
return or accept a wallet key or a raw signing key. If no identity file is
present the call fails with `COMPUTE_SIGNING_IDENTITY_REQUIRED`. A supervised
`btx-modeld` already creates that application identity.

Imports are idempotent when the canonical bytes match. A different body under
the same id fails. Every mutation result includes `automatic_spend_atoms: 0`.

Stable errors include `COMPUTE_PROFILE_UNKNOWN`, `COMPUTE_PROFILE_MISMATCH`,
`COMPUTE_TEST_PROFILE_DISABLED`, `COMPUTE_CHALLENGE_UNKNOWN`,
`COMPUTE_CHALLENGE_EXPIRED`, `COMPUTE_CHALLENGE_REDEEMED`,
`COMPUTE_CHALLENGE_INVALID`, `COMPUTE_SUBJECT_MISMATCH`,
`COMPUTE_DIGEST_MISMATCH`, `COMPUTE_RATE_TOO_LOW`,
`COMPUTE_TIME_BUDGET_EXCEEDED`, `COMPUTE_RECORD_INVALID`,
`COMPUTE_SIGNATURE_INVALID`, `COMPUTE_SIGNING_IDENTITY_REQUIRED`,
`COMPUTE_NETWORK_MISMATCH`, `COMPUTE_OFFER_EXPIRED`,
`COMPUTE_AGREEMENT_EXPIRED`, `COMPUTE_AGREEMENT_CANCELLED`,
`COMPUTE_UNAUTHORIZED_SCHEDULER`, `COMPUTE_UNAUTHORIZED_RECEIPT_ISSUER`,
`COMPUTE_JOB_EXPIRED`, `COMPUTE_JOB_ALREADY_SETTLED`,
`COMPUTE_RESULT_INVALID`, `COMPUTE_DUPLICATE_RECEIPT`,
`COMPUTE_RECEIPT_CREDIT_MISMATCH`, `COMPUTE_CREDIT_OVERFLOW`,
`COMPUTE_NOT_SATISFIED`, `COMPUTE_NOT_IN_GOOD_STANDING`,
`COMPUTE_GRANT_EXPIRED`, and `COMPUTE_GRANT_INVALID`.
