# Neutral client integration

`crl_client.py` and `crl_client.ts` are transport/reference SDKs over the new operation catalogue. They have no brand mapping, default provider or built-in credentials. The production generated SDK should reuse the existing HCP client and its authentication, schema and error machinery.

The application supplies audience-specific authorization headers through its existing provider identity system and verifies signed results through the native HCP verifier. A callback is not a replacement for implementing OAuth, DPoP/mTLS or ML-DSA; those are explicit integration dependencies.

Use a stable business operation ID and Idempotency-Key for a repeated mutation. Poll `/layer/jobs/{id}` after asynchronous acceptance. Do not create another financial operation after a timeout. The v1.2 SDK contains no automatic financial-execution route: institutional instructions translate into the existing v1.1 draft and approval flow.

Binary chunks are authenticated, bounded and hash-checked. Signed manifests and original record signatures must be verified by the receiving production implementation before records become authoritative.
