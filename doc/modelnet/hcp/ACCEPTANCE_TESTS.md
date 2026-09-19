# HCP native acceptance catalogue

120 individually specified cases. This is an execution assignment, not evidence of a passing BTX build.

## HCP-FRM — Framing, signatures and provider enrollment

Required test environment: native codec + real ML-DSA provider keys.

### HCP-FRM-01 — Canonical statement round trip

**Given:** A ProviderProfile with canonical body and a native provider signature. **When:** Encode, decode and independently re-encode it. **Then:** Identical body bytes and body_id; native signature verifies; field roles remain distinct.

**Evidence:** evidence/HCP-FRM-01/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-FRM-02 — Parser differential rejection

**Given:** Raw bodies containing duplicate keys, float/exponent numbers, lone surrogates or trailing bytes. **When:** Feed the same vectors to API, native verifier and SDK readers. **Then:** All reject before privileged effects; no parser selects a different meaning.

**Evidence:** evidence/HCP-FRM-02/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-FRM-03 — Domain separation

**Given:** The same semantic fields signed as CapabilityOffer. **When:** Relabel the envelope as FinancialReceipt without resigning. **Then:** Body domain mismatch fails; no economic observation is accepted.

**Evidence:** evidence/HCP-FRM-03/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-FRM-04 — Unknown provider self-signature

**Given:** A syntactically valid profile signed by a new unaccepted root. **When:** Attempt automatic enrollment through a model package. **Then:** Preview may display the claim; no trusted provider or account connection is installed.

**Evidence:** evidence/HCP-FRM-04/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-FRM-05 — Operational key rotation

**Given:** An enrolled root, old key and valid sequence-bound rotation. **When:** Rotate during active handoffs and replay an older keyset. **Then:** Permitted overlap works; stale sequence and expired/revoked keys cannot authorize new effects.

**Evidence:** evidence/HCP-FRM-05/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-FRM-06 — Origin rebinding

**Given:** A trusted provider profile whose next fetch redirects to a different origin. **When:** Fetch profile and token metadata through the redirect. **Then:** No credential is forwarded; unapproved origin change requires enrollment.

**Evidence:** evidence/HCP-FRM-06/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-FRM-07 — Size and structural bounds

**Given:** Oversized body, enormous arrays and nesting above configured limits. **When:** Submit before expensive schema and signature verification. **Then:** Bounded rejection, memory ceiling and no CPU-amplification loop.

**Evidence:** evidence/HCP-FRM-07/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-FRM-08 — Role separation across signatures

**Given:** Accepted provider key and independently trusted package/software keys. **When:** Use provider signature as package author, client distributor or wallet signature. **Then:** Every inappropriate role is rejected; correct provider receipt remains only an attestation.

**Evidence:** evidence/HCP-FRM-08/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

## HCP-AUTH — Authentication and tenant isolation

Required test environment: real configured OAuth test identity provider.

### HCP-AUTH-01 — Authorization code PKCE

**Given:** Two browser sessions and separate PKCE challenges. **When:** Swap code, redirect, state or verifier across sessions. **Then:** Code is rejected; no account session/token leaks; exact legitimate session succeeds.

**Evidence:** evidence/HCP-AUTH-01/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-AUTH-02 — Sender-constrained token theft

**Given:** A DPoP-bound or mTLS-bound financial token. **When:** Use it with a different key/certificate or replay proof ID. **Then:** Access is denied; no financial preparation/signing effect occurs.

**Evidence:** evidence/HCP-AUTH-02/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-AUTH-03 — Audience enforcement

**Given:** Tokens for catalogue and a distinct MCP/resource service. **When:** Present each to finance and local capability endpoints. **Then:** Audience mismatch is rejected; no token passthrough to downstream services.

**Evidence:** evidence/HCP-AUTH-03/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-AUTH-04 — Scope escalation

**Given:** catalog:read token and a valid private account. **When:** Attempt quote, authorization, submit and policy creation through GET/POST variants. **Then:** All writes fail; read-only responses reveal no account-private data.

**Evidence:** evidence/HCP-AUTH-04/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-AUTH-05 — Tenant object isolation

**Given:** Accounts A and B with similarly named intents/devices. **When:** A requests B objects by guessed IDs and cursor. **Then:** Response denies access without leaking existence, balances or metadata.

**Evidence:** evidence/HCP-AUTH-05/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-AUTH-06 — DPoP is not body approval

**Given:** A sender-valid token and previously approved intent body. **When:** Change principal or terms while retaining request proof. **Then:** Immutable intent digest check rejects content mutation despite valid token possession.

**Evidence:** evidence/HCP-AUTH-06/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-AUTH-07 — Refresh and revocation

**Given:** Active agent token and revoked refresh/policy context. **When:** Attempt reuse across renewal and in-flight new authorization. **Then:** Revoked authority blocks new effects; existing dispatched effects remain reconcilable.

**Evidence:** evidence/HCP-AUTH-07/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-AUTH-08 — Secret leakage sweep

**Given:** Sentinel OAuth tokens, cloud credentials and wallet secret fixtures. **When:** Exercise failure, export, runtime, logs and source-hint paths. **Then:** Sentinels occur only in approved secret stores; no child runtime environment or public payload contains them.

**Evidence:** evidence/HCP-AUTH-08/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

## HCP-GRANT — Local and hosted authority

Required test environment: native local grant service + gateway policy adapter.

### HCP-GRANT-01 — Handoff without local grant

**Given:** Valid signed handoff and no LocalCapabilityGrant. **When:** Ask the connector to acquire and run. **Then:** Returns LOCAL_GRANT_REQUIRED without model network/runtime side effects.

**Evidence:** evidence/HCP-GRANT-01/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-GRANT-02 — Finite first-use convenience

**Given:** Owner grants acquire/load for exact recipes and finite budgets. **When:** Complete several covered local steps unattended. **Then:** No repeated per-step approval; every effect and reservation stays within the original scope.

**Evidence:** evidence/HCP-GRANT-02/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-GRANT-03 — Financial policy cannot launch

**Given:** Valid HostedAccountPolicy allowing release funding. **When:** Present it as authority for runtime execution. **Then:** Rejected by local service; no executable or memory allocation is authorized.

**Evidence:** evidence/HCP-GRANT-03/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-GRANT-04 — Local grant cannot spend

**Given:** Valid local acquisition/run policy and funded customer account. **When:** Try finance authorize/submit using local grant ID. **Then:** Rejected by gateway/custody policy; balances unchanged.

**Evidence:** evidence/HCP-GRANT-04/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-GRANT-05 — Revocation race

**Given:** Authorized local job and account policy revision near expiry. **When:** Revoke as another worker attempts a new signature or local effect. **Then:** New effects fail; already in-flight buffers/signatures follow safe reconciliation.

**Evidence:** evidence/HCP-GRANT-05/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-GRANT-06 — Resource ceilings

**Given:** Two concurrent ensure jobs each fitting isolated memory budget. **When:** Run both under one shared host ceiling. **Then:** Atomic admission prevents combined oversubscription; no duplicate broker creates fictitious capacity.

**Evidence:** evidence/HCP-GRANT-06/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-GRANT-07 — Future issuer scope

**Given:** Finite subscription for publisher P. **When:** Deliver signed release by Q and P after root rotation. **Then:** Q denied; P rotation follows exact delegation policy rather than arbitrary same display name.

**Evidence:** evidence/HCP-GRANT-07/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-GRANT-08 — Deadline does not relax policy

**Given:** Fast untrusted source and slow approved source. **When:** Set an unreachable TTC deadline. **Then:** Returns explicit unmet deadline; no verification, software trust or privacy rule is disabled.

**Evidence:** evidence/HCP-GRANT-08/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

## HCP-DISC — Catalogue and package discovery

Required test environment: native signed-object store + hosted projection.

### HCP-DISC-01 — Exact package preservation

**Given:** Native Core v3 descriptor with documents and recipes. **When:** Fetch it through two independent hosted providers. **Then:** Same package_core_id and byte hash; provider wrappers do not mutate the signed core.

**Evidence:** evidence/HCP-DISC-01/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-DISC-02 — Curation versus truth

**Given:** Sponsored entry with limited availability evidence. **When:** Render search and export machine response. **Then:** Sponsorship/rank, signature status, quality claims and observed availability are separate fields.

**Evidence:** evidence/HCP-DISC-02/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-DISC-03 — No invented capacity

**Given:** Source reports unknown memory compatibility and incomplete provider view. **When:** Search with strict memory/evidence requirements. **Then:** Unknown remains unknown; does not become compatible or globally complete.

**Evidence:** evidence/HCP-DISC-03/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-DISC-04 — Catalogue caching isolation

**Given:** Public immutable package and account-private funding view. **When:** Exercise shared caches across accounts and stale versions. **Then:** Immutable bytes cache safely; private responses no-store and no cross-account cache hit.

**Evidence:** evidence/HCP-DISC-04/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-DISC-05 — Bounded natural-language input

**Given:** Query containing native RPC text or SQL-like syntax. **When:** Search and paginate through gateway. **Then:** Text stays data; query budget enforced; no native mutation or expression execution.

**Evidence:** evidence/HCP-DISC-05/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-DISC-06 — Economic freshness

**Given:** Old percent-funded label and current different chain state. **When:** Read economy view before planning finance. **Then:** Dated observation displayed separately; current terms/anchor required for financial plan.

**Evidence:** evidence/HCP-DISC-06/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-DISC-07 — Capability equivalence guard

**Given:** Two similarly named recipes with different evidence/outputs. **When:** Select under a minimum capability contract. **Then:** Only qualifying recipe eligible; same keyword is not substitution authority.

**Evidence:** evidence/HCP-DISC-07/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-DISC-08 — Independent provider alternative

**Given:** Provider A offline, provider B has same exact package. **When:** Explicitly switch discovery configuration. **Then:** Read discovery succeeds without changing package/resource identity or migrating financial intent.

**Evidence:** evidence/HCP-DISC-08/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

## HCP-HAND — Handoff delivery

Required test environment: hosted connector + native package verifier.

### HCP-HAND-01 — Device and nonce binding

**Given:** Valid handoff for device A nonce N. **When:** Replay to B or to A with a different pending nonce. **Then:** Rejected before planning; no transfer or execution job created.

**Evidence:** evidence/HCP-HAND-01/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-HAND-02 — Expiry and clock policy

**Given:** Handoff at boundary of allowed skew and a stale one. **When:** Verify with deterministic clock fixtures. **Then:** Only policy-valid handoff accepted; no unlimited grace caused by malformed timestamp.

**Evidence:** evidence/HCP-HAND-02/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-HAND-03 — Package substitution

**Given:** Handoff binds one exact package/recipe. **When:** Serve another validly signed package at the same URL. **Then:** PACKAGE_MISMATCH; neither author signature nor HTTPS hides substitution.

**Evidence:** evidence/HCP-HAND-03/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-HAND-04 — Durable duplicate handoff

**Given:** Accepted handoff and interrupted response. **When:** Deliver repeatedly after client restart. **Then:** One local business job/generation or explicit previous outcome; no duplicate resource reservation.

**Evidence:** evidence/HCP-HAND-04/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-HAND-05 — Malicious instruction fields

**Given:** Valid provider signature over unsupported shell/env/path fields. **When:** Import handoff into local connector. **Then:** Strict schema/effect boundary rejects; no shell evaluation or runtime trust expansion.

**Evidence:** evidence/HCP-HAND-05/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-HAND-06 — Free path

**Given:** Public capability available natively and empty CEX balance. **When:** Acquire through hosted handoff. **Then:** No wallet sync, monetary signature or compulsory platform payment occurs.

**Evidence:** evidence/HCP-HAND-06/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-HAND-07 — Optional reporting

**Given:** Owner disables readiness reporting. **When:** Finish acquisition and inference. **Then:** No report leaves device; local result remains usable.

**Evidence:** evidence/HCP-HAND-07/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-HAND-08 — Provider disconnect

**Given:** Ready public capability with provider subsequently unreachable. **When:** Run local workload, release lease and use local cache later. **Then:** No mandatory CEX heartbeat; fresh hosted actions fail clearly without killing acquired data.

**Evidence:** evidence/HCP-HAND-08/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

## HCP-LOCAL — Locality and runtime sovereignty

Required test environment: real capability runtime + local/LAN sources.

### HCP-LOCAL-01 — Resident base reuse

**Given:** Exact base resident, compatible adapter on LAN and remote source hint. **When:** Ensure the selected recipe. **Then:** No base re-download; local TTC plan chooses permitted missing components and native result matches baseline.

**Evidence:** evidence/HCP-LOCAL-01/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-LOCAL-02 — Faster path not fixed rank

**Given:** Slow local disk and faster authorized LAN source. **When:** Plan using measured inputs then execute. **Then:** Planner can choose LAN; explains confidence and stage costs without a rigid category hierarchy.

**Evidence:** evidence/HCP-LOCAL-02/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-LOCAL-03 — Runtime trust

**Given:** Provider recommends unsupported executable URL. **When:** Plan client/runtime preparation. **Then:** SOFTWARE_TRUST_REQUIRED or unsupported profile; no automatic untrusted install.

**Evidence:** evidence/HCP-LOCAL-03/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-LOCAL-04 — Sparse missing extent

**Given:** Partially materialized model with an absent required piece. **When:** Attempt loading through hosted journey. **Then:** Verified reader blocks/fails; missing bytes never become zero-valued trusted weights.

**Evidence:** evidence/HCP-LOCAL-04/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-LOCAL-05 — Readiness distinction

**Given:** Transfer complete but runtime warmup fails. **When:** Report hosted/local statuses. **Then:** Download completion is not RUNTIME_READY; financial success remains separate.

**Evidence:** evidence/HCP-LOCAL-05/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-LOCAL-06 — Cancel under DMA

**Given:** Active GPU transfer with remote CEX cancel request. **When:** Authorize local cancellation while physical transfer remains active. **Then:** Lease retained until fence; no stale write to reused generation.

**Evidence:** evidence/HCP-LOCAL-06/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-LOCAL-07 — Private state containment

**Given:** Active prompt/KV/prefix cache and hosted reporting enabled. **When:** Send allowed coarse report and export handoff state. **Then:** No prompts, completions, KV, pointers or private paths leave local trust domain.

**Evidence:** evidence/HCP-LOCAL-07/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-LOCAL-08 — No remote inference shortcut

**Given:** Local runtime unavailable and provider has a remote inference API. **When:** Ensure a LOCAL_ONLY recipe. **Then:** Returns explicit unsupported/not ready; never forwards a prompt to the provider.

**Evidence:** evidence/HCP-LOCAL-08/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

## HCP-CUST — Custody and native template support

Required test environment: isolated native chain + actual supported signer.

### HCP-CUST-01 — Native key capability

**Given:** Custody backend advertising only generic EVM support. **When:** Enable FUNDING profile. **Then:** Profile remains disabled with CUSTODY_UNSUPPORTED; no fabricated BTX signature path.

**Evidence:** evidence/HCP-CUST-01/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-CUST-02 — Frozen script validation

**Given:** Prepared release/bounty tree and approved refund key. **When:** Change claimant, script, amount or refund height before signing. **Then:** Custody independent validation rejects exact mismatch.

**Evidence:** evidence/HCP-CUST-02/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-CUST-03 — Customer lot attribution

**Given:** Two custodial users co-fund one native round. **When:** Prepare/sign/broadcast and reconcile lots. **Then:** Each contribution maps to its own authorized lot and beneficiary; no principal counted twice.

**Evidence:** evidence/HCP-CUST-03/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-CUST-04 — No synthetic council seats

**Given:** One custodian with many customer subaccounts. **When:** Project participants and evaluator rights. **Then:** Native rules used; subaccounts do not create independent control or votes by UI fiction.

**Evidence:** evidence/HCP-CUST-04/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-CUST-05 — Signer timeout ambiguity

**Given:** Custody creates signature but response is lost. **When:** Retry caller and restart executor. **Then:** Lookup same signing operation; no new independent spend or automatic hold release.

**Evidence:** evidence/HCP-CUST-05/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-CUST-06 — Recovery drill

**Given:** Encrypted backups of keys, native transaction state and customer ledger. **When:** Restore into isolated lab and perform eligible refund. **Then:** Correct beneficiary recovers; evidence includes native transactions and accounting reconciliation.

**Evidence:** evidence/HCP-CUST-06/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-CUST-07 — Watch-only export honesty

**Given:** Customer exports receipts and public refund paths without keys. **When:** Inspect/export recovery explanation. **Then:** No claim of unilateral refund; custody controller and deadline obligations explicit.

**Evidence:** evidence/HCP-CUST-07/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-CUST-08 — Signer network isolation

**Given:** Malformed native candidate and compromised model helper. **When:** Probe custody endpoint through model/public bridge. **Then:** No route or credential; signer accepts only authenticated typed executor operations.

**Evidence:** evidence/HCP-CUST-08/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

## HCP-INTENT — Financial intent lifecycle

Required test environment: transactional gateway + native executor fault injection.

### HCP-INTENT-01 — Idempotent creation

**Given:** Stable client_operation_id and one signed quote. **When:** Create twice with same body and then altered amount/terms. **Then:** Same outcome for same body; 409 for conflict; no second reservation.

**Evidence:** evidence/HCP-INTENT-01/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-INTENT-02 — Authorization binds intent

**Given:** Prepared immutable intent approved at policy revision N. **When:** Mutate body or raise fees before submit. **Then:** Expected digest/revision validation rejects before signing.

**Evidence:** evidence/HCP-INTENT-02/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-INTENT-03 — Expired quote

**Given:** Firm quote expires before authorized submission. **When:** Submit with valid OAuth token. **Then:** QUOTE_EXPIRED; no native effect; hold handled under proven unsigned state.

**Evidence:** evidence/HCP-INTENT-03/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-INTENT-04 — Terms change

**Given:** Approved terms digest differs from current frozen round. **When:** Submit the previously prepared intent. **Then:** TERMS_CHANGED; reprepare requires new explicit authorization.

**Evidence:** evidence/HCP-INTENT-04/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-INTENT-05 — Crash before broadcast

**Given:** Signed bytes durably recorded and worker dies before dispatch. **When:** Restart and resume execution. **Then:** Recover exact bytes and native input reservations; at most identical dispatch.

**Evidence:** evidence/HCP-INTENT-05/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-INTENT-06 — Crash after broadcast

**Given:** Native accepts transaction but gateway loses response. **When:** Restart all API/executor replicas and retry client. **Then:** BROADCAST_UNKNOWN until reconciled; same bytes only; no second debit.

**Evidence:** evidence/HCP-INTENT-06/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-INTENT-07 — Cancel boundary

**Given:** One unsigned prepared intent and one ambiguously broadcast intent. **When:** Cancel both. **Then:** Unsigned cancellation releases safe holds; ambiguous one enters reconciliation without false refund.

**Evidence:** evidence/HCP-INTENT-07/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-INTENT-08 — Conversion partial success

**Given:** Fiat conversion executed, native target becomes ineligible. **When:** Continue composite intent. **Then:** Retain actual converted balance and explicit failed funding leg; no unauthorized reverse trade.

**Evidence:** evidence/HCP-INTENT-08/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

## HCP-LEDGER — Ledger, exposure and fees

Required test environment: real partner ledger adapter or transactional native test ledger.

### HCP-LEDGER-01 — Concurrent funds reservation

**Given:** One account balance and many simultaneous valid intents. **When:** Race reservations across service replicas. **Then:** Committed holds never exceed available balance; database uniqueness/fencing demonstrated.

**Evidence:** evidence/HCP-LEDGER-01/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-LEDGER-02 — Principal versus fees

**Given:** Quote principal, network reserve and service fee. **When:** Authorize and render pool/account statements. **Then:** Only principal enters native funding sum; all debit components itemized.

**Evidence:** evidence/HCP-LEDGER-02/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-LEDGER-03 — Lifetime limit

**Given:** Policy has limited lifetime principal plus separate outstanding cap. **When:** Spend, refund and attempt another action. **Then:** Exposure may decrease after proven refund; lifetime budget does not silently replenish.

**Evidence:** evidence/HCP-LEDGER-03/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-LEDGER-04 — Overlapping batch outputs

**Given:** Native batch contains output referenced by two ledger entries. **When:** Reconcile funded commitments. **Then:** Duplicate attribution rejected; ledger cannot credit two customers for one economic output.

**Evidence:** evidence/HCP-LEDGER-04/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-LEDGER-05 — Native money bounds

**Given:** Amount string exceeds native range or has leading zero/exponent. **When:** Prepare quote/intent. **Then:** Reject before integer overflow or native signing; native MoneyRange still enforced.

**Evidence:** evidence/HCP-LEDGER-05/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-LEDGER-06 — Fee change

**Given:** Network fee required exceeds approved fee cap. **When:** Executor attempts replacement/rebuild. **Then:** Fresh authority required; no hidden principal reduction or fee overrun.

**Evidence:** evidence/HCP-LEDGER-06/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-LEDGER-07 — Reservation persistence

**Given:** Accepted intent and held funds before database/process crash. **When:** Restore and reconcile. **Then:** Financial intent and hold durably coupled; no orphan release or missing liability.

**Evidence:** evidence/HCP-LEDGER-07/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-LEDGER-08 — Statements

**Given:** Available, held, escrow, claimed and refunded positions coexist. **When:** Generate customer and aggregate reconciliation report. **Then:** No double-counted available capital; ledger balances and native output attribution reconcile.

**Evidence:** evidence/HCP-LEDGER-08/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

## HCP-CHAIN — Chain observation and knowledge

Required test environment: native BTX test network with controllable reorgs.

### HCP-CHAIN-01 — 202 is not settlement

**Given:** Native submission accepted asynchronously. **When:** Read API receipt immediately. **Then:** State is pending/accepted; not funded or final until evidence threshold.

**Evidence:** evidence/HCP-CHAIN-01/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-CHAIN-02 — Confirmation policy

**Given:** One valid transaction progresses through configured confirmations. **When:** Observe at each anchor. **Then:** Threshold applied; anchor/hash/count exposed as observation, not absolute finality.

**Evidence:** evidence/HCP-CHAIN-02/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-CHAIN-03 — Reorg correction

**Given:** Confirmed funding falls out of active chain. **When:** Reorganize and deliver observer update. **Then:** Corrective receipt/event, no budget reset or duplicate funding; dependent unsent work paused.

**Evidence:** evidence/HCP-CHAIN-03/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-CHAIN-04 — Disclosed secret survives reorg

**Given:** Valid release secret observed before claim reorg. **When:** Revert chain anchor. **Then:** Knowledge state remains disclosed; settlement state reverts independently.

**Evidence:** evidence/HCP-CHAIN-04/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-CHAIN-05 — Observer outage

**Given:** Native node temporarily unavailable. **When:** Query finance state and attempt dependent action. **Then:** NATIVE_VERIFIER_UNAVAILABLE/unknown; absence not claimed and no automatic respend.

**Evidence:** evidence/HCP-CHAIN-05/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-CHAIN-06 — Verifier disagreement

**Given:** CEX observer and configured independent verifier disagree. **When:** Evaluate required financial prerequisite. **Then:** Explicit conflict; no merged fake certainty; free public data remains separately acquirable.

**Evidence:** evidence/HCP-CHAIN-06/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-CHAIN-07 — Refund conditions

**Given:** Unawarded bounty before and after native refund height. **When:** Try refund with exact stored template. **Then:** Early attempt denied; eligible refund follows native verification and correct beneficiary credit.

**Evidence:** evidence/HCP-CHAIN-07/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-CHAIN-08 — Receipt authority label

**Given:** Provider receipt reports a native-node observation. **When:** Import on walletless local client. **Then:** Displayed as HOSTED_ATTESTED unless independently checked; no SPV/full validation claim from signature alone.

**Evidence:** evidence/HCP-CHAIN-08/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

## HCP-EVENT — Events and subscriptions

Required test environment: durable outbox + stream/webhook clients.

### HCP-EVENT-01 — At-least-once duplicate

**Given:** One native transition delivered repeatedly through SSE. **When:** Restart client between deliveries. **Then:** One logical local action; event duplicate retained safely without promise of exactly-once transport.

**Evidence:** evidence/HCP-EVENT-01/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-EVENT-02 — Cursor retention

**Given:** Client cursor predates retained history. **When:** Request events. **Then:** CURSOR_TOO_OLD plus reconciliation route, not empty success.

**Evidence:** evidence/HCP-EVENT-02/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-EVENT-03 — Account cursor binding

**Given:** Cursor for account A and filter F. **When:** Use with B or altered filter. **Then:** Rejected; no cross-tenant event leakage.

**Evidence:** evidence/HCP-EVENT-03/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-EVENT-04 — Future subscription race

**Given:** Many workers see same publisher event under finite policy. **When:** Create action concurrently. **Then:** One durable policy/event/action business key; no duplicate debit.

**Evidence:** evidence/HCP-EVENT-04/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-EVENT-05 — Catalogue restore

**Given:** Restore old records after index rebuild. **When:** Replay discovery into subscriptions. **Then:** Historical matches not counted as new chargeable events.

**Evidence:** evidence/HCP-EVENT-05/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-EVENT-06 — Outbox crash

**Given:** State committed but event delivery interrupted. **When:** Recover worker. **Then:** Event eventually delivered from durable outbox without losing accepted transition.

**Evidence:** evidence/HCP-EVENT-06/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-EVENT-07 — Webhook SSRF

**Given:** Callback targets loopback, private metadata address or rebinding host. **When:** Register and trigger callback. **Then:** Configuration policy/DNS/network controls block; no credentials or internal response disclosed.

**Evidence:** evidence/HCP-EVENT-07/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-EVENT-08 — Revoked subscription

**Given:** Policy revoked with queued events. **When:** Process queue after revocation. **Then:** No new signatures; dispatched intents remain reconcilable and visible.

**Evidence:** evidence/HCP-EVENT-08/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

## HCP-FLEET — Browser and device pairing

Required test environment: real browser + owner-only client connector.

### HCP-FLEET-01 — Pair exact device

**Given:** Device key and short-lived pairing challenge. **When:** Approve from authenticated account. **Then:** Device/account binding confirmed on both ends; wrong/expired challenge rejected.

**Evidence:** evidence/HCP-FLEET-01/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-FLEET-02 — No ambient localhost API

**Given:** Malicious web page probes local daemon. **When:** Try GET/POST/CORS/custom URI calls. **Then:** No unrestricted privileged route; no finance token in URI or local process launch.

**Evidence:** evidence/HCP-FLEET-02/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-FLEET-03 — Outbound-only handoff

**Given:** Paired device behind NAT/firewall. **When:** Queue capability handoff. **Then:** Device retrieves through authorized outbound session without opening inbound execution port.

**Evidence:** evidence/HCP-FLEET-03/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-FLEET-04 — Device revocation

**Given:** Paired device with pending handoff. **When:** Revoke pair then poll/report. **Then:** New handoffs/reports rejected as configured; already local public model stays under owner policy.

**Evidence:** evidence/HCP-FLEET-04/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-FLEET-05 — Cross-device replay

**Given:** Handoff for one fleet device. **When:** Replay to another device in same account. **Then:** Device/nonce binding rejects without changing selected recipe.

**Evidence:** evidence/HCP-FLEET-05/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-FLEET-06 — Coarse progress

**Given:** Transfer complete, runtime not ready and later ready. **When:** Render portal updates. **Then:** Correct stages; no private paths/prompts; readiness only after valid device observation.

**Evidence:** evidence/HCP-FLEET-06/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-FLEET-07 — CEX cannot administer local grant

**Given:** CEX fleet admin attempts to broaden execution policy. **When:** Send remote grant mutation disguised as handoff. **Then:** Local owner/organization policy authority required; hosted credential insufficient.

**Evidence:** evidence/HCP-FLEET-07/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-FLEET-08 — Mixed platform fleet

**Given:** Two genuinely supported local platforms and different recipes. **When:** Launch same capability request via portal. **Then:** Each local resolver selects eligible exact implementation; unsupported runtime fails explicitly.

**Evidence:** evidence/HCP-FLEET-08/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

## HCP-PRIV — Privacy and data minimization

Required test environment: packet capture + logs/export fixtures.

### HCP-PRIV-01 — Prompts stay local

**Given:** Real local inference after hosted handoff. **When:** Capture all provider traffic. **Then:** No prompts, completions, KV or prefix-state identifiers in provider requests.

**Evidence:** evidence/HCP-PRIV-01/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-PRIV-02 — Inventory off by default

**Given:** Local residency contains private models/hardware identifiers. **When:** Search and ensure using default reporting policy. **Then:** No full inventory/fingerprint exfiltration; coarse capability constraints only if approved.

**Evidence:** evidence/HCP-PRIV-02/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-PRIV-03 — Private URL redaction

**Given:** Source origin includes bearer query credential. **When:** Generate package, receipt, logs and export. **Then:** Secret URL excluded/redacted; public hints contain no access capability.

**Evidence:** evidence/HCP-PRIV-03/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-PRIV-04 — Tenant analytics

**Given:** Two tenants with low-volume distinctive capability requests. **When:** Produce analytics views. **Then:** No customer-identifying cross-tenant exposure; cohort policy or suppression applied.

**Evidence:** evidence/HCP-PRIV-04/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-PRIV-05 — Required versus optional records

**Given:** Owner disables product analytics. **When:** Fund a permitted native action. **Then:** Optional analytics off; required financial records retained under declared policy without public broadcast.

**Evidence:** evidence/HCP-PRIV-05/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-PRIV-06 — Read token in runtime

**Given:** Connector authenticated to CEX. **When:** Spawn local loader worker and inspect environment/FDs. **Then:** No provider/custody/cloud token inherited.

**Evidence:** evidence/HCP-PRIV-06/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-PRIV-07 — Native-only acquisition

**Given:** Enrolled hosted metadata provider but model policy NATIVE_ONLY. **When:** Return external cloud URL as source hint. **Then:** External payload fetch denied unless separately approved; metadata permission not origin permission.

**Evidence:** evidence/HCP-PRIV-07/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-PRIV-08 — No inference billing

**Given:** Model runs repeatedly after free or funded acquisition. **When:** Inspect exchange/network events. **Then:** No mandatory per-inference BTX debit or usage heartbeat introduced.

**Evidence:** evidence/HCP-PRIV-08/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

## HCP-PORT — Portability, migration and exit

Required test environment: two independent test providers + client export.

### HCP-PORT-01 — Discovery switch

**Given:** Exact package/lock acquired using A. **When:** Export and import under B. **Then:** Identity preserved; new provider authentication explicit; no software trust migration.

**Evidence:** evidence/HCP-PORT-01/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-PORT-02 — Uncertain finance across providers

**Given:** A has BROADCAST_UNKNOWN intent. **When:** Switch discovery to B. **Then:** No automatic equivalent funding at B; unresolved A obligation remains visible.

**Evidence:** evidence/HCP-PORT-02/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-PORT-03 — Free use after exit

**Given:** Public assets and runtime lease local. **When:** Revoke CEX enrollment and disconnect network. **Then:** Local permitted use persists; no origin/issuer heartbeat dependency.

**Evidence:** evidence/HCP-PORT-03/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-PORT-04 — Custody exit statement

**Given:** Pending lots and refunds under custodial keys. **When:** Export customer state. **Then:** Native references, controller and conditions explicit; not falsely called self-custody.

**Evidence:** evidence/HCP-PORT-04/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-PORT-05 — Schema evolution

**Given:** HCP/1 client sees unknown critical profile capability. **When:** Attempt action. **Then:** Fail closed with version error; no unsafe downcast into generic RPC.

**Evidence:** evidence/HCP-PORT-05/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-PORT-06 — Migration interruption

**Given:** Local connector/account schema migration mid-write. **When:** Crash/restart using backed-up fixtures. **Then:** Atomic/restartable migration; enrollments and financial histories not silently dropped.

**Evidence:** evidence/HCP-PORT-06/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-PORT-07 — Independent SDK parity

**Given:** Python and TypeScript serializations of same intent. **When:** Hash and compare canonical signed body. **Then:** Identical body_id and decimal values; unsupported encodings rejected consistently.

**Evidence:** evidence/HCP-PORT-07/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-PORT-08 — No native core rewrite

**Given:** Hosted wrapper of existing Core v3 package. **When:** Remove wrapper and use native client. **Then:** Original native package and recipe remain exact and usable.

**Evidence:** evidence/HCP-PORT-08/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

## HCP-OPS — Isolation, release evidence and operations

Required test environment: isolated integration environment + operator runbooks.

### HCP-OPS-01 — Public bridge isolation

**Given:** Existing read-only explorer/browser bridge. **When:** Try all hosted finance method names and path variants. **Then:** Remains read-only; new API service is not a native wallet proxy.

**Evidence:** evidence/HCP-OPS-01/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-OPS-02 — Money-only regression

**Given:** WITH_MODELNET=OFF build and helper-kill fixture. **When:** Build/run monetary regression and stop model/capability helper. **Then:** Money unaffected; hosted model operations fail safely.

**Evidence:** evidence/HCP-OPS-02/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-OPS-03 — Replica fencing

**Given:** Two finance executors race ownership lease. **When:** Force lease expiry/network partition during submit. **Then:** Only fenced owner initiates new signing; reconciliation prevents replacement spend.

**Evidence:** evidence/HCP-OPS-03/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-OPS-04 — Scale within limits

**Given:** Configured concurrent SSE/search/intents beyond capacity. **When:** Load test with held-down native dependency. **Then:** Backpressure/rate limits, bounded memory and durable accepted intents; no false success.

**Evidence:** evidence/HCP-OPS-04/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-OPS-05 — No production side effects

**Given:** Live process/keys alongside isolated test prefix. **When:** Run conformance and recovery scripts. **Then:** No production binary replacement, wallet mutation or restart; record evidence paths.

**Evidence:** evidence/HCP-OPS-05/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-OPS-06 — Provider compromise drill

**Given:** Revoke operational control key during active account session. **When:** Recover with independently enrolled root. **Then:** New unsafe actions stop; native spending keys remain separate; historical receipts retain context.

**Evidence:** evidence/HCP-OPS-06/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-OPS-07 — Claimed profile evidence

**Given:** Backend flag is enabled but native signer or runtime test unavailable. **When:** Generate go-live manifest. **Then:** Profile support not reported proven; specific NOT_RUN/blocker exposed.

**Evidence:** evidence/HCP-OPS-07/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-OPS-08 — Full audit closure

**Given:** All individual cases and J01–J12 have evidence rows. **When:** Independent reviewers reconcile final candidate. **Then:** PASS only for executed relevant tier; unresolved mandatory failures block advertised profile.

**Evidence:** evidence/HCP-OPS-08/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**
