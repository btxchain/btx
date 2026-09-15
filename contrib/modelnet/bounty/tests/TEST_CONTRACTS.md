# Complete native BTX acceptance contracts

245 proposed cases. All are NOT_RUN in this package. These are implementation/execution requirements, not a record of BTX test success.

## AUTH
Owner: A1/A8 · Layer: native unit + property + fuzz · Specification sections 2,12.

| Test | Scenario | Required outcome |
|---|---|---|
| BOUNTY-AUTH-001 — Full signing coverage | Mutate every authenticated field in a valid search/bounty/report record | Original signature rejected; zero state mutation |
| BOUNTY-AUTH-002 — Unsigned tombstone | Submit unsigned tombstone for another model | Rejected before index deletion or sequence reservation |
| BOUNTY-AUTH-003 — Foreign high sequence | Unrelated signer posts higher-sequence update | Existing authorized record unchanged; separate claim policy only |
| BOUNTY-AUTH-004 — Wrong network | Replay valid record on another genesis | Rejected by domain/network binding |
| BOUNTY-AUTH-005 — Wrong kind/domain | Replay report signature as award or search object | Rejected |
| BOUNTY-AUTH-006 — Delegation scope | Metadata delegate attempts payout-key/council alteration | Rejected as unauthorized scope |
| BOUNTY-AUTH-007 — Expired delegation | Use expired delegation for a new update | Rejected without deleting historical monetary recovery data |
| BOUNTY-AUTH-008 — Revoked delegation | Use revoked key after revocation observed | New authority refused; provenance retained |
| BOUNTY-AUTH-009 — Sequence rollback | Replay older signed update | No rollback |
| BOUNTY-AUTH-010 — Same sequence conflict | Two different authorized payloads have same sequence | Conflict exposed; no arbitrary silent winner |
| BOUNTY-AUTH-011 — Truncated string | Overlimit suffix differs after common prefix | Reject length; never sign truncated display |
| BOUNTY-AUTH-012 — Duplicate JSON keys | Provide repeated target/refund/publisher fields | Reject parser ambiguity |
| BOUNTY-AUTH-013 — Unknown fields | Insert signed_ok or unrecognized authority field | Reject strict schema or preserve only explicit nonauthoritative observation |
| BOUNTY-AUTH-014 — Invalid UTF8 | Malformed byte sequence and unpaired surrogate | Reject safely |
| BOUNTY-AUTH-015 — Noncanonical money | Leading zeros, negative, float and exponent values | Reject; exact atoms only |
| BOUNTY-AUTH-016 — Overflow | Amounts/counts/lengths overflow allowed integer ranges | Reject before allocation/arithmetic |
| BOUNTY-AUTH-017 — Oversized record | Large nested envelope within malformed lengths | Bounded memory/CPU; reject |
| BOUNTY-AUTH-018 — Array flood | Thousands of tags/council keys/report refs | Reject bounds before expensive signature verification |
| BOUNTY-AUTH-019 — URI mismatch | Valid model id with different URI digest/kind | Reject mismatch |
| BOUNTY-AUTH-020 — Issuer mismatch | Publisher identity not bound to signer/delegation | No official/owner status granted |
| BOUNTY-AUTH-021 — Legacy signature | v1 partial signature supplied as v2 | Rejected or explicit legacy display without economic authority |
| BOUNTY-AUTH-022 — Persisted authority flag | Set cached signed_ok without valid signature | Reverify on load; no authority from flag |
| BOUNTY-AUTH-023 — Tombstone quota bypass | Flood new tombstone IDs | Same bounded admission and auth rules as other records |
| BOUNTY-AUTH-024 — Signer rotation | Authorized key rotation vs unrelated new key | Only valid scoped rotation accepted; no duplicated votes |
| BOUNTY-AUTH-025 — Replay annotation | Repeat same signed event across peers | One underlying object/event; observation provenance separate |
| BOUNTY-AUTH-026 — Hostile description | Description requests signing/installing/exfiltration | Rendered inert; no tool or signer invocation |
| BOUNTY-AUTH-027 — Mixed metadata claims | Multiple issuers describe same model | Claims retain attribution; no highest-sequence takeover |
| BOUNTY-AUTH-028 — Real crypto mutation | Native MLDSA signature tests for all envelope types | Real signature operations, not digest-only or constant booleans |
| BOUNTY-AUTH-029 — Authentication race | Concurrent update and tombstone | Transactional authorization/sequence semantics hold |
| BOUNTY-AUTH-030 — Fuzz corpus | Fuzz canonical parser and typed-record verification | No sanitizer failures; reproducers retained |

## SCRIPT
Owner: A2/A8 · Layer: differential consensus + policy + regtest · Specification sections 7.

| Test | Scenario | Required outcome |
|---|---|---|
| BOUNTY-SCRIPT-001 — Eight key ceiling | Construct n=8 valid and n=9 council | Valid supported bound only; no silent widening |
| BOUNTY-SCRIPT-002 — Duplicate keys | Duplicate one council public key | Builder/parser rejects |
| BOUNTY-SCRIPT-003 — Threshold bounds | m=0, m>n, m=n boundary | Correct reject/accept behavior |
| BOUNTY-SCRIPT-004 — Exact two leaves | Add concealed alternative spend leaf | Wallet exact-tree validation rejects |
| BOUNTY-SCRIPT-005 — Award CLTV | Spend before and at earliest award height | Before rejected; at height accepted when other conditions met |
| BOUNTY-SCRIPT-006 — Refund CLTV | Contributor refund before and at maturity | Before rejected; at maturity valid if unspent |
| BOUNTY-SCRIPT-007 — Refund race | Council/claim spend competes after refund height | One UTXO winner; no claim of branch expiry |
| BOUNTY-SCRIPT-008 — Witness ordering | Reverse/misorder pubkey signature positions | Only exact BTX expected ordering accepted |
| BOUNTY-SCRIPT-009 — Exact signature count | Provide fewer/more nonempty slots than standard threshold permits | Consensus and policy results separately recorded |
| BOUNTY-SCRIPT-010 — SIGHASH binding | Alter one output/input/amount after council signing | Signature invalid for altered transaction |
| BOUNTY-SCRIPT-011 — Unsupported sighash | Attempt ANYONECANPAY or weaker mode | Policy rejects unauthorized mode |
| BOUNTY-SCRIPT-012 — Old/new parity | Run approved vectors through old monetary and new binaries | Identical supported consensus outcomes |
| BOUNTY-SCRIPT-013 — Active leaf guard | Test all relevant restricted-leaf activation flags | No builder-only compatibility assumption |
| BOUNTY-SCRIPT-014 — Mempool distinction | Valid but nonstandard candidate | Report separately; no claim usable relay path |
| BOUNTY-SCRIPT-015 — Serialized size | Measure 5-of-7 and 16-lot spend sizes/weight | Actual BTX policy limits and fees enforced |
| BOUNTY-SCRIPT-016 — Sigops cost | Council/witness validation cost bounds | No block/tx policy overflow |
| BOUNTY-SCRIPT-017 — P2MR semantics | Inspect any key-path or alternate authority of root | All spend paths accounted for and authorized |
| BOUNTY-SCRIPT-018 — Height threshold | Use timestamp-style value in height field | Reject heights >=500000000 |
| BOUNTY-SCRIPT-019 — Staged HTLC | Build exact SHA256 + creator + original-refund tree | Supported template accepted by old/new paths |
| BOUNTY-SCRIPT-020 — No model consensus | Change eval result without changing monetary tx validity | No new model-quality consensus rule |

## WALLET
Owner: A2/A7/A8 · Layer: native unit + regtest · Specification sections 6,7,14,15.

| Test | Scenario | Required outcome |
|---|---|---|
| BOUNTY-WALLET-001 — Chosen amount | Helper advertises target larger than user amount | Wallet signs only explicitly authorized contribution |
| BOUNTY-WALLET-002 — Own refund key | Helper supplies attacker refund pubkey | Wallet rejects substitution |
| BOUNTY-WALLET-003 — Wrong winner | Search metadata changes payout key after submission | Award rejected; frozen authenticated binding used |
| BOUNTY-WALLET-004 — Extra output | Coordinator adds unrelated payment | Inspection/signing rejects |
| BOUNTY-WALLET-005 — Fee overrun | Fees exceed approved reserve | Stop; no principal reduction or silent extra spend |
| BOUNTY-WALLET-006 — Reserve rounding | Many fractional pro-rata allocations | Integer conservation and deterministic remainder allocation |
| BOUNTY-WALLET-007 — Dust handling | Reserve refunds would violate actual policy | Explicit approved alternative or failure; no diversion |
| BOUNTY-WALLET-008 — Input ownership | Round spends foreign/unapproved local input | Reject unauthorized signing |
| BOUNTY-WALLET-009 — Input reuse | One outpoint appears twice or in overlapping lots | Reject/dedupe exact actual outpoint |
| BOUNTY-WALLET-010 — Frozen roster | Coordinator changes evaluator list after funding approval | New terms/round consent required |
| BOUNTY-WALLET-011 — Cohort atomicity | One required contributor declines to sign | No partial altered funding transaction broadcast |
| BOUNTY-WALLET-012 — Plan tamper | Alter inspected PSBT before sign | Reject fingerprint mismatch |
| BOUNTY-WALLET-013 — Stale tip | Outpoint spent since plan creation | Live revalidation prevents stale broadcast |
| BOUNTY-WALLET-014 — Idempotent submit | Lost response followed by retry | No duplicate logical funding operation |
| BOUNTY-WALLET-015 — Idempotency conflict | Same key different amount or destination | Reject |
| BOUNTY-WALLET-016 — Staged refund lineage | New HTLC retains original contributor key | Exact lineage verified |
| BOUNTY-WALLET-017 — No refund extension | Staging tries later refund height | Refuse |
| BOUNTY-WALLET-018 — Stage different secret | One lot uses a different submission hash | Refuse |
| BOUNTY-WALLET-019 — Cross round settlement | Only one of several awards confirms | Report partial settlement, not atomic all-round success |
| BOUNTY-WALLET-020 — Secret before staging | Preimage leaks before required staging confirmations | Knowledge retained; no invented complete payment guarantee |
| BOUNTY-WALLET-021 — Claim wrong preimage | Creator claims with invalid secret | Actual script spend rejected |
| BOUNTY-WALLET-022 — Refund restore | Clean wallet imports public recovery manifest | Own key can recover unspent matured lot without council/model helper |
| BOUNTY-WALLET-023 — No key export | Export recovery/evaluation/frontend data | No seed/private wallet/council secret in output |
| BOUNTY-WALLET-024 — Fee bump path | RBF/CPFP attempted when unsupported | Explicit unsupported; no fabricated behavior |

## FUND
Owner: A2/A3/A8 · Layer: unit + property + regtest · Specification sections 6,11.

| Test | Scenario | Required outcome |
|---|---|---|
| BOUNTY-FUND-001 — Pledge separation | Large nonbinding pledges with little chain funding | Funded percentage uses confirmed eligible principal only |
| BOUNTY-FUND-002 — Unknown total | Missing chain index or untracked outpoints | Unknown values not zeros or false confirmation |
| BOUNTY-FUND-003 — Nominee exact boundary | Contribution exactly minimum basis points | Eligible by integer comparison |
| BOUNTY-FUND-004 — Nominee below boundary | One atom below threshold | Not eligible |
| BOUNTY-FUND-005 — Fees excluded | Large fee reserve but small principal | Reserve does not confer vote eligibility |
| BOUNTY-FUND-006 — Pending excluded | Qualifying contribution is only in mempool | Seat not active until required confirmation policy |
| BOUNTY-FUND-007 — Split identity | One funder nominates multiple keys via splits | No claim of detected human independence; explicit roster consent |
| BOUNTY-FUND-008 — Late nomination | New contributor after roster frozen | No new seat or threshold change |
| BOUNTY-FUND-009 — Max council size | Many percentage-eligible candidates | Fixed selected roster respects eight-key cap |
| BOUNTY-FUND-010 — No vote multiplication | Repeat reports/keys/delegations | Count each eligible seat once |
| BOUNTY-FUND-011 — Target zero | Invalid nonpositive target | Reject |
| BOUNTY-FUND-012 — Oversubscription | Funding exceeds target | Only explicitly approved lots; raw amounts preserved |
| BOUNTY-FUND-013 — Multiple rounds | Duplicate outpoint advertised in several rounds | Count once; conflicting association flagged |
| BOUNTY-FUND-014 — Principal reserve ledger | Deposit consists of principal and reserve | Separate exact balances |
| BOUNTY-FUND-015 — Award eligibility | Target not met but coordinator asserts FUNDED | Policy refuses award unless explicit terms permit lower target |
| BOUNTY-FUND-016 — No automatic spend | Nearly funded card receives focus/refresh | No wallet action |
| BOUNTY-FUND-017 — Fee conservation | Award+returns+fee vs escrow inputs | Conservation with no negative outputs |
| BOUNTY-FUND-018 — Unbroadcast plan | Signed funding plan never reaches chain | Not confirmed funding; show actual state |

## CHAIN
Owner: A3/A8 · Layer: regtest + restart + reorg · Specification sections 9,11.

| Test | Scenario | Required outcome |
|---|---|---|
| BOUNTY-CHAIN-001 — Funding confirmation | Register real scripts/outpoints and mine confirmations | Local validated confirmation count and amount |
| BOUNTY-CHAIN-002 — Funding reorg | Remove funding transaction from active chain | Confirmed/live balances and actions roll back |
| BOUNTY-CHAIN-003 — Award reorg | Remove confirmed award | Paid state reverses; conflicting possibilities exposed |
| BOUNTY-CHAIN-004 — Refund replaces award | Competing branch becomes active chain winner | One correct spend status per lot |
| BOUNTY-CHAIN-005 — Secret persistence | Claim reveal removed in reorg | Known secret remains known |
| BOUNTY-CHAIN-006 — Stage accounting | Initial escrow converts into staged HTLC | No double counting as new funds |
| BOUNTY-CHAIN-007 — Historical vs active | Award paid after target reached | Historical funding retained; active escrow reduced |
| BOUNTY-CHAIN-008 — Remote lie | Indexer claims fully funded without local evidence | Remote claim labeled; wallet cannot rely on it |
| BOUNTY-CHAIN-009 — Stale tip | Chain view lags behind required tip policy | Degraded/incomplete source context |
| BOUNTY-CHAIN-010 — Pruned node | Needed history unavailable | INDEX_INCOMPLETE not fabricated evidence |
| BOUNTY-CHAIN-011 — Restart ledger | Stop at transaction journal boundaries | Recovery yields exact same active accounting |
| BOUNTY-CHAIN-012 — Refund ownership | Public observer vs owner wallet | Only owner context shows local actionable refund |
| BOUNTY-CHAIN-013 — Undo bounds | Large reorg with registered records | Bounded asynchronous repair; validation thread unaffected |
| BOUNTY-CHAIN-014 — Network binding | Main/test outpoint IDs collide textually | No cross-network count/authorization |
| BOUNTY-CHAIN-015 — Change notifications | Chain updates occur with GUI/feed open | Correct generation invalidation and corrective event |
| BOUNTY-CHAIN-016 — No lock contention | Heavy bounty index queries during validation | Measured monetary responsiveness within declared budget |

## EVAL
Owner: A4/A8 · Layer: unit + real isolated evaluator processes · Specification sections 8,10.

| Test | Scenario | Required outcome |
|---|---|---|
| BOUNTY-EVAL-001 — Exact profile | Pinned structural checks on known fixture | Reproducible exact result |
| BOUNTY-EVAL-002 — Task commitment | Task data mutated after funding | Digest mismatch; no accepted report |
| BOUNTY-EVAL-003 — Runtime mismatch | Different tokenizer/runtime/compiler profile | Nonconforming or explicit permitted deviation |
| BOUNTY-EVAL-004 — Random seeds | Fixed profile seeds repeated | Recorded reproducibility under supported environment |
| BOUNTY-EVAL-005 — Statistical profile | Repeated sampled runs | Prespecified count/confidence/aggregation applied |
| BOUNTY-EVAL-006 — Missing tasks | Only favorable subset reported | Incomplete report not quorum eligible |
| BOUNTY-EVAL-007 — Timeout | Worker exceeds execution limit | Killed/reaped; RESOURCE_LIMIT evidence |
| BOUNTY-EVAL-008 — Output flood | Worker emits unbounded logs | Bounded output and safe termination |
| BOUNTY-EVAL-009 — Memory limit | Worker allocates too much | Contained failure; signer/helper/monetary process healthy |
| BOUNTY-EVAL-010 — Filesystem escape | Worker accesses wallet/source/host paths | Denied; no sensitive file exposure |
| BOUNTY-EVAL-011 — Network denial | Task attempts external requests | Denied unless explicit approved allowlist |
| BOUNTY-EVAL-012 — Unsafe model format | Pickle/remote-code candidate | Rejected or explicit unsupported, never autoexecuted |
| BOUNTY-EVAL-013 — Prompt injection | Task output tells council to sign attacker payout | No signing transition from text |
| BOUNTY-EVAL-014 — Wrong submission | Report refers to different model | Rejected from acceptance set |
| BOUNTY-EVAL-015 — Wrong evaluator | Unappointed key signs PASS | Report retained only as external claim, no council count |
| BOUNTY-EVAL-016 — Duplicate report | Same evaluator republishes result | No quorum multiplication |
| BOUNTY-EVAL-017 — Hidden tests | Evaluate committed hidden set | Declared trust/reveal rules honored; no secret test substitution |
| BOUNTY-EVAL-018 — Overfitting policy | Candidate memorizes public suite | Precommitted held-out/robustness gates still required |
| BOUNTY-EVAL-019 — Report signing | Runner provides arbitrary JSON unrelated to job | Signer requires matching authentic local evidence and explicit role |
| BOUNTY-EVAL-020 — No GPU key access | GPU worker host inspected | No council or wallet key/cookie/control socket |
| BOUNTY-EVAL-021 — Reviewer leak risk | Sealed reviewer learns decrypting secret | Disclosure risk demonstrated and documented, not denied |
| BOUNTY-EVAL-022 — Ciphertext relationship | Review exact encrypted artifact and plaintext root | Successful full relation check, not different-copy assumption |
| BOUNTY-EVAL-023 — Bad plaintext | Key matches HTLC but model fails local checks | Not marked verified/qualified; correct release-only limitation |
| BOUNTY-EVAL-024 — Cross hardware | Scores differ across supported hardware | Apply precommitted tolerance; no universal bitwise claim |

## COUNCIL
Owner: A2/A4/A8 · Layer: unit + regtest + public workflow · Specification sections 6,10.

| Test | Scenario | Required outcome |
|---|---|---|
| BOUNTY-COUNCIL-001 — Appointment consent | Council member signs exact terms/scope | Appointment bound before deposits |
| BOUNTY-COUNCIL-002 — Minimum reports | Fewer than M conforming eligible reports | Acceptance cannot proceed |
| BOUNTY-COUNCIL-003 — Report consistency | Reports for mixed spec versions | No combined quorum |
| BOUNTY-COUNCIL-004 — Policy vs spend | Acceptance certificate supplied as tx witness | No spend authority inferred |
| BOUNTY-COUNCIL-005 — Challenge window | Signing requested before challenge close | Honest signer refuses |
| BOUNTY-COUNCIL-006 — Challenge evidence | Valid artifact-mismatch challenge | Precommitted rerun/reject procedure |
| BOUNTY-COUNCIL-007 — Challenge flood | Repeated huge objections | Bounds and deadline enforced |
| BOUNTY-COUNCIL-008 — Tie selection | Equal candidates under fixed rule | Deterministic documented winner |
| BOUNTY-COUNCIL-009 — Late criteria change | Requester changes threshold after submissions | New terms required; no retrofit |
| BOUNTY-COUNCIL-010 — Council unavailable | No signatures obtained | Contributor recovery remains viable at maturity |
| BOUNTY-COUNCIL-011 — Council collusion limit | M valid signers choose wrong destination | Document actual on-chain authority; software refusal not misrepresented as covenant |
| BOUNTY-COUNCIL-012 — Milestone isolation | Award one tranche | Cannot spend separate later-tranche lot without its own approval |

## SEARCH
Owner: A5/A8 · Layer: native unit + process network + scale · Specification sections 2,12,13.

| Test | Scenario | Required outcome |
|---|---|---|
| BOUNTY-SEARCH-001 — Description only local | Opaque title; query appears only in description | Correct result |
| BOUNTY-SEARCH-002 — Description only WAN | Fresh peer has no local ID/record | Live remote discovery succeeds |
| BOUNTY-SEARCH-003 — Mixed kinds | Query matches public model, bounty and release | Typed results; no fabricated future model id |
| BOUNTY-SEARCH-004 — Economic filters | Remaining/confirmed/fundable filters | Applied against known validated economics; unknown handled explicitly |
| BOUNTY-SEARCH-005 — Language normalization | Japanese/fullwidth/accents mixed with English | Documented normalized matching; original signed text untouched |
| BOUNTY-SEARCH-006 — Bad Unicode | Malformed search bytes | Bounded rejection |
| BOUNTY-SEARCH-007 — String query limit | Direct string query larger than max | Same limits as structured object path |
| BOUNTY-SEARCH-008 — Local no network | scope=LOCAL | Zero outbound lookup messages |
| BOUNTY-SEARCH-009 — Sort after enrichment | Provider/economic values arrive remotely | Requested order retained, not overwritten by relevance |
| BOUNTY-SEARCH-010 — Duplicate results | Ten peers relay same issuer/object | One result with attributed observations |
| BOUNTY-SEARCH-011 — Conflicting issuers | Same title/model different signed claims | No ownership/metadata takeover |
| BOUNTY-SEARCH-012 — Applied filters | Unsupported or ignored filter requested | Explicit rejection/unsupported list, never false applied status |
| BOUNTY-SEARCH-013 — Real asynchronous jobs | Slow remote peer and concurrent UI | RUNNING/partial/final accurately match work |
| BOUNTY-SEARCH-014 — Cancel actual work | Cancel active multi-peer query | Network jobs stop; no more fanout |
| BOUNTY-SEARCH-015 — Job bounds | Many completed/cancelled queries | TTL/LRU bounded store |
| BOUNTY-SEARCH-016 — Iterator regression | Index peer source classification | Stable vector snapshot; sanitizer clean |
| BOUNTY-SEARCH-017 — Inverted index | 100k search records | No per-keystroke full-scan surprise; measured query cost |
| BOUNTY-SEARCH-018 — Remote card integrity | Remote card conflicts with signed record | Signed metadata wins; derived fields attributed |
| BOUNTY-SEARCH-019 — Negative cache expiry | Previously missing bounty later published | New valid record becomes discoverable |
| BOUNTY-SEARCH-020 — No tool execution | Search text contains function-call/command syntax | Only inert query data, no side effects |

## HEALTH
Owner: A5/A8 · Layer: unit + live swarm · Specification sections 2,13.

| Test | Scenario | Required outcome |
|---|---|---|
| BOUNTY-HEALTH-001 — Provider dedupe | Repeated identity/endpoint announcement | Count and rarity both dedupe |
| BOUNTY-HEALTH-002 — Per-file ranges | Same piece index in different model files | No cross-file coverage confusion |
| BOUNTY-HEALTH-003 — Partial-only complete union | No full seeder but ranges cover all files | Reconstructable true with evidence class |
| BOUNTY-HEALTH-004 — Unknown manifest | Zero/unknown total with providers | UNKNOWN, never falsely HIGH |
| BOUNTY-HEALTH-005 — Stale providers | Expire last unique source | Correct fragile/unavailable view |
| BOUNTY-HEALTH-006 — Huge ranges | Attacker advertises enormous sparse index | Bounded interval validation; no giant allocation |
| BOUNTY-HEALTH-007 — Ciphertext vs plaintext | Only encrypted pieces available | No usable plaintext badge |
| BOUNTY-HEALTH-008 — No global count | Two independent observers differ | Both show observation scope/time, not global census |

## FEED
Owner: A5/A8 · Layer: unit + network + crash recovery · Specification sections 9,13.

| Test | Scenario | Required outcome |
|---|---|---|
| BOUNTY-FEED-001 — New bounty propagation | A publishes; C knows only B | C network feed discovers without manual URI |
| BOUNTY-FEED-002 — Publication dedupe | Many relays announce one object | One publication event |
| BOUNTY-FEED-003 — Metadata not new | Issuer updates description | UPDATED event, not perpetual NEWEST promotion |
| BOUNTY-FEED-004 — Future time spam | Publisher timestamp far ahead | Policy reject/clamp with actual observation time |
| BOUNTY-FEED-005 — Durable change cursor | Consume events then restart | Continue from correct local sequence/epoch |
| BOUNTY-FEED-006 — ExportSince regression | Ask after nonzero sequence | Only correct subsequent changes or explicit gap |
| BOUNTY-FEED-007 — Snapshot pagination | Insert/delete while paging | Documented stable snapshot; no unexplained duplicate/skip |
| BOUNTY-FEED-008 — Cursor query binding | Reuse cursor with changed filter/sort | Reject |
| BOUNTY-FEED-009 — Cursor expiry | Old log retention gap | RESYNC_REQUIRED/CURSOR_EXPIRED |
| BOUNTY-FEED-010 — Reorg correction | Award event loses chain confirmation | Corrective observation; immutable original publication retained |
| BOUNTY-FEED-011 — Trending replay | Repeated identical announcements | No trend inflation |
| BOUNTY-FEED-012 — Trending authority | Remote claimed views/BTX not confirmed | No fake local/global usage metric |
| BOUNTY-FEED-013 — Index outage | Primary search/index peer dies | Bounded partial response and surviving discovery |
| BOUNTY-FEED-014 — Resource governor | Catalog follow during bandwidth/battery pressure | No bypass of global limits |
| BOUNTY-FEED-015 — Recovery retention | Discovery TTL expires while escrow live | Financial terms/recovery retained |
| BOUNTY-FEED-016 — Public privacy | Public feed requested by explorer | No wallet ownership, mandate or private report material |

## AGENT
Owner: A7/A8 · Layer: unit + concurrent wallet regtest · Specification sections 14,15.

| Test | Scenario | Required outcome |
|---|---|---|
| BOUNTY-AGENT-001 — Default zero spend | Agent only discovers bounty | No payment/signature |
| BOUNTY-AGENT-002 — Role separation | Reader calls signer endpoint | Denied |
| BOUNTY-AGENT-003 — Finite total | Many contributions under mandate | Total ceiling never exceeded |
| BOUNTY-AGENT-004 — Per action | One request exceeds allowed amount | Denied |
| BOUNTY-AGENT-005 — Fee ceiling | Small principal high fee | Denied |
| BOUNTY-AGENT-006 — Concurrent reservations | Parallel agents reserve same remaining budget | Atomic exposure bounds |
| BOUNTY-AGENT-007 — Idempotent retry | Lost response and reconnect | Same action/result, no duplicate reserve |
| BOUNTY-AGENT-008 — Changed request key | Same idempotency key altered payload | Conflict |
| BOUNTY-AGENT-009 — Mandate revocation | Revoke before new signing | No new signature |
| BOUNTY-AGENT-010 — Released signature caveat | Revoke after signature given | No claim of retroactive revocation |
| BOUNTY-AGENT-011 — Expired mandate | Expiry passed with prepared plan | Signing refused |
| BOUNTY-AGENT-012 — Wrong bounty | Allowed agent targets unapproved terms | Refused |
| BOUNTY-AGENT-013 — Wrong network | Allowed action sent to another genesis | Refused |
| BOUNTY-AGENT-014 — Refund key policy | Agent asks external refund destination | Refused |
| BOUNTY-AGENT-015 — Source injection | Description claims higher authorization | Ignored as data |
| BOUNTY-AGENT-016 — Reorg exposure | Funded tx reorgs while budget activity continues | No double release of reserved budget; explicit accounting policy |
| BOUNTY-AGENT-017 — Secret logs | Claims and evaluator reports logged | Sensitive data redacted; public preimage only at actual allowed disclosure |
| BOUNTY-AGENT-018 — Recovery role | Refund-only mandate attempts new funding | Denied |
| BOUNTY-AGENT-019 — Council role | Evaluator runner asks council tx signature | Denied |
| BOUNTY-AGENT-020 — Private API | Public bridge probes mandate/activity routes | Unavailable or explicitly denied |

## GUI
Owner: A6/A8 · Layer: Qt automated + supported desktop manual evidence · Specification sections 16.

| Test | Scenario | Required outcome |
|---|---|---|
| BOUNTY-GUI-001 — Find without terminal | Description search from fresh GUI | Public/bounty/release cards correctly typed |
| BOUNTY-GUI-002 — Create wizard | Full terms and council setup | Exact preview, validation and local draft/publication separation |
| BOUNTY-GUI-003 — Pledge distinction | User pledges then closes | No funds broadcast |
| BOUNTY-GUI-004 — Funding confirmation | User funds own lot | Amount/fees/council/refund shown and explicit authorization |
| BOUNTY-GUI-005 — Double click | Rapid repeated Fund/Submit clicks | One idempotent operation |
| BOUNTY-GUI-006 — Asynchronous cancel | Slow search/eval cancelled | UI responsive; actual job cancelled |
| BOUNTY-GUI-007 — Report detail | Multiple evaluator outcomes | Evidence and profile shown, no single misleading trusted badge |
| BOUNTY-GUI-008 — Policy vs signature | Council approves then signs | Separate operations and exact tx review |
| BOUNTY-GUI-009 — Recovery offline | Model helper/index unavailable | Wallet recovery still reachable |
| BOUNTY-GUI-010 — Copy URI | Abbreviated display copied | Full canonical exact URI |
| BOUNTY-GUI-011 — Escaping | HTML/bidi/long malicious metadata | Inert rendering and safe layout |
| BOUNTY-GUI-012 — Local vs public | Explorer and local owner compare entry | No owner secrets in public view |
| BOUNTY-GUI-013 — Sealed flow | User caches ciphertext and reveal occurs | Secret-known and local-verified states distinct |
| BOUNTY-GUI-014 — Accessibility | Keyboard and translated labels | All primary actions accessible |
| BOUNTY-GUI-015 — External client | Reference explorer uses documented API only | No private catalog/log reads or signer routes |

## E2E
Owner: C0/A8 · Layer: full process + wallet regtest + evaluator + network · Specification sections 20.

| Test | Scenario | Required outcome |
|---|---|---|
| BOUNTY-E2E-001 — A public award | Requester/funders/creator/5-of-7 reviewers/fresh observer | Complete discover→fund→evaluate→award→download→seed path |
| BOUNTY-E2E-002 — B refund restore | No accepted model; council/helper/index offline | Own matured refund from clean restore |
| BOUNTY-E2E-003 — C sealed staging | Exact reviewed ciphertext, individual staged HTLCs | Confirmed award→preimage→verify public artifact, original refunds preserved |
| BOUNTY-E2E-004 — D malicious council | Wrong proposal plus unavailable council cases | Honest policy refuses; actual quorum trust limit explicit |
| BOUNTY-E2E-005 — E reorg reveal | Reorg stage/claim after secret observed | Money rolls back; secret knowledge does not |
| BOUNTY-E2E-006 — F nomination | Percentage-qualified frozen council cohort | Exact eligibility, roster consent and no later seat mutation |
| BOUNTY-E2E-007 — G agent budget | Concurrent mandated proposals/replay/revoke | No unauthorized exposure or key substitution |
| BOUNTY-E2E-008 — H network/explorer | A/B/C/D no manually supplied object IDs; index loss | Surviving real network search/feed and public frontend |
| BOUNTY-E2E-009 — I GUI only | All supported human journeys | No terminal needed for core operations |
| BOUNTY-E2E-010 — J scale soak | 100k records, 10k bounties, updates/reorgs/jobs | Bounded resources with measured latency and monetary priority |
| BOUNTY-E2E-011 — Large artifact | Existing 13+GiB/equivalent signed model path | Actual bytes, hashes, network statistics and restart evidence |
| BOUNTY-E2E-012 — Previous-spec regression | Reconcile swarm/connectivity/governor claims | No unused helper/module mistaken for live implementation |

## RELEASE
Owner: C0/A9/A8 · Layer: build + packaging + documentation validation · Specification sections 19,21,22.

| Test | Scenario | Required outcome |
|---|---|---|
| BOUNTY-RELEASE-001 — Modelnet off | Build and run monetary tests with WITH_MODELNET=OFF | No helper/search/eval dependency on consensus path |
| BOUNTY-RELEASE-002 — Linux build | Supported Linux CPU/CUDA artifacts | Correct dependencies, explicit capabilities, actual tests |
| BOUNTY-RELEASE-003 — Apple build | Supported Apple Silicon/Qt artifact | Actual build and available tests; no invented GPU parity |
| BOUNTY-RELEASE-004 — ExactReplay regression | Compare baseline/new under supported validation profile | Unchanged monetary correctness and measured contention |
| BOUNTY-RELEASE-005 — API inventory | Compare docs/schema/RPC registry/routes | Every advertised handler exists and tested; no fake capability |
| BOUNTY-RELEASE-006 — README examples | Run human/agent documented read/prepare examples | Correct syntax and explicit no-spend/read boundaries |
| BOUNTY-RELEASE-007 — Dependency licenses | Audit pinned reused fragments/libs/tasks/data | Notices and licenses included; no incompatible code copied |
| BOUNTY-RELEASE-008 — Evidence integrity | Reconcile all matrix rows against logs/SHAs | No PASS from names/source presence/mocks for live requirements |
| BOUNTY-RELEASE-009 — Archive manifest | Verify package/binary hashes and source versions | Reproducible inventory, no secrets/private hostnames |
| BOUNTY-RELEASE-010 — Release gate | Mandatory failure/NOT_RUN present | Release flag cannot be justified as ready |
