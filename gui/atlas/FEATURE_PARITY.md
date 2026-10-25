# Qt replacement coverage and retirement gates

**No complete Qt parity claim.** This matrix describes source coverage in this
candidate. Native tests and the full Qt-source scan must close every transition
before Qt is removed. A generic RPC template is not a complete redesigned dialog.

| Existing function / new feature | Candidate implementation | Remaining parity work |
|---|---|---|
| Overview, sync/chain/mining status | Dashboard and bounded native observations | Sync overlays, exact warnings, initial-download and all network transitions |
| Multiwallet create/open/close/restore/migrate | Selector and reviewed native templates | Real descriptor/legacy/encrypted/PQ migration and error recovery |
| Send, multiple outputs, fees, RBF | Dedicated exact-amount native PSBT composer | All address types, custom change UI, subtract-fee behavior, external signatures |
| Coin control and locking | Input picker and native lock/unlock templates | Grouping/tree selections, fee estimators and manual selection edge cases |
| Receive and QR | Native new-address review, exact URI and QR matrix | Request history, optional amount/message composer, save-image/print parity |
| History/details/export | Paged transaction tables, detail RPC, safe CSV helpers | Full Qt filters, rebroadcast/replacement workflow, privacy export review |
| Address book | Native labels and address-by-label operations | Full CRUD UX and sending/receiving separation |
| Sign/verify message | Reviewed operation templates | Native sign/verify UX, supported key/script types and warning equivalence |
| PSBT import/decode/sign/finalize | Dedicated tools and immutable native composer | Hardware signer roundtrip, repeated partial signatures, clipboard/import limits |
| Wallet encryption/passphrase/backup | Reviewed native methods; hidden credential values in native review | Hardened native secret-entry widgets; backup/restore crash tests |
| Raw private-key export | Deliberately denied in Atlas | Not required by ordinary wallet UI; unrestricted Qt-console equivalence is intentionally narrower |
| RPC console | Strict JSON operator console, native confirmation for effects | Legacy nested-console grammar intentionally not copied; document migration |
| Node peers/bans/network activity | Read views and reviewed native controls | Full NetWatch plots/context menus and platform warning parity |
| Mempool/block inspection | Native information and generic read tools | Bespoke time-series charts, historical range/selection/export behavior |
| Tor pairing | Observed v3 onion URI and copy; native QR utility | Pairing QR screen, lifecycle/endpoint-change UX |
| Node settings | 59 allowlisted config keys, full native diff review, hash conflict refusal | Full OptionID inventory, effective CLI overrides, reset/restart semantics, platform migration |
| Startup/tray/single instance | Native tray, explicit login launch, singleton routing | Close/minimize policy, menus, window-state persistence, notifications |
| URI/file associations | Native scheme config and bounded URI preview | Real OS `.btx` file-open event routing on all platforms and startup race tests |
| Language/font/denominations | System fonts; BTX/mBTX/atoms; reduced-motion/scaling | Qt translations, configurable fonts, full legacy TBC/tonal behavior |
| Model catalog/search/acquire/import | Live contract forms and dedicated catalog | Full source RPC audit, all native job/refusal/cancel flows, large-search paging |
| Downloads/shared/collections/preservation/identity | Tabs plus native operations | Source-specific semantics and read/write declarations independently audited |
| Funding/bounties/capabilities | Reviewed method templates; native availability check | Actual exact-contract sign/refund/recovery flows, real regtest and native qualification |
| Atlas 3D / 2D | Custom WebGL2 + Canvas fallback, stable layouts, inspect/search | Native GPU/worker contexts, picking/focus, large-data accessibility and leakage tests |
| Local assistant | Bounded verified local-model session, redacted reads, no effect tools | Real locally installed model and hostile-output tests, runtime cancellation |
| Generated widgets | Bounded read-only AST, preview/revision history | Native-context fuzzing and durable policy review; no arbitrary-code extension |
| Workflows / agent observation | Draft DAG editor and native evidence views | Native task dispatcher/receipt integration where backend supports it; drafts are not executable |
| Model internals / scientific research | Actual capture import, header inspect, manual local capture adapter | Live runtime adapters, independent evidence/signatures, scientifically validated steering |
| Model evolution / L2 economy | Observational UI, native operations only when present | Does not implement or qualify missing native distributed capabilities |

## Required no-regression review

Run `contrib/atlas/scan_qt.py` and reconcile every QAction, OptionID, `.ui` dialog,
ClientModel/WalletModel path and native RPC at the actual descendant commit.
Test absent wallets, disabled ModelNet, unavailable helpers, errors, cancellation,
timeouts, offline startup, locked wallets, process crashes, wallet restore, zero
balance, address/key formats, multiple monitors and platform accessibility.

The replacement is the product direction, but preservation of old Qt in the
repository is a safety/rollback measure until these gates pass. This app does not
call out to Qt dialogs to claim parity, and it does not depend on Qt at runtime.
