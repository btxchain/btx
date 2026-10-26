# Qt replacement coverage and retirement gates

Atlas is the interface to one BTX node on the peer network. Money peers and
model peers are both participants in that network. The Qt client remains in the
tree until the machine gates below have been run. A generic RPC template is not
a finished dialog, and this matrix is not a retirement certificate.

| Existing function / new feature | Candidate implementation | Remaining parity work |
|---|---|---|
| Overview, sync/chain/mining status | Network home, wallet overview with recent transactions, and the sync banner | Exact warning text for every network transition |
| Multiwallet create/open/close/restore/migrate | Selector and reviewed native templates | Real descriptor/legacy/encrypted/PQ migration and error recovery |
| Send, multiple outputs, fees, RBF | Exact-amount PSBT composer, owned change address, subtract-fee for one recipient, and a node fee estimate converted from BTX/kvB | All address types and external signatures |
| Coin control and locking | Coins grouped by address, with select-all, select-address, clear, and native lock/unlock | Tree selection and manual selection edge cases |
| Receive and QR | Native new-address review, optional amount/label/message, local request history, SVG save, and printing the request | A dedicated receipt layout |
| History/details/export | Paged tables, filters, transaction summary, bump-fee and abandon review, and a privacy-masked CSV of the loaded page | Export of a wallet’s entire history |
| Address book | Receiving and sending lists, saving a sending label, and clearing a label through native review | Deleting a key is intentionally absent |
| Sign/verify message | Dedicated sign review and boolean verify result | Supported key/script types and warning equivalence |
| PSBT import/decode/sign/finalize | Dedicated tools and immutable native composer | Hardware signer roundtrip, repeated partial signatures, clipboard/import limits |
| Wallet encryption/passphrase/backup | Reviewed native methods; hidden credential values in native review | Hardened native secret-entry widgets; backup/restore crash tests |
| Raw private-key export | Deliberately denied in Atlas | Not required by ordinary wallet UI; unrestricted Qt-console equivalence is intentionally narrower |
| RPC console | Strict JSON operator console, native confirmation for effects | Legacy nested-console grammar intentionally not copied; document migration |
| Node peers/bans/network activity | Network home with money peers, model peers, disconnect, ban, and recent headers | NetWatch plots and platform warning parity |
| Mempool/block inspection | Current size, bytes, transaction ids, fee histogram, and samples taken while the network page is open | Historical mempool charts stored by the node |
| Tor pairing | Observed onion URI, copy, and QR | Endpoint-change lifecycle |
| Node settings | 59 allowlisted config keys, full native diff review, hash conflict refusal | Full OptionID inventory, effective CLI overrides, reset/restart semantics, platform migration |
| Startup/tray/single instance | Native tray, login launch, singleton routing, minimize-on-close, and a separate window-bounds file | Menus, notifications, and multi-monitor placement |
| URI/file associations | Scheme config, bounded URI preview, and a regular `.btx` file that contains one URI | OS registration and startup races on every platform |
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
