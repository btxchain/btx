# Integration coordinator instructions

## Objective

Integrate the delivered independent BTX Atlas source as the replacement desktop
product on a descendant of PR #245. Keep Neuron Explorer's black scientific
spatial interface as the visual direction, and the client/runtime separation,
bounded surface descriptions and evidence inspection as the functional direction.
Do not turn it into a chat-only app or a Qt WebView tab. No React/Electron/Three.js
runtime is required by this implementation. Reuse BTX's native consensus, wallet,
ModelNet and local inference contracts rather than rebuilding those systems.

## Parent and branch

Parent: `18ea826ee3d82edf65a274c00316bd118ed731d2` (`btx-035/swarm`, PR245).
Suggested branch: `btx-035/atlas-native`. PR base: `btx-035/swarm`.

1. Fetch the real PR head, record its SHA and check whether it has advanced.
2. Apply this package at the pinned parent using the provided installer, or create
   a clean worktree there and copy the overlay. Preserve its manifests/reports.
3. If upstream advanced, merge/rebase its new head explicitly and regenerate the
   native method/Qt inventory. Do not pretend the old pin is still current.
4. Resolve and audit `Cargo.lock`, compile native code, fix API/compiler problems,
   format Rust and run the supplied tests. No native compilation occurred here.
5. Create a **draft** PR only after source integrity and baseline builds work.
   Commit and push are your tasks; this delivery did not mutate GitHub.

## Work allocation

Assign non-overlapping owners: native RPC/approvals/financial correctness;
WebView/OS integration and installers; wallet parity; ModelNet/compute operations;
spatial rendering/memory/accessibility; local assistant/generated surfaces; and
independent adversarial verification. Freeze shared RPC DTOs and operation schemas
before parallel edits. Require tests for cross-boundary changes.

## Must complete before making Atlas the default or deleting Qt

* Run `contrib/atlas/scan_qt.py` against the complete pinned/merged tree. Compare
  QAction routes, dialog workflows, OptionID settings, `.ui` files, translations,
  wallet-model behavior, node controls and indirect RPC dispatches. The lexical
  scanner is a starting inventory, not an automatic equivalence proof.
* Replace generic forms with task-specific controls where needed for full parity,
  and test every state, warning, cancellation and recovery path listed in
  `FEATURE_PARITY.md`. Mark deferred work explicitly; never call it done because
  the RPC method exists.
* Complete OS behavior: wallet/client notifications, minimize/close/tray policy,
  native file-open association events, application menus, keyboard conventions,
  persisted window state, native language catalogs and any legacy denomination.
* Verify native financial flows with real disposable wallets: all address/script
  types supported by BTX (including PQ forms), fees, multiple recipients, locked
  coins, RBF, PSBT external signing, encrypted/watch-only wallets, backup/restore,
  migration, refunds, chain reorg and uncertain-outcome reconciliation.
* Native CSP/IPC tests must attempt calls from remote origins, nested frames,
  poisoned metadata, generated panels and the local model. No approval/spend may
  occur. Enforce restrictive Windows file ACLs before public qualification.
* Test real native browser engines and GPU/worker paths on Mac/Windows/Linux;
  compile-time success alone is not runtime qualification. Measure startup/RSS,
  idle CPU, GPU buffers and resource pressure while local inference is active.
* Run a real locally acquired/verified model through `generatemodel`, confirming
  model/profile mismatch, missing adapter, cancellation and no-provider operation.
  Model-authored suggestions never supply privileged arguments or confirmation.
* Preserve current native swarm/evolution/L2 qualification boundaries. A UI is
  not an implementation of native distributed training, admission or settlement.
* Commit all exact acceptance evidence against the integrated source SHA. Run
  `check_gate.py` and obtain human security review before the Qt retirement commit.

## Mandatory invariants

No monetary consensus edits; no second swarm scheduler; no rendering-derived
permissions; no raw wallet credential in agent context; no external inference
fallback; exact atoms; native chain/genesis checks for writes; independent
confirmation of sign and broadcast; no blind retry after uncertain delivery; no
privileged HTML/JS surface renderer; no synthetic data in live mode; no invented
host count, model activation, payout, liquidity or research qualification.

## Suggested PR body

"Adds standalone BTX Atlas: framework-free spatial interface, native authority
broker, wallet/ModelNet operator workbench, local assistant, bounded surfaces,
source inventory, and qualification harnesses. Parent: [exact SHA]. Qt retained
until the tracked replacement gates pass. Executed tests: [actual evidence].
Unrun/failed gates: [exact IDs]. No distributed release or formal security claim."

The final migration commit may update desktop/default build/install targets and
retire old Qt sources only when all required parity/platform records are accepted.
Do not delete Qt now merely to make the repository appear transitioned.
