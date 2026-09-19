# Agent-package CLI / GUI (BTX-AHP-001 Lane G)

Local source notes for the agent-readable `.btx` handoff. This file does **not**
claim a release, a helper RPC inventory, or a built Qt binary.

Lane G ownership this round: `src/btx-open.cpp` and this audit. **Not**
`src/modelnet/helper.cpp`, **not** any `CMakeLists.txt`, **not** enabling
`BUILD_GUI`.

## `btx-open` (implemented in source)

Exactly one argument (`argc == 2`). No shell. Preview only.

| argv | Behavior |
|---|---|
| `btx://…` | **Unchanged** URI dispatcher: canonical / display / copy / kind / digest, `action=preview-only`, storage-consent fields, `wallet=not-opened`. No file I/O. |
| Path ending in `.btx` (any case), or a path whose first eight bytes match `LooksLikeBtxBundle` (`BTXPKG1`) | Bounded local inspect (read cap = 68-byte frame + 4 MiB payload). Prints `core_version` and `package_core_id` when a `core.version` of 1 or 2 is parseable, a comma-separated `documents=` list, and `agents_snippet=` (first 200 characters of embedded `AGENTS.md` if present). Always `action=preview-only`. |
| One argv that mixes `btx://` with a file path (whitespace after a URI, or `btx://` not at the start) | Rejected. Still a single argument; do not pass URI and file together. |
| Bare 85-character token / `btx:` convenience form (not a `.btx` path, not bundle magic) | Same URI decode path as before. |

Inspect **does not** install a client, open the spending wallet, use the
network, run inference, import trust, upload, seed, or write `AGENTS.md` (or
any other document) into the workspace. Terminal control bytes in printed
document text and paths are escaped (`\n` / `\r` / `\t` / `\x1b` / other C0 / DEL).

File-mode `package_core_id` is BTX-PJSON1 `PackageCoreId` when
`DecodeBtxPackage` succeeds (`SHA384(UTF8("BTX/PackageCore/v{N}") || 0x00 ||
LE64(len(C)) || C)`). Fallback `DecodeBtxBundle` is NETWORK-02
`UniValue::write()` framing only. Preview is not helper verification.

## Spec §16 helper recipes

Helper RPCs exist in this 0.34.8-dev tree (`inspectbtxpackage`,
`verifybtxpackage`, `getbtxpackagedocument`, `planbtxacquisition`,
`executebtxacquisition`, `getbtxacquisition`, `cancelbtxacquisition`,
`planbtxclientinstall`, `planbtxruntime`). `btx-model package inspect`
accepts a `.btx` path or hex. GUI remains **DEFERRED_WITH_EVIDENCE**
(`BUILD_GUI=OFF`). `verifybtxpackage` is fail-closed on unsigned packages;
inspect remains available. `planbtxruntime` is plan-only and is not a
public execution door.

An agent with no BTX still starts with generic inspection (`btx-open` file
mode, or any bounded reader), not a helper RPC.

## GUI — DEFERRED_WITH_EVIDENCE (`BUILD_GUI=OFF`)

This lane **does not** enable `BUILD_GUI` and **does not** compile `btx-qt`.

Evidence the option is off and stays off:

- `CMakeLists.txt`: `option(BUILD_GUI "Build btx-qt executable (BTX-Qt app on macOS)." OFF)` (default OFF).
- `audit/final-convergence-baseline.md`: `BUILD_GUI` **OFF**; Qt6 libraries present on the host, **no** `qt6-base-dev` headers; `BUILD_GUI=ON` recorded NOT_RUN.
- `audit/performance-0.34.8.md` and modelnet docs already describe GUI as source-only under `BUILD_GUI=OFF`.

Source that would matter after an authorized GUI build (not executed here):

- `src/qt/modelnetpage.cpp` — file picker includes `*.btx`; open path calls `openmodelshare` **preview-only** (no auto-`getmodel`).
- `src/qt/paymentserver.cpp` — existing `.btx` / `.btxlink` file paths emit `receivedModelResource` (model share), not a payment/BIP70 path.
- `src/qt/intro.cpp` — OS-handler install locates sibling `btx-open` (URI handler). Spec §15: double-click is bounded local inspect; that needs the file mode above plus installer/wizard association. Not proven at runtime.

Deferred work (still not this lane): Qt document preview that does not render
active HTML / external images / scripts / link previews; trust-level fields
kept separate; no secret re-display. Double-click must not install BTX, mine,
seed, spend, or run a model.

## Out of scope / not done

- No commit / push / production binary replacement.
- GUI compile remains `BUILD_GUI=OFF`.
- `CLIENT_VERSION_IS_RELEASE` remains false.
