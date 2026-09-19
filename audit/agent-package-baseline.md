# Agent-readable package — tree fingerprint (before Core v2 writes)

Recorded 2026-09-16 for CURSOR_NEXT_PHASE_PROMPT.txt (zip
`~/Downloads/BTX_Agent_Readable_Package_and_Neutral_Model_Layer.zip`).

## Tree

- Path: `/home/administrator/btx-0.34.7-private`
- Branch: `feat/0.34.8-modelnet-first-run`
- HEAD: `573b4aa41f26ea6c61a00ee6096c5ff4de319335`
- Working tree: **dirty** (NETWORK-02 + gap impl; ~42 tracked files, thousands of insertions)
- `CLIENT_VERSION`: 0.34.8, `CLIENT_VERSION_IS_RELEASE=false`
- Compile tree: `build-gcc13` Release GCC 13 (only tree)
- Disk `/`: ~7.2G free (99%) — incremental rebuilds only
- Production `btxd`: do not stop/SIGKILL/replace

## Package zip

- Extract: `/home/administrator/Documents/btxchain/.0348-agent-package.local/BTX_Agent_Package_and_Neutral_Model_Layer/`
- Prompt: `CURSOR_NEXT_PHASE_PROMPT.txt` (no `Cursor_Prompt.txt`; this is the assignment)
- Spec: `specification/BTX_0348_Agent_Readable_Package_Spec.md` (BTX-AHP-001 rev 1.0)

## Prior unresolved blockers (still true)

- Live R2 WAN, live Hugging Face, GUI compile, ASan, mixed 0.34.7 binary, 400 GiB I/O, real `btx-torrentd` subprocess: NOT_RUN
- No push / merge / tag / `IS_RELEASE`

## Existing package symbols (do not duplicate)

| Spec area | Existing | Gap |
|---|---|---|
| BTXPKG1 frame | `EncodeBtxBundle` / `DecodeBtxBundle` | payload is `UniValue::write()`, not BTX-PJSON1; no Core v2 schema |
| Magnet analog | `EncodeMagnetAnalog` `schema_version: 2` | **different object** from Package Core v2 |
| Bundle public | `EncodePublicBtxBundle` | inspect/import via VerifiedManifest; no documents/handoff |
| Canonical tagged codec | `canonical_codec.cpp` bounty CODEC.md | **not** BTX-PJSON1 |
| `btx-open` | URI preview only | no `.btx` file mode |
| RPC | `inspectbtxpackage` / `createbtxpackage` | no `getbtxpackagedocument`, install/runtime plans |

No `BTX/PackageCore/v2` or `agent_handoff` symbols in the private tree at freeze.
