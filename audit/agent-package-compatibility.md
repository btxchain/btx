# Compatibility decision — Package Core v2

## Version allocation

**Decision: allocate Package Core `version: 2` as specified. No collision.**

Private-tree search found:

- No `BTX/PackageCore/v1` or `BTX/PackageCore/v2` domain
- No `agent_handoff` field in native package codec
- `EncodeMagnetAnalog` emits JSON `schema_version: 2` for the **thin magnet analog**, which is not a BTXPKG1 core version and must stay distinct

If a later commit introduces an incompatible Core v2, stop and pick the next unused core version with operator approval. Do not emit two formats under `version: 2`.

## Write policy

- Agent-handoff packages: Core v2 only, critical extension `AGENT_HANDOFF_V1`
- Legacy acquisition-only descriptors may still be written as Core v1 (no documents/handoff)
- Old readers must return `UNSUPPORTED_CORE_VERSION` / `UNSUPPORTED_CRITICAL_EXTENSION`; never silent downgrade
- Outer frame remains BTXPKG1 (`42 54 58 50 4b 47 00 01`), max payload 4 MiB, flags 0
- Preserve existing `EncodeBtxBundle` for current NETWORK-02 tests; Core v2 uses new `EncodeBtxPackage` / `DecodeBtxPackage` with BTX-PJSON1 payload
- `package_core_id` is SHA-384(`UTF8("BTX/PackageCore/v{N}") || 0x00 || LE64(len(C)) || C`) — **not** `DomainHash`

## Identity domains that must not mix

- ModelCore / ArtifactCore (existing)
- PackageCore v1/v2 (this round)
- Software distributor release digest (InstallPlan; independent trust)
- Wallet / spend (automatic_spend_atoms remains 0)
