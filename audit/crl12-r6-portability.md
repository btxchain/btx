# Extra High review R6 — portability

Tree: `/home/administrator/btx-0.34.7-private`

## Verdict

v1.1 `GET /extensions/cognitive-reserve` is unchanged. v1.2 is a separate route. Combined contract 84+43=127. SDK has no `/rpc` and no `executeAllocation` operation_id. Package TYPE_CONTRACTS names are now accepted by `HcpObjectTypeOk` as inbound aliases; engine **responses** still sign the shorter engine names (domain-separated, tests lock them).

## Findings

### R6-01 MAJOR (documented) — signed response type strings vs package names

Engine still emits `AdapterCapabilityReportV1_2`, `InstitutionalAssetV1_2`, `AssetRightsV1_2`, `ImportManifestV1_2`, `InstitutionalScenarioResultV1_2`, `LayerConformanceClaimV1_2`. Package wants `AdapterCapabilityManifestV1_2`, `InstitutionalAssetRecordV1_2`, `RightsStatementV1_2`, `InteroperabilityReceiptV1_2`, `ScenarioResultV1_2`, `ConformanceStatementV1_2`.  
This round registered the package names in `kTypes` so inbound envelopes with those names verify. Changing **outbound** names would rewrite body_id and break the 211 native cases. Do not flip outbound without a coordinated test + SDK update.

### R6-02 COMPLETE — SDK / desktop view-draft

Python 26 tests PASS. TypeScript 16 PASS. Desktop apply is INSPECT/COMPARE/DRAFT only.

### R6-03 COMPLETE — persist roundtrip of CR12 maps

`PersistObj` / `Restore` now dump and load CR12 maps. `btx-hcpd` persists after each Handle when `-datadir` is set. Native `cr12_recovery_11_persist_roundtrip` PASS.
