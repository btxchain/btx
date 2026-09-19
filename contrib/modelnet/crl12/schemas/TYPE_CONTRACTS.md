# Signed type contracts — CRL/1.2

All eighteen types have `schema_revision=1.2`, `provider_id` and `created_at`. They use the unchanged HCP body-domain formula with the exact type name. Every declared field is required; unavailable facts use an explicit nullable type where defined. Production validation enforces cross-field and authority constraints beyond JSON Schema.

## LayerExtensionProfileV1_2

- `extension_id`: `#/$defs/Id`.
- `parent_profile_ref`: `#/$defs/ExactRef`.
- `base_extension_ref`: `#/$defs/ExactRef`.
- `schema_digest`: `#/$defs/Digest48`.
- `operations_digest`: `#/$defs/Digest48`.
- `supported_features`: `array`.
- `expires_at`: `#/$defs/UInt`.

## ProviderRoleManifestV1_2

- `manifest_id`: `#/$defs/Id`.
- `profile_ref`: `#/$defs/ExactRef`.
- `roles`: `array`.
- `endpoints`: `array`.
- `network_refs`: `array`.
- `conformance_refs`: `array`.
- `sequence`: `#/$defs/UInt`.
- `expires_at`: `#/$defs/UInt`.

## ServiceBindingV1_2

- `binding_id`: `#/$defs/Id`.
- `scope`: `#/$defs/Scope`.
- `role`: `#/$defs/Role`.
- `remote_profile_ref`: `#/$defs/ExactRef`.
- `remote_role_ref`: `#/$defs/ExactRef`.
- `permitted_effects`: `array`.
- `owner_policy_ref`: `#/$defs/ExactRef`.
- `generation`: `#/$defs/UInt`.
- `status`: `['PROPOSED', 'ACTIVE', 'REVOKED']`.
- `expires_at`: `#/$defs/UInt`.

## AdapterCapabilityManifestV1_2

- `adapter_id`: `#/$defs/Id`.
- `interface_name`: `#/$defs/Id`.
- `interface_revision`: `#/$defs/Id`.
- `schema_digest`: `#/$defs/Digest48`.
- `operations`: `array`.
- `support`: `['IMPLEMENTED', 'DISABLED', 'UNAVAILABLE']`.
- `ambiguity_contract_ref`: `#/$defs/ExactRef`.
- `evidence_refs`: `array`.

## InstitutionalAssetRecordV1_2

- `asset_id`: `#/$defs/Id`.
- `asset_kind`: `#/$defs/AssetKind`.
- `identifiers`: `array`.
- `native_resource_refs`: `array`.
- `rights_ref`: `nullable/union`.
- `quantity_unit`: `#/$defs/Id`.
- `financial_status`: `['FINANCIAL', 'NONFINANCIAL', 'UNDETERMINED']`.
- `record_authority_ref`: `#/$defs/ExactRef`.
- `effective_at`: `#/$defs/UInt`.
- `generation`: `#/$defs/UInt`.

## RightsStatementV1_2

- `rights_id`: `#/$defs/Id`.
- `asset_ref`: `#/$defs/ExactRef`.
- `holder_entity_id`: `#/$defs/Id`.
- `rights_kind`: `['PUBLIC_USE', 'LICENSE', 'OWNERSHIP', 'CONTRACT_CLAIM', 'FUND_SHARE', 'SPONSOR_COMMITMENT']`.
- `transferability`: `['PERMITTED_BY_TERMS', 'PROHIBITED', 'UNDETERMINED']`.
- `contract_digest`: `nullable/union`.
- `issuer_ref`: `#/$defs/ExactRef`.
- `valid_from`: `#/$defs/UInt`.
- `valid_until`: `nullable/union`.

## PositionObservationV1_2

- `observation_id`: `#/$defs/Id`.
- `scope`: `#/$defs/Scope`.
- `asset_ref`: `#/$defs/ExactRef`.
- `economic_position_key`: `#/$defs/Id`.
- `custodian_position_ref`: `#/$defs/Id`.
- `quantity`: `#/$defs/Quantity`.
- `view`: `['DIRECT', 'LOOKTHROUGH', 'OPERATIONAL']`.
- `status`: `['OPEN', 'CLOSED', 'DISPUTED']`.
- `authority_ref`: `#/$defs/ExactRef`.
- `effective_at`: `#/$defs/UInt`.
- `recorded_at`: `#/$defs/UInt`.
- `sequence`: `#/$defs/UInt`.
- `supersedes`: `nullable/union`.

## ValuationObservationV1_2

- `valuation_id`: `#/$defs/Id`.
- `asset_ref`: `#/$defs/ExactRef`.
- `position_ref`: `#/$defs/ExactRef`.
- `purpose`: `['MARKET_VALUE', 'COST_BASIS', 'REPLACEMENT_SCENARIO', 'UTILITY']`.
- `status`: `['CURRENT', 'STALE', 'UNAVAILABLE']`.
- `value`: `nullable/union`.
- `valuation_policy_ref`: `#/$defs/ExactRef`.
- `evidence_refs`: `array`.
- `effective_at`: `#/$defs/UInt`.
- `recorded_at`: `#/$defs/UInt`.
- `valid_until`: `#/$defs/UInt`.

## ExposureLinkV1_2

- `link_id`: `#/$defs/Id`.
- `scope`: `#/$defs/Scope`.
- `source_ref`: `#/$defs/ExactRef`.
- `links`: `array`.
- `financial_leverage_policy_ref`: `nullable/union`.
- `effective_at`: `#/$defs/UInt`.
- `coverage_bps`: `integer`.

## PortfolioProjectionV1_2

- `projection_id`: `#/$defs/Id`.
- `scope`: `#/$defs/Scope`.
- `as_of`: `#/$defs/UInt`.
- `observed_cutoff`: `#/$defs/UInt`.
- `watermarks`: `array`.
- `metric_results`: `array`.
- `position_refs`: `array`.
- `operational_refs`: `array`.
- `reconciliation_refs`: `array`.
- `next_cursor`: `nullable/union`.

## MetricDefinitionV1_2

- `metric_id`: `#/$defs/Id`.
- `metric_kind`: `['AUM', 'AUC', 'AUA', 'PLATFORM_ASSETS', 'FINANCIAL_NAV', 'CAPABILITY_COUNT', 'ACTUAL_COST', 'SCENARIO_VALUE']`.
- `scope_role`: `['MANAGER', 'CUSTODIAN', 'ADMINISTRATOR', 'PLATFORM', 'OWNER', 'OPERATOR']`.
- `inclusion_kinds`: `array`.
- `basis`: `['DIRECT_ONLY', 'LOOKTHROUGH_ONLY', 'OPERATIONAL_ONLY']`.
- `valuation_purpose`: `['MARKET_VALUE', 'COST_BASIS', 'NONE', 'REPLACEMENT_SCENARIO']`.
- `mandate_required`: `boolean`.
- `policy_ref`: `#/$defs/ExactRef`.
- `generation`: `#/$defs/UInt`.

## ExportManifestV1_2

- `export_id`: `#/$defs/Id`.
- `scope`: `#/$defs/Scope`.
- `projection_ref`: `#/$defs/ExactRef`.
- `format`: `['JSONL', 'CSV', 'DESKTOP_CONTEXT']`.
- `mapping_digest`: `#/$defs/Digest48`.
- `chunks`: `array`.
- `total_rows`: `#/$defs/UInt`.
- `privacy_policy_ref`: `#/$defs/ExactRef`.
- `expires_at`: `#/$defs/UInt`.

## PortfolioInstructionV1_2

- `instruction_id`: `#/$defs/Id`.
- `scope`: `#/$defs/Scope`.
- `source_projection_ref`: `#/$defs/ExactRef`.
- `source_system_id`: `#/$defs/Id`.
- `requested_action`: `['DRAFT_RESERVE_ALLOCATION', 'DRAFT_RESEARCH_COMMITMENT', 'DRAFT_CAPABILITY_ACQUISITION', 'DRAFT_PRODUCT_REFERRAL']`.
- `objective`: `#/$defs/Text`.
- `maximum_exposure`: `#/$defs/Money`.
- `target_refs`: `array`.
- `client_operation_id`: `#/$defs/Id`.
- `expires_at`: `#/$defs/UInt`.

## InteroperabilityReceiptV1_2

- `receipt_id`: `#/$defs/Id`.
- `scope`: `#/$defs/Scope`.
- `operation_id`: `#/$defs/Id`.
- `request_body_id`: `#/$defs/Digest48`.
- `state`: `['ACCEPTED', 'VALIDATED', 'APPLIED', 'REJECTED', 'RECONCILIATION_REQUIRED']`.
- `result_refs`: `array`.
- `original_provider_ref`: `#/$defs/ExactRef`.
- `sequence`: `#/$defs/UInt`.

## ScenarioDefinitionV1_2

- `scenario_id`: `#/$defs/Id`.
- `scope`: `#/$defs/Scope`.
- `projection_ref`: `#/$defs/ExactRef`.
- `shocks`: `array`.
- `method`: `['DETERMINISTIC_SHOCK_V1']`.
- `assumption_refs`: `array`.
- `expires_at`: `#/$defs/UInt`.

## ScenarioResultV1_2

- `result_id`: `#/$defs/Id`.
- `scope`: `#/$defs/Scope`.
- `scenario_ref`: `#/$defs/ExactRef`.
- `financial_change`: `nullable/union`.
- `unpriced_refs`: `array`.
- `operational_impacts`: `array`.
- `source_coverage_bps`: `integer`.
- `calculation_version`: `#/$defs/Id`.

## ConformanceStatementV1_2

- `statement_id`: `#/$defs/Id`.
- `role_manifest_ref`: `#/$defs/ExactRef`.
- `candidate_fingerprint`: `#/$defs/Digest48`.
- `test_manifest_digest`: `#/$defs/Digest48`.
- `evidence_level`: `['REFERENCE', 'NATIVE_UNIT', 'PROCESS_E2E', 'NATIVE_CHAIN', 'OPERATOR_PILOT']`.
- `passed_case_ids`: `array`.
- `unrun_case_ids`: `array`.
- `issuer_class`: `['SELF_ATTESTED', 'INDEPENDENT_REVIEW']`.
- `expires_at`: `#/$defs/UInt`.

## ReconciliationBreakV1_2

- `break_id`: `#/$defs/Id`.
- `scope`: `#/$defs/Scope`.
- `kind`: `['DUPLICATE_CLAIM', 'QUANTITY_MISMATCH', 'PRICE_MISSING', 'RIGHTS_UNKNOWN', 'STALE_SOURCE', 'IDENTIFIER_COLLISION', 'SEQUENCE_GAP']`.
- `source_refs`: `array`.
- `state`: `['OPEN', 'ACKNOWLEDGED', 'RESOLVED_BY_EVIDENCE']`.
- `assigned_role`: `#/$defs/Id`.
- `resolution_refs`: `array`.
- `generation`: `#/$defs/UInt`.

