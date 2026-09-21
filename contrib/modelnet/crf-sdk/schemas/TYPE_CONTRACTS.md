# Signed extension objects

## ReserveExtensionProfileV1_1

Required body fields: `schema_revision`, `provider_id`, `created_at`, `extension_id`, `parent_profile_body_id`, `schema_digest`, `operations_digest`, `supported_features`, `expires_at`.

Strict canonicalization and domain-separated identity apply. Cross-field validation follows the normative specification.

## EntityLinkV1_1

Required body fields: `schema_revision`, `provider_id`, `created_at`, `link_id`, `parent_entity_id`, `child_entity_id`, `relationship`, `scopes`, `accepted_by`, `generation`, `expires_at`, `status`.

Strict canonicalization and domain-separated identity apply. Cross-field validation follows the normative specification.

## PortfolioV1_1

Required body fields: `schema_revision`, `provider_id`, `created_at`, `legal_entity_id`, `portfolio_id`, `account_ref`, `label`, `purpose`, `reporting_currency`, `generation`, `status`.

Strict canonicalization and domain-separated identity apply. Cross-field validation follows the normative specification.

## ReservePolicyV1_1

Required body fields: `schema_revision`, `provider_id`, `created_at`, `scope`, `policy_id`, `generation`, `protected_atoms`, `per_plan_cap_atoms`, `lifetime_cap_atoms`, `outstanding_cap_atoms`, `permitted_actions`, `replenishment_mode`, `expires_at`, `status`.

Strict canonicalization and domain-separated identity apply. Cross-field validation follows the normative specification.

## ReserveSnapshotV1_1

Required body fields: `schema_revision`, `provider_id`, `created_at`, `scope`, `snapshot_id`, `ledger_sequence`, `policy_ref`, `available_atoms`, `protected_atoms`, `remaining_authority_atoms`, `allocation_capacity_atoms`, `existing_hold_atoms`, `committed_atoms`, `refund_pending_atoms`, `observed_at`.

Strict canonicalization and domain-separated identity apply. Cross-field validation follows the normative specification.

## WorkloadProfileV1_1

Required body fields: `schema_revision`, `provider_id`, `created_at`, `legal_entity_id`, `workload_id`, `generation`, `objective`, `accepted_task_definition`, `evidence_minimum`, `annual_accepted_tasks`, `horizon_months`, `data_policy`, `runtime_profiles`, `assumptions`.

Strict canonicalization and domain-separated identity apply. Cross-field validation follows the normative specification.

## TCOComparisonV1_1

Required body fields: `schema_revision`, `provider_id`, `created_at`, `legal_entity_id`, `comparison_id`, `workload_ref`, `calculation_version`, `quality_equivalent`, `route`, `candidate_refs`, `cost_lines`, `unknown_inputs`, `expires_at`.

Strict canonicalization and domain-separated identity apply. Cross-field validation follows the normative specification.

## CapitalPlanV1_1

Required body fields: `schema_revision`, `provider_id`, `created_at`, `legal_entity_id`, `plan_id`, `objective`, `comparison_ref`, `route`, `maximum_exposure`, `expected_outcome`, `observation_refs`, `expires_at`.

Strict canonicalization and domain-separated identity apply. Cross-field validation follows the normative specification.

## AllocationPlanV1_1

Required body fields: `schema_revision`, `provider_id`, `created_at`, `legal_entity_id`, `allocation_id`, `capital_plan_ref`, `policy_ref`, `network`, `legs`, `maximum_exposure`, `client_operation_id`, `expires_at`.

Strict canonicalization and domain-separated identity apply. Cross-field validation follows the normative specification.

## ApprovalRuleV1_1

Required body fields: `schema_revision`, `provider_id`, `created_at`, `legal_entity_id`, `rule_id`, `generation`, `eligible_roles`, `distinct_person_quorum`, `exclude_initiator`, `veto_enabled`, `threshold_atoms`, `expires_at`, `status`.

Strict canonicalization and domain-separated identity apply. Cross-field validation follows the normative specification.

## ApprovalRequestV1_1

Required body fields: `schema_revision`, `provider_id`, `created_at`, `legal_entity_id`, `request_id`, `allocation_ref`, `allocation_body_id`, `rule_ref`, `rule_body_id`, `policy_ref`, `policy_generation`, `initiator_person_id`, `maximum_exposure`, `expires_at`.

Strict canonicalization and domain-separated identity apply. Cross-field validation follows the normative specification.

## ApprovalDecisionV1_1

Required body fields: `schema_revision`, `provider_id`, `created_at`, `legal_entity_id`, `decision_id`, `request_ref`, `request_body_id`, `allocation_body_id`, `policy_generation`, `rule_body_id`, `actor`, `decision`, `sequence`, `expires_at`.

Strict canonicalization and domain-separated identity apply. Cross-field validation follows the normative specification.

## CapabilityPositionV1_1

Required body fields: `schema_revision`, `provider_id`, `created_at`, `legal_entity_id`, `position_id`, `portfolio_id`, `package_core_id`, `recipe_id`, `lock_id`, `resource_refs`, `rights_ref`, `acquisition_refs`, `lifecycle`, `generation`.

Strict canonicalization and domain-separated identity apply. Cross-field validation follows the normative specification.

## ResearchProgramV1_1

Required body fields: `schema_revision`, `provider_id`, `created_at`, `legal_entity_id`, `program_id`, `objective`, `evidence_refs`, `native_terms_refs`, `programme_ceiling_atoms`, `visibility`, `deadline`, `generation`.

Strict canonicalization and domain-separated identity apply. Cross-field validation follows the normative specification.

## ProgramMembershipV1_1

Required body fields: `schema_revision`, `provider_id`, `created_at`, `legal_entity_id`, `membership_id`, `program_ref`, `member_entity_id`, `role`, `ceiling_atoms`, `accepted_terms_ref`, `status`, `expires_at`.

Strict canonicalization and domain-separated identity apply. Cross-field validation follows the normative specification.

## ProductOfferV1_1

Required body fields: `schema_revision`, `provider_id`, `created_at`, `offer_id`, `product_provider_id`, `product_class`, `rights_ref`, `eligibility_policy_ref`, `fee_disclosure_ref`, `supported_action`, `expires_at`.

Strict canonicalization and domain-separated identity apply. Cross-field validation follows the normative specification.

## CapitalExecutionReceiptV1_1

Required body fields: `schema_revision`, `provider_id`, `created_at`, `legal_entity_id`, `execution_id`, `allocation_ref`, `allocation_body_id`, `child_refs`, `state`, `observation`, `sequence`.

Strict canonicalization and domain-separated identity apply. Cross-field validation follows the normative specification.

## ReserveReportV1_1

Required body fields: `schema_revision`, `provider_id`, `created_at`, `legal_entity_id`, `report_id`, `snapshot_refs`, `position_refs`, `commitment_refs`, `reporting_currency`, `report_type`, `period_start`, `period_end`, `as_of`.

Strict canonicalization and domain-separated identity apply. Cross-field validation follows the normative specification.
