// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// Generated from BTX035_v1_1/schemas/*.schema.json record payloads.
// Skips envelope.schema.json and schemas that are not record payloads.
// Each record lists required property names in schema order.
// reject_unknown is true when additionalProperties is false.

struct V11PayloadRule {
    const char* record_type;
    bool reject_unknown;
    const char* const* required;
};

static const char* const kPayloadReq_IdentityGenesis[] = {
    "root_public_key_hex",
    "recovery_key_ids",
    "recovery_threshold",
    "recovery_delay_ms",
    "label",
    nullptr,
};

static const char* const kPayloadReq_IdentityTransition[] = {
    "root_id",
    "previous_transition",
    "previous_epoch",
    "new_epoch",
    "new_public_key_hex",
    "mode",
    "effective_after_ms",
    "recovery_policy_id",
    "new_key_proof_id",
    "proposal_nonce",
    "observed_authority_state_id",
    nullptr,
};

static const char* const kPayloadReq_CapabilityGrant[] = {
    "issuer_root",
    "subject_key_id",
    "subject_public_key_hex",
    "audience_ids",
    "parent_grant_id",
    "permissions",
    "limits",
    "not_before_ms",
    "not_after_ms",
    "remaining_delegation_depth",
    "revocation_epoch",
    "release_id",
    nullptr,
};

static const char* const kPayloadReq_Revocation[] = {
    "issuer_root",
    "revocation_epoch",
    "targets",
    "effective_after_ms",
    "reason_code",
    "prior_revocation_id",
    "quarantine_since_ms",
    nullptr,
};

static const char* const kPayloadReq_TransportBinding[] = {
    "root_id",
    "transport_spki_sha384",
    "service_key_id",
    "roles",
    "endpoint_hints",
    "key_epoch",
    "valid_until_ms",
    nullptr,
};

static const char* const kPayloadReq_SessionProof[] = {
    "local_nonce",
    "remote_nonce",
    "exporter_binding",
    "local_transport_binding",
    "remote_transport_binding",
    "requested_roles",
    "deadline_ms",
    nullptr,
};

static const char* const kPayloadReq_ProjectPolicy[] = {
    "project_id",
    "previous_policy_id",
    "epoch",
    "maintainer_keys",
    "threshold",
    "protected_refs",
    "admission_policy_id",
    "project_genesis_id",
    nullptr,
};

static const char* const kPayloadReq_GovernanceApproval[] = {
    "proposal_id",
    "policy_id",
    "decision",
    "decision_context",
    nullptr,
};

static const char* const kPayloadReq_ExternalBinding[] = {
    "root_id",
    "provider_kind",
    "issuer",
    "subject_commitment",
    "evidence_ref",
    "expires_ms",
    "assurance",
    nullptr,
};

static const char* const kPayloadReq_GitSnapshot[] = {
    "repository_id",
    "commit",
    "commit_raw_sha384",
    "snapshot_root",
    "file_index_root",
    "file_count",
    "total_bytes",
    "dependency_lock_id",
    "history_root",
    "history_complete",
    nullptr,
};

static const char* const kPayloadReq_FileIndexPage[] = {
    "page_index",
    "entries",
    "next_page_id",
    nullptr,
};

static const char* const kPayloadReq_GitRefUpdate[] = {
    "repository_id",
    "ref_name",
    "old_target",
    "new_target",
    "snapshot_id",
    "sequence",
    "previous_update_id",
    "policy_id",
    "force",
    nullptr,
};

static const char* const kPayloadReq_GitAttestation[] = {
    "snapshot_id",
    "repository_id",
    "commit",
    "source_root",
    "build_closure_id",
    "purpose",
    "builder_evidence_id",
    nullptr,
};

static const char* const kPayloadReq_ArtifactManifest[] = {
    "resource_kind",
    "file_index_root",
    "file_count",
    "total_bytes",
    "content_root",
    "format",
    "execution_class",
    "license_ref",
    "redistribution",
    "dependencies",
    nullptr,
};

static const char* const kPayloadReq_DependencyLock[] = {
    "dependencies",
    "closed",
    "closure_root",
    nullptr,
};

static const char* const kPayloadReq_SourcePointer[] = {
    "resource",
    "expected_bytes",
    "manifest_id",
    "origin_hints",
    "acquire_only",
    nullptr,
};

static const char* const kPayloadReq_WorkspaceCheckpoint[] = {
    "workspace_id",
    "base_snapshot_id",
    "generation",
    "tree_root",
    "operation_checkpoint_id",
    "conflicts",
    "state",
    "export_snapshot_id",
    nullptr,
};

static const char* const kPayloadReq_OperationEvent[] = {
    "workspace_id",
    "generation",
    "sequence",
    "parents",
    "kind",
    "before_root",
    "after_root",
    "detail_ref",
    "visibility",
    nullptr,
};

static const char* const kPayloadReq_JournalCheckpoint[] = {
    "stream_id",
    "first_sequence",
    "last_sequence",
    "entry_count",
    "merkle_root",
    "previous_checkpoint",
    "retention_until_ms",
    nullptr,
};

static const char* const kPayloadReq_WitnessReceipt[] = {
    "checkpoint_id",
    "witness_sequence",
    "previous_receipt_id",
    "observed_at_ms",
    "retained_until_ms",
    nullptr,
};

static const char* const kPayloadReq_ResearchInterest[] = {
    "topics",
    "objective_refs",
    "available_roles",
    "contact_binding_id",
    "expires_ms",
    nullptr,
};

static const char* const kPayloadReq_ActivityAnnouncement[] = {
    "objective_id",
    "base_contribution_ids",
    "intent",
    "expires_ms",
    "collaboration",
    "contact_binding_id",
    nullptr,
};

static const char* const kPayloadReq_CollaborationInvite[] = {
    "objective_id",
    "recipient_root",
    "context_refs",
    "message_ref",
    "reply_before_ms",
    nullptr,
};

static const char* const kPayloadReq_ResearchObjective[] = {
    "title",
    "description_ref",
    "evaluation_spec_id",
    "resource_constraints",
    "project_policy_id",
    "parent_objective_id",
    "economic_refs",
    nullptr,
};

static const char* const kPayloadReq_ResearchContribution[] = {
    "objective_id",
    "kind",
    "source_snapshot_id",
    "physical_parent_ids",
    "informed_by",
    "capsule_id",
    "claim_refs",
    "evidence_refs",
    "summary",
    nullptr,
};

static const char* const kPayloadReq_ResearchCapsule[] = {
    "objective_id",
    "source_snapshot_id",
    "dependency_lock_id",
    "recipe_id",
    "base_model_refs",
    "data_refs",
    "parent_capsules",
    "result_refs",
    "memory_ref",
    "phase",
    "input_capsule_id",
    nullptr,
};

static const char* const kPayloadReq_EvaluationSpec[] = {
    "task_ref",
    "development_data",
    "holdout_commitment",
    "metric_contracts",
    "execution_profile_id",
    "test_budget",
    "comparison_rule",
    "selection_correction_ref",
    nullptr,
};

static const char* const kPayloadReq_ExperimentResult[] = {
    "capsule_id",
    "evaluation_spec_id",
    "status",
    "metrics",
    "output_refs",
    "environment_id",
    "resource_counters",
    "start_ms",
    "end_ms",
    "runtime_receipt_ids",
    nullptr,
};

static const char* const kPayloadReq_EvidenceAttestation[] = {
    "subject_id",
    "claim_kind",
    "result",
    "evaluation_spec_id",
    "evidence_refs",
    "runtime_binding_id",
    "related_attestation_ids",
    "assurance",
    nullptr,
};

static const char* const kPayloadReq_ResearchMemory[] = {
    "subject_refs",
    "summary_ref",
    "evidence_refs",
    "supersedes",
    "claims_are_instructions",
    nullptr,
};

static const char* const kPayloadReq_DatasetSnapshot[] = {
    "manifest_id",
    "tokenizer_ref",
    "source_rights_ref",
    "transformation_recipe_id",
    "parent_data_ids",
    "sensitivity",
    "permitted_uses",
    "data_order_commitment",
    nullptr,
};

static const char* const kPayloadReq_TrainingProfile[] = {
    "semantic_id",
    "source_snapshot_id",
    "environment_ref",
    "algorithm_description_ref",
    "state_schema_ref",
    "operator_conformance_root",
    "deterministic",
    "supported_backends",
    "test_only",
    nullptr,
};

static const char* const kPayloadReq_TrainingRecipe[] = {
    "profile_id",
    "base_model_ref",
    "initialization_commitment",
    "dataset_ids",
    "tokenizer_ref",
    "hyperparameters_ref",
    "rng_description_ref",
    "step_count",
    "output_format",
    "dependency_lock_id",
    nullptr,
};

static const char* const kPayloadReq_TrainingTrajectory[] = {
    "recipe_id",
    "profile_id",
    "initial_state",
    "final_state",
    "total_steps",
    "trajectory_index_root",
    "checkpoint_manifest_id",
    "final_model_ref",
    "complete_state_commitment",
    nullptr,
};

static const char* const kPayloadReq_ReplayAttestation[] = {
    "trajectory_id",
    "profile_id",
    "interval",
    "observed_final_model",
    "result",
    "evidence_ref",
    "runtime_binding_id",
    "independence_evidence_ids",
    nullptr,
};

static const char* const kPayloadReq_AdmissionPolicy[] = {
    "policy_epoch",
    "previous_policy_id",
    "mode",
    "minimum_independent_roots",
    "accepted_verifier_keys",
    "full_replay_required",
    "required_evaluation_ids",
    "accepted_profile_ids",
    "maximum_evidence_age_ms",
    "redistribution_required",
    "allow_delegated_observation",
    "minimum_coverage_per_transition",
    "independence_policy_id",
    "bootstrap_policy_id",
    nullptr,
};

static const char* const kPayloadReq_AdmissionDecision[] = {
    "model_ref",
    "policy_id",
    "evidence_root",
    "trajectory_ids",
    "state",
    "verification_mode",
    "attestation_ids",
    "reason_codes",
    "valid_until_ms",
    nullptr,
};

static const char* const kPayloadReq_AgentRelease[] = {
    "source_snapshot_id",
    "model_refs",
    "tool_refs",
    "memory_ids",
    "environment_ref",
    "predecessors",
    "evaluation_ids",
    "requested_permissions",
    "delegation_inheritance",
    nullptr,
};

static const char* const kPayloadReq_AdoptionReceipt[] = {
    "previous_release_id",
    "new_release_id",
    "authority_decision_id",
    "runtime_binding_id",
    "local_generation",
    "state",
    "observed_checks",
    nullptr,
};

static const char* const kPayloadReq_RuntimeBinding[] = {
    "release_id",
    "runtime_key_id",
    "runtime_public_key_hex",
    "supervisor_key_id",
    "session_nonce",
    "environment_ref",
    "assurance",
    "attestation_ref",
    "grant_ids",
    "expires_ms",
    "local_capability_grant_id",
    "capability_generation",
    "grant_intersection_root",
    nullptr,
};

static const char* const kPayloadReq_ActionIntent[] = {
    "runtime_binding_id",
    "action",
    "resource_id",
    "parameters_ref",
    "expected_state",
    "grant_id",
    "request_nonce",
    "deadline_ms",
    nullptr,
};

static const char* const kPayloadReq_ActionDecision[] = {
    "intent_id",
    "grant_id",
    "policy_id",
    "revocation_epoch",
    "decision",
    "reason_codes",
    "permit_expires_ms",
    "permit_commitment",
    nullptr,
};

static const char* const kPayloadReq_ActionReceipt[] = {
    "intent_id",
    "decision_id",
    "executor_id",
    "before_state",
    "after_state",
    "result_refs",
    "outcome",
    "physical_state",
    "sequence",
    "previous_receipt_id",
    nullptr,
};

static const char* const kPayloadReq_IncidentDisclosure[] = {
    "affected_refs",
    "affected_keys",
    "severity",
    "confidence",
    "evidence_refs",
    "failed_control_ids",
    "disclosure",
    "mitigation_ref",
    nullptr,
};

static const char* const kPayloadReq_MitigationAttestation[] = {
    "incident_id",
    "action_receipt_ids",
    "replacement_refs",
    "policy_id",
    "remaining_risks_ref",
    "result",
    nullptr,
};

static const char* const kPayloadReq_RealmPolicy[] = {
    "realm_id",
    "name",
    "epoch",
    "previous_policy_id",
    "authority_keys",
    "threshold",
    "public_connectivity",
    "outbound_publication",
    "admission_policy_id",
    "trusted_attestor_keys",
    "attestor_threshold",
    "revocation_freshness_ms",
    "realm_genesis_id",
    nullptr,
};

static const char* const kPayloadReq_PromotionManifest[] = {
    "source_realm_id",
    "destination_realm_id",
    "resources",
    "closure_root",
    "destination_policy_id",
    "public_admission_ids",
    "confidentiality_review_ref",
    "proposal_nonce",
    "expires_ms",
    "source_export_authorization_id",
    "foreign_evidence_link_ids",
    nullptr,
};

static const char* const kPayloadReq_ModelTrustAttestation[] = {
    "promotion_id",
    "destination_realm_id",
    "policy_id",
    "closure_root",
    "resource_decisions",
    "checks_ref",
    "attestor_set_epoch",
    "valid_until_ms",
    "scope",
    nullptr,
};

static const char* const kPayloadReq_ChannelUpdate[] = {
    "realm_id",
    "channel",
    "epoch",
    "sequence",
    "previous_update_id",
    "promotion_id",
    "trust_attestation_ids",
    "desired_closure_root",
    "policy_id",
    "valid_until_ms",
    "rollback_of",
    "conflict_resolution_id",
    nullptr,
};

static const char* const kPayloadReq_RolloutPlan[] = {
    "channel_update_id",
    "fleet_policy_id",
    "rings",
    "activation",
    "deadline_ms",
    "rollback_update_id",
    "bandwidth_limit_bytes_s",
    nullptr,
};

static const char* const kPayloadReq_DeploymentReceipt[] = {
    "rollout_id",
    "channel_update_id",
    "device_id",
    "ring_id",
    "state",
    "observed_closure_root",
    "local_generation",
    "health_evidence_id",
    "last_observed_ms",
    "observation_epoch",
    "receipt_sequence",
    "previous_receipt_id",
    "controller_pause_epoch",
    "activation_authorization_id",
    "observer_key_id",
    nullptr,
};

static const char* const kPayloadReq_FleetPolicy[] = {
    "realm_id",
    "policy_epoch",
    "device_keys",
    "admission_policy_id",
    "maximum_offline_ms",
    "stale_behavior",
    "rollout_authority_keys",
    "threshold",
    "health_spec_id",
    nullptr,
};

static const char* const kPayloadReq_ExportBundle[] = {
    "origin_realm_id",
    "destination_realm_id",
    "entry_refs",
    "record_ids",
    "closure_root",
    "identity_state_root",
    "minimum_policy_epoch",
    "expiry_ms",
    "bundle_nonce",
    "physical_manifest_root",
    nullptr,
};

static const char* const kPayloadReq_EncryptedResource[] = {
    "realm_id",
    "key_epoch",
    "plaintext_manifest_id",
    "plaintext_size",
    "ciphertext_manifest_id",
    "aead",
    "chunk_size",
    "nonce_prefix_hex",
    "encryption_attempt_nonce",
    nullptr,
};

static const char* const kPayloadReq_KeyDelivery[] = {
    "realm_id",
    "recipient_key_id",
    "recipient_kem_public_key_hex",
    "kem_ciphertext_hex",
    "key_epoch",
    "wrap_nonce_hex",
    "wrapped_key_hex",
    "valid_until_ms",
    "recipient_binding_id",
    "encrypted_resource_id",
    nullptr,
};

static const char* const kPayloadReq_PeerAnnouncement[] = {
    "binding_id",
    "topics",
    "record_ids",
    "hop_budget",
    "expiry_ms",
    "announcement_nonce",
    nullptr,
};

static const char* const kPayloadReq_BuildManifest[] = {
    "source_snapshot_id",
    "environment_id",
    "dependency_lock_id",
    "build_recipe_id",
    "outputs",
    "builder_runtime_id",
    "reproducibility",
    "test_evidence_ids",
    nullptr,
};

static const char* const kPayloadReq_RecoveryPolicy[] = {
    "root_id",
    "previous_policy_id",
    "epoch",
    "recovery_key_ids",
    "threshold",
    "delay_ms",
    nullptr,
};

static const char* const kPayloadReq_ApprovalSet[] = {
    "proposal_id",
    "policy_id",
    "approval_ids",
    nullptr,
};

static const char* const kPayloadReq_RepositoryGenesis[] = {
    "repository_id",
    "founder_key_id",
    "nonce",
    "object_format",
    "project_genesis_id",
    "default_ref",
    "display_name",
    nullptr,
};

static const char* const kPayloadReq_RepositoryOriginUpdate[] = {
    "repository_genesis_id",
    "sequence",
    "previous_update_id",
    "origins",
    "project_policy_id",
    nullptr,
};

static const char* const kPayloadReq_ProjectGenesis[] = {
    "project_id",
    "founder_key_id",
    "nonce",
    "label",
    nullptr,
};

static const char* const kPayloadReq_RealmGenesis[] = {
    "realm_id",
    "founder_key_id",
    "nonce",
    "label",
    nullptr,
};

static const char* const kPayloadReq_IdentityState[] = {
    "root_id",
    "key_epoch",
    "transition_id",
    "revocation_epoch",
    "revocation_head_id",
    "policy_id",
    "sequence",
    "previous_state_id",
    "issued_ms",
    "valid_until_ms",
    "challenge_nonce",
    nullptr,
};

static const char* const kPayloadReq_NewKeyProof[] = {
    "root_id",
    "previous_epoch",
    "new_epoch",
    "new_public_key_hex",
    "mode",
    "proposal_nonce",
    "recovery_policy_id",
    nullptr,
};

static const char* const kPayloadReq_TransitionObservation[] = {
    "transition_id",
    "identity_state_id",
    "observer_key_id",
    "observation_sequence",
    "observed_ms",
    "clock_error_ms",
    "previous_observation_id",
    nullptr,
};

static const char* const kPayloadReq_EncryptionKeyBinding[] = {
    "recipient_root_id",
    "recipient_key_id",
    "kem_public_key_hex",
    "purpose",
    "key_epoch",
    "valid_until_ms",
    "revocation_authority_id",
    nullptr,
};

static const char* const kPayloadReq_SourceExportAuthorization[] = {
    "source_realm_id",
    "destination_realm_id",
    "closure_root",
    "export_nonce",
    "permitted_record_ids",
    "valid_until_ms",
    "policy_id",
    nullptr,
};

static const char* const kPayloadReq_ForeignEvidenceLink[] = {
    "source_realm_id",
    "destination_realm_id",
    "original_record_id",
    "source_identity_state_id",
    "export_authorization_id",
    "destination_policy_id",
    "use",
    nullptr,
};

static const char* const kPayloadReq_GitUpdateBatch[] = {
    "repository_genesis_id",
    "push_session_nonce",
    "audience_binding_id",
    "updates",
    "grant_id",
    "project_policy_id",
    "atomic",
    "expires_ms",
    nullptr,
};

static const char* const kPayloadReq_ChannelResolution[] = {
    "realm_id",
    "channel",
    "conflicting_head_ids",
    "previous_policy_id",
    "new_epoch",
    "selected_closure_root",
    "proposal_nonce",
    nullptr,
};

static const char* const kPayloadReq_ComparisonResult[] = {
    "evaluation_spec_id",
    "baseline_ref",
    "candidate_ref",
    "baseline_result_ids",
    "candidate_result_ids",
    "procedure",
    "metric_name",
    "direction",
    "wins",
    "losses",
    "ties",
    "selection_trial_count",
    "alpha_numerator",
    "alpha_denominator",
    "holdout_epoch",
    "result",
    "negative_result_ids",
    "evaluation_access_policy_id",
    nullptr,
};

static const char* const kPayloadReq_EvaluationAccessPolicy[] = {
    "evaluation_spec_id",
    "holdout_epoch",
    "holdout_manifest_commitment",
    "authorized_evaluator_roots",
    "maximum_comparisons",
    "refresh_after_ms",
    "disclosure",
    nullptr,
};

static const char* const kPayloadReq_DeviceObservationGenesis[] = {
    "device_id",
    "realm_id",
    "observation_epoch",
    "previous_observation_head",
    "device_runtime_key_id",
    "fleet_policy_id",
    "recovery_anchor_id",
    nullptr,
};

static const V11PayloadRule kV11PayloadRules[] = {
    {"IdentityGenesis", true, kPayloadReq_IdentityGenesis},
    {"IdentityTransition", true, kPayloadReq_IdentityTransition},
    {"CapabilityGrant", true, kPayloadReq_CapabilityGrant},
    {"Revocation", true, kPayloadReq_Revocation},
    {"TransportBinding", true, kPayloadReq_TransportBinding},
    {"SessionProof", true, kPayloadReq_SessionProof},
    {"ProjectPolicy", true, kPayloadReq_ProjectPolicy},
    {"GovernanceApproval", true, kPayloadReq_GovernanceApproval},
    {"ExternalBinding", true, kPayloadReq_ExternalBinding},
    {"GitSnapshot", true, kPayloadReq_GitSnapshot},
    {"FileIndexPage", true, kPayloadReq_FileIndexPage},
    {"GitRefUpdate", true, kPayloadReq_GitRefUpdate},
    {"GitAttestation", true, kPayloadReq_GitAttestation},
    {"ArtifactManifest", true, kPayloadReq_ArtifactManifest},
    {"DependencyLock", true, kPayloadReq_DependencyLock},
    {"SourcePointer", true, kPayloadReq_SourcePointer},
    {"WorkspaceCheckpoint", true, kPayloadReq_WorkspaceCheckpoint},
    {"OperationEvent", true, kPayloadReq_OperationEvent},
    {"JournalCheckpoint", true, kPayloadReq_JournalCheckpoint},
    {"WitnessReceipt", true, kPayloadReq_WitnessReceipt},
    {"ResearchInterest", true, kPayloadReq_ResearchInterest},
    {"ActivityAnnouncement", true, kPayloadReq_ActivityAnnouncement},
    {"CollaborationInvite", true, kPayloadReq_CollaborationInvite},
    {"ResearchObjective", true, kPayloadReq_ResearchObjective},
    {"ResearchContribution", true, kPayloadReq_ResearchContribution},
    {"ResearchCapsule", true, kPayloadReq_ResearchCapsule},
    {"EvaluationSpec", true, kPayloadReq_EvaluationSpec},
    {"ExperimentResult", true, kPayloadReq_ExperimentResult},
    {"EvidenceAttestation", true, kPayloadReq_EvidenceAttestation},
    {"ResearchMemory", true, kPayloadReq_ResearchMemory},
    {"DatasetSnapshot", true, kPayloadReq_DatasetSnapshot},
    {"TrainingProfile", true, kPayloadReq_TrainingProfile},
    {"TrainingRecipe", true, kPayloadReq_TrainingRecipe},
    {"TrainingTrajectory", true, kPayloadReq_TrainingTrajectory},
    {"ReplayAttestation", true, kPayloadReq_ReplayAttestation},
    {"AdmissionPolicy", true, kPayloadReq_AdmissionPolicy},
    {"AdmissionDecision", true, kPayloadReq_AdmissionDecision},
    {"AgentRelease", true, kPayloadReq_AgentRelease},
    {"AdoptionReceipt", true, kPayloadReq_AdoptionReceipt},
    {"RuntimeBinding", true, kPayloadReq_RuntimeBinding},
    {"ActionIntent", true, kPayloadReq_ActionIntent},
    {"ActionDecision", true, kPayloadReq_ActionDecision},
    {"ActionReceipt", true, kPayloadReq_ActionReceipt},
    {"IncidentDisclosure", true, kPayloadReq_IncidentDisclosure},
    {"MitigationAttestation", true, kPayloadReq_MitigationAttestation},
    {"RealmPolicy", true, kPayloadReq_RealmPolicy},
    {"PromotionManifest", true, kPayloadReq_PromotionManifest},
    {"ModelTrustAttestation", true, kPayloadReq_ModelTrustAttestation},
    {"ChannelUpdate", true, kPayloadReq_ChannelUpdate},
    {"RolloutPlan", true, kPayloadReq_RolloutPlan},
    {"DeploymentReceipt", true, kPayloadReq_DeploymentReceipt},
    {"FleetPolicy", true, kPayloadReq_FleetPolicy},
    {"ExportBundle", true, kPayloadReq_ExportBundle},
    {"EncryptedResource", true, kPayloadReq_EncryptedResource},
    {"KeyDelivery", true, kPayloadReq_KeyDelivery},
    {"PeerAnnouncement", true, kPayloadReq_PeerAnnouncement},
    {"BuildManifest", true, kPayloadReq_BuildManifest},
    {"RecoveryPolicy", true, kPayloadReq_RecoveryPolicy},
    {"ApprovalSet", true, kPayloadReq_ApprovalSet},
    {"RepositoryGenesis", true, kPayloadReq_RepositoryGenesis},
    {"RepositoryOriginUpdate", true, kPayloadReq_RepositoryOriginUpdate},
    {"ProjectGenesis", true, kPayloadReq_ProjectGenesis},
    {"RealmGenesis", true, kPayloadReq_RealmGenesis},
    {"IdentityState", true, kPayloadReq_IdentityState},
    {"NewKeyProof", true, kPayloadReq_NewKeyProof},
    {"TransitionObservation", true, kPayloadReq_TransitionObservation},
    {"EncryptionKeyBinding", true, kPayloadReq_EncryptionKeyBinding},
    {"SourceExportAuthorization", true, kPayloadReq_SourceExportAuthorization},
    {"ForeignEvidenceLink", true, kPayloadReq_ForeignEvidenceLink},
    {"GitUpdateBatch", true, kPayloadReq_GitUpdateBatch},
    {"ChannelResolution", true, kPayloadReq_ChannelResolution},
    {"ComparisonResult", true, kPayloadReq_ComparisonResult},
    {"EvaluationAccessPolicy", true, kPayloadReq_EvaluationAccessPolicy},
    {"DeviceObservationGenesis", true, kPayloadReq_DeviceObservationGenesis},
};
