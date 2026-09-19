// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// BTX-HCP-001 frozen HCP/1 object types, effects, finance actions, and
// authority boundaries. HostedAccountPolicy is never LocalCapabilityGrant.

#ifndef BITCOIN_MODELNET_HCP_TYPES_H
#define BITCOIN_MODELNET_HCP_TYPES_H

#include <cstdint>
#include <cstddef>
#include <string_view>

namespace modelnet {

inline constexpr const char* HCP_SPEC_ID = "BTX-HCP-001";
inline constexpr const char* HCP_PROTOCOL = "HCP/1";
inline constexpr const char* HCP_DOMAIN_PREFIX = "BTX/HCP/";
inline constexpr const char* HCP_DOMAIN_SUFFIX = "/v1";
inline constexpr int64_t HCP_AUTOMATIC_SPEND_ATOMS = 0;
inline constexpr int64_t HCP_MAX_BODY_BYTES = 1048576;
inline constexpr int64_t HCP_CR12_MAX_STAGE_BYTES = 16 * 1024 * 1024;
inline constexpr int HCP_MAX_PAGE = 100;
inline constexpr int HCP_MAX_SOURCE_HINTS = 16;
inline constexpr int HCP_MAX_EFFECTS = 16;
inline constexpr int64_t HCP_DEFAULT_CLOCK_MS = 1790000000000LL;

inline constexpr const char* HCP_TYPE_PROVIDER_PROFILE = "ProviderProfile";
inline constexpr const char* HCP_TYPE_CAPABILITY_OFFER = "CapabilityOffer";
inline constexpr const char* HCP_TYPE_FUNDING_QUOTE = "FundingQuote";
inline constexpr const char* HCP_TYPE_FINANCE_INTENT = "FinanceIntent";
inline constexpr const char* HCP_TYPE_FINANCIAL_RECEIPT = "FinancialReceipt";
inline constexpr const char* HCP_TYPE_CAPABILITY_HANDOFF = "CapabilityHandoff";
inline constexpr const char* HCP_TYPE_LOCAL_READINESS = "LocalReadinessReport";

// Cognitive Reserve v1.1 negotiated extension (exact reviewed names; underscores
// are not a general relaxation of the object-type charset).
inline constexpr const char* HCP_TYPE_RESERVE_EXTENSION = "ReserveExtensionProfileV1_1";
inline constexpr const char* HCP_TYPE_ENTITY_LINK = "EntityLinkV1_1";
inline constexpr const char* HCP_TYPE_PORTFOLIO = "PortfolioV1_1";
inline constexpr const char* HCP_TYPE_RESERVE_POLICY = "ReservePolicyV1_1";
inline constexpr const char* HCP_TYPE_RESERVE_SNAPSHOT = "ReserveSnapshotV1_1";
inline constexpr const char* HCP_TYPE_WORKLOAD = "WorkloadProfileV1_1";
inline constexpr const char* HCP_TYPE_TCO = "TCOComparisonV1_1";
inline constexpr const char* HCP_TYPE_CAPITAL_PLAN = "CapitalPlanV1_1";
inline constexpr const char* HCP_TYPE_ALLOCATION = "AllocationPlanV1_1";
inline constexpr const char* HCP_TYPE_APPROVAL_RULE = "ApprovalRuleV1_1";
inline constexpr const char* HCP_TYPE_APPROVAL_REQUEST = "ApprovalRequestV1_1";
inline constexpr const char* HCP_TYPE_APPROVAL_DECISION = "ApprovalDecisionV1_1";
inline constexpr const char* HCP_TYPE_CAPABILITY_POSITION = "CapabilityPositionV1_1";
inline constexpr const char* HCP_TYPE_RESEARCH_PROGRAM = "ResearchProgramV1_1";
inline constexpr const char* HCP_TYPE_PROGRAM_MEMBERSHIP = "ProgramMembershipV1_1";
inline constexpr const char* HCP_TYPE_PRODUCT_OFFER = "ProductOfferV1_1";
inline constexpr const char* HCP_TYPE_CAPITAL_EXECUTION = "CapitalExecutionReceiptV1_1";
inline constexpr const char* HCP_TYPE_RESERVE_REPORT = "ReserveReportV1_1";

// Cognitive Reserve Layer v1.2 negotiated extension (exact reviewed names).
inline constexpr const char* HCP_TYPE_LAYER_EXTENSION = "LayerExtensionProfileV1_2";
inline constexpr const char* HCP_TYPE_PROVIDER_ROLE = "ProviderRoleManifestV1_2";
inline constexpr const char* HCP_TYPE_SERVICE_BINDING = "ServiceBindingV1_2";
inline constexpr const char* HCP_TYPE_ADAPTER_CAPABILITY = "AdapterCapabilityReportV1_2";
inline constexpr const char* HCP_TYPE_INSTITUTIONAL_ASSET = "InstitutionalAssetV1_2";
inline constexpr const char* HCP_TYPE_ASSET_RIGHTS = "AssetRightsV1_2";
inline constexpr const char* HCP_TYPE_POSITION_OBS = "PositionObservationV1_2";
inline constexpr const char* HCP_TYPE_VALUATION_OBS = "ValuationObservationV1_2";
inline constexpr const char* HCP_TYPE_EXPOSURE_LINK = "ExposureLinkV1_2";
inline constexpr const char* HCP_TYPE_PORTFOLIO_PROJECTION = "PortfolioProjectionV1_2";
inline constexpr const char* HCP_TYPE_METRIC_DEFINITION = "MetricDefinitionV1_2";
inline constexpr const char* HCP_TYPE_EXPORT_MANIFEST = "ExportManifestV1_2";
inline constexpr const char* HCP_TYPE_IMPORT_MANIFEST = "ImportManifestV1_2";
inline constexpr const char* HCP_TYPE_RECONCILIATION_BREAK = "ReconciliationBreakV1_2";
inline constexpr const char* HCP_TYPE_PORTFOLIO_INSTRUCTION = "PortfolioInstructionV1_2";
inline constexpr const char* HCP_TYPE_SCENARIO_RESULT = "InstitutionalScenarioResultV1_2";
inline constexpr const char* HCP_TYPE_LAYER_CONFORMANCE = "LayerConformanceClaimV1_2";
inline constexpr const char* HCP_TYPE_LAYER_JOB = "LayerJobV1_2";
// Package TYPE_CONTRACTS.md names accepted for inbound verify (same 18 types).
inline constexpr const char* HCP_TYPE_ADAPTER_CAPABILITY_MANIFEST = "AdapterCapabilityManifestV1_2";
inline constexpr const char* HCP_TYPE_INSTITUTIONAL_ASSET_RECORD = "InstitutionalAssetRecordV1_2";
inline constexpr const char* HCP_TYPE_RIGHTS_STATEMENT = "RightsStatementV1_2";
inline constexpr const char* HCP_TYPE_INTEROP_RECEIPT = "InteroperabilityReceiptV1_2";
inline constexpr const char* HCP_TYPE_SCENARIO_DEFINITION = "ScenarioDefinitionV1_2";
inline constexpr const char* HCP_TYPE_SCENARIO_RESULT_SPEC = "ScenarioResultV1_2";
inline constexpr const char* HCP_TYPE_CONFORMANCE_STATEMENT = "ConformanceStatementV1_2";

inline constexpr const char* HCP_EXT_COGNITIVE_RESERVE = "cognitive-reserve";
inline constexpr const char* HCP_EXT_COGNITIVE_RESERVE_V12 = "cognitive-reserve/v1.2";
inline constexpr int HCP_CR11_MAX_LEGS = 32;
inline constexpr int HCP_CR11_MAX_DEPTH = 16;
inline constexpr int HCP_CR12_MAX_LOOKTHROUGH_DEPTH = 16;
inline constexpr int HCP_CR12_MAX_GRAPH_EDGES = 4096;

inline constexpr const char* HCP_PROFILE_DISCOVERY = "DISCOVERY";
inline constexpr const char* HCP_PROFILE_HANDOFF = "HANDOFF";
inline constexpr const char* HCP_PROFILE_CUSTODY = "CUSTODY";
inline constexpr const char* HCP_PROFILE_FUNDING = "FUNDING";
inline constexpr const char* HCP_PROFILE_FLEET = "FLEET";

inline constexpr const char* HCP_ACTION_FUND_RELEASE = "FUND_RELEASE";
inline constexpr const char* HCP_ACTION_FUND_BOUNTY = "FUND_BOUNTY";
inline constexpr const char* HCP_ACTION_CLAIM = "CLAIM";
inline constexpr const char* HCP_ACTION_REFUND = "REFUND";

inline constexpr const char* HCP_EFFECT_INSPECT = "INSPECT";
inline constexpr const char* HCP_EFFECT_FETCH_METADATA = "FETCH_METADATA";
inline constexpr const char* HCP_EFFECT_ACQUIRE_MODEL = "ACQUIRE_MODEL";
inline constexpr const char* HCP_EFFECT_SEED_MODEL = "SEED_MODEL";
inline constexpr const char* HCP_EFFECT_INSTALL_CLIENT = "INSTALL_CLIENT";
inline constexpr const char* HCP_EFFECT_PLAN_LOCAL_RUN = "PLAN_LOCAL_RUN";
inline constexpr const char* HCP_EFFECT_EXECUTE_LOCAL_RUN = "EXECUTE_LOCAL_RUN";
inline constexpr const char* HCP_EFFECT_REPORT_READINESS = "REPORT_READINESS";

inline constexpr const char* HCP_CUSTODY_DISABLED = "DISABLED";
inline constexpr const char* HCP_CUSTODY_BTX_NATIVE = "BTX_NATIVE_TEMPLATES";
inline constexpr const char* HCP_CUSTODY_EVM_GENERIC = "EVM_GENERIC";

inline constexpr const char* HCP_ERR_BODY_ID_MISMATCH = "BODY_ID_MISMATCH";
inline constexpr const char* HCP_ERR_DOMAIN_MISMATCH = "BODY_DOMAIN_MISMATCH";
inline constexpr const char* HCP_ERR_LOCAL_GRANT_REQUIRED = "LOCAL_GRANT_REQUIRED";
inline constexpr const char* HCP_ERR_PACKAGE_MISMATCH = "PACKAGE_MISMATCH";
inline constexpr const char* HCP_ERR_QUOTE_EXPIRED = "QUOTE_EXPIRED";
inline constexpr const char* HCP_ERR_TERMS_CHANGED = "TERMS_CHANGED";
inline constexpr const char* HCP_ERR_BROADCAST_UNKNOWN = "BROADCAST_UNKNOWN";
inline constexpr const char* HCP_ERR_CUSTODY_UNSUPPORTED = "CUSTODY_UNSUPPORTED";
inline constexpr const char* HCP_ERR_FUNDING_DISABLED = "FUNDING_DISABLED";
inline constexpr const char* HCP_ERR_GENERIC_RPC = "GENERIC_RPC_DISABLED";
inline constexpr const char* HCP_ERR_CURSOR_TOO_OLD = "CURSOR_TOO_OLD";
inline constexpr const char* HCP_ERR_AUDIENCE = "AUDIENCE_MISMATCH";
inline constexpr const char* HCP_ERR_SCOPE = "SCOPE_DENIED";
inline constexpr const char* HCP_ERR_DPOP = "DPOP_BINDING";
inline constexpr const char* HCP_ERR_SOFTWARE_TRUST = "SOFTWARE_TRUST_REQUIRED";
inline constexpr const char* HCP_ERR_NATIVE_VERIFIER = "NATIVE_VERIFIER_UNAVAILABLE";
inline constexpr const char* HCP_ERR_DEADLINE = "DEADLINE_UNACHIEVABLE";
inline constexpr const char* HCP_ERR_VERSION = "HCP_VERSION_UNSUPPORTED";
inline constexpr const char* HCP_ERR_PROVIDER_UNENROLLED = "PROVIDER_NOT_ENROLLED";
inline constexpr const char* HCP_ERR_HANDOFF_BINDING = "HANDOFF_BINDING";
inline constexpr const char* HCP_ERR_ATOM_ENCODING = "ATOM_ENCODING";
inline constexpr const char* HCP_ERR_CONFLICT = "IDEMPOTENCY_CONFLICT";
inline constexpr const char* HCP_ERR_FENCED = "REPLICA_NOT_OWNER";
inline constexpr const char* HCP_ERR_REMOTE_INFERENCE = "REMOTE_INFERENCE_FORBIDDEN";
inline constexpr const char* HCP_ERR_POLICY_FINANCE = "HOSTED_POLICY_NOT_LOCAL_GRANT";
inline constexpr const char* HCP_ERR_GRANT_NOT_SPEND = "LOCAL_GRANT_NOT_SPEND";
inline constexpr const char* HCP_ERR_PROFILE_UNSUPPORTED = "PROFILE_UNSUPPORTED";
inline constexpr const char* HCP_ERR_CAPACITY = "CAPACITY_EXCEEDED";
inline constexpr const char* HCP_ERR_PRICE_STALE = "PRICE_STALE";
inline constexpr const char* HCP_ERR_GRAPH_CYCLE = "GRAPH_CYCLE";
inline constexpr const char* HCP_ERR_GRAPH_LIMIT = "GRAPH_LIMIT";
inline constexpr const char* HCP_ERR_GRAPH_DEPTH = "GRAPH_DEPTH";
inline constexpr const char* HCP_ERR_QUALITY = "QUALITY_UNPROVEN";
inline constexpr const char* HCP_ERR_INPUT_UNKNOWN = "INPUT_UNKNOWN";
inline constexpr const char* HCP_ERR_HORIZON = "INVALID_HORIZON";
inline constexpr const char* HCP_ERR_ENTITY_SCOPE = "ENTITY_SCOPE_DENIED";
inline constexpr const char* HCP_ERR_FAMILY_VIEW = "FAMILY_VIEW_NOT_DEBIT";
inline constexpr const char* HCP_ERR_QUORUM = "QUORUM_UNMET";
inline constexpr const char* HCP_ERR_BINDING = "BINDING_MISMATCH";
inline constexpr const char* HCP_ERR_CROSS_CEX = "CROSS_CEX_DUPLICATE";
inline constexpr const char* HCP_ERR_NO_REPLENISH = "REFUND_NO_REPLENISH";
inline constexpr const char* HCP_ERR_EXACT_DECIMAL = "USE_EXACT_DECIMAL";
inline constexpr const char* HCP_ERR_CORE_V4 = "CORE_V4_FORBIDDEN";
inline constexpr const char* HCP_ERR_SOFT_BUDGET = "SOFT_BUDGET_NOT_MONEY";
inline constexpr const char* HCP_ERR_ZERO_RESERVE = "ZERO_RESERVATION";
inline constexpr const char* HCP_ERR_NAV_MERGE = "NAV_MERGE_FORBIDDEN";
inline constexpr const char* HCP_ERR_ROLE_EFFECT = "ROLE_EFFECT_MISMATCH";
inline constexpr const char* HCP_ERR_ROLE_UNAVAILABLE = "ROLE_UNAVAILABLE";
inline constexpr const char* HCP_ERR_IDENTIFIER_COLLISION = "IDENTIFIER_COLLISION";
inline constexpr const char* HCP_ERR_STALE_SOURCE = "STALE_SOURCE";
inline constexpr const char* HCP_ERR_PRICE_MISSING = "PRICE_MISSING";
inline constexpr const char* HCP_ERR_MANDATE_REQUIRED = "MANDATE_REQUIRED";
inline constexpr const char* HCP_ERR_LOOKTHROUGH = "LOOKTHROUGH_DOUBLE_COUNT";
inline constexpr const char* HCP_ERR_INSTRUCTION_NOT_EXECUTE = "INSTRUCTION_NOT_EXECUTE";
inline constexpr const char* HCP_ERR_JOB_COMMITTED = "JOB_ALREADY_COMMITTED";
inline constexpr const char* HCP_ERR_CHUNK_DIGEST = "CHUNK_DIGEST";
inline constexpr const char* HCP_ERR_CHUNK_NOT_OWNED = "CHUNK_NOT_OWNED";
inline constexpr const char* HCP_ERR_BRAND_DISPATCH = "BRAND_DISPATCH";
inline constexpr const char* HCP_ERR_NETWORK_MISMATCH = "NETWORK_MISMATCH";
inline constexpr const char* HCP_ERR_ADAPTER_DISABLED = "ADAPTER_DISABLED";
inline constexpr const char* HCP_ERR_OBSERVATION_CONFLICT = "OBSERVATION_CONFLICT";
inline constexpr const char* HCP_ERR_CURSOR_MISMATCH = "CURSOR_MISMATCH";
inline constexpr const char* HCP_ERR_WEIGHT_OVERFLOW = "WEIGHT_OVERFLOW";
inline constexpr const char* HCP_ERR_NONFINITE = "NONFINITE_INPUT";
inline constexpr const char* HCP_ERR_MAPPING_CAS = "MAPPING_CAS";
inline constexpr const char* HCP_ERR_ISSUER_UNACCEPTED = "ISSUER_UNACCEPTED";
inline constexpr const char* HCP_ERR_TRANSFER_RESTRICTED = "TRANSFER_RESTRICTED";
inline constexpr const char* HCP_ERR_BINDING_REVOKED = "BINDING_REVOKED";
inline constexpr const char* HCP_ERR_SOURCE_NOT_AUTHORIZED = "SOURCE_NOT_AUTHORIZED";
inline constexpr const char* HCP_ERR_LOOKTHROUGH_CYCLE = "LOOKTHROUGH_CYCLE";
inline constexpr const char* HCP_ERR_MAPPING_MISMATCH = "MAPPING_MISMATCH";
inline constexpr const char* HCP_ERR_CHUNK_MISMATCH = "CHUNK_MISMATCH";
inline constexpr const char* HCP_ERR_IMPORT_NOT_VALIDATED = "IMPORT_NOT_VALIDATED";
inline constexpr const char* HCP_ERR_STALE_PROJECTION = "STALE_PROJECTION";
inline constexpr const char* HCP_ERR_DRAFT_ONLY = "DRAFT_ONLY";
inline constexpr const char* HCP_ERR_JOB_PENDING = "JOB_PENDING";

inline bool HcpIsFinanceAction(std::string_view a)
{
    return a == HCP_ACTION_FUND_RELEASE || a == HCP_ACTION_FUND_BOUNTY || a == HCP_ACTION_CLAIM ||
           a == HCP_ACTION_REFUND;
}

inline bool HcpIsLocalEffect(std::string_view e)
{
    return e == HCP_EFFECT_INSPECT || e == HCP_EFFECT_FETCH_METADATA || e == HCP_EFFECT_ACQUIRE_MODEL ||
           e == HCP_EFFECT_SEED_MODEL || e == HCP_EFFECT_INSTALL_CLIENT || e == HCP_EFFECT_PLAN_LOCAL_RUN ||
           e == HCP_EFFECT_EXECUTE_LOCAL_RUN || e == HCP_EFFECT_REPORT_READINESS;
}

} // namespace modelnet

#endif // BITCOIN_MODELNET_HCP_TYPES_H
