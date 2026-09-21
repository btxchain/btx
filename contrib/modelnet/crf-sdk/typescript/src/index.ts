// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
/** Typed HCP Cognitive Reserve client. Additive HCP/1 extension (50 ops).
 *  No financial retry, signing or local execution. HTTP 202 is UNKNOWN.
 *  automatic_spend_atoms stays 0. No /rpc passthrough. */

export {
  bodyId,
  body_id,
  canonicalBody,
  canonical_body,
  OBJECT_TYPES,
} from "./body_id.ts";
export type { JsonValue, ObjectTypeV1_1 } from "./body_id.ts";

/** automatic_spend_atoms stays 0; this SDK never increments it. */
export const AUTOMATIC_SPEND_ATOMS = 0 as const;

/** 50 additive operation_ids (schemas/operations-v1.1.json). Preserves HCP/1's 34. */
export const OPERATION_IDS = [
  "getCognitiveReserveExtension",
  "createEntityLink",
  "listEntityLink",
  "getEntityLink",
  "createPortfolio",
  "listPortfolio",
  "getPortfolio",
  "createReservePolicy",
  "listReservePolicy",
  "getReservePolicy",
  "createWorkloadProfile",
  "listWorkloadProfile",
  "getWorkloadProfile",
  "createApprovalRule",
  "listApprovalRule",
  "getApprovalRule",
  "createResearchProgram",
  "listResearchProgram",
  "getResearchProgram",
  "assignEntityRoles",
  "revokeEntityLink",
  "getReserveSnapshot",
  "revokeReservePolicy",
  "planReserveReplenishment",
  "createTCOComparison",
  "getTCOComparison",
  "createCapitalPlan",
  "getCapitalPlan",
  "createAllocationPlan",
  "getAllocationPlan",
  "createApprovalRequest",
  "getApprovalRequest",
  "recordApprovalDecision",
  "listApprovalDecisions",
  "executeAllocation",
  "getCapitalExecution",
  "cancelCapitalExecution",
  "listCapabilityPositions",
  "getCapabilityPosition",
  "createCapabilityPosition",
  "updateCapabilityLifecycle",
  "joinResearchProgram",
  "prepareProgramCommitment",
  "listProductOffers",
  "getProductOffer",
  "createProductReferral",
  "createReserveReport",
  "getReserveReport",
  "createCapitalExport",
  "getCapitalExport",
] as const;

export type OperationId = (typeof OPERATION_IDS)[number];

export class Cr11Error extends Error {
  readonly code: string;
  readonly status: number;
  readonly unknown: boolean;
  constructor(code: string, message: string, status = 0) {
    super(code + ": " + message);
    this.name = "Cr11Error";
    this.code = code;
    this.status = status;
    this.unknown = status === 202 || code === "UNKNOWN";
  }
}

function isLoopbackLabHttp(origin: string): boolean {
  const u = new URL(origin);
  if (u.protocol !== "http:") return false;
  if (u.username || u.password || u.search || u.hash) return false;
  if (u.pathname !== "/") return false;
  return u.hostname === "127.0.0.1";
}

function assertOrigin(origin: string, labOrigin: boolean | string | undefined): void {
  const u = new URL(origin);
  if (labOrigin) {
    if (typeof labOrigin === "string") {
      if (!isLoopbackLabHttp(labOrigin)) {
        throw new Error("labOrigin must be http://127.0.0.1 for REGTEST lab");
      }
      const flag = new URL(labOrigin);
      if (flag.port !== "" && u.port !== flag.port) {
        throw new Error("origin port must match labOrigin");
      }
    }
    if (!isLoopbackLabHttp(origin)) {
      throw new Error("labOrigin allows only http://127.0.0.1 for REGTEST lab");
    }
    return;
  }
  if (u.protocol !== "https:" || u.username || u.password || u.pathname !== "/" || u.search || u.hash) {
    throw new Error("Use an independently enrolled HTTPS origin without credentials or path");
  }
}

/** 202 body when the response is empty or not JSON. Never treat as settlement. */
function unknown202(parsed?: unknown): { status: 202; unknown: true } & Record<string, unknown> {
  if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
    return { ...(parsed as Record<string, unknown>), status: 202, unknown: true };
  }
  return { status: 202, unknown: true };
}

export type Id = string;
export type Digest = string;
export type UInt = string;
export type Decimal = string;
export type Amount = { "unit_code": string; "exponent": number; "minor_units": UInt };
export type Ref = { "kind": Id; "id": Id; "digest"?: Digest };
export type NativeNetwork = { "name": "REGTEST" | "TESTNET" | "MAINNET"; "genesis_hash": string };
export type ScopedPortfolio = { "legal_entity_id": Id; "portfolio_id": Id };
export type Observation = { "source_id": Id; "observed_at": UInt; "expires_at"?: UInt; "evidence_basis": "SOURCE_DOCUMENT" | "LEDGER" | "NATIVE_NODE" | "CUSTOMER_INPUT" | "LOCAL_DEVICE" | "VENUE_QUOTE" | "MEASURED_WORKLOAD"; "reference"?: Ref };
export type Exposure = { "principal_atoms": UInt; "network_fee_cap_atoms": UInt; "service_fee_cap_atoms": UInt; "maximum_debit_atoms": UInt };
export type CostLine = { "category": "ACQUISITION" | "HARDWARE" | "ENERGY" | "OPERATIONS" | "MAINTENANCE" | "UPDATE" | "REPLACEMENT" | "NETWORK" | "EXTERNAL_SERVICE"; "period_index": number; "known": boolean; "amount"?: Amount; "observation": Observation };
export type ApprovalSeat = { "person_id": Id; "role": Id; "legal_entity_id": Id };
export type CapitalLeg = { "leg_id": Id; "kind": "CONVERT" | "FUND_RELEASE" | "FUND_BOUNTY" | "CLAIM" | "REFUND" | "PARTNER_REFERRAL" | "PARTNER_OPERATION" | "HANDOFF" | "LOCAL_PREPARATION" | "REPORT"; "depends_on": (Id)[]; "scope": ScopedPortfolio; "effect_ref": Ref; "child_operation_id": Id; "maximum_exposure"?: Exposure; "compensation": "NONE" | "REVIEW_REQUIRED" | "EXACT_PREAUTHORIZED" };
export type BodyCommon = { "schema_revision": "1.1"; "provider_id": Id; "created_at": UInt };
export type ReserveExtensionProfileV1_1 = { "schema_revision": "1.1"; "provider_id": Id; "created_at": UInt; "extension_id": "COGNITIVE_RESERVE_V1_1"; "parent_profile_body_id": Digest; "schema_digest": Digest; "operations_digest": Digest; "supported_features": ("ENTITIES" | "RESERVES" | "CAPITAL_PLANS" | "COMMITTEES" | "PROGRAMMES" | "HOLDINGS" | "PRODUCTS" | "REPORTS")[]; "expires_at": UInt };
export type EntityLinkV1_1 = { "schema_revision": "1.1"; "provider_id": Id; "created_at": UInt; "link_id": Id; "parent_entity_id": Id; "child_entity_id": Id; "relationship": "CORPORATE_GROUP" | "FAMILY_GROUP" | "ADVISER" | "FOUNDATION" | "OTHER_DECLARED"; "scopes": ("VIEW" | "DRAFT" | "REPORT")[]; "accepted_by": (Id)[]; "generation": UInt; "expires_at": UInt; "status": "ACTIVE" | "REVOKED" | "EXPIRED" };
export type PortfolioV1_1 = { "schema_revision": "1.1"; "provider_id": Id; "created_at": UInt; "legal_entity_id": Id; "portfolio_id": Id; "account_ref": Ref; "label": string; "purpose": "STRATEGIC_RESERVE" | "DEPLOYMENT" | "RESEARCH" | "LIQUIDITY"; "reporting_currency": string; "policy_ref"?: Ref; "generation": UInt; "status": "ACTIVE" | "ARCHIVED" };
export type ReservePolicyV1_1 = { "schema_revision": "1.1"; "provider_id": Id; "created_at": UInt; "scope": ScopedPortfolio; "policy_id": Id; "generation": UInt; "protected_atoms": UInt; "per_plan_cap_atoms": UInt; "lifetime_cap_atoms": UInt; "outstanding_cap_atoms": UInt; "permitted_actions": ("FUND_RELEASE" | "FUND_BOUNTY" | "CONVERT" | "WITHDRAW" | "PARTNER_OPERATION")[]; "replenishment_mode": "SUGGEST" | "AUTO"; "replenishment"?: { "allowed_source_assets": (string)[]; "lower_band_atoms": UInt; "target_atoms": UInt; "max_order_atoms": UInt; "max_turnover_atoms": UInt; "cooldown_seconds": UInt; "max_price_age_seconds": UInt; "slippage_bps": number }; "expires_at": UInt; "status": "ACTIVE" | "REVOKED" | "EXPIRED" };
export type ReserveSnapshotV1_1 = { "schema_revision": "1.1"; "provider_id": Id; "created_at": UInt; "scope": ScopedPortfolio; "snapshot_id": Id; "ledger_sequence": UInt; "policy_ref": Ref; "available_atoms": UInt; "protected_atoms": UInt; "remaining_authority_atoms": UInt; "allocation_capacity_atoms": UInt; "existing_hold_atoms": UInt; "committed_atoms": UInt; "refund_pending_atoms": UInt; "valuation"?: Amount; "valuation_observation"?: Observation; "observed_at": UInt };
export type WorkloadProfileV1_1 = { "schema_revision": "1.1"; "provider_id": Id; "created_at": UInt; "legal_entity_id": Id; "workload_id": Id; "generation": UInt; "objective": string; "accepted_task_definition": string; "evidence_minimum": (Ref)[]; "annual_accepted_tasks": UInt; "horizon_months": number; "data_policy": "LOCAL_ONLY" | "PRIVATE_FABRIC" | "EXTERNAL_ALLOWED"; "runtime_profiles": (Id)[]; "assumptions": (CostLine)[] };
export type TCOComparisonV1_1 = { "schema_revision": "1.1"; "provider_id": Id; "created_at": UInt; "legal_entity_id": Id; "comparison_id": Id; "workload_ref": Ref; "calculation_version": Id; "quality_equivalent": boolean; "route": "REUSE_LOCAL" | "ACQUIRE_PUBLIC" | "COMPOSE_LOCAL" | "ACQUIRE_LICENSED" | "FUND_RELEASE" | "FUND_CREATION" | "RETAIN_EXTERNAL_SERVICE"; "candidate_refs": (Ref)[]; "cost_lines": (CostLine)[]; "total_cash_cost"?: Amount; "break_even_annual_tasks"?: Decimal; "unknown_inputs": (Id)[]; "expires_at": UInt };
export type CapitalPlanV1_1 = { "schema_revision": "1.1"; "provider_id": Id; "created_at": UInt; "legal_entity_id": Id; "plan_id": Id; "objective": string; "comparison_ref": Ref; "selected_recipe_ref"?: Ref; "route": Id; "maximum_exposure": Exposure; "expected_outcome": string; "observation_refs": (Ref)[]; "expires_at": UInt };
export type AllocationPlanV1_1 = { "schema_revision": "1.1"; "provider_id": Id; "created_at": UInt; "legal_entity_id": Id; "allocation_id": Id; "capital_plan_ref": Ref; "policy_ref": Ref; "network": NativeNetwork; "legs": (CapitalLeg)[]; "maximum_exposure": Exposure; "client_operation_id": Id; "expires_at": UInt };
export type ApprovalRuleV1_1 = { "schema_revision": "1.1"; "provider_id": Id; "created_at": UInt; "legal_entity_id": Id; "rule_id": Id; "generation": UInt; "eligible_roles": (Id)[]; "distinct_person_quorum": number; "exclude_initiator": boolean; "veto_enabled": boolean; "threshold_atoms": UInt; "expires_at": UInt; "status": "ACTIVE" | "REVOKED" | "EXPIRED" };
export type ApprovalRequestV1_1 = { "schema_revision": "1.1"; "provider_id": Id; "created_at": UInt; "legal_entity_id": Id; "request_id": Id; "allocation_ref": Ref; "allocation_body_id": Digest; "rule_ref": Ref; "rule_body_id": Digest; "policy_ref": Ref; "policy_generation": UInt; "initiator_person_id": Id; "maximum_exposure": Exposure; "expires_at": UInt };
export type ApprovalDecisionV1_1 = { "schema_revision": "1.1"; "provider_id": Id; "created_at": UInt; "legal_entity_id": Id; "decision_id": Id; "request_ref": Ref; "request_body_id": Digest; "allocation_body_id": Digest; "policy_generation": UInt; "rule_body_id": Digest; "actor": ApprovalSeat; "decision": "APPROVE" | "REJECT" | "WITHDRAW"; "sequence": UInt; "expires_at": UInt };
export type CapabilityPositionV1_1 = { "schema_revision": "1.1"; "provider_id": Id; "created_at": UInt; "legal_entity_id": Id; "position_id": Id; "portfolio_id": Id; "package_core_id": Digest; "recipe_id": Digest; "lock_id": Digest; "resource_refs": (Ref)[]; "rights_ref": Ref; "acquisition_refs": (Ref)[]; "allocated_cost"?: Amount; "lifecycle": "ACQUIRED" | "DEPLOYING" | "USABLE" | "SUPERSEDED" | "RETIRED"; "readiness_observation"?: Observation; "generation": UInt };
export type ResearchProgramV1_1 = { "schema_revision": "1.1"; "provider_id": Id; "created_at": UInt; "legal_entity_id": Id; "program_id": Id; "objective": string; "evidence_refs": (Ref)[]; "native_terms_refs": (Ref)[]; "programme_ceiling_atoms": UInt; "visibility": "PRIVATE" | "MEMBERS" | "PUBLIC"; "deadline": UInt; "generation": UInt };
export type ProgramMembershipV1_1 = { "schema_revision": "1.1"; "provider_id": Id; "created_at": UInt; "legal_entity_id": Id; "membership_id": Id; "program_ref": Ref; "member_entity_id": Id; "role": "SPONSOR" | "SUPPLIER" | "OBSERVER"; "ceiling_atoms": UInt; "accepted_terms_ref": Ref; "status": "ACTIVE" | "WITHDRAWN" | "EXPIRED"; "expires_at": UInt };
export type ProductOfferV1_1 = { "schema_revision": "1.1"; "provider_id": Id; "created_at": UInt; "offer_id": Id; "product_provider_id": Id; "product_class": "CUSTODY" | "SPOT_OTC" | "TREASURY_CREDIT" | "HEDGING" | "INFRASTRUCTURE_FINANCE" | "RESEARCH_ADMINISTRATION"; "rights_ref": Ref; "eligibility_policy_ref": Ref; "fee_disclosure_ref": Ref; "supported_action": "REFERRAL" | "QUOTE" | "EXISTING_PRODUCT_EXECUTION"; "expires_at": UInt };
export type CapitalExecutionReceiptV1_1 = { "schema_revision": "1.1"; "provider_id": Id; "created_at": UInt; "legal_entity_id": Id; "execution_id": Id; "allocation_ref": Ref; "allocation_body_id": Digest; "child_refs": (Ref)[]; "state": "PLANNED" | "APPROVAL_PENDING" | "AUTHORIZED" | "EXECUTING" | "PARTIAL" | "COMPLETED" | "RECONCILIATION_REQUIRED" | "CANCELED_WHERE_SAFE"; "actual_fees"?: Amount; "observation": Observation; "sequence": UInt; "supersedes"?: Ref };
export type ReserveReportV1_1 = { "schema_revision": "1.1"; "provider_id": Id; "created_at": UInt; "legal_entity_id": Id; "report_id": Id; "snapshot_refs": (Ref)[]; "position_refs": (Ref)[]; "commitment_refs": (Ref)[]; "reporting_currency": string; "report_type": "CORPORATE" | "INSTITUTIONAL" | "FAMILY_GROUP" | "PROGRAMME" | "FOCUS_EXPORT"; "period_start": UInt; "period_end": UInt; "as_of": UInt; "export_ref"?: Ref };
export type ReserveExtensionProfileV1_1Envelope = { "object_type": "ReserveExtensionProfileV1_1"; "body": ReserveExtensionProfileV1_1; "body_id": Digest; "signer_key_id": Id; "signature": string };
export type EntityLinkV1_1Envelope = { "object_type": "EntityLinkV1_1"; "body": EntityLinkV1_1; "body_id": Digest; "signer_key_id": Id; "signature": string };
export type PortfolioV1_1Envelope = { "object_type": "PortfolioV1_1"; "body": PortfolioV1_1; "body_id": Digest; "signer_key_id": Id; "signature": string };
export type ReservePolicyV1_1Envelope = { "object_type": "ReservePolicyV1_1"; "body": ReservePolicyV1_1; "body_id": Digest; "signer_key_id": Id; "signature": string };
export type ReserveSnapshotV1_1Envelope = { "object_type": "ReserveSnapshotV1_1"; "body": ReserveSnapshotV1_1; "body_id": Digest; "signer_key_id": Id; "signature": string };
export type WorkloadProfileV1_1Envelope = { "object_type": "WorkloadProfileV1_1"; "body": WorkloadProfileV1_1; "body_id": Digest; "signer_key_id": Id; "signature": string };
export type TCOComparisonV1_1Envelope = { "object_type": "TCOComparisonV1_1"; "body": TCOComparisonV1_1; "body_id": Digest; "signer_key_id": Id; "signature": string };
export type CapitalPlanV1_1Envelope = { "object_type": "CapitalPlanV1_1"; "body": CapitalPlanV1_1; "body_id": Digest; "signer_key_id": Id; "signature": string };
export type AllocationPlanV1_1Envelope = { "object_type": "AllocationPlanV1_1"; "body": AllocationPlanV1_1; "body_id": Digest; "signer_key_id": Id; "signature": string };
export type ApprovalRuleV1_1Envelope = { "object_type": "ApprovalRuleV1_1"; "body": ApprovalRuleV1_1; "body_id": Digest; "signer_key_id": Id; "signature": string };
export type ApprovalRequestV1_1Envelope = { "object_type": "ApprovalRequestV1_1"; "body": ApprovalRequestV1_1; "body_id": Digest; "signer_key_id": Id; "signature": string };
export type ApprovalDecisionV1_1Envelope = { "object_type": "ApprovalDecisionV1_1"; "body": ApprovalDecisionV1_1; "body_id": Digest; "signer_key_id": Id; "signature": string };
export type CapabilityPositionV1_1Envelope = { "object_type": "CapabilityPositionV1_1"; "body": CapabilityPositionV1_1; "body_id": Digest; "signer_key_id": Id; "signature": string };
export type ResearchProgramV1_1Envelope = { "object_type": "ResearchProgramV1_1"; "body": ResearchProgramV1_1; "body_id": Digest; "signer_key_id": Id; "signature": string };
export type ProgramMembershipV1_1Envelope = { "object_type": "ProgramMembershipV1_1"; "body": ProgramMembershipV1_1; "body_id": Digest; "signer_key_id": Id; "signature": string };
export type ProductOfferV1_1Envelope = { "object_type": "ProductOfferV1_1"; "body": ProductOfferV1_1; "body_id": Digest; "signer_key_id": Id; "signature": string };
export type CapitalExecutionReceiptV1_1Envelope = { "object_type": "CapitalExecutionReceiptV1_1"; "body": CapitalExecutionReceiptV1_1; "body_id": Digest; "signer_key_id": Id; "signature": string };
export type ReserveReportV1_1Envelope = { "object_type": "ReserveReportV1_1"; "body": ReserveReportV1_1; "body_id": Digest; "signer_key_id": Id; "signature": string };
export type Error = { "code": Id; "stage": Id; "retryable": boolean; "correlation_id": Id; "safe_next_action": string; "reference"?: Ref };
export type Job = { "job_id": Id; "state": "ACCEPTED" | "RUNNING" | "COMPLETED" | "FAILED" | "RECONCILIATION_REQUIRED"; "result_ref"?: Ref };
export type MutationRequest = { "client_operation_id": Id; "expected_body_id": Digest; "expected_generation"?: UInt; "policy_ref"?: Ref };
export type RefRequest = { "client_operation_id": Id; "subject_ref": Ref; "expected_body_id": Digest; "parameters_ref"?: Ref };
export type RoleAssignmentRequest = { "client_operation_id": Id; "legal_entity_id": Id; "person_id": Id; "roles": (Id)[]; "expected_generation": UInt; "approval_ref": Ref };
export type CreateReserveExtensionProfileV1_1 = { "client_operation_id": Id; "body": ReserveExtensionProfileV1_1; "expected_parent_ref"?: Ref };
export type CreateEntityLinkV1_1 = { "client_operation_id": Id; "body": EntityLinkV1_1; "expected_parent_ref"?: Ref };
export type CreatePortfolioV1_1 = { "client_operation_id": Id; "body": PortfolioV1_1; "expected_parent_ref"?: Ref };
export type CreateReservePolicyV1_1 = { "client_operation_id": Id; "body": ReservePolicyV1_1; "expected_parent_ref"?: Ref };
export type CreateReserveSnapshotV1_1 = { "client_operation_id": Id; "body": ReserveSnapshotV1_1; "expected_parent_ref"?: Ref };
export type CreateWorkloadProfileV1_1 = { "client_operation_id": Id; "body": WorkloadProfileV1_1; "expected_parent_ref"?: Ref };
export type CreateTCOComparisonV1_1 = { "client_operation_id": Id; "body": TCOComparisonV1_1; "expected_parent_ref"?: Ref };
export type CreateCapitalPlanV1_1 = { "client_operation_id": Id; "body": CapitalPlanV1_1; "expected_parent_ref"?: Ref };
export type CreateAllocationPlanV1_1 = { "client_operation_id": Id; "body": AllocationPlanV1_1; "expected_parent_ref"?: Ref };
export type CreateApprovalRuleV1_1 = { "client_operation_id": Id; "body": ApprovalRuleV1_1; "expected_parent_ref"?: Ref };
export type CreateApprovalRequestV1_1 = { "client_operation_id": Id; "body": ApprovalRequestV1_1; "expected_parent_ref"?: Ref };
export type CreateApprovalDecisionV1_1 = { "client_operation_id": Id; "body": ApprovalDecisionV1_1; "expected_parent_ref"?: Ref };
export type CreateCapabilityPositionV1_1 = { "client_operation_id": Id; "body": CapabilityPositionV1_1; "expected_parent_ref"?: Ref };
export type CreateResearchProgramV1_1 = { "client_operation_id": Id; "body": ResearchProgramV1_1; "expected_parent_ref"?: Ref };
export type CreateProgramMembershipV1_1 = { "client_operation_id": Id; "body": ProgramMembershipV1_1; "expected_parent_ref"?: Ref };
export type CreateProductOfferV1_1 = { "client_operation_id": Id; "body": ProductOfferV1_1; "expected_parent_ref"?: Ref };
export type CreateCapitalExecutionReceiptV1_1 = { "client_operation_id": Id; "body": CapitalExecutionReceiptV1_1; "expected_parent_ref"?: Ref };
export type CreateReserveReportV1_1 = { "client_operation_id": Id; "body": ReserveReportV1_1; "expected_parent_ref"?: Ref };
export type EntityLinkV1_1List = { "items": (EntityLinkV1_1Envelope)[]; "snapshot_id": Id; "next_cursor"?: string };
export type PortfolioV1_1List = { "items": (PortfolioV1_1Envelope)[]; "snapshot_id": Id; "next_cursor"?: string };
export type ReservePolicyV1_1List = { "items": (ReservePolicyV1_1Envelope)[]; "snapshot_id": Id; "next_cursor"?: string };
export type WorkloadProfileV1_1List = { "items": (WorkloadProfileV1_1Envelope)[]; "snapshot_id": Id; "next_cursor"?: string };
export type ApprovalRuleV1_1List = { "items": (ApprovalRuleV1_1Envelope)[]; "snapshot_id": Id; "next_cursor"?: string };
export type ResearchProgramV1_1List = { "items": (ResearchProgramV1_1Envelope)[]; "snapshot_id": Id; "next_cursor"?: string };
export type ApprovalDecisionV1_1List = { "items": (ApprovalDecisionV1_1Envelope)[]; "snapshot_id": Id; "next_cursor"?: string };
export type CapabilityPositionV1_1List = { "items": (CapabilityPositionV1_1Envelope)[]; "snapshot_id": Id; "next_cursor"?: string };
export type LifecycleRequest = { "client_operation_id": Id; "expected_body_id": Digest; "expected_generation": UInt; "lifecycle": "ACQUIRED" | "DEPLOYING" | "USABLE" | "SUPERSEDED" | "RETIRED"; "evidence_ref": Ref };
export type ProductOfferV1_1List = { "items": (ProductOfferV1_1Envelope)[]; "snapshot_id": Id; "next_cursor"?: string };

export interface ClientOptions {
  origin: string;
  authHeaders: (method: string, absoluteUrl: string) => Promise<Record<string,string>>;
  validate: (schemaName: string, value: unknown) => void;
  fetcher?: typeof fetch;
  /** REGTEST lab only. Must be true or "http://127.0.0.1"; never silent arbitrary http. */
  labOrigin?: boolean | string;
}
export class CognitiveReserveClient {
  private readonly options: ClientOptions;
  readonly automaticSpendAtoms = AUTOMATIC_SPEND_ATOMS;
  constructor(options:ClientOptions) {
    assertOrigin(options.origin, options.labOrigin);
    this.options=options;
  }
  private async bounded(response:Response):Promise<unknown> {
    if(!response.body) throw new Error('EMPTY_RESPONSE');
    const reader=response.body.getReader(); const chunks:Uint8Array[]=[]; let size=0;
    try { while(true) {const r=await reader.read();if(r.done)break;size+=r.value.byteLength;
      if(size>4194304){await reader.cancel();throw new Error('RESPONSE_TOO_LARGE');}chunks.push(r.value);}}
    finally{reader.releaseLock();}
    const all=new Uint8Array(size);let offset=0;for(const c of chunks){all.set(c,offset);offset+=c.byteLength;}
    return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(all));
  }
  private async call<T>(method:string,path:string,requestSchema:string|null,responseSchema:string,
                        body?:unknown,idempotencyKey?:string,signal?:AbortSignal):Promise<T> {
    if(path==='/rpc' || path.startsWith('/rpc/') || !path.startsWith('/btx/hcp/v1/'))
      throw new Error('GENERIC_RPC_DISABLED');
    const url=new URL(path,this.options.origin).href;
    if(method==='POST' && !idempotencyKey) throw new Error('STABLE_IDEMPOTENCY_KEY_REQUIRED');
    if(requestSchema)this.options.validate(requestSchema,body);
    const encoded=body===undefined?undefined:JSON.stringify(body);
    if(encoded && new TextEncoder().encode(encoded).byteLength>1048576)throw new Error('REQUEST_TOO_LARGE');
    const auth=await this.options.authHeaders(method,url);
    const headers:Record<string,string>={...auth,'Accept':'application/json'};
    if(encoded!==undefined)headers['Content-Type']='application/json';
    if(idempotencyKey)headers['Idempotency-Key']=idempotencyKey;
    let response: Response;
    try {
      response=await (this.options.fetcher??fetch)(url,{method,headers,body:encoded,redirect:'error',signal});
    } catch (err) {
      const name = err instanceof Error ? err.name : "";
      if (name === "TimeoutError" || name === "AbortError") {
        throw new Cr11Error("UNKNOWN", "timeout", 0);
      }
      throw err;
    }
    if(response.status===202) {
      // UNKNOWN — never auto-submit / authorize / execute / cancel from this branch.
      let parsed: unknown;
      try { parsed = await this.bounded(response); }
      catch { return unknown202() as T; }
      return unknown202(parsed) as T;
    }
    const parsed=await this.bounded(response);
    this.options.validate(response.ok?responseSchema:'Error',parsed);
    if(!response.ok)throw Object.assign(new Error('HCP_REQUEST_FAILED'),{status:response.status,detail:parsed});
    return parsed as T;
  }

  /** READ · scope catalog:read.  */
  getCognitiveReserveExtension(signal?:AbortSignal):Promise<ReserveExtensionProfileV1_1Envelope> {
    return this.call("GET",`/btx/hcp/v1/extensions/cognitive-reserve`,null,"ReserveExtensionProfileV1_1Envelope",undefined,undefined,signal);
  }
  /** DRAFT_OR_POLICY · scope entities:admin.  */
  createEntityLink(body:CreateEntityLinkV1_1, idempotencyKey:string, signal?:AbortSignal):Promise<EntityLinkV1_1Envelope> {
    return this.call("POST",`/btx/hcp/v1/reserve/entities/links`,"CreateEntityLinkV1_1","EntityLinkV1_1Envelope",body,idempotencyKey,signal);
  }
  /** READ · scope capital:read.  */
  listEntityLink(signal?:AbortSignal):Promise<EntityLinkV1_1List> {
    return this.call("GET",`/btx/hcp/v1/reserve/entities/links`,null,"EntityLinkV1_1List",undefined,undefined,signal);
  }
  /** READ · scope capital:read.  */
  getEntityLink(id:string, signal?:AbortSignal):Promise<EntityLinkV1_1Envelope> {
    return this.call("GET",`/btx/hcp/v1/reserve/entities/links/${encodeURIComponent(id)}`,null,"EntityLinkV1_1Envelope",undefined,undefined,signal);
  }
  /** DRAFT_OR_POLICY · scope capital:prepare.  */
  createPortfolio(body:CreatePortfolioV1_1, idempotencyKey:string, signal?:AbortSignal):Promise<PortfolioV1_1Envelope> {
    return this.call("POST",`/btx/hcp/v1/reserve/portfolios`,"CreatePortfolioV1_1","PortfolioV1_1Envelope",body,idempotencyKey,signal);
  }
  /** READ · scope capital:read.  */
  listPortfolio(signal?:AbortSignal):Promise<PortfolioV1_1List> {
    return this.call("GET",`/btx/hcp/v1/reserve/portfolios`,null,"PortfolioV1_1List",undefined,undefined,signal);
  }
  /** READ · scope capital:read.  */
  getPortfolio(id:string, signal?:AbortSignal):Promise<PortfolioV1_1Envelope> {
    return this.call("GET",`/btx/hcp/v1/reserve/portfolios/${encodeURIComponent(id)}`,null,"PortfolioV1_1Envelope",undefined,undefined,signal);
  }
  /** DRAFT_OR_POLICY · scope policies:admin.  */
  createReservePolicy(body:CreateReservePolicyV1_1, idempotencyKey:string, signal?:AbortSignal):Promise<ReservePolicyV1_1Envelope> {
    return this.call("POST",`/btx/hcp/v1/reserve/policies`,"CreateReservePolicyV1_1","ReservePolicyV1_1Envelope",body,idempotencyKey,signal);
  }
  /** READ · scope capital:read.  */
  listReservePolicy(signal?:AbortSignal):Promise<ReservePolicyV1_1List> {
    return this.call("GET",`/btx/hcp/v1/reserve/policies`,null,"ReservePolicyV1_1List",undefined,undefined,signal);
  }
  /** READ · scope capital:read.  */
  getReservePolicy(id:string, signal?:AbortSignal):Promise<ReservePolicyV1_1Envelope> {
    return this.call("GET",`/btx/hcp/v1/reserve/policies/${encodeURIComponent(id)}`,null,"ReservePolicyV1_1Envelope",undefined,undefined,signal);
  }
  /** DRAFT_OR_POLICY · scope capital:prepare.  */
  createWorkloadProfile(body:CreateWorkloadProfileV1_1, idempotencyKey:string, signal?:AbortSignal):Promise<WorkloadProfileV1_1Envelope> {
    return this.call("POST",`/btx/hcp/v1/capital/workloads`,"CreateWorkloadProfileV1_1","WorkloadProfileV1_1Envelope",body,idempotencyKey,signal);
  }
  /** READ · scope capital:read.  */
  listWorkloadProfile(signal?:AbortSignal):Promise<WorkloadProfileV1_1List> {
    return this.call("GET",`/btx/hcp/v1/capital/workloads`,null,"WorkloadProfileV1_1List",undefined,undefined,signal);
  }
  /** READ · scope capital:read.  */
  getWorkloadProfile(id:string, signal?:AbortSignal):Promise<WorkloadProfileV1_1Envelope> {
    return this.call("GET",`/btx/hcp/v1/capital/workloads/${encodeURIComponent(id)}`,null,"WorkloadProfileV1_1Envelope",undefined,undefined,signal);
  }
  /** DRAFT_OR_POLICY · scope policies:admin.  */
  createApprovalRule(body:CreateApprovalRuleV1_1, idempotencyKey:string, signal?:AbortSignal):Promise<ApprovalRuleV1_1Envelope> {
    return this.call("POST",`/btx/hcp/v1/capital/approval-rules`,"CreateApprovalRuleV1_1","ApprovalRuleV1_1Envelope",body,idempotencyKey,signal);
  }
  /** READ · scope capital:read.  */
  listApprovalRule(signal?:AbortSignal):Promise<ApprovalRuleV1_1List> {
    return this.call("GET",`/btx/hcp/v1/capital/approval-rules`,null,"ApprovalRuleV1_1List",undefined,undefined,signal);
  }
  /** READ · scope capital:read.  */
  getApprovalRule(id:string, signal?:AbortSignal):Promise<ApprovalRuleV1_1Envelope> {
    return this.call("GET",`/btx/hcp/v1/capital/approval-rules/${encodeURIComponent(id)}`,null,"ApprovalRuleV1_1Envelope",undefined,undefined,signal);
  }
  /** DRAFT_OR_POLICY · scope research:publish.  */
  createResearchProgram(body:CreateResearchProgramV1_1, idempotencyKey:string, signal?:AbortSignal):Promise<ResearchProgramV1_1Envelope> {
    return this.call("POST",`/btx/hcp/v1/capital/programs`,"CreateResearchProgramV1_1","ResearchProgramV1_1Envelope",body,idempotencyKey,signal);
  }
  /** READ · scope capital:read.  */
  listResearchProgram(signal?:AbortSignal):Promise<ResearchProgramV1_1List> {
    return this.call("GET",`/btx/hcp/v1/capital/programs`,null,"ResearchProgramV1_1List",undefined,undefined,signal);
  }
  /** READ · scope capital:read.  */
  getResearchProgram(id:string, signal?:AbortSignal):Promise<ResearchProgramV1_1Envelope> {
    return this.call("GET",`/btx/hcp/v1/capital/programs/${encodeURIComponent(id)}`,null,"ResearchProgramV1_1Envelope",undefined,undefined,signal);
  }
  /** POLICY · scope entities:admin.  */
  assignEntityRoles(body:RoleAssignmentRequest, idempotencyKey:string, signal?:AbortSignal):Promise<Job> {
    return this.call("POST",`/btx/hcp/v1/reserve/entities/roles`,"RoleAssignmentRequest","Job",body,idempotencyKey,signal);
  }
  /** POLICY · scope entities:admin.  */
  revokeEntityLink(id:string, body:MutationRequest, idempotencyKey:string, signal?:AbortSignal):Promise<EntityLinkV1_1Envelope> {
    return this.call("POST",`/btx/hcp/v1/reserve/entities/links/${encodeURIComponent(id)}/revoke`,"MutationRequest","EntityLinkV1_1Envelope",body,idempotencyKey,signal);
  }
  /** READ · scope reserve:read.  */
  getReserveSnapshot(id:string, signal?:AbortSignal):Promise<ReserveSnapshotV1_1Envelope> {
    return this.call("GET",`/btx/hcp/v1/reserve/portfolios/${encodeURIComponent(id)}/snapshot`,null,"ReserveSnapshotV1_1Envelope",undefined,undefined,signal);
  }
  /** POLICY · scope policies:admin.  */
  revokeReservePolicy(id:string, body:MutationRequest, idempotencyKey:string, signal?:AbortSignal):Promise<ReservePolicyV1_1Envelope> {
    return this.call("POST",`/btx/hcp/v1/reserve/policies/${encodeURIComponent(id)}/revoke`,"MutationRequest","ReservePolicyV1_1Envelope",body,idempotencyKey,signal);
  }
  /** PLAN · scope capital:prepare.  */
  planReserveReplenishment(body:RefRequest, idempotencyKey:string, signal?:AbortSignal):Promise<CapitalPlanV1_1Envelope> {
    return this.call("POST",`/btx/hcp/v1/reserve/replenishment/plans`,"RefRequest","CapitalPlanV1_1Envelope",body,idempotencyKey,signal);
  }
  /** PLAN · scope capital:prepare.  */
  createTCOComparison(body:RefRequest, idempotencyKey:string, signal?:AbortSignal):Promise<TCOComparisonV1_1Envelope> {
    return this.call("POST",`/btx/hcp/v1/capital/comparisons`,"RefRequest","TCOComparisonV1_1Envelope",body,idempotencyKey,signal);
  }
  /** READ · scope capital:read.  */
  getTCOComparison(id:string, signal?:AbortSignal):Promise<TCOComparisonV1_1Envelope> {
    return this.call("GET",`/btx/hcp/v1/capital/comparisons/${encodeURIComponent(id)}`,null,"TCOComparisonV1_1Envelope",undefined,undefined,signal);
  }
  /** PLAN · scope capital:prepare.  */
  createCapitalPlan(body:CreateCapitalPlanV1_1, idempotencyKey:string, signal?:AbortSignal):Promise<CapitalPlanV1_1Envelope> {
    return this.call("POST",`/btx/hcp/v1/capital/plans`,"CreateCapitalPlanV1_1","CapitalPlanV1_1Envelope",body,idempotencyKey,signal);
  }
  /** READ · scope capital:read.  */
  getCapitalPlan(id:string, signal?:AbortSignal):Promise<CapitalPlanV1_1Envelope> {
    return this.call("GET",`/btx/hcp/v1/capital/plans/${encodeURIComponent(id)}`,null,"CapitalPlanV1_1Envelope",undefined,undefined,signal);
  }
  /** PLAN · scope capital:prepare.  */
  createAllocationPlan(body:CreateAllocationPlanV1_1, idempotencyKey:string, signal?:AbortSignal):Promise<AllocationPlanV1_1Envelope> {
    return this.call("POST",`/btx/hcp/v1/capital/allocations`,"CreateAllocationPlanV1_1","AllocationPlanV1_1Envelope",body,idempotencyKey,signal);
  }
  /** READ · scope capital:read.  */
  getAllocationPlan(id:string, signal?:AbortSignal):Promise<AllocationPlanV1_1Envelope> {
    return this.call("GET",`/btx/hcp/v1/capital/allocations/${encodeURIComponent(id)}`,null,"AllocationPlanV1_1Envelope",undefined,undefined,signal);
  }
  /** PLAN · scope capital:prepare.  */
  createApprovalRequest(body:CreateApprovalRequestV1_1, idempotencyKey:string, signal?:AbortSignal):Promise<ApprovalRequestV1_1Envelope> {
    return this.call("POST",`/btx/hcp/v1/capital/approvals`,"CreateApprovalRequestV1_1","ApprovalRequestV1_1Envelope",body,idempotencyKey,signal);
  }
  /** READ · scope capital:read.  */
  getApprovalRequest(id:string, signal?:AbortSignal):Promise<ApprovalRequestV1_1Envelope> {
    return this.call("GET",`/btx/hcp/v1/capital/approvals/${encodeURIComponent(id)}`,null,"ApprovalRequestV1_1Envelope",undefined,undefined,signal);
  }
  /** AUTHORIZE · scope capital:approve. Derive actor from verified caller; request actor must match. Approval does not execute. */
  recordApprovalDecision(id:string, body:CreateApprovalDecisionV1_1, idempotencyKey:string, signal?:AbortSignal):Promise<ApprovalDecisionV1_1Envelope> {
    return this.call("POST",`/btx/hcp/v1/capital/approvals/${encodeURIComponent(id)}/decisions`,"CreateApprovalDecisionV1_1","ApprovalDecisionV1_1Envelope",body,idempotencyKey,signal);
  }
  /** READ · scope capital:read.  */
  listApprovalDecisions(id:string, signal?:AbortSignal):Promise<ApprovalDecisionV1_1List> {
    return this.call("GET",`/btx/hcp/v1/capital/approvals/${encodeURIComponent(id)}/decisions`,null,"ApprovalDecisionV1_1List",undefined,undefined,signal);
  }
  /** EXECUTE_APPROVED · scope capital:execute. Recheck exact plan, quorum, policy and reserve; dispatch only approved child effects. */
  executeAllocation(id:string, body:MutationRequest, idempotencyKey:string, signal?:AbortSignal):Promise<CapitalExecutionReceiptV1_1Envelope> {
    return this.call("POST",`/btx/hcp/v1/capital/allocations/${encodeURIComponent(id)}/execute`,"MutationRequest","CapitalExecutionReceiptV1_1Envelope",body,idempotencyKey,signal);
  }
  /** READ · scope capital:read.  */
  getCapitalExecution(id:string, signal?:AbortSignal):Promise<CapitalExecutionReceiptV1_1Envelope> {
    return this.call("GET",`/btx/hcp/v1/capital/executions/${encodeURIComponent(id)}`,null,"CapitalExecutionReceiptV1_1Envelope",undefined,undefined,signal);
  }
  /** CANCEL_SAFE_ONLY · scope capital:execute.  */
  cancelCapitalExecution(id:string, body:MutationRequest, idempotencyKey:string, signal?:AbortSignal):Promise<CapitalExecutionReceiptV1_1Envelope> {
    return this.call("POST",`/btx/hcp/v1/capital/executions/${encodeURIComponent(id)}/cancel`,"MutationRequest","CapitalExecutionReceiptV1_1Envelope",body,idempotencyKey,signal);
  }
  /** READ · scope capital:read.  */
  listCapabilityPositions(signal?:AbortSignal):Promise<CapabilityPositionV1_1List> {
    return this.call("GET",`/btx/hcp/v1/capital/positions`,null,"CapabilityPositionV1_1List",undefined,undefined,signal);
  }
  /** READ · scope capital:read.  */
  getCapabilityPosition(id:string, signal?:AbortSignal):Promise<CapabilityPositionV1_1Envelope> {
    return this.call("GET",`/btx/hcp/v1/capital/positions/${encodeURIComponent(id)}`,null,"CapabilityPositionV1_1Envelope",undefined,undefined,signal);
  }
  /** RECORD · scope holdings:write.  */
  createCapabilityPosition(body:CreateCapabilityPositionV1_1, idempotencyKey:string, signal?:AbortSignal):Promise<CapabilityPositionV1_1Envelope> {
    return this.call("POST",`/btx/hcp/v1/capital/positions`,"CreateCapabilityPositionV1_1","CapabilityPositionV1_1Envelope",body,idempotencyKey,signal);
  }
  /** RECORD · scope holdings:write.  */
  updateCapabilityLifecycle(id:string, body:LifecycleRequest, idempotencyKey:string, signal?:AbortSignal):Promise<CapabilityPositionV1_1Envelope> {
    return this.call("POST",`/btx/hcp/v1/capital/positions/${encodeURIComponent(id)}/lifecycle`,"LifecycleRequest","CapabilityPositionV1_1Envelope",body,idempotencyKey,signal);
  }
  /** MEMBERSHIP_ONLY · scope research:publish.  */
  joinResearchProgram(id:string, body:CreateProgramMembershipV1_1, idempotencyKey:string, signal?:AbortSignal):Promise<ProgramMembershipV1_1Envelope> {
    return this.call("POST",`/btx/hcp/v1/capital/programs/${encodeURIComponent(id)}/memberships`,"CreateProgramMembershipV1_1","ProgramMembershipV1_1Envelope",body,idempotencyKey,signal);
  }
  /** PLAN · scope capital:prepare. Creates a proposal, never an unapproved financial commitment. */
  prepareProgramCommitment(id:string, body:RefRequest, idempotencyKey:string, signal?:AbortSignal):Promise<AllocationPlanV1_1Envelope> {
    return this.call("POST",`/btx/hcp/v1/capital/programs/${encodeURIComponent(id)}/commitments`,"RefRequest","AllocationPlanV1_1Envelope",body,idempotencyKey,signal);
  }
  /** READ · scope products:read.  */
  listProductOffers(signal?:AbortSignal):Promise<ProductOfferV1_1List> {
    return this.call("GET",`/btx/hcp/v1/capital/products`,null,"ProductOfferV1_1List",undefined,undefined,signal);
  }
  /** READ · scope products:read.  */
  getProductOffer(id:string, signal?:AbortSignal):Promise<ProductOfferV1_1Envelope> {
    return this.call("GET",`/btx/hcp/v1/capital/products/${encodeURIComponent(id)}`,null,"ProductOfferV1_1Envelope",undefined,undefined,signal);
  }
  /** REFERRAL_ONLY · scope products:refer.  */
  createProductReferral(id:string, body:RefRequest, idempotencyKey:string, signal?:AbortSignal):Promise<Job> {
    return this.call("POST",`/btx/hcp/v1/capital/products/${encodeURIComponent(id)}/referral`,"RefRequest","Job",body,idempotencyKey,signal);
  }
  /** REPORT · scope reports:create.  */
  createReserveReport(body:RefRequest, idempotencyKey:string, signal?:AbortSignal):Promise<Job> {
    return this.call("POST",`/btx/hcp/v1/capital/reports`,"RefRequest","Job",body,idempotencyKey,signal);
  }
  /** READ · scope reports:read.  */
  getReserveReport(id:string, signal?:AbortSignal):Promise<ReserveReportV1_1Envelope> {
    return this.call("GET",`/btx/hcp/v1/capital/reports/${encodeURIComponent(id)}`,null,"ReserveReportV1_1Envelope",undefined,undefined,signal);
  }
  /** EXPORT · scope exports:create.  */
  createCapitalExport(body:RefRequest, idempotencyKey:string, signal?:AbortSignal):Promise<Job> {
    return this.call("POST",`/btx/hcp/v1/capital/exports`,"RefRequest","Job",body,idempotencyKey,signal);
  }
  /** READ · scope exports:read.  */
  getCapitalExport(id:string, signal?:AbortSignal):Promise<Job> {
    return this.call("GET",`/btx/hcp/v1/capital/exports/${encodeURIComponent(id)}`,null,"Job",undefined,undefined,signal);
  }
}