# Cognitive Reserve v1.1 — operation contract

50 additive operations. Prefix `/btx/hcp/v1`. Preserve the base HCP operation contracts. Every POST is explicitly idempotent, but that never makes cross-provider economic retries safe.

## getCognitiveReserveExtension

`GET /btx/hcp/v1/extensions/cognitive-reserve`

**Scope:** `catalog:read` · **Effect:** `READ`
**Request:** `Path/query context only` · **Response:** `ReserveExtensionProfileV1_1Envelope`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## createEntityLink

`POST /btx/hcp/v1/reserve/entities/links`

**Scope:** `entities:admin` · **Effect:** `DRAFT_OR_POLICY`
**Request:** `CreateEntityLinkV1_1` · **Response:** `EntityLinkV1_1Envelope`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## listEntityLink

`GET /btx/hcp/v1/reserve/entities/links`

**Scope:** `capital:read` · **Effect:** `READ`
**Request:** `Path/query context only` · **Response:** `EntityLinkV1_1List`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## getEntityLink

`GET /btx/hcp/v1/reserve/entities/links/{id}`

**Scope:** `capital:read` · **Effect:** `READ`
**Request:** `Path/query context only` · **Response:** `EntityLinkV1_1Envelope`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## createPortfolio

`POST /btx/hcp/v1/reserve/portfolios`

**Scope:** `capital:prepare` · **Effect:** `DRAFT_OR_POLICY`
**Request:** `CreatePortfolioV1_1` · **Response:** `PortfolioV1_1Envelope`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## listPortfolio

`GET /btx/hcp/v1/reserve/portfolios`

**Scope:** `capital:read` · **Effect:** `READ`
**Request:** `Path/query context only` · **Response:** `PortfolioV1_1List`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## getPortfolio

`GET /btx/hcp/v1/reserve/portfolios/{id}`

**Scope:** `capital:read` · **Effect:** `READ`
**Request:** `Path/query context only` · **Response:** `PortfolioV1_1Envelope`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## createReservePolicy

`POST /btx/hcp/v1/reserve/policies`

**Scope:** `policies:admin` · **Effect:** `DRAFT_OR_POLICY`
**Request:** `CreateReservePolicyV1_1` · **Response:** `ReservePolicyV1_1Envelope`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## listReservePolicy

`GET /btx/hcp/v1/reserve/policies`

**Scope:** `capital:read` · **Effect:** `READ`
**Request:** `Path/query context only` · **Response:** `ReservePolicyV1_1List`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## getReservePolicy

`GET /btx/hcp/v1/reserve/policies/{id}`

**Scope:** `capital:read` · **Effect:** `READ`
**Request:** `Path/query context only` · **Response:** `ReservePolicyV1_1Envelope`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## createWorkloadProfile

`POST /btx/hcp/v1/capital/workloads`

**Scope:** `capital:prepare` · **Effect:** `DRAFT_OR_POLICY`
**Request:** `CreateWorkloadProfileV1_1` · **Response:** `WorkloadProfileV1_1Envelope`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## listWorkloadProfile

`GET /btx/hcp/v1/capital/workloads`

**Scope:** `capital:read` · **Effect:** `READ`
**Request:** `Path/query context only` · **Response:** `WorkloadProfileV1_1List`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## getWorkloadProfile

`GET /btx/hcp/v1/capital/workloads/{id}`

**Scope:** `capital:read` · **Effect:** `READ`
**Request:** `Path/query context only` · **Response:** `WorkloadProfileV1_1Envelope`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## createApprovalRule

`POST /btx/hcp/v1/capital/approval-rules`

**Scope:** `policies:admin` · **Effect:** `DRAFT_OR_POLICY`
**Request:** `CreateApprovalRuleV1_1` · **Response:** `ApprovalRuleV1_1Envelope`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## listApprovalRule

`GET /btx/hcp/v1/capital/approval-rules`

**Scope:** `capital:read` · **Effect:** `READ`
**Request:** `Path/query context only` · **Response:** `ApprovalRuleV1_1List`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## getApprovalRule

`GET /btx/hcp/v1/capital/approval-rules/{id}`

**Scope:** `capital:read` · **Effect:** `READ`
**Request:** `Path/query context only` · **Response:** `ApprovalRuleV1_1Envelope`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## createResearchProgram

`POST /btx/hcp/v1/capital/programs`

**Scope:** `research:publish` · **Effect:** `DRAFT_OR_POLICY`
**Request:** `CreateResearchProgramV1_1` · **Response:** `ResearchProgramV1_1Envelope`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## listResearchProgram

`GET /btx/hcp/v1/capital/programs`

**Scope:** `capital:read` · **Effect:** `READ`
**Request:** `Path/query context only` · **Response:** `ResearchProgramV1_1List`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## getResearchProgram

`GET /btx/hcp/v1/capital/programs/{id}`

**Scope:** `capital:read` · **Effect:** `READ`
**Request:** `Path/query context only` · **Response:** `ResearchProgramV1_1Envelope`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## assignEntityRoles

`POST /btx/hcp/v1/reserve/entities/roles`

**Scope:** `entities:admin` · **Effect:** `POLICY`
**Request:** `RoleAssignmentRequest` · **Response:** `Job`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## revokeEntityLink

`POST /btx/hcp/v1/reserve/entities/links/{id}/revoke`

**Scope:** `entities:admin` · **Effect:** `POLICY`
**Request:** `MutationRequest` · **Response:** `EntityLinkV1_1Envelope`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## getReserveSnapshot

`GET /btx/hcp/v1/reserve/portfolios/{id}/snapshot`

**Scope:** `reserve:read` · **Effect:** `READ`
**Request:** `Path/query context only` · **Response:** `ReserveSnapshotV1_1Envelope`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## revokeReservePolicy

`POST /btx/hcp/v1/reserve/policies/{id}/revoke`

**Scope:** `policies:admin` · **Effect:** `POLICY`
**Request:** `MutationRequest` · **Response:** `ReservePolicyV1_1Envelope`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## planReserveReplenishment

`POST /btx/hcp/v1/reserve/replenishment/plans`

**Scope:** `capital:prepare` · **Effect:** `PLAN`
**Request:** `RefRequest` · **Response:** `CapitalPlanV1_1Envelope`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## createTCOComparison

`POST /btx/hcp/v1/capital/comparisons`

**Scope:** `capital:prepare` · **Effect:** `PLAN`
**Request:** `RefRequest` · **Response:** `TCOComparisonV1_1Envelope`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## getTCOComparison

`GET /btx/hcp/v1/capital/comparisons/{id}`

**Scope:** `capital:read` · **Effect:** `READ`
**Request:** `Path/query context only` · **Response:** `TCOComparisonV1_1Envelope`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## createCapitalPlan

`POST /btx/hcp/v1/capital/plans`

**Scope:** `capital:prepare` · **Effect:** `PLAN`
**Request:** `CreateCapitalPlanV1_1` · **Response:** `CapitalPlanV1_1Envelope`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## getCapitalPlan

`GET /btx/hcp/v1/capital/plans/{id}`

**Scope:** `capital:read` · **Effect:** `READ`
**Request:** `Path/query context only` · **Response:** `CapitalPlanV1_1Envelope`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## createAllocationPlan

`POST /btx/hcp/v1/capital/allocations`

**Scope:** `capital:prepare` · **Effect:** `PLAN`
**Request:** `CreateAllocationPlanV1_1` · **Response:** `AllocationPlanV1_1Envelope`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## getAllocationPlan

`GET /btx/hcp/v1/capital/allocations/{id}`

**Scope:** `capital:read` · **Effect:** `READ`
**Request:** `Path/query context only` · **Response:** `AllocationPlanV1_1Envelope`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## createApprovalRequest

`POST /btx/hcp/v1/capital/approvals`

**Scope:** `capital:prepare` · **Effect:** `PLAN`
**Request:** `CreateApprovalRequestV1_1` · **Response:** `ApprovalRequestV1_1Envelope`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## getApprovalRequest

`GET /btx/hcp/v1/capital/approvals/{id}`

**Scope:** `capital:read` · **Effect:** `READ`
**Request:** `Path/query context only` · **Response:** `ApprovalRequestV1_1Envelope`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## recordApprovalDecision

`POST /btx/hcp/v1/capital/approvals/{id}/decisions`

**Scope:** `capital:approve` · **Effect:** `AUTHORIZE`
**Request:** `CreateApprovalDecisionV1_1` · **Response:** `ApprovalDecisionV1_1Envelope`

Derive actor from verified caller; request actor must match. Approval does not execute.

## listApprovalDecisions

`GET /btx/hcp/v1/capital/approvals/{id}/decisions`

**Scope:** `capital:read` · **Effect:** `READ`
**Request:** `Path/query context only` · **Response:** `ApprovalDecisionV1_1List`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## executeAllocation

`POST /btx/hcp/v1/capital/allocations/{id}/execute`

**Scope:** `capital:execute` · **Effect:** `EXECUTE_APPROVED`
**Request:** `MutationRequest` · **Response:** `CapitalExecutionReceiptV1_1Envelope`

Recheck exact plan, quorum, policy and reserve; dispatch only approved child effects.

## getCapitalExecution

`GET /btx/hcp/v1/capital/executions/{id}`

**Scope:** `capital:read` · **Effect:** `READ`
**Request:** `Path/query context only` · **Response:** `CapitalExecutionReceiptV1_1Envelope`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## cancelCapitalExecution

`POST /btx/hcp/v1/capital/executions/{id}/cancel`

**Scope:** `capital:execute` · **Effect:** `CANCEL_SAFE_ONLY`
**Request:** `MutationRequest` · **Response:** `CapitalExecutionReceiptV1_1Envelope`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## listCapabilityPositions

`GET /btx/hcp/v1/capital/positions`

**Scope:** `capital:read` · **Effect:** `READ`
**Request:** `Path/query context only` · **Response:** `CapabilityPositionV1_1List`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## getCapabilityPosition

`GET /btx/hcp/v1/capital/positions/{id}`

**Scope:** `capital:read` · **Effect:** `READ`
**Request:** `Path/query context only` · **Response:** `CapabilityPositionV1_1Envelope`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## createCapabilityPosition

`POST /btx/hcp/v1/capital/positions`

**Scope:** `holdings:write` · **Effect:** `RECORD`
**Request:** `CreateCapabilityPositionV1_1` · **Response:** `CapabilityPositionV1_1Envelope`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## updateCapabilityLifecycle

`POST /btx/hcp/v1/capital/positions/{id}/lifecycle`

**Scope:** `holdings:write` · **Effect:** `RECORD`
**Request:** `LifecycleRequest` · **Response:** `CapabilityPositionV1_1Envelope`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## joinResearchProgram

`POST /btx/hcp/v1/capital/programs/{id}/memberships`

**Scope:** `research:publish` · **Effect:** `MEMBERSHIP_ONLY`
**Request:** `CreateProgramMembershipV1_1` · **Response:** `ProgramMembershipV1_1Envelope`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## prepareProgramCommitment

`POST /btx/hcp/v1/capital/programs/{id}/commitments`

**Scope:** `capital:prepare` · **Effect:** `PLAN`
**Request:** `RefRequest` · **Response:** `AllocationPlanV1_1Envelope`

Creates a proposal, never an unapproved financial commitment.

## listProductOffers

`GET /btx/hcp/v1/capital/products`

**Scope:** `products:read` · **Effect:** `READ`
**Request:** `Path/query context only` · **Response:** `ProductOfferV1_1List`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## getProductOffer

`GET /btx/hcp/v1/capital/products/{id}`

**Scope:** `products:read` · **Effect:** `READ`
**Request:** `Path/query context only` · **Response:** `ProductOfferV1_1Envelope`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## createProductReferral

`POST /btx/hcp/v1/capital/products/{id}/referral`

**Scope:** `products:refer` · **Effect:** `REFERRAL_ONLY`
**Request:** `RefRequest` · **Response:** `Job`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## createReserveReport

`POST /btx/hcp/v1/capital/reports`

**Scope:** `reports:create` · **Effect:** `REPORT`
**Request:** `RefRequest` · **Response:** `Job`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## getReserveReport

`GET /btx/hcp/v1/capital/reports/{id}`

**Scope:** `reports:read` · **Effect:** `READ`
**Request:** `Path/query context only` · **Response:** `ReserveReportV1_1Envelope`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## createCapitalExport

`POST /btx/hcp/v1/capital/exports`

**Scope:** `exports:create` · **Effect:** `EXPORT`
**Request:** `RefRequest` · **Response:** `Job`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.

## getCapitalExport

`GET /btx/hcp/v1/capital/exports/{id}`

**Scope:** `exports:read` · **Effect:** `READ`
**Request:** `Path/query context only` · **Response:** `Job`

Derive authenticated context server-side. Recheck scope, object ownership and policy. Unknown/ambiguous external outcomes remain explicit.
