// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
/** Typed HCP Cognitive Reserve Layer v1.2 client. 43 ops. automatic_spend_atoms stays 0. */

export {
  bodyId,
  body_id,
  canonicalBody,
  canonical_body,
  OBJECT_TYPES,
} from "./body_id.ts";
export type { JsonValue, ObjectTypeV1_2 } from "./body_id.ts";

export {
  ANALYTICS_SCOPES,
  AUTOMATIC_SPEND_ATOMS,
  Crl12Client,
  Crl12Error,
  CrlClient,
  CognitiveReserveLayerClient,
  OPERATION_IDS,
  OPERATIONS,
  analyticsClient,
  containsSecrets,
} from "./client.ts";
export type { CallOptions, ClientOptions, Json, Operation } from "./client.ts";

export {
  CONTEXT_TYPE,
  DRAFT_PURPOSES,
  DesktopContextError,
  VIEW_PURPOSES,
  applyDesktopContext,
  apply_desktop_context,
} from "./desktop_context.ts";
export type { DesktopPlan, PlannedOp } from "./desktop_context.ts";
