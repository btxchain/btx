// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
/** Desktop context is view/draft only. Never HTTP, never localhost execute. */

export const CONTEXT_TYPE = "btx.cognitiveReserve.v1_2";
export const VIEW_PURPOSES = ["INSPECT", "COMPARE"] as const;
export const DRAFT_PURPOSES = [
  "DRAFT",
  "DRAFT_RESERVE_ALLOCATION",
  "DRAFT_RESEARCH_COMMITMENT",
  "DRAFT_CAPABILITY_ACQUISITION",
  "DRAFT_PRODUCT_REFERRAL",
] as const;

const FORBIDDEN_KEYS = new Set([
  "access_token",
  "refresh_token",
  "id_token",
  "token",
  "private_key",
  "secret",
  "mnemonic",
  "wallet_rpc",
  "prompt",
  "private_prompt",
  "local_path",
  "cwd",
  "automatic_spend_atoms",
  "grand_total",
  "combined_aum_auc",
  "invented_aum",
  "invented_auc",
]);
const FORBIDDEN_SUBSTR = ["127.0.0.1", "localhost", "/capital/allocations/", "/execute", "BEGIN PRIVATE KEY"];

export class DesktopContextError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(code + ": " + message);
    this.name = "DesktopContextError";
    this.code = code;
  }
}

export type PlannedOp = {
  operation_id: string;
  method: "GET" | "POST";
  path?: Record<string, string>;
  body?: Record<string, unknown>;
};

export type DesktopPlan = {
  type: typeof CONTEXT_TYPE;
  purpose: string;
  operations: PlannedOp[];
  http: false;
  localhost: false;
  execute: false;
  view_or_draft: true;
};

function walk(value: unknown): void {
  if (value && typeof value === "object") {
    if (Array.isArray(value)) {
      for (const item of value) walk(item);
      return;
    }
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const lk = k.toLowerCase();
      if ((FORBIDDEN_KEYS.has(lk) || lk.endsWith("_secret")) && v !== null && v !== undefined && v !== "") {
        throw new DesktopContextError("SECRET_INLINE", "context must not carry " + k);
      }
      if (typeof v === "string") {
        const low = v.toLowerCase();
        for (const needle of FORBIDDEN_SUBSTR) {
          if (low.includes(needle.toLowerCase())) {
            throw new DesktopContextError("LOCALHOST_EXECUTE_FORBIDDEN", needle);
          }
        }
      }
      walk(v);
    }
    return;
  }
  if (typeof value === "string") {
    const low = value.toLowerCase();
    for (const needle of FORBIDDEN_SUBSTR) {
      if (low.includes(needle.toLowerCase())) {
        throw new DesktopContextError("LOCALHOST_EXECUTE_FORBIDDEN", needle);
      }
    }
  }
}

export function applyDesktopContext(ctx: Record<string, unknown>): DesktopPlan {
  walk(ctx);
  if (ctx.type !== CONTEXT_TYPE) {
    throw new DesktopContextError("UNKNOWN_CONTEXT_TYPE", String(ctx.type));
  }
  const btx = ctx.btx;
  if (!btx || typeof btx !== "object" || Array.isArray(btx)) {
    throw new DesktopContextError("MISSING_BTX", "btx object required");
  }
  const b = btx as Record<string, unknown>;
  const purpose = String(b.purpose ?? "");
  const allowed = new Set<string>([...VIEW_PURPOSES, ...DRAFT_PURPOSES]);
  if (!allowed.has(purpose)) {
    throw new DesktopContextError("VIEW_DRAFT_ONLY", purpose || "missing purpose");
  }
  const ops: PlannedOp[] = [];
  const asset = b.asset_ref;
  const projection = b.projection_ref;
  if ((VIEW_PURPOSES as readonly string[]).includes(purpose)) {
    if (typeof asset === "string" && asset) {
      ops.push({ operation_id: "getInstitutionalAsset", method: "GET", path: { id: asset } });
    }
    if (typeof projection === "string" && projection) {
      ops.push({ operation_id: "getPortfolioProjection", method: "GET", path: { id: projection } });
    }
    if (purpose === "COMPARE") {
      ops.push({ operation_id: "listInstitutionalMetrics", method: "GET" });
    }
  } else {
    const body: Record<string, unknown> = {
      requested_action: purpose === "DRAFT" ? "DRAFT_RESERVE_ALLOCATION" : purpose,
      execute: false,
    };
    if (typeof projection === "string" && projection) body.source_projection_ref = projection;
    ops.push({ operation_id: "preparePortfolioInstruction", method: "POST", body });
  }
  for (const op of ops) {
    if (op.operation_id === "executeAllocation") {
      throw new DesktopContextError("VIEW_DRAFT_ONLY", op.operation_id);
    }
  }
  return {
    type: CONTEXT_TYPE,
    purpose,
    operations: ops,
    http: false,
    localhost: false,
    execute: false,
    view_or_draft: true,
  };
}

export { applyDesktopContext as apply_desktop_context };
