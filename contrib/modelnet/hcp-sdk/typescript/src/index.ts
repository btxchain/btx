// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
/** HCP/1 TypeScript SDK. Atom amounts stay decimal strings. Never auto-submit on timeout. */

export {
  bodyId,
  body_id,
  canonicalBody,
  canonical_body,
} from "./body_id.ts";
export type { JsonValue } from "./body_id.ts";

/** Envelope wrapper. `body_id` is hex SHA-384; this client does not sign. */
export type HcpEnvelope = {
  object_type: string;
  body: Record<string, unknown>;
  body_id: string;
  signer_key_id: string;
  signature: string | null;
};

/** Cursor page query for list endpoints. */
export type HcpPageQuery = {
  cursor?: string;
  limit?: number;
};

/** automatic_spend_atoms stays 0; this SDK never increments it. */
export const AUTOMATIC_SPEND_ATOMS = 0 as const;

export class HcpError extends Error {
  readonly code: string;
  readonly status: number;
  constructor(code: string, message: string, status = 0) {
    super(code + ": " + message);
    this.name = "HcpError";
    this.code = code;
    this.status = status;
  }
}

type JsonBody = Record<string, unknown>;

type ReqInit = {
  idempotencyKey?: string;
  accept?: string;
};

function pathId(id: string): string {
  return encodeURIComponent(id);
}

function withQuery(path: string, query?: HcpPageQuery): string {
  if (!query) return path;
  const usp = new URLSearchParams();
  if (query.cursor !== undefined && query.cursor !== "") usp.set("cursor", query.cursor);
  if (query.limit !== undefined) usp.set("limit", String(query.limit));
  const s = usp.toString();
  return s ? path + "?" + s : path;
}

/** 202 body when the response is empty or not JSON. Never treat as settlement. */
function unknown202(): { status: 202; unknown: true } {
  return { status: 202, unknown: true };
}

export class HcpClient {
  readonly base: string;
  accessToken?: string;
  dpop?: string;

  constructor(base: string, accessToken?: string, dpop?: string) {
    this.base = base;
    this.accessToken = accessToken;
    this.dpop = dpop;
  }

  private root(): string {
    return this.base.replace(/\/$/, "");
  }

  private headers(init: ReqInit, hasJsonBody: boolean): Record<string, string> {
    const headers: Record<string, string> = {
      Accept: init.accept ?? "application/json",
    };
    if (hasJsonBody) headers["Content-Type"] = "application/json";
    if (this.accessToken) headers.Authorization = "Bearer " + this.accessToken;
    if (this.dpop) headers.DPoP = this.dpop;
    if (init.idempotencyKey) headers["Idempotency-Key"] = init.idempotencyKey;
    return headers;
  }

  /**
   * HTTP helper. HTTP 202 is UNKNOWN / accepted async work — returned as-is.
   * Does not authorize, submit, or cancel as a follow-up. Timeouts throw
   * HcpError UNKNOWN and do not retry a finance mutation.
   */
  private async raw(
    method: string,
    path: string,
    body?: unknown,
    init: ReqInit = {},
  ): Promise<Response> {
    const hasJsonBody = body !== undefined;
    let res: Response;
    try {
      res = await fetch(this.root() + path, {
        method,
        headers: this.headers(init, hasJsonBody),
        body: hasJsonBody ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(30_000),
      });
    } catch (err) {
      const name = err instanceof Error ? err.name : "";
      if (name === "TimeoutError" || name === "AbortError") {
        throw new HcpError("UNKNOWN", "timeout", 0);
      }
      throw err;
    }
    return res;
  }

  private async req(method: string, path: string, body?: unknown, init: ReqInit = {}): Promise<unknown> {
    const res = await this.raw(method, path, body, init);
    const text = await res.text();
    if (res.status === 202) {
      // UNKNOWN — never auto-submit / authorize / cancel from this branch.
      if (!text) return unknown202();
      try {
        return JSON.parse(text);
      } catch {
        return unknown202();
      }
    }
    const parsed = text ? (() => {
      try {
        return JSON.parse(text);
      } catch {
        return { raw: text };
      }
    })() : {};
    if (!res.ok) {
      const msg = typeof parsed === "object" && parsed !== null ? JSON.stringify(parsed) : String(parsed);
      throw new HcpError("HTTP", msg, res.status);
    }
    return parsed;
  }

  private async reqBytes(method: string, path: string, init: ReqInit = {}): Promise<Uint8Array> {
    const res = await this.raw(method, path, undefined, {
      ...init,
      accept: init.accept ?? "application/octet-stream",
    });
    if (res.status === 202) {
      // UNKNOWN — do not follow with submit.
      return new Uint8Array(await res.arrayBuffer());
    }
    if (!res.ok) {
      const text = await res.text();
      throw new HcpError("HTTP", text || res.statusText, res.status);
    }
    return new Uint8Array(await res.arrayBuffer());
  }

  private async reqStream(path: string): Promise<ReadableStream<Uint8Array>> {
    const res = await this.raw("GET", path, undefined, { accept: "text/event-stream" });
    if (res.status === 202) {
      // UNKNOWN — return the stream if present; never auto-submit.
      if (!res.body) throw new HcpError("UNKNOWN", "empty 202 stream", 202);
      return res.body;
    }
    if (!res.ok) {
      const text = await res.text();
      throw new HcpError("HTTP", text || res.statusText, res.status);
    }
    if (!res.body) throw new HcpError("HTTP", "empty event stream", res.status);
    return res.body;
  }

  // --- 34 REST operations (src/modelnet/hcp/schemas/rpc-catalog.json) ---

  /** GET /profile */
  getProfile() {
    return this.req("GET", "/profile");
  }

  /**
   * POST /capabilities/search
   * String form sends `{ query, limit: 20 }`. Object form is sent as-is.
   */
  search(q: string | JsonBody = "") {
    const body: JsonBody = typeof q === "object" && q !== null ? q : { query: q, limit: 20 };
    return this.req("POST", "/capabilities/search", body);
  }

  /** GET /packages/{package_core_id} — exact BTXPKG1 bytes, not JSON. */
  getPackage(packageCoreId: string) {
    return this.reqBytes("GET", "/packages/" + pathId(packageCoreId));
  }

  /** GET /economy/{target_id} */
  getEconomy(targetId: string) {
    return this.req("GET", "/economy/" + pathId(targetId));
  }

  /**
   * POST /handoffs
   * Object form is the CreateHandoffRequest body. The 3-string form keeps the
   * original helper (device_id, package_core_id, recipe_id).
   */
  createHandoff(
    bodyOrDeviceId: JsonBody | string,
    packageCoreIdOrKey?: string,
    recipeId?: string,
  ) {
    if (typeof bodyOrDeviceId === "string") {
      return this.req("POST", "/handoffs", {
        device_id: bodyOrDeviceId,
        package_core_id: packageCoreIdOrKey,
        recipe_id: recipeId,
      });
    }
    return this.req("POST", "/handoffs", bodyOrDeviceId, {
      idempotencyKey: packageCoreIdOrKey,
    });
  }

  /** GET /handoffs/{handoff_id} */
  getHandoff(handoffId: string) {
    return this.req("GET", "/handoffs/" + pathId(handoffId));
  }

  /** POST /devices/enroll */
  enrollDevice(body: JsonBody, idempotencyKey?: string) {
    return this.req("POST", "/devices/enroll", body, { idempotencyKey });
  }

  /** POST /devices/{device_id}/confirm */
  confirmDevice(deviceId: string, body: JsonBody, idempotencyKey?: string) {
    return this.req("POST", "/devices/" + pathId(deviceId) + "/confirm", body, { idempotencyKey });
  }

  /** POST /devices/{device_id}/revoke */
  revokeDevice(deviceId: string, idempotencyKey?: string) {
    return this.req("POST", "/devices/" + pathId(deviceId) + "/revoke", {}, { idempotencyKey });
  }

  /** GET /devices/{device_id}/handoffs */
  getDeviceHandoffs(deviceId: string, query?: HcpPageQuery) {
    return this.req("GET", withQuery("/devices/" + pathId(deviceId) + "/handoffs", query));
  }

  /**
   * POST /devices/{device_id}/reports — HTTP 202 UNKNOWN.
   * Returns the 202 body. Does not auto-submit finance.
   */
  reportReadiness(deviceId: string, body: JsonBody, idempotencyKey?: string) {
    return this.req("POST", "/devices/" + pathId(deviceId) + "/reports", body, { idempotencyKey });
  }

  /** GET /treasury/balances */
  getBalances() {
    return this.req("GET", "/treasury/balances");
  }

  /** POST /finance/quotes — keep *_atoms fields as decimal strings. */
  createFundingQuote(body: JsonBody, idempotencyKey?: string) {
    return this.req("POST", "/finance/quotes", body, { idempotencyKey });
  }

  /** POST /finance/intents — keep *_atoms fields as decimal strings. */
  createFinanceIntent(body: JsonBody, idempotencyKey?: string) {
    return this.req("POST", "/finance/intents", body, { idempotencyKey });
  }

  /** Alias of createFinanceIntent (amounts remain decimal strings). */
  createIntent(body: Record<string, string>, idempotencyKey?: string) {
    return this.createFinanceIntent(body, idempotencyKey);
  }

  /** GET /finance/intents/{intent_id} */
  getFinanceIntent(intentId: string) {
    return this.req("GET", "/finance/intents/" + pathId(intentId));
  }

  /** POST /finance/intents/{intent_id}/authorize */
  authorizeFinanceIntent(intentId: string, body: JsonBody, idempotencyKey?: string) {
    return this.req("POST", "/finance/intents/" + pathId(intentId) + "/authorize", body, {
      idempotencyKey,
    });
  }

  /**
   * POST /finance/intents/{intent_id}/submit — HTTP 202 UNKNOWN.
   * Caller must pass expected_body_id. This method does not chain from 202.
   */
  submitFinanceIntent(intentId: string, body: JsonBody, idempotencyKey?: string) {
    return this.req("POST", "/finance/intents/" + pathId(intentId) + "/submit", body, {
      idempotencyKey,
    });
  }

  /**
   * POST /finance/intents/{intent_id}/cancel — HTTP 202 UNKNOWN.
   * Not invoked automatically on timeout or a lost submit.
   */
  cancelFinanceIntent(intentId: string, body: JsonBody, idempotencyKey?: string) {
    return this.req("POST", "/finance/intents/" + pathId(intentId) + "/cancel", body, {
      idempotencyKey,
    });
  }

  /** GET /finance/intents/{intent_id}/receipts */
  getFinanceReceipts(intentId: string, query?: HcpPageQuery) {
    return this.req("GET", withQuery("/finance/intents/" + pathId(intentId) + "/receipts", query));
  }

  /** GET /finance/receipts/{receipt_id} */
  getFinanceReceipt(receiptId: string) {
    return this.req("GET", "/finance/receipts/" + pathId(receiptId));
  }

  /** POST /policies */
  createAccountPolicy(body: JsonBody, idempotencyKey?: string) {
    return this.req("POST", "/policies", body, { idempotencyKey });
  }

  /** GET /policies/{policy_id} */
  getAccountPolicy(policyId: string) {
    return this.req("GET", "/policies/" + pathId(policyId));
  }

  /** POST /policies/{policy_id}/revoke */
  revokeAccountPolicy(policyId: string, idempotencyKey?: string) {
    return this.req("POST", "/policies/" + pathId(policyId) + "/revoke", {}, { idempotencyKey });
  }

  /** POST /subscriptions */
  createSubscription(body: JsonBody, idempotencyKey?: string) {
    return this.req("POST", "/subscriptions", body, { idempotencyKey });
  }

  /** POST /subscriptions/{subscription_id}/revoke */
  revokeSubscription(subscriptionId: string, idempotencyKey?: string) {
    return this.req("POST", "/subscriptions/" + pathId(subscriptionId) + "/revoke", {}, {
      idempotencyKey,
    });
  }

  /** GET /events */
  getEvents(query?: HcpPageQuery) {
    return this.req("GET", withQuery("/events", query));
  }

  /** GET /events/stream — SSE. Does not JSON-parse the body. */
  streamEvents() {
    return this.reqStream("/events/stream");
  }

  /**
   * POST /exports — HTTP 202 UNKNOWN.
   * Returns the 202 body. Does not auto-submit finance.
   */
  createExport(body: JsonBody, idempotencyKey?: string) {
    return this.req("POST", "/exports", body, { idempotencyKey });
  }

  /** GET /exports/{export_id} */
  getExport(exportId: string) {
    return this.req("GET", "/exports/" + pathId(exportId));
  }

  /** POST /research/drafts */
  createResearchDraft(body: JsonBody, idempotencyKey?: string) {
    return this.req("POST", "/research/drafts", body, { idempotencyKey });
  }

  /** POST /research/drafts/{draft_id}/validate */
  validateResearchDraft(draftId: string) {
    return this.req("POST", "/research/drafts/" + pathId(draftId) + "/validate", {});
  }

  /**
   * POST /research/drafts/{draft_id}/publish — HTTP 202 UNKNOWN.
   * Returns the 202 body. Does not auto-submit finance.
   */
  publishResearchDraft(draftId: string, body: JsonBody, idempotencyKey?: string) {
    return this.req("POST", "/research/drafts/" + pathId(draftId) + "/publish", body, {
      idempotencyKey,
    });
  }

  /** GET /research/submissions/{submission_id} */
  getResearchSubmission(submissionId: string) {
    return this.req("GET", "/research/submissions/" + pathId(submissionId));
  }

  /** GET /operations/{operation_id} — poll UNKNOWN / 202 work. */
  getOperation(operationId: string) {
    return this.req("GET", "/operations/" + pathId(operationId));
  }

  /** Alias of getOperation. */
  pollOperation(id: string) {
    return this.getOperation(id);
  }
}
