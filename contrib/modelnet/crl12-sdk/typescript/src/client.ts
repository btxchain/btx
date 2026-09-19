// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
/** Typed CRL/1.2 HCP client. 43 catalogue operations. No /rpc, no executeAllocation. */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const AUTOMATIC_SPEND_ATOMS = 0 as const;

export const ANALYTICS_SCOPES = [
  "catalog:read",
  "capital:read",
  "capital:prepare",
  "projections:read",
  "metrics:read",
  "assets:read",
  "positions:read",
] as const;

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export type Operation = {
  operation_id: string;
  method: "GET" | "POST";
  path: string;
  request_schema: string | null;
  response_schema: string;
  effect: string;
  scope: string;
};
export type HeaderFactory = (method: string, url: string, body: Uint8Array) => Promise<Record<string, string>>;
export type Verifier = (statement: Record<string, Json>) => Promise<void>;

const SECRET_KEYS = new Set([
  "secret",
  "access_token",
  "refresh_token",
  "private_key",
  "password",
  "mnemonic",
  "client_secret",
  "wallet_rpc",
  "api_key",
  "bearer",
  "prompt",
  "private_prompt",
  "id_token",
  "session_token",
]);
const INVENTED = new Set(["grand_total", "combined_aum_auc", "invented_aum", "invented_auc", "unlabeled_combined_total"]);
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

function loadCatalog(): Operation[] {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const p = path.resolve(here, "../../schemas/operations-v1.2.json");
  const data = JSON.parse(readFileSync(p, "utf8")) as { operations: Operation[] };
  if (!Array.isArray(data.operations) || data.operations.length !== 43) {
    throw new Error("CRL v1.2 catalog must contain exactly 43 operations");
  }
  for (const o of data.operations) {
    if (!o.path.startsWith("/btx/hcp/v1/") || o.path === "/rpc" || o.path.startsWith("/rpc/")) {
      throw new Error("GENERIC_RPC_DISABLED");
    }
  }
  return data.operations;
}

export const OPERATIONS: Operation[] = loadCatalog();
export const OPERATION_IDS = OPERATIONS.map((o) => o.operation_id) as readonly string[];

export class Crl12Error extends Error {
  readonly code: string;
  readonly status: number;
  readonly unknown: boolean;
  constructor(code: string, message: string, status = 0) {
    super(code + ": " + message);
    this.name = "Crl12Error";
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

export function containsSecrets(value: unknown): boolean {
  if (value && typeof value === "object") {
    if (Array.isArray(value)) return value.some(containsSecrets);
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const lk = k.toLowerCase();
      if ((SECRET_KEYS.has(lk) || lk.endsWith("_secret")) && v !== null && v !== undefined && v !== "") {
        return true;
      }
      if (typeof v === "string" && v.includes("BEGIN PRIVATE KEY")) return true;
      if (containsSecrets(v)) return true;
    }
  }
  return typeof value === "string" && value.includes("BEGIN PRIVATE KEY");
}

function walkKeys(value: unknown, out: string[] = []): string[] {
  if (value && typeof value === "object") {
    if (Array.isArray(value)) {
      for (const x of value) walkKeys(x, out);
    } else {
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        out.push(k);
        walkKeys(v, out);
      }
    }
  }
  return out;
}

function rejectBody(operation: string, body: unknown): void {
  if (body === undefined || body === null) return;
  if (containsSecrets(body)) {
    throw new Crl12Error("SECRET_INLINE", operation === "createInstitutionalExport"
      ? "export must not include secrets or tokens"
      : "typed HCP bodies must not carry reusable secrets");
  }
  const keys = new Set(walkKeys(body).map((k) => k.toLowerCase()));
  for (const k of INVENTED) {
    if (keys.has(k)) throw new Crl12Error("INVENTED_TOTAL", "never invent combined AUM/AUC");
  }
  if (body && typeof body === "object" && !Array.isArray(body)) {
    const o = body as Record<string, unknown>;
    if (o.remote_inference === true) throw new Crl12Error("REMOTE_INFERENCE_FORBIDDEN", "no public prompt routing");
    if (operation === "commitInstitutionalImport" && o.custody_credit === true) {
      throw new Crl12Error("IMPORT_NOT_CUSTODY", "import is not custody credit");
    }
    if (o.brand_dispatch || o.provider_brand_route) {
      throw new Crl12Error("BRAND_DISPATCH", "generic fixtures only");
    }
  }
}

export type ClientOptions = {
  origin: string;
  headers?: HeaderFactory;
  verify?: Verifier;
  timeoutMs?: number;
  labOrigin?: boolean | string;
  scopes?: readonly string[];
  fetcher?: typeof fetch;
};

export type CallOptions = {
  path?: Record<string, string>;
  query?: Record<string, string>;
  body?: Json | Uint8Array;
  idempotencyKey?: string;
};

export class Crl12Client {
  readonly automaticSpendAtoms = AUTOMATIC_SPEND_ATOMS;
  readonly scopes: readonly string[];
  private readonly ops: Map<string, Operation>;
  private readonly origin: string;
  private readonly options: ClientOptions;
  constructor(options: ClientOptions) {
    assertOrigin(options.origin, options.labOrigin);
    this.options = options;
    this.origin = options.origin.replace(/\/$/, "");
    this.ops = new Map(OPERATIONS.map((o) => [o.operation_id, o]));
    this.scopes = options.scopes ?? [];
  }

  executeAllocation(_id?: string, _body?: Json, _idem?: string): never {
    throw new Crl12Error("SCOPE_DENIED", "CRL/1.2 SDK has no executeAllocation route; analytics cannot execute");
  }

  async call(id: string, options: CallOptions = {}): Promise<Json | Uint8Array> {
    if (id === "executeAllocation" || id === "genericRpc" || id === "/rpc") {
      throw new Crl12Error("SCOPE_DENIED", id + " is not a CRL/1.2 typed route");
    }
    const op = this.ops.get(id);
    if (!op) throw new Error("UNKNOWN_OPERATION");
    if (!op.path.startsWith("/btx/hcp/v1/") || op.path === "/rpc" || op.path.startsWith("/rpc/")) {
      throw new Error("GENERIC_RPC_DISABLED");
    }
    const pathParams = options.path ?? {};
    let route = op.path.replace(/^\/btx\/hcp\/v1/, "");
    const keys = [...route.matchAll(/\{([^}]+)\}/g)].map((x) => x[1]);
    if (keys.sort().join() !== Object.keys(pathParams).sort().join()) throw new Error("PATH_MISMATCH");
    for (const k of keys) {
      const v = pathParams[k] ?? "";
      if (!ID_RE.test(v)) throw new Error("INVALID_ID");
      route = route.replace(`{${k}}`, encodeURIComponent(v));
    }
    if (route.includes("/execute")) {
      throw new Crl12Error("SCOPE_DENIED", "CRL/1.2 client does not call execute paths");
    }
    const url = this.origin + "/btx/hcp/v1" + (route.startsWith("/") ? route : "/" + route) +
      (options.query ? "?" + new URLSearchParams(options.query).toString() : "");
    if (op.request_schema !== "BINARY") rejectBody(id, options.body);
    if (op.method === "POST" && (!options.idempotencyKey || !ID_RE.test(options.idempotencyKey))) {
      throw new Error("IDEMPOTENCY_REQUIRED");
    }
    let bytes: Uint8Array;
    let contentType = "application/json";
    if (op.request_schema === "BINARY") {
      if (!(options.body instanceof Uint8Array) || options.body.byteLength < 1 || options.body.byteLength > 16 * 1024 * 1024) {
        throw new Error("BINARY_CHUNK_REQUIRED");
      }
      bytes = options.body;
      contentType = "application/octet-stream";
    } else {
      const text = options.body === undefined ? "" : JSON.stringify(options.body);
      bytes = new TextEncoder().encode(text);
      if (bytes.byteLength > 1048576) throw new Error("BODY_TOO_LARGE");
    }
    const h = await (this.options.headers ?? (async () => ({})))(op.method, url, bytes);
    h["Accept"] = op.response_schema === "BINARY" ? "application/octet-stream" : "application/json";
    h["Content-Type"] = contentType;
    if (options.idempotencyKey) h["Idempotency-Key"] = options.idempotencyKey;
    if (op.request_schema === "BINARY") h["X-Content-SHA384"] = createHash("sha384").update(bytes).digest("hex");
    const c = new AbortController();
    const timer = setTimeout(() => c.abort(), this.options.timeoutMs ?? 30000);
    try {
      const r = await (this.options.fetcher ?? fetch)(url, {
        method: op.method,
        headers: h,
        body: op.method === "POST" ? bytes : undefined,
        redirect: "error",
        signal: c.signal,
      });
      if (r.status === 202) {
        let parsed: unknown;
        try {
          parsed = JSON.parse(await r.text());
        } catch {
          return { status: 202, unknown: true };
        }
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
          return { ...(parsed as Record<string, Json>), status: 202, unknown: true };
        }
        return { status: 202, unknown: true };
      }
      if (op.response_schema === "BINARY") {
        if (!r.ok) throw new Crl12Error("HTTP", "binary", r.status);
        return new Uint8Array(await r.arrayBuffer());
      }
      const data = JSON.parse(await r.text()) as Json;
      if (!r.ok) throw new Crl12Error("HTTP", JSON.stringify(data), r.status);
      if (data && typeof data === "object" && !Array.isArray(data) && "object_type" in data && this.options.verify) {
        await this.options.verify(data as Record<string, Json>);
      }
      return data;
    } catch (err) {
      const name = err instanceof Error ? err.name : "";
      if (name === "TimeoutError" || name === "AbortError") {
        throw new Crl12Error("UNKNOWN", "timeout", 0);
      }
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }
}

export const CrlClient = Crl12Client;
export const CognitiveReserveLayerClient = Crl12Client;

export function analyticsClient(options: Omit<ClientOptions, "scopes"> & { scopes?: readonly string[] }): Crl12Client {
  return new Crl12Client({ ...options, scopes: options.scopes ?? ANALYTICS_SCOPES });
}
