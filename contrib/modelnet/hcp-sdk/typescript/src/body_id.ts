// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// HCP/1 body_id: SHA-384 over domain-separated canonical JSON.
// Matches contrib/modelnet/hcp-sdk/python/btx_hcp.py (json.dumps
// sort_keys compact UTF-8, not a wallet / not native BTX-PJSON1).
// Amounts stay decimal strings. automatic_spend_atoms stays 0.

import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";

/** Sorted compact JSON object (Python json.dumps sort_keys, separators=(',', ':'), ensure_ascii=False). */
export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

function sorted(value: unknown): unknown {
  if (value === null || typeof value !== "object") {
    if (typeof value === "number" && !Number.isFinite(value)) {
      throw new TypeError("non-finite number");
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(sorted);
  }
  const obj = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(obj).sort()) {
    out[key] = sorted(obj[key]);
  }
  return out;
}

/** Canonical body bytes: UTF-8 compact JSON with lexicographically sorted object keys. */
export function canonicalBody(body: Record<string, unknown>): Buffer {
  const json = JSON.stringify(sorted(body));
  if (typeof json !== "string" || json === "") {
    throw new TypeError("canonical_body empty");
  }
  return Buffer.from(json, "utf8");
}

/**
 * body_id = SHA384( UTF8("BTX/HCP/" + kind + "/v1") || 0x00 || LE64(len(canonical_body)) || canonical_body )
 *
 * `kind` is envelope `object_type`. Hex digest is lowercase (96 hex chars).
 */
export function bodyId(object_type: string, body: Record<string, unknown>): string {
  const b = canonicalBody(body);
  const prefix = Buffer.from("BTX/HCP/" + object_type + "/v1", "utf8");
  const sep = Buffer.from([0]);
  const len = Buffer.alloc(8);
  len.writeBigUInt64LE(BigInt(b.length), 0);
  return createHash("sha384").update(Buffer.concat([prefix, sep, len, b])).digest("hex");
}

export { bodyId as body_id, canonicalBody as canonical_body };
