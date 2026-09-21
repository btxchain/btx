// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// CRL v1.2 body_id: SHA-384 over domain-separated canonical JSON.
// Matches contrib/modelnet/crl12-sdk/python/btx_crl12.py.
// automatic_spend_atoms stays 0.

import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

/** Exact engine V1_2 object types (src/modelnet/hcp_types.h). */
export const OBJECT_TYPES = [
  "LayerExtensionProfileV1_2",
  "ProviderRoleManifestV1_2",
  "ServiceBindingV1_2",
  "AdapterCapabilityReportV1_2",
  "InstitutionalAssetV1_2",
  "AssetRightsV1_2",
  "PositionObservationV1_2",
  "ValuationObservationV1_2",
  "ExposureLinkV1_2",
  "PortfolioProjectionV1_2",
  "MetricDefinitionV1_2",
  "ExportManifestV1_2",
  "ImportManifestV1_2",
  "ReconciliationBreakV1_2",
  "PortfolioInstructionV1_2",
  "InstitutionalScenarioResultV1_2",
  "LayerConformanceClaimV1_2",
  "LayerJobV1_2",
] as const;

export type ObjectTypeV1_2 = (typeof OBJECT_TYPES)[number];

const OBJECT_TYPE_SET: ReadonlySet<string> = new Set(OBJECT_TYPES);

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

export function canonicalBody(body: Record<string, unknown>): Buffer {
  const json = JSON.stringify(sorted(body));
  if (typeof json !== "string" || json === "") {
    throw new TypeError("canonical_body empty");
  }
  return Buffer.from(json, "utf8");
}

/**
 * body_id = SHA384( UTF8("BTX/HCP/" + object_type + "/v1") || 0x00 || LE64(len(canonical_body)) || canonical_body )
 */
export function bodyId(object_type: string, body: Record<string, unknown>): string {
  if (!OBJECT_TYPE_SET.has(object_type)) {
    throw new TypeError("unsupported object_type " + object_type);
  }
  const b = canonicalBody(body);
  const prefix = Buffer.from("BTX/HCP/" + object_type + "/v1", "utf8");
  const sep = Buffer.from([0]);
  const len = Buffer.alloc(8);
  len.writeBigUInt64LE(BigInt(b.length), 0);
  return createHash("sha384").update(Buffer.concat([prefix, sep, len, b])).digest("hex");
}

export { bodyId as body_id, canonicalBody as canonical_body };
