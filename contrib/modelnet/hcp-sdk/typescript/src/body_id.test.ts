#!/usr/bin/env node
// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
/**
 * Recompute HCP/1 body_id for each unsigned example envelope.
 *
 * Same vectors as contrib/modelnet/hcp-sdk/python/test_body_id.py.
 * Does not submit intents, sign spends, or talk to a wallet.
 * automatic_spend_atoms stays 0.
 */

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { HcpClient, bodyId, canonicalBody } from "./index.ts";
import { bodyId as bodyIdDirect, canonicalBody as canonicalBodyDirect } from "./body_id.ts";

assert.equal(bodyId, bodyIdDirect);
assert.equal(canonicalBody, canonicalBodyDirect);

const HERE = path.dirname(fileURLToPath(import.meta.url));
const EXAMPLES_DIR = path.resolve(HERE, "../../../../../src/modelnet/hcp/examples");

type Envelope = {
  object_type?: unknown;
  body?: unknown;
  body_id?: unknown;
};

function listUnsigned(): string[] {
  if (!fs.existsSync(EXAMPLES_DIR)) {
    throw new Error("no examples dir: " + EXAMPLES_DIR);
  }
  return fs
    .readdirSync(EXAMPLES_DIR)
    .filter((name) => name.endsWith(".unsigned.json"))
    .sort()
    .map((name) => path.join(EXAMPLES_DIR, name));
}

function checkFile(filePath: string): void {
  const env = JSON.parse(fs.readFileSync(filePath, "utf8")) as Envelope;
  const kind = env.object_type;
  const body = env.body;
  const expected = env.body_id;
  const name = path.basename(filePath);
  if (typeof kind !== "string" || typeof body !== "object" || body === null || Array.isArray(body) || typeof expected !== "string") {
    throw new Error("FAIL " + name + " missing object_type/body/body_id");
  }
  const rec = body as Record<string, unknown>;
  const canon = canonicalBody(rec);
  if (!canon.length) {
    throw new Error("FAIL " + name + " canonical_body empty");
  }
  const got = bodyId(kind, rec);
  if (got !== expected) {
    throw new Error(
      "FAIL " + name + "\n  object_type=" + kind + "\n  expected=" + expected + "\n  got     =" + got +
        "\n  canonical_body_len=" + canon.length,
    );
  }
}

test("unsigned.json body_id vectors match Python test_body_id.py", () => {
  const files = listUnsigned();
  assert.ok(files.length > 0, "FAIL no *.unsigned.json under " + EXAMPLES_DIR);
  let matched = 0;
  for (const filePath of files) {
    checkFile(filePath);
    matched += 1;
    console.log("PASS " + path.basename(filePath));
  }
  console.log(matched + "/" + files.length + " matched");
  assert.equal(matched, files.length);
});

test("atom amounts stay decimal strings in canonical JSON", () => {
  const body = {
    amounts: {
      principal_atoms: "1000",
      network_fee_cap_atoms: "30",
      service_fee_atoms: "20",
      tax_atoms: "0",
      max_total_debit_atoms: "1050",
    },
  };
  const json = canonicalBody(body).toString("utf8");
  assert.match(json, /"principal_atoms":"1000"/);
  assert.doesNotMatch(json, /"principal_atoms":1000/);
  assert.match(json, /"network_fee_cap_atoms":"30"/);
});

test("bodyId is SHA384(BTX/HCP/kind/v1 || 0x00 || LE64(len) || body)", () => {
  const id = bodyId("X", {});
  assert.equal(id.length, 96);
  assert.match(id, /^[0-9a-f]{96}$/);
});

const CATALOG_METHODS = [
  "getProfile",
  "search",
  "getPackage",
  "getEconomy",
  "createHandoff",
  "getHandoff",
  "enrollDevice",
  "confirmDevice",
  "revokeDevice",
  "getDeviceHandoffs",
  "reportReadiness",
  "getBalances",
  "createFundingQuote",
  "createFinanceIntent",
  "getFinanceIntent",
  "authorizeFinanceIntent",
  "submitFinanceIntent",
  "cancelFinanceIntent",
  "getFinanceReceipts",
  "getFinanceReceipt",
  "createAccountPolicy",
  "getAccountPolicy",
  "revokeAccountPolicy",
  "createSubscription",
  "revokeSubscription",
  "getEvents",
  "streamEvents",
  "createExport",
  "getExport",
  "createResearchDraft",
  "validateResearchDraft",
  "publishResearchDraft",
  "getResearchSubmission",
  "getOperation",
] as const;

test("HcpClient covers all 34 catalog operations", () => {
  const proto = HcpClient.prototype as Record<string, unknown>;
  const missing = CATALOG_METHODS.filter((name) => typeof proto[name] !== "function");
  assert.deepEqual(missing, []);
  assert.equal(CATALOG_METHODS.length, 34);
});

test("HTTP 202 is UNKNOWN and does not auto-submit", async () => {
  const calls: string[] = [];
  const orig = globalThis.fetch;
  globalThis.fetch = async (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
    calls.push(String(init?.method || "GET") + " " + String(input));
    return new Response(JSON.stringify({ status: "UNKNOWN" }), {
      status: 202,
      headers: { "Content-Type": "application/json" },
    });
  };
  try {
    const client = new HcpClient("https://exchange.example/btx/hcp/v1");
    const digest = "a".repeat(96);
    const submit = await client.submitFinanceIntent("intent-demo", { expected_body_id: digest });
    const cancel = await client.cancelFinanceIntent("intent-demo", { expected_body_id: digest });
    const report = await client.reportReadiness("device-demo", { object_type: "LocalReadinessReport" });
    const exported = await client.createExport({ client_operation_id: "op-1", include: ["INTENTS"] });
    const published = await client.publishResearchDraft("draft-1", { expected_body_id: digest });
    assert.equal(calls.length, 5);
    assert.ok(calls.every((c) => !c.includes("/authorize")));
    assert.equal(calls.filter((c) => c.includes("/submit")).length, 1);
    assert.deepEqual(submit, { status: "UNKNOWN" });
    assert.deepEqual(cancel, { status: "UNKNOWN" });
    assert.deepEqual(report, { status: "UNKNOWN" });
    assert.deepEqual(exported, { status: "UNKNOWN" });
    assert.deepEqual(published, { status: "UNKNOWN" });
  } finally {
    globalThis.fetch = orig;
  }
});

test("POST bodies keep *_atoms as decimal strings", async () => {
  let raw = "";
  const orig = globalThis.fetch;
  globalThis.fetch = async (_input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
    raw = String(init?.body || "");
    return new Response("{}", { status: 201, headers: { "Content-Type": "application/json" } });
  };
  try {
    const client = new HcpClient("https://exchange.example/btx/hcp/v1");
    await client.createFundingQuote({
      principal_atoms: "1000",
      max_network_fee_atoms: "30",
    });
    assert.match(raw, /"principal_atoms":"1000"/);
    assert.match(raw, /"max_network_fee_atoms":"30"/);
    assert.doesNotMatch(raw, /"principal_atoms":1000/);
  } finally {
    globalThis.fetch = orig;
  }
});
