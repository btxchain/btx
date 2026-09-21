#!/usr/bin/env node
// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
/**
 * CRF v1.1 SDK tests: 50 operation_ids, 18 type domain separation, HTTP 202.
 * Does not submit spends, sign, or talk to a wallet. automatic_spend_atoms stays 0.
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  AUTOMATIC_SPEND_ATOMS,
  CognitiveReserveClient,
  Cr11Error,
  OBJECT_TYPES,
  OPERATION_IDS,
  bodyId,
  canonicalBody,
} from "./index.ts";
import { bodyId as bodyIdDirect, canonicalBody as canonicalBodyDirect } from "./body_id.ts";

assert.equal(bodyId, bodyIdDirect);
assert.equal(canonicalBody, canonicalBodyDirect);

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CATALOG = path.resolve(HERE, "../../schemas/operations-v1.1.json");
const EXAMPLES = path.resolve(HERE, "../../../../../src/modelnet/crf/examples/valid");

function clientOpts(origin: string, extra: Record<string, unknown> = {}) {
  return {
    origin,
    authHeaders: async () => ({}),
    validate: () => undefined,
    ...extra,
  };
}

test("eighteen types are domain-separated", () => {
  assert.equal(OBJECT_TYPES.length, 18);
  assert.equal(new Set(OBJECT_TYPES).size, 18);
  const body = { schema_revision: "1.1", provider_id: "p", created_at: "1" };
  const ids = OBJECT_TYPES.map((t) => bodyId(t, body));
  assert.equal(new Set(ids).size, 18);
  assert.match(ids[0]!, /^[0-9a-f]{96}$/);
  const canon = canonicalBody(body);
  for (const kind of OBJECT_TYPES) {
    const prefix = Buffer.from("BTX/HCP/" + kind + "/v1", "utf8");
    const sep = Buffer.from([0]);
    const len = Buffer.alloc(8);
    len.writeBigUInt64LE(BigInt(canon.length), 0);
    const expected = createHash("sha384").update(Buffer.concat([prefix, sep, len, canon])).digest("hex");
    assert.equal(bodyId(kind, body), expected);
  }
});

test("bodyId rejects unknown and Core v4 types", () => {
  const body = { schema_revision: "1.1", provider_id: "p", created_at: "1" };
  assert.throws(() => bodyId("PortfolioV4", body));
  assert.throws(() => bodyId("ProviderProfile", body));
  assert.ok(OBJECT_TYPES.every((t) => !t.includes("V4")));
});

test("catalog has 50 unique operation_ids and client covers them", () => {
  const catalog = JSON.parse(fs.readFileSync(CATALOG, "utf8")) as {
    operations: { operation_id: string; path: string }[];
  };
  const ids = catalog.operations.map((o) => o.operation_id);
  assert.equal(ids.length, 50);
  assert.equal(new Set(ids).size, 50);
  assert.deepEqual(ids, [...OPERATION_IDS]);
  const proto = CognitiveReserveClient.prototype as Record<string, unknown>;
  const missing = OPERATION_IDS.filter((name) => typeof proto[name] !== "function");
  assert.deepEqual(missing, []);
  assert.ok(catalog.operations.every((o) => o.path.startsWith("/btx/hcp/v1/")));
  assert.ok(catalog.operations.every((o) => o.path !== "/rpc" && !o.path.startsWith("/rpc/")));
});

test("example vectors match body_id", () => {
  const files = fs.readdirSync(EXAMPLES).filter((n) => n.endsWith(".json")).sort();
  assert.equal(files.length, 18);
  const seen = new Set<string>();
  for (const name of files) {
    const env = JSON.parse(fs.readFileSync(path.join(EXAMPLES, name), "utf8")) as {
      object_type: string;
      body: Record<string, unknown>;
      body_id: string;
    };
    seen.add(env.object_type);
    assert.equal(bodyId(env.object_type, env.body), env.body_id);
  }
  assert.deepEqual(seen, new Set(OBJECT_TYPES));
});

test("automatic_spend_atoms stays 0", () => {
  const client = new CognitiveReserveClient(clientOpts("https://exchange.example"));
  assert.equal(AUTOMATIC_SPEND_ATOMS, 0);
  assert.equal(client.automaticSpendAtoms, 0);
});

test("HTTPS default rejects http; labOrigin is 127.0.0.1 only", () => {
  assert.throws(() => new CognitiveReserveClient(clientOpts("http://127.0.0.1")));
  assert.throws(() => new CognitiveReserveClient(clientOpts("http://example.com")));
  new CognitiveReserveClient(clientOpts("http://127.0.0.1:18780", { labOrigin: "http://127.0.0.1" }));
  new CognitiveReserveClient(clientOpts("http://127.0.0.1", { labOrigin: true }));
  assert.throws(() =>
    new CognitiveReserveClient(clientOpts("http://example.com", { labOrigin: "http://example.com" })),
  );
  assert.throws(() => new CognitiveReserveClient(clientOpts("http://8.8.8.8", { labOrigin: true })));
  assert.throws(() => new CognitiveReserveClient(clientOpts("http://localhost", { labOrigin: true })));
});

test("HTTP 202 is UNKNOWN and does not auto-submit", async () => {
  const calls: string[] = [];
  const fetcher: typeof fetch = async (input, init) => {
    calls.push(String(init?.method || "GET") + " " + String(input));
    return new Response(JSON.stringify({ job_id: "lab-job", state: "ACCEPTED" }), {
      status: 202,
      headers: { "Content-Type": "application/json" },
    });
  };
  const client = new CognitiveReserveClient(clientOpts("https://exchange.example", { fetcher }));
  const digest = "a".repeat(96);
  const execute = await client.executeAllocation("alloc-1", {
    client_operation_id: "op-1",
    expected_body_id: digest,
  }, "idem-1");
  const cancel = await client.cancelCapitalExecution("exec-1", {
    client_operation_id: "op-2",
    expected_body_id: digest,
  }, "idem-2");
  assert.equal(calls.length, 2);
  assert.ok(calls.every((c) => !c.includes("/rpc")));
  assert.equal(calls.filter((c) => c.includes("/execute")).length, 1);
  assert.equal(calls.filter((c) => c.includes("/cancel")).length, 1);
  assert.equal((execute as { unknown?: boolean }).unknown, true);
  assert.equal((cancel as { unknown?: boolean }).unknown, true);
  assert.equal(client.automaticSpendAtoms, 0);
});

test("timeout is UNKNOWN and does not retry", async () => {
  const fetcher: typeof fetch = async () => {
    const err = new Error("timeout");
    err.name = "TimeoutError";
    throw err;
  };
  const client = new CognitiveReserveClient(clientOpts("https://exchange.example", { fetcher }));
  await assert.rejects(
    () =>
      client.executeAllocation("alloc-1", {
        client_operation_id: "op-1",
        expected_body_id: "a".repeat(96),
      }, "idem-1"),
    (err: unknown) => {
      assert.ok(err instanceof Cr11Error);
      assert.equal(err.code, "UNKNOWN");
      assert.equal(err.unknown, true);
      return true;
    },
  );
});
