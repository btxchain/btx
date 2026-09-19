#!/usr/bin/env node
// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
/**
 * CRL v1.2 SDK tests: 43 operation_ids, 18 type domain separation.
 * automatic_spend_atoms stays 0. No /rpc. No executeAllocation.
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { bodyId, canonicalBody, OBJECT_TYPES } from "./body_id.ts";
import {
  ANALYTICS_SCOPES,
  AUTOMATIC_SPEND_ATOMS,
  Crl12Client,
  Crl12Error,
  OPERATION_IDS,
  containsSecrets,
} from "./client.ts";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CATALOG = path.resolve(HERE, "../../schemas/operations-v1.2.json");

test("eighteen types are domain-separated", () => {
  assert.equal(OBJECT_TYPES.length, 18);
  assert.equal(new Set(OBJECT_TYPES).size, 18);
  const body = { schema_revision: "1.2", provider_id: "p", created_at: "1" };
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
  const body = { schema_revision: "1.2", provider_id: "p", created_at: "1" };
  assert.throws(() => bodyId("PortfolioV4", body));
  assert.throws(() => bodyId("ProviderProfile", body));
  assert.ok(OBJECT_TYPES.every((t) => !t.includes("V4")));
});

test("catalog has 43 unique operation_ids and no executeAllocation", () => {
  const catalog = JSON.parse(fs.readFileSync(CATALOG, "utf8")) as {
    operations: { operation_id: string; path: string }[];
  };
  const ids = catalog.operations.map((o) => o.operation_id);
  assert.equal(ids.length, 43);
  assert.equal(new Set(ids).size, 43);
  assert.deepEqual(ids, [...OPERATION_IDS]);
  assert.ok(!ids.includes("executeAllocation"));
  assert.ok(catalog.operations.every((o) => o.path.startsWith("/btx/hcp/v1/")));
  assert.ok(catalog.operations.every((o) => o.path !== "/rpc" && !o.path.startsWith("/rpc/")));
});

test("automatic_spend_atoms stays 0", () => {
  const client = new Crl12Client({ origin: "https://exchange.example" });
  assert.equal(AUTOMATIC_SPEND_ATOMS, 0);
  assert.equal(client.automaticSpendAtoms, 0);
});

test("HTTPS default rejects http", () => {
  assert.throws(() => new Crl12Client({ origin: "http://127.0.0.1" }));
  new Crl12Client({ origin: "http://127.0.0.1", labOrigin: true });
});

test("refuse secrets in export", async () => {
  const client = new Crl12Client({ origin: "https://exchange.example" });
  await assert.rejects(
    () =>
      client.call("createInstitutionalExport", {
        body: { access_token: "stolen", format: "JSONL" },
        idempotencyKey: "exp-1",
      }),
    (err: unknown) => {
      assert.ok(err instanceof Crl12Error);
      assert.equal(err.code, "SECRET_INLINE");
      return true;
    },
  );
  assert.equal(containsSecrets({ secret_ref: "os:keyring/x" }), false);
  assert.equal(containsSecrets({ access_token: "x" }), true);
});

test("refuse executeAllocation from analytics scope", () => {
  const client = new Crl12Client({ origin: "https://exchange.example", scopes: ANALYTICS_SCOPES });
  assert.ok(!client.scopes.includes("capital:execute"));
  assert.throws(() => client.executeAllocation("alloc-1"), (err: unknown) => {
    assert.ok(err instanceof Crl12Error);
    assert.equal(err.code, "SCOPE_DENIED");
    return true;
  });
});

test("import is not custody credit", async () => {
  const client = new Crl12Client({ origin: "https://exchange.example" });
  await assert.rejects(
    () =>
      client.call("commitInstitutionalImport", {
        path: { id: "imp-1" },
        body: { custody_credit: true },
        idempotencyKey: "imp-1",
      }),
    (err: unknown) => err instanceof Crl12Error && err.code === "IMPORT_NOT_CUSTODY",
  );
});

test("no /rpc passthrough", async () => {
  const client = new Crl12Client({ origin: "https://exchange.example" });
  await assert.rejects(
    () => client.call("/rpc"),
    (err: unknown) => err instanceof Crl12Error && err.code === "SCOPE_DENIED",
  );
  await assert.rejects(
    () => client.call("genericRpc"),
    (err: unknown) => err instanceof Crl12Error && err.code === "SCOPE_DENIED",
  );
});

test("no invented AUM/AUC and no remote inference", async () => {
  const client = new Crl12Client({ origin: "https://exchange.example" });
  await assert.rejects(
    () =>
      client.call("createPortfolioProjection", {
        body: { combined_aum_auc: "99" },
        idempotencyKey: "proj-1",
      }),
    (err: unknown) => err instanceof Crl12Error && err.code === "INVENTED_TOTAL",
  );
  await assert.rejects(
    () =>
      client.call("preparePortfolioInstruction", {
        body: { remote_inference: true },
        idempotencyKey: "ins-1",
      }),
    (err: unknown) => err instanceof Crl12Error && err.code === "REMOTE_INFERENCE_FORBIDDEN",
  );
});
