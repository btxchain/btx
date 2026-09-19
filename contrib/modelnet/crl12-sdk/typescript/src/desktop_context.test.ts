#!/usr/bin/env node
// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
/** Desktop context: view/draft only, never localhost execute. */

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  CONTEXT_TYPE,
  DesktopContextError,
  applyDesktopContext,
} from "./desktop_context.ts";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const EXAMPLE = path.resolve(HERE, "../../fixtures/desktop-context.example.json");

test("example is INSPECT view only", () => {
  const ctx = JSON.parse(fs.readFileSync(EXAMPLE, "utf8")) as Record<string, unknown>;
  const out = applyDesktopContext(ctx);
  assert.equal(ctx.type, CONTEXT_TYPE);
  assert.equal(out.purpose, "INSPECT");
  assert.equal(out.http, false);
  assert.equal(out.localhost, false);
  assert.equal(out.execute, false);
  const ids = out.operations.map((o) => o.operation_id);
  assert.ok(ids.includes("getInstitutionalAsset"));
  assert.ok(!ids.includes("executeAllocation"));
  assert.ok(out.operations.every((o) => o.method === "GET"));
});

test("DRAFT maps to preparePortfolioInstruction", () => {
  const ctx = JSON.parse(fs.readFileSync(EXAMPLE, "utf8")) as Record<string, unknown>;
  (ctx.btx as Record<string, unknown>).purpose = "DRAFT";
  const out = applyDesktopContext(ctx);
  assert.equal(out.operations[0]?.operation_id, "preparePortfolioInstruction");
  assert.equal(out.operations[0]?.body?.execute, false);
});

test("rejects token and execute purpose", () => {
  const base = JSON.parse(fs.readFileSync(EXAMPLE, "utf8")) as Record<string, unknown>;
  const stolen = structuredClone(base);
  (stolen.btx as Record<string, unknown>).access_token = "stolen";
  assert.throws(() => applyDesktopContext(stolen), (err: unknown) => {
    assert.ok(err instanceof DesktopContextError);
    assert.equal(err.code, "SECRET_INLINE");
    return true;
  });
  const exec = structuredClone(base);
  (exec.btx as Record<string, unknown>).purpose = "EXECUTE";
  assert.throws(() => applyDesktopContext(exec), (err: unknown) => {
    assert.ok(err instanceof DesktopContextError);
    assert.equal(err.code, "VIEW_DRAFT_ONLY");
    return true;
  });
});

test("rejects localhost execute URL", () => {
  const ctx = JSON.parse(fs.readFileSync(EXAMPLE, "utf8")) as Record<string, unknown>;
  (ctx.btx as Record<string, unknown>).href =
    "http://127.0.0.1:8080/btx/hcp/v1/capital/allocations/x/execute";
  assert.throws(() => applyDesktopContext(ctx), (err: unknown) => {
    assert.ok(err instanceof DesktopContextError);
    assert.equal(err.code, "LOCALHOST_EXECUTE_FORBIDDEN");
    return true;
  });
});

test("desktop_context.ts has no HTTP client", () => {
  const src = fs.readFileSync(path.join(HERE, "desktop_context.ts"), "utf8");
  assert.ok(!src.includes("fetch("));
  assert.ok(!src.includes("http://"));
  assert.ok(!src.includes("node:http"));
});

test("COMPARE is view only and EXECUTE_NOW is rejected", () => {
  const ctx = JSON.parse(fs.readFileSync(EXAMPLE, "utf8")) as Record<string, unknown>;
  (ctx.btx as Record<string, unknown>).purpose = "COMPARE";
  const out = applyDesktopContext(ctx);
  assert.ok(out.operations.some((o) => o.operation_id === "listInstitutionalMetrics"));
  assert.ok(out.operations.every((o) => o.method === "GET"));
  assert.equal(out.execute, false);
  const exec = structuredClone(ctx);
  (exec.btx as Record<string, unknown>).purpose = "EXECUTE_NOW";
  assert.throws(() => applyDesktopContext(exec), (err: unknown) => {
    assert.ok(err instanceof DesktopContextError);
    assert.equal(err.code, "VIEW_DRAFT_ONLY");
    return true;
  });
});
