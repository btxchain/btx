#!/usr/bin/env node
// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
/** Map a desktop context JSON file to typed view/draft operations. No HTTP. */

import fs from "node:fs";
import { applyDesktopContext, DesktopContextError } from "./desktop_context.ts";

const file = process.argv[2];
if (!file) {
  console.error("usage: apply_desktop_context.ts CONTEXT.json");
  process.exit(2);
}
const ctx = JSON.parse(fs.readFileSync(file, "utf8")) as Record<string, unknown>;
try {
  const out = applyDesktopContext(ctx);
  process.stdout.write(JSON.stringify({ ok: true, ...out }));
} catch (err) {
  const code = err instanceof DesktopContextError ? err.code : "ERROR";
  process.stdout.write(JSON.stringify({ ok: false, code, error: String(err) }));
  process.exit(1);
}
