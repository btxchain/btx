#!/usr/bin/env node
// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
/** Print body_id for an HCP envelope JSON file. */

import fs from "node:fs";
import { bodyId } from "./body_id.ts";

const file = process.argv[2];
if (!file) {
  console.error("usage: compute_body_id.ts ENVELOPE.json");
  process.exit(2);
}
const env = JSON.parse(fs.readFileSync(file, "utf8")) as {
  object_type: string;
  body: Record<string, unknown>;
};
process.stdout.write(bodyId(env.object_type, env.body));
