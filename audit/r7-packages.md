# R7 — .btx packages (SPEC 16), independent review

Tree: `/home/administrator/btx-0.34.7-private`
Files in scope: `src/modelnet/package_bundle.cpp`, `src/modelnet/package_export.cpp`,
`src/btx-open.cpp`, package vectors.
Lane constraints honoured: no compile, no edits to `helper.cpp` or any CMake file.
Written: `audit/r7-packages.md`, `src/test/modelnet_r7_package_tests.cpp`,
`src/test/data/btx-package-vectors/`.

## Verdict

| Lane requirement | Result |
| --- | --- |
| Canonical vectors MODEL / COLLECTION / RELEASE / BOUNTY / MODEL_FAMILY | **FAIL** — the pre-existing set is not canonical; replacement set written. MODEL_FAMILY does not exist as a kind (R7-09) |
| Preview-first | **PASS** for `btx-open`; the five kinds are invisible in the preview (R7-11) |
| No auto-spend | **PARTIAL** — the guard is present but throws instead of refusing on an out-of-range literal (R7-02) and is dropped from the exported object (R7-05) |
| No execution | **PASS** — no install or execute path is reachable from `btx-open` or the export helpers |
| No arbitrary URL | **FAIL** — `btx-open` refuses non-`btx://` arguments, but `EncodeMagnetAnalog` accepts any string as `uri` (R7-03) |
| No wallet import | **PASS** — `wallet=not-opened` on every preview; no key or trust import in scope |
| Deterministic encoding | **PARTIAL** — `package_core_id` is canonical and stable; the bundle codec is order-dependent and accepts duplicate keys (R7-01) |
| Economic state refresh vs stale package | **FAIL** — staleness is missed when the cached observation has no `state` field (R7-06) and across a unit change (R7-07) |
| Offline shows stale/offline explicitly | **FAIL** — no explicit offline flag anywhere; `btx-open` prints no economic state at all (R7-06, R7-11) |

Blocking, in my view: **R7-01** (secret-scan and float-scan bypass) and **R7-02**
(abort on attacker-chosen integer). The rest are correctness and surfacing gaps.

## Evidence

Static reading plus execution of the **prebuilt** `build-gcc13/bin/btx-open`
(mtime 2026-09-17 12:37, newer than all three sources, so it matches the tree)
and the prebuilt `build-gcc13/bin/test_btx`. Nothing was compiled. The bech32m
encoder used to build vector URIs was validated against a known-good URI from the
tree's own tests: it decodes to kind byte 0 and re-encodes byte-identically.

Baseline: `modelnet_network02_tests, modelnet_network02_gh_tests,
modelnet_network02_import_tests, modelnet_ahp_frm_tests, modelnet_ahp_comp_tests,
modelnet_ahp_eco_tests` — 59 cases, no errors. Every finding below is outside
existing coverage. The duplicate-key hazard is not a new idea in this tree — see
R7-01 — but no test covers it on the `.btx` bundle path, and `grep` finds no
integer-range test over these entry points.

## Findings

### R7-01 — duplicate object keys shadow both the float scan and the secret scan (blocking)

`RejectFloats` in `package_bundle.cpp` and `ScanPublic` in `package_export.cpp`
both iterate `value.getKeys()` and then dereference `value[key]`. univalue's JSON
parser appends object keys with `keys.push_back` and performs **no** duplicate
check, while `findKey` returns the **first** match. So for `{"a":X,"a":Y}`,
`getKeys()` yields `a` twice and both iterations inspect `X`. `Y` is present in the
bytes and is never visited by any validator that dereferences by key.

Demonstrated against the real binary, with a control:

```
{"n":1.5}       -> DecodeBtxBundle REJECTS, "floats prohibited", exit 1
{"n":1,"n":1.5} -> DecodeBtxBundle ACCEPTS, exit 0
```

The same mechanism defeats the credential sentinels:
`{"a":{"public":1},"a":{"api_key":"..."}}` passes `PublicExportObjectAllowed`,
because the second `a` subtree is never scanned. A duplicated *forbidden key name*
is still caught — the name test runs once per `getKeys()` entry — so only shadowed
**values** escape. Vectors: `invalid/dup-key-shadowed-float.btxbundle`,
`invalid/dup-key-shadowed-secret.btxbundle`, and the control
`invalid/dup-key-toplevel-secret.btxbundle`.

Reachability is not theoretical, and the tree already knows this class of bug.
`DecodePjson1` rejects duplicate keys (`package_pjson.cpp:397`), `StrictParseJson`
rejects them (`canonical_codec.cpp:301`), and
`modelnet_jit_safety_tests.cpp:236` states the design position outright:
*"ParseCapabilityRecipe last-wins on UniValue duplicate keys; DecodePjson1 is the
reject gate."*

`DecodeBtxBundle` is the one decoder in scope that uses neither gate — it calls
plain `UniValue::read` (`package_bundle.cpp:99`). And it is not an obscure corner:
it is the **fallback that runs precisely when the pjson1 gate rejects**. Both
`btx-open` (`InspectLocalPackage`) and the import RPC
(`helper_network02.cpp:552`) try `DecodeBtxPackage` first and fall back to
`DecodeBtxBundle` / `DecodePublicBtxBundle` on failure. So a duplicate key makes the
strict decoder fail, which routes the payload to the decoder that cannot see it. The
import path then echoes the decoded object back to the caller via
`result.pushKV("bundle", decoded)`, so a package can smuggle a credential through
the gate that exists to stop it.

Fix: in `DecodeBtxBundle`, replace `out.read(payload)` with the in-tree
`modelnet::StrictParseJson(payload, out, err)`, which already rejects duplicate keys
and trailing JSON. Scanning `getValues()` alongside `getKeys()` in `RejectFloats`
and `ScanPublic` would close it defensively as well.

### R7-02 — `getInt` throws after an `isNum()` guard; `btx-open` aborts (blocking)

`isNum()` is true for any JSON integer literal, but `UniValue::getInt<Int>()`
throws `std::runtime_error("JSON integer out of range")` when the value does not
fit the target type. Three call sites guard with `isNum()` and then call `getInt`:
`package_export.cpp:141` (`automatic_spend_atoms`), `package_economy.cpp:150` and
`:211` (same field), and `btx-open.cpp:207` (`core.version`, into `int`).

`btx-open`'s `main` has no `try`/`catch`, so a 31-byte file aborts it:

```
$ printf '{"core":{"version":2147483648}}' > x.btx && btx-open x.btx
terminate called after throwing an instance of 'std::runtime_error'
  what():  JSON integer out of range
Aborted (core dumped)   exit=134
```

No framing is needed — the plain-JSON fallback at `btx-open.cpp:191` reaches the
same line. Scope honestly: the shipped `contrib/modelnet/btx-open.desktop`
registers only `x-scheme-handler/btx`, not a `.btx` file association, and a
`btx://` argument goes to `PrintUriPreview` and cannot reach this. So it is a
local-input crash on the documented `btx-open <path.btx>` form, not a
click-to-crash through the shipped handler.

The `package_export.cpp` instance matters on its own terms: the guard that is
supposed to refuse a spend mandate *raises* instead of returning
`"spend mandate forbidden"`, so the no-auto-spend refusal is not what an
attacker-chosen literal produces. Vectors:
`invalid/int-overflow-core-version.btx`, `invalid/int-overflow-auto-spend.btx`.

Fix: range-check the numeric string before `getInt`, or use the throwing form only
behind a `try`. `btx-open`'s `main` should also catch `std::exception` and exit
non-zero with a message.

### R7-03 — `EncodeMagnetAnalog` accepts an arbitrary URL as `uri`

`ValidateResources` (`package_core.cpp:182`) requires resource URIs to start with
`btx://` and notes the native decoder is still required. The magnet-analog path has
no equivalent: `uri` need only be a non-empty string that has no `dn=` in its
query. An exported `.btx` can carry
`"uri": "https://attacker.example/weights.gguf"`, and nothing in
`package_export.cpp` calls `DecodeResource`. `btx-open` itself is not the victim
here — it refuses non-`btx://` arguments (verified: `https://…` and `file:///etc/passwd`
both exit 1) — but any other reader that trusts an exported magnet analog is.
Vector: `invalid/non-btx-uri.btx`.

Fix: require `DecodeResource(uri)` to succeed in `EncodeMagnetAnalog` and
`ParseMagnetAnalog`.

### R7-04 — unknown `schema_version` is silently rewritten, not refused

`IsMagnetAnalogObject` only checks that `schema_version` exists, of any type.
`EncodeMagnetAnalog` then hardcodes `out.pushKV("schema_version", 2)`. A document
declaring `99` is accepted and downgraded to `2`, and a `1` is upgraded to `2`
without comment — which is why the pre-existing vectors declare `schema_version: 1`
even though the encoder can only ever emit `2`. Vector:
`invalid/unknown-schema-version.btx`.

Fix: refuse a `schema_version` outside the supported set.

### R7-05 — the exported object drops its own preview-first assertions

`EncodeMagnetAnalog` validates `automatic_spend_atoms == 0` when present, then
never emits it, and drops `preview_first` entirely. The output object is
`schema_version`, `kind`, `uri`, `copy_text` and optional public metadata only. So
a consumer of an exported `.btx` cannot see that no spend and no execution were
mandated; absence of a field is indistinguishable from a field that was never
checked. `helper_network02.cpp` adds `automatic_spend_atoms: 0` to the **RPC
result**, but not into the exported document itself.

Fix: emit `automatic_spend_atoms: 0` and `preview_first: true` into the document.

### R7-06 — staleness missed without a `state` field; no explicit offline flag

`EvaluatePackageRewardPreview` decides staleness from `ObservationState` (the
`state` string) and from `AmountMismatch`, which requires a value on **both**
sides. A cached observation that carries a funding number but no `state`, evaluated
against an empty local observation (offline), therefore takes the final `else`
branch: `cached_stale = false`, `current_state = "economic state unknown"`. The
only hint is `cached_percent_funded_ignored: true`, which is not the field a caller
reads to decide whether to trust the cache. Vector:
`invalid/stale-percent-funded-no-state.json`.

The case that does work: with a `state` on the cached side and none locally, the
cache is correctly marked stale and `current_state` is set to
`"economic state unknown"` rather than left blank.

Separately, nothing in the emitted JSON distinguishes *"refreshed, and the chain
says unknown"* from *"could not reach the chain"* — there is no
`observation_offline`, no `observed_at_height`, and no age. Staleness is a pure
string/amount comparison, so a cache that is old but unchanged reports fresh. The
lane requires offline to be explicit; the string `"economic state unknown"` is
overloaded across both meanings.

Fix: treat any cached economic claim with no fresh local observation as stale;
emit an explicit offline flag and an observation height.

### R7-07 — `AmountMismatch` compares a percentage against an atom count

```
const bool have_a = num(cached, "confirmed_funded_atoms", a) || num(cached, "percent_funded", a);
const bool have_b = num(local,  "confirmed_funded_atoms", b) || num(local,  "percent_funded", b);
return have_a && have_b && a != b;
```

Each side independently falls back to whichever field it has, so a cached
`percent_funded: 50` and a local `confirmed_funded_atoms: 50` compare equal and the
cache is reported fresh across a unit change. Vector:
`invalid/cross-unit-amount-match.json`.

Fix: compare like units only, and treat a unit change as stale.

### R7-08 — `copy_text` has no control/bidi filter and no length cap

`package_core.cpp` runs `SafeText` over `label`, profile ids and variant ids,
rejecting C0 controls, `U+061C`, `U+200E/200F`, `U+202A–202E` and `U+2066–2069` —
precisely the display-spoofing set. `copy_text` is the string a UI renders and a
user pastes, and `EncodeMagnetAnalog` copies it verbatim, unfiltered and uncapped.
`btx-open` runs `EscapeForTerminal` on document paths and the AGENTS.md snippet but
never reads magnet-analog `copy_text`, so the protection does not extend here.
Vector: `invalid/control-chars-in-copy-text.btx`.

Fix: apply `SafeText` and a length bound to `copy_text`.

### R7-09 — MODEL_FAMILY is not a kind anywhere in the tree

The lane requires a canonical MODEL_FAMILY vector. There is no `MODEL_FAMILY` in
`ResourceKind` (15 values, MODEL through AWARD), none in
`kPackageTypes = {MODEL, COLLECTION, RELEASE, BOUNTY, VARIANT_INDEX}`, and no
occurrence of the string anywhere in `src/`. The tree's family concept is
`package_type: VARIANT_INDEX` plus a `variants[]` array of objects carrying
`variant_id` / `resource_id` / `format`, indexed by `IndexVariants`.

`EncodeMagnetAnalog` accepts `"kind": "MODEL_FAMILY"` only because it never
validates `kind` against an enumeration — `"kind": "NOT_A_KIND"` is equally
accepted, and an absent `kind` silently becomes `"MODEL"`. So the field carries no
authority. My `valid/MODEL_FAMILY.btx` encodes its URI with the `COLLECTION` kind
byte and the mismatch is recorded in `manifest.json`.

Decision needed from the spec owner: either add a family kind to `ResourceKind` and
`kPackageTypes`, or rename the SPEC 16 requirement to `VARIANT_INDEX`. Until then a
"canonical MODEL_FAMILY vector" cannot exist.

### R7-10 — the export path does not run its own portable lint

`LintPackagePortable` rejects embedded presigned capabilities and the HF/S3/wallet
credential sentinels, and correctly refuses
`https://s3.example/w.gguf?X-Amz-Signature=…`. Neither `EncodeMagnetAnalog` nor
`EncodePublicBtxBundle` calls it; they call only `PublicExportObjectAllowed`, whose
sentinel list is narrower (no HF token, no S3 access key, no presigned-URL string
scan). So the writer lint exists but is not on the writer path. Vector:
`invalid/presigned-url.btx`.

Fix: call `LintPackagePortable` from the export helpers.

### R7-11 — `btx-open` surfaces nothing about a package it inspects

For every one of the five kinds, in either framing, the preview is:

```
path=…
looks_like_btxbundle=true|false
core_version=unparseable
documents=
action=preview-only … wallet=not-opened … install=false … network=false
```

No kind, no URI, no digest, no label, no economic state. `InspectLocalPackage`
only understands a core-v2 payload; a magnet-analog `.btx` and a
magnet-analog-in-a-frame both fall through to `core_version=unparseable`. So a user
inspecting a RELEASE or BOUNTY package sees nothing that identifies it, and — since
`btx-open` does not include `package_economy.h` at all — no stale or offline line
anywhere. The URI preview path is much better: it prints canonical/display/copy
forms, kind, digest, `action=preview-only`, `wallet=not-opened`,
`storage_consent_required` and an explicit note that download, seed, payment and
execution need separate approval.

Two smaller dispatcher issues, same file:

- A non-bundle file whose name does not end in `.btx` falls through to
  `PrintUriPreview`, so a file path produces the URI error
  `"invalid token length or mixed case"`. Confirmed with `invalid/frame-wrong-magic.bin`.
- When both decoders fail, the error reported is the `DecodeBtxBundle` message.
  `frame-declared-len-max.btxbundle` prints `flags/size/trailing` although
  `DecodeBtxPackage` classified it `PACKAGE_TOO_LARGE`.

`InspectLocalPackage` also never applies the secret scan on the plain-JSON path, so
an AGENTS.md snippet is echoed to the terminal without it. `EscapeForTerminal` does
neutralise the snippet, so this is minor.

## What holds up

Worth recording, because these are the parts a fix must not regress.

- **Framing.** Trailing bytes, nonzero flags, a lying `payload_len`, a corrupted
  digest, `payload_len = 2^64-1`, bad magic and a short header are all rejected.
  `DecodeBtxPackage` refuses `2^64-1` before any `68 + n` arithmetic.
- **`package_core_id` is canonical.** The same core with keys in a different order
  and with inserted whitespace yields byte-identical ids
  (`50c3a00d…` for all three), while the three files hash differently. This is the
  right split, and it means vectors must pin `package_core_id`, never the file hash.
  I recorded that in the vector README.
- **Preview-first in the URI path**, and no reachable install, execute, mine, seed
  or wallet path from anything in scope.
- **`dn=` containment**, nonzero spend mandates, top-level secret-bearing key names,
  and `FREE_ONLY` never converting to paid on timer expiry (checked at one year
  elapsed) all behave.
- **`EncodeLegacyAcquisitionExport`** strips `agent_handoff` at both levels and
  labels the result.

One latent issue in that last helper: it copies every input key and then
`pushKV("legacy_acquisition_export", true)`. `pushKV` replaces rather than appends,
so a caller-supplied `legacy_acquisition_export: false` is overwritten rather than
duplicated. Correct today, but it is the only thing standing between this helper
and emitting a duplicate key into R7-01's blind spot.

## Vectors written

`src/test/data/btx-package-vectors/` — 10 valid files (5 kinds × magnet-analog
`.btx` + `.btxbundle`), 19 invalid, 2 codec-divergence, plus `manifest.json`
recording the codec and expectation per file and `README.md` with the regeneration
rule.

The pre-existing `audit/btx-package-vectors/` set is **not canonical** and I did not
modify it. Its five `valid/*.json` files carry path-style URIs
(`btx://model/abababab…`) that `DecodeResource` rejects — token lengths 54 to 59
against the required 85 — so they exercise the framing but never the URI. They also
declare `schema_version: 1`, which the encoder cannot emit, and
`MODEL_FAMILY.json` sets `"variants": ["base","instruct"]`, an array of strings,
where `IndexVariants` and `ValidateHandoff` both require objects with `variant_id`
and `resource_id`. Their BTXPKG frames are well formed and their digests verify.

Replacement URIs are `EncodeResource(kind_byte, sha384("BTX-R7-VECTOR/" + KIND))`,
so the set regenerates from the kind names alone, and each was confirmed to decode
back to the intended kind byte through an independent bech32m implementation
cross-checked against the tree's encoder.

## Test written

`src/test/modelnet_r7_package_tests.cpp`, suite `modelnet_r7_package_tests`, 20
cases. **Authored, not executed** — the lane forbids compiling, and the file is not
in the `test_btx` source list, which is an explicit list in `src/test/CMakeLists.txt`
that R7 must not edit. A coordinator needs to add one line.

Payloads are built inline rather than read from the vector directory: that
directory is not in the `src/test/data/*.json` header pipeline and binary frames
never were, so reading from disk would have required the CMake change this lane
cannot make.

Cases proving a defect are suffixed `_today` and assert **current** behaviour, so
the suite is green when wired in and fails loudly when the defect is fixed. Each
carries its R7 id and the assertion to swap in. Since the file has not been
compiled, treat the C++ as unverified against the compiler even though every
assertion was derived from the sources and, where possible, from observed
`btx-open` behaviour.
