# .btx package vectors

Canonical and adversarial vectors for the `.btx` package surface
(`src/modelnet/package_bundle.cpp`, `src/modelnet/package_export.cpp`,
`src/btx-open.cpp`). Written by independent review lane R7; see
`audit/r7-packages.md` for the findings each invalid vector pins.

`manifest.json` records, per file, the codec and the expected outcome.

## Layout

- `valid/` — the five package kinds SPEC 16 requires, as `.btx` magnet-analog
  JSON plus the matching `.btxbundle` binary frame.
- `invalid/` — vectors that must be refused. Several are refused today; the rest
  carry an R7 finding id in `manifest.json` and are currently **accepted**.
- `codec-divergence/` — one logical package under both framings that share the
  `BTXPKG\x00\x01` magic.

## Reproducing

Each URI is `EncodeResource(kind_byte, sha384("BTX-R7-VECTOR/" + KIND))`, so the
whole set is regenerable from the kind names alone. The `.btx` files are exactly
`UniValue::write(0)` of `EncodeMagnetAnalog`'s output object, in its `pushKV`
emission order — `schema_version`, `kind`, `uri`, `copy_text`, then any of
`family`, `format`, `quantization`, `signed`. Order is load-bearing: the
`.btxbundle` frame digest is taken over those bytes.

`MODEL_FAMILY` has no `ResourceKind` and is not in `kPackageTypes`, so its URI is
encoded with the `COLLECTION` kind byte (2). See finding R7-09.

## Wiring

These files are not *compiled* into `test_btx`. `src/test/CMakeLists.txt` turns
`src/test/data/*.json` into generated headers, and binary frames were never in
that pipeline, so there is no `-D` path define for this directory and R7 does
not edit CMake.

`src/test/modelnet_r7_package_tests.cpp` reads them at run time instead: the
`vector_set_on_disk_*` cases resolve this directory from `__FILE__` and fail
(rather than skip) if it is missing. `manifest.json` is checked against the
directory listing, and every `.btxbundle` is checked against its recorded
`frame_sha384`, so a vector cannot be added, moved, or edited without a case
noticing. The earlier cases in that file still build equivalent payloads inline,
which is what keeps the suite meaningful if this directory is ever dropped.

Identify a package by `package_core_id`, never by the file hash: the frame bytes
are malleable (key order, whitespace) while `package_core_id` is not.
