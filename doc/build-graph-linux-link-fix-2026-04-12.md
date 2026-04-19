# Linux Build Graph Fix For Shielded And Utility Targets

Date: 2026-04-12

## Summary

This note documents the build-graph changes made to get the Linux BTX build
back into a usable state before beginning the CUDA backend replacement work.

The immediate problem was that:

- `cmake --build build-btx -j$(nproc)` failed on Linux at link time
- the failures were not missing system packages
- the failures were concentrated in BTX utility, wallet, bench, and shielded
  report-generator targets
- macOS had been building cleanly, which strongly suggested a linker behavior
  difference rather than a missing source file or missing feature flag

Two separate issues were identified:

1. Several standalone executables were missing a `G_TRANSLATION_FUN`
   definition.
2. The Linux link lines for static BTX libraries relied on archive resolution
   behavior that GNU `ld` does not provide automatically for cyclic
   dependencies.

In addition, the source ownership of `dbwrapper.cpp` was incorrect for the
current codebase: shielded code directly uses `CDBWrapper`, but the concrete
implementation lived only inside `bitcoin_node`.

## What Changed

### 1. Introduced `bitcoin_db`

A new internal static library, `bitcoin_db`, now owns `dbwrapper.cpp`.

This library is intentionally small and low-level:

- source: `dbwrapper.cpp`
- dependencies: `core_interface`, `bitcoin_util`, `leveldb`

The purpose is to make the database wrapper implementation available to both
`bitcoin_node` and `bitcoin_shielded` without requiring shielded code to rely on
node-only ownership of the symbols.

### 2. Updated Consumers To Link `bitcoin_db`

The following internal libraries now consume `bitcoin_db` directly:

- `bitcoin_shielded`
- `bitcoin_node`

This matches the actual symbol usage:

- shielded account registry code uses `CDBWrapper`, `CDBBatch`, and
  `CDBIterator`
- node code also uses the same database wrapper implementation

Before this change, Linux exposed the mismatch because shielded consumers were
depending on `dbwrapper.cpp` symbols that were only materialized in
`bitcoin_node`.

### 3. Added Linux-Only Static Archive Grouping

A helper was added so that Linux executables which depend on cyclic internal
static libraries can be linked with:

```text
-Wl,--start-group ... -Wl,--end-group
```

This is applied only on `UNIX AND NOT APPLE`.

The helper is used for BTX utility, daemon, bench, wallet, and report-generator
targets that pull in overlapping sets of:

- `bitcoin_common`
- `bitcoin_shielded`
- `bitcoin_db`
- `bitcoin_node`
- `bitcoin_wallet`
- `bitcoin_consensus`
- `bitcoin_util`
- `bitcoin_crypto`
- `bitcoin_clientversion`
- `bitcoinpqc`
- `secp256k1`
- `leveldb`
- `crc32c`

The intent is not to change behavior. The intent is to make the Linux linker
resolve the already-valid symbol graph reliably.

### 4. Added Missing Translation Stubs

The following standalone executables now define:

```cpp
const TranslateFn G_TRANSLATION_FUN{nullptr};
```

- `btx-matmul-backend-info`
- `btx-matmul-metal-bench`
- `btx-matmul-solve-bench`

This matches the existing pattern already used by other standalone BTX tools
such as `btx-util`, `btx-cli`, `btx-wallet`, `btx-tx`, and `btx-genesis`.

## Why This Is The Correct Fix

### The failures were not package-related

The repository's documented Unix dependencies were already present and CMake had
successfully configured the build. The observed failures were undefined
references to BTX project symbols implemented under `src/`, not failures to
find system headers or system libraries.

### `dbwrapper.cpp` belonged at a lower level already

The key architectural point is that shielded code directly uses the database
wrapper abstraction. That means the implementation cannot be truthfully owned
only by `bitcoin_node` if shielded libraries are expected to link
independently.

Moving `dbwrapper.cpp` into `bitcoin_db` corrects that mismatch:

- it reduces reliance on accidental transitive linkage
- it makes the build graph reflect real source-level dependencies
- it keeps database wrapper code below node-specific orchestration code

### Linux exposed a real build-graph bug

The old graph happened to work on macOS because the Apple linker is more
forgiving around static archives and repeated libraries. GNU `ld` is stricter
and will not always resolve cyclic archive references unless the archive set is
explicitly grouped.

That means the Linux build failure was not a Linux-only feature problem. It was
Linux correctly exposing a dependency structure that was underspecified.

### The change is scoped to linking and ownership, not runtime semantics

No runtime logic in `dbwrapper.cpp` changed.

No LevelDB settings changed.

No wallet format, shielded data format, or consensus logic changed.

No macOS-only source selection changed.

The patch changes:

- which static library owns `dbwrapper.cpp`
- which libraries declare direct dependence on it
- how Linux executables ask the linker to resolve internal static archives
- which standalone executables define the translation stub they already needed

## Why This Should Not Impact macOS Behavior

There are two parts to the patch, and they have different macOS implications.

### Linux archive grouping does not apply on macOS

The `--start-group/--end-group` helper is gated to:

```text
UNIX AND NOT APPLE
```

So the Linux-specific linker workaround is not used on macOS at all.

### `bitcoin_db` is a cross-platform build-graph cleanup

The cross-platform part is the introduction of `bitcoin_db` and the direct
linking of `bitcoin_shielded` and `bitcoin_node` against it.

This should not change macOS runtime behavior because:

- it compiles the same `dbwrapper.cpp`
- it does not change any source logic
- it does not change any feature flags
- it does not change Metal enablement or disablement
- it does not alter wallet or shielded runtime code paths

However, it still needs to be tested on macOS because:

- the target graph did change
- static-library ownership changed
- a clean Linux build is not proof of a clean macOS build

The expected outcome is "no behavioral change, no build regression", but that
expectation still needs explicit validation on macOS.

## Validation Performed

### Linux build

The following command now completes successfully:

```bash
cmake --build build-btx -j$(nproc)
```

This is the primary success criterion for the first stabilization step.

### Linux tests

`ctest --test-dir build-btx --output-on-failure -j$(nproc)` was also run.

The suite is not fully green, but the failures observed were not linker/build
graph regressions caused by this patch. The notable failures observed were:

- `util_test_runner`: expected `btx-tx` JSON fixtures disagree with the current
  reported `weight` field
- `pow_tests`: Boost test module reports runtime failures
- `shielded_v2_netting_capacity_report_tests`: aborts because chain params are
  not initialized in that standalone test path
- `shielded_wallet_chunk_discovery_tests`: runtime test failures unrelated to
  the build-graph fix

Those test failures should be handled separately from this build-unblock work.

## Risk Assessment

### Low-risk areas

- Linux link stability for BTX utilities and shielded report generators
- correctness of direct symbol ownership for `dbwrapper.cpp`
- standalone utility linkage for translation support

### Areas still requiring validation

- clean macOS build with the new `bitcoin_db` ownership
- any packaging or install flow that assumes `dbwrapper.cpp` symbols live only
  in `bitcoin_node`

### Known deferred concern

`bitcoinkernel` still compiles `../dbwrapper.cpp` directly instead of linking
`bitcoin_db`.

That does not affect the default build path used for this stabilization work,
because `BUILD_KERNEL_LIB` is experimental and off by default. But it is now a
build-graph inconsistency that should be cleaned up when kernel-enabled builds
become part of the active validation matrix.

## Deferred To-Do

### `BUILD_KERNEL_LIB` follow-up

Future cleanup should:

- update `src/kernel/CMakeLists.txt` so `bitcoinkernel` consumes the database
  wrapper through `bitcoin_db` or an equivalent deliberate ownership model
- validate `BUILD_KERNEL_LIB=ON`
- validate `BUILD_UTIL_CHAINSTATE=ON`
- confirm there is no duplicate or conflicting ownership of `dbwrapper.cpp`
  symbols across kernel and non-kernel library builds

This should be done as a separate change from the Linux build-unblock patch so
that kernel-library risk stays isolated.

## Recommendation

Treat this patch as the correct first stabilization step for the Linux CUDA
bring-up branch:

- keep the `bitcoin_db` split
- keep the Linux-only archive grouping
- keep the standalone translation stubs
- validate macOS explicitly before assuming cross-platform parity
- handle `BUILD_KERNEL_LIB` as a follow-up task, not as part of this initial
  unblock
