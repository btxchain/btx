# Capability baseline — private 0.34.8 tree

Recorded 2026-09-17. Dirty tree is not identified by HEAD alone.

| Item | Value |
|---|---|
| Working tree | `/home/administrator/btx-0.34.7-private` |
| Branch | `feat/0.34.8-modelnet-first-run` |
| HEAD | `573b4aa41f26ea6c61a00ee6096c5ff4de319335` (uncommitted JIT + prior AHP/NETWORK-02) |
| Compile | one Release `build-gcc13` GCC 13, `BUILD_GUI=OFF`, `WITH_MODELNET=ON`, CUDA compiler NOTFOUND |
| `CLIENT_VERSION` | 0.34.8 |
| `CLIENT_VERSION_IS_RELEASE` | **false** |
| Prior native | AHP/NETWORK-02 grouped 288/288 |
| Production | do not stop; CPU 0.34.8 is parallel-prefix only |
| Package Core v3 | **NEW** — private tree allocated only v1 and v2 (`PACKAGE_CORE_V2_DOMAIN`). No colliding v3 schema. |

## Existing paths reused (REUSED)

| Symbol | Path | Decision |
|---|---|---|
| Digest48 | `src/modelnet/types.h` | REUSED |
| PackageCoreId / EncodePjson1 | `package_core.cpp` / `package_pjson.cpp` | EXTENDED for v3 |
| VerifiedManifest / TransferSession / CreditBroker | `verified_manifest.cpp` `transfer_session.cpp` | REUSED by ensure |
| GlobalAcquisitionCredits | `package_execute.cpp` | REUSED; no second downloader |
| QualifySafeTensors | `qualification.cpp` | EXTENDED via TensorRangeMap |
| Helper unix + ProxyOrLocal | `helper.cpp` `rpc/modelnet.cpp` | EXTENDED with private capability methods |
| Browser bridge POST 405 | `http_bridge.cpp` | REUSED (already 405 mutating) |

## NEW modules

`src/modelnet/capability_*.cpp`, `src/capabilityd.cpp` (`btx-capabilityd`), native `src/test/modelnet_jit_*_tests.cpp`.
