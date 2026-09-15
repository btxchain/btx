# Source / dependency lock (B0 DOC-02)

This is an **in-tree pin list**, not an SPDX SBOM dump of every transitive
object and not a CSV PASS. Record what this helper/test tree expects.

| Component | Pin / note |
|---|---|
| OpenSSL (PQ1) | 3.5.x with ML-KEM-768 and ML-DSA-44. System 3.0 cannot host `SSL_get0_group_name` / ML-KEM. Second-process: `LD_LIBRARY_PATH` to a 3.5.8 prefix. Do not swap live `btxd.real`. |
| GCC | 13.x Release tree `build-gcc13` |
| CMake | existing `build-gcc13` only; no second Debug tree |
| CUDA | optional isolated worker; `nvcc` 12.9 on the lab GPU host. Qualification kernels are **not** compiled into `test_btx`. |
| HTLC | 0.34.6 `htlc_sha256` / `buildhtlcclaim` / `buildhtlcrefund`. No `htlc_sha256_tx`. |
| B0 markdown SHA-384 | `dcc94d534964bca13fccb9a87c2b78808608d0a6bdcf3a72d3c22203bee5cb4ba8039f650a05e25730ec55c24c285e1c` |

`validate-doc-examples.sh` records `openssl version`, `g++ --version`, and
`ninja --version` next to this file when those binaries are on `PATH`. It
does not rewrite B0 bytes.
