# Performance 0.34.8 (convergence round)

Hardware/build for this evidence. Bad numbers are included. Missing labs are NOT_RUN.

| Field | Value |
|---|---|
| Kernel | Linux 7.0.0-30-generic x86_64 |
| Filesystem | ext4 on NVMe |
| RAM | 91 GiB, ~79 GiB available; **swap 7.9/8 GiB used** |
| Disk `/` | 458 G, **7.9 G free (99%)** |
| Compiler | g++-13 13.4.0 |
| Build | `build-gcc13` Release, `BUILD_GUI=OFF`, `WITH_MODELNET=ON` |
| OpenSSL | 3.5.5 |
| CUDA | nvidia-smi failed; not used |
| Qt runtime | libQt6 present; headers missing; GUI not built |
| MinIO | **not installed** |

## Measurements actually taken

| Item | Result |
|---|---|
| Native `modelnet_convergence_tests` | **15/15 PASS**, ~0.9 s |
| Native `modelnet_network02*` | **44/44 PASS**, ~0.9 s |
| Native cloud/watch/event/submandate/first_run/swarm | **92/92 PASS**, ~1.3 s |
| Loopback PQ1 3-seeder retrieve (45-byte fixture) | **PASS**, job ~180 ms stall, ~222 B/s reported (artifact is 45 bytes; **do not treat as throughput**) |
| LAN/WAN GiB/s | **NOT_RUN** |
| Whole-file / extent / piece-object origin throughput | **NOT_RUN** (no MinIO, no 400 GiB I/O) |
| 400 GiB GET counts (arithmetic) | PIECE_OBJECTS **102400**, LARGE_EXTENTS **1600**, WHOLE_FILE/SOURCE_FILES **1** |
| Upload DRR 10 000 queued | 8 concurrent slots (configured) |
| Anti-entropy | 1 000 IDs sparse-diff bounded; **100k/1m/10m NOT_RUN** |
| Erasure encode/decode | Cauchy GF(256) unit; no GiB/s bench |
| `.btx` parse | vector encode/verify unit; no large-package bench |
| uTP vs TCP/PQ1 | **NONSHIPPING**; no comparative bench this round |
| Event gossip amplification | **NOT_RUN** (no 20-peer mesh) |

## Notes

- Reported e2e `bytes_per_sec≈222` is an artifact of a 45-byte model, not a LAN rating.
- Disk pressure (7.9 G free) forbids 400 GiB I/O, 10 M catalog, and a second cmake tree.
- Swap was already nearly full at freeze; this round did not add a Debug tree or parallel `ninja -j$(nproc)`.
