BTX version 0.32.3 is now available from:

  <https://github.com/btxchain/btx/releases/tag/v0.32.3>

This v0.32.3 point release updates the CUDA and Metal MatMul mining backends for
post-`nMatMulNonceSeedHeight` nonce-bound seed derivation. It also includes pool
share-target handling fixes, clearer CUDA fallback diagnostics, shielded-state
repair observability, ZMQ release-binary packaging fixes, and wallet/RPC
follow-ups from the 0.32.x block-125,000 activation series.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/btxchain/btx/issues>

To receive release and update notifications, please subscribe to:

  <https://btx.dev/>

# How to Upgrade

If you are running an older version, shut it down. Wait until it has completely
shut down, then install the new binaries or replace the existing `btxd`,
`btx-cli`, and GUI binaries with the 0.32.3 release artifacts.

BTX 0.32.3 does not introduce a new protocol activation height. Nodes, miners,
pools, exchanges, services, and explorers should upgrade from earlier 0.32.x
builds for the mining backend and operational fixes.

# Compatibility

BTX is supported on Linux, macOS 13+, and Windows 10+.

# Notable changes

- CUDA mining now has a post-`nMatMulNonceSeedHeight` nonce-seed path. The
  solver batches nonce-seeded pre-hash scans on CUDA, returns only candidates
  that pass the consensus sigma gate, and runs variable-base digest batches so
  per-candidate A/B matrix generation happens on the GPU instead of one nonce at
  a time on the CPU. The CUDA optimization notes recorded a representative
  height-125,000 benchmark improving from about 14.1k nonces/sec to about 2.45M
  nonces/sec while restoring high GPU utilization.

- Metal mining now uses the same post-activation structure: Metal pre-hash scan,
  variable-base digest batching, and miner-loop routing through the GPU batch
  path. The Metal nonce-seed default batch size scales from the detected Apple
  GPU core count, and `btx-matmul-backend-info` / `btx-matmul-solve-bench` now
  report the Metal device name, GPU core count, and detection source.

- CUDA nonce-seed batch sizing was tuned for production mining hosts. Operators
  can use `BTX_MATMUL_NONCE_SEED_BATCH_SIZE` for an exact override, and CUDA
  auto-sizing can be capped with `BTX_MATMUL_CUDA_NONCE_SEED_MEMORY_PERCENT`.
  The nonce-seed CUDA path currently uses the first selected visible CUDA device
  when `BTX_MATMUL_CUDA_DEVICES` lists multiple devices.

- Pool `share_target_override` handling was restored for the MatMul solvers.
  The override relaxes only the digest early-exit target used to return pool
  shares; the consensus pre-hash gate and pre-hash scan window continue to use
  the block target derived from `nBits`.

- CUDA fallback behavior is now visible in logs and diagnostics. When CUDA is
  requested but unavailable, the mining backend line includes the concrete
  reason. Runtime CUDA-to-CPU fallback warnings are emitted immediately and then
  throttled for sustained failures, and the new
  `doc/btx-cuda-mining-troubleshooting.md` guide covers common driver,
  architecture-list, WSL2, and kernel-load failures.

- CUDA compute-capability gating now supports an explicit older-GPU opt-in.
  `BTX_CUDA_ALLOW_OLDER_GPUS=1` lowers the default `sm_80+` floor to `sm_60+`
  for operators who have independently validated their hardware and built
  kernels for those architectures.

- Shielded-state operations have improved repair visibility. Startup rebuilds
  now log progress more clearly, `-resetshieldedstate` can force a local
  shielded-state repair, and the new `getshieldedstateinfo` RPC exposes current
  shielded-state status for operators and automation.

- Static release binaries now include ZMQ support by building and packaging the
  static `libzmq.a` dependency. Nodes also warn when ZMQ publish options are set
  on a build without ZMQ support.

- RPC and wallet follow-ups fix `getblock` verbosity-2 fee reporting for
  shielded transactions and tighten C-002 PSBT boundary handling.

- Release automation examples now point at the 0.32.3 artifacts.

# Credits

Thanks to everyone who contributed code, testing, operational validation, and
release engineering to this release.
