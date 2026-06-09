# BTX CUDA Multi-Device Mining

This document covers Linux CUDA operation when a CUDA-enabled BTX build runs
on a host with one or more NVIDIA GPUs.

The CUDA MatMul backend automatically probes all CUDA devices visible to the
process and, by default, selects every supported device. Single-GPU systems
continue to use the same single-device path; multi-GPU systems shard
host-prepared MatMul digest batches across the selected devices.

This is a runtime scheduling feature only. It does not change MatMul consensus
rules, block headers, digest formats, `getblocktemplate`, or CPU verification.

## Build

CUDA remains an opt-in build dependency:

```bash
cmake -S . -B build-cuda \
  -DBTX_ENABLE_CUDA_EXPERIMENTAL=ON \
  -DCUDAToolkit_ROOT=/usr/local/cuda \
  -DCMAKE_CUDA_COMPILER=/usr/local/cuda/bin/nvcc \
  -DBTX_CUDA_ARCHITECTURES=120
cmake --build build-cuda -j"$(nproc)"
```

Set `BTX_CUDA_ARCHITECTURES` for the NVIDIA architecture you are building for.
For a single GPU family, one value is enough.

`BTX_CUDA_ARCHITECTURES` controls which CUDA device-code architectures NVCC
emits for BTX CUDA kernels. It is not a runtime device-selection setting and
does not only toggle CUDA library features. If the binary does not contain code
compatible with a selected GPU, that GPU may fail to run the kernels or may
fall back to less optimal JIT behavior.

For mixed GPU-family deployments, specify every compute capability required by
the cards in the rig as a semicolon-separated CMake list. Quote the value in
the shell because semicolons are command separators.

Common consumer and professional RTX examples:

| Generation | Consumer examples | Professional RTX examples | Compute capability | CMake value |
|---|---|---|---:|---:|
| Ampere | GeForce RTX 30xx | RTX A6000, RTX A5000, RTX A4000, RTX A3000, RTX A2000 | 8.6 | `86` |
| Ada | GeForce RTX 40xx | RTX 6000 Ada, RTX 5000 Ada, RTX 4500 Ada, RTX 4000 Ada, RTX 4000 SFF Ada, RTX 2000 Ada | 8.9 | `89` |
| Blackwell | GeForce RTX 50xx | RTX PRO 6000 Blackwell Server Edition, RTX PRO 6000 Blackwell Workstation Edition, RTX PRO 6000 Blackwell Max-Q Workstation Edition, RTX PRO 5000 Blackwell, RTX PRO 4500 Blackwell, RTX PRO 4000 Blackwell, RTX PRO 4000 Blackwell SFF Edition, RTX PRO 2000 Blackwell | 12.0 | `120` |

For a rig containing RTX 30xx, 40xx, and 50xx cards:

```bash
cmake -S . -B build-cuda \
  -DBTX_ENABLE_CUDA_EXPERIMENTAL=ON \
  -DCUDAToolkit_ROOT=/usr/local/cuda \
  -DCMAKE_CUDA_COMPILER=/usr/local/cuda/bin/nvcc \
  -DBTX_CUDA_ARCHITECTURES="86;89;120"
cmake --build build-cuda -j"$(nproc)"
```

Do not specify only the highest architecture for a mixed rig. A binary built
only for `120` is not appropriate for RTX 30xx or 40xx devices. Specifying only
the lowest architecture is also not the preferred production choice because it
can leave newer-device performance on the table. Build for the GPU families you
intend to run.

## Runtime Selection

Enable CUDA for MatMul solving with:

```bash
BTX_MATMUL_BACKEND=cuda ./build-cuda/bin/btxd -server=1
```

The CUDA runtime already honors `CUDA_VISIBLE_DEVICES`. BTX sees only the CUDA
ordinals exposed through that variable.

BTX selection is controlled by `BTX_MATMUL_CUDA_DEVICES`:

| Value | Behavior |
|---|---|
| unset | Select all supported visible CUDA devices |
| `auto` or `all` | Select all supported visible CUDA devices |
| `0` | Select only visible CUDA ordinal `0` |
| `0,1,3` | Select the listed visible CUDA ordinals |

Examples:

```bash
# Use every supported GPU visible to the process.
BTX_MATMUL_BACKEND=cuda ./build-cuda/bin/btxd -server=1

# Let CUDA expose only two physical GPUs, then let BTX use both visible ordinals.
CUDA_VISIBLE_DEVICES=2,5 BTX_MATMUL_BACKEND=cuda ./build-cuda/bin/btxd -server=1

# Restrict BTX to one visible CUDA ordinal.
BTX_MATMUL_BACKEND=cuda BTX_MATMUL_CUDA_DEVICES=0 ./build-cuda/bin/btxd -server=1
```

If a requested ordinal is not visible or is unsupported, CUDA capability
probing fails closed and backend selection falls back to CPU instead of
silently mining on an unintended device set.

## Probing

Use `btx-matmul-backend-info` before mining:

```bash
BTX_MATMUL_BACKEND=cuda ./build-cuda/bin/btx-matmul-backend-info --backend cuda
```

The CUDA section reports:

- `visible_device_count`
- `selected_device_count`
- `visible_devices`
- `selected_devices`
- per-device name, compute capability, memory, SM count, clock, memory bus,
  and PCI location fields
- aggregate CUDA digest buffer-pool stats across selected devices

On a single-GPU host, `visible_device_count` and `selected_device_count` should
normally both be `1`. On a multi-GPU host, `selected_device_count` should match
the number of supported devices you intend to mine with.

## Nonce-Seed Mining Device Selection

The post-`nMatMulNonceSeedHeight` CUDA nonce-seed mining path is intentionally
single-device today. It uses the first selected visible CUDA ordinal for
nonce-seed pre-hash scan, device-prepared input generation, and variable-base
digest batching.

To choose that device explicitly:

```bash
BTX_MATMUL_BACKEND=cuda \
BTX_MATMUL_CUDA_DEVICES=1 \
./build-cuda/bin/btxd -server=1
```

If more than one device is listed, the nonce-seed path uses the first entry:

```bash
BTX_MATMUL_BACKEND=cuda \
BTX_MATMUL_CUDA_DEVICES=1,0 \
./build-cuda/bin/btxd -server=1
```

This keeps nonce-seed batching compatible with the current device-prepared
input model while leaving multi-GPU nonce-seed sharding as a later
optimization.

## Work Sharding

For host-prepared CUDA digest batches, BTX plans one or more device shards per
batch and submits those shards concurrently. Results are merged back into the
original nonce order before the solver checks candidate blocks.

When `BTX_MATMUL_SOLVE_BATCH_SIZE` is unset, CUDA AUTO expands the solve batch
size to at least the selected device count. This keeps every selected GPU
eligible for one or more shards by default. A manual
`BTX_MATMUL_SOLVE_BATCH_SIZE` override remains an explicit operator cap; if it
is lower than the selected device count, only that many devices can receive
work in a single batch.

Default weighting:

- equivalent cards split work evenly
- heterogeneous cards are weighted by `SM count * clock rate` when clock data
  is available
- if clock data is unavailable, weighting falls back to SM count

This handles the common cases without manual configuration:

- same GPU model repeated in one host
- mixed NVIDIA GPUs with different SM counts or boost clocks
- a single visible GPU, which collapses to the existing single-device path

## Manual Weight Overrides

If the automatic split is wrong for a specific rig, set
`BTX_MATMUL_CUDA_DEVICE_WEIGHTS` to relative integer weights:

```bash
BTX_MATMUL_BACKEND=cuda \
BTX_MATMUL_CUDA_DEVICES=0,1 \
BTX_MATMUL_CUDA_DEVICE_WEIGHTS=0:100,1:60 \
./build-cuda/bin/btxd -server=1
```

The numbers are relative. A `100:60` split means device `0` receives roughly
`100 / 160` of the batch work and device `1` receives roughly `60 / 160`,
subject to whole-request rounding.

Invalid weight strings are ignored and BTX falls back to automatic weighting.

## Per-Device Pool Slots

CUDA digest buffers, streams, base-matrix caches, and pool slots are
device-local. `btx-matmul-backend-info` reports aggregate pool stats across the
selected devices.

By default, each selected device gets an automatically sized pool based on host
CPU concurrency and the device SM count.

Override all devices with one value:

```bash
BTX_MATMUL_CUDA_POOL_SLOTS=4
```

Override individual devices:

```bash
BTX_MATMUL_CUDA_POOL_SLOTS=0:2,1:4
```

Pool slot values are capped internally. Raising them can improve overlap on
larger GPUs, but it also increases device memory pressure.

## Device-Prepared CUDA Inputs

The product-digest CUDA path can generate and consume prepared input buffers
directly on the GPU. Those buffers are device-affine.

For a single selected CUDA device, automatic mining keeps the device-prepared
path enabled for product-digest mainnet-shaped work. This preserves the
single-device CUDA execution model that saturates the GPU on the RTX 5060
validation host.

When more than one CUDA device is selected, automatic
`BTX_MATMUL_CUDA_DEVICE_PREPARED_INPUTS` disables the device-prepared fast path
so host-prepared batches can be sharded across all selected GPUs. Forced
device preparation remains device-affine.

Do not force `BTX_MATMUL_CUDA_DEVICE_PREPARED_INPUTS=1` for multi-GPU mining
unless you are intentionally testing that path. The current generator targets
the first selected CUDA runtime device, so forcing device-prepared inputs can
collapse work back onto one GPU.

## CUDA-Generated Host Inputs

With multiple selected CUDA devices, automatic mining still allows CUDA to
generate prepared inputs and copy them back to host memory. This keeps the
digest inputs shardable, but input generation itself is not currently sharded.

Current multi-GPU AUTO flow:

```text
first selected CUDA device generates host inputs
selected CUDA devices digest their assigned shards
```

For equivalent GPUs this usually does not require manual ordering. For mixed
GPU families or capabilities, put the strongest input-generation device first
in `BTX_MATMUL_CUDA_DEVICES`:

```bash
BTX_MATMUL_BACKEND=cuda \
BTX_MATMUL_CUDA_DEVICES=2,0,1 \
./build-cuda/bin/btxd -server=1
```

In that example, device `2` generates CUDA host inputs, while digest batches
are still sharded across devices `2`, `0`, and `1` according to automatic or
manual weights.

If input generation becomes the bottleneck on a multi-GPU rig, compare against
CPU-prepared inputs:

```bash
BTX_MATMUL_GPU_INPUTS=0
```

This also keeps digest work shardable, but local single-GPU RTX 5060
benchmarks showed CPU-prepared inputs were about half the default throughput.

## Validation Status

The implementation is designed to be compatible with single-GPU systems and was
validated on a single-GPU CUDA workstation with:

- CUDA topology probing
- invalid-device fail-closed probing
- scheduler unit tests for equivalent, heterogeneous, unsupported, and manual
  weighted devices
- CUDA solve benchmarks for host-prepared and device-prepared paths
- temporary regtest block generation with `BTX_MATMUL_BACKEND=cuda`

Actual cross-device concurrency should still be validated on the target
multi-GPU rig before production use. Start with `btx-matmul-backend-info`, then
run short regtest mining and solve-bench checks before switching over a live
miner.

## Quick Checklist

1. Build with CUDA enabled and the correct `BTX_CUDA_ARCHITECTURES`.
2. Confirm Linux sees the intended NVIDIA GPUs.
3. Optionally set `CUDA_VISIBLE_DEVICES`.
4. Run `btx-matmul-backend-info --backend cuda`.
5. Confirm `selected_device_count` and per-device properties.
6. Start with automatic weights.
7. Add `BTX_MATMUL_CUDA_DEVICE_WEIGHTS` only if measured throughput shows a bad
   split.
8. Add per-device `BTX_MATMUL_CUDA_POOL_SLOTS` only after measuring memory use
   and overlap.
