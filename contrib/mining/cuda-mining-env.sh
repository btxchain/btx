#!/usr/bin/env bash
# RTX 5090 / Blackwell (sm_120, 128+ SM) MatMul CUDA mining defaults.
# Source before starting btxd or the live-mining supervisor.
#
# Usage:
#   source contrib/mining/cuda-mining-env.sh
#   ./build-cuda/bin/btxd -daemon ...
#
# Consensus-safe: these knobs only change scheduling/overlap, not digest math.
# BTX_MATMUL_CPU_CONFIRM stays enabled so GPU hits are re-verified on CPU.

export BTX_MATMUL_BACKEND=cuda
export BTX_MATMUL_PIPELINE_ASYNC=1
export BTX_MATMUL_CPU_CONFIRM=1
export BTX_MATMUL_GPU_INPUTS=1
export CUDA_DEVICE_ORDER=PCI_BUS_ID

# Ultra-tier AUTO heuristics (sm >= 128) widen batch/prefetch/pool slots in pow.cpp
# and matmul_accel.cu. Override one knob at a time when benchmarking:
#
# export BTX_MATMUL_SOLVE_BATCH_SIZE=12
# export BTX_MATMUL_CUDA_POOL_SLOTS=12
# export BTX_MATMUL_PREPARE_PREFETCH_DEPTH=6
# export BTX_MATMUL_SOLVER_THREADS=8
# export BTX_MATMUL_PREPARE_WORKERS=8
#
# Single-GPU product-digest mining (mainnet height >= 61000) auto-enables
# device-prepared inputs. Do not force that path on multi-GPU rigs.
#
# Verify the build and runtime:
#   ./build-cuda/bin/btx-matmul-backend-info --backend cuda
#   ./build-cuda/bin/btx-matmul-solve-bench --backend cuda --block-height 61000 \
#     --n 512 --b 16 --r 8 --iterations 20 --tries 4096
