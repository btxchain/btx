// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license.
//
// Non-CUDA link stub for the PR-89 GPU row-leaf sponge. Available() reports 0
// so the prover-side gate (BTX_GPU_ROWLEAF) fails HARD instead of silently
// running the CPU path when a GPU was requested.

#include <matmul/matmul_v4_rc_rowleaf_gpu.h>

extern "C" int BtxGpuRowLeafAvailable(void) { return 0; }
extern "C" int BtxGpuRowLeafSetConstants(const uint64_t*, const uint64_t*, const uint64_t*) { return -1; }
extern "C" int BtxGpuRowLeafBegin(uint32_t, void**) { return -1; }
extern "C" int BtxGpuRowLeafAbsorb(void*, const uint64_t*, uint32_t, uint64_t) { return -1; }
extern "C" int BtxGpuRowLeafFinalize(void*, uint64_t, uint64_t*) { return -1; }
extern "C" void BtxGpuRowLeafRelease(void*) {}
