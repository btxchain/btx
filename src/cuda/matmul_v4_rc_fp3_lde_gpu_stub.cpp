// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Non-CUDA / non-Metal link stub for BtxGpuFp3Lde*. Available() reports 0 so
// BTX_GPU_LDE fails HARD instead of silently running the CPU path when a GPU
// LDE was requested.

#include <matmul/matmul_v4_rc_fp3_lde_gpu.h>

extern "C" int BtxGpuFp3LdeAvailable(void) { return 0; }

extern "C" int BtxGpuFp3LdeBegin(uint32_t, const uint64_t*, uint32_t,
                                 const uint64_t*, uint32_t, uint64_t,
                                 void** ctx_out)
{
    if (ctx_out != nullptr) *ctx_out = nullptr;
    return -2;
}

extern "C" int BtxGpuFp3LdeForward(void*, const uint64_t*, uint32_t, uint64_t*)
{
    return -2;
}

extern "C" int BtxGpuFp3LdeInverse(void*, const uint64_t*, uint64_t*)
{
    return -2;
}

extern "C" void BtxGpuFp3LdeRelease(void*) {}
