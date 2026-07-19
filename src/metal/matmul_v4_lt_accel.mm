// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Apple Metal host glue for the MatMul v4.4 ENC-DR-LT ("MatExpand") mining
// backend.
//
// RELEASE SCOPE (explicitly allowed by this backend's task brief): no Metal
// compute kernels are wired yet. This TU runs the host-exact, template-
// amortized matmul::v4::lt::WindowSketchMinerLT pipeline -- byte-identical to
// matmul::v4::lt::ComputeDigestBMX4CLT by construction -- behind the Metal
// entry point, exactly mirroring how the reviewed BMX4-C CUDA context
// (cuda/matmul_v4_bmx4_context.h) documents "device buffers reserved for
// bring-up; the host-exact miner is the normative schedule today" for its
// own profile. A future revision can splice the portable integer-ALU / Metal
// 4 mpp::tensor_ops::matmul2d kernels from matmul_v4_bmx4_accel.mm into the
// window miner's P/Q GEMM stages once WindowSketchMinerLT exposes an
// injectable device backend. This file is deliberately kept free of any
// Objective-C/Metal API usage beyond the device-presence probe below, so it
// carries zero GPU correctness risk while still reporting truthful device
// availability.

#include <metal/matmul_v4_lt_accel.h>

#include <arith_uint256.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_lt.h>
#include <primitives/block.h>
#include <uint256.h>

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

#include <cstdint>
#include <vector>

namespace matmul_v4::metal {

bool IsMatMulLTMetalAvailable()
{
    id<MTLDevice> device = MTLCreateSystemDefaultDevice();
    return device != nil;
}

bool ComputeDigestsOnlyLTMetal(const CBlockHeader& tmpl, uint32_t n,
                               const uint64_t* nonces, size_t count,
                               std::vector<matmul::v4::lt::DigestOnlyResultLT>& out)
{
    out.clear();
    if (nonces == nullptr || count == 0) {
        return false;
    }

    uint32_t m = 0;
    if (!matmul::v4::lt::ValidateDimsBMX4CLT(n, m)) {
        return false;
    }

    matmul::v4::lt::WindowSketchMinerLT miner(tmpl, n);
    if (!miner.Valid()) {
        return false;
    }

    const std::vector<uint64_t> nonce_vec(nonces, nonces + count);
    const uint256 kNoTarget = ArithToUint256(~arith_uint256{});
    std::vector<matmul::v4::lt::DigestOnlyResultLT> results;
    if (!miner.Mine(nonce_vec, kNoTarget, results, nullptr)) {
        return false;
    }
    for (auto& r : results) {
        r.target_match = false;
        r.backend_status = matmul::v4::bmx4::DigestOnlyBackendStatus::Fallback;
    }

    out = std::move(results);
    return true;
}

} // namespace matmul_v4::metal
