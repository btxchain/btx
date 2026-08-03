// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Epoch-A ASERT calibration harness. This is the program that produced
// doc/evidence/asert-two-rig-calibration-2026-08-03; it is committed here so
// that campaign is reproducible rather than merely asserted.
//
// It is deliberately OUT OF TREE (not a CMake target): it links against the
// built static libraries of whatever revision you want to measure, so it must
// not be entangled with that revision's build graph.
//
// Build (Linux/CUDA), from the repo root after building the node:
//   g++ -std=c++20 -O2 -fopenmp -I src -I <build>/src \
//       -o <redacted-temporary-path> contrib/matmul-v4/measure-v3-regimes.cpp \
//       -Wl,--start-group <build>/lib/*.a <build>/src/libleveldb.a \
//       <build>/src/libcrc32c.a <build>/src/univalue/libunivalue.a \
//       <build>/src/secp256k1/lib/libsecp256k1.a -Wl,--end-group \
//       -L/usr/local/cuda/lib64 -lcudart -lcuda -lcublas -lcublasLt -lpthread
//
// Build (macOS/Metal):
//   clang++ -std=c++20 -O2 -Xpreprocessor -fopenmp \
//       -I/opt/homebrew/opt/libomp/include -I src -I <build>/src \
//       -o <redacted-temporary-path> contrib/matmul-v4/measure-v3-regimes.cpp \
//       <build>/lib/*.a <build>/src/libleveldb.a <build>/src/libcrc32c.a \
//       <build>/src/univalue/libunivalue.a \
//       <build>/src/secp256k1/lib/libsecp256k1.a \
//       -L/opt/homebrew/opt/libomp/lib -lomp -framework Metal \
//       -framework Foundation -framework CoreGraphics -framework Accelerate \
//       -framework IOKit -lpthread
//
// Run (set the backend explicitly; the ratio is only meaningful when both
// halves are measured on the SAME rig at the SAME revision):
//   BTX_MATMUL_V4_BACKEND=cuda  ./measure_v3 matmul 20000
//   BTX_MATMUL_V4_BACKEND=cuda  ./measure_v3 mixed  100000000 <seed>
//
// The quantity the consensus field wants is C = N/M, the PRE-GATE nonce-attempt
// rate over the RC episode rate. `mixed` reports attempts_per_s (that is N) and
// digest_requests (post-gate). M comes from a production canary corpus. Do NOT
// install the realized loosen k = 2^eps * p * C as the coefficient; see
// src/consensus/params.h on nMatMulRCAsertRescaleNum.

// Standalone (out-of-tree) measurement of the MatMul v3 two-stage mining
// pipeline rates on this host. Mirrors
// src/test/matmul_v3_asert_parent_ratio_measure.cpp field-for-field, but
// parameterises epsilon and nBits so the sigma-grind stage and the matmul
// stage can be separated.
//
// Modes:
//   sigma : eps=18, target=1   -> pre-hash gate essentially never passes
//                                 (P = 2^18/2^256), so attempts/s == R_sigma
//                                 (header-hash grind rate). This reproduces the
//                                 evidence file's 523462 attempts/s.
//   matmul: eps=255, target=1  -> pre-hash gate ALWAYS passes, so every attempt
//                                 runs one full v3 matmul digest:
//                                 attempts/s == R_M (digest trials/s).
//   mixed : eps=18, target=live mainnet nBits -> the real v3 loop.
//                                 attempts/s == R_nonce; the effective digest
//                                 trial rate is R_nonce * 2^18 * p.

#include <arith_uint256.h>
#include <chainparams.h>
#include <common/args.h>
#include <consensus/params.h>
#include <matmul/accelerated_solver.h>
#include <pow.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/translation.h>

const TranslateFn G_TRANSLATION_FUN{nullptr};

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <optional>
#include <string>

int main(int argc, char** argv)
{
    const std::string mode{argc > 1 ? argv[1] : "sigma"};
    const uint64_t tries{argc > 2 ? std::strtoull(argv[2], nullptr, 10) : 2'000'000ULL};
    const uint64_t seed_off{argc > 3 ? std::strtoull(argv[3], nullptr, 10) : 0ULL};

    ArgsManager args;
    auto chainparams = CreateChainParams(args, ChainType::MAIN);
    auto consensus = chainparams->GetConsensus();

    // Identical to the in-tree harness.
    consensus.fMatMulPOW = true;
    consensus.fSkipMatMulValidation = false;
    consensus.nMatMulDimension = 512;
    consensus.nMatMulMinDimension = 64;
    consensus.nMatMulTranscriptBlockSize = 16;
    consensus.nMatMulNoiseRank = 8;
    consensus.nMatMulNonceSeedHeight = 0;
    consensus.nMatMulParentMtpSeedHeight = 0;
    consensus.nMatMulProductDigestHeight = 0;
    consensus.nMatMulV4Height = std::numeric_limits<int32_t>::max();
    consensus.nMatMulBMX4CHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulDRLTHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulRCHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulRCCoupledHeight = std::numeric_limits<int32_t>::max();

    uint32_t eps = 18;
    // Live mainnet difficulty 3.531677073810059 at height 176445
    // (doc/evidence/.../asert-work-ratio-proposal.json live_network_context).
    // target = (0xffff << 208) / 3.531677073810059
    arith_uint256 target;
    if (mode == "matmul") {
        eps = 255;                     // gate always passes -> matmul every attempt
        target = arith_uint256{1};     // digest never wins
    } else if (mode == "mixed") {
        eps = 18;
        arith_uint256 diff1;
        diff1.SetCompact(0x1d00ffff);
        // divide by 3.531677073810059 ~= 3531677073810059 / 1e15
        target = diff1 / arith_uint256{3531677073810059ULL};
        target = target * arith_uint256{1000000000000000ULL};
    } else {
        eps = 18;
        target = arith_uint256{1};
    }
    consensus.nMatMulPreHashEpsilonBits = eps;
    consensus.nMatMulPreHashEpsilonBitsUpgrade = eps;
    consensus.nMatMulPreHashEpsilonBitsUpgradeHeight = 0;

    CBlockHeader header{};
    header.nVersion = 4;
    header.hashPrevBlock = uint256{"00000000000000000000000000000000000000000000000000000000000000a1"};
    header.hashMerkleRoot = uint256{"00000000000000000000000000000000000000000000000000000000000000a2"};
    header.nTime = 1780000000U;
    header.nBits = target.GetCompact();
    header.nNonce64 = seed_off;
    header.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    header.matmul_digest.SetNull();

    constexpr int32_t kHeight = 200000;
    constexpr int64_t kParentMtp = 1779999910;
    uint64_t max_tries = tries;

    matmul::accelerated::ResetMatMulBackendRuntimeStats();
    ResetMatMulSolveRuntimeStats();
    const auto t0 = std::chrono::steady_clock::now();
    const bool solved = SolveMatMul(header, consensus, max_tries, kHeight,
                                    /*abort_flag=*/nullptr,
                                    /*freivalds_payload_out=*/nullptr,
                                    /*share_target_override=*/nullptr,
                                    std::optional<int64_t>{kParentMtp});
    const auto t1 = std::chrono::steady_clock::now();
    const double wall_s = std::chrono::duration<double>(t1 - t0).count();
    const uint64_t done = tries - max_tries;
    const auto bs = matmul::accelerated::ProbeMatMulBackendRuntimeStats();

    std::printf("MEASURE_JSON:{\"mode\":\"%s\",\"eps\":%u,\"nBits\":\"%08x\","
                "\"tries\":%llu,\"attempts_done\":%llu,\"wall_s\":%.6f,"
                "\"attempts_per_s\":%.4f,\"solved\":%d,"
                "\"digest_requests\":%llu,\"requested_cpu\":%llu}\n",
                mode.c_str(), eps, header.nBits,
                (unsigned long long)tries, (unsigned long long)done, wall_s,
                wall_s > 0 ? double(done) / wall_s : 0.0, solved ? 1 : 0,
                (unsigned long long)bs.digest_requests,
                (unsigned long long)bs.requested_cpu);
    return 0;
}
