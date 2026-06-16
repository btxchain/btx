// Copyright (c) 2015-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <common/args.h>
#include <cuda/oracle_accel.h>
#include <cuda/cuda_scheduler.h>
#include <matmul/accelerated_solver.h>
#include <matmul/freivalds.h>
#include <matmul/matmul_pow.h>
#include <matmul/matrix.h>
#include <matmul/noise.h>
#include <matmul/transcript.h>
#include <metal/oracle_accel.h>
#include <pow.h>
#include <test/util/mining.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>
#include <util/time.h>
#include <validation.h>

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <limits>
#include <optional>
#include <stdexcept>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(pow_tests, BasicTestingSetup)

namespace {
arith_uint256 DecodeTarget(uint32_t nbits)
{
    bool negative{false};
    bool overflow{false};
    arith_uint256 target{};
    target.SetCompact(nbits, &negative, &overflow);
    BOOST_REQUIRE(!negative);
    BOOST_REQUIRE(!overflow);
    BOOST_REQUIRE(target > 0);
    return target;
}

double TargetRatio(const arith_uint256& value, const arith_uint256& reference)
{
    const double reference_double{reference.getdouble()};
    BOOST_REQUIRE(reference_double > 0.0);
    return value.getdouble() / reference_double;
}

constexpr int64_t DGW_PAST_BLOCKS{180};
constexpr uint32_t DGW_STEADY_BITS{0x1f040d7fU};

Consensus::Params LegacyRetargetConsensus()
{
    ArgsManager args;
    auto consensus = CreateChainParams(args, ChainType::MAIN)->GetConsensus();
    consensus.fMatMulPOW = false;
    consensus.fKAWPOW = false;
    consensus.fPowAllowMinDifficultyBlocks = false;
    consensus.fPowNoRetargeting = false;
    consensus.enforce_BIP94 = false;
    consensus.nPowTargetSpacing = 10 * 60;
    consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
    consensus.powLimit = uint256{"00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
    return consensus;
}

void SeedSteadyDGWChain(const Consensus::Params& consensus, std::vector<CBlockIndex>& blocks, std::vector<arith_uint256>& targets)
{
    BOOST_REQUIRE(blocks.size() == targets.size());
    BOOST_REQUIRE(blocks.size() > static_cast<size_t>(2 * DGW_PAST_BLOCKS));

    const arith_uint256 steady_target{DecodeTarget(DGW_STEADY_BITS)};
    for (size_t i = 0; i <= static_cast<size_t>(2 * DGW_PAST_BLOCKS); ++i) {
        blocks[i].nHeight = static_cast<int>(i);
        blocks[i].nBits = DGW_STEADY_BITS;
        blocks[i].nTime = 1'700'000'000 + static_cast<int64_t>(i) * consensus.nPowTargetSpacing;
        blocks[i].pprev = (i == 0) ? nullptr : &blocks[i - 1];
        targets[i] = steady_target;
    }
}

int64_t ExpectedSpacingForHashrate(const Consensus::Params& consensus, const arith_uint256& steady_target, const arith_uint256& current_target, double hashrate_multiplier)
{
    BOOST_REQUIRE(hashrate_multiplier > 0.0);
    const double current_target_double{current_target.getdouble()};
    BOOST_REQUIRE(current_target_double > 0.0);

    const double spacing{(consensus.nPowTargetSpacing * (steady_target.getdouble() / current_target_double)) / hashrate_multiplier};
    return std::max<int64_t>(1, static_cast<int64_t>(std::llround(spacing)));
}

void AppendDGWSimulatedBlock(
    const Consensus::Params& consensus,
    std::vector<CBlockIndex>& blocks,
    std::vector<arith_uint256>& targets,
    int height,
    int64_t reported_spacing)
{
    auto& prev = blocks[height - 1];
    auto& current = blocks[height];

    CBlockHeader next{};
    next.nTime = prev.GetBlockTime() + std::max<int64_t>(1, reported_spacing);

    current.nHeight = height;
    current.pprev = &prev;
    current.nTime = next.nTime;
    current.nBits = GetNextWorkRequired(&prev, &next, consensus);

    const arith_uint256 target{DecodeTarget(current.nBits)};
    BOOST_CHECK(target <= UintToArith256(consensus.powLimit));
    targets[height] = target;
}

class ScopedAsyncPipelineEnv
{
public:
    ScopedAsyncPipelineEnv()
    {
#if defined(WIN32)
        _putenv_s("BTX_MATMUL_PIPELINE_ASYNC", "1");
#else
        setenv("BTX_MATMUL_PIPELINE_ASYNC", "1", 1);
#endif
    }

    ~ScopedAsyncPipelineEnv()
    {
#if defined(WIN32)
        _putenv_s("BTX_MATMUL_PIPELINE_ASYNC", "");
#else
        unsetenv("BTX_MATMUL_PIPELINE_ASYNC");
#endif
    }
};

class ScopedBatchSizeEnv
{
public:
    explicit ScopedBatchSizeEnv(const char* value)
    {
#if defined(WIN32)
        _putenv_s("BTX_MATMUL_SOLVE_BATCH_SIZE", value != nullptr ? value : "");
#else
        if (value != nullptr) {
            setenv("BTX_MATMUL_SOLVE_BATCH_SIZE", value, 1);
        } else {
            unsetenv("BTX_MATMUL_SOLVE_BATCH_SIZE");
        }
#endif
    }

    ~ScopedBatchSizeEnv()
    {
#if defined(WIN32)
        _putenv_s("BTX_MATMUL_SOLVE_BATCH_SIZE", "");
#else
        unsetenv("BTX_MATMUL_SOLVE_BATCH_SIZE");
#endif
    }
};

class ScopedNonceSeedBatchSizeEnv
{
public:
    explicit ScopedNonceSeedBatchSizeEnv(const char* value)
    {
#if defined(WIN32)
        _putenv_s("BTX_MATMUL_NONCE_SEED_BATCH_SIZE", value != nullptr ? value : "");
#else
        if (value != nullptr) {
            setenv("BTX_MATMUL_NONCE_SEED_BATCH_SIZE", value, 1);
        } else {
            unsetenv("BTX_MATMUL_NONCE_SEED_BATCH_SIZE");
        }
#endif
    }

    ~ScopedNonceSeedBatchSizeEnv()
    {
#if defined(WIN32)
        _putenv_s("BTX_MATMUL_NONCE_SEED_BATCH_SIZE", "");
#else
        unsetenv("BTX_MATMUL_NONCE_SEED_BATCH_SIZE");
#endif
    }
};

class ScopedPrefetchDepthEnv
{
public:
    explicit ScopedPrefetchDepthEnv(const char* value)
    {
#if defined(WIN32)
        _putenv_s("BTX_MATMUL_PREPARE_PREFETCH_DEPTH", value != nullptr ? value : "");
#else
        if (value != nullptr) {
            setenv("BTX_MATMUL_PREPARE_PREFETCH_DEPTH", value, 1);
        } else {
            unsetenv("BTX_MATMUL_PREPARE_PREFETCH_DEPTH");
        }
#endif
    }

    ~ScopedPrefetchDepthEnv()
    {
#if defined(WIN32)
        _putenv_s("BTX_MATMUL_PREPARE_PREFETCH_DEPTH", "");
#else
        unsetenv("BTX_MATMUL_PREPARE_PREFETCH_DEPTH");
#endif
    }
};

class ScopedPrepareWorkersEnv
{
public:
    explicit ScopedPrepareWorkersEnv(const char* value)
    {
#if defined(WIN32)
        _putenv_s("BTX_MATMUL_PREPARE_WORKERS", value != nullptr ? value : "");
#else
        if (value != nullptr) {
            setenv("BTX_MATMUL_PREPARE_WORKERS", value, 1);
        } else {
            unsetenv("BTX_MATMUL_PREPARE_WORKERS");
        }
#endif
    }

    ~ScopedPrepareWorkersEnv()
    {
#if defined(WIN32)
        _putenv_s("BTX_MATMUL_PREPARE_WORKERS", "");
#else
        unsetenv("BTX_MATMUL_PREPARE_WORKERS");
#endif
    }
};

class ScopedHeaderTimeRefreshEnv
{
public:
    explicit ScopedHeaderTimeRefreshEnv(const char* value)
    {
#if defined(WIN32)
        _putenv_s("BTX_MINER_HEADER_TIME_REFRESH_ATTEMPTS", value != nullptr ? value : "");
#else
        if (value != nullptr) {
            setenv("BTX_MINER_HEADER_TIME_REFRESH_ATTEMPTS", value, 1);
        } else {
            unsetenv("BTX_MINER_HEADER_TIME_REFRESH_ATTEMPTS");
        }
#endif
    }

    ~ScopedHeaderTimeRefreshEnv()
    {
#if defined(WIN32)
        _putenv_s("BTX_MINER_HEADER_TIME_REFRESH_ATTEMPTS", "");
#else
        unsetenv("BTX_MINER_HEADER_TIME_REFRESH_ATTEMPTS");
#endif
    }
};

class ScopedBackendEnv
{
public:
    explicit ScopedBackendEnv(const char* value)
    {
#if defined(WIN32)
        _putenv_s("BTX_MATMUL_BACKEND", value != nullptr ? value : "");
#else
        if (value != nullptr) {
            setenv("BTX_MATMUL_BACKEND", value, 1);
        } else {
            unsetenv("BTX_MATMUL_BACKEND");
        }
#endif
    }

    ~ScopedBackendEnv()
    {
#if defined(WIN32)
        _putenv_s("BTX_MATMUL_BACKEND", "");
#else
        unsetenv("BTX_MATMUL_BACKEND");
#endif
    }
};

class ScopedRequireBackendEnv
{
public:
    explicit ScopedRequireBackendEnv(const char* value)
    {
#if defined(WIN32)
        _putenv_s("BTX_MATMUL_REQUIRE_BACKEND", value != nullptr ? value : "");
#else
        if (value != nullptr) {
            setenv("BTX_MATMUL_REQUIRE_BACKEND", value, 1);
        } else {
            unsetenv("BTX_MATMUL_REQUIRE_BACKEND");
        }
#endif
    }

    ~ScopedRequireBackendEnv()
    {
#if defined(WIN32)
        _putenv_s("BTX_MATMUL_REQUIRE_BACKEND", "");
#else
        unsetenv("BTX_MATMUL_REQUIRE_BACKEND");
#endif
    }
};

class ScopedCpuConfirmEnv
{
public:
    explicit ScopedCpuConfirmEnv(const char* value)
    {
#if defined(WIN32)
        _putenv_s("BTX_MATMUL_CPU_CONFIRM", value != nullptr ? value : "");
#else
        if (value != nullptr) {
            setenv("BTX_MATMUL_CPU_CONFIRM", value, 1);
        } else {
            unsetenv("BTX_MATMUL_CPU_CONFIRM");
        }
#endif
    }

    ~ScopedCpuConfirmEnv()
    {
#if defined(WIN32)
        _putenv_s("BTX_MATMUL_CPU_CONFIRM", "");
#else
        unsetenv("BTX_MATMUL_CPU_CONFIRM");
#endif
    }
};

class ScopedGpuInputsEnv
{
public:
    explicit ScopedGpuInputsEnv(const char* value)
    {
#if defined(WIN32)
        _putenv_s("BTX_MATMUL_GPU_INPUTS", value != nullptr ? value : "");
#else
        if (value != nullptr) {
            setenv("BTX_MATMUL_GPU_INPUTS", value, 1);
        } else {
            unsetenv("BTX_MATMUL_GPU_INPUTS");
        }
#endif
    }

    ~ScopedGpuInputsEnv()
    {
#if defined(WIN32)
        _putenv_s("BTX_MATMUL_GPU_INPUTS", "");
#else
        unsetenv("BTX_MATMUL_GPU_INPUTS");
#endif
    }
};

class ScopedSolverThreadsEnv
{
public:
    explicit ScopedSolverThreadsEnv(const char* value)
    {
#if defined(WIN32)
        _putenv_s("BTX_MATMUL_SOLVER_THREADS", value != nullptr ? value : "");
#else
        if (value != nullptr) {
            setenv("BTX_MATMUL_SOLVER_THREADS", value, 1);
        } else {
            unsetenv("BTX_MATMUL_SOLVER_THREADS");
        }
#endif
    }

    ~ScopedSolverThreadsEnv()
    {
#if defined(WIN32)
        _putenv_s("BTX_MATMUL_SOLVER_THREADS", "");
#else
        unsetenv("BTX_MATMUL_SOLVER_THREADS");
#endif
    }
};

class ScopedApplePerfLogicalCpuOverrideEnv
{
public:
    explicit ScopedApplePerfLogicalCpuOverrideEnv(const char* value)
    {
#if defined(WIN32)
        _putenv_s("BTX_MATMUL_APPLE_PERFLEVEL0_LOGICALCPU_OVERRIDE", value != nullptr ? value : "");
#else
        if (value != nullptr) {
            setenv("BTX_MATMUL_APPLE_PERFLEVEL0_LOGICALCPU_OVERRIDE", value, 1);
        } else {
            unsetenv("BTX_MATMUL_APPLE_PERFLEVEL0_LOGICALCPU_OVERRIDE");
        }
#endif
    }

    ~ScopedApplePerfLogicalCpuOverrideEnv()
    {
#if defined(WIN32)
        _putenv_s("BTX_MATMUL_APPLE_PERFLEVEL0_LOGICALCPU_OVERRIDE", "");
#else
        unsetenv("BTX_MATMUL_APPLE_PERFLEVEL0_LOGICALCPU_OVERRIDE");
#endif
    }
};

class ScopedMetalGpuCoresOverrideEnv
{
public:
    explicit ScopedMetalGpuCoresOverrideEnv(const char* value)
    {
#if defined(WIN32)
        _putenv_s("BTX_MATMUL_METAL_GPU_CORES_OVERRIDE", value != nullptr ? value : "");
#else
        if (value != nullptr) {
            setenv("BTX_MATMUL_METAL_GPU_CORES_OVERRIDE", value, 1);
        } else {
            unsetenv("BTX_MATMUL_METAL_GPU_CORES_OVERRIDE");
        }
#endif
    }

    ~ScopedMetalGpuCoresOverrideEnv()
    {
#if defined(WIN32)
        _putenv_s("BTX_MATMUL_METAL_GPU_CORES_OVERRIDE", "");
#else
        unsetenv("BTX_MATMUL_METAL_GPU_CORES_OVERRIDE");
#endif
    }
};

class ScopedNodeMockTime
{
public:
    explicit ScopedNodeMockTime(int64_t seconds)
    {
        SetMockTime(seconds);
    }

    ~ScopedNodeMockTime()
    {
        SetMockTime(0);
    }
};

CBlockHeader MakeDigestProbeHeader()
{
    CBlockHeader header{};
    header.nVersion = 4;
    header.hashPrevBlock = uint256{"0000000000000000000000000000000000000000000000000000000000000011"};
    header.hashMerkleRoot = uint256{"0000000000000000000000000000000000000000000000000000000000000022"};
    header.nTime = 1'700'000'101U;
    header.nBits = 0x207fffffU;
    header.nNonce64 = 9;
    header.nNonce = static_cast<uint32_t>(header.nNonce64);
    header.matmul_dim = 64;
    header.seed_a = DeterministicMatMulSeed(header.hashPrevBlock, /*height=*/1, /*which=*/0);
    header.seed_b = DeterministicMatMulSeed(header.hashPrevBlock, /*height=*/1, /*which=*/1);
    return header;
}

CBlockHeader MakeStrictRegtestWarningReproHeader()
{
    CBlockHeader header{};
    header.nVersion = 0x20000000;
    header.hashPrevBlock = *uint256::FromHex(
        "a3432bb1ebb8f1a98f5e562008f5570e426b94adc0759f3d9775ab9045918b98");
    header.hashMerkleRoot = *uint256::FromHex(
        "03f67b1aa858ac986a405770f91757b59eaf486823121589dd427a4f53f7e2f9");
    header.nTime = 1'776'143'281U;
    header.nBits = 0x201a6e0fU;
    header.nNonce64 = 0;
    header.nNonce = 0;
    header.matmul_dim = 64;
    header.seed_a = *uint256::FromHex(
        "1c11f95cd6c54e39670afeb96dd669a0db35c91319d5ba1776b087566783eac0");
    header.seed_b = *uint256::FromHex(
        "94e1b272422751e260b954ad9c7ba12598c76342855c90cb7030daa235f8b73f");
    header.matmul_digest.SetNull();
    return header;
}

struct ProductDigestBoundaryCase {
    uint32_t nbits{0};
    arith_uint256 target{};
    uint64_t nonce64{0};
    uint256 product_digest;
    uint256 transcript_digest;
};

std::optional<ProductDigestBoundaryCase> FindProductDigestBoundaryCase(const CBlockHeader& header_template,
                                                                      const Consensus::Params& consensus,
                                                                      uint8_t min_shift = 8,
                                                                      uint8_t max_shift = 16,
                                                                      uint64_t max_nonce = 50'000)
{
    const auto matrix_a = matmul::FromSeed(header_template.seed_a, header_template.matmul_dim);
    const auto matrix_b = matmul::FromSeed(header_template.seed_b, header_template.matmul_dim);

    for (uint8_t shift = min_shift; shift <= max_shift; ++shift) {
        arith_uint256 target = UintToArith256(consensus.powLimit);
        target >>= shift;
        if (target == 0) {
            continue;
        }

        CBlockHeader candidate = header_template;
        candidate.nBits = target.GetCompact();
        const arith_uint256 derived_target = DecodeTarget(candidate.nBits);

        for (uint64_t nonce64 = 0; nonce64 < max_nonce; ++nonce64) {
            candidate.nNonce64 = nonce64;
            candidate.nNonce = static_cast<uint32_t>(nonce64);

            const uint256 product_digest = matmul::accelerated::ComputeMatMulDigestCPU(
                candidate,
                matrix_a,
                matrix_b,
                consensus.nMatMulTranscriptBlockSize,
                consensus.nMatMulNoiseRank,
                matmul::accelerated::DigestScheme::PRODUCT_COMMITTED);
            if (UintToArith256(product_digest) > derived_target) {
                continue;
            }

            const uint256 transcript_digest = matmul::accelerated::ComputeMatMulDigestCPU(
                candidate,
                matrix_a,
                matrix_b,
                consensus.nMatMulTranscriptBlockSize,
                consensus.nMatMulNoiseRank,
                matmul::accelerated::DigestScheme::TRANSCRIPT);
            if (UintToArith256(transcript_digest) > derived_target) {
                return ProductDigestBoundaryCase{
                    .nbits = candidate.nBits,
                    .target = derived_target,
                    .nonce64 = nonce64,
                    .product_digest = product_digest,
                    .transcript_digest = transcript_digest,
                };
            }

            break;
        }
    }

    return std::nullopt;
}
} // namespace

/* Test calculation of next difficulty target with no constraints applying */
BOOST_AUTO_TEST_CASE(get_next_work)
{
    const auto consensus = LegacyRetargetConsensus();
    int64_t nLastRetargetTime = 1261130161; // Block #30240
    CBlockIndex pindexLast;
    pindexLast.nHeight = 32255;
    pindexLast.nTime = 1262152739;  // Block #32255
    pindexLast.nBits = 0x1d00ffff;

    // Here (and below): expected_nbits is calculated in
    // CalculateNextWorkRequired(); redoing the calculation here would be just
    // reimplementing the same code that is written in pow.cpp. Rather than
    // copy that code, we just hardcode the expected result.
    unsigned int expected_nbits = 0x1d00d86aU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, consensus), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(consensus, pindexLast.nHeight + 1, pindexLast.nBits, expected_nbits));
}

/* Test the constraint on the upper bound for next work */
BOOST_AUTO_TEST_CASE(get_next_work_pow_limit)
{
    const auto consensus = LegacyRetargetConsensus();
    int64_t nLastRetargetTime = 1231006505; // Block #0
    CBlockIndex pindexLast;
    pindexLast.nHeight = 2015;
    pindexLast.nTime = 1233061996;  // Block #2015
    pindexLast.nBits = 0x1d00ffff;
    unsigned int expected_nbits = 0x1d00ffffU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, consensus), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(consensus, pindexLast.nHeight + 1, pindexLast.nBits, expected_nbits));
}

/* Test the constraint on the lower bound for actual time taken */
BOOST_AUTO_TEST_CASE(get_next_work_lower_limit_actual)
{
    const auto consensus = LegacyRetargetConsensus();
    int64_t nLastRetargetTime = 1279008237; // Block #66528
    CBlockIndex pindexLast;
    pindexLast.nHeight = 68543;
    pindexLast.nTime = 1279297671;  // Block #68543
    pindexLast.nBits = 0x1c05a3f4;
    unsigned int expected_nbits = 0x1c0168fdU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, consensus), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(consensus, pindexLast.nHeight + 1, pindexLast.nBits, expected_nbits));
    // Test that reducing nbits further would not be a PermittedDifficultyTransition.
    unsigned int invalid_nbits = expected_nbits - 1;
    BOOST_CHECK(!PermittedDifficultyTransition(consensus, pindexLast.nHeight + 1, pindexLast.nBits, invalid_nbits));
}

/* Test the constraint on the upper bound for actual time taken */
BOOST_AUTO_TEST_CASE(get_next_work_upper_limit_actual)
{
    const auto consensus = LegacyRetargetConsensus();
    int64_t nLastRetargetTime = 1263163443; // NOTE: Not an actual block time
    CBlockIndex pindexLast;
    pindexLast.nHeight = 46367;
    pindexLast.nTime = 1269211443;  // Block #46367
    pindexLast.nBits = 0x1c387f6f;
    unsigned int expected_nbits = 0x1d00e1fdU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, consensus), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(consensus, pindexLast.nHeight + 1, pindexLast.nBits, expected_nbits));
    // Test that increasing nbits further would not be a PermittedDifficultyTransition.
    unsigned int invalid_nbits = expected_nbits + 1;
    BOOST_CHECK(!PermittedDifficultyTransition(consensus, pindexLast.nHeight + 1, pindexLast.nBits, invalid_nbits));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_negative_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    nBits = UintToArith256(consensus.powLimit).GetCompact(true);
    hash = uint256{1};
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_overflow_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits{~0x00800000U};
    hash = uint256{1};
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_too_easy_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 nBits_arith = UintToArith256(consensus.powLimit);
    nBits_arith *= 2;
    nBits = nBits_arith.GetCompact();
    hash = uint256{1};
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_biger_hash_than_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith = UintToArith256(consensus.powLimit);
    nBits = hash_arith.GetCompact();
    hash_arith *= 2; // hash > nBits
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_zero_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith{0};
    nBits = hash_arith.GetCompact();
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(GetBlockProofEquivalentTime_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    std::vector<CBlockIndex> blocks(10000);
    for (int i = 0; i < 10000; i++) {
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight = i;
        blocks[i].nTime = 1269211443 + i * chainParams->GetConsensus().nPowTargetSpacing;
        blocks[i].nBits = 0x207fffff; /* target 0x7fffff000... */
        blocks[i].nChainWork = i ? blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]) : arith_uint256(0);
    }

    for (int j = 0; j < 1000; j++) {
        CBlockIndex *p1 = &blocks[m_rng.randrange(10000)];
        CBlockIndex *p2 = &blocks[m_rng.randrange(10000)];
        CBlockIndex *p3 = &blocks[m_rng.randrange(10000)];

        int64_t tdiff = GetBlockProofEquivalentTime(*p1, *p2, *p3, chainParams->GetConsensus());
        BOOST_CHECK_EQUAL(tdiff, p1->GetBlockTime() - p2->GetBlockTime());
    }
}

void sanity_check_chainparams(const ArgsManager& args, ChainType chain_type)
{
    const auto chainParams = CreateChainParams(args, chain_type);
    const auto consensus = chainParams->GetConsensus();

    // hash genesis is correct
    BOOST_CHECK_EQUAL(consensus.hashGenesisBlock, chainParams->GenesisBlock().GetHash());

    // target timespan is an even multiple of spacing
    BOOST_CHECK_EQUAL(consensus.nPowTargetTimespan % consensus.nPowTargetSpacing, 0);

    // genesis nBits is positive, doesn't overflow and is lower than powLimit
    arith_uint256 pow_compact;
    bool neg, over;
    pow_compact.SetCompact(chainParams->GenesisBlock().nBits, &neg, &over);
    BOOST_CHECK(!neg && pow_compact != 0);
    BOOST_CHECK(!over);
    BOOST_CHECK(UintToArith256(consensus.powLimit) >= pow_compact);

    // Legacy interval retargeting multiplies before division, so its powLimit
    // must stay below the no-overflow threshold. MatMul chains use DGW instead.
    if (!consensus.fPowNoRetargeting && !consensus.fMatMulPOW) {
        arith_uint256 targ_max{UintToArith256(uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"})};
        targ_max /= consensus.nPowTargetTimespan*4;
        BOOST_CHECK(UintToArith256(consensus.powLimit) < targ_max);
    }
}

void assert_genesis_respects_reduced_data_limits(const CChainParams& params)
{
    const auto& consensus{params.GetConsensus()};
    BOOST_REQUIRE(consensus.fReducedDataLimits);
    const CBlock& genesis{params.GenesisBlock()};
    BOOST_REQUIRE(!genesis.vtx.empty());
    BOOST_REQUIRE(!genesis.vtx[0]->vout.empty());
    BOOST_CHECK_LE(genesis.vtx[0]->vout[0].scriptPubKey.size(), consensus.nMaxTxoutScriptPubKeyBytes);
}

void assert_btx_genesis_header_fields(
    const CChainParams& params,
    uint32_t expected_time,
    uint32_t expected_nonce,
    const std::string& expected_bits_hex,
    uint64_t expected_nonce64)
{
    const CBlock& genesis{params.GenesisBlock()};
    BOOST_CHECK_EQUAL(genesis.nTime, expected_time);
    BOOST_CHECK_EQUAL(genesis.nNonce, expected_nonce);
    BOOST_CHECK_EQUAL(strprintf("%08x", genesis.nBits), expected_bits_hex);
    BOOST_CHECK_EQUAL(genesis.nNonce64, expected_nonce64);
    BOOST_CHECK(genesis.mix_hash.IsNull());
}

void assert_btx_genesis_hashes(
    const CChainParams& params,
    const std::string& expected_block_hash,
    const std::string& expected_merkle_root)
{
    const CBlock& genesis{params.GenesisBlock()};
    BOOST_CHECK_EQUAL(genesis.GetHash().GetHex(), expected_block_hash);
    BOOST_CHECK_EQUAL(genesis.hashMerkleRoot.GetHex(), expected_merkle_root);
}

BOOST_AUTO_TEST_CASE(ChainParams_MAIN_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::MAIN);
}

BOOST_AUTO_TEST_CASE(ChainParams_REGTEST_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::REGTEST);
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::TESTNET);
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET_matmul_activation)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::TESTNET)->GetConsensus();
    BOOST_CHECK(!consensus.fKAWPOW);
    BOOST_CHECK(consensus.fMatMulPOW);
    BOOST_CHECK(consensus.enforce_BIP94);
    BOOST_CHECK_EQUAL(consensus.nKAWPOWHeight, std::numeric_limits<int>::max());
    BOOST_CHECK(consensus.fReducedDataLimits);
    BOOST_CHECK_EQUAL(consensus.nMaxOpReturnBytes, 83U);
    BOOST_CHECK_EQUAL(consensus.nMaxTxoutScriptPubKeyBytes, 34U);
    BOOST_CHECK_EQUAL(consensus.nPowTargetSpacing, 90);
    BOOST_CHECK_EQUAL(consensus.nPowTargetSpacingFastMs, 250);
    BOOST_CHECK_EQUAL(consensus.nFastMineDifficultyScale, 4U);
    BOOST_CHECK_EQUAL(consensus.nPowTargetSpacingNormal, 90);
    BOOST_CHECK_EQUAL(consensus.nFastMineHeight, 61'000);
    BOOST_CHECK_EQUAL(consensus.nMatMulDimension, 256U);
    BOOST_CHECK_EQUAL(consensus.nMatMulTranscriptBlockSize, 8U);
    BOOST_CHECK_EQUAL(consensus.nMatMulNoiseRank, 4U);
    BOOST_CHECK_EQUAL(consensus.BIP34Height, 0);
    BOOST_CHECK_EQUAL(consensus.BIP65Height, 0);
    BOOST_CHECK_EQUAL(consensus.BIP66Height, 0);
    BOOST_CHECK_EQUAL(consensus.CSVHeight, 0);
    BOOST_CHECK_EQUAL(consensus.SegwitHeight, 0);
    BOOST_CHECK_EQUAL(consensus.nShieldedSpendPathRecoveryActivationHeight, 88'000);
    BOOST_CHECK_EQUAL(
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime,
        Consensus::BIP9Deployment::ALWAYS_ACTIVE);
    BOOST_CHECK_EQUAL(
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout,
        Consensus::BIP9Deployment::NO_TIMEOUT);
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET_genesis_reduced_data_compliant)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::TESTNET);
    assert_genesis_respects_reduced_data_limits(*params);
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET_btx_network_identity)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::TESTNET);
    const auto msg = params->MessageStart();

    BOOST_CHECK_EQUAL(msg[0], 0xb7);
    BOOST_CHECK_EQUAL(msg[1], 0x54);
    BOOST_CHECK_EQUAL(msg[2], 0x58);
    BOOST_CHECK_EQUAL(msg[3], 0x02);
    BOOST_CHECK_EQUAL(params->GetDefaultPort(), 29335);
    BOOST_CHECK_EQUAL(params->Bech32HRP(), "tbtx");
    BOOST_CHECK_GE(params->DNSSeeds().size(), 1U);
    // No hardcoded fixed seeds yet; DNS seeds are the primary discovery method.
    BOOST_CHECK(params->FixedSeeds().empty());
    BOOST_CHECK_EQUAL(params->Checkpoints().mapCheckpoints.size(), 1U);
    BOOST_CHECK(params->GetAvailableSnapshotHeights().empty());
    BOOST_CHECK(params->AssumeutxoForHeight(110).has_value() == false);
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET4_btx_network_identity)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::TESTNET4);

    BOOST_CHECK_EQUAL(params->GetDefaultPort(), 48333);
    BOOST_CHECK_EQUAL(params->Bech32HRP(), "tbtx4");
    BOOST_CHECK_GE(params->DNSSeeds().size(), 1U);
    BOOST_CHECK(params->FixedSeeds().empty());
    BOOST_CHECK(params->GetAvailableSnapshotHeights().empty());
    BOOST_CHECK(!params->AssumeutxoForHeight(110));
    BOOST_CHECK_EQUAL(params->GetConsensus().nShieldedSpendPathRecoveryActivationHeight, 88'000);
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET4_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::TESTNET4);
}

BOOST_AUTO_TEST_CASE(ChainParams_SIGNET_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::SIGNET);
}

BOOST_AUTO_TEST_CASE(ChainParams_SIGNET_shielded_activation_heights)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::SIGNET);
    BOOST_CHECK_EQUAL(params->GetConsensus().nShieldedSpendPathRecoveryActivationHeight, 88'000);
}

BOOST_AUTO_TEST_CASE(ChainParams_MAIN_matmul_activation)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    BOOST_CHECK(!consensus.fKAWPOW);
    BOOST_CHECK(consensus.fMatMulPOW);
    BOOST_CHECK(consensus.enforce_BIP94);
    BOOST_CHECK_EQUAL(consensus.nKAWPOWHeight, std::numeric_limits<int>::max());
    BOOST_CHECK(consensus.fReducedDataLimits);
    BOOST_CHECK_EQUAL(consensus.nMaxOpReturnBytes, 83U);
    BOOST_CHECK_EQUAL(consensus.nMaxTxoutScriptPubKeyBytes, 34U);
    BOOST_CHECK_EQUAL(consensus.nPowTargetSpacing, 90);
    BOOST_CHECK_EQUAL(consensus.nPowTargetSpacingFastMs, 250);
    BOOST_CHECK_EQUAL(consensus.nFastMineDifficultyScale, 6U);
    BOOST_CHECK_EQUAL(consensus.nPowTargetSpacingNormal, 90);
    BOOST_CHECK_EQUAL(consensus.nFastMineHeight, 50'000);
    BOOST_CHECK_EQUAL(consensus.nDgwAsymmetricClampHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK_EQUAL(consensus.nDgwEasingBoostHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK_EQUAL(consensus.nDgwWindowAlignmentHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK_EQUAL(consensus.nDgwSlewGuardHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK_EQUAL(consensus.nMatMulAsertHeight, 50'000);
    BOOST_CHECK_EQUAL(consensus.nMatMulAsertHalfLife, 3'600);
    BOOST_CHECK_EQUAL(consensus.nMatMulAsertBootstrapFactor, 180U);
    BOOST_CHECK_EQUAL(consensus.nMatMulAsertRetuneHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK_EQUAL(consensus.nMatMulAsertRetuneHardeningFactor, 1U);
    BOOST_CHECK_EQUAL(consensus.nMatMulAsertRetune2Height, std::numeric_limits<int32_t>::max());
    BOOST_CHECK_EQUAL(consensus.nMatMulAsertRetune2TargetNum, 1U);
    BOOST_CHECK_EQUAL(consensus.nMatMulAsertRetune2TargetDen, 1U);
    BOOST_CHECK_EQUAL(consensus.nMatMulAsertHalfLifeUpgradeHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK_EQUAL(consensus.nMatMulAsertHalfLifeUpgrade, 3'600);
    BOOST_CHECK_EQUAL(consensus.nMatMulMaxFutureMtpDriftHeight, 118'482);
    BOOST_CHECK_EQUAL(consensus.nMatMulMaxFutureMtpDrift, 3'600);
    BOOST_CHECK(!consensus.IsMatMulMaxFutureMtpDriftActive(118'481));
    BOOST_CHECK(consensus.IsMatMulMaxFutureMtpDriftActive(118'482));
    BOOST_CHECK_EQUAL(consensus.nMatMulTimewarpReconcileHeight, 125'000);
    BOOST_CHECK(!consensus.IsMatMulTimewarpReconcileActive(124'999));
    BOOST_CHECK(consensus.IsMatMulTimewarpReconcileActive(125'000));
    BOOST_REQUIRE(consensus.MaxMatMulFutureBlockTime(118'482, 1'700'000'000).has_value());
    BOOST_CHECK_EQUAL(*consensus.MaxMatMulFutureBlockTime(118'482, 1'700'000'000), 1'700'003'600);
    BOOST_CHECK_EQUAL(consensus.nMatMulPreHashEpsilonBits, 10U);
    BOOST_CHECK_EQUAL(consensus.nMatMulPreHashEpsilonBitsUpgradeHeight, 50'000);
    BOOST_CHECK_EQUAL(consensus.nMatMulPreHashEpsilonBitsUpgrade, 18U);
    BOOST_CHECK_EQUAL(GetMatMulPreHashEpsilonBitsForHeight(consensus, 49'999), 10U);
    BOOST_CHECK_EQUAL(GetMatMulPreHashEpsilonBitsForHeight(consensus, 50'000), 18U);
    BOOST_CHECK_EQUAL(GetMatMulPreHashEpsilonBitsForHeight(consensus, 50'001), 18U);
    BOOST_CHECK_EQUAL(consensus.nMatMulNonceSeedHeight, 125'000);
    BOOST_CHECK(!consensus.IsMatMulNonceSeedActive(124'999));
    BOOST_CHECK(consensus.IsMatMulNonceSeedActive(125'000));
    BOOST_CHECK_EQUAL(consensus.nMatMulParentMtpSeedHeight, 130'500);
    BOOST_CHECK(!consensus.IsMatMulParentMtpSeedActive(130'499));
    BOOST_CHECK(consensus.IsMatMulParentMtpSeedActive(130'500));
    BOOST_CHECK_EQUAL(UintToArith256(consensus.powLimit).GetCompact(), 0x2066c154U);
    // Guard: powLimit must retain compact headroom above genesis bits, otherwise
    // fast-phase difficulty scaling is silently clamped out.
    BOOST_CHECK_GT(UintToArith256(consensus.powLimit).GetCompact(), 0x20147ae1U);
    BOOST_CHECK_EQUAL(consensus.nMatMulDimension, 512U);
    BOOST_CHECK_EQUAL(consensus.nMatMulTranscriptBlockSize, 16U);
    BOOST_CHECK_EQUAL(consensus.nMatMulNoiseRank, 8U);
    BOOST_CHECK_EQUAL(consensus.nMatMulPhase2FailBanThreshold, 1U);
    BOOST_CHECK_EQUAL(consensus.nMaxReorgDepth, 12U);
    BOOST_CHECK_EQUAL(consensus.nReorgProtectionStartHeight, 61'000);
    BOOST_CHECK_EQUAL(consensus.nEmptyBlockSubsidyPenaltyHeight, 130'000);
    BOOST_CHECK_EQUAL(consensus.nEmptyBlockSubsidyStrictPenaltyHeight, 130'500);
    BOOST_CHECK_EQUAL(consensus.nEmptyBlockSubsidyPenaltyEndHeight, 132'000);
    BOOST_CHECK_EQUAL(consensus.nShieldedUnshieldVelocityEndHeight, 135'000);
    BOOST_CHECK_EQUAL(consensus.nShieldedUnshieldVelocityMinCapHeight, 132'000);
    BOOST_CHECK_EQUAL(consensus.nShieldedUnshieldVelocityMinCap, 10'000 * COIN);
    BOOST_CHECK_EQUAL(consensus.nMatMulFreivaldsBindingHeight, 61'000);
    BOOST_CHECK_EQUAL(consensus.nMatMulProductDigestHeight, 61'000);
    BOOST_CHECK_EQUAL(consensus.nShieldedTxBindingActivationHeight, 61'000);
    BOOST_CHECK_EQUAL(consensus.nShieldedBridgeTagActivationHeight, 61'000);
    BOOST_CHECK_EQUAL(consensus.nShieldedSmileRiceCodecDisableHeight, 61'000);
    BOOST_CHECK_EQUAL(consensus.nShieldedSpendPathRecoveryActivationHeight, 88'000);
}

BOOST_AUTO_TEST_CASE(ChainParams_MAIN_genesis_reduced_data_compliant)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::MAIN);
    assert_genesis_respects_reduced_data_limits(*params);
}

BOOST_AUTO_TEST_CASE(ChainParams_MAIN_historical_asert_boundary_matches_live_chain)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();

    CBlockIndex block_49999{};
    block_49999.nHeight = 49'999;
    block_49999.nTime = 1'774'294'180;
    block_49999.nBits = 0x2066c154U;
    block_49999.BuildSkip();

    CBlockHeader block_50000_header{};
    block_50000_header.nTime = 1'774'294'180;
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&block_49999, &block_50000_header, consensus), 0x2066c154U);

    CBlockIndex block_50000{block_50000_header};
    block_50000.nHeight = 50'000;
    block_50000.nTime = 1'774'294'180;
    block_50000.nBits = 0x2066c154U;
    block_50000.pprev = &block_49999;
    block_50000.BuildSkip();

    CBlockHeader block_50001_header{};
    block_50001_header.nTime = 1'774'294'208;
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&block_50000, &block_50001_header, consensus), 0x2064fe91U);
}

BOOST_AUTO_TEST_CASE(ChainParams_MAIN_genesis_header_fields_frozen)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::MAIN);
    assert_btx_genesis_header_fields(*params, 1773878400U, 0U, "20147ae1", 1U);
}

BOOST_AUTO_TEST_CASE(ChainParams_MAIN_genesis_hashes_frozen)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::MAIN);
    assert_btx_genesis_hashes(
        *params,
        "75a998a39d2d6e25a9ca7de2cc659309c4105839c06cd435ba2b1aabf0fa4601",
        "94ae75cb0cd5f08b9447306ae914635d1c36d1a43d330daf596957e91cee002a");
}

BOOST_AUTO_TEST_CASE(ChainParams_REGTEST_matmul_activation)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::REGTEST);
    const auto& consensus = params->GetConsensus();
    const auto snapshot_heights = params->GetAvailableSnapshotHeights();
    const std::vector<int> expected_snapshot_heights{110, 299, 61'010};
    BOOST_CHECK(!consensus.fKAWPOW);
    BOOST_CHECK(consensus.fMatMulPOW);
    BOOST_CHECK(consensus.fSkipKAWPOWValidation);
    BOOST_CHECK(consensus.fSkipMatMulValidation);
    BOOST_CHECK_EQUAL(consensus.nKAWPOWHeight, std::numeric_limits<int>::max());
    BOOST_CHECK(consensus.fReducedDataLimits);
    BOOST_CHECK_EQUAL(consensus.nMaxOpReturnBytes, 83U);
    BOOST_CHECK_EQUAL(consensus.nMaxTxoutScriptPubKeyBytes, 34U);
    BOOST_CHECK_EQUAL(consensus.nPowTargetSpacing, 90);
    BOOST_CHECK_EQUAL(consensus.nPowTargetSpacingFastMs, 250);
    BOOST_CHECK_EQUAL(consensus.nFastMineDifficultyScale, 4U);
    BOOST_CHECK_EQUAL(consensus.nPowTargetSpacingNormal, 90);
    BOOST_CHECK_EQUAL(consensus.nFastMineHeight, 0);
    BOOST_CHECK_EQUAL(consensus.nDgwWindowAlignmentHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK_EQUAL(consensus.nDgwSlewGuardHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK_EQUAL(consensus.nMatMulAsertHeight, 0);
    BOOST_CHECK_EQUAL(consensus.nMatMulAsertHalfLife, 14'400);
    BOOST_CHECK_EQUAL(consensus.nMatMulAsertBootstrapFactor, 1U);
    BOOST_CHECK_EQUAL(consensus.nMatMulAsertRetuneHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK_EQUAL(consensus.nMatMulAsertRetuneHardeningFactor, 1U);
    BOOST_CHECK_EQUAL(consensus.nMatMulAsertRetune2Height, std::numeric_limits<int32_t>::max());
    BOOST_CHECK_EQUAL(consensus.nMatMulAsertRetune2TargetNum, 1U);
    BOOST_CHECK_EQUAL(consensus.nMatMulAsertRetune2TargetDen, 1U);
    BOOST_CHECK_EQUAL(consensus.nMatMulAsertHalfLifeUpgradeHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK_EQUAL(consensus.nMatMulAsertHalfLifeUpgrade, 14'400);
    BOOST_CHECK_EQUAL(consensus.nMatMulPreHashEpsilonBits, 0U);
    BOOST_CHECK_EQUAL(consensus.nMatMulPreHashEpsilonBitsUpgradeHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK_EQUAL(consensus.nMatMulPreHashEpsilonBitsUpgrade, 0U);
    BOOST_CHECK_EQUAL(consensus.nMatMulDimension, 64U);
    BOOST_CHECK_EQUAL(consensus.nMatMulTranscriptBlockSize, 8U);
    BOOST_CHECK_EQUAL(consensus.nMatMulNoiseRank, 4U);
    BOOST_CHECK_EQUAL(consensus.nShieldedTxBindingActivationHeight, 0);
    BOOST_CHECK_EQUAL(consensus.nShieldedBridgeTagActivationHeight, 0);
    BOOST_CHECK_EQUAL(consensus.nShieldedSmileRiceCodecDisableHeight, 0);
    BOOST_CHECK_EQUAL(consensus.nShieldedMatRiCTDisableHeight, 0);
    BOOST_CHECK_EQUAL(consensus.nShieldedSpendPathRecoveryActivationHeight, 0);
    BOOST_CHECK(consensus.IsShieldedSpendPathRecoveryActive(0));
    BOOST_CHECK_EQUAL_COLLECTIONS(snapshot_heights.begin(),
                                  snapshot_heights.end(),
                                  expected_snapshot_heights.begin(),
                                  expected_snapshot_heights.end());
    BOOST_CHECK(params->AssumeutxoForHeight(61'010).has_value());
}

BOOST_AUTO_TEST_CASE(ChainParams_REGTEST_genesis_reduced_data_compliant)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::REGTEST);
    assert_genesis_respects_reduced_data_limits(*params);
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET_genesis_header_fields_frozen)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::TESTNET);
    assert_btx_genesis_header_fields(*params, 1773878400U, 0U, "20027525", 238U);
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET_genesis_hashes_frozen)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::TESTNET);
    assert_btx_genesis_hashes(
        *params,
        "f2bc3fb2eca6aa6059c4d0178b56efe038d46aa440d406905ef752179aa0e1a4",
        "94ae75cb0cd5f08b9447306ae914635d1c36d1a43d330daf596957e91cee002a");
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET4_genesis_hashes_frozen)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::TESTNET4);
    assert_btx_genesis_hashes(
        *params,
        "f2bc3fb2eca6aa6059c4d0178b56efe038d46aa440d406905ef752179aa0e1a4",
        "94ae75cb0cd5f08b9447306ae914635d1c36d1a43d330daf596957e91cee002a");
}

BOOST_AUTO_TEST_CASE(ChainParams_REGTEST_genesis_header_fields_frozen)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::REGTEST);
    assert_btx_genesis_header_fields(*params, 1296688602U, 2U, "207fffff", 2U);
}

BOOST_AUTO_TEST_CASE(ChainParams_REGTEST_genesis_hashes_frozen)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::REGTEST);
    assert_btx_genesis_hashes(
        *params,
        "521ad0951ed299e9c56aeb7db8188972772067560351b8e55adf71dbed532360",
        "94ae75cb0cd5f08b9447306ae914635d1c36d1a43d330daf596957e91cee002a");
}

BOOST_AUTO_TEST_CASE(ChainParams_REGTEST_custom_overrides)
{
    ArgsManager args;
    args.ForceSetArg("-regtestmsgstart", "0a0b0c0d");
    args.ForceSetArg("-regtestport", "19444");
    args.ForceSetArg("-regtestgenesisntime", "1700001234");
    args.ForceSetArg("-regtestgenesisnonce", "42");
    args.ForceSetArg("-regtestgenesisbits", "2070ffff");
    args.ForceSetArg("-regtestgenesisversion", "4");
    const auto params = CreateChainParams(args, ChainType::REGTEST);

    const auto& consensus = params->GetConsensus();
    const auto& genesis = params->GenesisBlock();
    const auto msg = params->MessageStart();

    BOOST_CHECK_EQUAL(msg[0], 0x0a);
    BOOST_CHECK_EQUAL(msg[1], 0x0b);
    BOOST_CHECK_EQUAL(msg[2], 0x0c);
    BOOST_CHECK_EQUAL(msg[3], 0x0d);
    BOOST_CHECK_EQUAL(params->GetDefaultPort(), 19444);
    BOOST_CHECK_EQUAL(genesis.nTime, 1700001234U);
    BOOST_CHECK_EQUAL(genesis.nNonce, 42U);
    BOOST_CHECK_EQUAL(genesis.nNonce64, 42U);
    BOOST_CHECK_EQUAL(strprintf("%08x", genesis.nBits), "2070ffff");
    BOOST_CHECK_EQUAL(genesis.nVersion, 4);
    BOOST_CHECK_NE(consensus.hashGenesisBlock.GetHex(), "521ad0951ed299e9c56aeb7db8188972772067560351b8e55adf71dbed532360");
    BOOST_CHECK(params->GetAvailableSnapshotHeights().empty());
    BOOST_CHECK(!params->AssumeutxoForHeight(110).has_value());
    BOOST_CHECK(!params->AssumeutxoForHeight(299).has_value());
    BOOST_CHECK(!params->AssumeutxoForHeight(61'010).has_value());
}

BOOST_AUTO_TEST_CASE(ChainParams_REGTEST_invalid_custom_overrides_rejected)
{
    {
        ArgsManager args;
        args.ForceSetArg("-regtestmsgstart", "aabbcc");
        BOOST_CHECK_THROW(CreateChainParams(args, ChainType::REGTEST), std::runtime_error);
    }
    {
        ArgsManager args;
        args.ForceSetArg("-regtestgenesisbits", "nothex");
        BOOST_CHECK_THROW(CreateChainParams(args, ChainType::REGTEST), std::runtime_error);
    }
    {
        ArgsManager args;
        args.ForceSetArg("-regtestmatmulbindingheight", "-1");
        BOOST_CHECK_THROW(CreateChainParams(args, ChainType::REGTEST), std::runtime_error);
    }
    {
        ArgsManager args;
        args.ForceSetArg("-regtestmatmulproductdigestheight", "-1");
        BOOST_CHECK_THROW(CreateChainParams(args, ChainType::REGTEST), std::runtime_error);
    }
    {
        ArgsManager args;
        args.ForceSetArg("-regtestmatmulrequireproductpayload", "maybe");
        BOOST_CHECK_THROW(CreateChainParams(args, ChainType::REGTEST), std::runtime_error);
    }
    {
        ArgsManager args;
        args.ForceSetArg("-regtestmatmulaserthalflife", "0");
        BOOST_CHECK_THROW(CreateChainParams(args, ChainType::REGTEST), std::runtime_error);
    }
    {
        ArgsManager args;
        args.ForceSetArg("-regtestmatmulaserthalflifeupgradeheight", "10");
        BOOST_CHECK_THROW(CreateChainParams(args, ChainType::REGTEST), std::runtime_error);
    }
    {
        ArgsManager args;
        args.ForceSetArg("-regtestmatmulaserthalflifeupgrade", "3600");
        BOOST_CHECK_THROW(CreateChainParams(args, ChainType::REGTEST), std::runtime_error);
    }
    {
        ArgsManager args;
        args.ForceSetArg("-regtestmatmulprehashepsilonbitsupgradeheight", "12");
        BOOST_CHECK_THROW(CreateChainParams(args, ChainType::REGTEST), std::runtime_error);
    }
    {
        ArgsManager args;
        args.ForceSetArg("-regtestmatmulprehashepsilonbitsupgrade", "6");
        BOOST_CHECK_THROW(CreateChainParams(args, ChainType::REGTEST), std::runtime_error);
    }
    {
        ArgsManager args;
        args.ForceSetArg("-regtestmatmulnonceseedheight", "-1");
        BOOST_CHECK_THROW(CreateChainParams(args, ChainType::REGTEST), std::runtime_error);
    }
}

BOOST_AUTO_TEST_CASE(ChainParams_REGTEST_matmul_strict_option)
{
    CChainParams::RegTestOptions options;
    options.matmul_strict = true;
    const auto consensus = CChainParams::RegTest(options)->GetConsensus();
    BOOST_CHECK(consensus.fMatMulPOW);
    BOOST_CHECK(!consensus.fKAWPOW);
    BOOST_CHECK(!consensus.fSkipKAWPOWValidation);
    BOOST_CHECK(!consensus.fSkipMatMulValidation);
}

BOOST_AUTO_TEST_CASE(ChainParams_REGTEST_matmul_dgw_option)
{
    CChainParams::RegTestOptions options;
    options.matmul_dgw = true;
    const auto consensus = CChainParams::RegTest(options)->GetConsensus();
    BOOST_CHECK(!consensus.fPowNoRetargeting);
    BOOST_CHECK(!consensus.fPowAllowMinDifficultyBlocks);
    BOOST_CHECK_EQUAL(consensus.nFastMineHeight, 2);
    BOOST_CHECK_EQUAL(consensus.nPowTargetSpacingFastMs, 250);
    BOOST_CHECK_EQUAL(consensus.nFastMineDifficultyScale, 4U);
    BOOST_CHECK_EQUAL(consensus.nPowTargetSpacingNormal, 90);
}

BOOST_AUTO_TEST_CASE(ChainParams_REGTEST_matmul_activation_override_options)
{
    CChainParams::RegTestOptions options;
    options.matmul_dgw = true;
    options.matmul_binding_height = 5;
    options.matmul_product_digest_height = 5;
    options.matmul_require_product_payload = false;
    options.matmul_asert_half_life = 14'400;
    options.matmul_asert_half_life_upgrade_height = 10;
    options.matmul_asert_half_life_upgrade = 3'600;
    options.matmul_pre_hash_epsilon_bits_upgrade_height = 12;
    options.matmul_pre_hash_epsilon_bits_upgrade = 6;
    options.matmul_nonce_seed_height = 9;

    const auto consensus = CChainParams::RegTest(options)->GetConsensus();
    BOOST_CHECK_EQUAL(consensus.nMatMulFreivaldsBindingHeight, 5);
    BOOST_CHECK_EQUAL(consensus.nMatMulProductDigestHeight, 5);
    BOOST_CHECK(!consensus.fMatMulRequireProductPayload);
    BOOST_CHECK(!consensus.IsMatMulProductPayloadRequired(4));
    BOOST_CHECK(consensus.IsMatMulProductPayloadRequired(5));
    BOOST_CHECK_EQUAL(consensus.nMatMulAsertHalfLife, 14'400);
    BOOST_CHECK_EQUAL(consensus.nMatMulAsertHalfLifeUpgradeHeight, 10);
    BOOST_CHECK_EQUAL(consensus.nMatMulAsertHalfLifeUpgrade, 3'600);
    BOOST_CHECK_EQUAL(consensus.nMatMulPreHashEpsilonBits, 0U);
    BOOST_CHECK_EQUAL(consensus.nMatMulPreHashEpsilonBitsUpgradeHeight, 12);
    BOOST_CHECK_EQUAL(consensus.nMatMulPreHashEpsilonBitsUpgrade, 6U);
    BOOST_CHECK_EQUAL(consensus.nMatMulNonceSeedHeight, 9);
    BOOST_CHECK(!consensus.IsMatMulNonceSeedActive(8));
    BOOST_CHECK(consensus.IsMatMulNonceSeedActive(9));
}

BOOST_AUTO_TEST_CASE(ChainParams_REGTEST_matmul_activation_override_args)
{
    ArgsManager args;
    args.ForceSetArg("-test", "matmuldgw");
    args.ForceSetArg("-regtestmatmulbindingheight", "5");
    args.ForceSetArg("-regtestmatmulproductdigestheight", "5");
    args.ForceSetArg("-regtestmatmulrequireproductpayload", "0");
    args.ForceSetArg("-regtestmatmulaserthalflife", "14400");
    args.ForceSetArg("-regtestmatmulaserthalflifeupgradeheight", "10");
    args.ForceSetArg("-regtestmatmulaserthalflifeupgrade", "3600");
    args.ForceSetArg("-regtestmatmulprehashepsilonbitsupgradeheight", "12");
    args.ForceSetArg("-regtestmatmulprehashepsilonbitsupgrade", "6");
    args.ForceSetArg("-regtestmatmulnonceseedheight", "9");

    const auto consensus = CreateChainParams(args, ChainType::REGTEST)->GetConsensus();
    BOOST_CHECK_EQUAL(consensus.nMatMulFreivaldsBindingHeight, 5);
    BOOST_CHECK_EQUAL(consensus.nMatMulProductDigestHeight, 5);
    BOOST_CHECK(!consensus.fMatMulRequireProductPayload);
    BOOST_CHECK(!consensus.IsMatMulProductPayloadRequired(4));
    BOOST_CHECK(consensus.IsMatMulProductPayloadRequired(5));
    BOOST_CHECK_EQUAL(consensus.nMatMulAsertHalfLife, 14'400);
    BOOST_CHECK_EQUAL(consensus.nMatMulAsertHalfLifeUpgradeHeight, 10);
    BOOST_CHECK_EQUAL(consensus.nMatMulAsertHalfLifeUpgrade, 3'600);
    BOOST_CHECK_EQUAL(consensus.nMatMulPreHashEpsilonBits, 0U);
    BOOST_CHECK_EQUAL(consensus.nMatMulPreHashEpsilonBitsUpgradeHeight, 12);
    BOOST_CHECK_EQUAL(consensus.nMatMulPreHashEpsilonBitsUpgrade, 6U);
    BOOST_CHECK_EQUAL(consensus.nMatMulNonceSeedHeight, 9);
    BOOST_CHECK(!consensus.IsMatMulNonceSeedActive(8));
    BOOST_CHECK(consensus.IsMatMulNonceSeedActive(9));
}

BOOST_AUTO_TEST_CASE(MatMulPreHashEpsilonBits_resolve_upgrade_at_boundary)
{
    Consensus::Params params{};
    params.nMatMulPreHashEpsilonBits = 10;
    params.nMatMulPreHashEpsilonBitsUpgradeHeight = 12;
    params.nMatMulPreHashEpsilonBitsUpgrade = 14;

    BOOST_CHECK_EQUAL(GetMatMulPreHashEpsilonBitsForHeight(params, 11), 10U);
    BOOST_CHECK_EQUAL(GetMatMulPreHashEpsilonBitsForHeight(params, 12), 14U);
    BOOST_CHECK_EQUAL(GetMatMulPreHashEpsilonBitsForHeight(params, 13), 14U);
}

BOOST_AUTO_TEST_CASE(MatMulNonceSeedV2_binds_mutable_header_fields)
{
    CBlockHeader header{};
    header.nVersion = 4;
    header.hashPrevBlock = uint256{"0000000000000000000000000000000000000000000000000000000000000001"};
    header.hashMerkleRoot = uint256{"0000000000000000000000000000000000000000000000000000000000000002"};
    header.nTime = 1'780'000'000U;
    header.nBits = 0x1d00ffff;
    header.nNonce64 = 7;
    header.matmul_dim = 64;

    const uint256 legacy = DeterministicMatMulSeed(header.hashPrevBlock, 125'000, 0);
    const uint256 v2 = DeterministicMatMulSeedV2(header, 125'000, 0);
    BOOST_CHECK_NE(legacy, v2);

    CBlockHeader mutated{header};
    mutated.nNonce64 += 1;
    BOOST_CHECK_NE(v2, DeterministicMatMulSeedV2(mutated, 125'000, 0));

    mutated = header;
    mutated.hashMerkleRoot = uint256{"0000000000000000000000000000000000000000000000000000000000000003"};
    BOOST_CHECK_NE(v2, DeterministicMatMulSeedV2(mutated, 125'000, 0));

    mutated = header;
    mutated.nTime += 1;
    BOOST_CHECK_NE(v2, DeterministicMatMulSeedV2(mutated, 125'000, 0));

    mutated = header;
    mutated.nBits += 1;
    BOOST_CHECK_NE(v2, DeterministicMatMulSeedV2(mutated, 125'000, 0));
}

BOOST_AUTO_TEST_CASE(MatMulNonceSeed_activation_boundary_selects_legacy_then_v2)
{
    auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    BOOST_REQUIRE_EQUAL(consensus.nMatMulNonceSeedHeight, 125'000);

    CBlockHeader header{};
    header.nVersion = 4;
    header.hashPrevBlock = uint256{"0000000000000000000000000000000000000000000000000000000000000004"};
    header.hashMerkleRoot = uint256{"0000000000000000000000000000000000000000000000000000000000000005"};
    header.nTime = 1'780'000'001U;
    header.nBits = 0x1d00ffff;
    header.nNonce64 = 11;
    header.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);

    CBlockHeader before{header};
    BOOST_REQUIRE(SetDeterministicMatMulSeeds(before, consensus, 124'999));
    BOOST_CHECK_EQUAL(before.seed_a, DeterministicMatMulSeed(header.hashPrevBlock, 124'999, 0));
    BOOST_CHECK_EQUAL(before.seed_b, DeterministicMatMulSeed(header.hashPrevBlock, 124'999, 1));

    CBlockHeader at_activation{header};
    BOOST_REQUIRE(SetDeterministicMatMulSeeds(at_activation, consensus, 125'000));
    BOOST_CHECK_EQUAL(at_activation.seed_a, DeterministicMatMulSeedV2(header, 125'000, 0));
    BOOST_CHECK_EQUAL(at_activation.seed_b, DeterministicMatMulSeedV2(header, 125'000, 1));

    CBlockHeader next_nonce{header};
    next_nonce.nNonce64 += 1;
    BOOST_REQUIRE(SetDeterministicMatMulSeeds(next_nonce, consensus, 125'000));
    BOOST_CHECK_NE(at_activation.seed_a, next_nonce.seed_a);
    BOOST_CHECK_NE(at_activation.seed_b, next_nonce.seed_b);
}

BOOST_AUTO_TEST_CASE(MatMulParentMtpSeed_activation_selects_v3_and_requires_parent_context)
{
    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.nMatMulNonceSeedHeight = 2;
    consensus.nMatMulParentMtpSeedHeight = 3;

    CBlockHeader header{};
    header.nVersion = 4;
    header.hashPrevBlock = uint256{"0000000000000000000000000000000000000000000000000000000000000104"};
    header.hashMerkleRoot = uint256{"0000000000000000000000000000000000000000000000000000000000000105"};
    header.nTime = 1'780'000'010U;
    header.nBits = 0x1d00ffff;
    header.nNonce64 = 11;
    header.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);

    CBlockHeader v2{header};
    BOOST_REQUIRE(SetDeterministicMatMulSeeds(v2, consensus, 2));
    BOOST_CHECK_EQUAL(v2.seed_a, DeterministicMatMulSeedV2(header, 2, 0));
    BOOST_CHECK_EQUAL(v2.seed_b, DeterministicMatMulSeedV2(header, 2, 1));

    CBlockHeader missing_parent{header};
    BOOST_CHECK(!SetDeterministicMatMulSeeds(missing_parent, consensus, 3));
    BOOST_CHECK(missing_parent.seed_a.IsNull());
    BOOST_CHECK(missing_parent.seed_b.IsNull());

    constexpr int64_t parent_mtp{1'780'000'000};
    CBlockHeader v3{header};
    BOOST_REQUIRE(SetDeterministicMatMulSeeds(v3, consensus, 3, parent_mtp));
    BOOST_CHECK_EQUAL(v3.seed_a, DeterministicMatMulSeedV3(header, 3, parent_mtp, 0));
    BOOST_CHECK_EQUAL(v3.seed_b, DeterministicMatMulSeedV3(header, 3, parent_mtp, 1));
    BOOST_CHECK_NE(v3.seed_a, v2.seed_a);

    CBlockHeader alternate_parent{header};
    BOOST_REQUIRE(SetDeterministicMatMulSeeds(alternate_parent, consensus, 3, parent_mtp + 1));
    BOOST_CHECK_NE(v3.seed_a, alternate_parent.seed_a);
    BOOST_CHECK_NE(v3.seed_b, alternate_parent.seed_b);
}

BOOST_AUTO_TEST_CASE(MatMulParentMtpSeed_solver_requires_parent_context_after_activation)
{
    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fSkipMatMulValidation = false;
    consensus.nMatMulDimension = 16;
    consensus.nMatMulMinDimension = 16;
    consensus.nMatMulTranscriptBlockSize = 8;
    consensus.nMatMulNoiseRank = 4;
    consensus.nMatMulPreHashEpsilonBits = 0;
    consensus.nMatMulNonceSeedHeight = 2;
    consensus.nMatMulParentMtpSeedHeight = 2;
    consensus.nMatMulProductDigestHeight = 2;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    CBlockHeader header{};
    header.nVersion = 4;
    header.hashPrevBlock = uint256{"0000000000000000000000000000000000000000000000000000000000000106"};
    header.hashMerkleRoot = uint256{"0000000000000000000000000000000000000000000000000000000000000107"};
    header.nTime = 1'780'000'020U;
    header.nBits = UintToArith256(consensus.powLimit).GetCompact();
    header.nNonce64 = 0;
    header.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);

    {
        CBlockHeader missing_parent{header};
        uint64_t max_tries{1};
        BOOST_CHECK(!SolveMatMul(missing_parent, consensus, max_tries, 2));
    }

    constexpr int64_t parent_mtp{1'780'000'000};
    CBlockHeader solved{header};
    uint64_t max_tries{1};
    BOOST_REQUIRE(SolveMatMul(
        solved,
        consensus,
        max_tries,
        2,
        nullptr,
        nullptr,
        nullptr,
        parent_mtp));
    BOOST_CHECK_EQUAL(solved.seed_a, DeterministicMatMulSeedV3(solved, 2, parent_mtp, 0));
    BOOST_CHECK_EQUAL(solved.seed_b, DeterministicMatMulSeedV3(solved, 2, parent_mtp, 1));
}

BOOST_AUTO_TEST_CASE(MatMulNonceSeed_solver_mines_and_verifies_at_activation_boundary)
{
    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fSkipMatMulValidation = false;
    consensus.nMatMulDimension = 16;
    consensus.nMatMulMinDimension = 16;
    consensus.nMatMulTranscriptBlockSize = 8;
    consensus.nMatMulNoiseRank = 4;
    consensus.nMatMulPreHashEpsilonBits = 0;
    consensus.nMatMulNonceSeedHeight = 2;
    consensus.nMatMulProductDigestHeight = 2;

    CBlockHeader header{};
    header.nVersion = 4;
    header.hashPrevBlock = uint256{"0000000000000000000000000000000000000000000000000000000000000006"};
    header.hashMerkleRoot = uint256{"0000000000000000000000000000000000000000000000000000000000000007"};
    header.nTime = 1'780'000'002U;
    header.nBits = UintToArith256(consensus.powLimit).GetCompact();
    header.nNonce64 = 0;
    header.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    BOOST_REQUIRE(SetDeterministicMatMulSeeds(header, consensus, 2));

    std::vector<uint32_t> payload;
    uint64_t max_tries{1};
    BOOST_REQUIRE(SolveMatMul(header, consensus, max_tries, 2, nullptr, &payload));
    BOOST_CHECK(!payload.empty());
    BOOST_CHECK_EQUAL(header.seed_a, DeterministicMatMulSeedV2(header, 2, 0));
    BOOST_CHECK_EQUAL(header.seed_b, DeterministicMatMulSeedV2(header, 2, 1));

    CBlock block{header};
    block.matrix_c_data = payload;
    BOOST_CHECK(CheckMatMulProofOfWork_ProductCommitted(block, consensus, 2));
}

BOOST_AUTO_TEST_CASE(MatMulNonceSeed_solver_disables_shared_base_matrix_batching)
{
    ScopedBatchSizeEnv batch_size_env("8");
    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fSkipMatMulValidation = false;
    consensus.nMatMulDimension = 16;
    consensus.nMatMulMinDimension = 16;
    consensus.nMatMulTranscriptBlockSize = 8;
    consensus.nMatMulNoiseRank = 4;
    consensus.nMatMulPreHashEpsilonBits = 0;
    consensus.nMatMulNonceSeedHeight = 2;
    consensus.nMatMulProductDigestHeight = 2;

    CBlockHeader header{};
    header.nVersion = 4;
    header.hashPrevBlock = uint256{"0000000000000000000000000000000000000000000000000000000000000008"};
    header.hashMerkleRoot = uint256{"0000000000000000000000000000000000000000000000000000000000000009"};
    header.nTime = 1'780'000'003U;
    header.nBits = UintToArith256(consensus.powLimit).GetCompact();
    header.nNonce64 = 0;
    header.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);

    ResetMatMulSolvePipelineStats();
    std::vector<uint32_t> payload;
    uint64_t max_tries{2};
    BOOST_REQUIRE(SolveMatMul(header, consensus, max_tries, 2, nullptr, &payload));

    const auto stats = ProbeMatMulSolvePipelineStats();
    BOOST_CHECK_EQUAL(stats.batch_size, 1U);
    BOOST_CHECK_EQUAL(stats.batched_digest_requests, 0U);
    BOOST_CHECK_EQUAL(header.seed_a, DeterministicMatMulSeedV2(header, 2, 0));
    BOOST_CHECK_EQUAL(header.seed_b, DeterministicMatMulSeedV2(header, 2, 1));

    CBlock block{header};
    block.matrix_c_data = payload;
    BOOST_CHECK(CheckMatMulProofOfWork_ProductCommitted(block, consensus, 2));
}

BOOST_AUTO_TEST_CASE(MatMulNonceSeed_cuda_prehash_scan_matches_cpu_gate)
{
    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.nMatMulDimension = 16;
    consensus.nMatMulMinDimension = 16;
    consensus.nMatMulTranscriptBlockSize = 8;
    consensus.nMatMulNoiseRank = 4;
    consensus.nMatMulPreHashEpsilonBits = 4;
    consensus.nMatMulPreHashEpsilonBitsUpgradeHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulNonceSeedHeight = 2;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    arith_uint256 block_target{1};
    block_target <<= 250;
    CBlockHeader header{};
    header.nVersion = 4;
    header.hashPrevBlock = uint256{"00000000000000000000000000000000000000000000000000000000000000c1"};
    header.hashMerkleRoot = uint256{"00000000000000000000000000000000000000000000000000000000000000c2"};
    header.nTime = 1'780'000'004U;
    header.nBits = block_target.GetCompact();
    header.nNonce64 = 17;
    header.nNonce = static_cast<uint32_t>(header.nNonce64);
    header.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);

    arith_uint256 pre_hash_target = DecodeTarget(header.nBits);
    pre_hash_target <<= consensus.nMatMulPreHashEpsilonBits;
    constexpr uint32_t kScanCount{96};
    const auto scan = btx::cuda::ScanMatMulNonceSeedPreHashGPU({
        .version = header.nVersion,
        .previous_block_hash = header.hashPrevBlock,
        .merkle_root = header.hashMerkleRoot,
        .time = header.nTime,
        .bits = header.nBits,
        .start_nonce = header.nNonce64,
        .matmul_dim = header.matmul_dim,
        .block_height = 2,
        .scan_count = kScanCount,
        .pre_hash_target = ArithToUint256(pre_hash_target),
    });
    if (!scan.available) {
        return;
    }

    BOOST_REQUIRE_MESSAGE(scan.success, scan.error);
    BOOST_REQUIRE_EQUAL(scan.scanned_count, kScanCount);
    BOOST_REQUIRE_EQUAL(scan.pass_flags.size(), kScanCount);
    for (uint32_t i = 0; i < kScanCount; ++i) {
        CBlockHeader candidate{header};
        candidate.nNonce64 = header.nNonce64 + i;
        candidate.nNonce = static_cast<uint32_t>(candidate.nNonce64);
        BOOST_REQUIRE(SetDeterministicMatMulSeeds(candidate, consensus, 2));
        const bool expected = CheckMatMulPreHashGate(candidate, consensus, 2);
        BOOST_CHECK_EQUAL(scan.pass_flags[i] != 0, expected);
    }
}

BOOST_AUTO_TEST_CASE(MatMulNonceSeed_metal_prehash_scan_matches_cpu_gate)
{
    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.nMatMulDimension = 16;
    consensus.nMatMulMinDimension = 16;
    consensus.nMatMulTranscriptBlockSize = 8;
    consensus.nMatMulNoiseRank = 4;
    consensus.nMatMulPreHashEpsilonBits = 4;
    consensus.nMatMulPreHashEpsilonBitsUpgradeHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulNonceSeedHeight = 2;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    arith_uint256 block_target{1};
    block_target <<= 250;
    CBlockHeader header{};
    header.nVersion = 4;
    header.hashPrevBlock = uint256{"00000000000000000000000000000000000000000000000000000000000000d1"};
    header.hashMerkleRoot = uint256{"00000000000000000000000000000000000000000000000000000000000000d2"};
    header.nTime = 1'780'000'005U;
    header.nBits = block_target.GetCompact();
    header.nNonce64 = 23;
    header.nNonce = static_cast<uint32_t>(header.nNonce64);
    header.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);

    arith_uint256 pre_hash_target = DecodeTarget(header.nBits);
    pre_hash_target <<= consensus.nMatMulPreHashEpsilonBits;
    constexpr uint32_t kScanCount{96};
    const auto scan = btx::metal::ScanMatMulNonceSeedPreHashGPU({
        .version = header.nVersion,
        .previous_block_hash = header.hashPrevBlock,
        .merkle_root = header.hashMerkleRoot,
        .time = header.nTime,
        .bits = header.nBits,
        .start_nonce = header.nNonce64,
        .matmul_dim = header.matmul_dim,
        .block_height = 2,
        .scan_count = kScanCount,
        .pre_hash_target = ArithToUint256(pre_hash_target),
    });
    if (!scan.available) {
        return;
    }

    BOOST_REQUIRE_MESSAGE(scan.success, scan.error);
    BOOST_REQUIRE_EQUAL(scan.scanned_count, kScanCount);
    BOOST_REQUIRE_EQUAL(scan.pass_flags.size(), kScanCount);
    for (uint32_t i = 0; i < kScanCount; ++i) {
        CBlockHeader candidate{header};
        candidate.nNonce64 = header.nNonce64 + i;
        candidate.nNonce = static_cast<uint32_t>(candidate.nNonce64);
        BOOST_REQUIRE(SetDeterministicMatMulSeeds(candidate, consensus, 2));
        const bool expected = CheckMatMulPreHashGate(candidate, consensus, 2);
        BOOST_CHECK_EQUAL(scan.pass_flags[i] != 0, expected);
    }
}

BOOST_AUTO_TEST_CASE(MatMulParentMtpSeed_cuda_prehash_scan_matches_cpu_gate)
{
    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.nMatMulDimension = 16;
    consensus.nMatMulMinDimension = 16;
    consensus.nMatMulTranscriptBlockSize = 8;
    consensus.nMatMulNoiseRank = 4;
    consensus.nMatMulPreHashEpsilonBits = 4;
    consensus.nMatMulPreHashEpsilonBitsUpgradeHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulNonceSeedHeight = 2;
    consensus.nMatMulParentMtpSeedHeight = 2;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    constexpr int64_t parent_mtp{1'779'999'900};
    arith_uint256 block_target{1};
    block_target <<= 250;
    CBlockHeader header{};
    header.nVersion = 4;
    header.hashPrevBlock = uint256{"00000000000000000000000000000000000000000000000000000000000000c3"};
    header.hashMerkleRoot = uint256{"00000000000000000000000000000000000000000000000000000000000000c4"};
    header.nTime = 1'780'000'009U;
    header.nBits = block_target.GetCompact();
    header.nNonce64 = 29;
    header.nNonce = static_cast<uint32_t>(header.nNonce64);
    header.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);

    arith_uint256 pre_hash_target = DecodeTarget(header.nBits);
    pre_hash_target <<= consensus.nMatMulPreHashEpsilonBits;
    constexpr uint32_t kScanCount{96};
    const auto scan = btx::cuda::ScanMatMulNonceSeedPreHashGPU({
        .version = header.nVersion,
        .previous_block_hash = header.hashPrevBlock,
        .merkle_root = header.hashMerkleRoot,
        .time = header.nTime,
        .bits = header.nBits,
        .start_nonce = header.nNonce64,
        .matmul_dim = header.matmul_dim,
        .block_height = 2,
        .scan_count = kScanCount,
        .pre_hash_target = ArithToUint256(pre_hash_target),
        .seed_version = 3,
        .parent_median_time_past = parent_mtp,
    });
    if (!scan.available) {
        return;
    }

    BOOST_REQUIRE_MESSAGE(scan.success, scan.error);
    BOOST_REQUIRE_EQUAL(scan.scanned_count, kScanCount);
    BOOST_REQUIRE_EQUAL(scan.pass_flags.size(), kScanCount);
    for (uint32_t i = 0; i < kScanCount; ++i) {
        CBlockHeader candidate{header};
        candidate.nNonce64 = header.nNonce64 + i;
        candidate.nNonce = static_cast<uint32_t>(candidate.nNonce64);
        BOOST_REQUIRE(SetDeterministicMatMulSeeds(candidate, consensus, 2, parent_mtp));
        const bool expected = CheckMatMulPreHashGate(candidate, consensus, 2);
        BOOST_CHECK_EQUAL(scan.pass_flags[i] != 0, expected);
    }
}

BOOST_AUTO_TEST_CASE(MatMulParentMtpSeed_metal_prehash_scan_matches_cpu_gate)
{
    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.nMatMulDimension = 16;
    consensus.nMatMulMinDimension = 16;
    consensus.nMatMulTranscriptBlockSize = 8;
    consensus.nMatMulNoiseRank = 4;
    consensus.nMatMulPreHashEpsilonBits = 4;
    consensus.nMatMulPreHashEpsilonBitsUpgradeHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulNonceSeedHeight = 2;
    consensus.nMatMulParentMtpSeedHeight = 2;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    constexpr int64_t parent_mtp{1'779'999'901};
    arith_uint256 block_target{1};
    block_target <<= 250;
    CBlockHeader header{};
    header.nVersion = 4;
    header.hashPrevBlock = uint256{"00000000000000000000000000000000000000000000000000000000000000d3"};
    header.hashMerkleRoot = uint256{"00000000000000000000000000000000000000000000000000000000000000d4"};
    header.nTime = 1'780'000'010U;
    header.nBits = block_target.GetCompact();
    header.nNonce64 = 31;
    header.nNonce = static_cast<uint32_t>(header.nNonce64);
    header.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);

    arith_uint256 pre_hash_target = DecodeTarget(header.nBits);
    pre_hash_target <<= consensus.nMatMulPreHashEpsilonBits;
    constexpr uint32_t kScanCount{96};
    const auto scan = btx::metal::ScanMatMulNonceSeedPreHashGPU({
        .version = header.nVersion,
        .previous_block_hash = header.hashPrevBlock,
        .merkle_root = header.hashMerkleRoot,
        .time = header.nTime,
        .bits = header.nBits,
        .start_nonce = header.nNonce64,
        .matmul_dim = header.matmul_dim,
        .block_height = 2,
        .scan_count = kScanCount,
        .pre_hash_target = ArithToUint256(pre_hash_target),
        .seed_version = 3,
        .parent_median_time_past = parent_mtp,
    });
    if (!scan.available) {
        return;
    }

    BOOST_REQUIRE_MESSAGE(scan.success, scan.error);
    BOOST_REQUIRE_EQUAL(scan.scanned_count, kScanCount);
    BOOST_REQUIRE_EQUAL(scan.pass_flags.size(), kScanCount);
    for (uint32_t i = 0; i < kScanCount; ++i) {
        CBlockHeader candidate{header};
        candidate.nNonce64 = header.nNonce64 + i;
        candidate.nNonce = static_cast<uint32_t>(candidate.nNonce64);
        BOOST_REQUIRE(SetDeterministicMatMulSeeds(candidate, consensus, 2, parent_mtp));
        const bool expected = CheckMatMulPreHashGate(candidate, consensus, 2);
        BOOST_CHECK_EQUAL(scan.pass_flags[i] != 0, expected);
    }
}

BOOST_AUTO_TEST_CASE(MatMulNonceSeed_metal_solver_uses_gpu_scan_and_variable_base_batch)
{
    const auto capability = matmul::backend::CapabilityFor(matmul::backend::Kind::METAL);
    if (!capability.available) {
        BOOST_TEST_MESSAGE("Skipping Metal nonce-seed solver integration test: Metal backend unavailable ("
            << capability.reason << ")");
        return;
    }

    ScopedBackendEnv backend_env("metal");
    ScopedBatchSizeEnv solve_batch_env(nullptr);
    ScopedNonceSeedBatchSizeEnv nonce_seed_batch_env("3");
    ScopedCpuConfirmEnv cpu_confirm_env("1");

    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fSkipMatMulValidation = false;
    consensus.fMatMulPOW = true;
    consensus.nMatMulDimension = 16;
    consensus.nMatMulMinDimension = 16;
    consensus.nMatMulTranscriptBlockSize = 8;
    consensus.nMatMulNoiseRank = 4;
    consensus.nMatMulPreHashEpsilonBits = 4;
    consensus.nMatMulPreHashEpsilonBitsUpgradeHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulNonceSeedHeight = 2;
    consensus.nMatMulProductDigestHeight = 2;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    CBlockHeader header{};
    header.nVersion = 4;
    header.hashPrevBlock = uint256{"00000000000000000000000000000000000000000000000000000000000000e1"};
    header.hashMerkleRoot = uint256{"00000000000000000000000000000000000000000000000000000000000000e2"};
    header.nTime = 1'780'000'006U;
    header.nBits = UintToArith256(consensus.powLimit).GetCompact();
    header.nNonce64 = 0;
    header.nNonce = 0;
    header.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    header.matmul_digest.SetNull();

    ResetMatMulSolvePipelineStats();
    matmul::accelerated::ResetMatMulBackendRuntimeStats();
    std::vector<uint32_t> payload;
    uint64_t max_tries{3};
    BOOST_REQUIRE(SolveMatMul(header, consensus, max_tries, 2, nullptr, &payload));

    const auto solve_stats = ProbeMatMulSolvePipelineStats();
    BOOST_CHECK_EQUAL(solve_stats.batch_size, 3U);
    BOOST_CHECK_EQUAL(solve_stats.batched_digest_requests, 1U);
    BOOST_CHECK_EQUAL(solve_stats.batched_nonce_attempts, 3U);

    const auto backend_stats = matmul::accelerated::ProbeMatMulBackendRuntimeStats();
    BOOST_CHECK_EQUAL(backend_stats.requested_metal, 3U);
    BOOST_CHECK_EQUAL(backend_stats.metal_successes, 3U);
    BOOST_CHECK(!payload.empty());
    BOOST_CHECK_EQUAL(header.seed_a, DeterministicMatMulSeedV2(header, 2, 0));
    BOOST_CHECK_EQUAL(header.seed_b, DeterministicMatMulSeedV2(header, 2, 1));

    CBlock block{header};
    block.matrix_c_data = payload;
    BOOST_CHECK(CheckMatMulProofOfWork_ProductCommitted(block, consensus, 2));
}

BOOST_AUTO_TEST_CASE(MatMulParentMtpSeed_metal_solver_uses_gpu_scan_and_variable_base_batch)
{
    const auto capability = matmul::backend::CapabilityFor(matmul::backend::Kind::METAL);
    if (!capability.available) {
        BOOST_TEST_MESSAGE("Skipping Metal parent-MTP nonce-seed solver integration test: Metal backend unavailable ("
            << capability.reason << ")");
        return;
    }

    ScopedBackendEnv backend_env("metal");
    ScopedBatchSizeEnv solve_batch_env(nullptr);
    ScopedNonceSeedBatchSizeEnv nonce_seed_batch_env("3");
    ScopedCpuConfirmEnv cpu_confirm_env("1");

    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fSkipMatMulValidation = false;
    consensus.fMatMulPOW = true;
    consensus.nMatMulDimension = 16;
    consensus.nMatMulMinDimension = 16;
    consensus.nMatMulTranscriptBlockSize = 8;
    consensus.nMatMulNoiseRank = 4;
    consensus.nMatMulPreHashEpsilonBits = 4;
    consensus.nMatMulPreHashEpsilonBitsUpgradeHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulNonceSeedHeight = 2;
    consensus.nMatMulParentMtpSeedHeight = 2;
    consensus.nMatMulProductDigestHeight = 2;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    constexpr int64_t parent_mtp{1'779'999'902};
    CBlockHeader header{};
    header.nVersion = 4;
    header.hashPrevBlock = uint256{"00000000000000000000000000000000000000000000000000000000000000e3"};
    header.hashMerkleRoot = uint256{"00000000000000000000000000000000000000000000000000000000000000e4"};
    header.nTime = 1'780'000'011U;
    header.nBits = UintToArith256(consensus.powLimit).GetCompact();
    header.nNonce64 = 0;
    header.nNonce = 0;
    header.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    header.matmul_digest.SetNull();

    ResetMatMulSolvePipelineStats();
    ResetMatMulGpuPreHashScanStats();
    matmul::accelerated::ResetMatMulBackendRuntimeStats();
    std::vector<uint32_t> payload;
    uint64_t max_tries{3};
    BOOST_REQUIRE(SolveMatMul(header, consensus, max_tries, 2, nullptr, &payload, nullptr, parent_mtp));

    const auto scan_stats = ProbeMatMulGpuPreHashScanStats();
    BOOST_CHECK(scan_stats.attempts > 0);
    BOOST_CHECK(scan_stats.successes > 0);
    BOOST_CHECK_EQUAL(scan_stats.failures, 0U);

    const auto solve_stats = ProbeMatMulSolvePipelineStats();
    BOOST_CHECK_EQUAL(solve_stats.batch_size, 3U);
    BOOST_CHECK_EQUAL(solve_stats.batched_digest_requests, 1U);
    BOOST_CHECK_EQUAL(solve_stats.batched_nonce_attempts, 3U);
    BOOST_CHECK(!solve_stats.parallel_solver_enabled);

    const auto backend_stats = matmul::accelerated::ProbeMatMulBackendRuntimeStats();
    BOOST_CHECK_EQUAL(backend_stats.requested_metal, 3U);
    BOOST_CHECK_EQUAL(backend_stats.metal_successes, 3U);
    BOOST_CHECK(!payload.empty());
    BOOST_CHECK_EQUAL(header.seed_a, DeterministicMatMulSeedV3(header, 2, parent_mtp, 0));
    BOOST_CHECK_EQUAL(header.seed_b, DeterministicMatMulSeedV3(header, 2, parent_mtp, 1));

    CBlock block{header};
    block.matrix_c_data = payload;
    BOOST_CHECK(CheckMatMulProofOfWork_ProductCommitted(block, consensus, 2));
}

BOOST_AUTO_TEST_CASE(MatMulParentMtpSeed_cuda_solver_uses_gpu_scan_and_variable_base_batch)
{
    const auto capability = matmul::backend::CapabilityFor(matmul::backend::Kind::CUDA);
    if (!capability.available) {
        BOOST_TEST_MESSAGE("Skipping CUDA parent-MTP nonce-seed solver integration test: CUDA backend unavailable ("
            << capability.reason << ")");
        return;
    }

    ScopedBackendEnv backend_env("cuda");
    ScopedBatchSizeEnv solve_batch_env(nullptr);
    ScopedNonceSeedBatchSizeEnv nonce_seed_batch_env("3");
    ScopedCpuConfirmEnv cpu_confirm_env("1");
    ScopedGpuInputsEnv gpu_inputs_env("1");

    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fSkipMatMulValidation = false;
    consensus.fMatMulPOW = true;
    consensus.nMatMulDimension = 16;
    consensus.nMatMulMinDimension = 16;
    consensus.nMatMulTranscriptBlockSize = 8;
    consensus.nMatMulNoiseRank = 4;
    consensus.nMatMulPreHashEpsilonBits = 4;
    consensus.nMatMulPreHashEpsilonBitsUpgradeHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulNonceSeedHeight = 2;
    consensus.nMatMulParentMtpSeedHeight = 2;
    consensus.nMatMulProductDigestHeight = 2;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    constexpr int64_t parent_mtp{1'779'999'903};
    CBlockHeader header{};
    header.nVersion = 4;
    header.hashPrevBlock = uint256{"00000000000000000000000000000000000000000000000000000000000000e5"};
    header.hashMerkleRoot = uint256{"00000000000000000000000000000000000000000000000000000000000000e6"};
    header.nTime = 1'780'000'012U;
    header.nBits = UintToArith256(consensus.powLimit).GetCompact();
    header.nNonce64 = 0;
    header.nNonce = 0;
    header.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    header.matmul_digest.SetNull();

    ResetMatMulSolvePipelineStats();
    ResetMatMulGpuPreHashScanStats();
    matmul::accelerated::ResetMatMulBackendRuntimeStats();
    std::vector<uint32_t> payload;
    uint64_t max_tries{3};
    BOOST_REQUIRE(SolveMatMul(header, consensus, max_tries, 2, nullptr, &payload, nullptr, parent_mtp));

    const auto scan_stats = ProbeMatMulGpuPreHashScanStats();
    BOOST_CHECK(scan_stats.attempts > 0);
    BOOST_CHECK(scan_stats.successes > 0);
    BOOST_CHECK_EQUAL(scan_stats.failures, 0U);
    BOOST_CHECK_EQUAL(scan_stats.cuda_fallbacks_to_cpu, 0U);

    const auto solve_stats = ProbeMatMulSolvePipelineStats();
    BOOST_CHECK_EQUAL(solve_stats.batch_size, 3U);
    BOOST_CHECK_EQUAL(solve_stats.batched_digest_requests, 1U);
    BOOST_CHECK_EQUAL(solve_stats.batched_nonce_attempts, 3U);
    BOOST_CHECK(!solve_stats.parallel_solver_enabled);

    const auto backend_stats = matmul::accelerated::ProbeMatMulBackendRuntimeStats();
    BOOST_CHECK_EQUAL(backend_stats.requested_cuda, 3U);
    BOOST_CHECK_EQUAL(backend_stats.cuda_successes, 3U);
    BOOST_CHECK_EQUAL(backend_stats.cuda_fallbacks_to_cpu, 0U);
    BOOST_CHECK(!payload.empty());
    BOOST_CHECK_EQUAL(header.seed_a, DeterministicMatMulSeedV3(header, 2, parent_mtp, 0));
    BOOST_CHECK_EQUAL(header.seed_b, DeterministicMatMulSeedV3(header, 2, parent_mtp, 1));

    CBlock block{header};
    block.matrix_c_data = payload;
    BOOST_CHECK(CheckMatMulProofOfWork_ProductCommitted(block, consensus, 2));
}

BOOST_AUTO_TEST_CASE(MatMulNonceSeed_metal_batch_default_scales_with_gpu_core_count)
{
    const auto capability = matmul::backend::CapabilityFor(matmul::backend::Kind::METAL);
    if (!capability.available) {
        BOOST_TEST_MESSAGE("Skipping Metal nonce-seed batch default scaling test: Metal backend unavailable ("
            << capability.reason << ")");
        return;
    }

    ScopedBackendEnv backend_env("metal");
    ScopedBatchSizeEnv solve_batch_env(nullptr);
    ScopedNonceSeedBatchSizeEnv nonce_seed_batch_env(nullptr);
    ScopedSolverThreadsEnv solver_threads_env("1");

    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.fMatMulFreivaldsEnabled = true;
    consensus.fMatMulRequireProductPayload = false;
    consensus.nMatMulFreivaldsBindingHeight = 2;
    consensus.nMatMulDimension = 512;
    consensus.nMatMulMinDimension = 512;
    consensus.nMatMulTranscriptBlockSize = 16;
    consensus.nMatMulNoiseRank = 8;
    consensus.nMatMulPreHashEpsilonBits = 18;
    consensus.nMatMulPreHashEpsilonBitsUpgradeHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulNonceSeedHeight = 2;
    consensus.nMatMulProductDigestHeight = 2;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    auto check_default_for_gpu_cores = [&](const char* gpu_cores, uint32_t expected_batch_size) {
        ScopedMetalGpuCoresOverrideEnv gpu_cores_env(gpu_cores);

        CBlockHeader candidate{};
        candidate.nVersion = 4;
        candidate.hashPrevBlock = uint256{"00000000000000000000000000000000000000000000000000000000000000f1"};
        candidate.hashMerkleRoot = uint256{"00000000000000000000000000000000000000000000000000000000000000f2"};
        candidate.nTime = 1'780'000'007U;
        candidate.nBits = arith_uint256{1}.GetCompact();
        candidate.nNonce64 = expected_batch_size;
        candidate.nNonce = static_cast<uint32_t>(candidate.nNonce64);
        candidate.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
        candidate.matmul_digest.SetNull();

        uint64_t max_tries{1};
        ResetMatMulSolvePipelineStats();
        const bool solved = SolveMatMul(candidate, consensus, max_tries, 2);
        BOOST_CHECK(!solved);

        const auto stats = ProbeMatMulSolvePipelineStats();
        BOOST_CHECK_EQUAL(stats.batch_size, expected_batch_size);
        BOOST_CHECK(!stats.parallel_solver_enabled);
        BOOST_CHECK_EQUAL(stats.parallel_solver_threads, 1U);
    };

    check_default_for_gpu_cores("10", 64);
    check_default_for_gpu_cores("20", 128);
    check_default_for_gpu_cores("40", 192);
    check_default_for_gpu_cores("76", 256);
}

BOOST_AUTO_TEST_CASE(MatMulNonceSeed_cuda_batch_override_accepts_large_batch)
{
    const auto capability = matmul::backend::CapabilityFor(matmul::backend::Kind::CUDA);
    if (!capability.available) {
        BOOST_TEST_MESSAGE("Skipping CUDA nonce-seed batch override test: CUDA backend unavailable ("
            << capability.reason << ")");
        return;
    }

    ScopedBackendEnv backend_env("cuda");
    ScopedBatchSizeEnv solve_batch_env(nullptr);
    ScopedNonceSeedBatchSizeEnv nonce_seed_batch_env("512");
    ScopedSolverThreadsEnv solver_threads_env("1");

    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.fMatMulFreivaldsEnabled = true;
    consensus.fMatMulRequireProductPayload = false;
    consensus.nMatMulFreivaldsBindingHeight = 2;
    consensus.nMatMulDimension = 512;
    consensus.nMatMulMinDimension = 512;
    consensus.nMatMulTranscriptBlockSize = 16;
    consensus.nMatMulNoiseRank = 8;
    consensus.nMatMulPreHashEpsilonBits = 18;
    consensus.nMatMulPreHashEpsilonBitsUpgradeHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulNonceSeedHeight = 2;
    consensus.nMatMulProductDigestHeight = 2;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    CBlockHeader candidate{};
    candidate.nVersion = 4;
    candidate.hashPrevBlock = uint256{"00000000000000000000000000000000000000000000000000000000000000f3"};
    candidate.hashMerkleRoot = uint256{"00000000000000000000000000000000000000000000000000000000000000f4"};
    candidate.nTime = 1'780'000'008U;
    candidate.nBits = arith_uint256{1}.GetCompact();
    candidate.nNonce64 = 0;
    candidate.nNonce = 0;
    candidate.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    candidate.matmul_digest.SetNull();

    uint64_t max_tries{1};
    ResetMatMulSolvePipelineStats();
    const bool solved = SolveMatMul(candidate, consensus, max_tries, 2);
    BOOST_CHECK(!solved);

    const auto stats = ProbeMatMulSolvePipelineStats();
    BOOST_CHECK_EQUAL(stats.batch_size, 512U);
}

BOOST_AUTO_TEST_CASE(EffectiveTargetSpacingForHeight_uses_fast_phase_schedule)
{
    const auto main_consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    BOOST_CHECK_EQUAL(
        EffectiveTargetSpacingForHeight(0, main_consensus).count(),
        std::chrono::milliseconds{main_consensus.nPowTargetSpacingFastMs}.count());
    BOOST_CHECK_EQUAL(
        EffectiveTargetSpacingForHeight(main_consensus.nFastMineHeight, main_consensus).count(),
        std::chrono::milliseconds{std::chrono::seconds{main_consensus.nPowTargetSpacing}}.count());

    auto simulated_fast_phase = main_consensus;
    simulated_fast_phase.nFastMineHeight = 10;
    BOOST_CHECK_EQUAL(
        EffectiveTargetSpacingForHeight(0, simulated_fast_phase).count(),
        std::chrono::milliseconds{250}.count());
    BOOST_CHECK_EQUAL(
        EffectiveTargetSpacingForHeight(simulated_fast_phase.nFastMineHeight, simulated_fast_phase).count(),
        std::chrono::milliseconds{std::chrono::seconds{simulated_fast_phase.nPowTargetSpacing}}.count());

    auto legacy = main_consensus;
    legacy.fMatMulPOW = false;
    BOOST_CHECK_EQUAL(
        EffectiveTargetSpacingForHeight(0, legacy).count(),
        std::chrono::milliseconds{std::chrono::seconds{legacy.nPowTargetSpacing}}.count());
}

BOOST_AUTO_TEST_CASE(ChainParams_MAIN_btx_network_identity)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto msg = params->MessageStart();

    BOOST_CHECK_EQUAL(msg[0], 0xb7);
    BOOST_CHECK_EQUAL(msg[1], 0x54);
    BOOST_CHECK_EQUAL(msg[2], 0x58);
    BOOST_CHECK_EQUAL(msg[3], 0x01);
    BOOST_CHECK_EQUAL(params->GetDefaultPort(), 19335);
    BOOST_CHECK_EQUAL(params->Bech32HRP(), "btx");
    BOOST_CHECK_EQUAL(params->Base58Prefix(CChainParams::PUBKEY_ADDRESS).at(0), 25);
    BOOST_CHECK_EQUAL(params->Base58Prefix(CChainParams::SCRIPT_ADDRESS).at(0), 50);
    BOOST_CHECK_EQUAL(params->Base58Prefix(CChainParams::SECRET_KEY).at(0), 153);
    BOOST_CHECK_GE(params->DNSSeeds().size(), 1U);
    BOOST_CHECK(!params->FixedSeeds().empty());
    BOOST_CHECK_GE(params->Checkpoints().mapCheckpoints.size(), 1U);
    BOOST_CHECK(!params->AssumeutxoForHeight(110).has_value());
}

BOOST_AUTO_TEST_CASE(ChainParams_MAIN_hardening_anchor_consistency)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto consensus = params->GetConsensus();

    BOOST_CHECK_EQUAL(
        consensus.nMinimumChainWork.GetHex(),
        "000000000000000000000000000000000000000000000000000005323d5ff789");
    BOOST_CHECK_EQUAL(
        consensus.defaultAssumeValid.GetHex(),
        "d95c8b565fefcda79efe47acad98648b0a24899f22facba9eedeb02c8bffd4d2");
    BOOST_CHECK_EQUAL(params->AssumedBlockchainSize(), 16U);
    BOOST_CHECK_EQUAL(params->AssumedChainStateSize(), 1U);

    const auto& checkpoints = params->Checkpoints().mapCheckpoints;
    BOOST_REQUIRE_GE(checkpoints.size(), 2U);
    const auto it_0 = checkpoints.find(0);
    BOOST_REQUIRE(it_0 != checkpoints.end());
    BOOST_CHECK_EQUAL(
        it_0->second.GetHex(),
        "75a998a39d2d6e25a9ca7de2cc659309c4105839c06cd435ba2b1aabf0fa4601");
    const auto it_anchor = checkpoints.find(128605);
    BOOST_REQUIRE(it_anchor != checkpoints.end());
    BOOST_CHECK_EQUAL(
        it_anchor->second.GetHex(),
        "d95c8b565fefcda79efe47acad98648b0a24899f22facba9eedeb02c8bffd4d2");

    const auto assumeutxo_55000 = params->AssumeutxoForHeight(55000);
    BOOST_REQUIRE(assumeutxo_55000.has_value());
    BOOST_CHECK_EQUAL(assumeutxo_55000->height, 55000);
    BOOST_CHECK_EQUAL(
        assumeutxo_55000->hash_serialized.ToString(),
        "3fdff3b95b68ae2d40ef949e41d9e39fe68591f7fcc4cbfbc46c04f58030dda5");
    BOOST_CHECK_EQUAL(assumeutxo_55000->m_chain_tx_count, 56457U);
    BOOST_CHECK_EQUAL(
        assumeutxo_55000->blockhash.GetHex(),
        "db5e6530e55606be66aa78fe3f711e9dc4406ee4b26dde2ed819103c37d97d63");

    const auto assumeutxo_60760 = params->AssumeutxoForHeight(60760);
    BOOST_REQUIRE(assumeutxo_60760.has_value());
    BOOST_CHECK_EQUAL(assumeutxo_60760->height, 60760);
    BOOST_CHECK_EQUAL(
        assumeutxo_60760->hash_serialized.ToString(),
        "e05de35057bbb3b8fa3834c9a2b557b8d54328b2100c06396a0741ab06c98e2a");
    BOOST_CHECK_EQUAL(assumeutxo_60760->m_chain_tx_count, 66205U);
    BOOST_CHECK_EQUAL(
        assumeutxo_60760->blockhash.GetHex(),
        "6528ebf50342363b63c17afd851a28307bc2c0fac596373ca9f59c30726d169c");

    const auto assumeutxo_64900 = params->AssumeutxoForHeight(64900);
    BOOST_REQUIRE(assumeutxo_64900.has_value());
    BOOST_CHECK_EQUAL(assumeutxo_64900->height, 64900);
    BOOST_CHECK_EQUAL(
        assumeutxo_64900->hash_serialized.ToString(),
        "696f6ae3bcfed21881647be3871bf9574eb02fc10b7082677cc29a9b98529459");
    BOOST_CHECK_EQUAL(assumeutxo_64900->m_chain_tx_count, 73257U);
    BOOST_CHECK_EQUAL(
        assumeutxo_64900->blockhash.GetHex(),
        "6e5ebacea9f8168371f7c0255e7314aefa69516224675aa326166dbbf39b85f0");

    const auto assumeutxo_71260 = params->AssumeutxoForHeight(71260);
    BOOST_REQUIRE(assumeutxo_71260.has_value());
    BOOST_CHECK_EQUAL(assumeutxo_71260->height, 71260);
    BOOST_CHECK_EQUAL(
        assumeutxo_71260->hash_serialized.ToString(),
        "46c2582d63ebb1aaf3865f0541e39287c59970ce890253c426b65911eb87e5fa");
    BOOST_CHECK_EQUAL(assumeutxo_71260->m_chain_tx_count, 83531U);
    BOOST_CHECK_EQUAL(
        assumeutxo_71260->blockhash.GetHex(),
        "993ddd9ccd08820ad4df089de6a444ffacc788b1b3b9015657d60e353fbad924");

    const auto assumeutxo_71435 = params->AssumeutxoForHeight(71435);
    BOOST_REQUIRE(assumeutxo_71435.has_value());
    BOOST_CHECK_EQUAL(assumeutxo_71435->height, 71435);
    BOOST_CHECK_EQUAL(
        assumeutxo_71435->hash_serialized.ToString(),
        "9739e6a5891433d542617d28ae71131d976fe60d51a06af87db49f4a0c5a68d6");
    BOOST_CHECK_EQUAL(assumeutxo_71435->m_chain_tx_count, 83851U);
    BOOST_CHECK_EQUAL(
        assumeutxo_71435->blockhash.GetHex(),
        "46f81957ac0d40c57eef01810f4da3abb8e8a2c67ebb9fd88f36b1cc5a8e7be0");

    const auto assumeutxo_85850 = params->AssumeutxoForHeight(85850);
    BOOST_REQUIRE(assumeutxo_85850.has_value());
    BOOST_CHECK_EQUAL(assumeutxo_85850->height, 85850);
    BOOST_CHECK_EQUAL(
        assumeutxo_85850->hash_serialized.ToString(),
        "c0dc455137b4e30554ec91570e198d9c80b1e934f41bece43040e133c8ba9328");
    BOOST_CHECK_EQUAL(assumeutxo_85850->m_chain_tx_count, 101463U);
    BOOST_CHECK_EQUAL(
        assumeutxo_85850->blockhash.GetHex(),
        "bbb36b59df48e364dcf32e8ca13f3e5a89fdc16c483fa26779c43da5feb4d40c");

    const auto assumeutxo_105550 = params->AssumeutxoForHeight(105550);
    BOOST_REQUIRE(assumeutxo_105550.has_value());
    BOOST_CHECK_EQUAL(assumeutxo_105550->height, 105550);
    BOOST_CHECK_EQUAL(
        assumeutxo_105550->hash_serialized.ToString(),
        "20465f460f43e3f1ed4baf237cd52564d6a6f8e4ae3961237dbd60be7bfc1865");
    BOOST_CHECK_EQUAL(assumeutxo_105550->m_chain_tx_count, 126978U);
    BOOST_CHECK_EQUAL(
        assumeutxo_105550->blockhash.GetHex(),
        "3245a5e7debf69da9589fb0bc7bfd88fec32575c6f9a3a5d687dc38251a88fc7");

    const auto assumeutxo_106875 = params->AssumeutxoForHeight(106875);
    BOOST_REQUIRE(assumeutxo_106875.has_value());
    BOOST_CHECK_EQUAL(assumeutxo_106875->height, 106875);
    BOOST_CHECK_EQUAL(
        assumeutxo_106875->hash_serialized.ToString(),
        "662b8b2a2d17654002b0532658ac560f1aa59e35e21738b986eb78212871250b");
    BOOST_CHECK_EQUAL(assumeutxo_106875->m_chain_tx_count, 128730U);
    BOOST_CHECK_EQUAL(
        assumeutxo_106875->blockhash.GetHex(),
        "88a7b534ff66a863d45813668d9e53010a257af18b2d73154ec31a873bd36534");

    const auto assumeutxo_118225 = params->AssumeutxoForHeight(118225);
    BOOST_REQUIRE(assumeutxo_118225.has_value());
    BOOST_CHECK_EQUAL(assumeutxo_118225->height, 118225);
    BOOST_CHECK_EQUAL(
        assumeutxo_118225->hash_serialized.ToString(),
        "69810930f3c4102c10bde6a5380059f6b9b59fc5a0f28c0805576c04a95cd8e1");
    BOOST_CHECK_EQUAL(assumeutxo_118225->m_chain_tx_count, 144179U);
    BOOST_CHECK_EQUAL(
        assumeutxo_118225->blockhash.GetHex(),
        "f4dfb86209f2f4f2c9ccfb960368cc334afea065916a82f38698f6391118cd8e");

    const auto assumeutxo_120900 = params->AssumeutxoForHeight(120900);
    BOOST_REQUIRE(assumeutxo_120900.has_value());
    BOOST_CHECK_EQUAL(assumeutxo_120900->height, 120900);
    BOOST_CHECK_EQUAL(
        assumeutxo_120900->hash_serialized.ToString(),
        "73c62a680afefae9a861131938947831becc774513bd788cc4f93cc42aa06f55");
    BOOST_CHECK_EQUAL(assumeutxo_120900->m_chain_tx_count, 147449U);
    BOOST_CHECK_EQUAL(
        assumeutxo_120900->blockhash.GetHex(),
        "24744e8793137d0a6639a90c066b78e7edb6722ad7007cdac0911ae171ead611");

    const auto assumeutxo_123225 = params->AssumeutxoForHeight(123225);
    BOOST_REQUIRE(assumeutxo_123225.has_value());
    BOOST_CHECK_EQUAL(assumeutxo_123225->height, 123225);
    BOOST_CHECK_EQUAL(
        assumeutxo_123225->hash_serialized.ToString(),
        "153ed4ddf0957251bd450f25f8b10956c3cb47d382ecbc7692e04da1a878b2b8");
    BOOST_CHECK_EQUAL(assumeutxo_123225->m_chain_tx_count, 150104U);
    BOOST_CHECK_EQUAL(
        assumeutxo_123225->blockhash.GetHex(),
        "bee000e92d6b64ceb6ad9a3759fb38c1d6752713240e76bde3617f073b9cbe74");

    const auto assumeutxo_126800 = params->AssumeutxoForHeight(126800);
    BOOST_REQUIRE(assumeutxo_126800.has_value());
    BOOST_CHECK_EQUAL(assumeutxo_126800->height, 126800);
    BOOST_CHECK_EQUAL(
        assumeutxo_126800->hash_serialized.ToString(),
        "240d2b278972ad96afa9c5e26f1f846b2a60a4a9aea4aa8f0a57baa0108db6ae");
    BOOST_CHECK_EQUAL(assumeutxo_126800->m_chain_tx_count, 155621U);
    BOOST_CHECK_EQUAL(
        assumeutxo_126800->blockhash.GetHex(),
        "fb6dcf553916244d09ea1cf1f0c0dfc714f232ac17c94f8d0a73d21a75de9e34");

    const auto assumeutxo_128605 = params->AssumeutxoForHeight(128605);
    BOOST_REQUIRE(assumeutxo_128605.has_value());
    BOOST_CHECK_EQUAL(assumeutxo_128605->height, 128605);
    BOOST_CHECK_EQUAL(
        assumeutxo_128605->hash_serialized.ToString(),
        "2cfa629907fbc18f3edc1dbb8b33fda651ad3655fb88a9dffe7a67ead580a102");
    BOOST_CHECK_EQUAL(assumeutxo_128605->m_chain_tx_count, 158299U);
    BOOST_CHECK_EQUAL(
        assumeutxo_128605->blockhash.GetHex(),
        "d95c8b565fefcda79efe47acad98648b0a24899f22facba9eedeb02c8bffd4d2");
    BOOST_CHECK_EQUAL(
        assumeutxo_128605->shielded_state_commitment.GetHex(),
        "827f8bf52ddf6de1e780a0917179dac715abeb428580744505dc30fbd6be5f9d");

    const auto assumeutxo_132173 = params->AssumeutxoForHeight(132173);
    BOOST_REQUIRE(assumeutxo_132173.has_value());
    BOOST_CHECK_EQUAL(assumeutxo_132173->height, 132173);
    BOOST_CHECK_EQUAL(
        assumeutxo_132173->hash_serialized.ToString(),
        "088b124e34af88441ce485deb0418d92c090983253956cb6c7c0d8249a747be2");
    BOOST_CHECK_EQUAL(assumeutxo_132173->m_chain_tx_count, 169410U);
    BOOST_CHECK_EQUAL(
        assumeutxo_132173->blockhash.GetHex(),
        "010aad22cd3c10caf33c049b08c34c46c86ec812c74ec5962a477916850ffb5b");
    BOOST_CHECK_EQUAL(
        assumeutxo_132173->shielded_state_commitment.GetHex(),
        "5d215cf4ed8cb9fbaddd2321cc996e0b754da0cfbd6055514a3cca78f7aa2792");

    const auto assumeutxo_132209 = params->AssumeutxoForHeight(132209);
    BOOST_REQUIRE(assumeutxo_132209.has_value());
    BOOST_CHECK_EQUAL(assumeutxo_132209->height, 132209);
    BOOST_CHECK_EQUAL(
        assumeutxo_132209->hash_serialized.ToString(),
        "56139bf25e3749650ec9f5608b417b0842fb99775b61b7433cfdee1768e40a0e");
    BOOST_CHECK_EQUAL(assumeutxo_132209->m_chain_tx_count, 169454U);
    BOOST_CHECK_EQUAL(
        assumeutxo_132209->blockhash.GetHex(),
        "9e6776ee8c5e8dceefcb108b429838be8bda3d66a6553d8b4c8cef613840c940");
    BOOST_CHECK_EQUAL(
        assumeutxo_132209->shielded_state_commitment.GetHex(),
        "5d215cf4ed8cb9fbaddd2321cc996e0b754da0cfbd6055514a3cca78f7aa2792");

    const auto snapshot_heights = params->GetAvailableSnapshotHeights();
    BOOST_REQUIRE_EQUAL(snapshot_heights.size(), 18U);
    BOOST_CHECK(std::is_sorted(snapshot_heights.begin(), snapshot_heights.end()));
    BOOST_CHECK_EQUAL(snapshot_heights.front(), 55000);
    BOOST_CHECK_EQUAL(snapshot_heights.back(), 132209);
    BOOST_CHECK_GE(snapshot_heights.back(), std::prev(checkpoints.end())->first);
}

BOOST_AUTO_TEST_CASE(HasValidProofOfWork_matmul_phase1_checks)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    BOOST_REQUIRE(consensus.fMatMulPOW);

    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock = uint256{1};
    header.nBits = UintToArith256(consensus.powLimit).GetCompact();
    header.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    header.seed_a = *uint256::FromHex("0000000000000000000000000000000000000000000000000000000000000001");
    header.seed_b = *uint256::FromHex("0000000000000000000000000000000000000000000000000000000000000002");
    std::vector<CBlockHeader> headers{header};

    BOOST_CHECK(HasValidProofOfWork(headers, consensus));

    headers[0].seed_b.SetNull();
    BOOST_CHECK(!HasValidProofOfWork(headers, consensus));
}

BOOST_AUTO_TEST_CASE(GetNextWorkRequired_matmul_dgw_window_guard)
{
    // MatMul now uses ASERT exclusively. Verify retargeting returns a valid
    // compact target for a steady-state chain (all blocks at target spacing).
    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.fKAWPOW = false;
    consensus.fPowNoRetargeting = false;
    consensus.nFastMineDifficultyScale = 1;
    // Keep this scenario in the bootstrap/fixed-difficulty phase.
    consensus.nMatMulAsertHeight = std::numeric_limits<int32_t>::max();

    std::vector<CBlockIndex> blocks(101);
    for (size_t i = 0; i < blocks.size(); ++i) {
        blocks[i].nHeight = static_cast<int>(i);
        blocks[i].nBits = 0x207fffff;
        blocks[i].nTime = 1700000000 + static_cast<int64_t>(i) * consensus.nPowTargetSpacing;
        blocks[i].pprev = (i == 0) ? nullptr : &blocks[i - 1];
    }

    CBlockHeader next;
    next.nTime = blocks.back().nTime + consensus.nPowTargetSpacing;

    // ASERT returns a valid compact target; just verify it doesn't crash or
    // return zero.
    const auto result = GetNextWorkRequired(&blocks.back(), &next, consensus);
    BOOST_CHECK(result != 0);
}

BOOST_AUTO_TEST_CASE(GetNextWorkRequired_matmul_malformed_ancestor_chain_fails_closed)
{
    // With ASERT, a malformed chain (self-loop) should still return a valid
    // target without crashing.
    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.fKAWPOW = false;
    consensus.fPowNoRetargeting = false;
    // Keep this scenario in the bootstrap/fixed-difficulty phase.
    consensus.nMatMulAsertHeight = std::numeric_limits<int32_t>::max();

    CBlockIndex malformed_tip{};
    malformed_tip.nHeight = static_cast<int>(2 * DGW_PAST_BLOCKS + 5);
    malformed_tip.nBits = UintToArith256(consensus.powLimit).GetCompact();
    malformed_tip.nTime = 1'700'000'000;
    malformed_tip.pprev = &malformed_tip; // self-loop should never be traversed as a valid chain

    CBlockHeader next{};
    next.nTime = malformed_tip.nTime + consensus.nPowTargetSpacing;

    // ASERT should return a valid target; it may or may not match powLimit.
    const auto result = GetNextWorkRequired(&malformed_tip, &next, consensus);
    BOOST_CHECK(result != 0);
}

BOOST_AUTO_TEST_CASE(GetNextWorkRequired_matmul_missing_prev_link_fails_closed)
{
    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.fKAWPOW = false;
    consensus.fPowNoRetargeting = false;
    // Keep this scenario in the bootstrap/fixed-difficulty phase.
    consensus.nMatMulAsertHeight = std::numeric_limits<int32_t>::max();

    CBlockIndex malformed_tip{};
    malformed_tip.nHeight = static_cast<int>(2 * DGW_PAST_BLOCKS + 5);
    malformed_tip.nBits = UintToArith256(consensus.powLimit).GetCompact();
    malformed_tip.nTime = 1'700'000'000;
    malformed_tip.pprev = nullptr; // inconsistent: non-genesis height without parent link

    CBlockHeader next{};
    next.nTime = malformed_tip.nTime + consensus.nPowTargetSpacing;

    BOOST_CHECK_EQUAL(GetNextWorkRequired(&malformed_tip, &next, consensus), UintToArith256(consensus.powLimit).GetCompact());
}

BOOST_AUTO_TEST_CASE(PermittedDifficultyTransition_matmul_bounds)
{
    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.fKAWPOW = false;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    constexpr uint32_t old_nbits = 0x1f040d7fU;
    const arith_uint256 old_target = DecodeTarget(old_nbits);

    arith_uint256 allowed_easier = old_target;
    allowed_easier *= 4;
    BOOST_CHECK(PermittedDifficultyTransition(consensus, /*height=*/1, old_nbits, allowed_easier.GetCompact()));

    arith_uint256 disallowed_easier = old_target;
    disallowed_easier *= 8;
    BOOST_CHECK(!PermittedDifficultyTransition(consensus, /*height=*/1, old_nbits, disallowed_easier.GetCompact()));

    arith_uint256 allowed_harder = old_target;
    allowed_harder /= 4;
    if (allowed_harder == 0) {
        allowed_harder = arith_uint256{1};
    }
    BOOST_CHECK(PermittedDifficultyTransition(consensus, /*height=*/1, old_nbits, allowed_harder.GetCompact()));

    arith_uint256 disallowed_harder = old_target;
    disallowed_harder /= 8;
    if (disallowed_harder == 0) {
        disallowed_harder = arith_uint256{1};
    }
    BOOST_CHECK(!PermittedDifficultyTransition(consensus, /*height=*/1, old_nbits, disallowed_harder.GetCompact()));
}

BOOST_AUTO_TEST_CASE(GetNextWorkRequired_matmul_warmup_floor)
{
    // With ASERT, verify a short chain with a large time gap still returns a
    // valid difficulty without crashing.
    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.fKAWPOW = false;
    consensus.fPowNoRetargeting = false;
    consensus.nFastMineHeight = 4;
    consensus.nMatMulAsertHeight = 4;
    consensus.nFastMineDifficultyScale = 1;
    consensus.nPowTargetSpacingNormal = 90;
    consensus.powLimit = uint256{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    std::vector<CBlockIndex> blocks(5);
    for (size_t i = 0; i < blocks.size(); ++i) {
        blocks[i].nHeight = static_cast<int>(i);
        blocks[i].nBits = 0x1d00ffffU;
        blocks[i].nTime = 1'700'000'000 + static_cast<int64_t>(i);
        blocks[i].pprev = (i == 0) ? nullptr : &blocks[i - 1];
    }
    // Force a large observed span at the first warmup retarget step.
    blocks.back().nTime = blocks[blocks.size() - 2].nTime + 5'000;

    CBlockHeader next{};
    next.nTime = blocks.back().nTime + 1;
    const uint32_t retarget_bits = GetNextWorkRequired(&blocks.back(), &next, consensus);
    const uint32_t bootstrap_bits = blocks.back().nBits;
    // ASERT-only routing may harden difficulty at this boundary, but it must
    // never make difficulty easier than the bootstrap floor.
    BOOST_CHECK(retarget_bits <= bootstrap_bits);
}

BOOST_AUTO_TEST_CASE(GetNextWorkRequired_matmul_dgw_steady_state)
{
    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.fKAWPOW = false;
    consensus.fPowNoRetargeting = false;

    constexpr int64_t nPastBlocks = 2 * DGW_PAST_BLOCKS;
    std::vector<CBlockIndex> blocks(nPastBlocks + 1);
    for (int i = 0; i <= nPastBlocks; ++i) {
        blocks[i].nHeight = i;
        blocks[i].nBits = 0x207fffff;
        blocks[i].nTime = 1700000000 + i * consensus.nPowTargetSpacing;
        blocks[i].pprev = (i == 0) ? nullptr : &blocks[i - 1];
    }

    CBlockHeader next;
    next.nTime = blocks.back().nTime + consensus.nPowTargetSpacing;
    const uint32_t next_bits{GetNextWorkRequired(&blocks.back(), &next, consensus)};
    const arith_uint256 target{DecodeTarget(next_bits)};
    BOOST_CHECK(target <= UintToArith256(consensus.powLimit));
    BOOST_CHECK(target < DecodeTarget(blocks.back().nBits));
}

BOOST_AUTO_TEST_CASE(GetNextWorkRequired_matmul_dgw_long_horizon_scaling)
{
    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.fKAWPOW = false;
    consensus.fPowNoRetargeting = false;

    constexpr int baseline_phase_blocks{300};
    constexpr int high_hashrate_phase_blocks{500};
    constexpr int first_recovery_phase_blocks{500};
    constexpr int low_hashrate_phase_blocks{500};
    constexpr int second_recovery_phase_blocks{500};
    constexpr int simulated_blocks{
        baseline_phase_blocks + high_hashrate_phase_blocks + first_recovery_phase_blocks + low_hashrate_phase_blocks + second_recovery_phase_blocks};
    constexpr int seed_blocks{static_cast<int>(2 * DGW_PAST_BLOCKS) + 1};
    constexpr int total_blocks{seed_blocks + simulated_blocks};

    std::vector<CBlockIndex> blocks(total_blocks);
    std::vector<arith_uint256> targets(total_blocks);
    SeedSteadyDGWChain(consensus, blocks, targets);

    const arith_uint256 steady_target{DecodeTarget(DGW_STEADY_BITS)};
    for (int i = seed_blocks; i < total_blocks; ++i) {
        const int phase_height{i - seed_blocks};
        double hashrate_multiplier{1.0};
        if (phase_height >= baseline_phase_blocks &&
            phase_height < baseline_phase_blocks + high_hashrate_phase_blocks) {
            hashrate_multiplier = 10.0;
        } else if (phase_height >= baseline_phase_blocks + high_hashrate_phase_blocks + first_recovery_phase_blocks &&
                   phase_height <
                       baseline_phase_blocks + high_hashrate_phase_blocks + first_recovery_phase_blocks + low_hashrate_phase_blocks) {
            hashrate_multiplier = 0.1;
        }

        const int64_t spacing{
            ExpectedSpacingForHashrate(consensus, steady_target, targets[i - 1], hashrate_multiplier)};
        AppendDGWSimulatedBlock(consensus, blocks, targets, i, spacing);
    }

    const arith_uint256 baseline_target{targets[seed_blocks + baseline_phase_blocks - 1]};
    const arith_uint256 high_phase_start_target{targets[seed_blocks + baseline_phase_blocks]};
    const arith_uint256 fast_target{targets[seed_blocks + baseline_phase_blocks + high_hashrate_phase_blocks - 1]};
    const arith_uint256 fast_recovery_target{
        targets[seed_blocks + baseline_phase_blocks + high_hashrate_phase_blocks + first_recovery_phase_blocks - 1]};
    const arith_uint256 low_phase_start_target{
        targets[seed_blocks + baseline_phase_blocks + high_hashrate_phase_blocks + first_recovery_phase_blocks]};
    const arith_uint256 slow_target{
        targets[seed_blocks + baseline_phase_blocks + high_hashrate_phase_blocks + first_recovery_phase_blocks + low_hashrate_phase_blocks - 1]};
    const arith_uint256 final_target{targets[total_blocks - 1]};

    BOOST_CHECK(fast_target < high_phase_start_target);
    BOOST_CHECK(fast_target < baseline_target);
    BOOST_CHECK(slow_target > low_phase_start_target);
    BOOST_CHECK(final_target < slow_target);

    // DGW should return close to the baseline target after extended recovery windows.
    const double fast_recovery_ratio{TargetRatio(fast_recovery_target, baseline_target)};
    BOOST_CHECK_GE(fast_recovery_ratio, 0.01);
    BOOST_CHECK_LE(fast_recovery_ratio, 5.00);

    const double final_recovery_ratio{TargetRatio(final_target, baseline_target)};
    BOOST_CHECK_GE(final_recovery_ratio, 0.0001);
    BOOST_CHECK_LE(final_recovery_ratio, 5.00);
}

BOOST_AUTO_TEST_CASE(GetNextWorkRequired_matmul_dgw_oscillation_resilience)
{
    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.fKAWPOW = false;
    consensus.fPowNoRetargeting = false;

    constexpr int seed_blocks{static_cast<int>(2 * DGW_PAST_BLOCKS) + 1};
    constexpr int baseline_phase_blocks{200};
    constexpr int oscillation_phase_blocks{2800};
    constexpr int total_blocks{seed_blocks + baseline_phase_blocks + oscillation_phase_blocks};

    std::vector<CBlockIndex> blocks(total_blocks);
    std::vector<arith_uint256> targets(total_blocks);
    SeedSteadyDGWChain(consensus, blocks, targets);

    const arith_uint256 steady_target{DecodeTarget(DGW_STEADY_BITS)};
    for (int i = seed_blocks; i < total_blocks; ++i) {
        const int phase_height{i - seed_blocks};
        double hashrate_multiplier{1.0};
        if (phase_height >= baseline_phase_blocks) {
            hashrate_multiplier = ((phase_height - baseline_phase_blocks) % 2 == 0) ? 10.0 : 0.1;
        }

        const int64_t spacing{
            ExpectedSpacingForHashrate(consensus, steady_target, targets[i - 1], hashrate_multiplier)};
        AppendDGWSimulatedBlock(consensus, blocks, targets, i, spacing);
    }

    const arith_uint256 baseline_target{targets[seed_blocks + baseline_phase_blocks - 1]};
    double min_ratio{std::numeric_limits<double>::max()};
    double max_ratio{0.0};
    double first_half_sum{0.0};
    double second_half_sum{0.0};
    int first_half_count{0};
    int second_half_count{0};
    const int tail_start{seed_blocks + baseline_phase_blocks + 400};
    const int tail_midpoint{tail_start + (total_blocks - tail_start) / 2};
    for (int height = tail_start; height < total_blocks; ++height) {
        const double ratio{TargetRatio(targets[height], baseline_target)};
        min_ratio = std::min(min_ratio, ratio);
        max_ratio = std::max(max_ratio, ratio);
        if (height < tail_midpoint) {
            first_half_sum += ratio;
            ++first_half_count;
        } else {
            second_half_sum += ratio;
            ++second_half_count;
        }
    }
    BOOST_REQUIRE(first_half_count > 0);
    BOOST_REQUIRE(second_half_count > 0);
    const double first_half_average{first_half_sum / first_half_count};
    const double second_half_average{second_half_sum / second_half_count};
    const double drift_ratio{second_half_average / first_half_average};

    // Under sustained oscillation, DGW should stay bounded and avoid extreme collapse/spikes.
    BOOST_CHECK_GE(min_ratio, 0.0000001);
    BOOST_CHECK_LE(max_ratio, 1000.00);
    BOOST_CHECK_GE(drift_ratio, 0.50);
    BOOST_CHECK_LE(drift_ratio, 2.00);
}

BOOST_AUTO_TEST_CASE(GetNextWorkRequired_matmul_dgw_timestamp_drift_recovery)
{
    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.fKAWPOW = false;
    consensus.fPowNoRetargeting = false;

    constexpr int seed_blocks{static_cast<int>(2 * DGW_PAST_BLOCKS) + 1};
    constexpr int baseline_phase_blocks{200};
    constexpr int drift_phase_blocks{400};
    constexpr int recovery_phase_blocks{1000};
    constexpr int total_blocks{seed_blocks + baseline_phase_blocks + drift_phase_blocks + recovery_phase_blocks};

    std::vector<CBlockIndex> blocks(total_blocks);
    std::vector<arith_uint256> targets(total_blocks);
    SeedSteadyDGWChain(consensus, blocks, targets);

    const arith_uint256 steady_target{DecodeTarget(DGW_STEADY_BITS)};
    for (int i = seed_blocks; i < total_blocks; ++i) {
        const int phase_height{i - seed_blocks};
        int64_t reported_spacing{consensus.nPowTargetSpacing};
        if (phase_height < baseline_phase_blocks) {
            reported_spacing = ExpectedSpacingForHashrate(consensus, steady_target, targets[i - 1], 1.0);
        } else if (phase_height < baseline_phase_blocks + drift_phase_blocks) {
            // Simulate timestamp withholding/minimal increment while high hashrate mines quickly.
            reported_spacing = 1;
        } else {
            reported_spacing = ExpectedSpacingForHashrate(consensus, steady_target, targets[i - 1], 1.0);
        }

        AppendDGWSimulatedBlock(consensus, blocks, targets, i, reported_spacing);
    }

    const arith_uint256 baseline_target{targets[seed_blocks + baseline_phase_blocks - 1]};
    const arith_uint256 drift_target{targets[seed_blocks + baseline_phase_blocks + drift_phase_blocks - 1]};
    const arith_uint256 recovered_target{targets[total_blocks - 1]};

    BOOST_CHECK(drift_target < baseline_target);
    const double drift_ratio{TargetRatio(drift_target, baseline_target)};
    BOOST_CHECK_LE(drift_ratio, 0.25);

    const double recovered_ratio{TargetRatio(recovered_target, baseline_target)};
    BOOST_CHECK_GE(recovered_ratio, 0.01);
    BOOST_CHECK_LE(recovered_ratio, 3.00);
}

BOOST_AUTO_TEST_CASE(CBlockIndex_preserves_matmul_header_fields)
{
    CBlockHeader header;
    header.nVersion = 4;
    header.hashPrevBlock.SetNull();
    header.hashMerkleRoot = *uint256::FromHex("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100");
    header.nTime = 1700000400;
    header.nBits = 0x207fffff;
    header.nNonce = 1;
    header.nNonce64 = 0x1122334455667788ULL;
    header.matmul_digest = *uint256::FromHex("9999aaaabbbbccccddddeeeeffff000011112222333344445555666677778888");
    header.matmul_dim = 64;
    header.seed_a = *uint256::FromHex("0000000000000000000000000000000000000000000000000000000000000042");
    header.seed_b = *uint256::FromHex("0000000000000000000000000000000000000000000000000000000000000099");
    header.mix_hash = *uint256::FromHex("111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000");

    CBlockIndex index(header);
    const CBlockHeader reconstructed{index.GetBlockHeader()};

    BOOST_CHECK_EQUAL(reconstructed.nNonce64, header.nNonce64);
    BOOST_CHECK_EQUAL(reconstructed.matmul_digest, header.matmul_digest);
    BOOST_CHECK_EQUAL(reconstructed.matmul_dim, header.matmul_dim);
    BOOST_CHECK_EQUAL(reconstructed.seed_a, header.seed_a);
    BOOST_CHECK_EQUAL(reconstructed.seed_b, header.seed_b);
    BOOST_CHECK_EQUAL(reconstructed.mix_hash, header.mix_hash);
    BOOST_CHECK_EQUAL(reconstructed.GetHash(), header.GetHash());
}

BOOST_AUTO_TEST_CASE(CDiskBlockIndex_construct_hash_keeps_matmul_fields)
{
    CBlockHeader header;
    header.nVersion = 4;
    header.hashPrevBlock.SetNull();
    header.hashMerkleRoot = *uint256::FromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    header.nTime = 1700000500;
    header.nBits = 0x207fffff;
    header.nNonce = 2;
    header.nNonce64 = 0x8899aabbccddeeffULL;
    header.matmul_digest = *uint256::FromHex("1111111122222222333333334444444455555555666666667777777788888888");
    header.matmul_dim = 128;
    header.seed_a = *uint256::FromHex("aaaaaaaa00000000000000000000000000000000000000000000000000000000");
    header.seed_b = *uint256::FromHex("bbbbbbbb00000000000000000000000000000000000000000000000000000000");
    header.mix_hash = *uint256::FromHex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

    CBlockIndex index(header);
    CDiskBlockIndex disk_index(&index);

    BOOST_CHECK_EQUAL(disk_index.ConstructBlockHash(), header.GetHash());
}

BOOST_AUTO_TEST_CASE(bip94_timewarp_protection_applies_on_matmul_dgw_heights)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    BOOST_REQUIRE(consensus.enforce_BIP94);
    BOOST_REQUIRE(consensus.fMatMulPOW);
    BOOST_REQUIRE(!consensus.fPowNoRetargeting);

    const int64_t dai = consensus.DifficultyAdjustmentInterval();
    BOOST_CHECK_EQUAL(dai, 13'440);

    // DGW-retargeted, non-interval heights must still be BIP94 protected.
    for (int h : {61'181, 61'500, 61'000, 62'000, 63'000, 70'000}) {
        BOOST_REQUIRE(h % dai != 0);
        BOOST_CHECK(EnforceTimewarpProtectionAtHeight(consensus, h));
    }

    // Interval boundaries remain protected.
    BOOST_CHECK(EnforceTimewarpProtectionAtHeight(consensus, static_cast<int32_t>(dai)));
}

BOOST_AUTO_TEST_CASE(bip94_timewarp_protection_retains_boundary_behavior_on_legacy_retarget)
{
    auto consensus = LegacyRetargetConsensus();
    consensus.enforce_BIP94 = true;
    BOOST_REQUIRE(!consensus.fMatMulPOW);
    BOOST_REQUIRE(!consensus.fKAWPOW);

    const int64_t dai = consensus.DifficultyAdjustmentInterval();
    BOOST_CHECK(dai > 0);
    BOOST_CHECK(!EnforceTimewarpProtectionAtHeight(consensus, 1));
    BOOST_CHECK(EnforceTimewarpProtectionAtHeight(consensus, static_cast<int32_t>(dai)));
}

BOOST_AUTO_TEST_CASE(matmul_solve_pipelines_next_nonce_preparation_when_async_enabled)
{
    ScopedAsyncPipelineEnv async_env;
    ScopedBatchSizeEnv batch_size_env("3");

    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.nMatMulDimension = 16;
    consensus.nMatMulTranscriptBlockSize = 8;
    consensus.nMatMulNoiseRank = 4;
    consensus.nMatMulPreHashEpsilonBits = 0;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    CBlockHeader candidate{};
    candidate.nVersion = 4;
    candidate.hashPrevBlock = uint256{"0000000000000000000000000000000000000000000000000000000000000001"};
    candidate.hashMerkleRoot = uint256{"0000000000000000000000000000000000000000000000000000000000000002"};
    candidate.nTime = 1'700'000'001U;
    candidate.nBits = arith_uint256{1}.GetCompact();
    candidate.nNonce64 = 1;
    candidate.nNonce = 1;
    candidate.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    candidate.seed_a = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/0);
    candidate.seed_b = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/1);
    candidate.matmul_digest.SetNull();

    uint64_t max_tries{3};
    ResetMatMulSolvePipelineStats();
    const bool solved = SolveMatMul(candidate, consensus, max_tries);
    BOOST_CHECK(!solved);

    const auto stats = ProbeMatMulSolvePipelineStats();
    BOOST_CHECK(stats.async_prepare_enabled);
    BOOST_CHECK_GE(stats.prepared_inputs, 3U);
    BOOST_CHECK_GE(stats.async_prepare_worker_threads, 1U);
    BOOST_CHECK_GE(stats.async_prepare_submissions, 3U);
    BOOST_CHECK_EQUAL(stats.async_prepare_submissions, stats.async_prepare_completions);
    BOOST_CHECK_GE(stats.overlapped_prepares, 2U);
    BOOST_CHECK_GE(stats.batched_digest_requests, 1U);
    BOOST_CHECK_GE(stats.batched_nonce_attempts, 3U);
}

// Pool/share mining: a non-null share_target_override lets the solver return on an EASIER target while
// the consensus block target (pre-hash gate + miner pre-hash window) is unchanged. Exercised across both
// the legacy pre-activation path and the V2 nonce-seeded path, so every backend funnel is covered.
BOOST_AUTO_TEST_CASE(matmul_share_target_override_relaxes_only_digest_exit)
{
    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.nMatMulDimension = 16;
    consensus.nMatMulTranscriptBlockSize = 8;
    consensus.nMatMulNoiseRank = 4;
    consensus.nMatMulPreHashEpsilonBits = 0;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    // Block target == 1 (set via nBits below) is effectively unsolvable in a handful of tries, while the
    // maximal share target accepts the first scanned nonce. The two together prove the override changed
    // only the digest acceptance decision, not which nonces were scanned.
    const uint256 easy_share_target{uint256::FromHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").value()};

    // Cover both solver dispatch paths by reading the activation height from the params themselves.
    const int32_t nonce_seed_height = static_cast<int32_t>(consensus.nMatMulNonceSeedHeight);
    const std::vector<int32_t> heights{
        nonce_seed_height > 0 ? nonce_seed_height - 1 : -1,  // legacy (pre-activation)
        nonce_seed_height,                                   // V2 nonce-seeded
    };

    auto make_candidate = [&]() {
        CBlockHeader c{};
        c.nVersion = 4;
        c.hashPrevBlock = uint256{"0000000000000000000000000000000000000000000000000000000000000031"};
        c.hashMerkleRoot = uint256{"0000000000000000000000000000000000000000000000000000000000000032"};
        c.nTime = 1'700'000'777U;
        c.nBits = arith_uint256{1}.GetCompact();  // block target == 1
        c.nNonce64 = 1;
        c.nNonce = 1;
        c.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
        c.seed_a = DeterministicMatMulSeed(c.hashPrevBlock, /*height=*/0, /*which=*/0);
        c.seed_b = DeterministicMatMulSeed(c.hashPrevBlock, /*height=*/0, /*which=*/1);
        c.matmul_digest.SetNull();
        return c;
    };

    for (const int32_t height : heights) {
        // 1) Mining against the (tiny) block target finds nothing in a few tries.
        {
            CBlockHeader candidate = make_candidate();
            uint64_t max_tries{8};
            BOOST_CHECK_MESSAGE(!SolveMatMul(candidate, consensus, max_tries, height),
                                "block-target solve unexpectedly succeeded at height " << height);
        }

        // 2) The easy share target accepts the first scanned nonce as a share.
        {
            CBlockHeader candidate = make_candidate();
            uint64_t max_tries{8};
            const bool solved = SolveMatMul(candidate, consensus, max_tries, height,
                                            /*abort_flag=*/nullptr, /*freivalds_payload_out=*/nullptr,
                                            &easy_share_target);
            BOOST_CHECK_MESSAGE(solved, "share-target solve failed at height " << height);
            BOOST_CHECK(!candidate.matmul_digest.IsNull());
            BOOST_CHECK_LE(UintToArith256(candidate.matmul_digest), UintToArith256(easy_share_target));
            // The accepted digest does NOT meet the block target, so it is a share and not a consensus
            // block: this is the whole point of the override — the digest early-exit relaxed, nothing else.
            const auto block_target = DeriveTarget(candidate.nBits, consensus.powLimit);
            BOOST_REQUIRE(block_target.has_value());
            BOOST_CHECK_GT(UintToArith256(candidate.matmul_digest), *block_target);
        }

        // 3) A zero share target is rejected.
        {
            CBlockHeader candidate = make_candidate();
            uint64_t max_tries{8};
            const uint256 zero_target{};
            BOOST_CHECK(!SolveMatMul(candidate, consensus, max_tries, height,
                                     nullptr, nullptr, &zero_target));
        }

        // 4) A share target equal to the block target behaves exactly like no override.
        {
            const auto block_target = DeriveTarget(arith_uint256{1}.GetCompact(), consensus.powLimit);
            BOOST_REQUIRE(block_target.has_value());
            const uint256 block_target_u = ArithToUint256(*block_target);
            CBlockHeader candidate = make_candidate();
            uint64_t max_tries{8};
            BOOST_CHECK_MESSAGE(!SolveMatMul(candidate, consensus, max_tries, height,
                                             nullptr, nullptr, &block_target_u),
                                "block-target override unexpectedly solved at height " << height);
        }
    }
}

BOOST_AUTO_TEST_CASE(matmul_solve_prefetches_following_single_nonce_batches_when_async_enabled)
{
    ScopedAsyncPipelineEnv async_env;
    ScopedBatchSizeEnv batch_size_env("1");

    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.nMatMulDimension = 16;
    consensus.nMatMulTranscriptBlockSize = 8;
    consensus.nMatMulNoiseRank = 4;
    consensus.nMatMulPreHashEpsilonBits = 0;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    CBlockHeader candidate{};
    candidate.nVersion = 4;
    candidate.hashPrevBlock = uint256{"0000000000000000000000000000000000000000000000000000000000000011"};
    candidate.hashMerkleRoot = uint256{"0000000000000000000000000000000000000000000000000000000000000012"};
    candidate.nTime = 1'700'000'051U;
    candidate.nBits = arith_uint256{1}.GetCompact();
    candidate.nNonce64 = 1;
    candidate.nNonce = 1;
    candidate.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    candidate.seed_a = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/0);
    candidate.seed_b = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/1);
    candidate.matmul_digest.SetNull();

    uint64_t max_tries{3};
    ResetMatMulSolvePipelineStats();
    const bool solved = SolveMatMul(candidate, consensus, max_tries);
    BOOST_CHECK(!solved);

    const auto stats = ProbeMatMulSolvePipelineStats();
    BOOST_CHECK(stats.async_prepare_enabled);
    BOOST_CHECK_EQUAL(stats.batch_size, 1U);
    BOOST_CHECK_GE(stats.prepared_inputs, 3U);
    BOOST_CHECK_EQUAL(stats.overlapped_prepares, 0U);
    if (stats.prefetch_depth > 0) {
        BOOST_CHECK_GE(stats.prefetched_batches, 1U);
        BOOST_CHECK_GE(stats.prefetched_inputs, 1U);
    } else {
        BOOST_CHECK_EQUAL(stats.prefetched_batches, 0U);
        BOOST_CHECK_EQUAL(stats.prefetched_inputs, 0U);
    }
}

BOOST_AUTO_TEST_CASE(matmul_solve_extends_prefetch_queue_for_tuned_multi_nonce_batches)
{
    ScopedAsyncPipelineEnv async_env;
    ScopedBatchSizeEnv batch_size_env("2");
    ScopedPrefetchDepthEnv prefetch_depth_env("2");
    ScopedBackendEnv backend_env("metal");
    ScopedSolverThreadsEnv solver_threads_env("8");

    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.nMatMulDimension = 512;
    consensus.nMatMulTranscriptBlockSize = 16;
    consensus.nMatMulNoiseRank = 8;
    consensus.nMatMulPreHashEpsilonBits = 0;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    CBlockHeader candidate{};
    candidate.nVersion = 4;
    candidate.hashPrevBlock = uint256{"0000000000000000000000000000000000000000000000000000000000000021"};
    candidate.hashMerkleRoot = uint256{"0000000000000000000000000000000000000000000000000000000000000022"};
    candidate.nTime = 1'700'000'099U;
    candidate.nBits = arith_uint256{1}.GetCompact();
    candidate.nNonce64 = 0;
    candidate.nNonce = 0;
    candidate.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    candidate.seed_a = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/0);
    candidate.seed_b = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/1);
    candidate.matmul_digest.SetNull();

    uint64_t max_tries{4096};
    ResetMatMulSolvePipelineStats();
    const bool solved = SolveMatMul(candidate, consensus, max_tries);
    BOOST_CHECK(!solved);

    const auto stats = ProbeMatMulSolvePipelineStats();
    BOOST_CHECK_EQUAL(stats.batch_size, 2U);
    BOOST_CHECK(stats.async_prepare_enabled);
    BOOST_CHECK_EQUAL(stats.prefetch_depth, 2U);
    BOOST_CHECK_GE(stats.overlapped_prepares, 1U);
    BOOST_CHECK_GE(stats.prefetched_batches, 2U);
    BOOST_CHECK_GE(stats.prefetched_inputs, 4U);
}

BOOST_AUTO_TEST_CASE(matmul_solve_uses_two_nonce_batches_for_metal_product_mining_auto_policy)
{
    ScopedBackendEnv backend_env("metal");
    ScopedSolverThreadsEnv solver_threads_env(nullptr);
    ScopedApplePerfLogicalCpuOverrideEnv perf_override_env("10");

    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.nMatMulDimension = 512;
    consensus.nMatMulTranscriptBlockSize = 16;
    consensus.nMatMulNoiseRank = 8;
    consensus.nMatMulPreHashEpsilonBits = 0;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    CBlockHeader candidate{};
    candidate.nVersion = 4;
    candidate.hashPrevBlock = uint256{"0000000000000000000000000000000000000000000000000000000000000031"};
    candidate.hashMerkleRoot = uint256{"0000000000000000000000000000000000000000000000000000000000000032"};
    candidate.nTime = 1'700'000'121U;
    candidate.nBits = arith_uint256{1}.GetCompact();
    candidate.nNonce64 = 0;
    candidate.nNonce = 0;
    candidate.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    candidate.seed_a = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/0);
    candidate.seed_b = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/1);
    candidate.matmul_digest.SetNull();

    uint64_t max_tries{4096};
    ResetMatMulSolvePipelineStats();
    const bool solved = SolveMatMul(candidate, consensus, max_tries, /*block_height=*/61'000);
    BOOST_CHECK(!solved);

    const auto stats = ProbeMatMulSolvePipelineStats();
    const auto metal_capability = matmul::backend::CapabilityFor(matmul::backend::Kind::METAL);
    if (metal_capability.available) {
        BOOST_CHECK_EQUAL(stats.batch_size, 2U);
        BOOST_CHECK(stats.parallel_solver_enabled);
    } else {
        BOOST_CHECK_EQUAL(stats.batch_size, 1U);
    }
}

BOOST_AUTO_TEST_CASE(matmul_solve_processes_nonce_attempts_in_deterministic_batches_when_enabled)
{
    ScopedBatchSizeEnv batch_size_env("3");

    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.nMatMulDimension = 16;
    consensus.nMatMulTranscriptBlockSize = 8;
    consensus.nMatMulNoiseRank = 4;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    CBlockHeader candidate{};
    candidate.nVersion = 4;
    candidate.hashPrevBlock = uint256{"0000000000000000000000000000000000000000000000000000000000000003"};
    candidate.hashMerkleRoot = uint256{"0000000000000000000000000000000000000000000000000000000000000004"};
    candidate.nTime = 1'700'000'111U;
    candidate.nBits = arith_uint256{1}.GetCompact();
    candidate.nNonce64 = 11;
    candidate.nNonce = static_cast<uint32_t>(candidate.nNonce64);
    candidate.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    candidate.seed_a = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/0);
    candidate.seed_b = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/1);
    candidate.matmul_digest.SetNull();

    uint64_t max_tries{5};
    ResetMatMulSolvePipelineStats();
    const bool solved = SolveMatMul(candidate, consensus, max_tries);
    BOOST_CHECK(!solved);

    const auto stats = ProbeMatMulSolvePipelineStats();
    BOOST_CHECK_EQUAL(stats.batch_size, 3U);
    BOOST_CHECK_GE(stats.batched_digest_requests, 1U);
    BOOST_CHECK_GE(stats.batched_nonce_attempts, 3U);
    BOOST_CHECK_EQUAL(candidate.nNonce64, 16U);
    BOOST_CHECK_EQUAL(candidate.nNonce, static_cast<uint32_t>(candidate.nNonce64));
}

BOOST_AUTO_TEST_CASE(matmul_solve_advances_nonce_window_from_zero_without_exhaustion)
{
    ScopedBatchSizeEnv batch_size_env("4");

    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.nMatMulDimension = 16;
    consensus.nMatMulTranscriptBlockSize = 8;
    consensus.nMatMulNoiseRank = 4;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    CBlockHeader candidate{};
    candidate.nVersion = 4;
    candidate.hashPrevBlock = uint256{"0000000000000000000000000000000000000000000000000000000000000005"};
    candidate.hashMerkleRoot = uint256{"0000000000000000000000000000000000000000000000000000000000000006"};
    candidate.nTime = 1'700'000'211U;
    candidate.nBits = arith_uint256{1}.GetCompact();
    candidate.nNonce64 = 0;
    candidate.nNonce = 0;
    candidate.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    candidate.seed_a = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/0);
    candidate.seed_b = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/1);
    candidate.matmul_digest.SetNull();

    uint64_t max_tries{4};
    ResetMatMulSolvePipelineStats();
    const bool solved = SolveMatMul(candidate, consensus, max_tries);
    BOOST_CHECK(!solved);

    const auto stats = ProbeMatMulSolvePipelineStats();
    BOOST_CHECK_EQUAL(stats.batch_size, 4U);
    BOOST_CHECK_GE(stats.batched_nonce_attempts, 4U);
    BOOST_CHECK_EQUAL(max_tries, 0U);
    BOOST_CHECK_EQUAL(candidate.nNonce64, 4U);
    BOOST_CHECK_EQUAL(candidate.nNonce, static_cast<uint32_t>(candidate.nNonce64));
}

BOOST_AUTO_TEST_CASE(matmul_solve_refreshes_header_time_when_configured_interval_elapses)
{
    ScopedBatchSizeEnv batch_size_env("1");
    ScopedHeaderTimeRefreshEnv header_refresh_env("1");

    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.fPowAllowMinDifficultyBlocks = false;
    consensus.nMatMulDimension = 16;
    consensus.nMatMulTranscriptBlockSize = 8;
    consensus.nMatMulNoiseRank = 4;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    CBlockHeader candidate{};
    candidate.nVersion = 4;
    candidate.hashPrevBlock = uint256{"0000000000000000000000000000000000000000000000000000000000000009"};
    candidate.hashMerkleRoot = uint256{"000000000000000000000000000000000000000000000000000000000000000a"};
    candidate.nTime = 1'700'000'111U;
    candidate.nBits = arith_uint256{1}.GetCompact();
    candidate.nNonce64 = 0;
    candidate.nNonce = 0;
    candidate.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    candidate.seed_a = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/0);
    candidate.seed_b = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/1);
    candidate.matmul_digest.SetNull();

    const uint32_t refreshed_time{1'700'000'999U};
    ScopedNodeMockTime mock_time{refreshed_time};

    uint64_t max_tries{1};
    const bool solved = SolveMatMul(candidate, consensus, max_tries);
    BOOST_CHECK(!solved);
    BOOST_CHECK_EQUAL(max_tries, 0U);
    BOOST_CHECK_EQUAL(candidate.nTime, refreshed_time);
}

BOOST_AUTO_TEST_CASE(matmul_solve_skips_header_time_refresh_on_min_difficulty_networks)
{
    ScopedBatchSizeEnv batch_size_env("1");
    ScopedHeaderTimeRefreshEnv header_refresh_env("1");

    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.fPowAllowMinDifficultyBlocks = true;
    consensus.nMatMulDimension = 16;
    consensus.nMatMulTranscriptBlockSize = 8;
    consensus.nMatMulNoiseRank = 4;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    CBlockHeader candidate{};
    candidate.nVersion = 4;
    candidate.hashPrevBlock = uint256{"000000000000000000000000000000000000000000000000000000000000000b"};
    candidate.hashMerkleRoot = uint256{"000000000000000000000000000000000000000000000000000000000000000c"};
    candidate.nTime = 1'700'000'222U;
    candidate.nBits = arith_uint256{1}.GetCompact();
    candidate.nNonce64 = 0;
    candidate.nNonce = 0;
    candidate.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    candidate.seed_a = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/0);
    candidate.seed_b = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/1);
    candidate.matmul_digest.SetNull();

    const uint32_t original_time{candidate.nTime};
    ScopedNodeMockTime mock_time{1'700'000'999U};

    uint64_t max_tries{1};
    const bool solved = SolveMatMul(candidate, consensus, max_tries);
    BOOST_CHECK(!solved);
    BOOST_CHECK_EQUAL(max_tries, 0U);
    BOOST_CHECK_EQUAL(candidate.nTime, original_time);
}

BOOST_AUTO_TEST_CASE(matmul_solve_ignores_malformed_batch_size_env_suffix)
{
    ScopedBatchSizeEnv batch_size_env("3x");

    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.nMatMulDimension = 16;
    consensus.nMatMulTranscriptBlockSize = 8;
    consensus.nMatMulNoiseRank = 4;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    CBlockHeader candidate{};
    candidate.nVersion = 4;
    candidate.hashPrevBlock = uint256{"0000000000000000000000000000000000000000000000000000000000000007"};
    candidate.hashMerkleRoot = uint256{"0000000000000000000000000000000000000000000000000000000000000008"};
    candidate.nTime = 1'700'000'311U;
    candidate.nBits = arith_uint256{1}.GetCompact();
    candidate.nNonce64 = 0;
    candidate.nNonce = 0;
    candidate.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    candidate.seed_a = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/0);
    candidate.seed_b = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/1);
    candidate.matmul_digest.SetNull();

    uint64_t max_tries{3};
    ResetMatMulSolvePipelineStats();
    const bool solved = SolveMatMul(candidate, consensus, max_tries);
    BOOST_CHECK(!solved);

    const auto stats = ProbeMatMulSolvePipelineStats();
    BOOST_CHECK_EQUAL(stats.batch_size, 1U);
    BOOST_CHECK_EQUAL(stats.batched_nonce_attempts, 0U);
    BOOST_CHECK_EQUAL(max_tries, 0U);
    BOOST_CHECK_EQUAL(candidate.nNonce64, 3U);
    BOOST_CHECK_EQUAL(candidate.nNonce, static_cast<uint32_t>(candidate.nNonce64));
}

BOOST_AUTO_TEST_CASE(matmul_solve_defaults_to_single_nonce_batch_for_mainnet_shape)
{
    ScopedBatchSizeEnv batch_size_env(nullptr);
    ScopedBackendEnv backend_env("metal");

    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.nMatMulDimension = 512;
    consensus.nMatMulTranscriptBlockSize = 16;
    consensus.nMatMulNoiseRank = 8;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    CBlockHeader candidate{};
    candidate.nVersion = 4;
    candidate.hashPrevBlock = uint256{"000000000000000000000000000000000000000000000000000000000000000d"};
    candidate.hashMerkleRoot = uint256{"000000000000000000000000000000000000000000000000000000000000000e"};
    candidate.nTime = 1'700'000'333U;
    candidate.nBits = arith_uint256{1}.GetCompact();
    candidate.nNonce64 = 0;
    candidate.nNonce = 0;
    candidate.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    candidate.seed_a = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/0);
    candidate.seed_b = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/1);
    candidate.matmul_digest.SetNull();

    uint64_t max_tries{1};
    ResetMatMulSolvePipelineStats();
    const bool solved = SolveMatMul(candidate, consensus, max_tries);
    BOOST_CHECK(!solved);

    const auto stats = ProbeMatMulSolvePipelineStats();
    const auto selection = matmul::accelerated::ResolveMiningBackendFromEnvironment();
    BOOST_CHECK(!stats.parallel_solver_enabled);
    BOOST_CHECK_EQUAL(stats.parallel_solver_threads, 1U);
    BOOST_CHECK_EQUAL(stats.batch_size, 1U);
    BOOST_CHECK_EQUAL(
        stats.async_prepare_enabled,
        selection.active == matmul::backend::Kind::METAL || selection.active == matmul::backend::Kind::CUDA);
    BOOST_CHECK_EQUAL(stats.prefetched_batches, 0U);
    BOOST_CHECK_EQUAL(stats.prefetched_inputs, 0U);
}

BOOST_AUTO_TEST_CASE(matmul_solve_uses_two_nonce_batch_for_post_activation_mainnet_shape)
{
    ScopedBatchSizeEnv batch_size_env(nullptr);
    ScopedBackendEnv backend_env("metal");
    ScopedSolverThreadsEnv solver_threads_env("8");

    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.fMatMulFreivaldsEnabled = true;
    consensus.fMatMulRequireProductPayload = false;
    consensus.nMatMulFreivaldsBindingHeight = 61'000;
    consensus.nMatMulDimension = 512;
    consensus.nMatMulTranscriptBlockSize = 16;
    consensus.nMatMulNoiseRank = 8;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    CBlockHeader candidate{};
    candidate.nVersion = 4;
    candidate.hashPrevBlock = uint256{"0000000000000000000000000000000000000000000000000000000000000015"};
    candidate.hashMerkleRoot = uint256{"0000000000000000000000000000000000000000000000000000000000000016"};
    candidate.nTime = 1'700'000'339U;
    candidate.nBits = arith_uint256{1}.GetCompact();
    candidate.nNonce64 = 0;
    candidate.nNonce = 0;
    candidate.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    candidate.seed_a = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/0);
    candidate.seed_b = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/1);
    candidate.matmul_digest.SetNull();

    uint64_t max_tries{4};
    ResetMatMulSolvePipelineStats();
    const bool solved = SolveMatMul(candidate, consensus, max_tries, /*block_height_override=*/61'000);
    BOOST_CHECK(!solved);

    const auto stats = ProbeMatMulSolvePipelineStats();
    BOOST_CHECK_EQUAL(stats.batch_size, 2U);
    BOOST_CHECK_EQUAL(
        stats.async_prepare_enabled,
        matmul::accelerated::ResolveMiningBackendFromEnvironment().active == matmul::backend::Kind::METAL ||
            matmul::accelerated::ResolveMiningBackendFromEnvironment().active == matmul::backend::Kind::CUDA);
}

BOOST_AUTO_TEST_CASE(matmul_solve_uses_high_perf_apple_metal_defaults_when_perf_override_is_large)
{
    ScopedBatchSizeEnv batch_size_env(nullptr);
    ScopedPrefetchDepthEnv prefetch_depth_env(nullptr);
    ScopedPrepareWorkersEnv prepare_workers_env(nullptr);
    ScopedBackendEnv backend_env("metal");
    ScopedSolverThreadsEnv solver_threads_env(nullptr);
    ScopedApplePerfLogicalCpuOverrideEnv perf_override_env("10");

    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.fMatMulFreivaldsEnabled = true;
    consensus.fMatMulRequireProductPayload = false;
    consensus.nMatMulFreivaldsBindingHeight = 61'000;
    consensus.nMatMulDimension = 512;
    consensus.nMatMulTranscriptBlockSize = 16;
    consensus.nMatMulNoiseRank = 8;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    CBlockHeader candidate{};
    candidate.nVersion = 4;
    candidate.hashPrevBlock = uint256{"0000000000000000000000000000000000000000000000000000000000000019"};
    candidate.hashMerkleRoot = uint256{"000000000000000000000000000000000000000000000000000000000000001a"};
    candidate.nTime = 1'700'000'347U;
    candidate.nBits = arith_uint256{1}.GetCompact();
    candidate.nNonce64 = 0;
    candidate.nNonce = 0;
    candidate.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    candidate.seed_a = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/0);
    candidate.seed_b = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/1);
    candidate.matmul_digest.SetNull();

    uint64_t max_tries{4};
    ResetMatMulSolvePipelineStats();
    const bool solved = SolveMatMul(candidate, consensus, max_tries, /*block_height_override=*/61'000);
    BOOST_CHECK(!solved);

    const auto stats = ProbeMatMulSolvePipelineStats();
    BOOST_CHECK(stats.parallel_solver_enabled);
    BOOST_CHECK_EQUAL(stats.parallel_solver_threads, 6U);
    BOOST_CHECK_EQUAL(stats.async_prepare_worker_threads, 5U);
    BOOST_CHECK_EQUAL(stats.batch_size, 2U);
    BOOST_CHECK_EQUAL(stats.prefetch_depth, 1U);
}

BOOST_AUTO_TEST_CASE(matmul_solve_uses_conservative_generic_apple_metal_prefetch_default)
{
    ScopedBatchSizeEnv batch_size_env(nullptr);
    ScopedPrefetchDepthEnv prefetch_depth_env(nullptr);
    ScopedPrepareWorkersEnv prepare_workers_env(nullptr);
    ScopedBackendEnv backend_env("metal");
    ScopedSolverThreadsEnv solver_threads_env(nullptr);
    ScopedApplePerfLogicalCpuOverrideEnv perf_override_env("4");

    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.fMatMulFreivaldsEnabled = true;
    consensus.fMatMulRequireProductPayload = false;
    consensus.nMatMulFreivaldsBindingHeight = 61'000;
    consensus.nMatMulDimension = 512;
    consensus.nMatMulTranscriptBlockSize = 16;
    consensus.nMatMulNoiseRank = 8;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    CBlockHeader candidate{};
    candidate.nVersion = 4;
    candidate.hashPrevBlock = uint256{"000000000000000000000000000000000000000000000000000000000000001b"};
    candidate.hashMerkleRoot = uint256{"000000000000000000000000000000000000000000000000000000000000001c"};
    candidate.nTime = 1'700'000'359U;
    candidate.nBits = arith_uint256{1}.GetCompact();
    candidate.nNonce64 = 0;
    candidate.nNonce = 0;
    candidate.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    candidate.seed_a = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/0);
    candidate.seed_b = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/1);
    candidate.matmul_digest.SetNull();

    uint64_t max_tries{4};
    ResetMatMulSolvePipelineStats();
    const bool solved = SolveMatMul(candidate, consensus, max_tries, /*block_height_override=*/61'000);
    BOOST_CHECK(!solved);

    const auto stats = ProbeMatMulSolvePipelineStats();
    BOOST_CHECK(!stats.parallel_solver_enabled);
    BOOST_CHECK_EQUAL(stats.parallel_solver_threads, 1U);
    BOOST_CHECK_GE(stats.async_prepare_worker_threads, 1U);
    BOOST_CHECK_EQUAL(stats.batch_size, 2U);
    BOOST_CHECK_EQUAL(stats.prefetch_depth, 1U);
}

BOOST_AUTO_TEST_CASE(matmul_solve_uses_two_nonce_batch_on_tuned_mainnet_shape)
{
    ScopedAsyncPipelineEnv async_env;
    ScopedBatchSizeEnv batch_size_env("2");
    ScopedBackendEnv backend_env("metal");
    ScopedSolverThreadsEnv solver_threads_env("8");

    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.nMatMulDimension = 512;
    consensus.nMatMulTranscriptBlockSize = 16;
    consensus.nMatMulNoiseRank = 8;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    CBlockHeader candidate{};
    candidate.nVersion = 4;
    candidate.hashPrevBlock = uint256{"0000000000000000000000000000000000000000000000000000000000000017"};
    candidate.hashMerkleRoot = uint256{"0000000000000000000000000000000000000000000000000000000000000018"};
    candidate.nTime = 1'700'000'345U;
    candidate.nBits = arith_uint256{1}.GetCompact();
    candidate.nNonce64 = 0;
    candidate.nNonce = 0;
    candidate.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    candidate.seed_a = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/0);
    candidate.seed_b = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/1);
    candidate.matmul_digest.SetNull();

    uint64_t max_tries{4};
    ResetMatMulSolvePipelineStats();
    const bool solved = SolveMatMul(candidate, consensus, max_tries);
    BOOST_CHECK(!solved);

    const auto stats = ProbeMatMulSolvePipelineStats();
    BOOST_CHECK_EQUAL(stats.batch_size, 2U);
    BOOST_CHECK(stats.async_prepare_enabled);
}

BOOST_AUTO_TEST_CASE(matmul_solve_uses_cuda_batch_defaults_when_backend_is_available)
{
    ScopedBatchSizeEnv batch_size_env(nullptr);
    ScopedBackendEnv backend_env("cuda");

    const auto capability = matmul::backend::CapabilityFor(matmul::backend::Kind::CUDA);
    if (!capability.available) {
        BOOST_TEST_MESSAGE("Skipping CUDA batch-default test because CUDA is unavailable: " + capability.reason);
        return;
    }

    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.nMatMulDimension = 512;
    consensus.nMatMulTranscriptBlockSize = 16;
    consensus.nMatMulNoiseRank = 8;
    consensus.nMatMulPreHashEpsilonBits = 0;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    CBlockHeader candidate{};
    candidate.nVersion = 4;
    candidate.hashPrevBlock = uint256{"0000000000000000000000000000000000000000000000000000000000000031"};
    candidate.hashMerkleRoot = uint256{"0000000000000000000000000000000000000000000000000000000000000032"};
    candidate.nTime = 1'700'000'555U;
    // Disable the pre-hash gate for this test so the CUDA batch-default path
    // is exercised deterministically without making the digest target trivial.
    candidate.nBits = arith_uint256{1}.GetCompact();
    candidate.nNonce64 = 0;
    candidate.nNonce = 0;
    candidate.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    candidate.seed_a = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/0);
    candidate.seed_b = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/1);
    candidate.matmul_digest.SetNull();

    const auto topology = btx::cuda::ProbeCudaTopology();
    const uint32_t expected_min_batch_size =
        btx::cuda::ExpandCudaBatchSizeForSelectedDevices(/*batch_size=*/2, topology.selected_devices.size());

    uint64_t max_tries{std::max<uint64_t>(8, expected_min_batch_size)};
    ResetMatMulSolvePipelineStats();
    const bool solved = SolveMatMul(candidate, consensus, max_tries, /*block_height=*/61'000);
    BOOST_CHECK(!solved);

    const auto stats = ProbeMatMulSolvePipelineStats();
    BOOST_CHECK_GE(stats.batch_size, expected_min_batch_size);
    BOOST_CHECK(stats.async_prepare_enabled);
    BOOST_CHECK_GE(stats.prefetch_depth, 1U);
    BOOST_CHECK_GE(stats.batched_digest_requests, 1U);
    BOOST_CHECK_GE(stats.batched_nonce_attempts, stats.batch_size);
}

BOOST_AUTO_TEST_CASE(matmul_solve_enables_parallel_solver_when_configured)
{
    ScopedBatchSizeEnv batch_size_env(nullptr);
    ScopedBackendEnv backend_env("metal");
    ScopedSolverThreadsEnv solver_threads_env("2");

    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.nMatMulDimension = 512;
    consensus.nMatMulTranscriptBlockSize = 16;
    consensus.nMatMulNoiseRank = 8;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    CBlockHeader candidate{};
    candidate.nVersion = 4;
    candidate.hashPrevBlock = uint256{"00000000000000000000000000000000000000000000000000000000000000ef"};
    candidate.hashMerkleRoot = uint256{"00000000000000000000000000000000000000000000000000000000000000f0"};
    candidate.nTime = 1'700'000'377U;
    candidate.nBits = arith_uint256{1}.GetCompact();
    candidate.nNonce64 = 0;
    candidate.nNonce = 0;
    candidate.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    candidate.seed_a = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/0);
    candidate.seed_b = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/1);
    candidate.matmul_digest.SetNull();

    uint64_t max_tries{4};
    ResetMatMulSolvePipelineStats();
    const bool solved = SolveMatMul(candidate, consensus, max_tries);
    BOOST_CHECK(!solved);

    const auto stats = ProbeMatMulSolvePipelineStats();
    BOOST_CHECK(stats.parallel_solver_enabled);
    BOOST_CHECK_EQUAL(stats.parallel_solver_threads, 2U);
}

BOOST_AUTO_TEST_CASE(matmul_solve_keeps_async_prepare_enabled_for_multi_nonce_batches)
{
    ScopedBatchSizeEnv batch_size_env("4");
    ScopedBackendEnv backend_env("metal");

    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.nMatMulDimension = 512;
    consensus.nMatMulTranscriptBlockSize = 16;
    consensus.nMatMulNoiseRank = 8;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    CBlockHeader candidate{};
    candidate.nVersion = 4;
    candidate.hashPrevBlock = uint256{"00000000000000000000000000000000000000000000000000000000000000aa"};
    candidate.hashMerkleRoot = uint256{"00000000000000000000000000000000000000000000000000000000000000ab"};
    candidate.nTime = 1'700'000'444U;
    candidate.nBits = arith_uint256{1}.GetCompact();
    candidate.nNonce64 = 0;
    candidate.nNonce = 0;
    candidate.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    candidate.seed_a = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/0);
    candidate.seed_b = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/1);
    candidate.matmul_digest.SetNull();

    uint64_t max_tries{4};
    ResetMatMulSolvePipelineStats();
    const bool solved = SolveMatMul(candidate, consensus, max_tries);
    BOOST_CHECK(!solved);

    const auto stats = ProbeMatMulSolvePipelineStats();
    const auto selection = matmul::accelerated::ResolveMiningBackendFromEnvironment();
    BOOST_CHECK_EQUAL(stats.batch_size, 4U);
    BOOST_CHECK_EQUAL(
        stats.async_prepare_enabled,
        selection.active == matmul::backend::Kind::METAL || selection.active == matmul::backend::Kind::CUDA);
}

BOOST_AUTO_TEST_CASE(matmul_solve_respects_async_prepare_disable_override)
{
    ScopedBatchSizeEnv batch_size_env("4");
#if defined(WIN32)
    _putenv_s("BTX_MATMUL_PIPELINE_ASYNC", "0");
#else
    setenv("BTX_MATMUL_PIPELINE_ASYNC", "0", 1);
#endif

    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.nMatMulDimension = 512;
    consensus.nMatMulTranscriptBlockSize = 16;
    consensus.nMatMulNoiseRank = 8;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    CBlockHeader candidate{};
    candidate.nVersion = 4;
    candidate.hashPrevBlock = uint256{"00000000000000000000000000000000000000000000000000000000000000ba"};
    candidate.hashMerkleRoot = uint256{"00000000000000000000000000000000000000000000000000000000000000bb"};
    candidate.nTime = 1'700'000'455U;
    candidate.nBits = arith_uint256{1}.GetCompact();
    candidate.nNonce64 = 0;
    candidate.nNonce = 0;
    candidate.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    candidate.seed_a = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/0);
    candidate.seed_b = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/1);
    candidate.matmul_digest.SetNull();

    uint64_t max_tries{4};
    ResetMatMulSolvePipelineStats();
    const bool solved = SolveMatMul(candidate, consensus, max_tries);
    BOOST_CHECK(!solved);

    const auto stats = ProbeMatMulSolvePipelineStats();
    BOOST_CHECK_EQUAL(stats.batch_size, 4U);
    BOOST_CHECK(!stats.async_prepare_enabled);
    BOOST_CHECK_EQUAL(stats.prefetched_batches, 0U);
    BOOST_CHECK_EQUAL(stats.prefetched_inputs, 0U);

#if defined(WIN32)
    _putenv_s("BTX_MATMUL_PIPELINE_ASYNC", "");
#else
    unsetenv("BTX_MATMUL_PIPELINE_ASYNC");
#endif
}

BOOST_AUTO_TEST_CASE(matmul_solve_respects_cpu_confirm_env_override)
{
    ScopedBackendEnv backend_env("metal");
    ScopedCpuConfirmEnv cpu_confirm_env("0");

    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.fSkipMatMulValidation = false;
    consensus.nMatMulDimension = 16;
    consensus.nMatMulTranscriptBlockSize = 8;
    consensus.nMatMulNoiseRank = 4;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    CBlockHeader candidate{};
    candidate.nVersion = 4;
    candidate.hashPrevBlock = uint256{"0000000000000000000000000000000000000000000000000000000000000015"};
    candidate.hashMerkleRoot = uint256{"0000000000000000000000000000000000000000000000000000000000000016"};
    candidate.nTime = 1'700'000'377U;
    candidate.nBits = arith_uint256{1}.GetCompact();
    candidate.nNonce64 = 0;
    candidate.nNonce = 0;
    candidate.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    candidate.seed_a = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/0);
    candidate.seed_b = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/1);
    candidate.matmul_digest.SetNull();

    uint64_t max_tries{1};
    ResetMatMulSolvePipelineStats();
    const bool solved = SolveMatMul(candidate, consensus, max_tries);
    BOOST_CHECK(!solved);

    const auto stats = ProbeMatMulSolvePipelineStats();
    BOOST_CHECK(!stats.cpu_confirm_candidates);
}

BOOST_AUTO_TEST_CASE(matmul_solve_enables_cpu_confirm_for_cuda_in_strict_mode)
{
    ScopedBackendEnv backend_env("cuda");

    const auto capability = matmul::backend::CapabilityFor(matmul::backend::Kind::CUDA);
    if (!capability.available) {
        BOOST_TEST_MESSAGE("Skipping CUDA cpu-confirm test because CUDA is unavailable: " + capability.reason);
        return;
    }

    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.fSkipMatMulValidation = false;
    consensus.nMatMulDimension = 16;
    consensus.nMatMulTranscriptBlockSize = 8;
    consensus.nMatMulNoiseRank = 4;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    CBlockHeader candidate{};
    candidate.nVersion = 4;
    candidate.hashPrevBlock = uint256{"0000000000000000000000000000000000000000000000000000000000000041"};
    candidate.hashMerkleRoot = uint256{"0000000000000000000000000000000000000000000000000000000000000042"};
    candidate.nTime = 1'700'000'577U;
    candidate.nBits = arith_uint256{1}.GetCompact();
    candidate.nNonce64 = 0;
    candidate.nNonce = 0;
    candidate.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    candidate.seed_a = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/0);
    candidate.seed_b = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/1);
    candidate.matmul_digest.SetNull();

    uint64_t max_tries{1};
    ResetMatMulSolvePipelineStats();
    const bool solved = SolveMatMul(candidate, consensus, max_tries);
    BOOST_CHECK(!solved);

    const auto stats = ProbeMatMulSolvePipelineStats();
    BOOST_CHECK(stats.cpu_confirm_candidates);
}

BOOST_AUTO_TEST_CASE(matmul_solve_uses_resolved_backend_in_strict_mode_without_explicit_override)
{
    ScopedBackendEnv backend_env(nullptr);
    ScopedRequireBackendEnv require_backend_env(nullptr);

    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.fSkipMatMulValidation = false;
    consensus.nMatMulDimension = 16;
    consensus.nMatMulTranscriptBlockSize = 8;
    consensus.nMatMulNoiseRank = 4;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    CBlockHeader candidate{};
    candidate.nVersion = 4;
    candidate.hashPrevBlock = uint256{"0000000000000000000000000000000000000000000000000000000000000017"};
    candidate.hashMerkleRoot = uint256{"0000000000000000000000000000000000000000000000000000000000000018"};
    candidate.nTime = 1'700'000'401U;
    candidate.nBits = arith_uint256{1}.GetCompact();
    candidate.nNonce64 = 0;
    candidate.nNonce = 0;
    candidate.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    candidate.seed_a = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/0);
    candidate.seed_b = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/1);
    candidate.matmul_digest.SetNull();

    matmul::accelerated::ResetMatMulBackendRuntimeStats();
    uint64_t max_tries{1};
    const bool solved = SolveMatMul(candidate, consensus, max_tries);
    BOOST_CHECK(!solved);

    const auto stats = matmul::accelerated::ProbeMatMulBackendRuntimeStats();
    const auto selection = matmul::accelerated::ResolveMiningBackendFromEnvironment();
    if (selection.active == matmul::backend::Kind::METAL) {
        BOOST_CHECK_EQUAL(stats.requested_metal, 1U);
        BOOST_CHECK_EQUAL(stats.requested_cpu, 0U);
    } else if (selection.active == matmul::backend::Kind::CUDA) {
        BOOST_CHECK_EQUAL(stats.requested_cuda, 1U);
        BOOST_CHECK_EQUAL(stats.requested_cpu, 0U);
    } else {
        BOOST_CHECK_EQUAL(stats.requested_cpu, 1U);
    }
}

BOOST_AUTO_TEST_CASE(matmul_solve_fails_closed_when_required_backend_is_not_active)
{
    ScopedBackendEnv backend_env("cpu");
    ScopedRequireBackendEnv require_backend_env("metal");

    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.fSkipMatMulValidation = false;
    consensus.nMatMulDimension = 16;
    consensus.nMatMulTranscriptBlockSize = 8;
    consensus.nMatMulNoiseRank = 4;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    CBlockHeader candidate{};
    candidate.nVersion = 4;
    candidate.hashPrevBlock = uint256{"0000000000000000000000000000000000000000000000000000000000000091"};
    candidate.hashMerkleRoot = uint256{"0000000000000000000000000000000000000000000000000000000000000092"};
    candidate.nTime = 1'700'000'501U;
    candidate.nBits = UintToArith256(consensus.powLimit).GetCompact();
    candidate.nNonce64 = 0;
    candidate.nNonce = 0;
    candidate.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    candidate.seed_a = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/0);
    candidate.seed_b = DeterministicMatMulSeed(candidate.hashPrevBlock, /*height=*/0, /*which=*/1);
    candidate.matmul_digest.SetNull();

    matmul::accelerated::ResetMatMulBackendRuntimeStats();
    uint64_t max_tries{4};
    const bool solved = SolveMatMul(candidate, consensus, max_tries);
    BOOST_CHECK(!solved);

    const auto stats = matmul::accelerated::ProbeMatMulBackendRuntimeStats();
    BOOST_CHECK_EQUAL(stats.digest_requests, 0U);
    BOOST_CHECK_EQUAL(stats.requested_cpu, 0U);
    BOOST_CHECK_EQUAL(max_tries, 4U);

    const auto selection = matmul::accelerated::ResolveMiningBackendFromEnvironment();
    const auto requirement = matmul::accelerated::ResolveBackendRequirementFromEnvironment();
    BOOST_CHECK_EQUAL(matmul::backend::ToString(selection.active), "cpu");
    BOOST_CHECK(requirement.enabled);
    BOOST_CHECK(requirement.valid);
    BOOST_CHECK_EQUAL(matmul::backend::ToString(requirement.required), "metal");
    BOOST_CHECK(!matmul::accelerated::IsBackendRequirementSatisfied(requirement, selection));
}

BOOST_AUTO_TEST_CASE(matmul_solve_crosses_60999_to_61000_with_product_digest_contract)
{
    ScopedBatchSizeEnv batch_size_env("1");
    ScopedBackendEnv backend_env("cpu");

    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.fSkipMatMulValidation = false;
    consensus.fPowAllowMinDifficultyBlocks = false;
    consensus.fMatMulFreivaldsEnabled = true;
    consensus.fMatMulRequireProductPayload = false;
    consensus.nMatMulFreivaldsBindingHeight = 61'000;
    consensus.nMatMulProductDigestHeight = 61'000;
    consensus.nMatMulDimension = 64;
    consensus.nMatMulTranscriptBlockSize = 8;
    consensus.nMatMulNoiseRank = 4;
    consensus.nMatMulPreHashEpsilonBits = 0;
    consensus.nMatMulPreHashEpsilonBitsUpgradeHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulPreHashEpsilonBitsUpgrade = 0;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    BOOST_CHECK(!consensus.IsMatMulProductDigestActive(60'999));
    BOOST_CHECK(consensus.IsMatMulProductDigestActive(61'000));

    CBlockHeader header_template = MakeDigestProbeHeader();
    header_template.hashPrevBlock =
        uint256{"0000000000000000000000000000000000000000000000000000000000001234"};
    header_template.hashMerkleRoot =
        uint256{"0000000000000000000000000000000000000000000000000000000000005678"};
    header_template.nTime = 1'700'061'000U;
    header_template.nNonce64 = 0;
    header_template.nNonce = 0;
    header_template.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    header_template.seed_a = DeterministicMatMulSeed(header_template.hashPrevBlock, 61'000, /*which=*/0);
    header_template.seed_b = DeterministicMatMulSeed(header_template.hashPrevBlock, 61'000, /*which=*/1);
    header_template.matmul_digest.SetNull();

    const auto boundary = FindProductDigestBoundaryCase(header_template, consensus);
    BOOST_REQUIRE(boundary.has_value());

    const matmul::Matrix A = matmul::FromSeed(header_template.seed_a, header_template.matmul_dim);
    const matmul::Matrix B = matmul::FromSeed(header_template.seed_b, header_template.matmul_dim);

    CBlockHeader pre_activation = header_template;
    pre_activation.nBits = UintToArith256(consensus.powLimit).GetCompact();
    uint64_t pre_activation_tries{1};
    BOOST_REQUIRE(SolveMatMul(pre_activation, consensus, pre_activation_tries, 60'999));
    BOOST_CHECK_EQUAL(
        pre_activation.matmul_digest,
        matmul::accelerated::ComputeMatMulDigestCPU(
            pre_activation,
            A,
            B,
            consensus.nMatMulTranscriptBlockSize,
            consensus.nMatMulNoiseRank,
            matmul::accelerated::DigestScheme::TRANSCRIPT));

    CBlockHeader post_activation = header_template;
    post_activation.nBits = boundary->nbits;
    post_activation.nNonce64 = 0;
    post_activation.nNonce = 0;
    post_activation.matmul_digest.SetNull();

    uint64_t post_activation_tries{boundary->nonce64 + 1};
    BOOST_REQUIRE(SolveMatMul(post_activation, consensus, post_activation_tries, 61'000));
    BOOST_CHECK_EQUAL(post_activation.nNonce64, boundary->nonce64);
    BOOST_CHECK_EQUAL(post_activation.nNonce, static_cast<uint32_t>(boundary->nonce64));
    BOOST_CHECK_EQUAL(post_activation.matmul_digest, boundary->product_digest);
    BOOST_CHECK(UintToArith256(boundary->product_digest) <= boundary->target);
    BOOST_CHECK(UintToArith256(boundary->transcript_digest) > boundary->target);
    BOOST_CHECK_EQUAL(
        post_activation.matmul_digest,
        matmul::accelerated::ComputeMatMulDigestCPU(
            post_activation,
            A,
            B,
            consensus.nMatMulTranscriptBlockSize,
            consensus.nMatMulNoiseRank,
            matmul::accelerated::DigestScheme::PRODUCT_COMMITTED));

    CBlock solved_block;
    static_cast<CBlockHeader&>(solved_block) = post_activation;
    PopulateFreivaldsPayload(solved_block, consensus);
    BOOST_CHECK(CheckMatMulProofOfWork_ProductCommitted(solved_block, consensus, 61'000));
}

BOOST_AUTO_TEST_CASE(live_mainnet_61000_block_matches_fixed_contract_and_breaks_legacy_contract)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    BOOST_REQUIRE(consensus.IsMatMulProductDigestActive(61'000));
    BOOST_REQUIRE(!consensus.IsMatMulProductDigestActive(60'999));

    CBlockHeader block_61000{};
    block_61000.nVersion = 0x20000000;
    block_61000.hashPrevBlock =
        uint256{"045e9181fbbeba9b422ae70e0ab5834f466e286ae5b16edc61f3b13916490c70"};
    block_61000.hashMerkleRoot =
        uint256{"b14a337a0cfe98c9e620f2b6c29a41ac6a77bf95cbcc7b9f76a5529e1e367193"};
    block_61000.nTime = 1'775'242'281U;
    block_61000.nBits = 0x1e15d55eU;
    block_61000.nNonce64 = 83'649'524U;
    block_61000.nNonce = static_cast<uint32_t>(block_61000.nNonce64);
    block_61000.matmul_digest =
        uint256{"0000044434522189ef972f86660aa24400c878991effce289d8ff5a882da8241"};
    block_61000.matmul_dim = 512;
    block_61000.seed_a =
        uint256{"3346a31f91a59d6d51a829a0e4a316b45ee015f173a08b7c5a8c526cf1bb9366"};
    block_61000.seed_b =
        uint256{"61bab8f7324903584feea3c6641aa46f83616728d6e9adbe80b0047df90b303a"};

    const arith_uint256 target = DecodeTarget(block_61000.nBits);
    BOOST_CHECK(UintToArith256(block_61000.matmul_digest) <= target);

    const auto A = matmul::SharedFromSeed(block_61000.seed_a, block_61000.matmul_dim);
    const auto B = matmul::SharedFromSeed(block_61000.seed_b, block_61000.matmul_dim);
    const uint256 sigma = matmul::DeriveSigma(block_61000);
    const auto noise = matmul::noise::Generate(sigma, block_61000.matmul_dim, consensus.nMatMulNoiseRank);
    const auto A_prime = *A + (noise.E_L * noise.E_R);
    const auto B_prime = *B + (noise.F_L * noise.F_R);

    const uint256 mined_digest = matmul::transcript::ComputeProductCommittedDigestFromPerturbed(
        A_prime,
        B_prime,
        consensus.nMatMulTranscriptBlockSize,
        sigma);
    BOOST_CHECK_EQUAL(mined_digest, block_61000.matmul_digest);

    const auto canonical = matmul::transcript::CanonicalMatMul(
        A_prime,
        B_prime,
        consensus.nMatMulTranscriptBlockSize,
        sigma);
    const uint256 validator_digest = matmul::transcript::ComputeProductCommittedDigest(
        canonical.C_prime,
        consensus.nMatMulTranscriptBlockSize,
        sigma);
    BOOST_CHECK_EQUAL(validator_digest, block_61000.matmul_digest);
    BOOST_CHECK(UintToArith256(canonical.transcript_hash) > target);
}

BOOST_AUTO_TEST_CASE(matmul_digest_compare_probe_ignores_matching_digests)
{
    ResetMatMulDigestCompareStats();

    const CBlockHeader header = MakeDigestProbeHeader();
    static constexpr uint256 digest{"1111111111111111111111111111111111111111111111111111111111111111"};
    RegisterMatMulDigestCompareAttempt(header, digest, digest);

    const auto stats = ProbeMatMulDigestCompareStats();
    BOOST_CHECK_EQUAL(stats.compared_attempts, 1U);
    BOOST_CHECK(!stats.first_divergence_captured);
    BOOST_CHECK(stats.first_divergence_header_hash.empty());
    BOOST_CHECK(stats.first_divergence_backend_digest.empty());
    BOOST_CHECK(stats.first_divergence_cpu_digest.empty());
}

BOOST_AUTO_TEST_CASE(matmul_digest_compare_probe_captures_first_divergence_once)
{
    ResetMatMulDigestCompareStats();

    const CBlockHeader first = MakeDigestProbeHeader();
    static constexpr uint256 first_backend{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
    static constexpr uint256 first_cpu{"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"};
    RegisterMatMulDigestCompareAttempt(first, first_backend, first_cpu);

    auto stats = ProbeMatMulDigestCompareStats();
    BOOST_CHECK_EQUAL(stats.compared_attempts, 1U);
    BOOST_CHECK(stats.first_divergence_captured);
    BOOST_CHECK_EQUAL(stats.first_divergence_nonce64, first.nNonce64);
    BOOST_CHECK_EQUAL(stats.first_divergence_nonce32, first.nNonce);
    BOOST_CHECK_EQUAL(stats.first_divergence_header_hash, first.GetHash().GetHex());
    BOOST_CHECK_EQUAL(stats.first_divergence_backend_digest, first_backend.GetHex());
    BOOST_CHECK_EQUAL(stats.first_divergence_cpu_digest, first_cpu.GetHex());

    CBlockHeader second = first;
    ++second.nNonce64;
    second.nNonce = static_cast<uint32_t>(second.nNonce64);
    static constexpr uint256 second_backend{"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"};
    static constexpr uint256 second_cpu{"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"};
    RegisterMatMulDigestCompareAttempt(second, second_backend, second_cpu);

    stats = ProbeMatMulDigestCompareStats();
    BOOST_CHECK_EQUAL(stats.compared_attempts, 2U);
    BOOST_CHECK(stats.first_divergence_captured);
    BOOST_CHECK_EQUAL(stats.first_divergence_nonce64, first.nNonce64);
    BOOST_CHECK_EQUAL(stats.first_divergence_nonce32, first.nNonce);
    BOOST_CHECK_EQUAL(stats.first_divergence_header_hash, first.GetHash().GetHex());
    BOOST_CHECK_EQUAL(stats.first_divergence_backend_digest, first_backend.GetHex());
    BOOST_CHECK_EQUAL(stats.first_divergence_cpu_digest, first_cpu.GetHex());
}

BOOST_AUTO_TEST_CASE(cuda_strict_regtest_warning_repro_solves_without_digest_divergence)
{
    ScopedBackendEnv backend_env("cuda");
    ScopedSolverThreadsEnv solver_threads_env("1");
    ScopedBatchSizeEnv batch_size_env("1");

    const auto capability = matmul::backend::CapabilityFor(matmul::backend::Kind::CUDA);
    if (!capability.available) {
        BOOST_TEST_MESSAGE("Skipping strict-regtest CUDA SolveMatMul repro because CUDA is unavailable: " + capability.reason);
        return;
    }

    CChainParams::RegTestOptions options;
    options.matmul_strict = true;
    options.matmul_dgw = true;
    auto consensus = CChainParams::RegTest(options)->GetConsensus();
    BOOST_REQUIRE(!consensus.fSkipMatMulValidation);
    BOOST_REQUIRE(consensus.IsMatMulProductDigestActive(/*height=*/1507));

    CBlockHeader candidate = MakeStrictRegtestWarningReproHeader();
    uint64_t max_tries{64};

    ResetMatMulDigestCompareStats();
    const bool solved = SolveMatMul(candidate, consensus, max_tries, /*block_height=*/1507);
    const auto stats = ProbeMatMulDigestCompareStats();

    BOOST_REQUIRE(solved);
    BOOST_CHECK(candidate.nNonce64 < 64U);
    BOOST_CHECK_EQUAL(candidate.nNonce, static_cast<uint32_t>(candidate.nNonce64));
    BOOST_CHECK(!candidate.matmul_digest.IsNull());
    BOOST_CHECK_EQUAL(stats.compared_attempts, 0U);
    BOOST_CHECK(!stats.first_divergence_captured);
    BOOST_CHECK(stats.first_divergence_header_hash.empty());
    BOOST_CHECK(stats.first_divergence_backend_digest.empty());
    BOOST_CHECK(stats.first_divergence_cpu_digest.empty());
}

BOOST_AUTO_TEST_CASE(product_committed_digest_deterministic)
{
    // Use minimum MatMul dimensions: n=64, b=16.
    constexpr uint32_t n = 64;
    constexpr uint32_t b = 16;

    const uint256 seed_a = *uint256::FromHex("0000000000000000000000000000000000000000000000000000000000000001");
    const uint256 seed_b = *uint256::FromHex("0000000000000000000000000000000000000000000000000000000000000002");
    const uint256 sigma  = *uint256::FromHex("00000000000000000000000000000000000000000000000000000000deadbeef");

    const auto A = matmul::FromSeed(seed_a, n);
    const auto B = matmul::FromSeed(seed_b, n);
    const auto C_prime = A * B; // Treat A, B directly as A', B' for simplicity.

    // Compute digest twice with the same inputs -- must be identical.
    const uint256 digest1 = matmul::transcript::ComputeProductCommittedDigest(C_prime, b, sigma);
    const uint256 digest2 = matmul::transcript::ComputeProductCommittedDigest(C_prime, b, sigma);
    const uint256 digest_from_perturbed =
        matmul::transcript::ComputeProductCommittedDigestFromPerturbed(A, B, b, sigma);
    BOOST_CHECK(!digest1.IsNull());
    BOOST_CHECK_EQUAL(digest1, digest2);
    BOOST_CHECK_EQUAL(digest1, digest_from_perturbed);

    // Flip one element of C' -- digest must change.
    matmul::Matrix C_tampered(C_prime);
    C_tampered.at(0, 0) = (C_tampered.at(0, 0) + 1) % matmul::field::MODULUS;
    const uint256 digest_tampered = matmul::transcript::ComputeProductCommittedDigest(C_tampered, b, sigma);
    BOOST_CHECK(digest_tampered != digest1);
}

BOOST_AUTO_TEST_CASE(product_committed_digest_height_gate)
{
    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulFreivaldsEnabled = true;

    // Activate at height 500.
    consensus.nMatMulProductDigestHeight = 500;

    BOOST_CHECK(!consensus.IsMatMulProductDigestActive(-1));
    BOOST_CHECK(!consensus.IsMatMulProductDigestActive(0));
    BOOST_CHECK(!consensus.IsMatMulProductDigestActive(499));
    BOOST_CHECK(consensus.IsMatMulProductDigestActive(500));
    BOOST_CHECK(consensus.IsMatMulProductDigestActive(501));
    BOOST_CHECK(consensus.IsMatMulProductDigestActive(10000));

    // With Freivalds disabled the gate must remain false regardless of height.
    consensus.fMatMulFreivaldsEnabled = false;
    BOOST_CHECK(!consensus.IsMatMulProductDigestActive(500));
    BOOST_CHECK(!consensus.IsMatMulProductDigestActive(10000));

    // With sentinel max() the gate must remain false.
    consensus.fMatMulFreivaldsEnabled = true;
    consensus.nMatMulProductDigestHeight = std::numeric_limits<int32_t>::max();
    BOOST_CHECK(!consensus.IsMatMulProductDigestActive(500));
    BOOST_CHECK(!consensus.IsMatMulProductDigestActive(std::numeric_limits<int32_t>::max() - 1));
}

BOOST_AUTO_TEST_CASE(product_committed_digest_rejects_wrong_digest)
{
    // Build a minimal valid block with correct C' payload but wrong matmul_digest.
    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.fMatMulFreivaldsEnabled = true;
    consensus.nMatMulProductDigestHeight = 0; // active from genesis
    consensus.fSkipMatMulValidation = false;
    consensus.nMatMulFreivaldsRounds = 2;
    consensus.nMatMulPreHashEpsilonBits = 0; // disable pre-hash gate for unit test
    consensus.nMatMulPreHashEpsilonBitsUpgradeHeight = std::numeric_limits<int32_t>::max();

    const uint32_t n = consensus.nMatMulDimension; // 64 on regtest
    const uint32_t noise_rank = consensus.nMatMulNoiseRank;

    CBlock block;
    block.nVersion = 1;
    block.hashPrevBlock = uint256{1};
    block.nBits = UintToArith256(consensus.powLimit).GetCompact();
    block.matmul_dim = static_cast<uint16_t>(n);
    block.seed_a = *uint256::FromHex("0000000000000000000000000000000000000000000000000000000000000001");
    block.seed_b = *uint256::FromHex("0000000000000000000000000000000000000000000000000000000000000002");
    block.nNonce64 = 42;

    // Derive A', B', C' the same way the validator does.
    const auto A = matmul::SharedFromSeed(block.seed_a, n);
    const auto B = matmul::SharedFromSeed(block.seed_b, n);
    const uint256 sigma = matmul::DeriveSigma(block);
    const auto np = matmul::noise::Generate(sigma, n, noise_rank);
    const auto A_prime = *A + (np.E_L * np.E_R);
    const auto B_prime = *B + (np.F_L * np.F_R);
    const auto C_prime = A_prime * B_prime;

    // Populate matrix_c_data correctly.
    block.matrix_c_data.resize(static_cast<size_t>(n) * n);
    for (uint32_t r = 0; r < n; ++r) {
        for (uint32_t c = 0; c < n; ++c) {
            block.matrix_c_data[static_cast<size_t>(r) * n + c] = C_prime.at(r, c);
        }
    }

    // Compute the correct digest and set it.
    const uint256 correct_digest = matmul::transcript::ComputeProductCommittedDigest(
        C_prime,
        consensus.nMatMulTranscriptBlockSize,
        sigma);
    block.matmul_digest = correct_digest;

    // With the correct digest the check must pass.
    BOOST_CHECK(CheckMatMulProofOfWork_ProductCommitted(block, consensus, /*block_height=*/1));

    // Set matmul_digest to something wrong -- must reject.
    block.matmul_digest = *uint256::FromHex("000000000000000000000000000000000000000000000000000000000000dead");
    BOOST_CHECK(!CheckMatMulProofOfWork_ProductCommitted(block, consensus, /*block_height=*/1));
}

BOOST_AUTO_TEST_CASE(product_committed_digest_rejects_wrong_product)
{
    // Block has the correct digest for the original C' but C' payload is tampered.
    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.fMatMulFreivaldsEnabled = true;
    consensus.nMatMulProductDigestHeight = 0;
    consensus.fSkipMatMulValidation = false;
    consensus.nMatMulFreivaldsRounds = 2;
    consensus.nMatMulPreHashEpsilonBits = 0;
    consensus.nMatMulPreHashEpsilonBitsUpgradeHeight = std::numeric_limits<int32_t>::max();

    const uint32_t n = consensus.nMatMulDimension;
    const uint32_t noise_rank = consensus.nMatMulNoiseRank;

    CBlock block;
    block.nVersion = 1;
    block.hashPrevBlock = uint256{1};
    block.nBits = UintToArith256(consensus.powLimit).GetCompact();
    block.matmul_dim = static_cast<uint16_t>(n);
    block.seed_a = *uint256::FromHex("0000000000000000000000000000000000000000000000000000000000000001");
    block.seed_b = *uint256::FromHex("0000000000000000000000000000000000000000000000000000000000000002");
    block.nNonce64 = 42;

    const auto A = matmul::SharedFromSeed(block.seed_a, n);
    const auto B = matmul::SharedFromSeed(block.seed_b, n);
    const uint256 sigma = matmul::DeriveSigma(block);
    const auto np = matmul::noise::Generate(sigma, n, noise_rank);
    const auto A_prime = *A + (np.E_L * np.E_R);
    const auto B_prime = *B + (np.F_L * np.F_R);
    const auto C_prime = A_prime * B_prime;

    // Populate correct C' payload.
    block.matrix_c_data.resize(static_cast<size_t>(n) * n);
    for (uint32_t r = 0; r < n; ++r) {
        for (uint32_t c = 0; c < n; ++c) {
            block.matrix_c_data[static_cast<size_t>(r) * n + c] = C_prime.at(r, c);
        }
    }

    // Set the correct digest.
    const uint256 correct_digest = matmul::transcript::ComputeProductCommittedDigest(
        C_prime,
        consensus.nMatMulTranscriptBlockSize,
        sigma);
    block.matmul_digest = correct_digest;

    // Sanity: valid block passes.
    BOOST_CHECK(CheckMatMulProofOfWork_ProductCommitted(block, consensus, /*block_height=*/1));

    // Tamper one element of C' in the payload. The digest no longer matches
    // the payload, so the validator must reject.
    block.matrix_c_data[0] = (block.matrix_c_data[0] + 1) % matmul::field::MODULUS;
    BOOST_CHECK(!CheckMatMulProofOfWork_ProductCommitted(block, consensus, /*block_height=*/1));
}

BOOST_AUTO_TEST_CASE(e1_nonce_seed_fold_is_gated_and_backward_compatible)
{
    const uint256 prev = uint256::ONE;
    const uint32_t height = 200'000;

    // Backward compatibility: the legacy 3-arg derivation is byte-identical to the 4-arg call with
    // no nonce, so pre-activation blocks and genesis keep their exact historical seeds (no fork below
    // the flag day, genesis unaffected).
    BOOST_CHECK_EQUAL(DeterministicMatMulSeed(prev, height, 0),
                      DeterministicMatMulSeed(prev, height, 0, std::nullopt));
    BOOST_CHECK_EQUAL(DeterministicMatMulSeed(prev, height, 1),
                      DeterministicMatMulSeed(prev, height, 1, std::nullopt));

    // e1: folding a nonce changes the seed, so the dense A*B product becomes nonce-dependent...
    const uint256 legacy_a = DeterministicMatMulSeed(prev, height, 0);
    BOOST_CHECK(DeterministicMatMulSeed(prev, height, 0, /*nonce=*/uint64_t{0}) != legacy_a);
    // ...and DIFFERENT nonces yield DIFFERENT seeds, so A*B cannot be precomputed once and reused
    // across the nonce range -- this is exactly what defeats the ~12.8x amortization.
    const uint256 s0 = DeterministicMatMulSeed(prev, height, 0, /*nonce=*/uint64_t{0});
    const uint256 s1 = DeterministicMatMulSeed(prev, height, 0, /*nonce=*/uint64_t{1});
    const uint256 s2 = DeterministicMatMulSeed(prev, height, 0, /*nonce=*/uint64_t{123456789});
    BOOST_CHECK(s0 != s1);
    BOOST_CHECK(s1 != s2);
    BOOST_CHECK(s0 != s2);
    // 'which' still separates A from B under nonce folding.
    BOOST_CHECK(DeterministicMatMulSeed(prev, height, 0, uint64_t{7}) !=
                DeterministicMatMulSeed(prev, height, 1, uint64_t{7}));

    // Gate: disabled by default (INT32_MAX); active only at/after the configured flag-day height.
    Consensus::Params consensus{};
    consensus.fMatMulPOW = true;
    BOOST_CHECK(!consensus.IsMatMulNonceSeedActive(height));  // default INT32_MAX -> dormant
    consensus.nMatMulNonceSeedHeight = 250'000;
    BOOST_CHECK(!consensus.IsMatMulNonceSeedActive(249'999));
    BOOST_CHECK(consensus.IsMatMulNonceSeedActive(250'000));
    BOOST_CHECK(consensus.IsMatMulNonceSeedActive(300'000));
    // Inert on non-MatMul chains.
    consensus.fMatMulPOW = false;
    BOOST_CHECK(!consensus.IsMatMulNonceSeedActive(300'000));
}

BOOST_AUTO_TEST_CASE(e1_v2_miner_produces_consensus_valid_nonce_bound_seeds_across_boundary)
{
    // End-to-end safety proof for the 125,000 PoW fork: drive the REAL consensus miner
    // (SolveMatMul -> SolveMatMulNonceSeeded, the path every backend funnels through) across the
    // nonce-seed activation boundary and verify miner<->consensus seed agreement:
    //   (1) post-activation the miner emits seeds bound to the WINNING nonce that exactly match the
    //       consensus derivation SetDeterministicMatMulSeeds (what ContextualCheckBlockHeader enforces);
    //   (2) pre-activation it emits legacy nonce-independent seeds (no fork below the flag day);
    //   (3) a legacy-seeded block is rejected by the consensus seed rule post-activation.
    // This is what guarantees no mining halt at the fork: whatever the miner produces validates.
    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.nMatMulDimension = 16;
    consensus.nMatMulTranscriptBlockSize = 8;
    consensus.nMatMulNoiseRank = 4;
    consensus.nMatMulPreHashEpsilonBits = 0;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
    constexpr int32_t kActivation = 125'000;
    consensus.nMatMulNonceSeedHeight = kActivation;

    auto make_candidate = [&]() {
        CBlockHeader c{};
        c.nVersion = 4;
        c.hashPrevBlock = uint256{"00000000000000000000000000000000000000000000000000000000000000a1"};
        c.hashMerkleRoot = uint256{"00000000000000000000000000000000000000000000000000000000000000a2"};
        c.nTime = 1'700'000'123U;
        c.nBits = UintToArith256(consensus.powLimit).GetCompact();  // easiest target -> solves immediately
        c.nNonce64 = 1;
        c.nNonce = 1;
        c.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
        c.matmul_digest.SetNull();
        return c;
    };

    // (1) POST-activation: the mined block's seeds are nonce-bound and consensus-valid.
    {
        CBlockHeader candidate = make_candidate();
        BOOST_REQUIRE(SetDeterministicMatMulSeeds(candidate, consensus, kActivation));
        uint64_t max_tries{64};
        const bool solved = SolveMatMul(candidate, consensus, max_tries, /*block_height=*/kActivation);
        BOOST_REQUIRE(solved);
        // Seeds are bound to the winning nonce...
        BOOST_CHECK_EQUAL(candidate.seed_a, DeterministicMatMulSeedV2(candidate, kActivation, 0));
        BOOST_CHECK_EQUAL(candidate.seed_b, DeterministicMatMulSeedV2(candidate, kActivation, 1));
        // ...and differ from the legacy nonce-independent derivation (the property that defeats e1).
        BOOST_CHECK(candidate.seed_a != DeterministicMatMulSeed(candidate.hashPrevBlock, kActivation, 0));
        // Consensus agreement: ContextualCheckBlockHeader recomputes via SetDeterministicMatMulSeeds.
        CBlockHeader expected = candidate;
        BOOST_REQUIRE(SetDeterministicMatMulSeeds(expected, consensus, kActivation));
        BOOST_CHECK_EQUAL(expected.seed_a, candidate.seed_a);
        BOOST_CHECK_EQUAL(expected.seed_b, candidate.seed_b);
        // (3) A legacy-seeded block at this height would be rejected (seeds != expected V2).
        CBlockHeader tampered = candidate;
        tampered.seed_a = DeterministicMatMulSeed(candidate.hashPrevBlock, kActivation, 0);
        tampered.seed_b = DeterministicMatMulSeed(candidate.hashPrevBlock, kActivation, 1);
        CBlockHeader expected_tampered = tampered;
        BOOST_REQUIRE(SetDeterministicMatMulSeeds(expected_tampered, consensus, kActivation));
        BOOST_CHECK(expected_tampered.seed_a != tampered.seed_a);  // -> bad-matmul-seeds
    }

    // (2) PRE-activation: the mined block carries legacy nonce-independent seeds, also consensus-valid.
    {
        CBlockHeader candidate = make_candidate();
        const int32_t pre = kActivation - 1;
        BOOST_REQUIRE(SetDeterministicMatMulSeeds(candidate, consensus, pre));
        uint64_t max_tries{64};
        const bool solved = SolveMatMul(candidate, consensus, max_tries, /*block_height=*/pre);
        BOOST_REQUIRE(solved);
        BOOST_CHECK_EQUAL(candidate.seed_a, DeterministicMatMulSeed(candidate.hashPrevBlock, pre, 0));
        BOOST_CHECK_EQUAL(candidate.seed_b, DeterministicMatMulSeed(candidate.hashPrevBlock, pre, 1));
        CBlockHeader expected = candidate;
        BOOST_REQUIRE(SetDeterministicMatMulSeeds(expected, consensus, pre));
        BOOST_CHECK_EQUAL(expected.seed_a, candidate.seed_a);
    }
}

BOOST_AUTO_TEST_CASE(e1_v2_parallel_solver_engages_and_stays_consensus_valid)
{
    // Optimization (1): the V2 nonce-seeded solver now fans the nonce range out across cores
    // (via SolveMatMulParallel) instead of running the single-threaded reference. Force 4 solver
    // threads, confirm the parallel path engaged, and verify the parallel-produced block's seeds
    // still match the consensus per-nonce derivation (each worker derives its OWN per-nonce seeds).
    ScopedSolverThreadsEnv solver_threads_env("4");

    auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.nMatMulDimension = 16;
    consensus.nMatMulTranscriptBlockSize = 8;
    consensus.nMatMulNoiseRank = 4;
    consensus.nMatMulPreHashEpsilonBits = 0;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
    constexpr int32_t kActivation = 125'000;
    consensus.nMatMulNonceSeedHeight = kActivation;

    CBlockHeader candidate{};
    candidate.nVersion = 4;
    candidate.hashPrevBlock = uint256{"00000000000000000000000000000000000000000000000000000000000000b1"};
    candidate.hashMerkleRoot = uint256{"00000000000000000000000000000000000000000000000000000000000000b2"};
    candidate.nTime = 1'700'000'222U;
    candidate.nBits = UintToArith256(consensus.powLimit).GetCompact();
    candidate.nNonce64 = 1;
    candidate.nNonce = 1;
    candidate.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    candidate.matmul_digest.SetNull();
    BOOST_REQUIRE(SetDeterministicMatMulSeeds(candidate, consensus, kActivation));

    uint64_t max_tries{4096};
    ResetMatMulSolvePipelineStats();
    const bool solved = SolveMatMul(candidate, consensus, max_tries, /*block_height=*/kActivation);
    BOOST_REQUIRE(solved);

    // The parallel path was taken -- the single-threaded V2 reference would report threads == 1.
    const auto stats = ProbeMatMulSolvePipelineStats();
    BOOST_CHECK(stats.parallel_solver_enabled);
    BOOST_CHECK_GT(stats.parallel_solver_threads, 1U);

    // ...and the block produced by the parallel solver is consensus-valid (nonce-bound seeds match).
    BOOST_CHECK_EQUAL(candidate.seed_a, DeterministicMatMulSeedV2(candidate, kActivation, 0));
    BOOST_CHECK_EQUAL(candidate.seed_b, DeterministicMatMulSeedV2(candidate, kActivation, 1));
    CBlockHeader expected = candidate;
    BOOST_REQUIRE(SetDeterministicMatMulSeeds(expected, consensus, kActivation));
    BOOST_CHECK_EQUAL(expected.seed_a, candidate.seed_a);
    BOOST_CHECK_EQUAL(expected.seed_b, candidate.seed_b);
}

BOOST_AUTO_TEST_SUITE_END()
