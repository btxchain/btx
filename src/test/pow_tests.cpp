// Copyright (c) 2015-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <common/args.h>
#include <matmul/accelerated_solver.h>
#include <matmul/freivalds.h>
#include <matmul/matmul_pow.h>
#include <matmul/matrix.h>
#include <matmul/noise.h>
#include <matmul/transcript.h>
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
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET4_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::TESTNET4);
}

BOOST_AUTO_TEST_CASE(ChainParams_SIGNET_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::SIGNET);
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
    BOOST_CHECK_EQUAL(consensus.nMatMulPreHashEpsilonBits, 10U);
    BOOST_CHECK_EQUAL(consensus.nMatMulPreHashEpsilonBitsUpgradeHeight, 50'000);
    BOOST_CHECK_EQUAL(consensus.nMatMulPreHashEpsilonBitsUpgrade, 18U);
    BOOST_CHECK_EQUAL(GetMatMulPreHashEpsilonBitsForHeight(consensus, 49'999), 10U);
    BOOST_CHECK_EQUAL(GetMatMulPreHashEpsilonBitsForHeight(consensus, 50'000), 18U);
    BOOST_CHECK_EQUAL(GetMatMulPreHashEpsilonBitsForHeight(consensus, 50'001), 18U);
    BOOST_CHECK_EQUAL(UintToArith256(consensus.powLimit).GetCompact(), 0x2066c154U);
    // Guard: powLimit must retain compact headroom above genesis bits, otherwise
    // fast-phase difficulty scaling is silently clamped out.
    BOOST_CHECK_GT(UintToArith256(consensus.powLimit).GetCompact(), 0x20147ae1U);
    BOOST_CHECK_EQUAL(consensus.nMatMulDimension, 512U);
    BOOST_CHECK_EQUAL(consensus.nMatMulTranscriptBlockSize, 16U);
    BOOST_CHECK_EQUAL(consensus.nMatMulNoiseRank, 8U);
    BOOST_CHECK_EQUAL(consensus.nMatMulPhase2FailBanThreshold, 1U);
    BOOST_CHECK_EQUAL(consensus.nMaxReorgDepth, 144U);
    BOOST_CHECK_EQUAL(consensus.nReorgProtectionStartHeight, 61'000);
    BOOST_CHECK_EQUAL(consensus.nMatMulFreivaldsBindingHeight, 61'000);
    BOOST_CHECK_EQUAL(consensus.nMatMulProductDigestHeight, 61'000);
    BOOST_CHECK_EQUAL(consensus.nShieldedTxBindingActivationHeight, 61'000);
    BOOST_CHECK_EQUAL(consensus.nShieldedBridgeTagActivationHeight, 61'000);
    BOOST_CHECK_EQUAL(consensus.nShieldedSmileRiceCodecDisableHeight, 61'000);
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
        "0000000000000000000000000000000000000000000000000000000278daaa26");
    BOOST_CHECK_EQUAL(
        consensus.defaultAssumeValid.GetHex(),
        "d58f6755e52467ed624dfcd0be4e8ee0731b8e7525e8dc4cf9482879d0dfe3f8");
    BOOST_CHECK_EQUAL(params->AssumedBlockchainSize(), 16U);
    BOOST_CHECK_EQUAL(params->AssumedChainStateSize(), 1U);

    const auto& checkpoints = params->Checkpoints().mapCheckpoints;
    BOOST_REQUIRE_GE(checkpoints.size(), 2U);
    const auto it_0 = checkpoints.find(0);
    BOOST_REQUIRE(it_0 != checkpoints.end());
    BOOST_CHECK_EQUAL(
        it_0->second.GetHex(),
        "75a998a39d2d6e25a9ca7de2cc659309c4105839c06cd435ba2b1aabf0fa4601");
    const auto it_anchor = checkpoints.find(71433);
    BOOST_REQUIRE(it_anchor != checkpoints.end());
    BOOST_CHECK_EQUAL(
        it_anchor->second.GetHex(),
        "d58f6755e52467ed624dfcd0be4e8ee0731b8e7525e8dc4cf9482879d0dfe3f8");

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

    const auto snapshot_heights = params->GetAvailableSnapshotHeights();
    BOOST_REQUIRE_EQUAL(snapshot_heights.size(), 5U);
    BOOST_CHECK(std::is_sorted(snapshot_heights.begin(), snapshot_heights.end()));
    BOOST_CHECK_EQUAL(snapshot_heights.front(), 55000);
    BOOST_CHECK_EQUAL(snapshot_heights.back(), 71435);
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

BOOST_AUTO_TEST_CASE(matmul_solve_uses_multi_nonce_batch_for_post_activation_mainnet_shape)
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
    BOOST_CHECK_EQUAL(stats.batch_size, 1U);
    BOOST_CHECK_EQUAL(
        stats.async_prepare_enabled,
        matmul::accelerated::ResolveMiningBackendFromEnvironment().active == matmul::backend::Kind::METAL ||
            matmul::accelerated::ResolveMiningBackendFromEnvironment().active == matmul::backend::Kind::CUDA);
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

    uint64_t max_tries{8};
    ResetMatMulSolvePipelineStats();
    const bool solved = SolveMatMul(candidate, consensus, max_tries);
    BOOST_CHECK(!solved);

    const auto stats = ProbeMatMulSolvePipelineStats();
    BOOST_CHECK_EQUAL(stats.batch_size, 2U);
    BOOST_CHECK(stats.async_prepare_enabled);
    BOOST_CHECK_EQUAL(stats.prefetch_depth, 2U);
    BOOST_CHECK_GE(stats.batched_digest_requests, 1U);
    BOOST_CHECK_GE(stats.batched_nonce_attempts, 2U);
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
    const uint256 digest{"1111111111111111111111111111111111111111111111111111111111111111"};
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
    const uint256 first_backend{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
    const uint256 first_cpu{"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"};
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
    const uint256 second_backend{"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"};
    const uint256 second_cpu{"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"};
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

BOOST_AUTO_TEST_SUITE_END()
