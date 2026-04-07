// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <chainparams.h>
#include <common/args.h>
#include <matmul/matmul_pow.h>
#include <matmul/noise.h>
#include <matmul/transcript.h>
#include <pow.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>
#include <chrono>
#include <cstdint>
#include <limits>
#include <string_view>
#include <vector>

namespace {

uint256 ParseUint256(std::string_view hex)
{
    const auto parsed = uint256::FromHex(hex);
    BOOST_REQUIRE(parsed.has_value());
    return *parsed;
}

Consensus::Params BaseParams()
{
    auto params = CreateChainParams(ArgsManager{}, ChainType::REGTEST)->GetConsensus();
    params.fMatMulPOW = true;
    params.fSkipMatMulValidation = false;
    params.nMatMulDimension = 8;
    params.nMatMulTranscriptBlockSize = 4;
    params.nMatMulNoiseRank = 2;
    params.nMatMulMinDimension = 4;
    params.nMatMulMaxDimension = 64;
    params.nMatMulPeerVerifyBudgetPerMin = 8;
    params.nMatMulMaxPendingVerifications = 4;
    params.nMatMulPhase2FailBanThreshold = 3;
    params.fMatMulStrictPunishment = false;
    params.powLimit = ParseUint256("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    return params;
}

CBlockHeader MakeCandidateHeader(const Consensus::Params& params)
{
    CBlockHeader header;
    header.nVersion = 2;
    header.hashPrevBlock = ParseUint256("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    header.hashMerkleRoot = ParseUint256("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100");
    header.nTime = 1'700'000'000U;
    header.nBits = UintToArith256(params.powLimit).GetCompact();
    header.nNonce64 = 42;
    header.matmul_dim = static_cast<uint16_t>(params.nMatMulDimension);
    header.seed_a = ParseUint256("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    header.seed_b = ParseUint256("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210");
    return header;
}

CBlockHeader MakeValidHeader(const Consensus::Params& params)
{
    CBlockHeader header = MakeCandidateHeader(params);

    const auto A = matmul::FromSeed(header.seed_a, header.matmul_dim);
    const auto B = matmul::FromSeed(header.seed_b, header.matmul_dim);
    const uint256 sigma = matmul::DeriveSigma(header);
    const auto np = matmul::noise::Generate(sigma, header.matmul_dim, params.nMatMulNoiseRank);
    const auto A_prime = A + (np.E_L * np.E_R);
    const auto B_prime = B + (np.F_L * np.F_R);
    const auto result = matmul::transcript::CanonicalMatMul(
        A_prime,
        B_prime,
        params.nMatMulTranscriptBlockSize,
        sigma);
    header.matmul_digest = result.transcript_hash;
    return header;
}

std::vector<uint32_t> FlattenMatrixWords(const matmul::Matrix& matrix)
{
    std::vector<uint32_t> out;
    out.reserve(static_cast<size_t>(matrix.rows()) * matrix.cols());
    for (uint32_t row = 0; row < matrix.rows(); ++row) {
        for (uint32_t col = 0; col < matrix.cols(); ++col) {
            out.push_back(matrix.at(row, col));
        }
    }
    return out;
}

CBlock MakeValidPayloadBlock(const Consensus::Params& params)
{
    CBlock block;
    static_cast<CBlockHeader&>(block) = MakeCandidateHeader(params);
    const auto A = matmul::FromSeed(block.seed_a, block.matmul_dim);
    const auto B = matmul::FromSeed(block.seed_b, block.matmul_dim);
    block.matrix_a_data = FlattenMatrixWords(A);
    block.matrix_b_data = FlattenMatrixWords(B);

    const uint256 sigma = matmul::DeriveSigma(block);
    const auto np = matmul::noise::Generate(sigma, block.matmul_dim, params.nMatMulNoiseRank);
    const auto A_prime = A + (np.E_L * np.E_R);
    const auto B_prime = B + (np.F_L * np.F_R);
    const auto result = matmul::transcript::CanonicalMatMul(
        A_prime,
        B_prime,
        params.nMatMulTranscriptBlockSize,
        sigma);
    block.matmul_digest = result.transcript_hash;
    return block;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(matmul_validation_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(validation_phase1_rejects_bad_dim)
{
    const auto params = BaseParams();
    auto header = MakeValidHeader(params);
    header.matmul_dim = 1;
    BOOST_CHECK(!CheckMatMulProofOfWork_Phase1(header, params));
}

BOOST_AUTO_TEST_CASE(validation_phase1_rejects_high_digest)
{
    const auto params = BaseParams();
    auto header = MakeCandidateHeader(params);
    header.matmul_digest = ParseUint256("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    header.nBits = 0x1d00ffffU;
    BOOST_CHECK(!CheckMatMulProofOfWork_Phase1(header, params));
}

BOOST_AUTO_TEST_CASE(validation_phase1_rejects_null_seeds)
{
    const auto params = BaseParams();
    auto header = MakeValidHeader(params);
    header.seed_a.SetNull();
    BOOST_CHECK(!CheckMatMulProofOfWork_Phase1(header, params));
}

BOOST_AUTO_TEST_CASE(validation_phase1_accepts_valid)
{
    const auto params = BaseParams();
    const auto header = MakeValidHeader(params);
    BOOST_CHECK(CheckMatMulProofOfWork_Phase1(header, params));
}

BOOST_AUTO_TEST_CASE(validation_phase1_rejects_fake_genesis)
{
    const auto params = BaseParams();
    auto header = MakeValidHeader(params);
    header.hashPrevBlock.SetNull();
    BOOST_CHECK(!CheckMatMulProofOfWork_Phase1(header, params));
}

BOOST_AUTO_TEST_CASE(validation_phase1_accepts_actual_genesis_header)
{
    const auto chain_params = CreateChainParams(ArgsManager{}, ChainType::REGTEST);
    const auto& params = chain_params->GetConsensus();
    const CBlockHeader genesis = chain_params->GenesisBlock().GetBlockHeader();
    BOOST_CHECK(CheckMatMulProofOfWork_Phase1(genesis, params));
}

BOOST_AUTO_TEST_CASE(validation_phase1_fail_misbehavior_score)
{
    int score = 0;
    for (int i = 0; i < 5; ++i) {
        score += MATMUL_PHASE1_FAIL_MISBEHAVIOR;
    }
    BOOST_CHECK_EQUAL(MATMUL_PHASE1_FAIL_MISBEHAVIOR, 20);
    BOOST_CHECK_EQUAL(score, 100);
}

BOOST_AUTO_TEST_CASE(validation_phase2_recomputes)
{
    const auto params = BaseParams();
    const auto header = MakeValidHeader(params);
    BOOST_CHECK(CheckMatMulProofOfWork_Phase2(header, params));
}

BOOST_AUTO_TEST_CASE(validation_phase2_rejects_wrong_seed)
{
    const auto params = BaseParams();
    auto header = MakeValidHeader(params);
    header.seed_a = ParseUint256("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    BOOST_CHECK(!CheckMatMulProofOfWork_Phase2(header, params));
}

BOOST_AUTO_TEST_CASE(validation_phase2_rejects_tampered_digest)
{
    const auto params = BaseParams();
    auto header = MakeValidHeader(params);
    header.matmul_digest = ParseUint256("0100000000000000000000000000000000000000000000000000000000000000");
    BOOST_CHECK(!CheckMatMulProofOfWork_Phase2(header, params));
}

BOOST_AUTO_TEST_CASE(validation_phase2_payload_recomputes)
{
    const auto params = BaseParams();
    const auto block = MakeValidPayloadBlock(params);
    BOOST_CHECK(HasMatMulV2Payload(block));
    BOOST_CHECK(IsMatMulV2PayloadSizeValid(block, params));
    BOOST_CHECK(CheckMatMulProofOfWork_Phase2WithPayload(block, params));
}

BOOST_AUTO_TEST_CASE(validation_phase2_payload_rejects_tampered_matrix_data)
{
    const auto params = BaseParams();
    auto block = MakeValidPayloadBlock(params);
    block.matrix_a_data[0] = block.matrix_a_data[0] + 1;
    BOOST_CHECK(!CheckMatMulProofOfWork_Phase2WithPayload(block, params));
}

BOOST_AUTO_TEST_CASE(validation_phase2_payload_rejects_shape_mismatch)
{
    const auto params = BaseParams();
    auto block = MakeValidPayloadBlock(params);
    block.matrix_b_data.pop_back();
    BOOST_CHECK(!IsMatMulV2PayloadSizeValid(block, params));
    BOOST_CHECK(!CheckMatMulProofOfWork_Phase2WithPayload(block, params));
}

BOOST_AUTO_TEST_CASE(validation_matmul_v2_payload_selection)
{
    const auto params = BaseParams();
    auto block = MakeValidPayloadBlock(params);
    BOOST_CHECK(HasMatMulV2Payload(block));
}

BOOST_AUTO_TEST_CASE(validation_skip_mode)
{
    auto params = BaseParams();
    auto header = MakeValidHeader(params);
    header.matmul_digest = ParseUint256("0200000000000000000000000000000000000000000000000000000000000000");
    params.fSkipMatMulValidation = true;

    const bool accepted = CheckMatMulProofOfWork_Phase1(header, params) &&
        (params.fSkipMatMulValidation || CheckMatMulProofOfWork_Phase2(header, params));
    BOOST_CHECK(accepted);
}

BOOST_AUTO_TEST_CASE(validation_phase2_fail_first_offense_disconnect)
{
    const auto params = BaseParams();
    MatMulPeerVerificationBudget budget;
    const auto action = RegisterMatMulPhase2Failure(budget, params, std::chrono::steady_clock::now());
    BOOST_CHECK(action == MatMulPhase2Punishment::DISCONNECT);
    BOOST_CHECK_EQUAL(budget.phase2_failures, 1U);
}

BOOST_AUTO_TEST_CASE(validation_phase2_fail_second_offense_discourage)
{
    const auto params = BaseParams();
    MatMulPeerVerificationBudget budget;
    const auto now = std::chrono::steady_clock::now();
    (void)RegisterMatMulPhase2Failure(budget, params, now);
    const auto action = RegisterMatMulPhase2Failure(budget, params, now + std::chrono::minutes{1});
    BOOST_CHECK(action == MatMulPhase2Punishment::DISCOURAGE);
    BOOST_CHECK_EQUAL(budget.phase2_failures, 2U);
}

BOOST_AUTO_TEST_CASE(validation_phase2_fail_third_offense_ban)
{
    const auto params = BaseParams();
    MatMulPeerVerificationBudget budget;
    const auto now = std::chrono::steady_clock::now();
    (void)RegisterMatMulPhase2Failure(budget, params, now);
    (void)RegisterMatMulPhase2Failure(budget, params, now + std::chrono::minutes{1});
    const auto action = RegisterMatMulPhase2Failure(budget, params, now + std::chrono::minutes{2});
    BOOST_CHECK(action == MatMulPhase2Punishment::BAN);
    BOOST_CHECK_EQUAL(budget.phase2_failures, 3U);
}

BOOST_AUTO_TEST_CASE(validation_phase2_fail_strict_mode_immediate_ban)
{
    auto params = BaseParams();
    params.fMatMulStrictPunishment = true;

    MatMulPeerVerificationBudget budget;
    const auto action = RegisterMatMulPhase2Failure(budget, params, std::chrono::steady_clock::now());
    BOOST_CHECK(action == MatMulPhase2Punishment::BAN);
    BOOST_CHECK_EQUAL(EffectivePhase2BanThreshold(params), 1U);
}

BOOST_AUTO_TEST_CASE(validation_effective_threshold_computation)
{
    auto mainnet = BaseParams();
    mainnet.fMatMulStrictPunishment = false;
    mainnet.nMatMulPhase2FailBanThreshold = 3;
    BOOST_CHECK_EQUAL(EffectivePhase2BanThreshold(mainnet), 3U);

    mainnet.fMatMulStrictPunishment = true;
    BOOST_CHECK_EQUAL(EffectivePhase2BanThreshold(mainnet), 1U);

    auto softfail = BaseParams();
    softfail.nMatMulPhase2FailBanThreshold = std::numeric_limits<uint32_t>::max();
    softfail.fMatMulStrictPunishment = true;
    BOOST_CHECK_EQUAL(EffectivePhase2BanThreshold(softfail), std::numeric_limits<uint32_t>::max());
}

BOOST_AUTO_TEST_SUITE_END()
