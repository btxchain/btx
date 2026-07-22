// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_rc_coupled.h>
#include <matmul/matmul_v4_rc_mx_ozaki.h>
#include <matmul/matmul_v4_rc_selfqual.h>
#include <matmul/exact_gemm_resolve.h>

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <common/args.h>
#include <consensus/params.h>
#include <pow.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace rc = matmul::v4::rc;
namespace lt = matmul::v4::lt;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_coupled_tests, BasicTestingSetup)

namespace {

CBlockHeader MakeCoupHeader(uint64_t nonce)
{
    CBlockHeader header;
    header.nVersion = 0x20000004;
    header.nTime = 1'770'000'000;
    header.nBits = 0x207fffff;
    header.nNonce64 = nonce;
    header.nNonce = static_cast<uint32_t>(nonce);
    for (int i = 0; i < 32; ++i) {
        header.hashPrevBlock.data()[i] = static_cast<unsigned char>(0x51);
        header.hashMerkleRoot.data()[i] = static_cast<unsigned char>(0xa3);
        header.seed_a.data()[i] = static_cast<unsigned char>(0x11);
        header.seed_b.data()[i] = static_cast<unsigned char>(0x22);
    }
    return header;
}

bool WrongGemmS8S8(const std::vector<int8_t>& /*L*/, const std::vector<int8_t>& /*R*/,
                   uint32_t rows, uint32_t /*inner*/, uint32_t cols, std::vector<int32_t>& out)
{
    out.assign(static_cast<size_t>(rows) * cols, 123456789);
    return true;
}

bool WrongGemmS32S8(const std::vector<int32_t>& /*L*/, const std::vector<int8_t>& /*R*/,
                    uint32_t rows, uint32_t /*inner*/, uint32_t cols, std::vector<int32_t>& out)
{
    out.assign(static_cast<size_t>(rows) * cols, -999);
    return true;
}

} // namespace

BOOST_AUTO_TEST_CASE(rc_coup_inactive_and_constants)
{
    Consensus::Params consensus;
    BOOST_CHECK_EQUAL(consensus.nMatMulRCHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK_EQUAL(consensus.nMatMulRCCoupledHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK(!consensus.fMatMulRCCoupledUseToyDims);
    BOOST_CHECK_EQUAL(consensus.nMatMulRCCoupledProfile, 2u);
    BOOST_CHECK(!consensus.IsMatMulRCActive(0));
    BOOST_CHECK(!consensus.IsMatMulRCCoupledActive(0));
    BOOST_CHECK(consensus.GetMatMulEncodingProfile(0) !=
                Consensus::MatMulEncodingProfile::ENC_RC_COUPLED);
    BOOST_CHECK_EQUAL(rc::kRCCoupRounds, 4u);
    BOOST_CHECK_EQUAL(rc::kRCCoupLobes, 4u);
    BOOST_CHECK_EQUAL(rc::kRCCoupLobeWidth, 32u);
    BOOST_CHECK_EQUAL(rc::kRCCoupStateBytes, 128u);
    BOOST_CHECK_EQUAL(rc::kRCCoupBankPages, 8u);
    BOOST_CHECK_EQUAL(rc::kRCCoupMixPatterns, 2u);
    BOOST_CHECK_EQUAL(rc::kRCCoupLobeWidth % 32, 0u);
    BOOST_CHECK_EQUAL(rc::kRCCoupStateBytes % 32, 0u);

    const auto toy = rc::MakeToyRCCoupParams();
    BOOST_CHECK(rc::ValidateRCCoupParams(toy));
    BOOST_CHECK(rc::RCCoupBarrierLoopComplete(toy));
    BOOST_CHECK_EQUAL(toy.barriers, rc::kRCCoupRounds);
    BOOST_CHECK_EQUAL(toy.lobes, rc::kRCCoupLobes);
    BOOST_CHECK_EQUAL(toy.lobe_width, rc::kRCCoupLobeWidth);
    BOOST_CHECK_EQUAL(toy.bank_pages, rc::kRCCoupBankPages);
    BOOST_CHECK_EQUAL(toy.StateBytes(), rc::kRCCoupStateBytes);

    const auto med = rc::MakeMediumRCCoupParams();
    BOOST_CHECK(rc::ValidateRCCoupParams(med));
    BOOST_CHECK(rc::RCCoupBarrierLoopComplete(med));
    BOOST_CHECK_EQUAL(med.barriers, 8u);
    BOOST_CHECK_EQUAL(med.lobes, 8u);
    BOOST_CHECK_EQUAL(med.lobe_width, 64u);
    BOOST_CHECK_EQUAL(med.bank_pages, 32u);
    BOOST_CHECK_EQUAL(med.StateBytes(), 512u);
    BOOST_CHECK_EQUAL(med.lobe_width % 32, 0u);
    BOOST_CHECK_EQUAL(med.StateBytes() % 32, 0u);
    BOOST_CHECK_EQUAL(med.StateBytes() & (med.StateBytes() - 1), 0u);

    // C5: barriers outside [4,8] are rejected.
    rc::RCCoupParams bad = toy;
    bad.barriers = 3;
    BOOST_CHECK(!rc::ValidateRCCoupParams(bad));
    bad.barriers = 9;
    BOOST_CHECK(!rc::ValidateRCCoupParams(bad));
}

BOOST_AUTO_TEST_CASE(rc_coup_resolve_profile_toydims_matrix)
{
    // F8: -regtestrccoupledprofile × -regtestrccoupledtoydims selection + fail-closed.
    Consensus::Params p;
    p.nMatMulRCCoupledProfile = 2;
    p.fMatMulRCCoupledUseToyDims = true;
    {
        const auto got = rc::ResolveRCCoupParams(p);
        const auto want = rc::MakeToyRCCoupParams();
        BOOST_CHECK_EQUAL(got.barriers, want.barriers);
        BOOST_CHECK_EQUAL(got.rows_per_lobe, want.rows_per_lobe);
        BOOST_CHECK_EQUAL(got.pages_per_barrier_lobe, want.pages_per_barrier_lobe);
        BOOST_CHECK(rc::ValidateRCCoupParams(got));
    }
    p.fMatMulRCCoupledUseToyDims = false;
    {
        const auto got = rc::ResolveRCCoupParams(p);
        const auto want = rc::MakeMediumRCCoupParams();
        BOOST_CHECK_EQUAL(got.bank_pages, want.bank_pages);
        BOOST_CHECK_EQUAL(got.rows_per_lobe, 1u);
        BOOST_CHECK(rc::ValidateRCCoupParams(got));
    }
    p.nMatMulRCCoupledProfile = 3;
    p.fMatMulRCCoupledUseToyDims = true;
    {
        const auto got = rc::ResolveRCCoupParams(p);
        const auto want = rc::MakeMediumV3RCCoupParams();
        BOOST_CHECK_EQUAL(got.rows_per_lobe, want.rows_per_lobe);
        BOOST_CHECK_EQUAL(got.pages_per_barrier_lobe, want.pages_per_barrier_lobe);
        BOOST_CHECK_EQUAL(got.bank_pages, want.bank_pages);
        BOOST_CHECK(rc::ValidateRCCoupParams(got));
    }
    p.fMatMulRCCoupledUseToyDims = false;
    {
        const auto got = rc::ResolveRCCoupParams(p);
        const auto want = rc::MakeProductionV3RCCoupParams();
        BOOST_CHECK_EQUAL(got.rows_per_lobe, 128u);
        BOOST_CHECK_EQUAL(got.pages_per_barrier_lobe, want.pages_per_barrier_lobe);
        BOOST_CHECK_EQUAL(got.bank_pages, 1536u);
        BOOST_CHECK(rc::ValidateRCCoupParams(got));
    }
    // Invalid profile → zero params → fail closed.
    p.nMatMulRCCoupledProfile = 1;
    {
        const auto got = rc::ResolveRCCoupParams(p);
        BOOST_CHECK_EQUAL(got.barriers, 0u);
        BOOST_CHECK_EQUAL(got.rows_per_lobe, 0u);
        BOOST_CHECK_EQUAL(got.pages_per_barrier_lobe, 0u);
        BOOST_CHECK(!rc::ValidateRCCoupParams(got));
    }
    p.nMatMulRCCoupledProfile = 99;
    BOOST_CHECK(!rc::ValidateRCCoupParams(rc::ResolveRCCoupParams(p)));

    p.nMatMulRCCoupledProfile = 3;
    p.fMatMulRCCoupledUseToyDims = true;
    BOOST_CHECK_EQUAL(rc::ResolveRCCoupOptions(p).transcript_version, rc::ENC_RC_V3);
    p.nMatMulRCCoupledProfile = 2;
    BOOST_CHECK_EQUAL(rc::ResolveRCCoupOptions(p).transcript_version, rc::ENC_RC_V1);
}


BOOST_AUTO_TEST_CASE(rc_coup_admission_priced_per_activation_shape)
{
    // F1: Coupled-only must not inherit EncDr/v4/LT caps; stacked must price
    // coupled MACs (not RC episode MACs); RC-only keeps episode pricing.
    Consensus::Params p;
    p.nMatMulV4Height = 1;
    p.nMatMulBMX4CHeight = 1;
    p.nMatMulDRLTHeight = 1;
    p.fMatMulLTSealAsPoW = false;
    p.nMatMulMaxPendingVerifications = 16;
    p.nMatMulLTMaxPendingVerifications = 2;
    p.nMatMulRCMaxPendingVerifications = 1;
    p.nMatMulRCGlobalVerifyBudgetPerMin = 1;
    p.nMatMulRCPeerVerifyBudgetPerMin = 1;
    p.fMatMulRCUseToyDims = true;
    p.fMatMulRCCoupledUseToyDims = true;

    constexpr int32_t kH = 100;

    // --- RC-only ---
    p.nMatMulRCHeight = 50;
    p.nMatMulRCCoupledHeight = std::numeric_limits<int32_t>::max();
    BOOST_REQUIRE(p.IsMatMulRCActive(kH));
    BOOST_REQUIRE(!p.IsMatMulRCCoupledActive(kH));
    BOOST_REQUIRE(p.IsMatMulRCFamilyActive(kH));
    const uint32_t wu_rc = MatMulRCWorkUnits(p, kH);
    BOOST_CHECK_EQUAL(wu_rc, 1U); // toy episode → 1 unit
    BOOST_CHECK_EQUAL(EffectiveMatMulRCMaxPendingVerifications(p, kH), 1U);
    BOOST_CHECK(CanStartMatMulRCVerification(0, wu_rc, p, kH));
    BOOST_CHECK(!CanStartMatMulRCVerification(1, wu_rc, p, kH));
    // EncDr/LT pool stays on its own knobs.
    BOOST_CHECK_EQUAL(EffectiveMatMulMaxPendingVerifications(p, kH), 2U);

    // --- Coupled-only (RC still INT32_MAX) ---
    p.nMatMulRCHeight = std::numeric_limits<int32_t>::max();
    p.nMatMulRCCoupledHeight = 50;
    BOOST_REQUIRE(!p.IsMatMulRCActive(kH));
    BOOST_REQUIRE(p.IsMatMulRCCoupledActive(kH));
    BOOST_REQUIRE(p.IsMatMulRCFamilyActive(kH));
    const auto toy = rc::MakeToyRCCoupParams();
    BOOST_CHECK_EQUAL(rc::TotalRCCoupMacs(toy),
                      uint64_t{toy.rows_per_lobe} * toy.pages_per_barrier_lobe * toy.barriers *
                          toy.lobes * toy.lobe_width * toy.lobe_width);
    const uint32_t wu_coup = MatMulRCWorkUnits(p, kH);
    BOOST_CHECK_EQUAL(wu_coup, 1U); // toy coupled ≪ 2^40 → 1 unit
    // Must route through RC-family caps (pending=1), NOT EncDr 16 / LT 2.
    BOOST_CHECK_EQUAL(EffectiveMatMulRCMaxPendingVerifications(p, kH), 1U);
    BOOST_CHECK_EQUAL(EffectiveMatMulRCGlobalVerifyBudgetPerMin(p, kH), 1U);
    BOOST_CHECK_EQUAL(EffectiveMatMulRCPeerVerifyBudgetPerMin(p, false, kH), 1U);
    BOOST_CHECK(CanStartMatMulRCVerification(0, wu_coup, p, kH));
    BOOST_CHECK(!CanStartMatMulRCVerification(1, wu_coup, p, kH));
    BOOST_CHECK_EQUAL(EffectiveMatMulMaxPendingVerifications(p, kH), 2U);

    // --- Stacked: both live → profile is Coupled; price coupled, not episode ---
    p.nMatMulRCHeight = 40;
    p.nMatMulRCCoupledHeight = 50;
    p.fMatMulRCUseToyDims = false; // consensus RC dims would be ~49 units if mis-priced
    Consensus::FillDefaultRCGrowthTables(p);
    BOOST_REQUIRE(p.IsMatMulRCActive(kH));
    BOOST_REQUIRE(p.IsMatMulRCCoupledActive(kH));
    BOOST_CHECK(p.GetMatMulEncodingProfile(kH) ==
                Consensus::MatMulEncodingProfile::ENC_RC_COUPLED);
    const uint32_t wu_stacked = MatMulRCWorkUnits(p, kH);
    BOOST_CHECK_EQUAL(wu_stacked, wu_coup); // coupled cost, not ~49 episode units
    BOOST_CHECK_LT(wu_stacked, 40U);
    BOOST_CHECK_EQUAL(EffectiveMatMulRCMaxPendingVerifications(p, kH), wu_stacked);
    BOOST_CHECK(CanStartMatMulRCVerification(0, wu_stacked, p, kH));
    BOOST_CHECK(!CanStartMatMulRCVerification(wu_stacked, wu_stacked, p, kH));
}



BOOST_AUTO_TEST_CASE(rc_coup_asert_unsafe_ordering_rejected_at_construction)
{
    // F2: ValidateMatMulAsertParams (invoked from AssertBMX4CConstructionInvariants)
    // must fail-closed on Coupled < RC, Coupled below ASERT, or unified Coupled==RC
    // with a non-inert Coupled rescale (would double-apply / shadow without recalibration).
    Consensus::Params p;
    p.fMatMulPOW = true;
    p.nPowTargetSpacing = 90;
    p.nMatMulAsertHeight = 10;
    p.nMatMulAsertHalfLife = 14'400;
    p.nMatMulAsertBootstrapFactor = 1;
    p.nMatMulV4Height = 20;
    p.nMatMulBMX4CHeight = 20;
    p.nMatMulDRLTHeight = 20;
    p.nMatMulV4AsertRescaleNum = 1;
    p.nMatMulV4AsertRescaleDen = 1;
    p.nMatMulBMX4CAsertRescaleNum = 1;
    p.nMatMulBMX4CAsertRescaleDen = 1;
    p.nMatMulDRLTAsertRescaleNum = 1;
    p.nMatMulDRLTAsertRescaleDen = 1;
    p.nMatMulRCAsertRescaleNum = 1;
    p.nMatMulRCAsertRescaleDen = 1;
    p.nMatMulRCCoupledAsertRescaleNum = 1;
    p.nMatMulRCCoupledAsertRescaleDen = 1;

    // Legal: Coupled follows RC.
    p.nMatMulRCHeight = 30;
    p.nMatMulRCCoupledHeight = 40;
    BOOST_CHECK(ValidateMatMulAsertParams(p, p.nMatMulAsertHeight));

    // Unsafe: Coupled precedes RC.
    p.nMatMulRCCoupledHeight = 25;
    BOOST_CHECK(!ValidateMatMulAsertParams(p, p.nMatMulAsertHeight));

    // Unsafe: Coupled below ASERT activation.
    p.nMatMulRCHeight = std::numeric_limits<int32_t>::max();
    p.nMatMulRCCoupledHeight = 5;
    BOOST_CHECK(!ValidateMatMulAsertParams(p, p.nMatMulAsertHeight));

    // Unsafe: unified Coupled==RC with non-inert Coupled rescale (RC owns the shift).
    p.nMatMulRCHeight = 30;
    p.nMatMulRCCoupledHeight = 30;
    p.nMatMulRCCoupledAsertRescaleNum = 2;
    p.nMatMulRCCoupledAsertRescaleDen = 1;
    BOOST_CHECK(!ValidateMatMulAsertParams(p, p.nMatMulAsertHeight));

    // Legal again: unified with Coupled rescale 1/1.
    p.nMatMulRCCoupledAsertRescaleNum = 1;
    p.nMatMulRCCoupledAsertRescaleDen = 1;
    BOOST_CHECK(ValidateMatMulAsertParams(p, p.nMatMulAsertHeight));

    // Public mainnet heights stay unreachable (guardrail).
    const auto main = CreateChainParams(ArgsManager{}, ChainType::MAIN)->GetConsensus();
    BOOST_CHECK_EQUAL(main.nMatMulRCHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK_EQUAL(main.nMatMulRCCoupledHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK_EQUAL(main.nMatMulRCCoupledAsertRescaleNum, 1);
    BOOST_CHECK_EQUAL(main.nMatMulRCCoupledAsertRescaleDen, 1);
}

BOOST_AUTO_TEST_CASE(rc_coup_asert_transition_reanchors_at_coupled_height)
{
    // F2: at nMatMulRCCoupledHeight a 1/1 rescale keeps the parent target, then
    // ASERT re-anchors so mutating a pre-boundary parent does not perturb the
    // post-boundary target (mirrors asert_bmx4c_rescale_mechanism_applies_at_height).
    Consensus::Params params =
        CreateChainParams(ArgsManager{}, ChainType::REGTEST)->GetConsensus();
    params.fMatMulPOW = true;
    params.fPowNoRetargeting = false;
    params.fPowAllowMinDifficultyBlocks = false;
    params.nPowTargetSpacingFastMs = 90'000;
    params.nPowTargetSpacingNormal = 90;
    params.nFastMineDifficultyScale = 1;
    params.nFastMineHeight = 361;
    params.nMatMulAsertHeight = 361;
    params.nMatMulAsertHalfLife = 14'400;
    params.nMatMulAsertBootstrapFactor = 40;
    params.nMatMulV4Height = 362;
    params.nMatMulBMX4CHeight = 362;
    params.nMatMulDRLTHeight = 362;
    params.nMatMulV4AsertRescaleNum = 1;
    params.nMatMulV4AsertRescaleDen = 1;
    params.nMatMulBMX4CAsertRescaleNum = 1;
    params.nMatMulBMX4CAsertRescaleDen = 1;
    params.nMatMulDRLTAsertRescaleNum = 1;
    params.nMatMulDRLTAsertRescaleDen = 1;
    params.nMatMulRCHeight = 364;
    params.nMatMulRCAsertRescaleNum = 1;
    params.nMatMulRCAsertRescaleDen = 1;
    params.nMatMulRCCoupledHeight = 366;
    params.nMatMulRCCoupledAsertRescaleNum = 1;
    params.nMatMulRCCoupledAsertRescaleDen = 1;
    params.fMatMulRCUseToyDims = true;
    params.fMatMulRCCoupledUseToyDims = true;
    BOOST_REQUIRE(ValidateMatMulAsertParams(params, params.nMatMulAsertHeight));

    std::vector<CBlockIndex> blocks(367);
    const uint32_t seed_bits = 0x1f00ffffU;
    const int64_t start_time = 1'700'000'000;
    const int64_t spacing = 90;
    for (size_t i = 0; i < blocks.size(); ++i) {
        blocks[i].nHeight = static_cast<int>(i);
        blocks[i].nBits = seed_bits;
        blocks[i].nTime = start_time + static_cast<int64_t>(i) * spacing;
        blocks[i].pprev = (i == 0) ? nullptr : &blocks[i - 1];
    }

    CBlockHeader activation{};
    activation.nTime = blocks[360].GetBlockTime() + 1;
    blocks[361].nHeight = 361;
    blocks[361].nBits = GetNextWorkRequired(&blocks[360], &activation, params);
    blocks[361].nTime = activation.nTime;
    blocks[361].pprev = &blocks[360];
    for (int h = 362; h <= 365; ++h) {
        CBlockIndex& prev = blocks[h - 1];
        CBlockHeader next{};
        next.nTime = prev.GetBlockTime() + spacing;
        blocks[h].nHeight = h;
        blocks[h].nBits = GetNextWorkRequired(&prev, &next, params);
        blocks[h].nTime = next.nTime;
        blocks[h].pprev = &prev;
    }

    CBlockHeader coup_next{};
    coup_next.nTime = blocks[365].GetBlockTime() + spacing;
    const uint32_t coup_bits = GetNextWorkRequired(&blocks[365], &coup_next, params);
    BOOST_CHECK_EQUAL(coup_bits, blocks[365].nBits); // 1/1 continuity

    blocks[366].nHeight = 366;
    blocks[366].nBits = coup_bits;
    blocks[366].nTime = coup_next.nTime;
    blocks[366].pprev = &blocks[365];

    const auto info = GetMatMulAsertHalfLifeInfo(&blocks[366], params);
    BOOST_CHECK_EQUAL(info.current_anchor_height, 366);

    CBlockHeader after{};
    after.nTime = blocks[366].GetBlockTime() + spacing;
    const uint32_t target_367 = GetNextWorkRequired(&blocks[366], &after, params);
    const uint32_t saved_365 = blocks[365].nBits;
    blocks[365].nBits = 0x1b0404cbU;
    const uint32_t target_367_mut = GetNextWorkRequired(&blocks[366], &after, params);
    blocks[365].nBits = saved_365;
    BOOST_CHECK_EQUAL(target_367_mut, target_367);
}

BOOST_AUTO_TEST_CASE(rc_coup_check_pow_regtest_gate)
{
    Consensus::Params p;
    p.fMatMulPOW = true;
    p.nMatMulV4Height = 1;
    p.nMatMulRCCoupledHeight = 1;
    p.fMatMulRCCoupledUseToyDims = true;
    p.nMatMulV4Dimension = 256;
    p.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    constexpr int32_t kHeight = 10;
    BOOST_REQUIRE(p.IsMatMulRCCoupledActive(kHeight));
    BOOST_REQUIRE(p.GetMatMulEncodingProfile(kHeight) ==
                  Consensus::MatMulEncodingProfile::ENC_RC_COUPLED);
    // Coupled supersedes ENC_RC when both would be live.
    p.nMatMulRCHeight = 1;
    BOOST_CHECK(p.GetMatMulEncodingProfile(kHeight) ==
                Consensus::MatMulEncodingProfile::ENC_RC_COUPLED);

    auto header = MakeCoupHeader(42);
    header.matmul_dim = static_cast<uint16_t>(p.nMatMulV4Dimension);
    header.nBits = UintToArith256(p.powLimit).GetCompact();

    const auto params_coup = rc::ResolveRCCoupParams(p);
    BOOST_REQUIRE(p.fMatMulRCCoupledUseToyDims);
    BOOST_CHECK_EQUAL(params_coup.barriers, rc::MakeToyRCCoupParams().barriers);
    BOOST_CHECK(rc::RCCoupBarrierLoopComplete(params_coup));

    header.matmul_digest = rc::MineCoupledPuzzle(header, kHeight, params_coup);
    BOOST_CHECK(!header.matmul_digest.IsNull());
    BOOST_CHECK(CheckMatMulProofOfWork_RCCoupled(header, p, kHeight));

    CBlockHeader bad = header;
    bad.matmul_digest = uint256::ONE;
    BOOST_CHECK(!CheckMatMulProofOfWork_RCCoupled(bad, p, kHeight));

    Consensus::Params pub;
    BOOST_CHECK_EQUAL(pub.nMatMulRCCoupledHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK(!pub.IsMatMulRCCoupledActive(0));
    BOOST_CHECK(!pub.IsMatMulRCCoupledActive(std::numeric_limits<int32_t>::max() - 1));
}

BOOST_AUTO_TEST_CASE(rc_coup_golden_digest_stable)
{
    // FREEZE toy golden for MakeCoupHeader(42) @ height 0.
    // If the coupled algorithm changes, update this hex deliberately (no silent
    // replace) AND bump kRCTranscriptVersion / ENC_RC_V* while retaining prior
    // goldens in contrib/matmul-v4/rc-golden-gate.py (WS-F invariant).
    const auto header = MakeCoupHeader(42);
    const uint256 d1 = rc::RecomputeCoupledPuzzleReference(header, /*height=*/0);
    const uint256 d2 = rc::RecomputeCoupledPuzzleReference(header, /*height=*/0);
    BOOST_CHECK(!d1.IsNull());
    BOOST_CHECK(d1 == d2);
    BOOST_CHECK_EQUAL(d1.GetHex(),
                      "7a7ce1065c7881aa2bd2295c26778ebf88c22432e91326f98d098c11885579ee");

    // Toy params overload must stay byte-identical to the no-params path.
    const uint256 d_params =
        rc::RecomputeCoupledPuzzleReference(header, 0, rc::MakeToyRCCoupParams());
    BOOST_CHECK(d1 == d_params);
}

BOOST_AUTO_TEST_CASE(rc_coup_medium_golden_digest_stable)
{
    // FREEZE medium golden for MakeCoupHeader(42) + MakeMediumRCCoupParams() @ height 0.
    const auto header = MakeCoupHeader(42);
    const auto params = rc::MakeMediumRCCoupParams();
    const uint256 d1 = rc::RecomputeCoupledPuzzleReference(header, 0, params);
    const uint256 d2 = rc::RecomputeCoupledPuzzleReference(header, 0, params);
    BOOST_CHECK(!d1.IsNull());
    BOOST_CHECK(d1 == d2);
    // Placeholder — replaced after first honest run below if mismatched.
    BOOST_CHECK_EQUAL(d1.GetHex(),
                      "349175d557eba373cd59ea4cb5431d5710481cc8e7e121e90c2a0775df8b5f4c");
}

BOOST_AUTO_TEST_CASE(rc_coup_mode_equivalence_all_four)
{
    const auto header = MakeCoupHeader(7);
    const rc::RCCoupExecMode modes[] = {
        rc::RCCoupExecMode::SequentialLobes,
        rc::RCCoupExecMode::Checkpointed,
        rc::RCCoupExecMode::Streamed,
        rc::RCCoupExecMode::Resident,
    };

    // Toy — all four modes share ONE byte-identical golden.
    uint256 toy_ref;
    for (size_t i = 0; i < 4; ++i) {
        rc::RCCoupOptions opt;
        opt.mode = modes[i];
        const uint256 d = rc::RecomputeCoupledPuzzleReference(header, 0, opt);
        if (i == 0) toy_ref = d;
        else BOOST_CHECK(d == toy_ref);
    }

    // Medium
    const auto med = rc::MakeMediumRCCoupParams();
    uint256 med_ref;
    for (size_t i = 0; i < 4; ++i) {
        rc::RCCoupOptions opt;
        opt.mode = modes[i];
        const uint256 d = rc::RecomputeCoupledPuzzleReference(header, 0, med, opt);
        if (i == 0) med_ref = d;
        else BOOST_CHECK(d == med_ref);
    }
    BOOST_CHECK(toy_ref != med_ref);
}

BOOST_AUTO_TEST_CASE(rc_coup_modes_match_frozen_golden)
{
    // Resident / Checkpointed / Streamed / Sequential ≡ frozen toy golden.
    const auto header = MakeCoupHeader(42);
    constexpr const char* kToy =
        "7a7ce1065c7881aa2bd2295c26778ebf88c22432e91326f98d098c11885579ee";
    const rc::RCCoupExecMode modes[] = {
        rc::RCCoupExecMode::SequentialLobes,
        rc::RCCoupExecMode::Checkpointed,
        rc::RCCoupExecMode::Streamed,
        rc::RCCoupExecMode::Resident,
    };
    for (auto mode : modes) {
        rc::RCCoupOptions opt;
        opt.mode = mode;
        BOOST_CHECK_EQUAL(rc::RecomputeCoupledPuzzleReference(header, 0, opt).GetHex(), kToy);
    }
}

BOOST_AUTO_TEST_CASE(rc_coup_soft_4gib_streamed_budget)
{
    // Soft 4 GiB Streamed peak estimate (toy + medium). Not a production HBM proof.
    constexpr uint64_t kSoft4GiB = 4ull << 30;
    for (const auto& params : {rc::MakeToyRCCoupParams(), rc::MakeMediumRCCoupParams()}) {
        BOOST_REQUIRE(rc::RCCoupBarrierLoopComplete(params));
        const uint64_t peak = rc::EstimateRCCoupStreamedPeakBytes(params);
        BOOST_CHECK_LT(peak, kSoft4GiB);
        // Force Streamed completion under the soft cap.
        const auto header = MakeCoupHeader(13);
        rc::RCCoupOptions streamed;
        streamed.mode = rc::RCCoupExecMode::Streamed;
        const uint256 d = rc::RecomputeCoupledPuzzleReference(header, 0, params, streamed);
        BOOST_CHECK(!d.IsNull());
        BOOST_TEST_MESSAGE("Streamed peak_bytes=" << peak << " barriers=" << params.barriers);
    }
}

BOOST_AUTO_TEST_CASE(rc_coup_production_dims_provisional)
{
    // PROVISIONAL production coupled shape — CI checks structure + peak formulas only
    // (does NOT expand the 48 GiB Resident bank). Full puzzle golden is off-CI.
    const auto prod = rc::MakeProductionRCCoupParams();
    BOOST_REQUIRE(rc::ValidateRCCoupParams(prod));
    BOOST_REQUIRE(rc::RCCoupBarrierLoopComplete(prod));
    BOOST_CHECK_EQUAL(prod.barriers, 8u);
    BOOST_CHECK_EQUAL(prod.lobes, 8u);
    BOOST_CHECK_EQUAL(prod.lobe_width, 8192u);
    BOOST_CHECK_EQUAL(prod.bank_pages, 768u);
    BOOST_CHECK_EQUAL(prod.StateBytes(), 65536u);
    BOOST_CHECK_EQUAL(prod.StateBytes() & (prod.StateBytes() - 1), 0u);
    BOOST_CHECK_EQUAL(prod.StateBytes() % 32, 0u);

    const uint64_t streamed = rc::EstimateRCCoupStreamedPeakBytes(prod);
    const uint64_t resident = rc::EstimateRCCoupResidentPeakBytes(prod);
    constexpr uint64_t k24GiB = 24ull << 30;
    constexpr uint64_t k48GiB = 48ull << 30;
    constexpr uint64_t k512MiB = 512ull << 20;
    BOOST_CHECK_LE(streamed, k24GiB);
    BOOST_CHECK_LE(streamed, k512MiB); // fits soft mem-cap-sweep floor
    BOOST_CHECK_GE(resident, k48GiB);
    BOOST_CHECK_LT(resident, k48GiB + (1ull << 20)); // ~48 GiB + small state

    // Param fingerprint includes rows_per_lobe + pages_per_barrier_lobe (V3-ready).
    const uint256 fp = rc::FingerprintRCCoupParams(prod);
    BOOST_CHECK_EQUAL(fp, rc::FingerprintRCCoupParams(prod));
    BOOST_CHECK(!fp.IsNull());
    // Frozen hex updated when fingerprint inputs change intentionally.
    BOOST_TEST_MESSAGE("prod fingerprint=" << fp.GetHex());
    BOOST_TEST_MESSAGE("production streamed_peak=" << streamed << " resident_peak=" << resident);
}

BOOST_AUTO_TEST_CASE(rc_coup_stage_d_distributed_parity)
{
    // Stage D: lobe segment IDs independent of N; integer-sum reduce; Extract once.
    const auto header = MakeCoupHeader(21);
    const auto params = rc::MakeToyRCCoupParams();
    const auto orders = {rc::DistReduceOrder::TreeLeftToRight,
                         rc::DistReduceOrder::TreeRightToLeft,
                         rc::DistReduceOrder::PairwiseButterfly};

    rc::DistEpisodeResult baseline;
    bool have_baseline = false;
    for (uint32_t N : {1u, 2u, 4u}) {
        for (auto order : orders) {
            if (order == rc::DistReduceOrder::PairwiseButterfly && (N & (N - 1)) != 0) {
                continue;
            }
            const auto r =
                rc::RunCoupledBarrierDistributed(header, /*height=*/0, params, /*barrier=*/0, N,
                                                 order);
            BOOST_CHECK_EQUAL(r.n_segs, params.lobes);
            BOOST_CHECK_EQUAL(r.n_devices, N);
            BOOST_CHECK(!r.digest.IsNull());
            BOOST_CHECK_EQUAL(r.pre_extract_sum.size(), params.StateBytes());
            BOOST_CHECK_EQUAL(r.extracted.size(), params.StateBytes());
            if (!have_baseline) {
                baseline = r;
                have_baseline = true;
            } else {
                BOOST_CHECK(r.pre_extract_sum == baseline.pre_extract_sum);
                BOOST_CHECK(r.extracted == baseline.extracted);
                BOOST_CHECK(r.digest == baseline.digest);
            }
        }
    }
    BOOST_REQUIRE(have_baseline);

    // Segment ownership is round-robin on lobe id (independent of N).
    for (uint32_t ell = 0; ell < params.lobes; ++ell) {
        BOOST_CHECK_EQUAL(rc::ConsensusSegmentId(ell, /*seg_len=*/1), ell);
        for (uint32_t N : {1u, 2u, 4u}) {
            BOOST_CHECK_EQUAL(rc::DeviceForSegment(ell, N), ell % N);
        }
    }
}

BOOST_AUTO_TEST_CASE(rc_coup_shortcut_skip_barrier_changes_digest)
{
    const auto header = MakeCoupHeader(9);
    const uint256 honest = rc::RecomputeCoupledPuzzleReference(header, 0);
    rc::RCCoupOptions bad;
    bad.skip_barrier = true;
    bad.skip_barrier_index = 2;
    const uint256 cheated = rc::RecomputeCoupledPuzzleReference(header, 0, bad);
    BOOST_CHECK(honest != cheated);
}

BOOST_AUTO_TEST_CASE(rc_coup_shortcut_skip_page_changes_digest)
{
    const auto header = MakeCoupHeader(11);
    const uint256 honest = rc::RecomputeCoupledPuzzleReference(header, 0);
    rc::RCCoupOptions bad;
    bad.skip_bank_page = true;
    bad.skip_page_index = 3;
    const uint256 cheated = rc::RecomputeCoupledPuzzleReference(header, 0, bad);
    BOOST_CHECK(honest != cheated);

    // Streamed skip_page must also diverge.
    rc::RCCoupOptions bad_stream = bad;
    bad_stream.mode = rc::RCCoupExecMode::Streamed;
    const uint256 cheated_stream = rc::RecomputeCoupledPuzzleReference(header, 0, bad_stream);
    BOOST_CHECK(honest != cheated_stream);
}

BOOST_AUTO_TEST_CASE(rc_coup_medium_invariants_and_shortcuts)
{
    // Cross-gap: medium %32 / power-of-two already asserted in constants case;
    // additionally prove shortcut hooks change the medium digest.
    const auto header = MakeCoupHeader(13);
    const auto med = rc::MakeMediumRCCoupParams();
    BOOST_REQUIRE(rc::ValidateRCCoupParams(med));
    BOOST_CHECK_EQUAL(med.lobe_width % 32, 0u);
    BOOST_CHECK_EQUAL(med.StateBytes() % 32, 0u);
    BOOST_CHECK_EQUAL(med.StateBytes() & (med.StateBytes() - 1), 0u);

    const uint256 honest = rc::RecomputeCoupledPuzzleReference(header, 0, med);

    rc::RCCoupOptions skip_b;
    skip_b.skip_barrier = true;
    skip_b.skip_barrier_index = 3;
    BOOST_CHECK(honest != rc::RecomputeCoupledPuzzleReference(header, 0, med, skip_b));

    rc::RCCoupOptions skip_p;
    skip_p.skip_bank_page = true;
    skip_p.skip_page_index = 7;
    BOOST_CHECK(honest != rc::RecomputeCoupledPuzzleReference(header, 0, med, skip_p));
}

BOOST_AUTO_TEST_CASE(rc_coup_device_probe_skip_without_gpu)
{
    // Skip-friendly: without an admitted device backend after RC self-qual,
    // ProbeRCCoupledDevice reports backend_resolved=false and does not claim
    // native MX. With a GPU that passes self-qual, require CPU match.
    const auto probe = rc::ProbeRCCoupledDevice();
    BOOST_CHECK(!probe.detail.empty());
    if (!probe.backend_resolved) {
        BOOST_CHECK_EQUAL(probe.provider, "cpu");
        BOOST_TEST_MESSAGE("RC coupled ExactGemm device path skipped: " << probe.detail);
    } else if (!probe.device_gemm_returned || !probe.matched_cpu_exactgemm) {
        // Honesty: decline/mismatch must CLEAR provider (never leave "device").
        BOOST_CHECK(probe.provider != "device");
        BOOST_CHECK(probe.provider.empty());
        BOOST_TEST_MESSAGE("RC coupled ExactGemm declined/mismatched: " << probe.detail);
    } else {
        BOOST_REQUIRE(probe.device_gemm_returned);
        BOOST_CHECK(probe.matched_cpu_exactgemm);
        BOOST_CHECK(probe.provider != "device");
        BOOST_TEST_MESSAGE("RC coupled ExactGemm device path provider=" << probe.provider);
    }

    // Amendment 1.B: coupled ExactGemm never implies RC native MXFP4 without
    // a qualified Ozaki MXFP4 device path (separate from ExactGemm panels).
    const auto st = rc::ProbeRCSelfQual(matmul_v4::accel::MakeResolvedExactGemmBackendForRC());
    BOOST_CHECK_EQUAL(st.native_mxfp4_qualified, rc::IsRcOzakiMxfp4Qualified());
    BOOST_CHECK(!st.native_fp8_qualified);
}

BOOST_AUTO_TEST_CASE(rc_coup_malformed_params_reject_null_digest)
{
    // V1/V9: malformed dims → REJECT (null digest), never assert/crash (ASAN-safe).
    const auto header = MakeCoupHeader(7);
    const auto good = rc::MakeToyRCCoupParams();
    BOOST_REQUIRE(rc::ValidateRCCoupParams(good));
    const uint256 honest = rc::RecomputeCoupledPuzzleReference(header, 0, good);
    BOOST_CHECK(!honest.IsNull());

    rc::RCCoupParams bad = good;
    bad.barriers = 3; // outside [4,8]
    BOOST_REQUIRE(!rc::ValidateRCCoupParams(bad));
    BOOST_CHECK(rc::RecomputeCoupledPuzzleReference(header, 0, bad).IsNull());

    bad = good;
    bad.lobe_width = 31; // not MX-aligned
    BOOST_REQUIRE(!rc::ValidateRCCoupParams(bad));
    BOOST_CHECK(rc::RecomputeCoupledPuzzleReference(header, 0, bad).IsNull());

    bad = good;
    bad.lobes = 0;
    BOOST_REQUIRE(!rc::ValidateRCCoupParams(bad));
    BOOST_CHECK(rc::RecomputeCoupledPuzzleReference(header, 0, bad).IsNull());

    // Distributed helper: bad barrier / n_devices → null digest, no crash.
    const auto dist_bad =
        rc::RunCoupledBarrierDistributed(header, 0, good, /*barrier=*/99, /*n_devices=*/2,
                                         rc::DistReduceOrder::TreeLeftToRight);
    BOOST_CHECK(dist_bad.digest.IsNull());
    const auto dist_bad_n =
        rc::RunCoupledBarrierDistributed(header, 0, good, /*barrier=*/0, /*n_devices=*/0,
                                         rc::DistReduceOrder::TreeLeftToRight);
    BOOST_CHECK(dist_bad_n.digest.IsNull());
}

BOOST_AUTO_TEST_CASE(rc_coup_balanced_perm_hits_every_index_once)
{
    const auto header = MakeCoupHeader(42);
    const uint256 sigma = matmul::v4::DeriveSigma(header);
    for (uint32_t b = 0; b < rc::kRCCoupRounds; ++b) {
        const auto pi = rc::DeriveCoupledBalancedPermutation(sigma, b);
        BOOST_CHECK(rc::IsBalancedPermutation(pi));
        // Explicit: every output index appears exactly once.
        std::array<int, rc::kRCCoupStateBytes> hits{};
        for (uint32_t i = 0; i < rc::kRCCoupStateBytes; ++i) {
            BOOST_REQUIRE(pi[i] < rc::kRCCoupStateBytes);
            hits[pi[i]] += 1;
        }
        for (uint32_t j = 0; j < rc::kRCCoupStateBytes; ++j) {
            BOOST_CHECK_EQUAL(hits[j], 1);
        }
    }
}

BOOST_AUTO_TEST_CASE(rc_coup_nonce_fresh_digest_differs)
{
    const auto h0 = MakeCoupHeader(100);
    const auto h1 = MakeCoupHeader(101);
    const uint256 d0 = rc::RecomputeCoupledPuzzleReference(h0, 0);
    const uint256 d1 = rc::RecomputeCoupledPuzzleReference(h1, 0);
    BOOST_CHECK(d0 != d1);
}

BOOST_AUTO_TEST_CASE(rc_coup_exact_gemm_inject)
{
    const auto header = MakeCoupHeader(42);
    const auto params = rc::MakeToyRCCoupParams();
    const uint256 cpu = rc::RecomputeCoupledPuzzleReference(header, 0, params);

    // Honest wrapping backend must match CPU (device replaces CPU with identical output).
    lt::ExactGemmBackend good;
    good.gemm_s8s8 = +[](const std::vector<int8_t>& L, const std::vector<int8_t>& R,
                         uint32_t rows, uint32_t inner, uint32_t cols,
                         std::vector<int32_t>& out) -> bool {
        out = lt::ExactGemmS8S8(L, R, rows, inner, cols);
        return true;
    };
    good.gemm_s32s8 = +[](const std::vector<int32_t>& L, const std::vector<int8_t>& R,
                          uint32_t rows, uint32_t inner, uint32_t cols,
                          std::vector<int32_t>& out) -> bool {
        out = lt::ExactGemmS32S8(L, R, rows, inner, cols);
        return true;
    };
    const uint256 with_good = rc::MineCoupledPuzzle(header, 0, params, good);
    BOOST_CHECK(cpu == with_good);

    // Wrong-but-successful backend diverges — no silent CPU rescue.
    lt::ExactGemmBackend bad;
    bad.gemm_s8s8 = &WrongGemmS8S8;
    bad.gemm_s32s8 = &WrongGemmS32S8;
    const uint256 with_bad = rc::MineCoupledPuzzle(header, 0, params, bad);
    BOOST_CHECK(cpu != with_bad);
}

BOOST_AUTO_TEST_CASE(rc_coup_exchange_rounds_v3_digest_and_bytes)
{
    // Default exchange_rounds=0 must preserve frozen V1/V2 goldens.
    constexpr const char* kToy =
        "7a7ce1065c7881aa2bd2295c26778ebf88c22432e91326f98d098c11885579ee";
    constexpr const char* kMed =
        "349175d557eba373cd59ea4cb5431d5710481cc8e7e121e90c2a0775df8b5f4c";
    const auto header = MakeCoupHeader(42);
    rc::RCCoupOptions zero_rounds;
    BOOST_CHECK_EQUAL(zero_rounds.exchange_rounds, 0u);
    BOOST_CHECK_EQUAL(
        rc::RecomputeCoupledPuzzleReference(header, 0, zero_rounds).GetHex(), kToy);
    BOOST_CHECK_EQUAL(
        rc::RecomputeCoupledPuzzleReference(header, 0, rc::MakeMediumRCCoupParams(), zero_rounds)
            .GetHex(),
        kMed);

    // exchange_rounds>0 changes the toy digest (V3 domain tag path).
    rc::RCCoupOptions with_rounds;
    with_rounds.exchange_rounds = 2;
    const uint256 d2 =
        rc::RecomputeCoupledPuzzleReference(header, 0, rc::MakeToyRCCoupParams(), with_rounds);
    BOOST_CHECK(!d2.IsNull());
    BOOST_CHECK(d2.GetHex() != kToy);

    rc::RCCoupOptions with_four = with_rounds;
    with_four.exchange_rounds = 4;
    const uint256 d4 =
        rc::RecomputeCoupledPuzzleReference(header, 0, rc::MakeToyRCCoupParams(), with_four);
    BOOST_CHECK(d2 != d4);

    // Dependency: corrupt a bank page mid-episode → fold-linked exchange seed
    // diverges → digest changes vs honest rounds path.
    rc::RCCoupOptions corrupt = with_rounds;
    corrupt.skip_bank_page = true;
    corrupt.skip_page_index = 0;
    const uint256 d_bad =
        rc::RecomputeCoupledPuzzleReference(header, 0, rc::MakeToyRCCoupParams(), corrupt);
    BOOST_CHECK(d_bad != d2);

    // material_exchange OFF → rounds ignored (mix-seed legacy / no V3 rounds).
    rc::RCCoupOptions no_mat = with_rounds;
    no_mat.material_exchange = false;
    const uint256 d_nomat =
        rc::RecomputeCoupledPuzzleReference(header, 0, rc::MakeToyRCCoupParams(), no_mat);
    // Decorative-off mix seed differs from default-ON decorative path; still ≠ d2.
    BOOST_CHECK(d_nomat != d2);

    // V3 options + production params → exactly 4 GiB exchange R/W estimate.
    const auto v3p = rc::MakeProductionV3RCCoupParams();
    const auto v3o = rc::MakeV3RCCoupOptions();
    BOOST_CHECK_EQUAL(v3o.exchange_rounds, 4u);
    BOOST_CHECK_EQUAL(v3o.exchange_rows, 128u);
    BOOST_CHECK(v3o.material_exchange);
    BOOST_CHECK_EQUAL(rc::TotalRCCoupExchangeBytes(v3p, v3o), 4ull << 30);
    BOOST_CHECK_EQUAL(rc::TotalRCCoupExchangeBytes(v3p, zero_rounds), 0ull);

    // Extreme int64 lanes through barrier tail + exchange rounds (XOR path, no UB).
    const auto toy = rc::MakeToyRCCoupParams();
    std::vector<int64_t> acc(toy.StateBytes(), 0);
    acc[0] = std::numeric_limits<int64_t>::min();
    acc[1] = std::numeric_limits<int64_t>::max();
    if (acc.size() > 2) acc[2] = -1;
    std::vector<int8_t> state(toy.StateBytes());
    uint256 root;
    const uint256 sigma = matmul::v4::DeriveSigma(header);
    BOOST_REQUIRE(
        rc::ApplyCoupledBarrierTail(sigma, /*barrier=*/0, toy, acc, state, &root, with_rounds));
    BOOST_CHECK(!root.IsNull());
}

BOOST_AUTO_TEST_CASE(rc_coup_medium_v3_golden_digest_stable)
{
    // FREEZE medium-V3 golden (ratio-preserving CI shape; uint64-wrap Mix).
    const auto header = MakeCoupHeader(42);
    const auto params = rc::MakeMediumV3RCCoupParams();
    BOOST_REQUIRE(rc::ValidateRCCoupParams(params));
    BOOST_REQUIRE(rc::RCCoupUseMixU64Wrap(params));
    const uint256 d1 = rc::RecomputeCoupledPuzzleReference(header, 0, params);
    const uint256 d2 = rc::RecomputeCoupledPuzzleReference(header, 0, params);
    BOOST_CHECK(!d1.IsNull());
    BOOST_CHECK(d1 == d2);
    // Pin filled after first honest CI run (Agent C); do not silently replace.
    BOOST_CHECK_EQUAL(d1.GetHex(),
                      "744fd3dfda6a58ddcd95474a9895cd2c6b17c2f1c2591848fc631eed78dea6a9");
}


BOOST_AUTO_TEST_CASE(rc_coup_full_schedule_page_coverage_unique)
{
    // When bank_pages == barriers×lobes×P, full-schedule page IDs over the
    // episode are unique and cover [0, bank_pages) exactly once.
    const uint256 sigma = matmul::v4::DeriveSigma(MakeCoupHeader(42));
    for (const auto& params :
         {rc::MakeProductionRCCoupParams(), rc::MakeProductionV3RCCoupParams(),
          rc::MakeMediumV3RCCoupParams()}) {
        const uint32_t tv =
            params.rows_per_lobe >= 32 ? rc::ENC_RC_V3 : rc::ENC_RC_V1;
        const uint64_t slots = static_cast<uint64_t>(params.barriers) * params.lobes *
                               params.pages_per_barrier_lobe;
        BOOST_REQUIRE_EQUAL(slots, params.bank_pages);
        std::vector<uint32_t> counts(params.bank_pages, 0);
        for (uint32_t b = 0; b < params.barriers; ++b) {
            for (uint32_t ell = 0; ell < params.lobes; ++ell) {
                const auto ids =
                    rc::SelectCoupledBankPageIds(b, ell, params, sigma, /*full=*/true, tv);
                BOOST_REQUIRE_EQUAL(ids.size(), params.pages_per_barrier_lobe);
                for (uint32_t id : ids) {
                    BOOST_REQUIRE(id < params.bank_pages);
                    counts[id] += 1;
                }
            }
        }
        for (uint32_t c : counts) {
            BOOST_CHECK_EQUAL(c, 1u);
        }
    }
}


BOOST_AUTO_TEST_CASE(rc_coup_accumulator_overflow_bounds)
{
    // Documented bound: |acc| ≤ P·W·127² after page sums; ×StateBytes post-mix.
    for (const auto& params :
         {rc::MakeToyRCCoupParams(), rc::MakeMediumRCCoupParams(),
          rc::MakeMediumV3RCCoupParams(), rc::MakeProductionRCCoupParams(),
          rc::MakeProductionV3RCCoupParams()}) {
        const uint64_t page_bound = rc::MaxRCCoupPageSumAbsBound(params);
        const uint64_t expect_page =
            static_cast<uint64_t>(params.pages_per_barrier_lobe) * params.lobe_width *
            static_cast<uint64_t>(rc::kRCCoupInt8ProdAbsMax);
        BOOST_CHECK_EQUAL(page_bound, expect_page);
        const uint64_t post = rc::MaxRCCoupPostMixAbsBound(params);
        BOOST_CHECK_EQUAL(post, page_bound * params.StateBytes());
        BOOST_CHECK(rc::RCCoupPostMixFitsInt64(params));
        // V2 M=1: signed mix. V3 M≥32: uint64 wrap (even though magnitude fits).
        BOOST_CHECK_EQUAL(rc::RCCoupUseMixU64Wrap(params), params.rows_per_lobe >= 32);
    }
}


BOOST_AUTO_TEST_SUITE_END()
