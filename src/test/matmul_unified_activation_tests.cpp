// Unified single-flag-day activation tests: v4Height == bmx4cHeight.
// Audit wave-3: the whole MatMul upgrade activates on ONE flag day. These pin
// that (a) equality is legal, (b) the BMX4C rescale (not v4's) fires at the
// unified fork, (c) the profile there is ENC_BMX4C, (d) the anchor is the fork
// height, (e) chainparams construction survives equal heights. Before the fix,
// three layers blocked this: the chainparams assert(bmx4c > v4) SIGABRT, the
// ValidateMatMulAsertParams bmx4c <= v4 fail-closed, and the MatMulAsert cascade
// applying the v4 (wrong) rescale first. All three are now relaxed to allow (and
// correctly handle) equality.
//
// Expectations encoded below:
//   - equality is legal (unified flag day, ENC-S8 phase never live);
//   - the BMX4C rescale (and ONLY it) fires at the unified fork block;
//   - the profile at the unified height is ENC_BMX4C;
//   - the ASERT anchor after the fork is the unified height.

#include <boost/test/unit_test.hpp>

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <matmul/matmul_v4_rc_gkr.h>
#include <matmul/matmul_v4_rc_stage3.h>
#include <pow.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <versionbits.h>

#include <limits>

BOOST_FIXTURE_TEST_SUITE(matmul_unified_activation_tests, BasicTestingSetup)

namespace {

// Minimal ASERT-enabled params with the unified single-height fork.
// Adjust field spellings to match consensus/params.h if they drift.
Consensus::Params UnifiedParams(int32_t fork_height)
{
    Consensus::Params p{};
    p.fMatMulPOW = true;
    p.powLimit = uint256{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
    p.nPowTargetSpacing = 90;
    p.nMatMulAsertHeight = 0;
    p.nMatMulAsertHalfLife = 3'600;
    p.nMatMulAsertBootstrapFactor = 1;
    p.nMatMulAsertRetuneHeight = std::numeric_limits<int32_t>::max();
    p.nMatMulAsertRetuneHardeningFactor = 1;
    p.nMatMulAsertRetune2Height = std::numeric_limits<int32_t>::max();
    p.nMatMulAsertRetune2TargetNum = 1;
    p.nMatMulAsertRetune2TargetDen = 1;
    p.nMatMulAsertHalfLifeUpgradeHeight = std::numeric_limits<int32_t>::max();
    p.nMatMulAsertHalfLifeUpgrade = 3'600;
    // UNIFIED FLAG DAY: both forks at one height.
    p.nMatMulV4Height = fork_height;
    p.nMatMulBMX4CHeight = fork_height;
    // v4 rescale must be inert under unified activation (ENC-S8 never live);
    // the BMX4C ratio carries the full v3 -> ENC-BMX4C work-unit correction.
    p.nMatMulV4AsertRescaleNum = 1;
    p.nMatMulV4AsertRescaleDen = 1;
    p.nMatMulBMX4CAsertRescaleNum = 3; // distinguishable 3/7 sentinel ratio
    p.nMatMulBMX4CAsertRescaleDen = 7;
    return p;
}

// Public-network MatMul v4.7 Epoch A: one atomic v3 -> Profile-1 ExactReplay
// cutover. The older v4/BMX4C ratios are inert and RC owns the calibration.
Consensus::Params EpochAParams(int32_t fork_height)
{
    auto p = UnifiedParams(fork_height);
    const int32_t disabled{std::numeric_limits<int32_t>::max()};
    p.nMatMulBMX4CAsertRescaleNum = 1;
    p.nMatMulBMX4CAsertRescaleDen = 1;
    p.nMatMulRCHeight = fork_height;
    p.nMatMulRCAsertRescaleNum = 5; // distinguishable Epoch-A sentinel
    p.nMatMulRCAsertRescaleDen = 11;
    p.nMatMulPreHashEpsilonBits = 18;
    p.nMatMulDRLTHeight = disabled;
    p.nMatMulRCCoupledHeight = disabled;
    p.nMatMulRCProfile = 1;
    p.fMatMulRCUseToyDims = false;
    p.fMatMulRCCoupledUseToyDims = false;
    p.fMatMulLTSealAsPoW = false;
    p.nMatMulHeaderPoWDiscountBits = std::numeric_limits<uint32_t>::max();
    return p;
}

// Build a linear header chain [0..count-1] with constant nBits/spacing.
// (Mirrors the CBlockIndex-array helpers already used in pow_tests.cpp;
// reuse that suite's helper if it is exported.)
struct HeaderChain {
    std::vector<CBlockIndex> idx;
    explicit HeaderChain(size_t count, uint32_t bits, int64_t spacing)
        : idx(count)
    {
        for (size_t i = 0; i < count; ++i) {
            idx[i].pprev = i ? &idx[i - 1] : nullptr;
            idx[i].nHeight = static_cast<int>(i);
            idx[i].nTime = 1'700'000'000 + static_cast<int64_t>(i) * spacing;
            idx[i].nBits = bits;
            idx[i].BuildSkip();
        }
    }
    const CBlockIndex* tip() const { return &idx.back(); }
    const CBlockIndex* at(size_t h) const { return &idx[h]; }
};

} // namespace

// (A) Profile selector: at the unified height the live profile must be
// ENC_BMX4C — there is no ENC-S8 phase. Passes already today (selector is
// >=-based); pinned here so a fix can't regress it.
BOOST_AUTO_TEST_CASE(unified_height_profile_is_bmx4c)
{
    const auto p = UnifiedParams(100);
    BOOST_CHECK(p.IsMatMulV4Active(100));
    BOOST_CHECK(p.IsBMX4CActive(100));
    BOOST_CHECK(p.GetMatMulEncodingProfile(100) == Consensus::MatMulEncodingProfile::ENC_BMX4C);
    // Below the fork: v3 rules; the "ENC_S8 by default" return value is
    // meaningless there per the params.h contract (callers gate on v4 first).
    BOOST_CHECK(!p.IsMatMulV4Active(99));
}

// (B) THE CORE POST-FIX CHECK: at next_height == unified fork height,
// GetNextWorkRequired must apply the BMX4C rescale ratio (3/7 here) to the
// parent target — NOT the v4 ratio, NOT powLimit-fail-closed, NOT a silent
// pass-through.
// PRE-FIX: this returns powLimit (ValidateMatMulAsertParams ordering guard
// fails closed), so the BOOST_CHECK_EQUAL below fails loudly.
BOOST_AUTO_TEST_CASE(unified_fork_block_gets_bmx4c_rescale)
{
    const int32_t H = 100;
    const auto p = UnifiedParams(H);
    const uint32_t parent_bits = 0x1e0fffff;
    HeaderChain chain(H, parent_bits, p.nPowTargetSpacing); // tip = H-1

    CBlockHeader next{};
    next.nTime = chain.tip()->nTime + p.nPowTargetSpacing;
    const unsigned int got = GetNextWorkRequired(chain.tip(), &next, p);

    arith_uint256 parent_target{};
    parent_target.SetCompact(parent_bits);
    arith_uint256 want = parent_target * 3 / 7; // BMX4C ratio, not v4's 1/1
    const arith_uint256 pow_limit{UintToArith256(p.powLimit)};
    if (want > pow_limit) want = pow_limit;

    BOOST_CHECK_EQUAL(got, want.GetCompact());
    // Explicitly assert the two known-bad pre-fix outcomes are absent:
    BOOST_CHECK(got != pow_limit.GetCompact());     // no fail-closed collapse
    BOOST_CHECK(got != parent_bits);                // rescale not silently skipped
}

// (C) Non-fork heights above the unified fork must NOT fail closed to
// powLimit: ValidateMatMulAsertParams must accept equality so ordinary ASERT
// retargeting resumes at H+1 anchored on the (rescaled) fork block H.
BOOST_AUTO_TEST_CASE(unified_post_fork_asert_not_fail_closed)
{
    const int32_t H = 100;
    const auto p = UnifiedParams(H);
    const arith_uint256 pow_limit{UintToArith256(p.powLimit)};
    // Chain through H+5 at exact target spacing: ASERT should hold the anchor
    // target steady, and it must not be powLimit.
    const uint32_t bits = 0x1e0fffff;
    HeaderChain chain(H + 6, bits, p.nPowTargetSpacing);
    CBlockHeader next{};
    next.nTime = chain.tip()->nTime + p.nPowTargetSpacing;
    const unsigned int got = GetNextWorkRequired(chain.tip(), &next, p);
    BOOST_CHECK(got != pow_limit.GetCompact());
}

// (D) Anchor selection: once the tip passes the unified height, the ASERT
// anchor must be exactly the unified fork height (the rescaled block), for
// both the "v4 anchor" and "bmx4c anchor" bookkeeping — they coincide.
// Requires LatestMatMulAsertPreUpgradeAnchorHeight (or the HalfLifeInfo
// wrapper GetMatMulAsertHalfLifeInfo) to be visible to tests.
BOOST_AUTO_TEST_CASE(unified_anchor_is_fork_height)
{
    const int32_t H = 100;
    const auto p = UnifiedParams(H);
    HeaderChain chain(H + 3, 0x1e0fffff, p.nPowTargetSpacing);
    const auto info = GetMatMulAsertHalfLifeInfo(chain.tip(), p);
    BOOST_CHECK_EQUAL(info.current_anchor_height, H);
}

// (E) Construction invariants must ACCEPT equality after the fix. This
// exercises the real chainparams path via the regtest override knobs
// (-regtestmatmulv4height / -regtestbmx4cheight equivalents). PRE-FIX this
// SIGABRTs in AssertBMX4CConstructionInvariants — keep it last / guarded.
BOOST_AUTO_TEST_CASE(unified_chainparams_construction_survives)
{
    CChainParams::RegTestOptions opts{};
    opts.matmul_v4_height = 100;
    opts.matmul_bmx4c_height = 100; // unified flag day
    // This test pins the original v3 -> ENC-BMX4C unified transition. Regtest
    // now enables DRLT + seal-as-PoW at height 100 by default, so disable that
    // later profile explicitly instead of making a stale height-100 assertion.
    opts.matmul_drlt_height = std::numeric_limits<int32_t>::max();
    opts.matmul_lt_seal_as_pow = false;
    const auto params = CChainParams::RegTest(opts);
    BOOST_REQUIRE(params != nullptr);
    BOOST_CHECK(params->GetConsensus().GetMatMulEncodingProfile(100) ==
                Consensus::MatMulEncodingProfile::ENC_BMX4C);
}

// (F) The withdrawn HeaderPoW bit is never forced by ComputeBlockVersion,
// before, at, or after the unified v4 flag day.
BOOST_AUTO_TEST_CASE(unified_header_pow_commit_bit_not_forced_in_block_version)
{
    // WITHDRAWN: ComputeBlockVersion must NOT OR bit 26 (pre-activation wire split).
    const int32_t H = 100;
    const auto p = UnifiedParams(H);
    HeaderChain chain(H + 2, 0x1e0fffff, p.nPowTargetSpacing);
    VersionBitsCache cache;

    const int32_t pre = cache.ComputeBlockVersion(chain.at(H - 2), p);
    BOOST_CHECK_EQUAL(pre & CBlockHeader::BTX_HEADER_POW_COMMIT_VERSION_BIT, 0);

    const int32_t at_fork = cache.ComputeBlockVersion(chain.at(H - 1), p);
    BOOST_CHECK_EQUAL(at_fork & CBlockHeader::BTX_HEADER_POW_COMMIT_VERSION_BIT, 0);

    const int32_t post = cache.ComputeBlockVersion(chain.at(H), p);
    BOOST_CHECK_EQUAL(post & CBlockHeader::BTX_HEADER_POW_COMMIT_VERSION_BIT, 0);
}

// (G) The launch tuple is a direct atomic transition to ENC_RC Profile 1.
// HeaderPoW remains disabled because its nonce is not serialized.
BOOST_AUTO_TEST_CASE(epoch_a_tuple_selects_profile1_exact_replay_path)
{
    const int32_t H = 100;
    const auto p = EpochAParams(H);

    BOOST_CHECK(p.IsMatMulV47EpochAActivationTuple());
    BOOST_CHECK(!p.IsMatMulRCFamilyActive(H - 1));
    BOOST_CHECK(p.IsMatMulRCFamilyActive(H));
    BOOST_CHECK(p.GetMatMulEncodingProfile(H) ==
                Consensus::MatMulEncodingProfile::ENC_RC);
    BOOST_CHECK_EQUAL(p.nMatMulRCProfile, 1U);
    BOOST_CHECK(!p.IsMatMulHeaderPoWEnabled());
    BOOST_CHECK(ValidateMatMulAsertParams(p, H));
    // A structurally coherent tuple is not by itself an activation
    // authorization: the GPU mine/reseal/validate lifecycle and its ASERT
    // calibration are a separate gate. That gate has now been ratified for
    // Epoch A, so this pins it as true rather than false -- the point of the
    // assertion is that the flag is a deliberate, reviewed value, not that it
    // has one particular setting forever.
    BOOST_CHECK(Consensus::BTX_MATMUL_V47_GPU_LIFECYCLE_GATE_RATIFIED);
    BOOST_CHECK(Consensus::BTX_MATMUL_NO_INVERSION_GATE_RATIFIED);
}

// (H) At the atomic Epoch-A height, RC—not either superseded v4 profile—owns
// the one-time difficulty calibration.
BOOST_AUTO_TEST_CASE(epoch_a_fork_block_gets_rc_rescale)
{
    const int32_t H = 100;
    const auto p = EpochAParams(H);
    const uint32_t parent_bits = 0x1e0fffff;
    HeaderChain chain(H, parent_bits, p.nPowTargetSpacing);

    CBlockHeader next{};
    next.nTime = chain.tip()->nTime + p.nPowTargetSpacing;
    const unsigned int got = GetNextWorkRequired(chain.tip(), &next, p);

    arith_uint256 parent_target{};
    parent_target.SetCompact(parent_bits);
    const arith_uint256 pow_limit{UintToArith256(p.powLimit)};
    const auto want{DeriveMatMulEpochATransitionTarget(
        parent_target, p.nMatMulPreHashEpsilonBits, 5, 11, pow_limit)};

    BOOST_REQUIRE(want.has_value());
    BOOST_CHECK_EQUAL(got, want->GetCompact());
    BOOST_CHECK(got != parent_bits);
}

BOOST_AUTO_TEST_CASE(epoch_a_target_derivation_uses_live_parent_lottery)
{
    const arith_uint256 pow_limit{~arith_uint256{0}};
    const arith_uint256 parent{arith_uint256{1} << 200};
    const auto exact{DeriveMatMulEpochATransitionTarget(
        parent, 18, 1, 1, pow_limit)};
    BOOST_REQUIRE(exact.has_value());
    BOOST_CHECK(*exact == (arith_uint256{1} << 162));

    const auto different_parent{DeriveMatMulEpochATransitionTarget(
        arith_uint256{1} << 199, 18, 1, 1, pow_limit)};
    BOOST_REQUIRE(different_parent.has_value());
    BOOST_CHECK(*different_parent == (arith_uint256{1} << 160));
    BOOST_CHECK(*different_parent != *exact);

    // Saturating the retired pre-hash gate is still handled exactly.
    const auto saturated{DeriveMatMulEpochATransitionTarget(
        arith_uint256{1} << 255, 18, 1, 1, pow_limit)};
    BOOST_REQUIRE(saturated.has_value());
    BOOST_CHECK(*saturated == ((arith_uint256{1} << 255) - 1));

    BOOST_CHECK(!DeriveMatMulEpochATransitionTarget(
        parent, 18, 0, 1, pow_limit).has_value());
    BOOST_CHECK(!DeriveMatMulEpochATransitionTarget(
        parent, 18, 1, 0, pow_limit).has_value());
}


// FIXED VECTOR at the published calibration difficulty. Everything else in
// this suite tests the helper against synthetic inputs, i.e. against itself.
// This case pins the SHIPPED constant against an externally computed
// expectation so a future value of the wrong KIND fails here rather than on
// mainnet.
BOOST_AUTO_TEST_CASE(epoch_a_installed_coefficient_realizes_expected_loosen)
{
    // Mainnet nBits at the calibration sample, epsilon = 18.
    arith_uint256 parent{};
    parent.SetCompact(0x1c487c56);
    BOOST_REQUIRE(parent > 0);

    const auto main{CreateChainParams(ArgsManager{}, ChainType::MAIN)};
    const auto& p{main->GetConsensus()};
    const uint32_t eps{p.GetMatMulPreHashEpsilonBitsForHeight(p.nMatMulRCHeight - 1)};
    BOOST_CHECK_EQUAL(eps, 18u);

    uint64_t an{0}, ad{0};
    BOOST_REQUIRE(ReduceRescaleRatioToU64(p.nMatMulRCAsertRescaleNum,
                                          p.nMatMulRCAsertRescaleDen, an, ad));
    // The measured coefficient exceeds uint32; the Epoch-A path must not clip it.
    BOOST_CHECK_GT(an, static_cast<uint64_t>(std::numeric_limits<uint32_t>::max()));

    const auto derived{DeriveMatMulEpochATransitionTarget(
        parent, eps, an, ad, UintToArith256(p.powLimit))};
    BOOST_REQUIRE(derived.has_value());

    // Independently calculated integer vector for parent 0x1c487c56,
    // epsilon=18 and provisional C=6'931'159'304. Pin both the full target and its compact
    // encoding; a broad order-of-magnitude band would accept a materially
    // different consensus difficulty.
    static constexpr uint32_t EXPECTED_COMPACT{0x1f00847c};
    static constexpr const char* EXPECTED_TARGET{
        "0000847c761329b56486ac800000000000000000000000000000000000000000"};
    BOOST_CHECK_EQUAL(derived->GetHex(), EXPECTED_TARGET);
    BOOST_CHECK_EQUAL(derived->GetCompact(), EXPECTED_COMPACT);

    // k = p_rc / p, computed from the targets rather than from the model, so
    // this is an independent check of the helper's output.
    const arith_uint256 k_ratio = *derived / parent;
    BOOST_CHECK_EQUAL(k_ratio.GetLow64(), 119'783U);
    // Measured endpoints: Metal ~19'900, CUDA ~119'800. Installed at the CUDA
    // figure. A value of the WRONG KIND lands far outside this band: supplying
    // the realized loosen k instead of the attempt-rate ratio C yields ~2,
    // which is the 1/q under-loosen that would stall the chain for weeks.
    BOOST_CHECK(k_ratio > arith_uint256{50'000});
    BOOST_CHECK(k_ratio < arith_uint256{200'000});

    // The transition must loosen, never tighten, and must respect powLimit.
    BOOST_CHECK(*derived > parent);
    BOOST_CHECK(*derived <= UintToArith256(p.powLimit));

    // Exercise the real fork dispatcher with the published mainnet tuple. The
    // transition branch depends only on the live parent's height/nBits, so a
    // single synthetic parent is sufficient and avoids a 182k-entry fixture.
    CBlockIndex parent_index;
    parent_index.nHeight = p.nMatMulRCHeight - 1;
    parent_index.nBits = 0x1c487c56;
    parent_index.nTime = 1'700'000'000;
    CBlockHeader next;
    next.nTime = parent_index.nTime + p.nPowTargetSpacing;
    BOOST_CHECK_EQUAL(
        GetNextWorkRequired(&parent_index, &next, p),
        EXPECTED_COMPACT);
}

// A coefficient of the wrong KIND must be visibly wrong, not subtly wrong.
BOOST_AUTO_TEST_CASE(epoch_a_supplying_the_realized_loosen_is_catastrophic)
{
    arith_uint256 parent{};
    parent.SetCompact(0x1c487c56);
    const auto main{CreateChainParams(ArgsManager{}, ChainType::MAIN)};
    const auto& p{main->GetConsensus()};

    // Someone installs k (~121'581) where C (~6.93e9) belongs.
    const auto wrong{DeriveMatMulEpochATransitionTarget(
        parent, 18, 121'581, 1, UintToArith256(p.powLimit))};
    BOOST_REQUIRE(wrong.has_value());
    const arith_uint256 wrong_ratio = *wrong / parent;
    // Realized loosen collapses to single digits instead of ~1.2e5.
    BOOST_CHECK(wrong_ratio < arith_uint256{100});
}


// The Epoch-A wide derivation is selected by IsMatMulV47EpochAActivationTuple,
// and NOTHING outside this file exercises that selection. Regtest defaults are
// v4=100, BMX4C=100, RC=101 -- not equal, so the tuple is false and MatMulAsert
// takes the ScaleTargetByTimespan branch instead. Every functional test that
// crosses the RC boundary also runs -regtestrctoydims=1, which falsifies the
// tuple as well. Without this case the branch that will run on mainnet at the
// activation height is chosen by no test at all.
BOOST_AUTO_TEST_CASE(epoch_a_tuple_selects_the_wide_transition_on_regtest)
{
    ArgsManager args;
    // NOT -regtestrcunifiedheight: that sets RC *and the COUPLED height*, and
    // the Epoch-A tuple requires the coupled height DISABLED, so the "unified"
    // option actively prevents the shape it sounds like it produces. The three
    // heights have to be set individually.
    args.ForceSetArg("-regtestmatmulltsealaspow", "0");
    args.ForceSetArg("-regtestdrltheight", "2147483647");
    args.ForceSetArg("-regtestmatmulv4height", "200");
    args.ForceSetArg("-regtestbmx4cheight", "200");
    args.ForceSetArg("-regtestrcheight", "200");
    args.ForceSetArg("-regtestrctoydims", "0");
    // Inert on its own (the coupled height is disabled) but still a conjunct of
    // the tuple, and regtest defaults it true.
    args.ForceSetArg("-regtestrccoupledtoydims", "0");
    args.ForceSetArg("-regtestrcprofile", "1");
    const auto params{CreateChainParams(args, ChainType::REGTEST)};
    const auto& p{params->GetConsensus()};

    BOOST_REQUIRE_EQUAL(p.nMatMulV4Height, 200);
    BOOST_REQUIRE_EQUAL(p.nMatMulBMX4CHeight, 200);
    BOOST_REQUIRE_EQUAL(p.nMatMulRCHeight, 200);
    // Check each conjunct individually: a bare check on the compound predicate
    // reports only "false" and leaves the operator guessing which knob a future
    // regtest default change broke.
    const int32_t disabled{std::numeric_limits<int32_t>::max()};
    BOOST_CHECK_EQUAL(p.nMatMulDRLTHeight, disabled);
    BOOST_CHECK_EQUAL(p.nMatMulRCCoupledHeight, disabled);
    BOOST_CHECK_EQUAL(p.nMatMulRCProfile, 1);
    BOOST_CHECK(!p.fMatMulRCUseToyDims);
    BOOST_CHECK(!p.fMatMulRCCoupledUseToyDims);
    BOOST_CHECK(!p.fMatMulLTSealAsPoW);
    BOOST_CHECK(!p.IsMatMulHeaderPoWEnabled());
    BOOST_CHECK_EQUAL(p.nMatMulV4AsertRescaleNum, p.nMatMulV4AsertRescaleDen);
    BOOST_CHECK_EQUAL(p.nMatMulBMX4CAsertRescaleNum,
                      p.nMatMulBMX4CAsertRescaleDen);
    // This is the assertion that matters: the wide Epoch-A path is reachable
    // from a real chainparams object, not only from hand-built params.
    BOOST_CHECK(p.IsMatMulV47EpochAActivationTuple());

    // And the derivation itself produces a loosened, clamped target from a
    // realistic parent rather than failing closed.
    arith_uint256 parent{};
    parent.SetCompact(0x1d00ffff);
    uint64_t an{0}, ad{0};
    BOOST_REQUIRE(ReduceRescaleRatioToU64(p.nMatMulRCAsertRescaleNum,
                                          p.nMatMulRCAsertRescaleDen, an, ad));
    const auto derived{DeriveMatMulEpochATransitionTarget(
        parent, p.GetMatMulPreHashEpsilonBitsForHeight(199), an, ad,
        UintToArith256(p.powLimit))};
    BOOST_REQUIRE(derived.has_value());
    BOOST_CHECK(*derived <= UintToArith256(p.powLimit));
    BOOST_CHECK(*derived > 0);
}

// Pin the complete public Epoch-A contract from the real mainnet parameters.
// The activation height itself is intentionally not duplicated here: release
// preparation may move it forward to preserve deployment runway, but it must
// remain one finite atomic height for v4, BMX4C, and RC. Everything else below
// is the consensus shape that may not drift when that scheduling-only value is
// updated.
BOOST_AUTO_TEST_CASE(mainnet_epoch_a_complete_consensus_tuple)
{
    const auto main{CreateChainParams(ArgsManager{}, ChainType::MAIN)};
    const auto& p{main->GetConsensus()};
    const int32_t disabled{std::numeric_limits<int32_t>::max()};
    const int32_t height{p.nMatMulRCHeight};

    BOOST_REQUIRE_NE(height, disabled);
    BOOST_CHECK_EQUAL(p.nMatMulV4Height, height);
    BOOST_CHECK_EQUAL(p.nMatMulBMX4CHeight, height);
    BOOST_CHECK_EQUAL(p.nMatMulRCHeight, height);
    BOOST_CHECK_EQUAL(p.nMatMulDRLTHeight, disabled);
    BOOST_CHECK_EQUAL(p.nMatMulRCCoupledHeight, disabled);

    BOOST_CHECK_EQUAL(p.nMatMulV4Dimension, 4096U);
    BOOST_CHECK_EQUAL(p.nMatMulRCProfile, 1U);
    BOOST_CHECK(!p.fMatMulRCUseToyDims);
    BOOST_CHECK(!p.fMatMulRCCoupledUseToyDims);
    BOOST_CHECK(!p.fMatMulLTSealAsPoW);
    BOOST_CHECK(!p.IsMatMulHeaderPoWEnabled());
    BOOST_CHECK_EQUAL(p.nMatMulHeaderPoWDiscountBits,
                      std::numeric_limits<uint32_t>::max());

    BOOST_CHECK_EQUAL(p.nMatMulV4AsertRescaleNum, 1);
    BOOST_CHECK_EQUAL(p.nMatMulV4AsertRescaleDen, 1);
    BOOST_CHECK_EQUAL(p.nMatMulBMX4CAsertRescaleNum, 1);
    BOOST_CHECK_EQUAL(p.nMatMulBMX4CAsertRescaleDen, 1);
    BOOST_CHECK_EQUAL(p.nMatMulRCAsertRescaleNum, 6'931'159'304LL);
    BOOST_CHECK_EQUAL(p.nMatMulRCAsertRescaleDen, 1);
    BOOST_CHECK_EQUAL(
        p.GetMatMulPreHashEpsilonBitsForHeight(height - 1), 18U);

    BOOST_CHECK(!p.IsMatMulV4Active(height - 1));
    BOOST_CHECK(!p.IsMatMulRCFamilyActive(height - 1));
    BOOST_CHECK(p.IsMatMulV4Active(height));
    BOOST_CHECK(p.IsBMX4CActive(height));
    BOOST_CHECK(p.IsMatMulRCFamilyActive(height));
    BOOST_CHECK_EQUAL(p.GetMatMulEncodingProfile(height),
                      Consensus::MatMulEncodingProfile::ENC_RC);
    BOOST_CHECK(p.IsMatMulV47EpochAActivationTuple());
    BOOST_CHECK(ValidateMatMulAsertParams(p, height));

    BOOST_CHECK(Consensus::BTX_MATMUL_NO_INVERSION_GATE_RATIFIED);
    BOOST_CHECK(Consensus::BTX_MATMUL_V47_GPU_LIFECYCLE_GATE_RATIFIED);
    BOOST_CHECK(!matmul::v4::rc::kRCGkrFormalSoundnessReady);
    BOOST_CHECK(!matmul::v4::rc::kRCStage3ProductionProgramRegistryReady);
    BOOST_CHECK(!matmul::v4::rc::kRCStage3SuccinctAuthorityReady);
}

// Mainnet's Epoch-A tuple must not leak into public test networks. They remain
// neutral and disabled until each network receives its own deliberate height,
// calibration, and ratification change.
BOOST_AUTO_TEST_CASE(public_test_networks_remain_epoch_a_neutral)
{
    const int32_t disabled{std::numeric_limits<int32_t>::max()};
    for (const ChainType chain :
         {ChainType::TESTNET, ChainType::TESTNET4, ChainType::SIGNET}) {
        const auto params{CreateChainParams(ArgsManager{}, chain)};
        const auto& p{params->GetConsensus()};

        BOOST_CHECK_EQUAL(p.nMatMulV4Height, disabled);
        BOOST_CHECK_EQUAL(p.nMatMulBMX4CHeight, disabled);
        BOOST_CHECK_EQUAL(p.nMatMulDRLTHeight, disabled);
        BOOST_CHECK_EQUAL(p.nMatMulRCHeight, disabled);
        BOOST_CHECK_EQUAL(p.nMatMulRCCoupledHeight, disabled);
        BOOST_CHECK_EQUAL(p.nMatMulV4AsertRescaleNum, 1);
        BOOST_CHECK_EQUAL(p.nMatMulV4AsertRescaleDen, 1);
        BOOST_CHECK_EQUAL(p.nMatMulBMX4CAsertRescaleNum, 1);
        BOOST_CHECK_EQUAL(p.nMatMulBMX4CAsertRescaleDen, 1);
        BOOST_CHECK_EQUAL(p.nMatMulRCAsertRescaleNum, 1);
        BOOST_CHECK_EQUAL(p.nMatMulRCAsertRescaleDen, 1);
        BOOST_CHECK_EQUAL(p.nMatMulRCProfile, 1U);
        BOOST_CHECK(!p.fMatMulRCUseToyDims);
        BOOST_CHECK(!p.fMatMulRCCoupledUseToyDims);
        BOOST_CHECK(!p.fMatMulLTSealAsPoW);
        BOOST_CHECK(!p.IsMatMulHeaderPoWEnabled());
        BOOST_CHECK(!p.IsMatMulV47EpochAActivationTuple());
    }
}

BOOST_AUTO_TEST_SUITE_END()
