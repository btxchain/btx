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
    const auto params = CChainParams::RegTest(opts);
    BOOST_REQUIRE(params != nullptr);
    BOOST_CHECK(params->GetConsensus().GetMatMulEncodingProfile(100) ==
                Consensus::MatMulEncodingProfile::ENC_BMX4C);
}

// (F) Header-PoW commitment version bit rides the unified v4 flag day via
// ComputeBlockVersion: required at/above fork, absent below.
BOOST_AUTO_TEST_CASE(unified_header_pow_commit_bit_in_block_version)
{
    const int32_t H = 100;
    const auto p = UnifiedParams(H);
    HeaderChain chain(H + 2, 0x1e0fffff, p.nPowTargetSpacing);
    VersionBitsCache cache;

    const int32_t pre = cache.ComputeBlockVersion(chain.at(H - 2), p); // next height H-1
    BOOST_CHECK_EQUAL(pre & CBlockHeader::BTX_HEADER_POW_COMMIT_VERSION_BIT, 0);

    const int32_t at_fork = cache.ComputeBlockVersion(chain.at(H - 1), p); // next height H
    BOOST_CHECK((at_fork & CBlockHeader::BTX_HEADER_POW_COMMIT_VERSION_BIT) != 0);

    const int32_t post = cache.ComputeBlockVersion(chain.at(H), p); // next height H+1
    BOOST_CHECK((post & CBlockHeader::BTX_HEADER_POW_COMMIT_VERSION_BIT) != 0);
}

BOOST_AUTO_TEST_SUITE_END()
