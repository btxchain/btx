// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_stage3_stream_endpoint.h>

#include <array>
#include <cstdlib>

namespace {

using namespace matmul::v4::rc;
namespace ar = air_recurse;

std::array<uint32_t, 8> Value()
{
    return {0x11111111U, 0x22222222U, 0x33333333U, 0x44444444U,
            0x55555555U, 0x66666666U, 0x77777777U, 0x88888888U};
}

std::array<uint32_t, 8> RootOf(RCStage3StreamFamily fam,
                               const RCStage3StreamEndpointManifest& m)
{
    std::array<uint32_t, 8> r{};
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        RCStage3StreamEndpointCommittedRoot(fam, m, r, &why), why);
    return r;
}

} // namespace

BOOST_AUTO_TEST_SUITE(matmul_v4_rc_stage3_stream_endpoint_tests)

// The §4 SHA256d Merkle fold (leaf(domain ‖ index ‖ value) folded up the
// authentication path) is value / sibling / index / family binding: any change
// to what is authenticated moves the committed root. This is the fold the
// in-AIR child pins its terminal output to; the scalar evaluation here is
// byte-identical to that pinned root and is what CS-level tamper detection keys
// on. Fast (O(path_len) SHA256d).
BOOST_AUTO_TEST_CASE(stream_endpoint_fold_root_binds_value_sibling_index_family)
{
    const RCStage3StreamFamily fam = RCStage3StreamFamily::CompleteStream;
    for (uint32_t path_len : {1U, 2U, 3U, 8U}) {
        const uint32_t leaf_index = 5U & ((1U << path_len) - 1U);
        const auto base =
            BuildRCStage3StreamEndpointCanonicalManifest(fam, Value(), leaf_index,
                                                         path_len);
        const auto root = RootOf(fam, base);

        // Tamper the stream value -> different root.
        auto mv = base;
        mv.stream_value[3] ^= 0x1U;
        BOOST_CHECK(RootOf(fam, mv) != root);

        // Tamper a sibling -> different root (path_len >= 1 always here).
        auto ms = base;
        ms.siblings[0][0] ^= 0xdeadbeefU;
        BOOST_CHECK(RootOf(fam, ms) != root);

        // Reorder / wrong leaf index (index is bound in the leaf preimage AND in
        // the direction bits) -> different root.
        auto mi = base;
        const uint32_t other = (leaf_index ^ 1U) & ((1U << path_len) - 1U);
        auto mi2 = BuildRCStage3StreamEndpointCanonicalManifest(fam, Value(),
                                                                other, path_len);
        mi2.stream_value = base.stream_value;
        BOOST_CHECK(RootOf(fam, mi2) != root);

        // Family domain separation -> different root under identical path.
        auto fam2 = RCStage3StreamFamily::DirectSha256d;
        auto mf = BuildRCStage3StreamEndpointCanonicalManifest(fam2, Value(),
                                                               leaf_index, path_len);
        mf.siblings = base.siblings;
        mf.directions = base.directions;
        BOOST_CHECK(RootOf(fam2, mf) != root);
    }
}

// The light, column-shiftable binding fragment C_rho direct-products: honest
// witness -> 0 CS violations (value alias holds; the eight root columns match
// the committed root); a wrong root witness or a broken value alias -> > 0.
// This is the deg-1 piece the registry composes inline; the SHA compute is the
// deferred recursive child. Instant (n_rows == 2).
BOOST_AUTO_TEST_CASE(stream_endpoint_light_binding_fragment_verifies_and_rejects)
{
    const RCStage3StreamFamily fam = RCStage3StreamFamily::XofCounter;
    const uint32_t leaf_index = 3U;
    const uint32_t path_len = 2U;
    const auto manifest =
        BuildRCStage3StreamEndpointCanonicalManifest(fam, Value(), leaf_index,
                                                     path_len);
    std::array<uint32_t, 8> root{};
    std::string why;
    BOOST_REQUIRE(
        RCStage3StreamEndpointCommittedRoot(fam, manifest, root, &why));

    const gkr_field::Fp3 ctl =
        gkr_field::Fp3::FromFp(gkr_field::FromU64(Value()[0]));
    const auto cs =
        BuildRCStage3StreamEndpointConstraintSystem(fam, leaf_index, root, path_len);
    const auto w = BuildRCStage3StreamEndpointWitness(root, ctl);

    // Honest.
    BOOST_CHECK_EQUAL(ar::CountWitnessViolationsOnH(cs, w), 0U);

    // Wrong root witness column.
    {
        auto bad = w;
        for (auto& cell : bad[kRCStage3StreamEndpointBindRootBase]) {
            cell = gkr_field::Add(cell, gkr_field::Fp3::One());
        }
        BOOST_CHECK_GT(ar::CountWitnessViolationsOnH(cs, bad), 0U);
    }

    // Wrong committed root baked into the CS (matching-child pin mismatch).
    {
        auto bad_root = root;
        bad_root[0] ^= 1U;
        const auto bad_cs = BuildRCStage3StreamEndpointConstraintSystem(
            fam, leaf_index, bad_root, path_len);
        BOOST_CHECK_GT(ar::CountWitnessViolationsOnH(bad_cs, w), 0U);
    }

    // Broken value alias (value column != leaf_value column).
    {
        auto bad = w;
        for (auto& cell : bad[kRCStage3StreamEndpointBindValueColumn]) {
            cell = gkr_field::Add(cell, gkr_field::Fp3::One());
        }
        BOOST_CHECK_GT(ar::CountWitnessViolationsOnH(cs, bad), 0U);
    }
}

// Opt-in (NOT run by default: name starts with 'slow_'): the full in-AIR
// SHA256d Merkle-fold CHILD honest -> 0 violations, stream-value tamper -> > 0.
// The vertical SHA builder's base-row commitment is minute-scale even at the
// minimal 2-lane schedule (measured > 4 min to build in Release), which is the
// concrete reason the fold is a deferred recursive child rather than inline.
BOOST_AUTO_TEST_CASE(slow_stream_endpoint_child_fold_verifies_in_air,
                     *boost::unit_test::disabled())
{
    // Guard: the vertical SHA build is minute-scale even at the 2-lane minimum,
    // so stay inert unless explicitly opted in (env BTX_RUN_SLOW_STREAM=1),
    // regardless of how this suite is selected.
    if (std::getenv("BTX_RUN_SLOW_STREAM") == nullptr) {
        BOOST_TEST_MESSAGE("slow_stream_endpoint_child_fold: skipped (set "
                           "BTX_RUN_SLOW_STREAM=1 to run)");
        return;
    }
    const RCStage3StreamFamily fam = RCStage3StreamFamily::CompleteStream;
    const auto manifest =
        BuildRCStage3StreamEndpointCanonicalManifest(fam, Value(), 0U, 0U);
    uint256 seed;
    std::fill(seed.begin(), seed.end(), static_cast<unsigned char>(0x42));
    std::string why;
    const auto c = RCStage3StreamEndpointClose(fam, manifest, seed, &why, true);
    BOOST_REQUIRE_MESSAGE(c.ok, why);
    BOOST_CHECK_EQUAL(c.child_violations, 0U);

    auto tampered = c.child_witness;
    bool changed = false;
    for (uint32_t col = 0; col < tampered.size() && !changed; ++col) {
        for (uint32_t row = 0; row < tampered[col].size(); ++row) {
            if (!gkr_field::IsZero(tampered[col][row])) {
                tampered[col][row] =
                    gkr_field::Add(tampered[col][row], gkr_field::Fp3::One());
                changed = true;
                break;
            }
        }
    }
    BOOST_REQUIRE(changed);
    BOOST_CHECK_GT(ar::CountWitnessViolationsOnH(c.child_cs, tampered), 0U);
}

BOOST_AUTO_TEST_SUITE_END()
