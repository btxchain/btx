// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ============================================================================
// g2 / recursive_aggregation_ready — the CompositionLink in-CS closer.
//
// CompositionLink (role 32) was the ONE required role of a Composed statement
// with no role AIR at all. RCStage3RoleIsInCsClosable(CompositionLink) was
// false, so RebuildRCStage3RoleAirConstraintSystem short-circuited with
// "no_role_air:composition:link" and the recursive registry returned
// "complete_air_unavailable" — a Composed statement could NEVER be fully
// section-verified, and no aggregation over it could ever be complete.
//
// These tests are the NON-VACUITY evidence for the closer that replaces that
// hole. The registry-completeness gate they exercise
// (RCStage3CountInCsClosers == RCStage3RequiredInCsOpeningBlocks) is exactly
// the gate that a zero-closer stub AIR would have satisfied silently had
// CompositionLink kept its empty endpoint list, so the count is checked
// explicitly AND every closer is separately shown to bite.
// ============================================================================

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_fri_ext3_alg.h>
#include <matmul/matmul_v4_rc_gkr_field_ext3.h>
#include <matmul/matmul_v4_rc_stage3_recursive.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>
#include <matmul/matmul_v4_rc_stage3_role_sections.h>

#include <test/util/setup_common.h>

#include <array>
#include <string>
#include <vector>

namespace {

using namespace matmul::v4::rc;
using Fp3 = gkr_field::Fp3;
namespace ar = matmul::v4::rc::air_recurse;
namespace aq = matmul::v4::rc::air_quotient;
using AlgB3 = aq::AirFriBackendAlg<Fp3>;

std::array<uint32_t, 8> Root8(uint32_t base)
{
    std::array<uint32_t, 8> r{};
    for (uint32_t i = 0; i < 8; ++i) r[i] = base * 131u + i * 17u + 3u;
    return r;
}

Fp3 Leg(uint64_t v) { return Fp3::FromFp(gkr_field::FromU64(v)); }

/** The honest product both halves of this file work from. */
RCStage3RoleAirProduct HonestProduct()
{
    std::string why;
    auto p = BuildRCStage3CompositionLinkRoleAir(
        Leg(0x51ull), Leg(0x77ull), Root8(2), Root8(5), &why);
    BOOST_REQUIRE_MESSAGE(p.ok, p.note + " " + why);
    return p;
}

ar::ChildPublicInputs PinFor(const RCStage3RoleAirProduct& p)
{
    ar::ChildPublicInputs pin;
    pin.child_n_rows = p.cs.n_rows;
    pin.child_w = p.cs.n_columns;
    pin.endpoint_authority_roots = p.endpoint_committed_roots;
    return pin;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_stage3_composition_link_air_tests,
                         BasicTestingSetup)

// ---------------------------------------------------------------------------
// The registry now resolves a real C_rho for CompositionLink, and the
// completeness gate compares against a NONZERO closer count.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(composition_link_resolves_a_real_role_air_with_real_closers)
{
    BOOST_CHECK(RCStage3RoleIsInCsClosable(
        RCStage3RelationRole::CompositionLink));

    // The count MUST NOT come from RequiredRCStage3RelationEndpoints, which is
    // still empty for this role — if it did, the gate would compare against 0
    // and a zero-closer AIR would pass.
    BOOST_CHECK(RequiredRCStage3RelationEndpoints(
                    RCStage3RelationRole::CompositionLink)
                    .empty());
    BOOST_CHECK_EQUAL(
        RCStage3RequiredInCsOpeningBlocks(
            RCStage3RelationRole::CompositionLink),
        kRCStage3CompositionLinkInCsClosers);
    BOOST_CHECK_EQUAL(kRCStage3CompositionLinkInCsClosers, 3U);

    const RCStage3RoleAirProduct p = HonestProduct();
    BOOST_CHECK_EQUAL(p.cs.n_rows, 2U);
    BOOST_CHECK_EQUAL(p.witness.size(), p.cs.n_columns);
    BOOST_CHECK_EQUAL(p.endpoint_committed_roots.size(),
                      kRCStage3CompositionLinkInCsClosers);

    // Two stream_endpoint:value_alias closers + one sponge digest_pin family.
    BOOST_CHECK_EQUAL(RCStage3CountInCsClosers(p.cs),
                      kRCStage3CompositionLinkInCsClosers);

    // The relation constraints are present and named.
    uint32_t recompose = 0, pins = 0;
    for (const auto& c : p.cs.constraints) {
        if (c.name == nullptr) continue;
        const std::string n(c.name);
        if (n == "composition_link:episode_leg_recompose" ||
            n == "composition_link:coupled_leg_recompose") {
            ++recompose;
        } else if (n == "composition_link:index_pin" ||
                   n == "composition_link:pad_pin") {
            ++pins;
        }
    }
    BOOST_CHECK_EQUAL(recompose, 2U);
    BOOST_CHECK_EQUAL(pins, 2U);

    // The immutable registry the recursive verifier uses resolves it, and the
    // resolved CS is shape-identical to the proved product.
    aq::AirConstraintSystem<Fp3> resolved;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ResolveCurrentRCStage3RelationConstraintSystem(
            RCStage3RelationRole::CompositionLink, PinFor(p), resolved, &why),
        why);
    BOOST_CHECK(why.find("complete_air_unavailable") == std::string::npos);
    BOOST_CHECK_EQUAL(resolved.n_columns, p.cs.n_columns);
    BOOST_CHECK_EQUAL(resolved.n_rows, p.cs.n_rows);
    BOOST_CHECK_EQUAL(resolved.constraints.size(), p.cs.constraints.size());
    BOOST_CHECK_EQUAL(RCStage3CountInCsClosers(resolved),
                      kRCStage3CompositionLinkInCsClosers);

    // CS-LEVEL FLIP: the honest witness satisfies the RESOLVER's C_rho, not
    // merely the one the product builder emitted.
    uint32_t frow = 0;
    std::string fname;
    BOOST_CHECK_MESSAGE(
        ar::CountWitnessViolationsOnH(resolved, p.witness, &frow, &fname) == 0,
        std::string("composition_link honest witness violated ") + fname);

    // Fail-closed on a wrong root count.
    aq::AirConstraintSystem<Fp3> short_cs;
    ar::ChildPublicInputs short_pin = PinFor(p);
    short_pin.endpoint_authority_roots.pop_back();
    BOOST_CHECK(!ResolveCurrentRCStage3RelationConstraintSystem(
        RCStage3RelationRole::CompositionLink, short_pin, short_cs, nullptr));
}

// ---------------------------------------------------------------------------
// NON-VACUITY. Every one of the three closers, and the relation that ties them
// together, must independently reject.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(composition_link_air_binds_both_legs_and_the_link_digest)
{
    const RCStage3RoleAirProduct p = HonestProduct();
    const auto& cs = p.cs;

    const uint32_t episode_value_col = p.endpoint_value_columns.at(0);
    const uint32_t coupled_value_col = p.endpoint_value_columns.at(1);

    // (a) and (b) are the load-bearing non-vacuity checks: they must be caught
    //     by the COMPOSITION FOLD, not merely by the leg fragment's own
    //     internal value/leaf_value alias. So the fragment is kept INTERNALLY
    //     CONSISTENT — both its value column and its leaf_value twin move
    //     together, and its committed root is left untouched — leaving the fold
    //     as the only constraint family that can object. A closer that bound
    //     the legs but did not fold them would pass every other check in this
    //     file and fail exactly here.
    const uint32_t episode_leaf_col =
        episode_value_col + 1; // kRCStage3StreamEndpointBindValueColumn + 1
    const uint32_t coupled_leaf_col = coupled_value_col + 1;

    // (a) EPISODE leg, fragment-internally consistent.
    {
        auto w = p.witness;
        for (uint32_t r = 0; r < cs.n_rows; ++r) {
            w[episode_value_col][r] =
                gkr_field::Add(w[episode_value_col][r], Fp3::One());
            w[episode_leaf_col][r] =
                gkr_field::Add(w[episode_leaf_col][r], Fp3::One());
        }
        std::string fname;
        BOOST_CHECK(
            ar::CountWitnessViolationsOnH(cs, w, nullptr, &fname) > 0);
        BOOST_CHECK_MESSAGE(
            fname.rfind("composition_link:", 0) == 0,
            "episode leg substitution must be caught by the COMPOSITION FOLD, "
            "not by the leg fragment alias; caught by: " + fname);
        BOOST_TEST_MESSAGE("CLINK episode_leg_substitution rejected by " << fname);
    }

    // (b) COUPLED leg, fragment-internally consistent.
    {
        auto w = p.witness;
        for (uint32_t r = 0; r < cs.n_rows; ++r) {
            w[coupled_value_col][r] =
                gkr_field::Add(w[coupled_value_col][r], Fp3::One());
            w[coupled_leaf_col][r] =
                gkr_field::Add(w[coupled_leaf_col][r], Fp3::One());
        }
        std::string fname;
        BOOST_CHECK(
            ar::CountWitnessViolationsOnH(cs, w, nullptr, &fname) > 0);
        BOOST_CHECK_MESSAGE(
            fname.rfind("composition_link:", 0) == 0,
            "coupled leg substitution must be caught by the COMPOSITION FOLD, "
            "not by the leg fragment alias; caught by: " + fname);
        BOOST_TEST_MESSAGE("CLINK coupled_leg_substitution rejected by " << fname);
    }

    // (b2) The dual escape: move the SPONGE message to match a substituted leg
    //      while leaving the leg fragment alone. The recompose alias must
    //      object; if it did not, a prover could fold values it never bound.
    {
        auto w = p.witness;
        const uint32_t msg_base =
            2 * 10u + 130u; // sponge base 20 + kPermCellsPerPerm
        w[msg_base][0] = gkr_field::Add(w[msg_base][0], Fp3::One());
        std::string fname;
        BOOST_CHECK(
            ar::CountWitnessViolationsOnH(cs, w, nullptr, &fname) > 0);
        BOOST_TEST_MESSAGE("CLINK folded_message_substitution rejected by "
                           << fname);
    }

    // (c) rebuild the C_rho against a DIFFERENT episode authority root: the
    //     honest witness must stop satisfying it.
    {
        auto roots = p.endpoint_committed_roots;
        roots[0][0] = roots[0][0] + gkr_field::FromU64(1);
        aq::AirConstraintSystem<Fp3> other;
        std::string why;
        BOOST_REQUIRE_MESSAGE(
            BuildRCStage3CompositionLinkRoleAirCS(roots, other, &why), why);
        BOOST_CHECK(ar::CountWitnessViolationsOnH(other, p.witness) > 0);
    }

    // (d) rebuild against a DIFFERENT coupled authority root.
    {
        auto roots = p.endpoint_committed_roots;
        roots[1][0] = roots[1][0] + gkr_field::FromU64(1);
        aq::AirConstraintSystem<Fp3> other;
        BOOST_REQUIRE(
            BuildRCStage3CompositionLinkRoleAirCS(roots, other, nullptr));
        BOOST_CHECK(ar::CountWitnessViolationsOnH(other, p.witness) > 0);
    }

    // (e) rebuild against a DIFFERENT LINK DIGEST: this is the closer that
    //     carries the composition relation itself. Without it the AIR would be
    //     two unrelated leg bindings.
    {
        auto roots = p.endpoint_committed_roots;
        roots[2][0] = roots[2][0] + gkr_field::FromU64(1);
        aq::AirConstraintSystem<Fp3> other;
        BOOST_REQUIRE(
            BuildRCStage3CompositionLinkRoleAirCS(roots, other, nullptr));
        std::string fname;
        BOOST_CHECK(
            ar::CountWitnessViolationsOnH(other, p.witness, nullptr, &fname) > 0);
        BOOST_TEST_MESSAGE("CLINK link_digest_mutation rejected by " << fname);
    }

    // (f) ORDER SENSITIVITY: the fold must distinguish (episode, coupled) from
    //     (coupled, episode). A commutative fold would let a prover swap the
    //     two legs of the composition.
    {
        std::string why;
        const auto swapped = BuildRCStage3CompositionLinkRoleAir(
            Leg(0x77ull), Leg(0x51ull), Root8(2), Root8(5), &why);
        BOOST_REQUIRE_MESSAGE(swapped.ok, swapped.note);
        BOOST_CHECK(swapped.endpoint_committed_roots[2] !=
                    p.endpoint_committed_roots[2]);
    }

    // (g) The committed link digest is DERIVED from the legs, so two different
    //     leg pairs cannot share a pin.
    {
        std::string why;
        const auto other_legs = BuildRCStage3CompositionLinkRoleAir(
            Leg(0x52ull), Leg(0x77ull), Root8(2), Root8(5), &why);
        BOOST_REQUIRE_MESSAGE(other_legs.ok, other_legs.note);
        BOOST_CHECK(other_legs.endpoint_committed_roots[2] !=
                    p.endpoint_committed_roots[2]);
    }
}

// ---------------------------------------------------------------------------
// PROOF LEVEL, not witness level: the role AIR round-trips real FRI and a
// tampered proof is rejected by the real verifier.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(composition_link_air_full_fri_roundtrip_and_reject)
{
    const RCStage3RoleAirProduct p = HonestProduct();
    uint256 seed;
    for (int i = 0; i < 32; ++i) seed.data()[i] = static_cast<unsigned char>(0x30 + i);

    auto proved = aq::AirQuotientProve<Fp3, AlgB3>(p.cs, p.witness, seed, {});
    BOOST_REQUIRE_MESSAGE(proved.ok && proved.division_exact, proved.note);

    std::string why;
    BOOST_CHECK_MESSAGE(
        (aq::AirQuotientVerify<Fp3, AlgB3>(p.cs, proved.proof, seed, &why)),
        why);

    // Wrong-seed reject.
    uint256 other_seed = seed;
    other_seed.data()[0] ^= 0xff;
    BOOST_CHECK(
        (!aq::AirQuotientVerify<Fp3, AlgB3>(p.cs, proved.proof, other_seed,
                                            nullptr)));

    // Tampered proof reject.
    auto bad = proved.proof;
    BOOST_REQUIRE(!bad.batch.queries.empty());
    BOOST_REQUIRE(!bad.batch.queries[0].row.values.empty());
    bad.batch.queries[0].row.values[0].c0 =
        gkr_field::Add(bad.batch.queries[0].row.values[0].c0,
                       gkr_field::FromU64(1));
    BOOST_CHECK(
        (!aq::AirQuotientVerify<Fp3, AlgB3>(p.cs, bad, seed, nullptr)));

    // A C_rho rebuilt against a different link digest rejects the honest proof
    // at PROOF level, not merely at witness level.
    {
        auto roots = p.endpoint_committed_roots;
        roots[2][1] = roots[2][1] + gkr_field::FromU64(1);
        aq::AirConstraintSystem<Fp3> other;
        BOOST_REQUIRE(
            BuildRCStage3CompositionLinkRoleAirCS(roots, other, nullptr));
        BOOST_CHECK((!aq::AirQuotientVerify<Fp3, AlgB3>(other, proved.proof,
                                                        seed, nullptr)));
    }
}

// ---------------------------------------------------------------------------
// The HONEST RESIDUAL, pinned so it cannot be quietly overstated later.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(composition_link_closer_records_what_it_does_not_prove)
{
    // (1) The in-CS fold is the ALGEBRAIC hash, not the consensus SHA256d of
    //     ComputeRCStage3FinalDigest. Nothing in this closer claims otherwise,
    //     and no code path derives the link pin from a SHA256d final digest.
    //     This is the same deferral the four pure-stream roles carry.
    BOOST_CHECK(RCStage3RoleIsPureStream(
                    RCStage3RelationRole::CoupledDigest));

    // (2) Endpoint provenance — binding these three public pins to the
    //     statement's episode_digest / coupled_digest / final_digest — is a
    //     separate, still-open obligation owned by the role-sections lane.
    BOOST_CHECK(!kRCStage3RoleSectionEndpointProvenanceReady);

    // (3) g2 performance half: dense production_shape stays unrepresentable;
    //     narrow L2 verify pin is MEASURED within 900ms → within_relay_budget.
    //     AggregationReady / CompleteFP stay false.
    BOOST_CHECK(!kRCStage3RecursiveAggregationReady);
    const auto budget = CurrentRCStage3TwoLevelRootVerifyBudgetV1();
    BOOST_CHECK(!budget.production_shape_representable);
    BOOST_CHECK(kRCStage3NarrowL2RootVerifyMeasured);
    BOOST_CHECK(budget.within_relay_budget);
    BOOST_CHECK(budget.narrow_l2_within_relay_budget);
}

BOOST_AUTO_TEST_SUITE_END()
