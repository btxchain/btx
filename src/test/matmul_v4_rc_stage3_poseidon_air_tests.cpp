// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_poseidon_air.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace ah = matmul::v4::rc::alg_hash;
namespace aq = matmul::v4::rc::air_quotient;
namespace ar = matmul::v4::rc::air_recurse;
namespace gf = matmul::v4::rc::gkr_field;
namespace pa = matmul::v4::rc::stage3_poseidon_air;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_stage3_poseidon_air_tests,
                         BasicTestingSetup)

namespace {

bool Satisfies(
    const std::vector<aq::AirConstraint<gf::Fp3>>& constraints,
    const std::vector<gf::Fp3>& row)
{
    for (const auto& constraint : constraints) {
        if (!gf::IsZero(constraint.eval(row, row))) return false;
    }
    return true;
}

ah::State StateFor(uint64_t seed)
{
    ah::State out{};
    uint64_t state = seed;
    for (auto& lane : out) {
        state += UINT64_C(0x9e3779b97f4a7c15);
        uint64_t z = state;
        z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
        lane = gf::FromU64(z ^ (z >> 31));
    }
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(fixed_table_has_exact_quadratic_width_and_quotient)
{
    constexpr uint32_t N = 1024;
    const pa::Layout layout = pa::CanonicalLayout();
    std::string why;
    BOOST_REQUIRE_MESSAGE(layout.IsCanonical(&why), why);
    BOOST_CHECK_EQUAL(layout.perm.base, 0U);
    BOOST_CHECK_EQUAL(layout.perm.End(), 130U);
    BOOST_CHECK_EQUAL(layout.x2_base, 130U);
    BOOST_CHECK_EQUAL(layout.x4_base, 248U);
    BOOST_CHECK_EQUAL(layout.x6_base, 366U);
    BOOST_CHECK_EQUAL(layout.End(), 484U);

    const pa::Measurement m = pa::Measure(N);
    BOOST_TEST_MESSAGE(
        "Poseidon2 x^7 fully quadratic fixed table: columns="
        << m.fixed_columns << " (130 + " << m.auxiliary_columns
        << "), constraints=" << m.fixed_constraints
        << ", degree=" << m.fixed_max_degree
        << ", quotient_len=" << m.fixed_quotient_len);
    BOOST_TEST_MESSAGE(
        "Poseidon2 x^7 selector-gated table: columns="
        << m.selector_gated_columns
        << ", constraints=" << m.selector_gated_constraints
        << ", degree=" << m.selector_gated_max_degree
        << ", quotient_len=" << m.selector_gated_quotient_len);

    BOOST_CHECK_EQUAL(m.sboxes, 118U);
    BOOST_CHECK_EQUAL(m.base_columns, 130U);
    BOOST_CHECK_EQUAL(m.auxiliary_columns, 354U);
    BOOST_CHECK_EQUAL(m.fixed_columns, 484U);
    BOOST_CHECK_EQUAL(m.fixed_constraints, 472U);
    BOOST_CHECK_EQUAL(m.fixed_max_degree, 2U);
    BOOST_CHECK_EQUAL(m.fixed_composed_degree, 2ULL * (N - 1));
    BOOST_CHECK_EQUAL(m.fixed_quotient_len, N - 1);
    BOOST_CHECK_EQUAL(m.selector_gated_columns, 485U);
    BOOST_CHECK_EQUAL(m.selector_gated_constraints, 473U);
    BOOST_CHECK_EQUAL(m.selector_gated_max_degree, 3U);
    BOOST_CHECK_EQUAL(
        m.selector_gated_composed_degree, 3ULL * (N - 1));
    BOOST_CHECK_EQUAL(m.selector_gated_quotient_len, 2 * (N - 1));
    static_assert(pa::kPoseidonDecomposedAirExecutable);
    static_assert(!pa::kPoseidonDecomposedConsensusAuthority);
}

BOOST_AUTO_TEST_CASE(honest_witness_matches_native_poseidon2)
{
    const pa::Layout layout = pa::CanonicalLayout();
    const auto constraints = pa::BuildFixedConstraints(layout);
    BOOST_REQUIRE_EQUAL(constraints.size(), 472U);

    for (uint64_t seed = 1; seed <= 16; ++seed) {
        const ah::State input =
            StateFor(seed * UINT64_C(0xd1342543de82ef95));
        const pa::Witness witness = pa::BuildWitness(layout, input);
        BOOST_REQUIRE_EQUAL(witness.row.size(), 484U);
        BOOST_CHECK(Satisfies(constraints, witness.row));

        ah::State expected = input;
        ah::Permute(expected);
        for (uint32_t lane = 0; lane < ah::kAlgHashT; ++lane) {
            BOOST_CHECK_EQUAL(
                gf::Canonical(witness.output[lane]),
                gf::Canonical(expected[lane]));
            BOOST_CHECK(gf::Eq(
                ar::PermOutputLane(layout.perm, witness.row, lane),
                gf::Fp3::FromFp(expected[lane])));
        }
    }
}

BOOST_AUTO_TEST_CASE(every_base_and_auxiliary_cell_mutation_is_rejected)
{
    const pa::Layout layout = pa::CanonicalLayout();
    const auto constraints = pa::BuildFixedConstraints(layout);
    const pa::Witness honest =
        pa::BuildWitness(layout, StateFor(UINT64_C(0xc001d00d5eed)));
    BOOST_REQUIRE(Satisfies(constraints, honest.row));

    for (uint32_t column = 0; column < layout.End(); ++column) {
        std::vector<gf::Fp3> mutated = honest.row;
        // A non-base-field perturbation exercises the Fp3 identities rather
        // than only their embedded-Fp restriction.
        mutated[column] =
            gf::Add(mutated[column], gf::Fp3{1, 7, 11});
        BOOST_CHECK_MESSAGE(
            !Satisfies(constraints, mutated),
            "mutation survived at decomposed column " << column);
    }
}

BOOST_AUTO_TEST_CASE(selector_gating_is_degree_three_and_publicly_pinned)
{
    constexpr uint32_t N = 2;
    const pa::Layout layout = pa::CanonicalLayout();
    const uint32_t selector_col = layout.End();
    const std::vector<gf::Fp3> selectors{
        gf::Fp3::One(), gf::Fp3::Zero()};
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        pa::BuildSelectorGatedSystem(N, selectors, cs, &why), why);
    BOOST_CHECK_EQUAL(cs.n_columns, 485U);
    BOOST_CHECK_EQUAL(cs.constraints.size(), 473U);
    BOOST_REQUIRE_EQUAL(cs.preprocessed.size(), 1U);
    BOOST_CHECK_EQUAL(cs.preprocessed[0].first, selector_col);
    BOOST_CHECK_EQUAL(cs.preprocessed[0].second.size(), N);

    pa::Witness selected =
        pa::BuildWitness(layout, StateFor(UINT64_C(0x123456789abcdef0)));
    selected.row.push_back(gf::Fp3::One());
    std::vector<gf::Fp3> inactive(cs.n_columns, gf::Fp3::Zero());
    BOOST_CHECK(Satisfies(cs.constraints, selected.row));
    BOOST_CHECK(Satisfies(cs.constraints, inactive));

    // Disabling a selected row satisfies the gated identities locally, which
    // is why the selector is a canonical preprocessed column rather than a
    // prover-controlled witness.  Its committed value remains one in `cs`.
    selected.row[selector_col] = gf::Fp3::Zero();
    BOOST_CHECK(Satisfies(cs.constraints, selected.row));
    BOOST_CHECK(gf::Eq(
        cs.preprocessed[0].second[0], gf::Fp3::One()));

    auto bad_selector = selectors;
    bad_selector[0] = gf::Fp3{2, 0, 0};
    BOOST_CHECK(!pa::BuildSelectorGatedSystem(
        N, bad_selector, cs, &why));
    BOOST_CHECK(why.find("nonboolean_selector") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(two_row_fixed_air_proves_and_verifies)
{
    constexpr uint32_t N = 2;
    const pa::Layout layout = pa::CanonicalLayout();
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::string why;
    BOOST_REQUIRE_MESSAGE(pa::BuildFixedSystem(N, cs, &why), why);

    const pa::Witness row0 =
        pa::BuildWitness(layout, StateFor(UINT64_C(0xa5a5a5a55a5a5a5a)));
    const pa::Witness row1 =
        pa::BuildWitness(layout, StateFor(UINT64_C(0x5a5a5a5aa5a5a5a5)));
    std::vector<std::vector<gf::Fp3>> columns(
        cs.n_columns, std::vector<gf::Fp3>(N));
    for (uint32_t column = 0; column < cs.n_columns; ++column) {
        columns[column][0] = row0.row[column];
        columns[column][1] = row1.row[column];
    }

    uint256 seed;
    std::fill(seed.begin(), seed.end(), 0x6d);
    const auto proved =
        aq::AirQuotientProve<gf::Fp3>(cs, columns, seed);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    BOOST_CHECK_MESSAGE(
        aq::AirQuotientVerify<gf::Fp3>(
            cs, proved.proof, seed, &why),
        why);
}

BOOST_AUTO_TEST_SUITE_END()
