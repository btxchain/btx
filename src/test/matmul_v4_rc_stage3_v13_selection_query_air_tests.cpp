// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_stage3_v13_selection_query_air.h>

#include <array>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace sq =
    matmul::v4::rc::stage3_v13_selection_query_air;
namespace aq = matmul::v4::rc::air_quotient;
namespace gf = matmul::v4::rc::gkr_field;
namespace rc = matmul::v4::rc;

namespace {

sq::RawFp3V1 Raw(uint64_t c0, uint64_t c1, uint64_t c2)
{
    return {{c0, c1, c2}};
}

gf::Fp3 Field(const sq::RawFp3V1& raw)
{
    return {
        gf::FromU64(raw.coordinate[0]),
        gf::FromU64(raw.coordinate[1]),
        gf::FromU64(raw.coordinate[2])};
}

sq::InputV1 HonestInput(uint32_t queries)
{
    sq::InputV1 input;
    // Both z1 candidates are acceptable: first must win.
    input.ood_candidate[0] = Raw(11, 3, 0);
    input.ood_candidate[1] = Raw(17, 0, 5);
    // z2 candidate zero is equal to z1 and therefore unacceptable. Candidate
    // one is the first acceptable z2.
    input.ood_candidate[2] = input.ood_candidate[0];
    input.ood_candidate[3] = Raw(23, 7, 9);
    input.proof_tape_z1 = input.ood_candidate[0];
    input.proof_tape_z2 = input.ood_candidate[3];
    input.n_lde = 1U << 12;
    for (uint32_t query = 0; query < queries; ++query) {
        const uint64_t lane =
            UINT64_C(0x1234567800000000) +
            UINT64_C(0x9e3779b9) * query;
        input.query_digest_lane0.push_back(lane);
        input.proof_query_index.push_back(
            static_cast<uint32_t>(lane & (input.n_lde - 1)));
    }
    return input;
}

uint32_t Violations(
    const sq::ProductV1& product,
    const std::vector<std::vector<gf::Fp3>>& columns)
{
    return sq::CountViolationsV1(product.cs, columns);
}

uint256 Seed(uint8_t tag)
{
    uint256 seed;
    for (uint32_t i = 0; i < 32; ++i) {
        seed.data()[i] =
            static_cast<unsigned char>(tag + 7 * i);
    }
    return seed;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_v13_selection_query_air_tests)

BOOST_AUTO_TEST_CASE(
    fixed_k2_selection_matches_native_and_exports_exact_cells)
{
    const sq::InputV1 input = HonestInput(8);
    const sq::ProductV1 product = sq::BuildProductV1(input);
    BOOST_REQUIRE_MESSAGE(product.valid, product.note);
    BOOST_CHECK_EQUAL(product.violations, 0U);
    BOOST_CHECK_EQUAL(product.selected_z1_ordinal, 0U);
    BOOST_CHECK_EQUAL(product.selected_z2_ordinal, 1U);
    BOOST_CHECK(product.candidates_ordinary);
    BOOST_CHECK(product.outputs_ordinary);
    BOOST_CHECK(product.canonical_goldilocks_constrained);
    BOOST_CHECK(product.first_acceptable_constrained);
    BOOST_CHECK(product.distinct_z2_constrained);
    BOOST_CHECK(product.local_tape_equality_cells_constrained);
    BOOST_CHECK(product.query_reduction_constrained);
    BOOST_CHECK(!product.production_q192);
    BOOST_CHECK(!product.actual_v14_output_cells_bound);
    BOOST_CHECK(!product.actual_proof_tape_cells_bound);
    BOOST_CHECK(!product.recursive_authority);
    BOOST_CHECK_LE(product.max_alg_degree, 7U);

    const std::array<gf::Fp3, 2> z1_candidates{
        Field(input.ood_candidate[0]),
        Field(input.ood_candidate[1])};
    const std::array<gf::Fp3, 2> z2_candidates{
        Field(input.ood_candidate[2]),
        Field(input.ood_candidate[3])};
    uint32_t native_z1_ordinal = 99;
    uint32_t native_z2_ordinal = 99;
    gf::Fp3 native_z1{};
    gf::Fp3 native_z2{};
    BOOST_REQUIRE(
        rc::Fri3AlgSafeSelectOodK2V13(
            z1_candidates, nullptr,
            native_z1_ordinal, native_z1));
    BOOST_REQUIRE(
        rc::Fri3AlgSafeSelectOodK2V13(
            z2_candidates, &native_z1,
            native_z2_ordinal, native_z2));
    BOOST_CHECK_EQUAL(
        native_z1_ordinal, product.selected_z1_ordinal);
    BOOST_CHECK_EQUAL(
        native_z2_ordinal, product.selected_z2_ordinal);

    const sq::LayoutV1 layout;
    for (uint32_t coordinate = 0; coordinate < 3; ++coordinate) {
        const sq::CellRefV1 candidate_cell{
            layout.Candidate(0, coordinate),
            sq::kSelectionRowV1};
        const sq::CellRefV1 selected_cell{
            layout.SelectedZ1(coordinate),
            sq::kSelectionRowV1};
        const sq::CellRefV1 tape_cell{
            layout.ProofTapeZ2(coordinate),
            sq::kSelectionRowV1};
        BOOST_CHECK(
            product.cell_map.ood_candidate[0]
                .coordinate[coordinate] ==
            candidate_cell);
        BOOST_CHECK(
            product.cell_map.selected_z1
                .coordinate[coordinate] ==
            selected_cell);
        BOOST_CHECK(
            product.cell_map.proof_tape_z2
                .coordinate[coordinate] ==
            tape_cell);
    }
    BOOST_REQUIRE_EQUAL(product.cell_map.query.size(), 8U);
    const sq::CellRefV1 digest_cell{
        layout.scalar_value,
        sq::kQueryRowBaseV1 + 7};
    const sq::CellRefV1 query_tape_cell{
        layout.proof_tape_query_index,
        sq::kQueryRowBaseV1 + 7};
    BOOST_CHECK(
        product.cell_map.query[7].v14_digest_lane0 ==
        digest_cell);
    BOOST_CHECK(
        product.cell_map.query[7].proof_tape_index ==
        query_tape_cell);

    // The only preprocessed columns are positional selectors. Candidate,
    // selected-output, proof-tape, digest-lane and query-index cells are all
    // ordinary witness columns.
    for (const auto& [column, values] : product.cs.preprocessed) {
        BOOST_CHECK_GE(column, layout.scalar_active);
        BOOST_CHECK_LT(column, layout.dependent_zero);
        BOOST_REQUIRE_EQUAL(values.size(), product.trace_rows);
    }
}

BOOST_AUTO_TEST_CASE(
    q192_query_reduction_matches_native_wide_mod)
{
    sq::InputV1 input = HonestInput(0);
    input.query_digest_lane0.clear();
    input.proof_query_index.clear();
    input.n_lde = 1U << 20;

    rc::Fri3AlgDigest query_seed{
        gf::FromU64(101),
        gf::FromU64(103),
        gf::FromU64(107),
        gf::FromU64(109)};
    for (uint32_t query = 0;
         query < sq::kProductionQueriesV1; ++query) {
        gf::Fp3 candidate{};
        std::string why;
        BOOST_REQUIRE_MESSAGE(
            rc::Fri3AlgSafeQ192K2QueryCandidateV13(
                query_seed, query, candidate, &why),
            why);
        const uint64_t c0 = gf::Canonical(candidate.c0);
        const uint64_t c1 = gf::Canonical(candidate.c1);
        const unsigned __int128 wide =
            (static_cast<unsigned __int128>(c1) << 64) | c0;
        const uint32_t native =
            static_cast<uint32_t>(wide % input.n_lde);
        // Since n_lde is a power of two no larger than 2^31, 2^64 is zero
        // modulo n_lde and the wide native reduction is exactly c0's low bits.
        BOOST_REQUIRE_EQUAL(
            native,
            static_cast<uint32_t>(c0 & (input.n_lde - 1)));
        input.query_digest_lane0.push_back(c0);
        input.proof_query_index.push_back(native);
    }

    const sq::ProductV1 product = sq::BuildProductV1(input);
    BOOST_REQUIRE_MESSAGE(product.valid, product.note);
    BOOST_CHECK(product.production_q192);
    BOOST_CHECK_EQUAL(product.query_count, 192U);
    BOOST_CHECK_EQUAL(product.trace_rows, 256U);
    BOOST_CHECK_EQUAL(product.domain_bits, 20U);
    BOOST_CHECK_EQUAL(product.violations, 0U);
    BOOST_CHECK_EQUAL(product.cell_map.query.size(), 192U);

    // The protocol shape guard is part of the verifier CS, not a host hint.
    input.n_lde = (1U << 20) + 1;
    BOOST_CHECK(!sq::BuildProductV1(input).valid);
}

BOOST_AUTO_TEST_CASE(
    selection_and_tape_transplant_attacks_are_constrained)
{
    const sq::ProductV1 product =
        sq::BuildProductV1(HonestInput(8));
    BOOST_REQUIRE(product.valid);
    const uint32_t row = sq::kSelectionRowV1;

    // Both z1 candidates are acceptable. Selecting the later one is not a
    // legal witness even if the attacker transplants all three output cells.
    auto later = product.columns;
    later[product.layout.SelectedOrdinal(0)][row] =
        gf::Fp3::FromFp(gf::FromU64(1));
    for (uint32_t coordinate = 0; coordinate < 3; ++coordinate) {
        later[product.layout.SelectedZ1(coordinate)][row] =
            later[product.layout.Candidate(1, coordinate)][row];
        later[product.layout.ProofTapeZ1(coordinate)][row] =
            later[product.layout.Candidate(1, coordinate)][row];
    }
    BOOST_CHECK_GT(Violations(product, later), 0U);

    // An off-base-line candidate is mandatory.  Force the selected first
    // candidate onto the base line while retaining the "acceptable" witness.
    auto zero_extension = product.columns;
    for (uint32_t ext = 1; ext < 3; ++ext) {
        const uint32_t column = product.layout.Candidate(0, ext);
        for (uint32_t r = 0; r < product.trace_rows; ++r) {
            zero_extension[column][r] = gf::Fp3::Zero();
        }
    }
    BOOST_CHECK_GT(Violations(product, zero_extension), 0U);

    // z2 may not equal the already selected z1.
    auto same_z = product.columns;
    for (uint32_t coordinate = 0; coordinate < 3; ++coordinate) {
        same_z[product.layout.SelectedZ2(coordinate)][row] =
            same_z[product.layout.SelectedZ1(coordinate)][row];
        same_z[product.layout.ProofTapeZ2(coordinate)][row] =
            same_z[product.layout.SelectedZ1(coordinate)][row];
    }
    BOOST_CHECK_GT(Violations(product, same_z), 0U);

    // Output/proof-tape transplants are direct equality failures.
    auto output_transplant = product.columns;
    output_transplant[product.layout.ProofTapeZ1(0)][row] =
        gf::Add(
            output_transplant[
                product.layout.ProofTapeZ1(0)][row],
            gf::Fp3::One());
    BOOST_CHECK_GT(Violations(product, output_transplant), 0U);

    auto wrong_query = product.columns;
    const uint32_t query_row = sq::kQueryRowBaseV1 + 3;
    wrong_query[product.layout.proof_tape_query_index][query_row] =
        gf::Add(
            wrong_query[
                product.layout.proof_tape_query_index][query_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(Violations(product, wrong_query), 0U);
}

BOOST_AUTO_TEST_CASE(
    canonical_decomposition_rejects_goldilocks_x_plus_p_alias)
{
    sq::InputV1 input = HonestInput(8);
    // x < 2^32-1 makes x+p fit in uint64_t.  In the field it aliases x, so
    // selection would be unchanged absent the explicit canonical bit rule.
    const uint64_t canonical = 11;
    BOOST_REQUIRE((
        static_cast<unsigned __int128>(canonical) + gf::kP <
        static_cast<unsigned __int128>(
            std::numeric_limits<uint64_t>::max()) + 1));
    input.ood_candidate[0].coordinate[0] =
        canonical + gf::kP;
    const sq::ProductV1 aliased = sq::BuildProductV1(input);
    BOOST_CHECK(!aliased.valid);
    BOOST_CHECK_GT(aliased.violations, 0U);

    input = HonestInput(8);
    input.query_digest_lane0[0] =
        input.query_digest_lane0[0] % (UINT32_MAX - 1);
    input.proof_query_index[0] =
        static_cast<uint32_t>(
            input.query_digest_lane0[0] & (input.n_lde - 1));
    const sq::ProductV1 canonical_query =
        sq::BuildProductV1(input);
    BOOST_REQUIRE(canonical_query.valid);
    input.query_digest_lane0[0] += gf::kP;
    // The aliased bits alter the low mask and are noncanonical, while the
    // ordinary field lane itself aliases the honest lane.
    input.proof_query_index[0] =
        static_cast<uint32_t>(
            input.query_digest_lane0[0] & (input.n_lde - 1));
    const sq::ProductV1 aliased_query =
        sq::BuildProductV1(input);
    BOOST_CHECK(!aliased_query.valid);
    BOOST_CHECK_GT(aliased_query.violations, 0U);
}

BOOST_AUTO_TEST_CASE(
    unmodified_airquotient_roundtrip_and_proof_rejects)
{
    using Backend = aq::AirFriBackendAlg<gf::Fp3>;
    const sq::ProductV1 product =
        sq::BuildProductV1(
            HonestInput(sq::kProductionQueriesV1));
    BOOST_REQUIRE_MESSAGE(product.valid, product.note);
    BOOST_REQUIRE(product.production_q192);
    const uint256 seed = Seed(0x71);
    const auto proved =
        aq::AirQuotientProve<gf::Fp3, Backend>(
            product.cs, product.columns, seed);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    std::string why;
    BOOST_CHECK_MESSAGE(
        (aq::AirQuotientVerify<gf::Fp3, Backend>(
            product.cs, proved.proof, seed, &why)),
        why);

    auto output_forged = proved.proof;
    BOOST_REQUIRE(!output_forged.batch.queries.empty());
    BOOST_REQUIRE_GT(
        output_forged.batch.queries[0].row.values.size(),
        product.layout.SelectedZ1(0));
    output_forged.batch.queries[0]
        .row.values[product.layout.SelectedZ1(0)] =
        gf::Add(
            output_forged.batch.queries[0]
                .row.values[product.layout.SelectedZ1(0)],
            gf::Fp3::One());
    BOOST_CHECK(
        !(aq::AirQuotientVerify<gf::Fp3, Backend>(
            product.cs, output_forged, seed, nullptr)));

    auto index_forged = proved.proof;
    index_forged.batch.queries[0]
        .row.values[product.layout.proof_tape_query_index] =
        gf::Add(
            index_forged.batch.queries[0]
                .row.values[
                    product.layout.proof_tape_query_index],
            gf::Fp3::One());
    BOOST_CHECK(
        !(aq::AirQuotientVerify<gf::Fp3, Backend>(
            product.cs, index_forged, seed, nullptr)));
}

BOOST_AUTO_TEST_SUITE_END()
