// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_alg_hash_wide.h>
#include <matmul/matmul_v4_rc_gkr_field.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace wide = matmul::v4::rc::alg_hash_wide;
namespace gf = matmul::v4::rc::gkr_field;

BOOST_FIXTURE_TEST_SUITE(
    matmul_v4_rc_alg_hash_wide_tests, BasicTestingSetup)

namespace {

uint64_t SplitMix64(uint64_t& state)
{
    state += 0x9e3779b97f4a7c15ULL;
    uint64_t value = state;
    value =
        (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ULL;
    value =
        (value ^ (value >> 27)) * 0x94d049bb133111ebULL;
    return value ^ (value >> 31);
}

template <size_t N>
bool EqualCanonical(
    const std::array<gf::Fp, N>& left,
    const std::array<gf::Fp, N>& right)
{
    for (size_t i = 0; i < N; ++i) {
        if (gf::Canonical(left[i]) != gf::Canonical(right[i])) {
            return false;
        }
    }
    return true;
}

} // namespace

static_assert(wide::kWideT == 16);
static_assert(wide::kWideRate == 8);
static_assert(wide::kWideCapacity == 8);
static_assert(wide::kWideDigestLen == 8);
static_assert(wide::kWideFullRounds == 8);
static_assert(wide::kWidePartialRounds == 22);
static_assert(wide::kWideSboxCells == 150);
static_assert(wide::kWidePermCells == 166);

BOOST_AUTO_TEST_CASE(wide_permutation_inverse_and_frozen_material)
{
    const wide::Constants& constants = wide::GetConstants();
    BOOST_CHECK(constants.node_domain != constants.row_domain);
    BOOST_CHECK(constants.node_domain != constants.transcript_domain);
    BOOST_CHECK(constants.row_domain != constants.transcript_domain);
    BOOST_CHECK_EQUAL(
        wide::ConstantsChecksum().GetHex(),
        "f723115e8bf84b7bd11bb8bfcccc8082a3bb105ef97d7f573be8475a7e335875");

    wide::State zero{};
    wide::Permute(zero);
    BOOST_CHECK_EQUAL(
        gf::Canonical(zero[0]), 1517527635109155493ULL);
    wide::InversePermute(zero);
    for (const gf::Fp value : zero) {
        BOOST_CHECK_EQUAL(gf::Canonical(value), 0U);
    }

    uint64_t seed = 0x5749444550313655ULL;
    for (uint32_t trial = 0; trial < 16; ++trial) {
        wide::State input{};
        for (gf::Fp& value : input) {
            value = gf::FromU64(SplitMix64(seed));
        }
        wide::State output = input;
        wide::Permute(output);
        wide::InversePermute(output);
        BOOST_CHECK(EqualCanonical(output, input));

        output = input;
        wide::InversePermute(output);
        wide::Permute(output);
        BOOST_CHECK(EqualCanonical(output, input));
    }

    const wide::ResourceAudit audit = wide::AssessResources(1);
    BOOST_CHECK(audit.external_matrix_invertible);
    BOOST_CHECK(audit.internal_matrix_invertible);
}

BOOST_AUTO_TEST_CASE(wide_flattened_relation_checker_rejects_mutations)
{
    wide::State input{};
    for (uint32_t lane = 0; lane < wide::kWideT; ++lane) {
        input[lane] = gf::FromU64(17 + 13 * lane);
    }
    const wide::PermWitness honest = wide::BuildPermWitness(input);
    std::string why;
    BOOST_REQUIRE(wide::VerifyPermWitness(honest, &why));

    const std::array<uint32_t, 4> mutation_cells{
        wide::kWideT,
        wide::kWideT + wide::kWideT * 4,
        wide::kWideT + wide::kWideT * 4 +
            wide::kWidePartialRounds - 1,
        wide::kWidePermCells - 1,
    };
    for (const uint32_t cell : mutation_cells) {
        wide::PermWitness changed = honest;
        changed.cells[cell] =
            gf::Add(changed.cells[cell], gf::FromU64(1));
        why.clear();
        BOOST_CHECK(!wide::VerifyPermWitness(changed, &why));
        BOOST_CHECK_EQUAL(
            why, "wide permutation sbox relation");
    }
    {
        wide::PermWitness changed = honest;
        changed.output[7] =
            gf::Add(changed.output[7], gf::FromU64(1));
        why.clear();
        BOOST_CHECK(!wide::VerifyPermWitness(changed, &why));
        BOOST_CHECK_EQUAL(
            why, "wide permutation output relation");
    }
}

BOOST_AUTO_TEST_CASE(wide_domain_sponge_and_node_transcript)
{
    wide::Digest left{};
    wide::Digest right{};
    for (uint32_t lane = 0; lane < wide::kWideDigestLen; ++lane) {
        left[lane] = gf::FromU64(lane + 1);
        right[lane] = gf::FromU64(lane + 101);
    }

    const wide::SpongeWitness honest =
        wide::BuildCompressWitness(left, right);
    BOOST_REQUIRE_EQUAL(honest.permutations.size(), 3U);
    BOOST_CHECK(EqualCanonical(
        honest.digest, wide::Compress(left, right)));
    std::string why;
    BOOST_REQUIRE(wide::VerifySpongeWitness(honest, &why));

    {
        wide::SpongeWitness changed = honest;
        changed.message[8] =
            gf::Add(changed.message[8], gf::FromU64(1));
        why.clear();
        BOOST_CHECK(!wide::VerifySpongeWitness(changed, &why));
        BOOST_CHECK_EQUAL(
            why, "wide sponge absorb/chaining relation");
    }
    {
        wide::SpongeWitness changed = honest;
        changed.permutations[1].cells[wide::kWideT + 73] =
            gf::Add(
                changed.permutations[1].cells[wide::kWideT + 73],
                gf::FromU64(1));
        why.clear();
        BOOST_CHECK(!wide::VerifySpongeWitness(changed, &why));
        BOOST_CHECK_EQUAL(
            why, "wide permutation sbox relation");
    }
    {
        wide::SpongeWitness changed = honest;
        changed.digest[0] =
            gf::Add(changed.digest[0], gf::FromU64(1));
        why.clear();
        BOOST_CHECK(!wide::VerifySpongeWitness(changed, &why));
        BOOST_CHECK_EQUAL(why, "wide sponge digest relation");
    }

    std::vector<wide::Fp3> row{
        wide::Fp3{1, 2, 3}, wide::Fp3{4, 5, 6}};
    const wide::Digest row0 = wide::LeafHashRow(row, 0);
    const wide::Digest row1 = wide::LeafHashRow(row, 1);
    BOOST_CHECK(!EqualCanonical(row0, row1));

    std::vector<gf::Fp> flattened;
    for (const wide::Fp3& value : row) {
        flattened.push_back(value.c0);
        flattened.push_back(value.c1);
        flattened.push_back(value.c2);
    }
    flattened.push_back(0);
    const wide::Digest wrong_domain =
        wide::SpongeHashFpDomain(
            flattened, wide::GetConstants().node_domain);
    BOOST_CHECK(!EqualCanonical(row0, wrong_domain));
}

BOOST_AUTO_TEST_CASE(
    wide_internal_matrix_reference_condition_and_plonky3_comparison)
{
    const wide::ParameterConditionAudit& audit =
        wide::AssessParameterConditions();
    BOOST_CHECK_EQUAL(audit.active_version, 1U);
    BOOST_CHECK(audit.reference_grain_replayed);
    BOOST_CHECK(audit.reference_round_constant_pins_match);
    BOOST_CHECK(audit.reference_permutation_kat_matches);
    BOOST_CHECK(audit.round_geometry_equal);
    BOOST_CHECK_EQUAL(
        audit.btx_round_constants_checksum.GetHex(),
        "cd766e02b117a0a67e5240c00212541829d4d71a554f69873ab9c554068a1642");
    BOOST_CHECK_EQUAL(
        audit.plonky3_round_constants_checksum.GetHex(),
        "d95a3d43b8e97b934ca09084c5a124273d5bbd633d86eae5352cf887565dfd53");

    BOOST_CHECK_EQUAL(audit.btx_matrix.width, 16U);
    BOOST_CHECK_EQUAL(audit.btx_matrix.powers_required, 32U);
    BOOST_CHECK_EQUAL(audit.btx_matrix.powers_checked, 32U);
    BOOST_CHECK_EQUAL(audit.btx_matrix.irreducible_powers, 32U);
    BOOST_CHECK_EQUAL(audit.btx_matrix.first_failing_power, 0U);
    BOOST_CHECK(
        audit.btx_matrix
            .all_characteristic_polynomials_irreducible);
    BOOST_CHECK_EQUAL(
        audit.btx_matrix
            .characteristic_polynomials_checksum.GetHex(),
        "992ef7a4e509803278e5d9121b4f84e4ee14226ac19a9b1ae0c5ac0411bf35e3");

    BOOST_CHECK_EQUAL(audit.plonky3_matrix.width, 16U);
    BOOST_CHECK_EQUAL(
        audit.plonky3_matrix.powers_required, 32U);
    BOOST_CHECK_EQUAL(
        audit.plonky3_matrix.powers_checked, 32U);
    BOOST_CHECK_EQUAL(
        audit.plonky3_matrix.irreducible_powers, 32U);
    BOOST_CHECK_EQUAL(
        audit.plonky3_matrix.first_failing_power, 0U);
    BOOST_CHECK(
        audit.plonky3_matrix
            .all_characteristic_polynomials_irreducible);
    BOOST_CHECK_EQUAL(
        audit.plonky3_matrix
            .characteristic_polynomials_checksum.GetHex(),
        "de662e369dbab265892e0da7f63d9774ef4671ad79662976d8a077518e7a3a26");

    // BTX's versioned XOF instance is deliberately independent of the
    // canonical Grain/optimized-matrix instance.  Both satisfy the same
    // parameter condition; byte equality is not required or claimed.
    BOOST_CHECK(!audit.round_constants_equal);
    BOOST_CHECK(!audit.external_matrices_equal);
    BOOST_CHECK(!audit.internal_matrices_equal);
    BOOST_CHECK(audit.btx_parameter_condition_closed);
    BOOST_CHECK(!audit.deterministic_regeneration_required);

    // A rank-one all-ones matrix has a reducible characteristic polynomial;
    // this checks that the executable audit fails closed instead of merely
    // counting 32 iterations.
    std::array<gf::Fp, wide::kWideT> bad_mu{};
    const wide::InternalMatrixConditionAudit bad =
        wide::AuditInternalMatrixCondition(bad_mu);
    BOOST_CHECK(!bad.all_characteristic_polynomials_irreducible);
    BOOST_CHECK_EQUAL(bad.powers_checked, 1U);
    BOOST_CHECK_EQUAL(bad.irreducible_powers, 0U);
    BOOST_CHECK_EQUAL(bad.first_failing_power, 1U);
}

BOOST_AUTO_TEST_CASE(wide_resource_and_fail_closed_security_audit)
{
    const wide::ResourceAudit audit639 =
        wide::AssessResources(639);
    BOOST_CHECK_EQUAL(audit639.version, 1U);
    BOOST_CHECK_EQUAL(audit639.state_lanes, 16U);
    BOOST_CHECK_EQUAL(audit639.rate_lanes, 8U);
    BOOST_CHECK_EQUAL(audit639.capacity_lanes, 8U);
    BOOST_CHECK_EQUAL(audit639.digest_lanes, 8U);
    BOOST_CHECK_EQUAL(audit639.sboxes_per_permutation, 150U);
    BOOST_CHECK_EQUAL(audit639.perm_relation_columns, 166U);
    BOOST_CHECK_EQUAL(audit639.perm_relation_constraints, 150U);
    BOOST_CHECK_EQUAL(audit639.max_algebraic_degree, 7U);

    BOOST_CHECK_EQUAL(audit639.node_permutations, 3U);
    BOOST_CHECK_EQUAL(audit639.node_horizontal_columns, 514U);
    BOOST_CHECK_EQUAL(audit639.node_relation_constraints, 498U);
    BOOST_CHECK_EQUAL(audit639.node_sbox_evaluations, 450U);

    BOOST_CHECK_EQUAL(audit639.row_field_elements, 1918U);
    BOOST_CHECK_EQUAL(audit639.row_permutations, 240U);
    BOOST_CHECK_EQUAL(audit639.row_horizontal_columns, 39'840U);
    BOOST_CHECK_EQUAL(audit639.row_vertical_columns, 174U);
    BOOST_CHECK_EQUAL(audit639.row_sbox_evaluations, 36'000U);
    BOOST_CHECK(!audit639.row_horizontal_fits_parent);
    BOOST_CHECK(audit639.row_vertical_fits_parent);

    BOOST_CHECK_EQUAL(audit639.nominal_digest_bits, 512U);
    BOOST_CHECK_EQUAL(audit639.nominal_capacity_bits, 512U);
    BOOST_CHECK_GE(audit639.strict_generic_collision_bits, 255U);
    BOOST_CHECK_EQUAL(
        audit639.strict_common_binding_cap_bits,
        audit639.strict_generic_collision_bits);
    BOOST_CHECK_GT(
        audit639.strict_common_binding_cap_bits, 128U);
    BOOST_CHECK_EQUAL(
        audit639.production_security_claim_bits, 0U);

    BOOST_CHECK(audit639.external_matrix_invertible);
    BOOST_CHECK(audit639.internal_matrix_invertible);
    BOOST_CHECK(audit639.bounded_relation_checker_executable);
    BOOST_CHECK(
        audit639.round_geometry_matches_reference_search);
    BOOST_CHECK(
        !audit639.constants_match_reference_grain_instance);
    BOOST_CHECK(
        audit639.internal_subspace_condition_verified);
    BOOST_CHECK(!audit639.sponge_mode_reduction_complete);
    BOOST_CHECK(!audit639.fri_air_integrated);
    BOOST_CHECK(
        !audit639.recursive_verifier_consumes_digest);
    BOOST_CHECK(!audit639.formal_security_reduction_complete);
    BOOST_CHECK(!audit639.production_selected);
    BOOST_CHECK(!audit639.consensus_enabled);

    const wide::ResourceAudit audit647 =
        wide::AssessResources(647);
    BOOST_CHECK_EQUAL(audit647.row_field_elements, 1942U);
    BOOST_CHECK_EQUAL(audit647.row_permutations, 243U);
    BOOST_CHECK_EQUAL(
        audit647.row_horizontal_columns, 40'338U);
    BOOST_CHECK_EQUAL(
        audit647.row_sbox_evaluations, 36'450U);
    BOOST_CHECK(audit647.row_vertical_fits_parent);
}

BOOST_AUTO_TEST_SUITE_END()
