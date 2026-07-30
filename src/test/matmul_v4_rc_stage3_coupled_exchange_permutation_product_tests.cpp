// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_coupled_exchange_permutation_product.h>

#include <array>
#include <cstdlib>

namespace {

namespace rc = matmul::v4::rc;

uint256 H(uint8_t value)
{
    std::array<unsigned char, 32> bytes{};
    bytes.fill(value);
    return uint256{Span<const unsigned char>{
        bytes.data(), bytes.size()}};
}

rc::RCStage3CoupledShape Shape(uint32_t exchange_rounds)
{
    rc::RCStage3CoupledShape out;
    out.barriers = 4;
    out.lobes = 1;
    out.lobe_width = 32;
    out.bank_pages = 1;
    out.rows_per_lobe = 1;
    out.pages_per_barrier_lobe = 1;
    out.transcript_version = rc::ENC_RC_V4;
    out.full_bank_schedule = true;
    out.material_exchange = true;
    out.exchange_rows = 32;
    out.exchange_rounds = exchange_rounds;
    return out;
}

rc::RCStage3SuccinctProof Statement()
{
    rc::RCStage3SuccinctProof out;
    out.statement = rc::RCStage3StatementKind::Coupled;
    out.public_inputs.height = 811;
    out.public_inputs.n_bits = 0x207fffffU;
    out.public_inputs.coupled_profile = 4;
    out.public_inputs.transcript_version = rc::ENC_RC_V4;
    out.public_inputs.header_commitment = H(0x11);
    out.public_inputs.params_commitment = H(0x22);
    out.public_inputs.target = H(0xff);
    out.public_inputs.sigma = H(0x33);
    out.public_inputs.coupled_digest = H(0x44);
    out.public_inputs.final_digest = H(0x44);
    return out;
}

std::vector<int64_t> Values(uint32_t count, uint64_t salt)
{
    std::vector<int64_t> out(count);
    for (uint32_t i = 0; i < count; ++i) {
        const uint64_t bits =
            (salt << 48) ^
            (uint64_t{i} * UINT64_C(0x9e3779b97f4a7c15));
        out[i] = static_cast<int64_t>(bits);
    }
    return out;
}

rc::RCStage3CoupledExchangePermutationWitness Witness(
    const rc::RCStage3CoupledShape& shape)
{
    rc::RCStage3CoupledExchangePermutationWitness out;
    const uint32_t lobe_cells =
        shape.rows_per_lobe * shape.lobe_width;
    const uint32_t state_cells =
        shape.lobes * lobe_cells;
    for (uint32_t barrier = 0;
         barrier < shape.barriers; ++barrier) {
        for (uint32_t lobe = 0;
             lobe < shape.lobes; ++lobe) {
            out.fixed_exchange_inputs.push_back(
                Values(lobe_cells, 10 + barrier * 3 + lobe));
        }
        for (uint32_t round = 0;
             round < shape.exchange_rounds; ++round) {
            out.material_exchange_inputs.push_back(
                Values(state_cells, 40 + barrier * 7 + round));
        }
        out.permutation_inputs.push_back(
            Values(state_cells, 80 + barrier));
    }
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_coupled_exchange_permutation_product_tests)

BOOST_AUTO_TEST_CASE(
    exact_fixed_exchange_and_v4_permutation_products_execute)
{
    const auto statement = Statement();
    const auto shape = Shape(0);
    const auto witness = Witness(shape);
    rc::RCStage3CoupledExchangePermutationProduct product;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3CoupledExchangePermutationProduct(
            statement, shape, witness, product, &why),
        why);
    BOOST_REQUIRE_EQUAL(product.exchange_stages.size(), 4U);
    BOOST_REQUIRE_EQUAL(product.permutation_stages.size(), 4U);
    BOOST_CHECK_MESSAGE(
        rc::ValidateRCStage3CoupledExchangePermutationProductSchedule(
            statement, shape, product, &why),
        why);
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3CoupledExchangePermutationProduct(
            statement, shape, product, &why),
        why);
}

BOOST_AUTO_TEST_CASE(
    schedules_reject_omission_reorder_root_and_value_attacks)
{
    const auto statement = Statement();
    const auto shape = Shape(0);
    const auto witness = Witness(shape);
    rc::RCStage3CoupledExchangePermutationProduct honest;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3CoupledExchangePermutationProduct(
            statement, shape, witness, honest, &why),
        why);

    auto omitted = honest;
    omitted.exchange_stages.pop_back();
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledExchangePermutationProductSchedule(
            statement, shape, omitted, &why));

    auto reordered = honest;
    std::swap(
        reordered.exchange_stages[0],
        reordered.exchange_stages[1]);
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledExchangePermutationProductSchedule(
            statement, shape, reordered, &why));

    auto root = honest;
    root.permutation_output_endpoint_root = H(0xa1);
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledExchangePermutationProductSchedule(
            statement, shape, root, &why));

    auto pin_root = honest;
    pin_root.permutation_stages[0]
        .pin.column_roots[2].root = H(0xa2);
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledExchangePermutationProductSchedule(
            statement, shape, pin_root, &why));

    auto input_value = honest;
    input_value.permutation_stages[0].input[3] ^= 1;
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledExchangePermutationProductSchedule(
            statement, shape, input_value, &why));

    auto output_value = honest;
    output_value.exchange_stages[0].output[7] ^= 1;
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledExchangePermutationProductSchedule(
            statement, shape, output_value, &why));

    auto index_schedule = honest;
    index_schedule.permutation_stages[0]
        .schedule.xor_mask_bit[0] ^= 1;
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledExchangePermutationProductSchedule(
            statement, shape, index_schedule, &why));

    auto proof_root = honest;
    proof_root.permutation_stages[0]
        .proof.batch.columns[2].root = H(0xa3);
    BOOST_CHECK(
        !rc::VerifyRCStage3CoupledExchangePermutationProduct(
            statement, shape, proof_root, &why));
}

BOOST_AUTO_TEST_CASE(
    material_round_manifest_is_dependency_linked_and_exact)
{
    const auto statement = Statement();
    const auto shape = Shape(1);
    const auto witness = Witness(shape);
    rc::RCStage3CoupledExchangePermutationProduct product;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledExchangePermutationProduct(
            statement, shape, witness, product, &why),
        why);
    BOOST_REQUIRE_EQUAL(product.exchange_stages.size(), 8U);
    uint32_t material = 0;
    for (const auto& stage : product.exchange_stages) {
        if (stage.schedule.kind ==
            rc::RCStage3CoupledExchangeStageKind::MaterialRound) {
            ++material;
            BOOST_CHECK_EQUAL(stage.hash_executions.size(), 9U);
        }
    }
    BOOST_CHECK_EQUAL(material, 4U);
    BOOST_CHECK_MESSAGE(
        rc::ValidateRCStage3CoupledExchangePermutationProductSchedule(
            statement, shape, product, &why),
        why);
    // Empty proof bundles never masquerade as executed hash children.
    BOOST_CHECK(
        !rc::VerifyRCStage3CoupledExchangePermutationProduct(
            statement, shape, product, &why));

    auto seed = product;
    auto& first_material = seed.exchange_stages[1];
    first_material.hash_executions[0]
        .manifest.preimage.back() ^= 1;
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledExchangePermutationProductSchedule(
            statement, shape, seed, &why));

    auto xof = product;
    xof.exchange_stages[1].hash_executions[1]
        .manifest.digest[0] ^= 1;
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledExchangePermutationProductSchedule(
            statement, shape, xof, &why));

    auto value = product;
    value.exchange_stages[1].input[0] ^= 1;
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledExchangePermutationProductSchedule(
            statement, shape, value, &why));
}

BOOST_AUTO_TEST_CASE(material_round_full_sha_air_round_trip_optional)
{
    if (std::getenv(
            "BTX_RUN_STAGE3_COUPLED_EXCHANGE_HASH_PROVE") ==
        nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_COUPLED_EXCHANGE_HASH_PROVE=1 "
            "for all material-round SHA provenance proofs");
        return;
    }
    const auto statement = Statement();
    const auto shape = Shape(1);
    rc::RCStage3CoupledExchangePermutationProduct product;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3CoupledExchangePermutationProduct(
            statement, shape, Witness(shape), product, &why),
        why);
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3CoupledExchangePermutationProduct(
            statement, shape, product, &why),
        why);
}

BOOST_AUTO_TEST_CASE(audit_is_local_and_fail_closed_transitively)
{
    const auto audit =
        rc::CurrentRCStage3CoupledExchangePermutationProductAudit();
    BOOST_CHECK(audit.exact_exchange_schedule);
    BOOST_CHECK(audit.fixed_segment_equality_executable);
    BOOST_CHECK(audit.material_seed_sha256d_executable);
    BOOST_CHECK(audit.material_sha_xof_executable);
    BOOST_CHECK(audit.xor_and_indexed_permutation_executable);
    BOOST_CHECK(audit.exact_public_permutation_schedule);
    BOOST_CHECK(audit.permutation_indexed_product_executable);
    BOOST_CHECK(audit.proof_owned_endpoint_roots);
    BOOST_CHECK(
        audit.endpoints_34_through_38_bounded_local_complete);
    BOOST_CHECK(!audit.external_producer_provenance_complete);
    BOOST_CHECK(!audit.production_streaming_complete);
    BOOST_CHECK(!audit.recursively_consumed);
    BOOST_CHECK(!audit.transitively_complete);
}

BOOST_AUTO_TEST_SUITE_END()
