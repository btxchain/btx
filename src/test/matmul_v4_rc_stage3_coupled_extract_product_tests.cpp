// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_coupled_extract_product.h>

#include <array>
#include <cstdlib>
#include <stdexcept>

namespace {

namespace rc = matmul::v4::rc;

uint256 H(uint8_t value)
{
    std::array<unsigned char, 32> bytes{};
    bytes.fill(value);
    return uint256{Span<const unsigned char>{
        bytes.data(), bytes.size()}};
}

rc::RCStage3SuccinctProof Statement()
{
    rc::RCStage3SuccinctProof out;
    out.statement = rc::RCStage3StatementKind::Coupled;
    out.public_inputs.height = 907;
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

rc::RCStage3CoupledShape Shape()
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
    return out;
}

std::vector<std::array<int64_t, rc::kRCMxBlockLen>> Inputs()
{
    std::vector<std::array<int64_t, rc::kRCMxBlockLen>> out(4);
    for (uint32_t barrier = 0; barrier < out.size(); ++barrier) {
        for (uint32_t i = 0; i < out[barrier].size(); ++i) {
            out[barrier][i] =
                static_cast<int64_t>(
                    (uint64_t{barrier + 1} << 40) ^
                    (uint64_t{i} *
                     UINT64_C(0x9e3779b97f4a7c15)));
        }
    }
    return out;
}

const rc::RCStage3CoupledExtractProduct& StructuralProduct()
{
    static const rc::RCStage3CoupledExtractProduct product = [] {
        rc::RCStage3CoupledExtractProduct out;
        std::string why;
        if (!rc::BuildRCStage3CoupledExtractProduct(
                Statement(), Shape(), Inputs(), out, &why)) {
            throw std::runtime_error(why);
        }
        return out;
    }();
    return product;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_coupled_extract_product_tests)

BOOST_AUTO_TEST_CASE(
    exact_minimum_shape_schedule_maps_every_transcript_cell)
{
    const auto schedule =
        rc::BuildRCStage3CoupledExtractSchedule(
            Statement(), Shape());
    BOOST_REQUIRE_EQUAL(schedule.size(), 4U);
    for (uint32_t i = 0; i < schedule.size(); ++i) {
        BOOST_CHECK_EQUAL(schedule[i].instance, i);
        BOOST_CHECK_EQUAL(schedule[i].barrier, i);
        BOOST_CHECK_EQUAL(schedule[i].tile, 0U);
        BOOST_CHECK(!schedule[i].extract_prf.IsNull());
    }
}

BOOST_AUTO_TEST_CASE(
    structural_product_closes_endpoints_42_through_47)
{
    const auto& product = StructuralProduct();
    std::string why;
    BOOST_CHECK_MESSAGE(
        rc::ValidateRCStage3CoupledExtractProductSchedule(
            Statement(), Shape(), product, &why),
        why);
    BOOST_CHECK_EQUAL(product.expected_tiles, 4U);
    BOOST_CHECK_EQUAL(product.tiles.size(), 4U);
    BOOST_CHECK_EQUAL(product.input_cells.shards.size(), 4U);
    BOOST_CHECK_EQUAL(product.sampler_cells.shards.size(), 4U);
    BOOST_CHECK_EQUAL(product.scale_cells.shards.size(), 4U);
    BOOST_CHECK_EQUAL(
        product.output_to_barrier.extract_outputs.shards.size(), 4U);
    BOOST_CHECK_EQUAL(
        product.output_to_barrier.barriers.size(), 4U);
    BOOST_CHECK(
        !product.output_to_barrier.pin.link_commitment.IsNull());
}

BOOST_AUTO_TEST_CASE(
    omission_reorder_value_root_and_barrier_alias_fail_closed)
{
    const auto& product = StructuralProduct();
    std::string why;

    auto omitted = product;
    omitted.tiles.pop_back();
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledExtractProductSchedule(
            Statement(), Shape(), omitted, &why));

    auto reordered = product;
    std::swap(reordered.tiles[0], reordered.tiles[1]);
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledExtractProductSchedule(
            Statement(), Shape(), reordered, &why));

    auto value = product;
    value.tiles[2].input[7] ^= 1;
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledExtractProductSchedule(
            Statement(), Shape(), value, &why));

    auto root = product;
    root.sampler_endpoint_root = H(0xee);
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledExtractProductSchedule(
            Statement(), Shape(), root, &why));

    auto truncated_mix = product;
    truncated_mix.tiles[0].mix_pin.column_roots.clear();
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledExtractProductSchedule(
            Statement(), Shape(), truncated_mix, &why));

    auto barrier = product;
    barrier.output_to_barrier.barriers[1]
        .manifest.state_bytes[3] ^= 0x80;
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledExtractProductSchedule(
            Statement(), Shape(), barrier, &why));
}

BOOST_AUTO_TEST_CASE(
    proof_overlay_rebind_restores_flat_bundle_commitments)
{
    // Simulate engine verify: structural rebuild + wire proof public
    // material that differs from StructuralProofRoots stubs.
    auto product = StructuralProduct();
    std::string why;
    BOOST_REQUIRE(
        !product.input_cells.shards.empty() &&
        !product.input_cells.shards[0].proof.batch.columns.empty());
    BOOST_REQUIRE(
        !product.output_to_barrier.extract_outputs.shards.empty() &&
        !product.output_to_barrier.extract_outputs.shards[0]
             .proof.batch.columns.empty());
    const uint256 stale_input = product.input_cells.bundle_commitment;
    const uint256 stale_output =
        product.output_to_barrier.extract_outputs.bundle_commitment;
    const uint256 stale_link =
        product.output_to_barrier.pin.link_commitment;
    product.input_cells.shards[0].proof.trace_commit = H(0xab);
    product.input_cells.shards[0].proof.batch.columns.back().root =
        H(0xcd);
    product.output_to_barrier.extract_outputs.shards[0].proof.trace_commit =
        H(0xef);
    product.output_to_barrier.extract_outputs.shards[0]
        .proof.batch.columns.back()
        .root = H(0x11);
    BOOST_CHECK(
        rc::ComputeRCStage3CoupledSemanticFlatBundleCommitment(
            product.input_cells) != stale_input);
    BOOST_REQUIRE_MESSAGE(
        rc::RebindRCStage3CoupledExtractProductProofCommitments(
            Statement(), Shape(), product, &why),
        why);
    BOOST_CHECK(
        product.input_cells.bundle_commitment ==
        rc::ComputeRCStage3CoupledSemanticFlatBundleCommitment(
            product.input_cells));
    BOOST_CHECK(product.input_cells.bundle_commitment != stale_input);
    BOOST_CHECK(
        product.output_to_barrier.extract_outputs.bundle_commitment !=
        stale_output);
    BOOST_CHECK(
        product.output_to_barrier.pin.link_commitment != stale_link);
    BOOST_CHECK_MESSAGE(
        rc::ValidateRCStage3CoupledExtractProductSchedule(
            Statement(), Shape(), product, &why),
        why);
}

BOOST_AUTO_TEST_CASE(full_exact_prove_verify_optional)
{
    if (std::getenv(
            "BTX_RUN_STAGE3_COUPLED_EXTRACT_PROVE") == nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_COUPLED_EXTRACT_PROVE=1 for "
            "all sampler, ChaCha, SHA and endpoint-47 proofs");
        return;
    }
    rc::RCStage3CoupledExtractProduct product;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3CoupledExtractProduct(
            Statement(), Shape(), Inputs(), product, &why),
        why);
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3CoupledExtractProduct(
            Statement(), Shape(), product, &why),
        why);
}

BOOST_AUTO_TEST_CASE(audit_is_bounded_and_fail_closed_transitively)
{
    const auto audit =
        rc::CurrentRCStage3CoupledExtractProductAudit();
    BOOST_CHECK(audit.exact_all_tile_schedule);
    BOOST_CHECK(audit.int64_mix_binding_executable);
    BOOST_CHECK(audit.sampler_walk_executable);
    BOOST_CHECK(audit.chacha_consumption_executable);
    BOOST_CHECK(audit.scale_sha_executable);
    BOOST_CHECK(audit.output_memory_root_executable);
    BOOST_CHECK(audit.endpoint47_equality_executable);
    BOOST_CHECK(
        audit.endpoints_42_through_46_bounded_complete);
    BOOST_CHECK(!audit.upstream_producer_provenance_complete);
    BOOST_CHECK(!audit.production_streaming_complete);
    BOOST_CHECK(!audit.recursively_consumed);
    BOOST_CHECK(!audit.transitively_complete);
}

BOOST_AUTO_TEST_SUITE_END()
