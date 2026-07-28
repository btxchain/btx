// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_coupled_gemm_product.h>

#include <array>

namespace {

namespace rc = matmul::v4::rc;

uint256 H(uint8_t value)
{
    std::array<unsigned char, 32> bytes{};
    bytes.fill(value);
    return uint256{
        Span<const unsigned char>{bytes.data(), bytes.size()}};
}

rc::RCStage3SuccinctProof Statement()
{
    rc::RCStage3SuccinctProof out;
    out.statement = rc::RCStage3StatementKind::Coupled;
    out.public_inputs.height = 700;
    out.public_inputs.n_bits = 0x207fffffU;
    out.public_inputs.coupled_profile = 2;
    out.public_inputs.transcript_version = 4;
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
    out.transcript_version = 4;
    out.full_bank_schedule = true;
    return out;
}

std::vector<rc::RCStage3CoupledGemmOpening> Openings(
    size_t count, int64_t y = 32)
{
    std::vector<rc::RCStage3CoupledGemmOpening> out(count);
    for (auto& opening : out) {
        opening.operand_a.assign(32, 1);
        opening.operand_b.assign(32 * 32, 1);
        opening.output_y.assign(32, y);
    }
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_coupled_gemm_product_tests)

BOOST_AUTO_TEST_CASE(audit_is_exact_local_and_fail_closed_transitively)
{
    const auto audit =
        rc::CurrentRCStage3CoupledGemmProductAudit();
    BOOST_CHECK(audit.immutable_shape_derived_schedule);
    BOOST_CHECK(audit.every_a_opening_bound);
    BOOST_CHECK(audit.every_b_opening_bound);
    BOOST_CHECK(audit.every_y_opening_bound);
    BOOST_CHECK(audit.every_dot_air_executed);
    BOOST_CHECK(audit.endpoints_30_through_32_locally_complete);
    BOOST_CHECK(!audit.bank_page_producer_provenance_complete);
    BOOST_CHECK(!audit.prior_state_producer_provenance_complete);
    BOOST_CHECK(audit.production_streaming_complete);
    BOOST_CHECK(!audit.recursively_consumed);
    BOOST_CHECK(!audit.transitively_complete);
}

BOOST_AUTO_TEST_CASE(
    exact_product_executes_all_gemms_and_rejects_schedule_opening_sum_and_root_attacks)
{
    const auto statement = Statement();
    const auto shape = Shape();
    std::vector<rc::RCStage3CoupledGemmScheduleEntry> schedule;
    uint256 schedule_commitment;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledGemmSchedule(
            statement, shape, schedule,
            schedule_commitment, &why),
        why);
    BOOST_REQUIRE_EQUAL(schedule.size(), 4U);
    for (uint32_t i = 0; i < schedule.size(); ++i) {
        BOOST_CHECK_EQUAL(schedule[i].schedule_index, i);
        BOOST_CHECK_EQUAL(schedule[i].barrier, i);
        BOOST_CHECK_EQUAL(schedule[i].lobe, 0U);
        BOOST_CHECK_EQUAL(schedule[i].page_slot, 0U);
        BOOST_CHECK_EQUAL(schedule[i].page_id, 0U);
    }

    rc::RCStage3CoupledGemmProduct honest;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3CoupledGemmProduct(
            statement, shape, Openings(schedule.size()),
            honest, &why),
        why);
    BOOST_REQUIRE_EQUAL(honest.gemms.size(), 4U);
    BOOST_CHECK_EQUAL(honest.expected_output_tiles, 4U);
    BOOST_CHECK(!honest.operand_a_endpoint_root.IsNull());
    BOOST_CHECK(!honest.operand_b_endpoint_root.IsNull());
    BOOST_CHECK(!honest.output_y_endpoint_root.IsNull());
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3CoupledGemmProduct(
            statement, shape, honest, &why),
        why);

    auto omitted = honest;
    omitted.gemms.pop_back();
    BOOST_CHECK(!rc::ValidateRCStage3CoupledGemmSchedule(
        statement, shape, omitted, &why));

    auto reordered = honest;
    std::swap(reordered.gemms[0], reordered.gemms[1]);
    BOOST_CHECK(!rc::ValidateRCStage3CoupledGemmSchedule(
        statement, shape, reordered, &why));

    auto schedule_attack = honest;
    ++schedule_attack.gemms[0].schedule.barrier;
    BOOST_CHECK(!rc::ValidateRCStage3CoupledGemmSchedule(
        statement, shape, schedule_attack, &why));

    auto opening_attack = honest;
    opening_attack.gemms[0].operand_a[0] = 2;
    BOOST_CHECK(!rc::ValidateRCStage3CoupledGemmSchedule(
        statement, shape, opening_attack, &why));

    auto pin_root_attack = honest;
    pin_root_attack.gemms[0].tiles[0]
        .pin.column_roots[rc::kRCStage3CoupledGemmY]
        .root = H(0xee);
    BOOST_CHECK(!rc::VerifyRCStage3CoupledGemmProduct(
        statement, shape, pin_root_attack, &why));

    auto proof_root_attack = honest;
    proof_root_attack.gemms[0].tiles[0]
        .proof.batch.columns[rc::kRCStage3CoupledGemmA]
        .root = H(0xdd);
    BOOST_CHECK(!rc::VerifyRCStage3CoupledGemmProduct(
        statement, shape, proof_root_attack, &why));

    rc::RCStage3CoupledGemmProduct bad_sum;
    BOOST_CHECK(!rc::ProveRCStage3CoupledGemmProduct(
        statement, shape, Openings(schedule.size(), 31),
        bad_sum, &why));
}

BOOST_AUTO_TEST_CASE(
    compact_v2_proves_callback_instances_discards_native_vectors_and_rejects_proof_schedule_and_selector_attacks)
{
    const auto statement = Statement();
    const auto shape = Shape();
    std::vector<rc::RCStage3CoupledGemmScheduleEntry> schedule;
    uint256 schedule_commitment;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledGemmSchedule(
            statement, shape, schedule,
            schedule_commitment, &why),
        why);
    const auto openings = Openings(schedule.size());
    std::vector<
        rc::RCStage3CoupledGemmCompactInstanceV2>
        instances;
    for (uint64_t i = 0; i < schedule.size(); ++i) {
        rc::RCStage3CoupledGemmCompactInstanceV2 instance;
        BOOST_REQUIRE_MESSAGE(
            rc::ProveRCStage3CoupledGemmCompactInstanceV2(
                statement, shape, i, openings[i],
                instance, &why),
            why);
        BOOST_CHECK_EQUAL(
            instance.schedule.schedule_index, i);
        BOOST_CHECK(!instance.operand_a_trace_root.IsNull());
        BOOST_CHECK(!instance.operand_b_trace_root.IsNull());
        BOOST_CHECK(!instance.output_y_trace_root.IsNull());
        BOOST_CHECK(!instance.instance_commitment.IsNull());
        for (const auto& tile : instance.tiles) {
            // Degree-three product/chain constraints have quotient length
            // 2*N-1, so both the public pin and proof must enforce the 2*N
            // coefficient domain. This is consensus shape, not a prover
            // tuning parameter.
            BOOST_CHECK_EQUAL(
                tile.pin.n_coeffs,
                2u * tile.pin.n_rows);
            BOOST_CHECK_EQUAL(
                tile.proof.batch.n_coeffs,
                tile.pin.n_coeffs);
        }
        instances.push_back(std::move(instance));
    }

    rc::RCStage3CoupledGemmCompactProductV2 honest;
    BOOST_REQUIRE_MESSAGE(
        rc::FinalizeRCStage3CoupledGemmCompactProductV2(
            statement, shape, instances, honest, &why),
        why);
    BOOST_CHECK_EQUAL(honest.gemms.size(), schedule.size());
    BOOST_CHECK_EQUAL(
        honest.expected_output_tiles, schedule.size());
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3CoupledGemmCompactProductV2(
            statement, shape, honest, &why),
        why);

    auto omitted = honest;
    omitted.gemms.pop_back();
    BOOST_CHECK(
        !rc::VerifyRCStage3CoupledGemmCompactProductV2(
            statement, shape, omitted, &why));

    auto reordered = honest;
    std::swap(reordered.gemms[0], reordered.gemms[1]);
    BOOST_CHECK(
        !rc::VerifyRCStage3CoupledGemmCompactProductV2(
            statement, shape, reordered, &why));

    auto selector = honest;
    selector.gemms[0].tiles[0]
        .pin.column_roots[rc::kRCStage3CoupledGemmActive]
        .root = H(0xa1);
    BOOST_CHECK(
        !rc::VerifyRCStage3CoupledGemmCompactProductV2(
            statement, shape, selector, &why));

    auto proof = honest;
    proof.gemms[0].tiles[0]
        .proof.batch.columns[rc::kRCStage3CoupledGemmY]
        .root = H(0xa2);
    BOOST_CHECK(
        !rc::VerifyRCStage3CoupledGemmCompactProductV2(
            statement, shape, proof, &why));

    auto wrong_sum = openings[0];
    wrong_sum.output_y[0] = 31;
    rc::RCStage3CoupledGemmCompactInstanceV2 bad_sum;
    BOOST_CHECK(
        !rc::ProveRCStage3CoupledGemmCompactInstanceV2(
            statement, shape, 0, wrong_sum,
            bad_sum, &why));

    rc::RCStage3CoupledGemmCompactStreamingV2 stream{
        statement, shape};
    for (uint64_t i = 0; i < schedule.size(); ++i) {
        stream.OnGemm({
            .barrier = schedule[i].barrier,
            .lobe = schedule[i].lobe,
            .page_id = schedule[i].page_id,
            .rows = shape.rows_per_lobe,
            .width = shape.lobe_width,
            .operand_a = openings[i].operand_a.data(),
            .operand_b = openings[i].operand_b.data(),
            .gemm_y = openings[i].output_y.data(),
        });
        BOOST_CHECK_EQUAL(
            stream.RetainedNativeBytes(), 0U);
    }
    BOOST_CHECK_EQUAL(
        stream.PeakNativeBytes(),
        uint64_t{32} + uint64_t{32 * 32} +
            uint64_t{32 * sizeof(int64_t)});
    BOOST_REQUIRE_MESSAGE(stream.Complete(&why), why);
    rc::RCStage3CoupledGemmCompactProductV2 streamed;
    BOOST_REQUIRE_MESSAGE(
        stream.Finalize(streamed, &why), why);
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3CoupledGemmCompactProductV2(
            statement, shape, streamed, &why),
        why);

    rc::RCStage3CoupledGemmCompactStreamingV2 missing{
        statement, shape};
    missing.OnGemm({
        .barrier = schedule[0].barrier,
        .lobe = schedule[0].lobe,
        .page_id = schedule[0].page_id,
        .rows = shape.rows_per_lobe,
        .width = shape.lobe_width,
        .operand_a = openings[0].operand_a.data(),
        .operand_b = openings[0].operand_b.data(),
        .gemm_y = openings[0].output_y.data(),
    });
    BOOST_CHECK(!missing.Complete(&why));

    rc::RCStage3CoupledGemmCompactStreamingV2 reordered_stream{
        statement, shape};
    reordered_stream.OnGemm({
        .barrier = schedule[1].barrier,
        .lobe = schedule[1].lobe,
        .page_id = schedule[1].page_id,
        .rows = shape.rows_per_lobe,
        .width = shape.lobe_width,
        .operand_a = openings[1].operand_a.data(),
        .operand_b = openings[1].operand_b.data(),
        .gemm_y = openings[1].output_y.data(),
    });
    BOOST_CHECK(!reordered_stream.Complete(&why));
}

BOOST_AUTO_TEST_SUITE_END()
