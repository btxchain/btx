// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_coupled_initial_state_product.h>

#include <boost/test/unit_test.hpp>

#include <array>

namespace {

namespace rc = matmul::v4::rc;

uint256 H(uint8_t value)
{
    std::array<unsigned char, 32> bytes{};
    bytes.fill(value);
    return uint256{Span<const unsigned char>{
        bytes.data(), bytes.size()}};
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
    out.exchange_rows = 32;
    return out;
}

rc::RCStage3SuccinctProof Statement()
{
    rc::RCStage3SuccinctProof out;
    out.statement = rc::RCStage3StatementKind::Coupled;
    out.public_inputs.height = 700;
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

rc::RCCoupParams Params(
    const rc::RCStage3CoupledShape& shape)
{
    rc::RCCoupParams out;
    out.barriers = shape.barriers;
    out.lobes = shape.lobes;
    out.lobe_width = shape.lobe_width;
    out.bank_pages = shape.bank_pages;
    out.rows_per_lobe = shape.rows_per_lobe;
    out.pages_per_barrier_lobe =
        shape.pages_per_barrier_lobe;
    return out;
}

std::vector<int64_t> GemmY(
    const std::vector<int8_t>& a,
    const std::vector<int8_t>& b,
    uint32_t width)
{
    std::vector<int64_t> out(width, 0);
    for (uint32_t column = 0;
         column < width; ++column) {
        for (uint32_t k = 0; k < width; ++k) {
            out[column] +=
                int64_t{a[k]} *
                int64_t{b[k * width + column]};
        }
    }
    return out;
}

struct Fixture {
    rc::RCStage3SuccinctProof statement;
    rc::RCStage3CoupledShape shape;
    rc::RCStage3CoupledInitialStateProduct initial;
    std::vector<rc::RCStage3CoupledGemmOpening> openings;
    rc::RCStage3CoupledGemmProduct gemm;
    uint256 link;
};

Fixture MakeFixture()
{
    Fixture out;
    out.statement = Statement();
    out.shape = Shape();
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3CoupledInitialStateProduct(
            out.statement, out.shape, out.initial, &why),
        why);
    std::vector<rc::RCStage3CoupledGemmScheduleEntry>
        schedule;
    uint256 schedule_commitment;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledGemmSchedule(
            out.statement, out.shape, schedule,
            schedule_commitment, &why),
        why);
    out.openings.resize(schedule.size());
    for (uint32_t i = 0; i < schedule.size(); ++i) {
        auto& opening = out.openings[i];
        if (schedule[i].barrier == 0) {
            opening.operand_a.assign(
                out.initial.lobes[
                    schedule[i].lobe].expanded_tile.begin(),
                out.initial.lobes[
                    schedule[i].lobe].expanded_tile.begin() +
                    out.shape.rows_per_lobe *
                        out.shape.lobe_width);
        } else {
            opening.operand_a.assign(
                out.shape.rows_per_lobe *
                    out.shape.lobe_width,
                1);
        }
        opening.operand_b.assign(
            out.shape.lobe_width *
                out.shape.lobe_width,
            1);
        opening.output_y =
            GemmY(
                opening.operand_a,
                opening.operand_b,
                out.shape.lobe_width);
    }
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3CoupledGemmProduct(
            out.statement, out.shape, out.openings,
            out.gemm, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyRCStage3CoupledInitialStateGemmLink(
            out.statement, out.shape, out.initial,
            out.gemm, out.link, &why),
        why);
    return out;
}

const Fixture& Honest()
{
    static const Fixture out = MakeFixture();
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_coupled_initial_state_product_tests)

BOOST_AUTO_TEST_CASE(
    lobe_sha_xof_dequant_and_barrier0_a_link_are_exact)
{
    const auto& honest = Honest();
    BOOST_CHECK(!honest.link.IsNull());
    const auto seeds = rc::DeriveCoupledLobeSeeds(
        honest.statement.public_inputs.sigma,
        Params(honest.shape),
        honest.shape.transcript_version);
    BOOST_REQUIRE_EQUAL(
        seeds.size(), honest.initial.lobes.size());
    for (uint32_t lobe = 0; lobe < seeds.size(); ++lobe) {
        const auto expected = rc::ExpandMxDequantInt8(
            seeds[lobe], honest.shape.lobe_width,
            honest.shape.lobe_width);
        BOOST_CHECK(
            honest.initial.lobes[lobe].expanded_tile ==
            expected);
    }
    const auto audit =
        rc::CurrentRCStage3CoupledInitialStateProductAudit();
    BOOST_CHECK(audit.lobe_seed_sha_executable);
    BOOST_CHECK(audit.mantissa_scale_xof_executable);
    BOOST_CHECK(audit.dequant_executable);
    BOOST_CHECK(audit.complete_initial_state_root);
    BOOST_CHECK(audit.every_barrier0_gemm_a_slice_equal);
    BOOST_CHECK(!audit.production_streaming_complete);
    BOOST_CHECK(!audit.recursively_consumed);

    uint256 link;
    std::string why;
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3CoupledInitialStateProduct(
            honest.statement, honest.shape,
            honest.initial, &why),
        why);
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3CoupledInitialStateGemmLink(
            honest.statement, honest.shape,
            honest.initial, honest.gemm,
            link, &why),
        why);
    BOOST_CHECK(link == honest.link);
}

BOOST_AUTO_TEST_CASE(
    seed_xof_dequant_root_and_cross_product_mutations_reject)
{
    const auto& honest = Honest();
    std::string why;

    auto seed = honest.initial;
    seed.lobes[0].lobe_seed.manifest.preimage.back() ^= 1;
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledInitialStateProductSchedule(
            honest.statement, honest.shape, seed, &why));

    auto xof = honest.initial;
    xof.lobes[0].mantissa.output[0] ^= 1;
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledInitialStateProductSchedule(
            honest.statement, honest.shape, xof, &why));

    auto dequant = honest.initial;
    dequant.lobes[0].expanded_tile[0] ^= 1;
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledInitialStateProductSchedule(
            honest.statement, honest.shape, dequant, &why));

    auto root = honest.initial;
    root.initial_state_endpoint_root = H(0xa5);
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledInitialStateProductSchedule(
            honest.statement, honest.shape, root, &why));

    auto schedule = honest.initial;
    ++schedule.lobes[0].lobe;
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledInitialStateProductSchedule(
            honest.statement, honest.shape, schedule, &why));

    auto wrong_statement = honest.statement;
    wrong_statement.public_inputs.header_commitment = H(0xa6);
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledInitialStateProductSchedule(
            wrong_statement, honest.shape, honest.initial, &why));

    auto wrong_transcript = honest.shape;
    wrong_transcript.transcript_version = rc::ENC_RC_V3;
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledInitialStateProductSchedule(
            honest.statement, wrong_transcript,
            honest.initial, &why));

    auto openings = honest.openings;
    openings[0].operand_a[0] ^= 1;
    openings[0].output_y =
        GemmY(
            openings[0].operand_a,
            openings[0].operand_b,
            honest.shape.lobe_width);
    rc::RCStage3CoupledGemmProduct bad_gemm;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledGemmProduct(
            honest.statement, honest.shape,
            openings, bad_gemm, &why),
        why);
    uint256 link;
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledInitialStateGemmLink(
            honest.statement, honest.shape,
            honest.initial, bad_gemm, link, &why));
    BOOST_CHECK(
        why.find("25_to_30") != std::string::npos);

    auto sha_proof = honest.initial;
    BOOST_REQUIRE(
        !sha_proof.lobes[0].lobe_seed.proof.proofs.empty());
    BOOST_REQUIRE(
        !sha_proof.lobes[0].lobe_seed.proof.proofs[0]
             .quotient.batch.columns.empty());
    sha_proof.lobes[0].lobe_seed.proof.proofs[0]
        .quotient.batch.columns[0].root = H(0xb0);
    BOOST_CHECK(
        !rc::VerifyRCStage3CoupledInitialStateProduct(
            honest.statement, honest.shape,
            sha_proof, &why));

    auto mantissa_proof = honest.initial;
    BOOST_REQUIRE(
        !mantissa_proof.lobes[0]
             .mantissa_proof.proofs.empty());
    BOOST_REQUIRE(
        !mantissa_proof.lobes[0]
             .mantissa_proof.proofs[0]
             .quotient.batch.columns.empty());
    mantissa_proof.lobes[0].mantissa_proof.proofs[0]
        .quotient.batch.columns[0].root = H(0xb1);
    BOOST_CHECK(
        !rc::VerifyRCStage3CoupledInitialStateProduct(
            honest.statement, honest.shape,
            mantissa_proof, &why));

    auto scale_proof = honest.initial;
    BOOST_REQUIRE(
        !scale_proof.lobes[0].scale_proof.proofs.empty());
    BOOST_REQUIRE(
        !scale_proof.lobes[0].scale_proof.proofs[0]
             .quotient.batch.columns.empty());
    scale_proof.lobes[0].scale_proof.proofs[0]
        .quotient.batch.columns[0].root = H(0xb2);
    BOOST_CHECK(
        !rc::VerifyRCStage3CoupledInitialStateProduct(
            honest.statement, honest.shape,
            scale_proof, &why));

    auto dequant_proof = honest.initial;
    dequant_proof.lobes[0].dequant_proof.batch.groups[0]
        .row_commit.root[0] =
            rc::gkr_field::FromU64(0xb1);
    BOOST_CHECK(
        !rc::VerifyRCStage3CoupledInitialStateProduct(
            honest.statement, honest.shape,
            dequant_proof, &why));
}

BOOST_AUTO_TEST_SUITE_END()
