// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_gkr_wireless_receipt.h>

#include <cstdlib>

namespace wireless =
    matmul::v4::rc::stage3_gkr_wireless_receipt;
namespace rc = matmul::v4::rc;
namespace gf = matmul::v4::rc::gkr_field;

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_gkr_wireless_receipt_tests)

namespace {

uint256 Root(uint8_t seed)
{
    uint256 out;
    for (uint32_t index = 0; index < 32; ++index) {
        out.data()[index] =
            static_cast<uint8_t>(seed + 17 * index);
    }
    return out;
}

rc::RCEpisodeParams TinyParams()
{
    rc::RCEpisodeParams out;
    out.rounds = 1;
    out.d_head = 32;
    out.n_q = 32;
    out.n_ctx = 32;
    out.L_lyr = 1;
    out.d_model = 32;
    out.d_ff = 32;
    out.b_seq = 32;
    out.T_leaf = 64;
    return out;
}

wireless::PublicDescriptorV1 Descriptor()
{
    const auto params = TinyParams();
    const std::vector<uint256> round_roots{Root(0x31)};
    const uint256 digest =
        rc::RCGkrEpisodeDigestFromRoots(round_roots);
    wireless::PublicDescriptorV1 out;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        wireless::BuildPublicDescriptorV1(
            params, 177, digest,
            rc::RCGkrDerivePowBind(digest),
            Root(0x45), round_roots, Root(0x56),
            out, &why),
        why);
    return out;
}

std::vector<std::vector<gf::Fp3>> Columns(
    const wireless::PublicDescriptorV1& descriptor,
    const wireless::ChunkRangeV1& range)
{
    std::vector<std::vector<gf::Fp3>> out(
        range.column_count);
    for (uint32_t local = 0;
         local < range.column_count; ++local) {
        const uint32_t global =
            range.first_column + local;
        out[local].resize(
            descriptor.columns[global].logical_len);
        for (uint32_t row = 0;
             row < out[local].size(); ++row) {
            out[local][row] = {
                gf::FromU64(1 + 97 * global + 7 * row),
                gf::FromU64(3 + 89 * global + 11 * row),
                gf::FromU64(5 + 83 * global + 13 * row),
            };
        }
    }
    return out;
}

struct HonestFixture {
    wireless::PublicDescriptorV1 descriptor;
    wireless::ChunkRangeV1 range;
    wireless::ReceiptV1 receipt;
    wireless::AuditV1 build_audit;

    HonestFixture()
    {
        descriptor = Descriptor();
        range = wireless::BuildChunkPlanV1(
            descriptor,
            wireless::kMaxOracleColumnsPerReceiptV1)
                    .at(0);
        BOOST_REQUIRE_EQUAL(
            range.column_count,
            descriptor.columns.size());
        const uint256 chunk_seed =
            wireless::DeriveChunkFsSeedV1(
                descriptor, range);
        BOOST_REQUIRE(!chunk_seed.IsNull());
        const auto proved =
            rc::Fri3AlgSafeQ192K2V13BatchCommit(
                Columns(descriptor, range),
                chunk_seed, 17);
        BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
        build_audit =
            wireless::BuildReceiptV1(
                descriptor, range,
                proved.proof, receipt);
        BOOST_REQUIRE_MESSAGE(
            build_audit.valid,
            build_audit.note);
    }
};

const HonestFixture& Honest()
{
    static const HonestFixture fixture;
    return fixture;
}

} // namespace

BOOST_AUTO_TEST_CASE(
    canonical_descriptor_is_lambda_derived_and_chunk_seed_is_position_bound)
{
    const auto descriptor = Descriptor();
    BOOST_REQUIRE(
        wireless::ValidatePublicDescriptorV1(
            descriptor));
    const auto plan =
        wireless::BuildChunkPlanV1(descriptor, 2);
    BOOST_REQUIRE(!plan.empty());
    BOOST_CHECK_EQUAL(plan.front().first_column, 0U);
    BOOST_CHECK_LE(plan.front().column_count, 2U);
    uint32_t next = 0;
    for (const auto& range : plan) {
        BOOST_CHECK_EQUAL(range.first_column, next);
        BOOST_CHECK_GT(range.column_count, 0U);
        next += range.column_count;
    }
    BOOST_CHECK_EQUAL(next, descriptor.columns.size());
    BOOST_REQUIRE_GE(plan.size(), 2U);
    BOOST_CHECK(
        wireless::DeriveChunkFsSeedV1(
            descriptor, plan[0]) !=
        wireless::DeriveChunkFsSeedV1(
            descriptor, plan[1]));

    auto reordered = descriptor;
    std::swap(
        reordered.columns[0],
        reordered.columns[1]);
    reordered.descriptor_root =
        wireless::ComputePublicDescriptorRootV1(
            reordered);
    BOOST_CHECK(
        !wireless::ValidatePublicDescriptorV1(
            reordered));

    auto changed_length = descriptor;
    ++changed_length.columns[0].logical_len;
    changed_length.descriptor_root =
        wireless::ComputePublicDescriptorRootV1(
            changed_length);
    BOOST_CHECK(
        !wireless::ValidatePublicDescriptorV1(
            changed_length));

    uint32_t max_width_at_kappa = 0;
    for (uint32_t width = 1;
         width <=
             wireless::kMaxOracleColumnsPerReceiptV1;
         ++width) {
        const auto bytes =
            wireless::EstimateQ192V13ProofBytesV1(
                width,
                rc::kRCGkrColumnMaxCoeffs);
        if (!bytes.has_value() ||
            *bytes > rc::kRCFriMaxProofBytesHard) {
            break;
        }
        max_width_at_kappa = width;
    }
    BOOST_REQUIRE_GT(max_width_at_kappa, 0U);
    BOOST_REQUIRE_LE(
        *wireless::EstimateQ192V13ProofBytesV1(
            max_width_at_kappa,
            rc::kRCGkrColumnMaxCoeffs),
        rc::kRCFriMaxProofBytesHard);
    if (max_width_at_kappa <
        wireless::kMaxOracleColumnsPerReceiptV1) {
        BOOST_CHECK_GT(
            *wireless::EstimateQ192V13ProofBytesV1(
                max_width_at_kappa + 1,
                rc::kRCGkrColumnMaxCoeffs),
            rc::kRCFriMaxProofBytesHard);
    }
}

BOOST_AUTO_TEST_CASE(
    v13_wireless_receipt_authenticates_dual_ood_cells_and_rejects_transplants)
{
    if (std::getenv(
            "BTX_RUN_STAGE3_GKR_WIRELESS_V13") ==
        nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_GKR_WIRELESS_V13=1 "
            "for the proof-level V13 attack matrix");
        return;
    }
    const HonestFixture& honest = Honest();
    const auto& audit = honest.build_audit;
    BOOST_REQUIRE_MESSAGE(audit.valid, audit.note);
    BOOST_CHECK(audit.v13_fri_verified);
    BOOST_CHECK(
        audit.dual_ood_evaluations_proof_owned);
    BOOST_CHECK(
        audit.authenticated_proof_statement_bound);
    BOOST_CHECK(
        audit.normalized_public_input_exported);
    BOOST_CHECK(
        !audit.arbitrary_gkr_mle_claims_verified);
    BOOST_CHECK(
        !audit.episode_content_to_round_roots_verified);
    BOOST_CHECK(!audit.recursively_consumed);

    std::vector<unsigned char> encoded;
    const size_t actual_bytes =
        rc::SerializeFri3AlgBatchProof(
            honest.receipt.fri_proof, encoded);
    BOOST_REQUIRE_EQUAL(actual_bytes, encoded.size());
    const auto estimated_bytes =
        wireless::EstimateQ192V13ProofBytesV1(
            honest.receipt.range.column_count,
            honest.receipt.fri_proof.n_coeffs);
    BOOST_REQUIRE(estimated_bytes.has_value());
    BOOST_CHECK_EQUAL(
        *estimated_bytes, actual_bytes);

    wireless::NormalizedPublicInputV1 normalized;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        wireless::ExportNormalizedPublicInputV1(
            honest.descriptor, honest.receipt,
            normalized, &why),
        why);
    BOOST_CHECK_EQUAL(
        normalized.column_count,
        honest.descriptor.columns.size());

    auto eval_transplant = honest.receipt;
    eval_transplant.evaluations[0].at_z1.c0 =
        gf::Add(
            eval_transplant.evaluations[0].at_z1.c0,
            1);
    eval_transplant.evaluation_root =
        wireless::ComputeEvaluationRootV1(
            eval_transplant);
    eval_transplant.receipt_root =
        wireless::ComputeReceiptRootV1(
            eval_transplant);
    BOOST_CHECK(
        !wireless::VerifyReceiptV1(
             honest.descriptor,
             eval_transplant)
             .valid);

    auto proof_tamper = honest.receipt;
    BOOST_REQUIRE(
        !proof_tamper.fri_proof.queries.empty());
    BOOST_REQUIRE(
        !proof_tamper.fri_proof.queries[0]
             .row.values.empty());
    proof_tamper.fri_proof.queries[0]
        .row.values[0].c0 =
        gf::Add(
            proof_tamper.fri_proof.queries[0]
                .row.values[0].c0,
            1);
    proof_tamper.proof_statement_root =
        wireless::ComputeProofStatementRootV1(
            proof_tamper.fri_proof);
    proof_tamper.receipt_root =
        wireless::ComputeReceiptRootV1(
            proof_tamper);
    const auto proof_tamper_audit =
        wireless::VerifyReceiptV1(
            honest.descriptor, proof_tamper);
    BOOST_CHECK(!proof_tamper_audit.valid);
    BOOST_CHECK(
        !proof_tamper_audit.v13_fri_verified);

    auto noncanonical = honest.receipt;
    // Goldilocks x+p alias probe with x=0: the in-memory representative p
    // would serialize as zero unless the receipt rejects before encoding.
    noncanonical.fri_proof.z1.c0 = gf::kP;
    noncanonical.proof_statement_root =
        wireless::ComputeProofStatementRootV1(
            noncanonical.fri_proof);
    BOOST_CHECK(
        !wireless::VerifyReceiptV1(
             honest.descriptor, noncanonical)
             .valid);

    auto other_descriptor = honest.descriptor;
    ++other_descriptor.height;
    other_descriptor.descriptor_root =
        wireless::ComputePublicDescriptorRootV1(
            other_descriptor);
    BOOST_REQUIRE(
        wireless::ValidatePublicDescriptorV1(
            other_descriptor));
    auto descriptor_transplant = honest.receipt;
    descriptor_transplant.descriptor_root =
        other_descriptor.descriptor_root;
    descriptor_transplant.evaluation_root =
        wireless::ComputeEvaluationRootV1(
            descriptor_transplant);
    descriptor_transplant.receipt_root =
        wireless::ComputeReceiptRootV1(
            descriptor_transplant);
    const auto descriptor_transplant_audit =
        wireless::VerifyReceiptV1(
            other_descriptor,
            descriptor_transplant);
    BOOST_CHECK(
        !descriptor_transplant_audit.valid);
    BOOST_CHECK_EQUAL(
        descriptor_transplant_audit.note,
        "receipt_chunk_seed_transplant");

    auto wrong_length = honest.receipt;
    ++wrong_length.fri_proof.column_len[0];
    wrong_length.proof_statement_root =
        wireless::ComputeProofStatementRootV1(
            wrong_length.fri_proof);
    wrong_length.receipt_root =
        wireless::ComputeReceiptRootV1(
            wrong_length);
    BOOST_CHECK(
        !wireless::VerifyReceiptV1(
             honest.descriptor, wrong_length)
             .exact_column_order_and_lengths);
}

BOOST_AUTO_TEST_CASE(
    ordered_receipt_set_requires_exact_nonoverlapping_layout_partition)
{
    if (std::getenv(
            "BTX_RUN_STAGE3_GKR_WIRELESS_V13") ==
        nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_GKR_WIRELESS_V13=1 "
            "for the proof-backed receipt-set matrix");
        return;
    }
    const HonestFixture& honest = Honest();
    wireless::ReceiptSetV1 set;
    set.descriptor_root =
        honest.descriptor.descriptor_root;
    set.receipts.push_back(honest.receipt);
    set.ordered_set_root =
        wireless::ComputeOrderedSetRootV1(set);
    const auto audit =
        wireless::VerifyReceiptSetV1(
            honest.descriptor, set);
    BOOST_REQUIRE_MESSAGE(audit.valid, audit.note);
    BOOST_CHECK(audit.exact_disjoint_partition);
    BOOST_CHECK(audit.every_receipt_verified);
    BOOST_CHECK(!audit.coefficient_wires_serialized);
    BOOST_CHECK(
        !audit.episode_content_to_round_roots_verified);
    BOOST_CHECK(
        !audit.arbitrary_gkr_mle_claims_verified);
    BOOST_CHECK(!audit.recursively_consumed);

    auto duplicate = set;
    duplicate.receipts.push_back(honest.receipt);
    duplicate.ordered_set_root =
        wireless::ComputeOrderedSetRootV1(
            duplicate);
    BOOST_CHECK(
        !wireless::VerifyReceiptSetV1(
             honest.descriptor, duplicate)
             .valid);

    auto root_tamper = set;
    root_tamper.ordered_set_root[0] =
        gf::Add(root_tamper.ordered_set_root[0], 1);
    BOOST_CHECK(
        !wireless::VerifyReceiptSetV1(
             honest.descriptor, root_tamper)
             .valid);
}

BOOST_AUTO_TEST_SUITE_END()
