// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_bounded_semantic_codec.h>

#include <matmul/matmul_v4_rc_stage3_composition.h>
#include <primitives/block.h>

#include <boost/test/unit_test.hpp>

#include <array>

namespace {

namespace codec =
    matmul::v4::rc::bounded_semantic_codec;
namespace rc = matmul::v4::rc;

uint256 H(uint8_t value)
{
    std::array<unsigned char, 32> bytes{};
    bytes.fill(value);
    return uint256{
        Span<const unsigned char>{
            bytes.data(), bytes.size()}};
}

rc::RCStage3SuccinctProof Statement()
{
    rc::RCStage3SuccinctProof out;
    out.statement =
        rc::RCStage3StatementKind::Composed;
    out.public_inputs.height = 31;
    out.public_inputs.n_bits = 0x207fffffU;
    out.public_inputs.episode_profile = 2;
    out.public_inputs.coupled_profile = 4;
    out.public_inputs.transcript_version =
        rc::ENC_RC_V4;
    out.public_inputs.program_consensus_pin
        .recursive_alg_hash_root = H(0x11);
    out.public_inputs.program_consensus_pin
        .external_sha256d_audit_root = H(0x12);
    out.public_inputs.program_consensus_pin
        .registry_binding = H(0x13);
    out.public_inputs.header_commitment = H(0x21);
    out.public_inputs.params_commitment = H(0x22);
    out.public_inputs.target = H(0x23);
    out.public_inputs.sigma = H(0x24);
    out.public_inputs.episode_digest = H(0x25);
    out.public_inputs.coupled_digest = H(0x26);
    const auto roles =
        rc::RequiredRCStage3RelationRoles(
            out.statement);
    for (uint32_t i = 0;
         i < roles.size(); ++i) {
        out.commitments.push_back(
            {roles[i],
             H(static_cast<uint8_t>(
                 0x40 + i))});
        out.sections.push_back(
            {roles[i],
             {static_cast<uint8_t>(i),
              0xa5, 0x5a}});
    }
    out.public_inputs.final_digest =
        rc::ComputeRCStage3FinalDigest(out);
    out.public_inputs.transcript_commitment =
        rc::ComputeRCStage3TranscriptCommitment(
            out);
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_bounded_semantic_codec_tests)

BOOST_AUTO_TEST_CASE(
    exact_episode_and_coupled_inventory_round_trip)
{
    codec::EnvelopeV1 envelope;
    envelope.statement = Statement();
    // Seed distinct values in both branches so the test detects an accidental
    // statement-only or one-leg codec.
    envelope.composition.episode.gemm
        .collection_commitment = H(0x71);
    envelope.composition.coupled.gemm
        .product_commitment = H(0x72);

    codec::SizeReportV1 report;
    std::vector<unsigned char> bytes;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        codec::SerializeEnvelopeV1(
            envelope, bytes, &report, &why),
        why);
    BOOST_REQUIRE(report.direct_codec_fit);
    BOOST_REQUIRE(
        report.consensus_payload_fit);
    BOOST_REQUIRE_EQUAL(
        report.envelope_bytes,
        bytes.size());
    BOOST_REQUIRE_GT(report.episode_bytes, 0U);
    BOOST_REQUIRE_GT(report.coupled_bytes, 0U);

    const auto decoded =
        codec::DeserializeEnvelopeV1(
            bytes, &why);
    BOOST_REQUIRE_MESSAGE(
        decoded.has_value(), why);
    BOOST_CHECK(
        decoded->statement ==
        envelope.statement);
    BOOST_CHECK(
        decoded->composition.episode.gemm
            .collection_commitment ==
        H(0x71));
    BOOST_CHECK(
        decoded->composition.coupled.gemm
            .product_commitment ==
        H(0x72));

    auto noncanonical = bytes;
    noncanonical[6] = 1;
    BOOST_CHECK(
        !codec::DeserializeEnvelopeV1(
             noncanonical, &why).has_value());
    noncanonical = bytes;
    noncanonical.push_back(0);
    BOOST_CHECK(
        !codec::DeserializeEnvelopeV1(
             noncanonical, &why).has_value());
}

BOOST_AUTO_TEST_CASE(
    block_attachment_is_canonical_but_not_a_readiness_receipt)
{
    codec::EnvelopeV1 envelope;
    envelope.statement = Statement();
    CBlock block;
    codec::SizeReportV1 report;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        codec::AttachEnvelopeV1(
            block, envelope,
            &report, &why),
        why);
    BOOST_REQUIRE(
        report.consensus_payload_fit);
    const auto bytes =
        codec::UnpackEnvelopeWordsV1(
            block.matrix_c_data, &why);
    BOOST_REQUIRE_MESSAGE(
        bytes.has_value(), why);

    // An encoded object is not an accepted proof. Fresh verification must
    // execute the missing typed children and reject this empty inventory.
    rc::RCEpisodeParams episode;
    episode.rounds = 1;
    episode.d_head = 32;
    episode.n_q = 32;
    episode.n_ctx = 32;
    episode.L_lyr = 1;
    episode.d_model = 32;
    episode.d_ff = 64;
    episode.b_seq = 32;
    episode.T_leaf = 32;
    rc::RCCoupParams coupled_params;
    coupled_params.barriers = 4;
    coupled_params.lobes = 1;
    coupled_params.lobe_width = 32;
    coupled_params.bank_pages = 1;
    coupled_params.rows_per_lobe = 1;
    coupled_params.pages_per_barrier_lobe = 1;
    rc::RCCoupOptions options;
    options.full_bank_schedule = true;
    const auto shape =
        rc::MakeRCStage3CoupledShape(
            coupled_params, options);
    BOOST_CHECK(
        !codec::VerifyAttachedEnvelopeV1(
             block, episode, shape,
             nullptr, &why));
}

BOOST_AUTO_TEST_SUITE_END()
