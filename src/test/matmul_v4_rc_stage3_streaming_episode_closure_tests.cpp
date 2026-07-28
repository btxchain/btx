// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_streaming_episode_closure.h>
#include <primitives/block.h>

#include <algorithm>
#include <cstdlib>

namespace {

namespace rc = matmul::v4::rc;
namespace streaming =
    rc::streaming_episode_closure;

uint256 H(unsigned char tag)
{
    uint256 out;
    std::fill(out.begin(), out.end(), tag);
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

rc::RCStage3SuccinctProof Statement()
{
    rc::RCStage3SuccinctProof out;
    out.statement =
        rc::RCStage3StatementKind::Episode;
    out.public_inputs.height = 151;
    out.public_inputs.n_bits = 0x207fffffU;
    out.public_inputs.episode_profile = 2;
    out.public_inputs.coupled_profile = 3;
    out.public_inputs.transcript_version =
        rc::ENC_RC_V3;
    out.public_inputs.program_consensus_pin.version =
        1;
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
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_streaming_episode_closure_tests)

BOOST_AUTO_TEST_CASE(
    immutable_schedule_excludes_late_roots_and_binds_exact_geometry)
{
    const auto statement = Statement();
    const auto params = TinyParams();
    streaming::ImmutableEpisodeScheduleV1 schedule;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        streaming::BuildImmutableEpisodeScheduleV1(
            statement, params, schedule, &why),
        why);
    const auto layout = rc::RCGkrTraceLayout(params);
    BOOST_REQUIRE_EQUAL(
        schedule.layers.size(),
        layout.layers.size());
    BOOST_REQUIRE(
        !schedule.schedule_commitment.IsNull());
    BOOST_CHECK(
        schedule.schedule_commitment ==
        streaming::
            ComputeImmutableEpisodeScheduleCommitmentV1(
                schedule));
    BOOST_CHECK_MESSAGE(
        streaming::ValidateImmutableEpisodeScheduleV1(
            schedule, &why),
        why);
    for (uint32_t ordinal = 0;
         ordinal < schedule.layers.size();
         ++ordinal) {
        const auto& layer = schedule.layers[ordinal];
        BOOST_CHECK_EQUAL(layer.ordinal, ordinal);
        BOOST_CHECK(layer.bindings.extract_prf.IsNull());
        BOOST_CHECK(
            layer.bindings.operand_a_root_alg.IsNull());
        BOOST_CHECK(
            layer.bindings.operand_b_root_alg.IsNull());
        BOOST_CHECK(
            layer.bindings.gemm_y_root_alg.IsNull());
        BOOST_CHECK(
            layer.bindings.extract_input_root_alg.IsNull());
    }

    auto reordered = schedule;
    std::swap(reordered.layers[0],
              reordered.layers[1]);
    BOOST_CHECK(
        streaming::
            ComputeImmutableEpisodeScheduleCommitmentV1(
                reordered) !=
        schedule.schedule_commitment);
    reordered.schedule_commitment =
        streaming::
            ComputeImmutableEpisodeScheduleCommitmentV1(
                reordered);
    BOOST_CHECK(
        !streaming::ValidateImmutableEpisodeScheduleV1(
            reordered, &why));

    auto interval = schedule;
    ++interval.layers[0].extract_tile_begin;
    BOOST_CHECK(
        streaming::
            ComputeImmutableEpisodeScheduleCommitmentV1(
                interval) !=
        schedule.schedule_commitment);
    interval.schedule_commitment =
        streaming::
            ComputeImmutableEpisodeScheduleCommitmentV1(
                interval);
    BOOST_CHECK(
        !streaming::ValidateImmutableEpisodeScheduleV1(
            interval, &why));

    auto statement_attack = schedule;
    statement_attack.statement_commitment = H(0xee);
    BOOST_CHECK(
        streaming::
            ComputeImmutableEpisodeScheduleCommitmentV1(
                statement_attack) !=
        schedule.schedule_commitment);
}

BOOST_AUTO_TEST_CASE(
    callback_state_machine_rejects_missing_reordered_and_prf_change)
{
    const auto statement = Statement();
    const auto params = TinyParams();
    std::string why;

    streaming::StreamingEpisodeClosureSink missing(
        statement, params);
    BOOST_CHECK(!missing.Complete(&why));
    BOOST_CHECK(
        why.find("incomplete") !=
        std::string::npos);

    std::array<int8_t, rc::kRCMxBlockLen>
        operand8{};
    std::array<int64_t, rc::kRCMxBlockLen>
        output64{};
    streaming::StreamingEpisodeClosureSink reordered(
        statement, params);
    reordered.OnPhase1QKtTile({
        .round_ordinal = 0,
        .query_row = 0,
        .context_begin = 0,
        .tile_len = rc::kRCMxBlockLen,
        .contraction_size = params.d_head,
        .operand_a = operand8.data(),
        .operand_b = operand8.data(),
        .gemm_y = output64.data(),
        .extract_output = operand8.data(),
        .prf_key = H(0x31),
    });
    BOOST_CHECK(!reordered.Complete(&why));
    BOOST_CHECK(
        why.find("qkt_order") !=
        std::string::npos);

    std::vector<int8_t> q(
        uint64_t{params.n_q} * params.d_head);
    std::vector<int8_t> k(
        uint64_t{params.n_ctx} * params.d_head);
    std::vector<int8_t> v(
        uint64_t{params.n_ctx} * params.d_head);
    streaming::StreamingEpisodeClosureSink duplicate(
        statement, params);
    const rc::RCPhase1OperandsWitnessView operands{
        .round_ordinal = 0,
        .n_q = params.n_q,
        .n_ctx = params.n_ctx,
        .d_head = params.d_head,
        .q = &q,
        .k = &k,
        .v = &v,
    };
    duplicate.OnPhase1Operands(operands);
    duplicate.OnPhase1Operands(operands);
    BOOST_CHECK(!duplicate.Complete(&why));
    BOOST_CHECK(
        why.find("phase1_operands_order") !=
        std::string::npos);

    streaming::StreamingEpisodeClosureSink prf_change(
        statement, params);
    prf_change.OnPhase1Operands(operands);
    prf_change.OnPhase1QKtTile({
        .round_ordinal = 0,
        .query_row = 0,
        .context_begin = 0,
        .tile_len = rc::kRCMxBlockLen,
        .contraction_size = params.d_head,
        .operand_a = operand8.data(),
        .operand_b = operand8.data(),
        .gemm_y = output64.data(),
        .extract_output = operand8.data(),
        .prf_key = H(0x41),
    });
    // Same layer, second tile position cannot change the public PRF.
    prf_change.OnPhase1QKtTile({
        .round_ordinal = 0,
        .query_row = 1,
        .context_begin = 0,
        .tile_len = rc::kRCMxBlockLen,
        .contraction_size = params.d_head,
        .operand_a = operand8.data(),
        .operand_b = operand8.data(),
        .gemm_y = output64.data(),
        .extract_output = operand8.data(),
        .prf_key = H(0x42),
    });
    BOOST_CHECK(!prf_change.Complete(&why));
    BOOST_CHECK(
        why.find("append_extract_prf_change") !=
        std::string::npos);
}

BOOST_AUTO_TEST_CASE(
    real_miner_callbacks_prove_discard_and_verify_every_layer)
{
    if (std::getenv(
            "BTX_RUN_STAGE3_STREAMING_EPISODE_CLOSURE") ==
        nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_STREAMING_EPISODE_CLOSURE=1 "
            "for real mine->online-layer-prove->proof-only-verify");
        return;
    }
    const auto statement = Statement();
    const auto params = TinyParams();
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock = H(0x51);
    header.hashMerkleRoot = H(0x52);
    header.nTime = 1700000000U;
    header.nBits = 0x207fffffU;
    header.nNonce = 7;

    streaming::StreamingEpisodeClosureSink sink(
        statement, params);
    const uint256 digest =
        rc::MineRCEpisodeWithProofWitness(
            header, params, 151, sink);
    BOOST_REQUIRE(!digest.IsNull());
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        sink.Complete(&why), why);
    BOOST_CHECK_EQUAL(
        sink.Layers().size(),
        rc::RCGkrTraceLayout(params).layers.size());
    BOOST_CHECK_EQUAL(
        sink.RetainedNativeBytes(), 0U);
    BOOST_REQUIRE_MESSAGE(
        streaming::VerifyStreamingEpisodeClosureV1(
            sink.Schedule(), sink.Layers(),
            sink.RoundRoots(), sink.EpisodeDigest(),
            &why),
        why);
    streaming::StreamingEpisodeClosureReceiptV1
        receipt;
    BOOST_REQUIRE_MESSAGE(
        sink.BuildReceipt(receipt, &why), why);
    BOOST_REQUIRE_MESSAGE(
        streaming::
            VerifyStreamingEpisodeClosureReceiptV1(
                receipt, &why),
        why);
    auto authority_escalation = receipt;
    authority_escalation.production_authority = true;
    authority_escalation.receipt_commitment =
        streaming::
            ComputeStreamingEpisodeClosureReceiptCommitmentV1(
                authority_escalation);
    BOOST_CHECK(
        !streaming::
            VerifyStreamingEpisodeClosureReceiptV1(
                authority_escalation, &why));

    auto omitted = sink.Layers();
    omitted.pop_back();
    BOOST_CHECK(
        !streaming::VerifyStreamingEpisodeClosureV1(
            sink.Schedule(), omitted,
            sink.RoundRoots(), sink.EpisodeDigest(),
            &why));

    auto reordered = sink.Layers();
    std::swap(reordered[0], reordered[1]);
    BOOST_CHECK(
        !streaming::VerifyStreamingEpisodeClosureV1(
            sink.Schedule(), reordered,
            sink.RoundRoots(), sink.EpisodeDigest(),
            &why));

    // Recomputing the outer retained commitment cannot turn an invented Y
    // root into authority: the Y external-producer CTL owns the expected root.
    auto root_attack = sink.Layers();
    root_attack[0].gemm_y_vector_root_alg =
        H(0xe1);
    root_attack[0].retained_commitment =
        streaming::
            ComputeStreamedLayerClosureCommitmentV1(
                root_attack[0]);
    BOOST_CHECK(
        !streaming::VerifyStreamingEpisodeClosureV1(
            sink.Schedule(), root_attack,
            sink.RoundRoots(), sink.EpisodeDigest(),
            &why));

    auto proof_attack = sink.Layers();
    BOOST_REQUIRE(
        !proof_attack[0].consumer_bundle
             .leaves.empty());
    BOOST_REQUIRE(
        !proof_attack[0].consumer_bundle
             .leaves[0].proof.batch.queries.empty());
    BOOST_REQUIRE(
        !proof_attack[0].consumer_bundle
             .leaves[0].proof.batch.queries[0]
             .row.values.empty());
    auto& attacked =
        proof_attack[0].consumer_bundle
            .leaves[0].proof.batch.queries[0]
            .row.values[0];
    attacked = rc::gkr_field::Add(
        attacked, rc::gkr_field::Fp3::One());
    BOOST_CHECK(
        !streaming::VerifyStreamingEpisodeClosureV1(
            sink.Schedule(), proof_attack,
            sink.RoundRoots(), sink.EpisodeDigest(),
            &why));
}

BOOST_AUTO_TEST_SUITE_END()
