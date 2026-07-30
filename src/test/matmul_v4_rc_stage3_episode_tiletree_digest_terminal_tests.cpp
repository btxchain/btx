// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_episode_tiletree_digest_terminal.h>

#include <algorithm>
#include <cstdlib>
#include <vector>

namespace rc = matmul::v4::rc;
namespace digest = rc::episode_digest_all_instance;
namespace terminal = rc::episode_tiletree_digest_terminal;
namespace fp = rc::recursive_fixedpoint;
namespace gf = rc::gkr_field;
namespace ha = rc::stage3_hash_air;
namespace tape = rc::stage3_multirow_v13_proof_tape_air;

namespace {

uint256 Root(uint8_t byte)
{
    uint256 out;
    std::fill(out.begin(), out.end(), byte);
    return out;
}

rc::RCStage3SuccinctProof Statement(
    const uint256& episode_digest)
{
    rc::RCStage3SuccinctProof out;
    out.statement = rc::RCStage3StatementKind::Episode;
    auto& public_inputs = out.public_inputs;
    public_inputs.height = 91;
    public_inputs.n_bits = 0x207fffffU;
    public_inputs.episode_profile = 2;
    public_inputs.transcript_version = rc::ENC_RC_V4;
    public_inputs.header_commitment = Root(0x11);
    public_inputs.params_commitment = Root(0x22);
    public_inputs.sigma = Root(0x33);
    public_inputs.target = Root(0xff);
    public_inputs.episode_digest = episode_digest;
    public_inputs.final_digest = episode_digest;
    public_inputs.program_consensus_pin.recursive_alg_hash_root =
        Root(0x08);
    public_inputs.program_consensus_pin.external_sha256d_audit_root =
        Root(0x09);
    public_inputs.program_consensus_pin.registry_binding =
        Root(0x0a);
    return out;
}

digest::TapeChallengeContextV1 TapeContext()
{
    digest::TapeChallengeContextV1 out;
    out.shape.trace_rows = 2;
    out.shape.trace_columns = 2;
    out.shape.quotient_len = 2;
    out.shape.n_coeffs = 2;
    out.shape.base_column_indices = {0};
    out.binding.program_root = Root(0x71);
    out.binding.statement_root = Root(0x72);
    out.binding.public_fs_seed = Root(0x73);
    out.binding.proof_wire_root = Root(0x74);
    out.binding.tape_root = {1, 2, 3, 4};
    out.source_inventory_root =
        tape::ComputeShardSourceInventoryRootV2(
            out.shape, out.binding);
    out.shard_count =
        static_cast<uint32_t>(
            tape::BuildShardPlansV2(
                out.shape, out.binding).size());
    return out;
}

bool RebindReceipt(
    terminal::ProductV1& product,
    rc::RCStage3ProducerBusReceiptV1& receipt,
    std::string* why)
{
    if (!rc::SerializeRCStage3ProducerBusProofV1(
            receipt.proof,
            receipt.canonical_proof_bytes, why)) {
        return false;
    }
    receipt.proof_commitment =
        rc::ComputeRCStage3ProducerBusProofCommitmentV1(
            receipt.canonical_proof_bytes);
    receipt.receipt_commitment =
        rc::ComputeRCStage3ProducerBusReceiptCommitmentV1(
            receipt);
    product.product_commitment =
        terminal::CommitProductV1(product);
    return !receipt.proof_commitment.IsNull() &&
        !receipt.receipt_commitment.IsNull() &&
        !product.product_commitment.IsNull();
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_episode_tiletree_digest_terminal_tests)

BOOST_AUTO_TEST_CASE(exact_production_shape_is_eight_full_roots)
{
    BOOST_CHECK_EQUAL(
        terminal::kProductionRoundsV1, 8U);
    BOOST_CHECK_EQUAL(
        terminal::kRootBytesPerRoundV1, 32U);
    BOOST_CHECK_EQUAL(
        terminal::kProductionLogicalRowsV1, 256U);
    BOOST_CHECK(terminal::kLocalTerminalExecutableV1);
    BOOST_CHECK(
        !terminal::kNormalizedRecursiveConsumedV1);
    BOOST_CHECK(!terminal::kProductionAuthorityV1);
}

BOOST_AUTO_TEST_CASE(
    all_eight_round_terminals_cancel_and_attacks_reject)
{
    if (std::getenv(
            "BTX_RUN_STAGE3_TILETREE_DIGEST_TERMINAL") ==
        nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_TILETREE_DIGEST_TERMINAL=1 "
            "to execute the complete 8-round proof products");
        return;
    }

    std::string why;
    std::vector<ha::TileTreeManifest> trees(
        terminal::kProductionRoundsV1);
    std::vector<uint256> roots;
    roots.reserve(terminal::kProductionRoundsV1);
    for (uint32_t round = 0;
         round < terminal::kProductionRoundsV1; ++round) {
        const std::vector<uint8_t> stream{
            static_cast<uint8_t>(round + 1),
            static_cast<uint8_t>(0x40 + round),
        };
        BOOST_REQUIRE_MESSAGE(
            ha::BuildTileTreeManifest(
                stream, 32, trees[round], &why),
            why);
        roots.push_back(trees[round].root);
    }
    ha::EpisodeDigestManifest manifest;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildEpisodeDigestManifest(
            terminal::kProductionRoundsV1,
            roots, manifest, &why),
        why);
    const auto statement =
        Statement(manifest.direct.digest);
    const auto tape_context = TapeContext();

    // The expensive d64 digest product is generated once and reused by the
    // honest check and every attack below. No proof regeneration is hidden
    // in the mutation cases.
    digest::ProductV1 digest_product;
    BOOST_REQUIRE_MESSAGE(
        digest::ProveProductV1(
            statement, manifest, tape_context,
            digest_product, &why),
        why);
    rc::RCStage3EpisodeRoundRootProducerProduct
        tiletree_product;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3EpisodeRoundRootProducerProduct(
            statement,
            terminal::kProductionRoundsV1,
            digest_product.endpoint_root_chain,
            trees, tiletree_product, &why),
        why);

    terminal::ProductV1 product;
    BOOST_REQUIRE_MESSAGE(
        terminal::ProveProductV1(
            statement, tape_context,
            tiletree_product, digest_product,
            product, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        terminal::VerifyProductV1(
            statement, tape_context,
            tiletree_product, digest_product,
            product, &why),
        why);
    BOOST_CHECK_EQUAL(product.round_count, 8U);
    BOOST_CHECK_EQUAL(product.logical_rows, 256U);
    BOOST_CHECK(product.exact_all_round_inventory);
    BOOST_CHECK(product.proof_owned_terminal_pair);
    BOOST_CHECK(
        gf::IsZero(gf::Add(
            product.producer.terminal.alpha1_sum,
            product.consumer.terminal.alpha1_sum)));
    BOOST_CHECK(
        gf::IsZero(gf::Add(
            product.producer.terminal.alpha2_sum,
            product.consumer.terminal.alpha2_sum)));
    BOOST_CHECK(
        product.producer.base_row_commitment !=
        product.consumer.base_row_commitment);
    BOOST_CHECK(!product.normalized_recursive_consumed);
    BOOST_CHECK(!product.production_authority);

    auto omitted = tiletree_product;
    omitted.rounds.pop_back();
    omitted.collection_commitment =
        rc::ComputeRCStage3EpisodeRoundRootProducerCollectionCommitment(
            omitted);
    BOOST_CHECK(
        !terminal::VerifyProductV1(
            statement, tape_context,
            omitted, digest_product,
            product, &why));

    auto reordered = tiletree_product;
    std::swap(
        reordered.rounds[0],
        reordered.rounds[1]);
    reordered.rounds[0].round_index = 0;
    reordered.rounds[1].round_index = 1;
    reordered.collection_commitment =
        rc::ComputeRCStage3EpisodeRoundRootProducerCollectionCommitment(
            reordered);
    BOOST_CHECK(
        !terminal::VerifyProductV1(
            statement, tape_context,
            reordered, digest_product,
            product, &why));

    auto changed_root = tiletree_product;
    changed_root.rounds[0].tree_manifest.root = Root(0x55);
    changed_root.rounds[0].tree_manifest.commitment =
        ha::CommitTileTreeManifest(
            changed_root.rounds[0].tree_manifest);
    changed_root.rounds[0].hash_bundle.manifest_commitment =
        changed_root.rounds[0].tree_manifest.commitment;
    changed_root.collection_commitment =
        rc::ComputeRCStage3EpisodeRoundRootProducerCollectionCommitment(
            changed_root);
    BOOST_CHECK(
        !terminal::VerifyProductV1(
            statement, tape_context,
            changed_root, digest_product,
            product, &why));

    auto proof_root_forgery = product;
    proof_root_forgery.producer.proof.batch.
        columns[0].root = Root(0x5a);
    proof_root_forgery.producer.
        relation_value_column_root = Root(0x5a);
    BOOST_REQUIRE_MESSAGE(
        RebindReceipt(
            proof_root_forgery,
            proof_root_forgery.producer, &why),
        why);
    BOOST_CHECK(
        !terminal::VerifyProductV1(
            statement, tape_context,
            tiletree_product, digest_product,
            proof_root_forgery, &why));

    auto opening_forgery = product;
    BOOST_REQUIRE(
        !opening_forgery.producer.proof.batch.
            queries.empty());
    BOOST_REQUIRE(
        !opening_forgery.producer.proof.batch.
            queries[0].columns.empty());
    opening_forgery.producer.proof.batch.
        queries[0].columns[0].value =
        gf::Add(
            opening_forgery.producer.proof.batch.
                queries[0].columns[0].value,
            gf::Fp3::One());
    BOOST_REQUIRE_MESSAGE(
        RebindReceipt(
            opening_forgery,
            opening_forgery.producer, &why),
        why);
    BOOST_CHECK(
        !terminal::VerifyProductV1(
            statement, tape_context,
            tiletree_product, digest_product,
            opening_forgery, &why));

    auto transplanted_statement = statement;
    transplanted_statement.public_inputs.header_commitment =
        Root(0x99);
    BOOST_CHECK(
        !terminal::VerifyProductV1(
            transplanted_statement, tape_context,
            tiletree_product, digest_product,
            product, &why));

    auto precommit_transcript_forgery = product;
    precommit_transcript_forgery.public_challenge_seed =
        Root(0xa5);
    precommit_transcript_forgery.product_commitment =
        terminal::CommitProductV1(
            precommit_transcript_forgery);
    BOOST_CHECK(
        !terminal::VerifyProductV1(
            statement, tape_context,
            tiletree_product, digest_product,
            precommit_transcript_forgery, &why));

    auto transplanted_receipt = product;
    std::swap(
        transplanted_receipt.producer,
        transplanted_receipt.consumer);
    transplanted_receipt.product_commitment =
        terminal::CommitProductV1(
            transplanted_receipt);
    BOOST_CHECK(
        !terminal::VerifyProductV1(
            statement, tape_context,
            tiletree_product, digest_product,
            transplanted_receipt, &why));
}

BOOST_AUTO_TEST_SUITE_END()
