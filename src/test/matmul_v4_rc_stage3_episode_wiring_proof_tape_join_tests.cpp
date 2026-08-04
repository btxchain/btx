// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/MIT.

#include <boost/test/unit_test.hpp>

#include <hash.h>
#include <matmul/matmul_v4_rc_stage3_episode_wiring_proof_tape_join.h>

namespace matmul::v4::rc {
namespace {

namespace join =
    stage3_episode_wiring_proof_tape_join;
namespace wdp =
    stage3_episode_wiring_proof_descriptor;
namespace gf = gkr_field;

uint256 JoinTag(const char* text)
{
    HashWriter hash;
    hash << text;
    return hash.GetHash();
}

wdp::ManifestV1 JoinManifest(uint32_t value_bias = 0)
{
    wdp::ManifestV1 manifest;
    manifest.product_commitment =
        JoinTag("wdp-join-product");
    manifest.statement_commitment =
        JoinTag("wdp-join-statement");
    const std::array<wdp::RecordKindV1, 8> kinds{{
        wdp::RecordKindV1::BatchHeader,
        wdp::RecordKindV1::ColumnRoot,
        wdp::RecordKindV1::ColumnLeaves,
        wdp::RecordKindV1::QueryIndex,
        wdp::RecordKindV1::QueryOpeningValue,
        wdp::RecordKindV1::QueryOpeningSibling,
        wdp::RecordKindV1::NextOpeningValue,
        wdp::RecordKindV1::NextOpeningSibling,
    }};
    for (uint32_t i = 0; i < kinds.size(); ++i) {
        wdp::RecordV1 record;
        record.ordinal = i;
        record.owner.family =
            wdp::OwnerFamilyV1::Transpose;
        record.owner.section =
            wdp::OwnerSectionV1::EdgeProof;
        record.owner.edge_ordinal = 0;
        record.kind = kinds[i];
        record.coordinate = {i, 1, 2, 3};
        record.value =
            0x10203040U + value_bias + i;
        manifest.records.push_back(record);
    }
    manifest.schedule_root =
        wdp::ComputeScheduleRootV1(
            manifest.records);
    manifest.proof_wire_root =
        wdp::ComputeProofWireRootV1(
            manifest.records);
    manifest.relation_proofs = 1;
    manifest.root_words = 1;
    manifest.opening_words = 4;
    manifest.exact_product_envelope = true;
    manifest.exact_edge_order = true;
    manifest.exact_memory_shard_order = true;
    manifest.every_verifier_read_classified = true;
    manifest.canonical_u32_words = true;
    manifest.valid = true;
    manifest.note =
        "stage3:episode_wiring_proof_descriptor:"
        "manifest_valid";
    return manifest;
}

void RebindManifest(wdp::ManifestV1& manifest)
{
    for (uint32_t i = 0;
         i < manifest.records.size(); ++i) {
        manifest.records[i].ordinal = i;
    }
    manifest.schedule_root =
        wdp::ComputeScheduleRootV1(
            manifest.records);
    manifest.proof_wire_root =
        wdp::ComputeProofWireRootV1(
            manifest.records);
}

const join::ProofV1& SharedJoinProof()
{
    static const join::ProofV1 proof =
        join::ProveManifestV1(
            JoinManifest(), true);
    return proof;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_episode_wiring_proof_tape_join_tests)

BOOST_AUTO_TEST_CASE(
    canonical_consumer_and_dual_terminal_statement)
{
    const auto manifest = JoinManifest();
    join::StatementV1 statement;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        join::BuildStatementV1(
            manifest, statement, &why),
        why);
    BOOST_CHECK_EQUAL(
        statement.record_count,
        manifest.records.size());
    BOOST_CHECK(
        statement.schedule_root ==
        manifest.schedule_root);
    BOOST_CHECK(
        statement.proof_wire_root ==
        manifest.proof_wire_root);
    for (uint32_t lane = 0;
         lane < join::kTerminalLanesV1; ++lane) {
        BOOST_CHECK(
            gf::Eq(
                statement.producer_terminal[lane],
                statement.consumer_terminal[lane]));
    }

    const auto consumer =
        join::BuildAndProveConsumerManifestV1(
            manifest);
    BOOST_REQUIRE_MESSAGE(
        consumer.valid, consumer.note);
    BOOST_CHECK(consumer.exact_canonical_inventory);
    BOOST_CHECK(consumer.independently_rebuilt_air);
    BOOST_CHECK(
        consumer.ordinary_proof.valid);
    BOOST_CHECK(
        !consumer.legacy_fri_verifier_in_air);
}

BOOST_AUTO_TEST_CASE(
    normalized_parent_authenticates_ordered_three_child_join)
{
    const auto manifest = JoinManifest();
    const auto& proof = SharedJoinProof();
    BOOST_REQUIRE_MESSAGE(
        proof.construction_valid, proof.note);
    BOOST_CHECK(
        proof.three_ordinary_children_verified);
    BOOST_CHECK(
        proof.normalized_parent_proof_verified);
    BOOST_CHECK(
        proof.host_composition_authenticated);
    BOOST_CHECK(
        !proof.legacy_fri_verifier_in_parent_air);
    BOOST_CHECK(!proof.complete_fixed_point);
    BOOST_CHECK(!proof.semantic_sites_credited);
    BOOST_CHECK(!proof.authority_ready);

    std::string why;
    BOOST_REQUIRE_MESSAGE(
        join::VerifyManifestV1(
            manifest, proof, &why),
        why);

    auto parent_tamper = proof;
    BOOST_REQUIRE(
        !parent_tamper.parent.receipt.proof
             .batch.queries.empty());
    BOOST_REQUIRE(
        !parent_tamper.parent.receipt.proof
             .batch.queries[0].row.values.empty());
    auto& parent_value =
        parent_tamper.parent.receipt.proof
            .batch.queries[0].row.values[0];
    parent_value =
        gf::Add(parent_value, gf::Fp3::One());
    BOOST_CHECK(
        !join::VerifyManifestV1(
            manifest, parent_tamper, &why));

    auto child_order = proof;
    std::swap(
        child_order.producer,
        child_order.consumer.ordinary_proof);
    BOOST_CHECK(
        !join::VerifyManifestV1(
            manifest, child_order, &why));
}

BOOST_AUTO_TEST_CASE(
    omission_reorder_duplicate_root_opening_and_transplant_reject)
{
    const auto manifest = JoinManifest();
    const auto& proof = SharedJoinProof();
    BOOST_REQUIRE_MESSAGE(
        proof.construction_valid, proof.note);
    std::string why;

    auto omission = manifest;
    omission.records.erase(
        omission.records.begin() + 2);
    RebindManifest(omission);
    BOOST_CHECK(
        !join::VerifyManifestV1(
            omission, proof, &why));

    auto reorder = manifest;
    std::swap(
        reorder.records[2],
        reorder.records[5]);
    RebindManifest(reorder);
    BOOST_CHECK(
        !join::VerifyManifestV1(
            reorder, proof, &why));

    auto duplicate = manifest;
    duplicate.records[6] =
        duplicate.records[5];
    RebindManifest(duplicate);
    BOOST_CHECK(
        !join::VerifyManifestV1(
            duplicate, proof, &why));

    auto root = manifest;
    root.schedule_root.data()[0] ^= 1;
    BOOST_CHECK(
        !join::VerifyManifestV1(
            root, proof, &why));

    auto opening = manifest;
    opening.records[4].value ^= 1;
    RebindManifest(opening);
    BOOST_CHECK(
        !join::VerifyManifestV1(
            opening, proof, &why));

    const auto other = JoinManifest(0x100);
    BOOST_CHECK(
        !join::VerifyManifestV1(
            other, proof, &why));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc
