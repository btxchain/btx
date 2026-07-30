// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/MIT.

#include <boost/test/unit_test.hpp>

#include <hash.h>
#include <matmul/matmul_v4_rc_stage3_episode_wiring_proof_descriptor.h>

#include <algorithm>

namespace matmul::v4::rc {
namespace {

namespace wdp =
    stage3_episode_wiring_proof_descriptor;
namespace aq = air_quotient;
namespace gf = gkr_field;
using gf::Fp3;

uint256 Tag(const char* text)
{
    HashWriter hash;
    hash << text;
    return hash.GetHash();
}

aq::AirQuotientProof<Fp3> TinyLegacyProof()
{
    aq::AirConstraintSystem<Fp3> cs;
    cs.n_rows = 2;
    cs.n_columns = 1;
    aq::AirConstraint<Fp3> zero;
    zero.name = "wdp.test.zero";
    zero.kind = aq::AirKind::kEverywhere;
    zero.alg_degree = 1;
    zero.eval = [](
        const std::vector<Fp3>& current,
        const std::vector<Fp3>&) {
        return current[0];
    };
    cs.constraints.push_back(std::move(zero));
    const std::vector<std::vector<Fp3>> columns{
        std::vector<Fp3>(2, Fp3::Zero())};
    const auto proved =
        aq::AirQuotientProve<Fp3>(
            cs, columns, Tag("wdp-legacy-seed"));
    BOOST_REQUIRE_MESSAGE(
        proved.ok && proved.division_exact,
        proved.note);
    return proved.proof;
}

uint64_t ExpectedLegacyVerifierWords(
    const aq::AirQuotientProof<Fp3>& proof)
{
    const auto& batch = proof.batch;
    uint64_t words = 5; // version, nonce, blowup, n_coeffs
    words += 1 + uint64_t{9} * batch.columns.size();
    words += 1 + batch.column_len.size();
    words += 18; // lambda, z1, z2
    words += 1 + uint64_t{6} * batch.evals_z1.size();
    words += 1 + uint64_t{6} * batch.evals_z2.size();
    words += 12; // w1, w2
    words += 1 + uint64_t{9} * batch.fold_layers.size();
    words += 6; // final value
    words += 1 + uint64_t{6} *
        batch.fold_challenges.size();
    words += 1; // query vector length
    for (const auto& query : batch.queries) {
        words += 2; // index, column vector length
        for (const auto& column : query.columns) {
            words += 7 +
                uint64_t{8} * column.siblings.size();
        }
        words += 1; // step vector length
        for (const auto& step : query.steps) {
            words += 16; // indices, values, two lengths
            words += uint64_t{8} *
                (step.even_siblings.size() +
                 step.odd_siblings.size());
        }
    }
    words += 9; // trace_commit + next query length
    for (const auto& paths : proof.next_openings) {
        words += 1;
        for (const auto& path : paths) {
            words += 8 +
                uint64_t{8} * path.siblings.size();
        }
    }
    return words;
}

RCStage3EpisodeSemanticMemoryBundle MemoryBundle(
    const aq::AirQuotientProof<Fp3>& proof,
    const char* tag)
{
    RCStage3EpisodeSemanticMemoryBundle bundle;
    bundle.endpoint =
        RCStage3RelationEndpoint::EpisodeWiringTranspose;
    bundle.statement_commitment = Tag("wdp-statement");
    bundle.total_instance_count = 1;
    bundle.address_begin = 17;
    bundle.address_stride = 1;

    RCStage3EpisodeSemanticMemoryShard shard;
    shard.shard_index = 0;
    shard.value_begin = 0;
    shard.manifest.endpoint = bundle.endpoint;
    shard.manifest.role =
        RCStage3RelationRole::EpisodeWiring;
    shard.manifest.statement_commitment =
        bundle.statement_commitment;
    shard.manifest.instance_count = 1;
    shard.manifest.logical_rows = 1;
    shard.manifest.n_rows = 2;
    shard.manifest.address_begin = 17;
    shard.manifest.address_stride = 1;
    shard.manifest.canonical_value_root =
        Tag("wdp-memory-value-root");
    shard.manifest.schedule_commitment =
        Tag("wdp-memory-schedule");
    shard.manifest.manifest_commitment =
        Tag(tag);
    shard.proof.manifest_commitment =
        shard.manifest.manifest_commitment;
    shard.proof.quotient = proof;
    bundle.shards.push_back(std::move(shard));
    bundle.bundle_commitment = Tag(tag);
    return bundle;
}

RCStage3EpisodeWiringProduct TinyWiringProduct()
{
    const auto proof = TinyLegacyProof();
    RCStage3EpisodeWiringProduct product;
    product.statement_commitment = Tag("wdp-statement");
    product.manifest_commitment = Tag("wdp-manifest");
    product.gemm_product_commitment = Tag("wdp-gemm");
    product.extract_product_commitment = Tag("wdp-extract");

    RCStage3EpisodeWiringTransposeEdge edge;
    edge.schedule.schedule_index = 0;
    edge.schedule.layer_ordinal = 3;
    edge.schedule.slot =
        RCStage3EpisodeWiringOperandSlot::B;
    edge.schedule.first_column = 9;
    edge.schedule.n_chunks = 1;
    edge.schedule.source_rows = 1;
    edge.schedule.source_cols = 2;
    edge.schedule.value_count = 2;
    edge.schedule.registered_source_root =
        Tag("wdp-source");
    edge.pin.endpoint =
        RCStage3RelationEndpoint::EpisodeWiringTranspose;
    edge.pin.statement_commitment =
        product.statement_commitment;
    edge.pin.manifest_commitment =
        product.manifest_commitment;
    edge.pin.schedule_index = 0;
    edge.pin.logical_rows = 2;
    edge.pin.n_rows = 2;
    edge.pin.challenge_seed = Tag("wdp-pin-seed");
    edge.pin.column_roots.push_back(
        {0, proof.batch.columns[0].root});
    edge.pin.pin_commitment = Tag("wdp-pin");
    edge.proof = proof;
    edge.source_memory =
        MemoryBundle(proof, "wdp-source-memory");
    edge.destination_memory =
        MemoryBundle(proof, "wdp-destination-memory");
    edge.transposed_vector_root =
        Tag("wdp-transposed");
    edge.edge_commitment = Tag("wdp-edge");
    product.transpose_edges.push_back(std::move(edge));
    product.product_commitment = Tag("wdp-product");
    return product;
}

wdp::ManifestV1 TinyAirManifest()
{
    wdp::ManifestV1 manifest;
    manifest.product_commitment =
        Tag("wdp-air-product");
    manifest.statement_commitment =
        Tag("wdp-air-statement");
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
        record.coordinate = {i, 0, 0, 0};
        record.value = 0x10203040U + i;
        manifest.records.push_back(record);
    }
    manifest.schedule_root =
        wdp::ComputeScheduleRootV1(manifest.records);
    manifest.proof_wire_root =
        wdp::ComputeProofWireRootV1(manifest.records);
    manifest.relation_proofs = 1;
    manifest.root_words = 1;
    manifest.opening_words = 4;
    manifest.exact_product_envelope = true;
    manifest.exact_edge_order = true;
    manifest.exact_memory_shard_order = true;
    manifest.every_verifier_read_classified = true;
    manifest.canonical_u32_words = true;
    manifest.valid = true;
    manifest.note = "wdp-air-test";
    return manifest;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_episode_wiring_proof_descriptor_tests)

BOOST_AUTO_TEST_CASE(
    canonical_inventory_rebuild_and_adversarial_records)
{
    const auto product = TinyWiringProduct();
    std::vector<wdp::RecordV1> relation_records;
    const wdp::OwnerV1 relation_owner{
        wdp::OwnerFamilyV1::Transpose,
        wdp::OwnerSectionV1::EdgeProof, 0,
        UINT32_MAX};
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        wdp::AppendCanonicalLegacyProofRecordsV1(
            relation_owner,
            product.transpose_edges[0].proof,
            relation_records, &why),
        why);
    BOOST_CHECK_EQUAL(
        relation_records.size(),
        ExpectedLegacyVerifierWords(
            product.transpose_edges[0].proof));

    wdp::ManifestV1 manifest;
    BOOST_REQUIRE_MESSAGE(
        wdp::BuildManifestV1(
            product, manifest, &why),
        why);
    BOOST_CHECK(manifest.valid);
    BOOST_CHECK_EQUAL(manifest.relation_proofs, 1U);
    BOOST_CHECK_EQUAL(manifest.memory_proofs, 2U);
    BOOST_CHECK_GT(manifest.root_words, 0U);
    BOOST_CHECK_GT(manifest.opening_words, 0U);
    BOOST_CHECK(
        manifest.schedule_root ==
        wdp::ComputeScheduleRootV1(
            manifest.records));
    BOOST_CHECK(
        manifest.proof_wire_root ==
        wdp::ComputeProofWireRootV1(
            manifest.records));
    BOOST_REQUIRE(
        wdp::ValidateManifestV1(
            product, manifest, &why));

    auto omitted = manifest;
    omitted.records.erase(
        omitted.records.begin() +
        omitted.records.size() / 2);
    BOOST_CHECK(
        !wdp::ValidateManifestV1(
            product, omitted, &why));

    auto reordered = manifest;
    std::swap(
        reordered.records[3],
        reordered.records[4]);
    BOOST_CHECK(
        !wdp::ValidateManifestV1(
            product, reordered, &why));

    auto duplicated = manifest;
    duplicated.records.insert(
        duplicated.records.begin() + 2,
        duplicated.records[2]);
    BOOST_CHECK(
        !wdp::ValidateManifestV1(
            product, duplicated, &why));

    const auto root_it = std::find_if(
        manifest.records.begin(),
        manifest.records.end(),
        [](const auto& record) {
            return record.kind ==
                wdp::RecordKindV1::ColumnRoot;
        });
    BOOST_REQUIRE(root_it != manifest.records.end());
    auto root_tamper = manifest;
    root_tamper.records[
        std::distance(
            manifest.records.begin(), root_it)].value ^= 1U;
    BOOST_CHECK(
        !wdp::ValidateManifestV1(
            product, root_tamper, &why));

    const auto opening_it = std::find_if(
        manifest.records.begin(),
        manifest.records.end(),
        [](const auto& record) {
            return record.kind ==
                wdp::RecordKindV1::QueryOpeningValue;
        });
    BOOST_REQUIRE(
        opening_it != manifest.records.end());
    auto opening_tamper = manifest;
    opening_tamper.records[
        std::distance(
            manifest.records.begin(),
            opening_it)].value ^= 1U;
    BOOST_CHECK(
        !wdp::ValidateManifestV1(
            product, opening_tamper, &why));

    uint64_t decoded = 0;
    BOOST_CHECK(
        wdp::DecodeCanonicalFpWordPairV1(
            5, 0, decoded));
    const uint64_t alias = gf::kP + 5;
    BOOST_CHECK(
        !wdp::DecodeCanonicalFpWordPairV1(
            static_cast<uint32_t>(alias),
            static_cast<uint32_t>(alias >> 32),
            decoded));
}

BOOST_AUTO_TEST_CASE(
    descriptor_air_proof_and_proof_level_tamper_reject)
{
    const auto manifest = TinyAirManifest();
    const auto product =
        wdp::BuildProductV1(manifest);
    BOOST_REQUIRE_MESSAGE(product.valid, product.note);
    BOOST_CHECK_EQUAL(product.violations, 0U);
    BOOST_CHECK(!product.parent_terminal_cancelled);
    BOOST_CHECK(!product.recursively_consumed);
    BOOST_CHECK(!product.semantic_sites_credited);

    wdp::ProofV1 proof;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        wdp::ProveV1(product, proof, &why), why);
    BOOST_REQUIRE(
        wdp::VerifyV1(manifest, proof, &why));
    BOOST_CHECK(proof.locally_verified);
    BOOST_CHECK(!proof.parent_terminal_cancelled);
    BOOST_CHECK(!proof.recursively_consumed);
    BOOST_CHECK(!proof.semantic_sites_credited);

    auto wrong_root = proof;
    wrong_root.schedule_root =
        Tag("wdp-wrong-schedule");
    BOOST_CHECK(
        !wdp::VerifyV1(
            manifest, wrong_root, &why));

    auto wrong_terminal = proof;
    wrong_terminal.source_terminal[0] =
        gf::Add(
            wrong_terminal.source_terminal[0],
            Fp3::One());
    BOOST_CHECK(
        !wdp::VerifyV1(
            manifest, wrong_terminal, &why));

    auto forged = proof;
    forged.proof.batch.final_value =
        gf::Add(
            forged.proof.batch.final_value,
            Fp3::One());
    BOOST_REQUIRE(
        SerializeAirQuotientProofAlg(
            forged.proof,
            forged.canonical_proof_bytes, &why));
    BOOST_CHECK(
        !wdp::VerifyV1(
            manifest, forged, &why));

    auto byte_tamper = proof;
    BOOST_REQUIRE(
        !byte_tamper.canonical_proof_bytes.empty());
    byte_tamper.canonical_proof_bytes.back() ^= 1U;
    BOOST_CHECK(
        !wdp::VerifyV1(
            manifest, byte_tamper, &why));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc
