// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_episode_semantic.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

namespace rc = matmul::v4::rc;
namespace aq = matmul::v4::rc::air_quotient;
namespace gf = matmul::v4::rc::gkr_field;

BOOST_FIXTURE_TEST_SUITE(
    matmul_v4_rc_stage3_episode_semantic_tests,
    BasicTestingSetup)

namespace {

uint256 Filled(unsigned char value)
{
    uint256 out;
    std::fill(out.begin(), out.end(), value);
    return out;
}

std::vector<gf::Fp3> Values()
{
    return {
        gf::FromU64_3(11),
        gf::FromU64_3(17),
        gf::FromU64_3(23),
        gf::FromU64_3(29),
        gf::FromU64_3(31),
    };
}

rc::RCStage3SuccinctProof PowStatement(uint8_t digest, uint8_t target)
{
    rc::RCStage3SuccinctProof out;
    out.statement = rc::RCStage3StatementKind::Episode;
    out.public_inputs.height = 41;
    out.public_inputs.n_bits = 0x207fffffU;
    out.public_inputs.episode_profile = 2;
    out.public_inputs.transcript_version = 4;
    out.public_inputs.header_commitment = Filled(0x31);
    out.public_inputs.params_commitment = Filled(0x32);
    out.public_inputs.episode_digest.data()[0] = digest;
    out.public_inputs.target.data()[0] = target;
    out.public_inputs.final_digest = out.public_inputs.episode_digest;
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(all_26_endpoints_have_canonical_committed_memory)
{
    const auto values = Values();
    std::string why;
    const auto root = rc::ComputeRCStage3EpisodeSemanticValueRoot(
        values, values.size(), 8, &why);
    BOOST_REQUIRE_MESSAGE(root.has_value(), why);

    for (uint16_t id = 1;
         id <= rc::kRCStage3EpisodeSemanticEndpointCount; ++id) {
        const auto endpoint =
            static_cast<rc::RCStage3RelationEndpoint>(id);
        const auto role = rc::RCStage3EpisodeEndpointRole(endpoint);
        BOOST_REQUIRE(role.has_value());
        const auto manifest =
            rc::BuildRCStage3EpisodeSemanticMemoryManifest(
                endpoint, Filled(0x51), values.size(), values.size(),
                1000 + 100 * id, 3, *root, &why);
        BOOST_REQUIRE_MESSAGE(manifest.has_value(), why);
        BOOST_CHECK(
            manifest->endpoint == endpoint);
        BOOST_CHECK(
            manifest->role == *role);
        BOOST_CHECK_EQUAL(manifest->logical_rows, 5U);
        BOOST_CHECK_EQUAL(manifest->n_rows, 8U);
        BOOST_CHECK_MESSAGE(
            rc::ValidateRCStage3EpisodeSemanticMemoryManifest(
                *manifest, &why), why);

        aq::AirConstraintSystem<gf::Fp3> cs;
        std::vector<std::vector<gf::Fp3>> columns;
        BOOST_REQUIRE_MESSAGE(
            rc::BuildRCStage3EpisodeSemanticMemoryConstraintSystem(
                *manifest, cs, &why), why);
        BOOST_REQUIRE_MESSAGE(
            rc::BuildRCStage3EpisodeSemanticMemoryWitness(
                *manifest, values, columns, &why), why);
        BOOST_CHECK_EQUAL(
            cs.n_columns, rc::kRCStage3EpisodeMemoryColumns);
        BOOST_CHECK_EQUAL(cs.n_rows, 8U);
        BOOST_REQUIRE_EQUAL(cs.preprocessed_roots.size(), 1U);
        BOOST_CHECK(
            cs.preprocessed_roots[0].second ==
            manifest->canonical_value_root);
        BOOST_CHECK(std::equal(
            columns[rc::kRCStage3EpisodeMemoryValue].begin(),
            columns[rc::kRCStage3EpisodeMemoryValue].end(),
            columns[rc::kRCStage3EpisodeMemoryExport].begin(),
            [](const gf::Fp3& a, const gf::Fp3& b) {
                return gf::Eq(a, b);
            }));
        BOOST_CHECK(gf::IsZero(
            columns[rc::kRCStage3EpisodeMemoryValue][7]));
    }
}

BOOST_AUTO_TEST_CASE(real_air_roundtrip_rejects_root_schedule_and_query_mutation)
{
    const auto values = Values();
    std::string why;
    const auto root = rc::ComputeRCStage3EpisodeSemanticValueRoot(
        values, values.size(), 8, &why);
    BOOST_REQUIRE_MESSAGE(root.has_value(), why);
    const auto manifest =
        rc::BuildRCStage3EpisodeSemanticMemoryManifest(
            rc::RCStage3RelationEndpoint::EpisodeGemmOperandA,
            Filled(0x61), values.size(), values.size(),
            9000, 5, *root, &why);
    BOOST_REQUIRE_MESSAGE(manifest.has_value(), why);

    rc::RCStage3EpisodeSemanticMemoryProof proof;
    const auto prove_begin = std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3EpisodeSemanticMemory(
            *manifest, values, proof, &why), why);
    const auto prove_end = std::chrono::steady_clock::now();
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3EpisodeSemanticMemory(
            Filled(0x61), *manifest, proof, &why), why);
    const auto verify_end = std::chrono::steady_clock::now();

    BOOST_REQUIRE_EQUAL(
        proof.quotient.batch.columns.size(),
        rc::kRCStage3EpisodeMemoryColumns + 1);
    BOOST_CHECK(
        proof.quotient.batch
            .columns[rc::kRCStage3EpisodeMemoryValue].root ==
        manifest->canonical_value_root);
    BOOST_CHECK(
        proof.quotient.batch
            .columns[rc::kRCStage3EpisodeMemoryExport].root ==
        manifest->canonical_value_root);

    const auto prove_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            prove_end - prove_begin).count();
    const auto verify_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            verify_end - prove_end).count();
    BOOST_TEST_MESSAGE(
        "episode_semantic_memory rows=8 columns="
        << rc::kRCStage3EpisodeMemoryColumns
        << " prove_ms=" << prove_ms
        << " verify_ms=" << verify_ms);

    BOOST_CHECK(!rc::VerifyRCStage3EpisodeSemanticMemory(
        Filled(0x62), *manifest, proof, &why));

    auto bad_schedule = *manifest;
    ++bad_schedule.address_stride;
    BOOST_CHECK(
        !rc::ValidateRCStage3EpisodeSemanticMemoryManifest(
            bad_schedule, &why));

    const auto other_manifest =
        rc::BuildRCStage3EpisodeSemanticMemoryManifest(
            rc::RCStage3RelationEndpoint::EpisodeGemmOperandA,
            Filled(0x61), values.size(), values.size(),
            9000, 5, Filled(0xa5), &why);
    BOOST_REQUIRE_MESSAGE(other_manifest.has_value(), why);
    auto relabelled_proof = proof;
    relabelled_proof.manifest_commitment =
        other_manifest->manifest_commitment;
    BOOST_CHECK(!rc::VerifyRCStage3EpisodeSemanticMemory(
        Filled(0x61), *other_manifest, relabelled_proof, &why));

    auto bad_query = proof;
    BOOST_REQUIRE(!bad_query.quotient.batch.queries.empty());
    BOOST_REQUIRE(
        !bad_query.quotient.batch.queries[0].columns.empty());
    bad_query.quotient.batch.queries[0].columns[0].value =
        gf::Add(
            bad_query.quotient.batch.queries[0].columns[0].value,
            gf::Fp3::One());
    BOOST_CHECK(!rc::VerifyRCStage3EpisodeSemanticMemory(
        Filled(0x61), *manifest, bad_query, &why));

    auto bad_values = values;
    bad_values[2] =
        gf::Add(bad_values[2], gf::Fp3::One());
    rc::RCStage3EpisodeSemanticMemoryProof rejected;
    BOOST_CHECK(!rc::ProveRCStage3EpisodeSemanticMemory(
        *manifest, bad_values, rejected, &why));
}

BOOST_AUTO_TEST_CASE(audit_is_exact_and_does_not_promote_memory_to_semantics)
{
    const auto audit =
        rc::CurrentRCStage3EpisodeSemanticEndpointAudit();
    BOOST_REQUIRE_EQUAL(
        audit.size(),
        rc::kRCStage3EpisodeSemanticEndpointCount);
    uint32_t memory_complete = 0;
    uint32_t local_kernel = 0;
    uint32_t semantic_complete = 0;
    uint32_t recursive = 0;
    for (uint32_t i = 0; i < audit.size(); ++i) {
        BOOST_CHECK_EQUAL(
            static_cast<uint16_t>(audit[i].endpoint), i + 1);
        BOOST_CHECK(audit[i].canonical_schedule_executable);
        BOOST_CHECK(audit[i].proof_owned_memory_executable);
        BOOST_CHECK(audit[i].canonical_root_authenticated);
        BOOST_CHECK(audit[i].same_trace_export_constrained);
        BOOST_CHECK(!audit[i].source.empty());
        BOOST_CHECK(!audit[i].remaining.empty());
        memory_complete +=
            audit[i].canonical_schedule_executable &&
            audit[i].proof_owned_memory_executable &&
            audit[i].canonical_root_authenticated &&
            audit[i].same_trace_export_constrained;
        local_kernel += audit[i].local_semantic_air_available;
        semantic_complete += audit[i].semantic_relation_complete;
        recursive += audit[i].recursively_consumed;
    }
    BOOST_CHECK_EQUAL(memory_complete, 26U);
    BOOST_CHECK_EQUAL(local_kernel, 14U);
    BOOST_CHECK_EQUAL(semantic_complete, 2U);
    BOOST_CHECK_EQUAL(recursive, 0U);
    static_assert(rc::kRCStage3EpisodeSemanticMemoryExecutable);
    static_assert(!rc::kRCStage3EpisodeSemanticRelationsComplete);
}

BOOST_AUTO_TEST_CASE(pow_comparison_air_closes_all_256_borrow_steps)
{
    const auto statement = PowStatement(99, 100);
    std::string why;
    const auto pin = rc::BuildRCStage3EpisodePowPin(statement, &why);
    BOOST_REQUIRE_MESSAGE(pin.has_value(), why);
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3EpisodePowConstraintSystem(
            *pin, cs, &why), why);
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3EpisodePowWitness(
            *pin, columns, &why), why);
    BOOST_CHECK_EQUAL(cs.n_rows, 32U);
    BOOST_CHECK_EQUAL(
        cs.n_columns, rc::kRCStage3EpisodePowColumns);
    BOOST_CHECK(gf::IsZero(
        columns[rc::kRCStage3EpisodePowBorrow][0]));
    BOOST_CHECK(gf::IsZero(
        columns[rc::kRCStage3EpisodePowBorrowOut][31]));

    rc::RCStage3EpisodePowProof proof;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3EpisodePow(statement, proof, &why), why);
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3EpisodePow(
            statement, *pin, proof, &why), why);

    const auto equal = PowStatement(100, 100);
    rc::RCStage3EpisodePowProof equal_proof;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3EpisodePow(equal, equal_proof, &why), why);
    const auto equal_pin =
        rc::BuildRCStage3EpisodePowPin(equal, &why);
    BOOST_REQUIRE(equal_pin.has_value());
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3EpisodePow(
            equal, *equal_pin, equal_proof, &why), why);

    const auto above = PowStatement(101, 100);
    rc::RCStage3EpisodePowProof rejected;
    BOOST_CHECK(!rc::ProveRCStage3EpisodePow(
        above, rejected, &why));

    auto changed_statement = statement;
    changed_statement.public_inputs.target.data()[0] = 101;
    BOOST_CHECK(!rc::VerifyRCStage3EpisodePow(
        changed_statement, *pin, proof, &why));

    auto changed_query = proof;
    BOOST_REQUIRE(!changed_query.quotient.batch.queries.empty());
    BOOST_REQUIRE(
        !changed_query.quotient.batch.queries[0].columns.empty());
    changed_query.quotient.batch.queries[0].columns[0].value =
        gf::Add(
            changed_query.quotient.batch.queries[0].columns[0].value,
            gf::Fp3::One());
    BOOST_CHECK(!rc::VerifyRCStage3EpisodePow(
        statement, *pin, changed_query, &why));
    static_assert(rc::kRCStage3EpisodePowComparisonExecutable);
}

BOOST_AUTO_TEST_CASE(flat_memory_bundle_is_contiguous_exact_and_committed)
{
    std::vector<gf::Fp3> values;
    for (uint32_t i = 0; i < 17; ++i) {
        values.push_back(gf::FromU64_3(100 + i));
    }
    rc::RCStage3EpisodeSemanticMemoryBundle bundle;
    std::string why;
    const auto endpoint =
        rc::RCStage3RelationEndpoint::EpisodeExtractInput;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3EpisodeSemanticMemoryBundle(
            endpoint, Filled(0x71), 5000, 3,
            values, bundle, &why), why);
    BOOST_REQUIRE_EQUAL(bundle.shards.size(), 1U);
    const std::vector<uint256> expected_roots{
        bundle.shards[0].manifest.canonical_value_root};
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3EpisodeSemanticMemoryBundle(
            endpoint, Filled(0x71), values.size(),
            5000, 3, expected_roots, bundle, &why), why);
    BOOST_CHECK(!bundle.bundle_commitment.IsNull());

    auto missing = bundle;
    missing.shards.clear();
    BOOST_CHECK(!rc::VerifyRCStage3EpisodeSemanticMemoryBundle(
        endpoint, Filled(0x71), values.size(),
        5000, 3, expected_roots, missing, &why));

    auto shifted = bundle;
    ++shifted.shards[0].value_begin;
    shifted.bundle_commitment =
        rc::ComputeRCStage3EpisodeSemanticMemoryBundleCommitment(
            shifted);
    BOOST_CHECK(!rc::VerifyRCStage3EpisodeSemanticMemoryBundle(
        endpoint, Filled(0x71), values.size(),
        5000, 3, expected_roots, shifted, &why));

    auto bad_proof = bundle;
    BOOST_REQUIRE(
        !bad_proof.shards[0].proof.quotient.batch.queries.empty());
    bad_proof.shards[0].proof.quotient.batch.queries[0]
        .columns[0].value =
        gf::Add(
            bad_proof.shards[0].proof.quotient.batch.queries[0]
                .columns[0].value,
            gf::Fp3::One());
    bad_proof.bundle_commitment =
        rc::ComputeRCStage3EpisodeSemanticMemoryBundleCommitment(
            bad_proof);
    BOOST_CHECK(!rc::VerifyRCStage3EpisodeSemanticMemoryBundle(
        endpoint, Filled(0x71), values.size(),
        5000, 3, expected_roots, bad_proof, &why));
    BOOST_CHECK(!rc::VerifyRCStage3EpisodeSemanticMemoryBundle(
        endpoint, Filled(0x71), values.size(),
        5000, 3, {Filled(0x99)}, bundle, &why));

    // Exercise the production-size partition algebra without allocating or
    // proving a million-row trace.
    std::vector<rc::RCStage3EpisodeSemanticMemoryShard>
        two_shards;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3EpisodeSemanticMemoryShardManifests(
            endpoint, Filled(0x71),
            uint64_t{rc::kRCStage3EpisodeSemanticMaxRows} + 1,
            9000, 1, {Filled(0x72), Filled(0x73)},
            two_shards, &why), why);
    BOOST_REQUIRE_EQUAL(two_shards.size(), 2U);
    BOOST_CHECK_EQUAL(two_shards[0].value_begin, 0U);
    BOOST_CHECK_EQUAL(
        two_shards[0].manifest.logical_rows,
        rc::kRCStage3EpisodeSemanticMaxRows);
    BOOST_CHECK_EQUAL(
        two_shards[1].value_begin,
        rc::kRCStage3EpisodeSemanticMaxRows);
    BOOST_CHECK_EQUAL(two_shards[1].manifest.logical_rows, 1U);
    BOOST_CHECK_EQUAL(
        two_shards[1].manifest.address_begin,
        9000U + rc::kRCStage3EpisodeSemanticMaxRows);
}

BOOST_AUTO_TEST_CASE(hash_semantic_binding_is_typed_and_memory_root_exact)
{
    namespace ha = rc::stage3_hash_air;
    namespace hs = rc::stage3_hash_semantic;
    const auto statement = PowStatement(7, 9);
    ha::ShaManifest sha;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildShaManifest(
            std::vector<uint8_t>{'b', 't', 'x'},
            ha::ShaMode::Single, sha, &why), why);
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildShaManifestBoundaryInstances(
            sha, boundaries, &why), why);
    BOOST_REQUIRE_EQUAL(boundaries.size(), 1U);

    const auto memory =
        rc::BuildRCStage3EpisodeHashSemanticMemoryManifest(
            statement,
            rc::RCStage3RelationEndpoint::EpisodeBuilderSeedChain,
            boundaries, hs::BoundaryPort::ExternalThenFinal, &why);
    BOOST_REQUIRE_MESSAGE(memory.has_value(), why);
    std::vector<gf::Fp3> values;
    BOOST_REQUIRE_MESSAGE(
        hs::BuildCanonicalBoundaryValues(
            boundaries, hs::BoundaryPort::ExternalThenFinal,
            values, &why), why);
    rc::RCStage3EpisodeSemanticMemoryProof memory_proof;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3EpisodeSemanticMemory(
            *memory, values, memory_proof, &why), why);
    rc::RCStage3EpisodeHashSemanticBinding binding;
    binding.memory_manifest = *memory;
    binding.memory_proof = memory_proof;

    hs::FlatBoundaryProofBundle empty_hash;
    empty_hash.endpoint =
        rc::RCStage3RelationEndpoint::EpisodeBuilderSeedChain;
    empty_hash.statement_commitment =
        rc::RCStage3EpisodeStatementCommitment(statement);
    empty_hash.manifest_commitment = sha.commitment;
    BOOST_CHECK(!rc::VerifyRCStage3EpisodeShaSemantic(
        statement, empty_hash.endpoint, sha, empty_hash,
        binding, &why));
    BOOST_CHECK(!rc::VerifyRCStage3EpisodeShaSemantic(
        statement,
        rc::RCStage3RelationEndpoint::EpisodeDigestValue,
        sha, empty_hash, binding, &why));

    auto wrong_port = binding;
    wrong_port.port = hs::BoundaryPort::Final;
    BOOST_CHECK(!rc::VerifyRCStage3EpisodeShaSemantic(
        statement, empty_hash.endpoint, sha, empty_hash,
        wrong_port, &why));
    static_assert(
        rc::kRCStage3EpisodeFlatHashMemoryBindingExecutable);
}

BOOST_AUTO_TEST_CASE(flat_sha_semantic_and_memory_execute_together)
{
    if (std::getenv("BTX_RUN_STAGE3_HASH_SEMANTIC_PROVE") ==
        nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_HASH_SEMANTIC_PROVE=1 for "
            "flat SHA provenance + endpoint-memory composition");
        return;
    }
    namespace ha = rc::stage3_hash_air;
    namespace hs = rc::stage3_hash_semantic;
    const auto statement = PowStatement(7, 9);
    const auto endpoint =
        rc::RCStage3RelationEndpoint::EpisodeBuilderSeedChain;
    ha::ShaManifest sha;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildShaManifest(
            std::vector<uint8_t>{0x42}, ha::ShaMode::Single,
            sha, &why), why);
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildShaManifestBoundaryInstances(
            sha, boundaries, &why), why);
    BOOST_REQUIRE_EQUAL(boundaries.size(), 1U);

    const auto program = ha::BuildCanonicalProgram(
        ha::ProgramKind::Sha256Compression);
    ha::ProgramWitness witness;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildProgramWitness(
            program, boundaries[0].external_values,
            witness, &why), why);
    hs::FlatBoundaryProofBundle hash_bundle;
    hash_bundle.endpoint = endpoint;
    hash_bundle.statement_commitment =
        rc::RCStage3EpisodeStatementCommitment(statement);
    hash_bundle.manifest_commitment = sha.commitment;
    hash_bundle.proofs.resize(1);
    const uint256 hash_seed = hs::ComputeBoundaryProofSeed(
        endpoint, hash_bundle.statement_commitment,
        hash_bundle.manifest_commitment, 0, 1);
    BOOST_REQUIRE_MESSAGE(
        ha::ProveFixedProgramProvenanceAir(
            program, witness, boundaries[0].external_values,
            boundaries[0].final_words, hash_seed,
            hash_bundle.proofs[0], &why), why);

    const auto memory =
        rc::BuildRCStage3EpisodeHashSemanticMemoryManifest(
            statement, endpoint, boundaries,
            hs::BoundaryPort::ExternalThenFinal, &why);
    BOOST_REQUIRE_MESSAGE(memory.has_value(), why);
    std::vector<gf::Fp3> values;
    BOOST_REQUIRE_MESSAGE(
        hs::BuildCanonicalBoundaryValues(
            boundaries, hs::BoundaryPort::ExternalThenFinal,
            values, &why), why);
    rc::RCStage3EpisodeHashSemanticBinding binding;
    binding.memory_manifest = *memory;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3EpisodeSemanticMemory(
            *memory, values, binding.memory_proof, &why), why);
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3EpisodeShaSemantic(
            statement, endpoint, sha, hash_bundle,
            binding, &why), why);

    auto changed_memory = binding;
    BOOST_REQUIRE(
        !changed_memory.memory_proof.quotient.batch.queries.empty());
    changed_memory.memory_proof.quotient.batch.queries[0]
        .columns[0].value =
        gf::Add(
            changed_memory.memory_proof.quotient.batch.queries[0]
                .columns[0].value,
            gf::Fp3::One());
    BOOST_CHECK(!rc::VerifyRCStage3EpisodeShaSemantic(
        statement, endpoint, sha, hash_bundle,
        changed_memory, &why));

    auto changed_hash = hash_bundle;
    BOOST_REQUIRE(
        !changed_hash.proofs[0].quotient.batch.queries.empty());
    changed_hash.proofs[0].quotient.batch.queries[0]
        .columns[0].value =
        gf::Add(
            changed_hash.proofs[0].quotient.batch.queries[0]
                .columns[0].value,
            gf::Fp3::One());
    BOOST_CHECK(!rc::VerifyRCStage3EpisodeShaSemantic(
        statement, endpoint, sha, changed_hash,
        binding, &why));
}

BOOST_AUTO_TEST_SUITE_END()
