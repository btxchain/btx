// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_coupled_semantic.h>

#include <cstdlib>

namespace {

namespace rc = matmul::v4::rc;
namespace aq = matmul::v4::rc::air_quotient;
namespace gf = matmul::v4::rc::gkr_field;
using gf::Fp3;

uint256 H(const char* hex)
{
    std::string padded(hex);
    padded.insert(0, 64U - padded.size(), '0');
    return uint256::FromHex(padded).value();
}

rc::RCStage3CoupledShape ToyShape()
{
    return rc::MakeRCStage3CoupledShape(
        rc::MakeMediumV3RCCoupParams(),
        rc::MakeMediumV4RCCoupOptions());
}

rc::RCStage3CoupledAirRequest PermutationRequest()
{
    return {
        rc::RCStage3RelationRole::CoupledPermutation,
        ToyShape(),
        gf::FromU64_3(7),
        gf::FromU64_3(11),
        0};
}

rc::RCStage3SuccinctProof Statement()
{
    rc::RCStage3SuccinctProof statement;
    statement.statement = rc::RCStage3StatementKind::Composed;
    statement.public_inputs.coupled_profile = 4;
    statement.public_inputs.transcript_version = rc::ENC_RC_V4;
    statement.public_inputs.header_commitment = H("10");
    statement.public_inputs.params_commitment = H("11");
    statement.public_inputs.sigma = H("12");
    statement.public_inputs.coupled_digest = H("13");
    return statement;
}

} // namespace

BOOST_AUTO_TEST_SUITE(matmul_v4_rc_stage3_coupled_semantic_tests)

BOOST_AUTO_TEST_CASE(exact_twenty_six_entry_inventory_is_fail_closed)
{
    const auto audit = rc::CurrentRCStage3CoupledSemanticAudit(
        ToyShape(), gf::FromU64_3(7), gf::FromU64_3(11));
    BOOST_REQUIRE_EQUAL(audit.size(), 26U);
    uint32_t memory = 0;
    uint32_t complete = 0;
    for (uint32_t i = 0; i < audit.size(); ++i) {
        BOOST_CHECK_EQUAL(
            static_cast<uint16_t>(audit[i].endpoint), 27U + i);
        memory += audit[i].proof_owned_memory_root ? 1U : 0U;
        complete += audit[i].semantic_relation_complete ? 1U : 0U;
    }
    BOOST_CHECK_EQUAL(memory, 20U);
    BOOST_CHECK_EQUAL(complete, 0U);
    BOOST_CHECK(!rc::kRCStage3CoupledAllSemanticEndpointsComplete);
}

BOOST_AUTO_TEST_CASE(full_vector_memory_alias_rejects_value_mutation)
{
    const auto request = PermutationRequest();
    rc::RCStage3CoupledAirEntry entry;
    BOOST_REQUIRE(rc::ResolveRCStage3CoupledAir(request, entry));

    rc::RCStage3CoupledSemanticEndpointSpec spec;
    BOOST_REQUIRE(rc::ResolveRCStage3CoupledSemanticEndpointSpec(
        rc::RCStage3RelationEndpoint::CoupledPermutationInput,
        request, spec));
    BOOST_CHECK(spec.full_vector_export);
    BOOST_CHECK(spec.canonical_schedule);

    aq::AirConstraintSystem<Fp3> combined;
    rc::RCStage3CoupledSemanticLayout layout;
    BOOST_REQUIRE(rc::BuildRCStage3CoupledSemanticConstraintSystem(
        spec, entry.constraints, combined, &layout));

    std::vector<std::vector<Fp3>> relation(
        entry.constraints.n_columns,
        std::vector<Fp3>(entry.constraints.n_rows));
    relation[rc::coupled_air_col::COPY_INPUT] = {
        gf::FromU64_3(3), gf::FromU64_3(9)};
    relation[rc::coupled_air_col::COPY_OUTPUT] =
        relation[rc::coupled_air_col::COPY_INPUT];
    std::vector<std::vector<Fp3>> witness;
    BOOST_REQUIRE(rc::BuildRCStage3CoupledSemanticWitness(
        layout, relation, witness));

    const uint256 provisional_seed = H("42");
    const auto preliminary =
        aq::AirQuotientProve<Fp3>(
            combined, witness, provisional_seed);
    BOOST_REQUIRE_MESSAGE(preliminary.ok, preliminary.note);

    const auto statement = Statement();
    rc::RCStage3CoupledSemanticPublicPin pin;
    pin.endpoint =
        rc::RCStage3RelationEndpoint::CoupledPermutationInput;
    pin.request = request;
    pin.statement_commitment =
        rc::CommitRCStage3CoupledStatement(statement.public_inputs);
    pin.shape_commitment = spec.shape_commitment;
    pin.schedule_commitment = spec.schedule_commitment;
    pin.instance_count = spec.required_instances;
    for (uint32_t column = 0;
         column < entry.constraints.n_columns; ++column) {
        pin.relation_column_roots.push_back(
            preliminary.proof.batch.columns[column].root);
    }
    pin.value_column_roots.push_back(
        preliminary.proof.batch.columns[
            layout.ValueColumn(0)].root);
    pin.semantic_memory_root =
        rc::ComputeRCStage3CoupledSemanticMemoryRoot(
            pin.endpoint, pin.request.role, pin.instance_count,
            pin.shape_commitment, pin.schedule_commitment,
            pin.value_column_roots);
    BOOST_REQUIRE(!pin.semantic_memory_root.IsNull());
    const uint256 seed =
        rc::ComputeRCStage3CoupledSemanticProofSeed(pin);
    BOOST_REQUIRE(!seed.IsNull());
    const auto result =
        aq::AirQuotientProve<Fp3>(combined, witness, seed);
    BOOST_REQUIRE_MESSAGE(result.ok, result.note);
    BOOST_CHECK(rc::VerifyRCStage3CoupledSemanticProof(
        statement, pin, result.proof));

    auto changed_root = pin;
    changed_root.value_column_roots[0] = H("1234");
    BOOST_CHECK(!rc::VerifyRCStage3CoupledSemanticProof(
        statement, changed_root, result.proof));

    auto changed_schedule = pin;
    changed_schedule.schedule_commitment = H("5678");
    BOOST_CHECK(!rc::VerifyRCStage3CoupledSemanticProof(
        statement, changed_schedule, result.proof));

    auto changed_witness = witness;
    changed_witness[layout.ValueColumn(0)][0] =
        gf::Add(changed_witness[layout.ValueColumn(0)][0],
                Fp3::One());
    const auto bad =
        aq::AirQuotientProve<Fp3>(
            combined, changed_witness, seed);
    BOOST_CHECK(!bad.ok);
}

BOOST_AUTO_TEST_CASE(flat_local_bundle_executes_exact_contiguous_schedule)
{
    const auto request = PermutationRequest();
    const auto statement = Statement();
    rc::RCStage3CoupledAirEntry entry;
    BOOST_REQUIRE(rc::ResolveRCStage3CoupledAir(request, entry));
    rc::RCStage3CoupledSemanticEndpointSpec spec;
    BOOST_REQUIRE(rc::ResolveRCStage3CoupledSemanticEndpointSpec(
        rc::RCStage3RelationEndpoint::CoupledPermutationInput,
        request, spec));
    BOOST_REQUIRE_EQUAL(spec.required_instances, 4U);

    aq::AirConstraintSystem<Fp3> combined;
    rc::RCStage3CoupledSemanticLayout layout;
    BOOST_REQUIRE(rc::BuildRCStage3CoupledSemanticConstraintSystem(
        spec, entry.constraints, combined, &layout));
    std::vector<std::vector<Fp3>> relation(
        entry.constraints.n_columns,
        std::vector<Fp3>(entry.constraints.n_rows));
    relation[rc::coupled_air_col::COPY_INPUT] = {
        gf::FromU64_3(5), gf::FromU64_3(13)};
    relation[rc::coupled_air_col::COPY_OUTPUT] =
        relation[rc::coupled_air_col::COPY_INPUT];
    std::vector<std::vector<Fp3>> witness;
    BOOST_REQUIRE(rc::BuildRCStage3CoupledSemanticWitness(
        layout, relation, witness));

    const auto preliminary =
        aq::AirQuotientProve<Fp3>(
            combined, witness, H("77"));
    BOOST_REQUIRE_MESSAGE(preliminary.ok, preliminary.note);
    rc::RCStage3CoupledSemanticPublicPin base;
    base.endpoint =
        rc::RCStage3RelationEndpoint::CoupledPermutationInput;
    base.request = request;
    base.statement_commitment =
        rc::CommitRCStage3CoupledStatement(statement.public_inputs);
    base.shape_commitment = spec.shape_commitment;
    base.instance_count = spec.required_instances;
    for (uint32_t column = 0;
         column < entry.constraints.n_columns; ++column) {
        base.relation_column_roots.push_back(
            preliminary.proof.batch.columns[column].root);
    }
    base.value_column_roots.push_back(
        preliminary.proof.batch.columns[
            layout.ValueColumn(0)].root);

    rc::RCStage3CoupledSemanticFlatBundle bundle;
    bundle.endpoint = base.endpoint;
    bundle.statement_commitment = base.statement_commitment;
    bundle.total_instances = spec.required_instances;
    for (uint64_t i = 0; i < bundle.total_instances; ++i) {
        rc::RCStage3CoupledSemanticShard shard;
        shard.instance_begin = i;
        shard.pin = base;
        shard.pin.instance_begin = i;
        shard.pin.instance_span = 1;
        shard.pin.schedule_commitment =
            rc::ComputeRCStage3CoupledSemanticShardSchedule(
                spec.schedule_commitment, i, 1,
                bundle.total_instances);
        shard.pin.semantic_memory_root =
            rc::ComputeRCStage3CoupledSemanticMemoryRoot(
                shard.pin.endpoint, shard.pin.request.role,
                shard.pin.instance_count,
                shard.pin.shape_commitment,
                shard.pin.schedule_commitment,
                shard.pin.value_column_roots);
        const uint256 seed =
            rc::ComputeRCStage3CoupledSemanticProofSeed(shard.pin);
        const auto proved =
            aq::AirQuotientProve<Fp3>(
                combined, witness, seed);
        BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
        shard.proof = proved.proof;
        bundle.shards.push_back(std::move(shard));
    }
    bundle.bundle_commitment =
        rc::ComputeRCStage3CoupledSemanticFlatBundleCommitment(
            bundle);
    BOOST_REQUIRE(!bundle.bundle_commitment.IsNull());
    BOOST_CHECK(rc::VerifyRCStage3CoupledSemanticFlatBundle(
        statement, bundle));

    auto reordered = bundle;
    std::swap(reordered.shards[0], reordered.shards[1]);
    reordered.bundle_commitment =
        rc::ComputeRCStage3CoupledSemanticFlatBundleCommitment(
            reordered);
    BOOST_CHECK(!rc::VerifyRCStage3CoupledSemanticFlatBundle(
        statement, reordered));

    auto omitted = bundle;
    omitted.shards.pop_back();
    BOOST_CHECK(!rc::VerifyRCStage3CoupledSemanticFlatBundle(
        statement, omitted));

    auto changed_commitment = bundle;
    changed_commitment.bundle_commitment = H("abba");
    BOOST_CHECK(!rc::VerifyRCStage3CoupledSemanticFlatBundle(
        statement, changed_commitment));
}

BOOST_AUTO_TEST_CASE(flat_xof_bundle_is_exact_and_memory_root_bound)
{
    if (std::getenv("BTX_RUN_STAGE3_COUPLED_HASH_SEMANTIC_PROVE") ==
        nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_COUPLED_HASH_SEMANTIC_PROVE=1 "
            "for the fixed-program quotient round trip");
        return;
    }

    namespace ha = rc::stage3_hash_air;
    namespace hs = rc::stage3_hash_semantic;
    const auto statement = Statement();
    const auto shape = ToyShape();
    ha::CounterXofManifest manifest;
    std::string why;
    BOOST_REQUIRE(ha::BuildCounterXofManifest(
        H("99"), 7, ha::CounterXofMode::RawBytes,
        1, manifest, &why));
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    BOOST_REQUIRE(ha::BuildCounterXofManifestBoundaryInstances(
        manifest, boundaries, &why));
    BOOST_REQUIRE_EQUAL(boundaries.size(), 1U);

    const auto endpoint =
        rc::RCStage3RelationEndpoint::CoupledBankSeedXof;
    hs::FlatBoundaryProofBundle bundle;
    bundle.endpoint = endpoint;
    bundle.statement_commitment =
        rc::CommitRCStage3CoupledStatement(statement.public_inputs);
    bundle.manifest_commitment = manifest.commitment;
    bundle.proofs.resize(boundaries.size());
    const auto program = ha::BuildCanonicalProgram(
        ha::ProgramKind::Sha256Compression);
    for (uint32_t i = 0; i < boundaries.size(); ++i) {
        ha::ProgramWitness program_witness;
        BOOST_REQUIRE(ha::BuildProgramWitness(
            program, boundaries[i].external_values,
            program_witness, &why));
        const uint256 seed = hs::ComputeBoundaryProofSeed(
            endpoint, bundle.statement_commitment,
            bundle.manifest_commitment, i, boundaries.size());
        BOOST_REQUIRE(ha::ProveFixedProgramProvenanceAir(
            program, program_witness,
            boundaries[i].external_values,
            boundaries[i].final_words,
            seed, bundle.proofs[i], &why));
    }

    rc::RCStage3CoupledHashSemanticPin pin;
    BOOST_REQUIRE(rc::BuildRCStage3CoupledHashSemanticPin(
        endpoint, shape, bundle.statement_commitment,
        manifest.commitment, boundaries,
        hs::BoundaryPort::ExternalThenFinal, pin, &why));
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3CoupledCounterXofSemantic(
            statement, shape, manifest, bundle, pin, &why),
        why);

    auto bad_root = pin;
    bad_root.boundary_value_root = H("abcd");
    BOOST_CHECK(!rc::VerifyRCStage3CoupledCounterXofSemantic(
        statement, shape, manifest, bundle, bad_root, &why));

    auto bad_schedule = pin;
    bad_schedule.schedule_commitment = H("cafe");
    BOOST_CHECK(!rc::VerifyRCStage3CoupledCounterXofSemantic(
        statement, shape, manifest, bundle, bad_schedule, &why));

    auto missing = bundle;
    missing.proofs.clear();
    BOOST_CHECK(!rc::VerifyRCStage3CoupledCounterXofSemantic(
        statement, shape, manifest, missing, pin, &why));
}

BOOST_AUTO_TEST_SUITE_END()
