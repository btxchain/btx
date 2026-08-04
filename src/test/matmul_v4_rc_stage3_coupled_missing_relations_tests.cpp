// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_coupled_missing_relations.h>

#include <cstdlib>

namespace {

namespace rc = matmul::v4::rc;
namespace aq = rc::air_quotient;
namespace gf = rc::gkr_field;
namespace ha = rc::stage3_hash_air;
namespace hs = rc::stage3_hash_semantic;

uint256 H(unsigned char value)
{
    std::array<unsigned char, 32> bytes{};
    bytes.fill(value);
    return uint256{Span<const unsigned char>{
        bytes.data(), bytes.size()}};
}

rc::RCStage3CoupledShape ToyShape()
{
    return rc::MakeRCStage3CoupledShape(
        rc::MakeToyRCCoupParams(),
        rc::MakeV4RCCoupOptions());
}

rc::RCStage3SuccinctProof Statement(const uint256& digest = H(0x44))
{
    rc::RCStage3SuccinctProof statement;
    statement.statement = rc::RCStage3StatementKind::Composed;
    statement.public_inputs.height = 17;
    statement.public_inputs.episode_profile = 2;
    statement.public_inputs.coupled_profile = 4;
    statement.public_inputs.transcript_version = rc::ENC_RC_V4;
    statement.public_inputs.header_commitment = H(0x11);
    statement.public_inputs.params_commitment = H(0x22);
    statement.public_inputs.sigma = H(0x33);
    statement.public_inputs.coupled_digest = digest;
    return statement;
}

bool ProveHashBundle(
    rc::RCStage3RelationEndpoint endpoint,
    const uint256& statement_commitment,
    const uint256& manifest_commitment,
    const std::vector<ha::FixedProgramBoundaryInstance>& boundaries,
    hs::FlatBoundaryProofBundle& out,
    std::string* why)
{
    out = {};
    out.endpoint = endpoint;
    out.statement_commitment = statement_commitment;
    out.manifest_commitment = manifest_commitment;
    out.proofs.resize(boundaries.size());
    const auto program =
        ha::BuildCanonicalProgram(ha::ProgramKind::Sha256Compression);
    for (uint32_t i = 0; i < boundaries.size(); ++i) {
        ha::ProgramWitness witness;
        if (!ha::BuildProgramWitness(
                program, boundaries[i].external_values,
                witness, why)) {
            return false;
        }
        const uint256 seed = hs::ComputeBoundaryProofSeed(
            endpoint, statement_commitment, manifest_commitment,
            i, boundaries.size());
        if (!ha::ProveFixedProgramProvenanceAir(
                program, witness, boundaries[i].external_values,
                boundaries[i].final_words, seed,
                out.proofs[i], why)) {
            return false;
        }
    }
    return true;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_coupled_missing_relations_tests)

BOOST_AUTO_TEST_CASE(audit_separates_local_execution_from_root_links)
{
    const auto audit =
        rc::CurrentRCStage3CoupledMissingEndpointAudit(ToyShape());
    BOOST_REQUIRE_EQUAL(audit.size(), 6U);
    uint32_t local = 0;
    uint32_t local_relations = 0;
    uint32_t producer = 0;
    uint32_t strict = 0;
    for (const auto& endpoint : audit) {
        BOOST_CHECK(endpoint.local_engine_executable);
        local += endpoint.verifier_derived_schedule &&
                 endpoint.exact_all_instance_proof_execution &&
                 endpoint.proof_owned_memory_root;
        local_relations += endpoint.local_relation_complete;
        producer += endpoint.producer_graph_complete;
        strict += endpoint.strict_semantic_complete;
        BOOST_CHECK_EQUAL(
            endpoint.strict_semantic_complete,
            endpoint.local_relation_complete &&
                endpoint.producer_graph_complete);
        if (!endpoint.strict_semantic_complete) {
            BOOST_CHECK(!endpoint.remaining.empty());
        }
    }
    BOOST_CHECK_EQUAL(local, 6U);
    BOOST_CHECK_EQUAL(local_relations, 5U);
    BOOST_CHECK_EQUAL(producer, 0U);
    BOOST_CHECK_EQUAL(strict, 0U);
    BOOST_CHECK(
        audit.back().endpoint ==
        rc::RCStage3RelationEndpoint::CoupledDigestValue);
    BOOST_CHECK(audit.back().outer_statement_equality);
    const auto& digest_inputs = audit.at(4);
    BOOST_CHECK(
        digest_inputs.endpoint ==
        rc::RCStage3RelationEndpoint::
            CoupledDigestBankAndBarriers);
    BOOST_CHECK(digest_inputs.local_relation_complete);
    BOOST_CHECK(!digest_inputs.producer_graph_complete);
    BOOST_CHECK(!digest_inputs.strict_semantic_complete);
    BOOST_CHECK(!rc::kRCStage3CoupledMissingRelationsAuthorityReady);

    const auto production =
        rc::CurrentRCStage3CoupledMissingEndpointAudit(
            rc::MakeRCStage3CoupledShape(
                rc::MakeProductionV3RCCoupParams(),
                rc::MakeV4RCCoupOptions()));
    BOOST_REQUIRE_EQUAL(production.size(), 6U);
    BOOST_CHECK(production[0].local_engine_executable);
    BOOST_CHECK(!production[0].exact_all_instance_proof_execution);
    BOOST_CHECK(!production[0].proof_owned_memory_root);
    BOOST_CHECK(
        production[0].remaining.find("16 MiB") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(coupled_range_schedule_is_shape_derived_and_exact)
{
    const auto statement = Statement();
    rc::RCStage3CoupledSignedRangeManifest manifest;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledSignedRangeManifest(
            statement, ToyShape(), manifest, &why),
        why);
    BOOST_CHECK_EQUAL(manifest.scheduled_gemms, 192U);
    BOOST_CHECK_EQUAL(manifest.total_output_cells, 6144U);
    BOOST_CHECK_EQUAL(manifest.max_abs, 32U * 48U * 48U);
    BOOST_CHECK_EQUAL(manifest.shard_count, 1U);
    BOOST_CHECK(
        manifest.commitment ==
        rc::CommitRCStage3CoupledSignedRangeManifest(manifest));

    rc::RCStage3SignedRangePin pin;
    BOOST_REQUIRE_MESSAGE(
        rc::MakeRCStage3CoupledSignedRangePin(
            manifest, 0, pin, &why),
        why);
    BOOST_CHECK_EQUAL(pin.cell_begin, 0U);
    BOOST_CHECK_EQUAL(pin.logical_rows, 6144U);
    BOOST_CHECK_EQUAL(pin.n_rows, 8192U);
    BOOST_CHECK_EQUAL(pin.max_abs, manifest.max_abs);
    BOOST_CHECK(!rc::MakeRCStage3CoupledSignedRangePin(
        manifest, 1, pin, &why));

    auto changed = manifest;
    ++changed.total_output_cells;
    rc::RCStage3CoupledSignedRangeExecution empty;
    empty.manifest = changed;
    BOOST_CHECK(!rc::VerifyRCStage3CoupledSignedRangeExecution(
        statement, ToyShape(), empty, &why));
}

BOOST_AUTO_TEST_CASE(bank_manifest_and_ports_reject_unexecuted_bundle)
{
    const auto statement = Statement();
    const auto shape = ToyShape();
    const uint64_t page_bytes =
        uint64_t{shape.bank_pages} * shape.lobe_width *
        shape.lobe_width;
    std::vector<uint8_t> pages(page_bytes);
    for (uint64_t i = 0; i < pages.size(); ++i) {
        pages[i] = static_cast<uint8_t>(i);
    }
    rc::RCStage3CoupledBankRootExecution execution;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledBankRootManifest(
            statement, shape, pages, execution.manifest, &why),
        why);
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    BOOST_REQUIRE(ha::BuildShaManifestBoundaryInstances(
        execution.manifest.sha256d, boundaries, &why));
    BOOST_REQUIRE(rc::BuildRCStage3CoupledBoundaryPortPin(
        rc::RCStage3RelationEndpoint::CoupledBankRoot,
        hs::BoundaryPort::External, statement, shape,
        execution.manifest.sha256d.commitment, boundaries,
        execution.bank_bytes, &why));
    BOOST_REQUIRE(rc::BuildRCStage3CoupledBoundaryPortPin(
        rc::RCStage3RelationEndpoint::CoupledBankRoot,
        hs::BoundaryPort::Final, statement, shape,
        execution.manifest.sha256d.commitment, boundaries,
        execution.bank_digest, &why));
    execution.hash_proofs.endpoint =
        rc::RCStage3RelationEndpoint::CoupledBankRoot;
    execution.hash_proofs.statement_commitment =
        execution.manifest.statement_commitment;
    execution.hash_proofs.manifest_commitment =
        execution.manifest.sha256d.commitment;
    BOOST_CHECK(!rc::VerifyRCStage3CoupledBankRootExecution(
        statement, shape, execution, &why));

    auto wrong_shape = shape;
    ++wrong_shape.bank_pages;
    BOOST_CHECK(!rc::VerifyRCStage3CoupledBankRootExecution(
        statement, wrong_shape, execution, &why));

    auto wrong_pages = pages;
    wrong_pages.pop_back();
    rc::RCStage3CoupledBankRootManifest rejected;
    BOOST_CHECK(!rc::BuildRCStage3CoupledBankRootManifest(
        statement, shape, wrong_pages, rejected, &why));
}

BOOST_AUTO_TEST_CASE(bank_root_honest_product_executes_all_sha_children)
{
    if (std::getenv(
            "BTX_RUN_STAGE3_COUPLED_BANK_ROOT_PROVE") == nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_COUPLED_BANK_ROOT_PROVE=1 for the "
            "complete bounded bank-root SHA product round trip");
        return;
    }
    const auto statement = Statement();
    const auto shape = ToyShape();
    const uint64_t page_bytes =
        uint64_t{shape.bank_pages} * shape.lobe_width *
        shape.lobe_width;
    std::vector<uint8_t> pages(page_bytes);
    for (uint64_t i = 0; i < pages.size(); ++i) {
        pages[i] = static_cast<uint8_t>(17 * i + 3);
    }
    rc::RCStage3CoupledBankRootExecution execution;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3CoupledBankRootExecution(
            statement, shape, pages, execution, &why),
        why);
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3CoupledBankRootExecution(
            statement, shape, execution, &why),
        why);
    auto changed = execution;
    changed.bank_bytes.value_root.begin()[0] ^= 1U;
    BOOST_CHECK(!rc::VerifyRCStage3CoupledBankRootExecution(
        statement, shape, changed, &why));
}

BOOST_AUTO_TEST_CASE(barrier_and_digest_ports_are_typed_and_fail_closed)
{
    const auto shape = ToyShape();
    const uint64_t state_bytes =
        uint64_t{shape.lobes} * shape.rows_per_lobe *
        shape.lobe_width;
    std::vector<uint8_t> state(state_bytes, 7);
    ha::CoupledBarrierManifest barrier;
    std::string why;
    BOOST_REQUIRE(ha::BuildCoupledBarrierManifest(
        shape.transcript_version, shape.barriers, 0,
        state, barrier, &why));
    auto statement = Statement();
    rc::RCStage3CoupledBarrierEndpointExecution barrier_execution;
    barrier_execution.manifest = barrier;
    barrier_execution.hash_proofs.endpoint =
        rc::RCStage3RelationEndpoint::CoupledBarrierHash;
    barrier_execution.hash_proofs.statement_commitment =
        rc::CommitRCStage3CoupledStatement(statement.public_inputs);
    barrier_execution.hash_proofs.manifest_commitment =
        barrier.direct.commitment;
    std::vector<ha::FixedProgramBoundaryInstance> barrier_boundaries;
    BOOST_REQUIRE(ha::BuildDirectSha256dManifestBoundaryInstances(
        barrier.direct, barrier_boundaries, &why));
    BOOST_REQUIRE(rc::BuildRCStage3CoupledBoundaryPortPin(
        rc::RCStage3RelationEndpoint::CoupledBarrierInput,
        hs::BoundaryPort::External, statement, shape,
        barrier.direct.commitment, barrier_boundaries,
        barrier_execution.input, &why));
    BOOST_REQUIRE(rc::BuildRCStage3CoupledBoundaryPortPin(
        rc::RCStage3RelationEndpoint::CoupledBarrierOutput,
        hs::BoundaryPort::Final, statement, shape,
        barrier.direct.commitment, barrier_boundaries,
        barrier_execution.output, &why));
    BOOST_CHECK(!rc::VerifyRCStage3CoupledBarrierEndpointExecution(
        statement, shape, barrier_execution, &why));

    std::vector<uint256> barrier_roots(
        shape.barriers, H(0x55));
    ha::CoupledDigestManifest digest;
    BOOST_REQUIRE(ha::BuildCoupledDigestManifest(
        shape.transcript_version, shape.barriers, H(0x66),
        barrier_roots, digest, &why));
    statement = Statement(digest.direct.digest);
    rc::RCStage3CoupledDigestEndpointExecution digest_execution;
    digest_execution.manifest = digest;
    digest_execution.hash_proofs.endpoint =
        rc::RCStage3RelationEndpoint::CoupledDigestHash;
    digest_execution.hash_proofs.statement_commitment =
        rc::CommitRCStage3CoupledStatement(statement.public_inputs);
    digest_execution.hash_proofs.manifest_commitment =
        digest.direct.commitment;
    std::vector<ha::FixedProgramBoundaryInstance> digest_boundaries;
    BOOST_REQUIRE(ha::BuildDirectSha256dManifestBoundaryInstances(
        digest.direct, digest_boundaries, &why));
    BOOST_REQUIRE(rc::BuildRCStage3CoupledBoundaryPortPin(
        rc::RCStage3RelationEndpoint::CoupledDigestBankAndBarriers,
        hs::BoundaryPort::External, statement, shape,
        digest.direct.commitment, digest_boundaries,
        digest_execution.bank_and_barriers, &why));
    BOOST_REQUIRE(rc::BuildRCStage3CoupledBoundaryPortPin(
        rc::RCStage3RelationEndpoint::CoupledDigestValue,
        hs::BoundaryPort::Final, statement, shape,
        digest.direct.commitment, digest_boundaries,
        digest_execution.digest_value, &why));
    BOOST_CHECK(!rc::VerifyRCStage3CoupledDigestEndpointExecution(
        statement, shape, digest_execution, true, &why));
}

BOOST_AUTO_TEST_CASE(executable_range_and_digest_round_trips)
{
    if (std::getenv(
            "BTX_RUN_STAGE3_COUPLED_MISSING_RELATIONS_PROVE") ==
        nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_COUPLED_MISSING_RELATIONS_PROVE=1 "
            "for coupled range and digest quotient round trips");
        return;
    }
    const auto shape = ToyShape();
    auto statement = Statement();
    std::string why;

    rc::RCStage3CoupledSignedRangeExecution range;
    BOOST_REQUIRE(rc::BuildRCStage3CoupledSignedRangeManifest(
        statement, shape, range.manifest, &why));
    range.shards.resize(range.manifest.shard_count);
    for (uint32_t i = 0; i < range.shards.size(); ++i) {
        auto& shard = range.shards[i];
        BOOST_REQUIRE(rc::MakeRCStage3CoupledSignedRangePin(
            range.manifest, i, shard.pin, &why));
        std::vector<int64_t> values(shard.pin.logical_rows);
        for (uint32_t row = 0; row < values.size(); ++row) {
            values[row] = row % 2 == 0
                ? static_cast<int64_t>(row % (shard.pin.max_abs + 1))
                : -static_cast<int64_t>(
                    row % (shard.pin.max_abs + 1));
        }
        std::vector<std::vector<gf::Fp3>> columns;
        BOOST_REQUIRE(rc::BuildRCStage3SignedRangeColumns(
            shard.pin, values, columns, &why));
        for (uint32_t column = 0; column < columns.size(); ++column) {
            shard.pin.column_roots[column].root =
                aq::AirCommittedValuesRoot<gf::Fp3>(
                    columns[column], shard.pin.n_rows);
        }
        aq::AirConstraintSystem<gf::Fp3> cs;
        BOOST_REQUIRE(
            rc::ResolveRCStage3SignedRangeKernelConstraintSystem(
                shard.pin, cs, &why));
        const auto proved = aq::AirQuotientProve<gf::Fp3>(
            cs, columns,
            rc::ComputeRCStage3SignedRangeSeed(shard.pin));
        BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
        shard.proof = proved.proof;
    }
    range.value_roots_commitment =
        rc::CommitRCStage3CoupledSignedRangeValueRoots(
            range.manifest, range.shards);
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3CoupledSignedRangeExecution(
            statement, shape, range, &why),
        why);

    std::vector<uint256> barrier_roots(
        shape.barriers, H(0x77));
    ha::CoupledDigestManifest digest;
    BOOST_REQUIRE(ha::BuildCoupledDigestManifest(
        shape.transcript_version, shape.barriers, H(0x88),
        barrier_roots, digest, &why));
    statement = Statement(digest.direct.digest);
    rc::RCStage3CoupledDigestEndpointExecution execution;
    execution.manifest = digest;
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    BOOST_REQUIRE(ha::BuildDirectSha256dManifestBoundaryInstances(
        digest.direct, boundaries, &why));
    BOOST_REQUIRE(ProveHashBundle(
        rc::RCStage3RelationEndpoint::CoupledDigestHash,
        rc::CommitRCStage3CoupledStatement(statement.public_inputs),
        digest.direct.commitment, boundaries,
        execution.hash_proofs, &why));
    BOOST_REQUIRE(rc::BuildRCStage3CoupledBoundaryPortPin(
        rc::RCStage3RelationEndpoint::CoupledDigestBankAndBarriers,
        hs::BoundaryPort::External, statement, shape,
        digest.direct.commitment, boundaries,
        execution.bank_and_barriers, &why));
    BOOST_REQUIRE(rc::BuildRCStage3CoupledBoundaryPortPin(
        rc::RCStage3RelationEndpoint::CoupledDigestValue,
        hs::BoundaryPort::Final, statement, shape,
        digest.direct.commitment, boundaries,
        execution.digest_value, &why));
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3CoupledDigestEndpointExecution(
            statement, shape, execution, true, &why),
        why);

    auto changed_statement = statement;
    changed_statement.public_inputs.coupled_digest = H(0x99);
    BOOST_CHECK(!rc::VerifyRCStage3CoupledDigestEndpointExecution(
        changed_statement, shape, execution, true, &why));
}

BOOST_AUTO_TEST_SUITE_END()
