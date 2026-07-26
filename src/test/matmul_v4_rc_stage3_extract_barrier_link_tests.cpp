// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_extract_barrier_link.h>

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

rc::RCStage3SuccinctProof Statement()
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
    statement.public_inputs.coupled_digest = H(0x44);
    return statement;
}

bool ResolveExtractShape(
    const rc::RCStage3CoupledAirRequest& request,
    uint32_t& relation_rows,
    uint32_t& n_coeffs,
    std::string* why)
{
    rc::RCStage3CoupledSemanticEndpointSpec spec;
    rc::RCStage3CoupledAirEntry entry;
    aq::AirConstraintSystem<gf::Fp3> combined;
    if (!rc::ResolveRCStage3CoupledSemanticEndpointSpec(
            rc::RCStage3RelationEndpoint::CoupledExtractOutput,
            request, spec, why) ||
        !rc::ResolveRCStage3CoupledAir(request, entry, why) ||
        !rc::BuildRCStage3CoupledSemanticConstraintSystem(
            spec, entry.constraints, combined, nullptr, why)) {
        return false;
    }
    relation_rows = combined.n_rows;
    n_coeffs = rc::FriNextPow2(
        std::max(combined.n_rows, combined.QuotientLen()));
    return true;
}

uint256 OutputRoot(
    const std::vector<uint8_t>& bytes,
    uint64_t begin,
    uint32_t relation_rows,
    uint32_t n_coeffs)
{
    std::vector<gf::Fp3> values(
        relation_rows, gf::Fp3::Zero());
    for (uint32_t i = 0; i < rc::kRCMxBlockLen; ++i) {
        const uint8_t byte = bytes[begin + i];
        const int64_t signed_value = byte < 128
            ? static_cast<int64_t>(byte)
            : static_cast<int64_t>(byte) - 256;
        values[i] =
            gf::Fp3::FromFp(gf::FromSigned(signed_value));
    }
    return aq::AirCommittedValuesRoot<gf::Fp3>(
        values, n_coeffs);
}

struct Fixture {
    rc::RCStage3SuccinctProof statement{Statement()};
    rc::RCStage3CoupledShape shape{ToyShape()};
    rc::RCStage3ExtractBarrierLinkExecution execution;
};

bool BuildFixture(Fixture& fixture, std::string* why)
{
    const uint256 statement_commitment =
        rc::CommitRCStage3CoupledStatement(
            fixture.statement.public_inputs);
    const auto extract_counts =
        rc::ExpectedRCStage3CoupledRelationCounts(
            rc::RCStage3RelationRole::CoupledExtract,
            fixture.shape, why);
    if (!extract_counts.has_value()) return false;
    const uint64_t state_bytes_per_barrier =
        uint64_t{fixture.shape.lobes} *
        fixture.shape.rows_per_lobe *
        fixture.shape.lobe_width;

    fixture.execution.barriers.resize(fixture.shape.barriers);
    for (uint32_t barrier_index = 0;
         barrier_index < fixture.shape.barriers; ++barrier_index) {
        auto& barrier = fixture.execution.barriers[barrier_index];
        std::vector<uint8_t> state(state_bytes_per_barrier);
        for (uint64_t i = 0; i < state.size(); ++i) {
            state[i] = static_cast<uint8_t>(
                barrier_index * 53U + i * 17U);
        }
        if (!ha::BuildCoupledBarrierManifest(
                fixture.shape.transcript_version,
                fixture.shape.barriers, barrier_index,
                state, barrier.manifest, why)) {
            return false;
        }
        std::vector<ha::FixedProgramBoundaryInstance> boundaries;
        if (!ha::BuildDirectSha256dManifestBoundaryInstances(
                barrier.manifest.direct, boundaries, why) ||
            !rc::BuildRCStage3CoupledBoundaryPortPin(
                rc::RCStage3RelationEndpoint::CoupledBarrierInput,
                hs::BoundaryPort::External, fixture.statement,
                fixture.shape, barrier.manifest.direct.commitment,
                boundaries, barrier.input, why) ||
            !rc::BuildRCStage3CoupledBoundaryPortPin(
                rc::RCStage3RelationEndpoint::CoupledBarrierOutput,
                hs::BoundaryPort::Final, fixture.statement,
                fixture.shape, barrier.manifest.direct.commitment,
                boundaries, barrier.output, why)) {
            return false;
        }
        barrier.hash_proofs.endpoint =
            rc::RCStage3RelationEndpoint::CoupledBarrierHash;
        barrier.hash_proofs.statement_commitment =
            statement_commitment;
        barrier.hash_proofs.manifest_commitment =
            barrier.manifest.direct.commitment;
    }

    auto& bundle = fixture.execution.extract_outputs;
    bundle.version = rc::kRCStage3CoupledSemanticVersion;
    bundle.endpoint =
        rc::RCStage3RelationEndpoint::CoupledExtractOutput;
    bundle.statement_commitment = statement_commitment;
    bundle.total_instances = extract_counts->primary;
    bundle.shards.resize(bundle.total_instances);
    for (uint64_t instance = 0;
         instance < bundle.total_instances; ++instance) {
        auto& shard = bundle.shards[instance];
        shard.instance_begin = instance;
        auto& pin = shard.pin;
        pin.version = rc::kRCStage3CoupledSemanticVersion;
        pin.endpoint = bundle.endpoint;
        pin.request.role =
            rc::RCStage3RelationRole::CoupledExtract;
        pin.request.shape = fixture.shape;
        pin.request.gamma = gf::Fp3{3, 4, 5};
        pin.request.alpha = gf::Fp3{7, 8, 9};
        pin.request.extract_scale_e =
            static_cast<uint8_t>(instance % 4);
        pin.statement_commitment = statement_commitment;
        pin.shape_commitment =
            rc::CommitRCStage3CoupledShape(fixture.shape);
        pin.instance_begin = instance;
        pin.instance_span = 1;
        pin.instance_count = bundle.total_instances;

        rc::RCStage3CoupledSemanticEndpointSpec spec;
        if (!rc::ResolveRCStage3CoupledSemanticEndpointSpec(
                pin.endpoint, pin.request, spec, why)) {
            return false;
        }
        pin.schedule_commitment =
            rc::ComputeRCStage3CoupledSemanticShardSchedule(
                spec.schedule_commitment, instance, 1,
                bundle.total_instances);
        uint32_t relation_rows{0};
        uint32_t n_coeffs{0};
        if (!ResolveExtractShape(
                pin.request, relation_rows, n_coeffs, why)) {
            return false;
        }
        const uint64_t global_begin =
            instance * rc::kRCMxBlockLen;
        const uint64_t barrier_index =
            global_begin / state_bytes_per_barrier;
        const uint64_t local_begin =
            global_begin % state_bytes_per_barrier;
        pin.value_column_roots = {
            H(static_cast<unsigned char>(0x70 + instance)),
            OutputRoot(
                fixture.execution.barriers[barrier_index]
                    .manifest.state_bytes,
                local_begin, relation_rows, n_coeffs)};
        pin.semantic_memory_root =
            rc::ComputeRCStage3CoupledSemanticMemoryRoot(
                pin.endpoint, pin.request.role,
                pin.instance_count, pin.shape_commitment,
                pin.schedule_commitment,
                pin.value_column_roots);
        shard.proof.batch.n_coeffs = n_coeffs;
    }
    bundle.bundle_commitment =
        rc::ComputeRCStage3CoupledSemanticFlatBundleCommitment(
            bundle);
    if (bundle.bundle_commitment.IsNull()) return false;
    return rc::BuildRCStage3ExtractBarrierLinkPin(
        fixture.statement, fixture.shape, bundle,
        fixture.execution.barriers, fixture.execution.pin, why);
}

void RefreshBundleCommitment(
    rc::RCStage3CoupledSemanticFlatBundle& bundle)
{
    bundle.bundle_commitment =
        rc::ComputeRCStage3CoupledSemanticFlatBundleCommitment(
            bundle);
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_extract_barrier_link_tests)

BOOST_AUTO_TEST_CASE(
    exact_product_pin_covers_all_signed_extract_output_bytes)
{
    Fixture fixture;
    std::string why;
    BOOST_REQUIRE_MESSAGE(BuildFixture(fixture, &why), why);
    const auto& pin = fixture.execution.pin;
    BOOST_CHECK_EQUAL(pin.extract_instances, 16U);
    BOOST_CHECK_EQUAL(pin.barriers, 4U);
    BOOST_CHECK_EQUAL(pin.state_bytes_per_barrier, 128U);
    BOOST_CHECK_EQUAL(pin.total_state_bytes, 512U);
    BOOST_CHECK_EQUAL(
        pin.extract_output_block_roots.size(), 16U);
    BOOST_CHECK_EQUAL(
        pin.barrier_manifest_commitments.size(), 4U);
    BOOST_CHECK_EQUAL(
        pin.barrier_input_memory_roots.size(), 4U);
    BOOST_CHECK(
        pin.link_commitment ==
        rc::CommitRCStage3ExtractBarrierLinkPin(pin));

    bool saw_negative = false;
    for (const auto& barrier : fixture.execution.barriers) {
        for (uint8_t byte : barrier.manifest.state_bytes) {
            saw_negative |= byte >= 128;
        }
    }
    BOOST_CHECK(saw_negative);
}

BOOST_AUTO_TEST_CASE(
    ordering_omission_and_root_substitution_fail_closed)
{
    Fixture fixture;
    std::string why;
    BOOST_REQUIRE_MESSAGE(BuildFixture(fixture, &why), why);

    auto swapped_barriers = fixture.execution.barriers;
    std::swap(swapped_barriers[0], swapped_barriers[1]);
    rc::RCStage3ExtractBarrierLinkPin rejected;
    BOOST_CHECK(!rc::BuildRCStage3ExtractBarrierLinkPin(
        fixture.statement, fixture.shape,
        fixture.execution.extract_outputs,
        swapped_barriers, rejected, &why));

    auto omitted_barrier = fixture.execution.barriers;
    omitted_barrier.pop_back();
    BOOST_CHECK(!rc::BuildRCStage3ExtractBarrierLinkPin(
        fixture.statement, fixture.shape,
        fixture.execution.extract_outputs,
        omitted_barrier, rejected, &why));

    auto swapped_extract =
        fixture.execution.extract_outputs;
    std::swap(swapped_extract.shards[0],
              swapped_extract.shards[1]);
    RefreshBundleCommitment(swapped_extract);
    BOOST_CHECK(!rc::BuildRCStage3ExtractBarrierLinkPin(
        fixture.statement, fixture.shape, swapped_extract,
        fixture.execution.barriers, rejected, &why));

    auto omitted_extract =
        fixture.execution.extract_outputs;
    omitted_extract.shards.pop_back();
    RefreshBundleCommitment(omitted_extract);
    BOOST_CHECK(!rc::BuildRCStage3ExtractBarrierLinkPin(
        fixture.statement, fixture.shape, omitted_extract,
        fixture.execution.barriers, rejected, &why));

    auto substituted =
        fixture.execution.extract_outputs;
    substituted.shards[3].pin.value_column_roots[1] =
        H(0xee);
    substituted.shards[3].pin.semantic_memory_root =
        rc::ComputeRCStage3CoupledSemanticMemoryRoot(
            substituted.shards[3].pin.endpoint,
            substituted.shards[3].pin.request.role,
            substituted.shards[3].pin.instance_count,
            substituted.shards[3].pin.shape_commitment,
            substituted.shards[3].pin.schedule_commitment,
            substituted.shards[3].pin.value_column_roots);
    RefreshBundleCommitment(substituted);
    BOOST_CHECK(!rc::BuildRCStage3ExtractBarrierLinkPin(
        fixture.statement, fixture.shape, substituted,
        fixture.execution.barriers, rejected, &why));
}

BOOST_AUTO_TEST_CASE(
    typed_state_and_public_pin_substitution_fail_closed)
{
    Fixture fixture;
    std::string why;
    BOOST_REQUIRE_MESSAGE(BuildFixture(fixture, &why), why);

    auto bad_state = fixture.execution.barriers;
    bad_state[2].manifest.state_bytes[7] ^= 0x80;
    rc::RCStage3ExtractBarrierLinkPin rejected;
    BOOST_CHECK(!rc::BuildRCStage3ExtractBarrierLinkPin(
        fixture.statement, fixture.shape,
        fixture.execution.extract_outputs,
        bad_state, rejected, &why));

    auto bad_input = fixture.execution.barriers;
    bad_input[1].input.semantic_memory_root = H(0xdd);
    BOOST_CHECK(!rc::BuildRCStage3ExtractBarrierLinkPin(
        fixture.statement, fixture.shape,
        fixture.execution.extract_outputs,
        bad_input, rejected, &why));

    auto bad_execution = fixture.execution;
    bad_execution.pin.link_commitment = H(0xcc);
    BOOST_CHECK(
        !rc::VerifyRCStage3ExtractBarrierLinkExecution(
            fixture.statement, fixture.shape,
            bad_execution, &why));
}

BOOST_AUTO_TEST_CASE(
    audit_is_explicit_about_flat_product_and_recursion_gap)
{
    const auto audit =
        rc::CurrentRCStage3ExtractBarrierLinkAudit(ToyShape());
    BOOST_CHECK_EQUAL(audit.expected_extract_instances, 16U);
    BOOST_CHECK_EQUAL(audit.expected_barriers, 4U);
    BOOST_CHECK_EQUAL(audit.expected_total_state_bytes, 512U);
    BOOST_CHECK(audit.consensus_shape_resolved);
    BOOST_CHECK(audit.exact_extract_order_enforced);
    BOOST_CHECK(audit.exact_barrier_order_enforced);
    BOOST_CHECK(audit.signed_byte_embedding_bound);
    BOOST_CHECK(audit.all_instance_proof_product_executable);
    BOOST_CHECK(!audit.recursive_child_consumption_complete);
    BOOST_CHECK(!audit.strict_semantic_complete);
    BOOST_CHECK(!audit.remaining.empty());
    BOOST_CHECK(
        rc::kRCStage3ExtractBarrierLinkProductExecutable);
    BOOST_CHECK(
        !rc::kRCStage3ExtractBarrierLinkRecursiveAuthorityReady);
}

BOOST_AUTO_TEST_SUITE_END()
