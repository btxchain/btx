// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_extract_barrier_link.h>

#include <hash.h>
#include <matmul/matmul_v4_rc_stage3_root_chain.h>

#include <algorithm>
#include <limits>

namespace matmul::v4::rc {
namespace {

namespace aq = air_quotient;
namespace gf = gkr_field;
namespace ha = stage3_hash_air;
namespace hs = stage3_hash_semantic;
using gf::Fp3;

constexpr char LINK_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_EXTRACT_BARRIER_LINK_V1";

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:extract_barrier_link:" + detail;
    }
    return false;
}

bool CheckedMul(uint64_t a, uint64_t b, uint64_t& out)
{
    if (a != 0 && b > std::numeric_limits<uint64_t>::max() / a) {
        return false;
    }
    out = a * b;
    return true;
}

bool IsCoupledStatement(const RCStage3SuccinctProof& statement)
{
    return statement.statement == RCStage3StatementKind::Coupled ||
           statement.statement == RCStage3StatementKind::Composed;
}

bool ResolveGeometry(
    const RCStage3CoupledShape& shape,
    uint64_t& extract_instances,
    uint64_t& state_bytes_per_barrier,
    uint64_t& total_state_bytes,
    std::string* why)
{
    const auto extract_counts = ExpectedRCStage3CoupledRelationCounts(
        RCStage3RelationRole::CoupledExtract, shape, why);
    const auto barrier_counts = ExpectedRCStage3CoupledRelationCounts(
        RCStage3RelationRole::CoupledBarrier, shape, why);
    uint64_t rows_and_lobes{0};
    if (!extract_counts.has_value() || !barrier_counts.has_value() ||
        !CheckedMul(
            shape.lobes, shape.rows_per_lobe, rows_and_lobes) ||
        !CheckedMul(
            rows_and_lobes, shape.lobe_width,
            state_bytes_per_barrier) ||
        !CheckedMul(
            shape.barriers, state_bytes_per_barrier,
            total_state_bytes) ||
        state_bytes_per_barrier == 0 ||
        (state_bytes_per_barrier % kRCMxBlockLen) != 0 ||
        extract_counts->primary !=
            total_state_bytes / kRCMxBlockLen ||
        extract_counts->secondary != total_state_bytes ||
        barrier_counts->primary != shape.barriers ||
        barrier_counts->secondary != total_state_bytes) {
        return Fail(why, "geometry");
    }
    extract_instances = extract_counts->primary;
    return true;
}

bool ResolveExtractCommitmentShape(
    const RCStage3CoupledSemanticPublicPin& pin,
    uint32_t& relation_rows,
    uint32_t& n_coeffs,
    std::string* why)
{
    RCStage3CoupledSemanticEndpointSpec spec;
    RCStage3CoupledAirEntry entry;
    aq::AirConstraintSystem<Fp3> combined;
    if (!ResolveRCStage3CoupledSemanticEndpointSpec(
            RCStage3RelationEndpoint::CoupledExtractOutput,
            pin.request, spec, why) ||
        !ResolveRCStage3CoupledAir(pin.request, entry, why) ||
        !entry.constraint_system_available ||
        !BuildRCStage3CoupledSemanticConstraintSystem(
            spec, entry.constraints, combined, nullptr, why)) {
        return Fail(why, "extract_constraint_system");
    }
    relation_rows = combined.n_rows;
    n_coeffs = FriNextPow2(
        std::max(combined.n_rows, combined.QuotientLen()));
    if (relation_rows < kRCMxBlockLen ||
        n_coeffs < relation_rows) {
        return Fail(why, "extract_commitment_shape");
    }
    return true;
}

bool ExpectedExtractOutputRoot(
    const std::vector<uint8_t>& state_bytes,
    uint64_t local_begin,
    uint32_t relation_rows,
    uint32_t n_coeffs,
    uint256& out,
    std::string* why)
{
    if (local_begin > state_bytes.size() ||
        state_bytes.size() - local_begin < kRCMxBlockLen ||
        relation_rows < kRCMxBlockLen) {
        return Fail(why, "state_block");
    }
    std::vector<Fp3> values(relation_rows, Fp3::Zero());
    for (uint32_t i = 0; i < kRCMxBlockLen; ++i) {
        const uint8_t byte = state_bytes[local_begin + i];
        const int64_t signed_value = byte < 128
            ? static_cast<int64_t>(byte)
            : static_cast<int64_t>(byte) - 256;
        values[i] = Fp3::FromFp(gf::FromSigned(signed_value));
    }
    out = aq::AirCommittedValuesRoot<Fp3>(values, n_coeffs);
    return !out.IsNull() || Fail(why, "null_expected_output_root");
}

bool PinRequestIsExact(
    const RCStage3CoupledSemanticPublicPin& pin,
    const RCStage3CoupledShape& shape,
    const uint256& statement_commitment,
    uint64_t instance,
    uint64_t extract_instances,
    uint32_t& relation_rows,
    uint32_t& n_coeffs,
    std::string* why)
{
    if (pin.endpoint !=
            RCStage3RelationEndpoint::CoupledExtractOutput ||
        pin.request.role != RCStage3RelationRole::CoupledExtract ||
        pin.request.shape != shape ||
        pin.statement_commitment != statement_commitment ||
        pin.shape_commitment != CommitRCStage3CoupledShape(shape) ||
        pin.instance_begin != instance ||
        pin.instance_span != 1 ||
        pin.instance_count != extract_instances ||
        pin.value_column_roots.size() != 2 ||
        pin.value_column_roots[0].IsNull() ||
        pin.value_column_roots[1].IsNull()) {
        return Fail(why, "extract_pin_identity");
    }
    RCStage3CoupledSemanticEndpointSpec spec;
    if (!ResolveRCStage3CoupledSemanticEndpointSpec(
            pin.endpoint, pin.request, spec, why) ||
        spec.required_instances != extract_instances ||
        pin.schedule_commitment !=
            ComputeRCStage3CoupledSemanticShardSchedule(
                spec.schedule_commitment, instance, 1,
                extract_instances) ||
        pin.semantic_memory_root !=
            ComputeRCStage3CoupledSemanticMemoryRoot(
                pin.endpoint, pin.request.role,
                pin.instance_count, pin.shape_commitment,
                pin.schedule_commitment,
                pin.value_column_roots) ||
        !ResolveExtractCommitmentShape(
            pin, relation_rows, n_coeffs, why)) {
        return Fail(why, "extract_pin_schedule");
    }
    return true;
}

bool ExpectedBarrierInputPin(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    uint32_t barrier_index,
    const RCStage3CoupledBarrierEndpointExecution& barrier,
    RCStage3CoupledBoundaryPortPin& out,
    std::string* why)
{
    if (!ValidateRCStage3CoupledBarrierManifestStructural(
            shape, barrier_index, barrier.manifest, why)) {
        return Fail(why, "barrier_manifest_" +
            std::to_string(barrier_index));
    }
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    if (!ha::BuildDirectSha256dManifestBoundaryInstances(
            barrier.manifest.direct, boundaries, why) ||
        !BuildRCStage3CoupledBoundaryPortPin(
            RCStage3RelationEndpoint::CoupledBarrierInput,
            hs::BoundaryPort::External, statement, shape,
            barrier.manifest.direct.commitment, boundaries,
            out, why)) {
        return Fail(why, "barrier_input_pin_" +
            std::to_string(barrier_index));
    }
    return true;
}

} // namespace

uint256 CommitRCStage3ExtractBarrierLinkPin(
    const RCStage3ExtractBarrierLinkPin& pin)
{
    if (pin.version != kRCStage3ExtractBarrierLinkVersion ||
        pin.statement_commitment.IsNull() ||
        pin.shape_commitment.IsNull() ||
        pin.extract_instances == 0 || pin.barriers == 0 ||
        pin.state_bytes_per_barrier == 0 ||
        pin.total_state_bytes == 0 ||
        pin.extract_relation_rows < kRCMxBlockLen ||
        pin.extract_n_coeffs < pin.extract_relation_rows ||
        pin.extract_bundle_commitment.IsNull() ||
        pin.barrier_manifest_commitments.size() != pin.barriers ||
        pin.barrier_input_memory_roots.size() != pin.barriers ||
        pin.extract_output_block_roots.size() !=
            pin.extract_instances) {
        return {};
    }
    HashWriter hash;
    hash << LINK_DOMAIN;
    hash << pin.version;
    hash << pin.statement_commitment;
    hash << pin.shape_commitment;
    hash << pin.extract_instances;
    hash << pin.barriers;
    hash << pin.state_bytes_per_barrier;
    hash << pin.total_state_bytes;
    hash << pin.extract_relation_rows;
    hash << pin.extract_n_coeffs;
    hash << pin.extract_bundle_commitment;
    hash << static_cast<uint64_t>(
        pin.barrier_manifest_commitments.size());
    for (const auto& root : pin.barrier_manifest_commitments) {
        if (root.IsNull()) return {};
        hash << root;
    }
    hash << static_cast<uint64_t>(
        pin.barrier_input_memory_roots.size());
    for (const auto& root : pin.barrier_input_memory_roots) {
        if (root.IsNull()) return {};
        hash << root;
    }
    hash << static_cast<uint64_t>(
        pin.extract_output_block_roots.size());
    for (const auto& root : pin.extract_output_block_roots) {
        if (root.IsNull()) return {};
        hash << root;
    }
    return hash.GetHash();
}

bool BuildRCStage3ExtractBarrierLinkPin(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledSemanticFlatBundle& extract_outputs,
    const std::vector<RCStage3CoupledBarrierEndpointExecution>& barriers,
    RCStage3ExtractBarrierLinkPin& out,
    std::string* why)
{
    out = {};
    uint64_t extract_instances{0};
    uint64_t state_bytes_per_barrier{0};
    uint64_t total_state_bytes{0};
    const uint256 statement_commitment =
        CommitRCStage3CoupledStatement(statement.public_inputs);
    const uint256 shape_commitment =
        CommitRCStage3CoupledShape(shape);
    if (!IsCoupledStatement(statement) ||
        statement_commitment.IsNull() ||
        shape_commitment.IsNull() ||
        !ResolveGeometry(
            shape, extract_instances, state_bytes_per_barrier,
            total_state_bytes, why) ||
        extract_outputs.version !=
            kRCStage3CoupledSemanticVersion ||
        extract_outputs.endpoint !=
            RCStage3RelationEndpoint::CoupledExtractOutput ||
        extract_outputs.statement_commitment != statement_commitment ||
        extract_outputs.total_instances != extract_instances ||
        extract_outputs.shards.size() != extract_instances ||
        extract_outputs.bundle_commitment !=
            ComputeRCStage3CoupledSemanticFlatBundleCommitment(
                extract_outputs) ||
        barriers.size() != shape.barriers) {
        return Fail(why, "product_shape");
    }

    out.version = kRCStage3ExtractBarrierLinkVersion;
    out.statement_commitment = statement_commitment;
    out.shape_commitment = shape_commitment;
    out.extract_instances = extract_instances;
    out.barriers = shape.barriers;
    out.state_bytes_per_barrier = state_bytes_per_barrier;
    out.total_state_bytes = total_state_bytes;
    out.extract_bundle_commitment =
        extract_outputs.bundle_commitment;
    out.barrier_manifest_commitments.reserve(shape.barriers);
    out.barrier_input_memory_roots.reserve(shape.barriers);
    out.extract_output_block_roots.reserve(extract_instances);

    for (uint32_t barrier_index = 0;
         barrier_index < shape.barriers; ++barrier_index) {
        const auto& barrier = barriers[barrier_index];
        if (barrier.manifest.state_bytes.size() !=
                state_bytes_per_barrier) {
            return Fail(
                why, "barrier_state_size_" +
                    std::to_string(barrier_index));
        }
        RCStage3CoupledBoundaryPortPin expected_input;
        if (!ExpectedBarrierInputPin(
                statement, shape, barrier_index, barrier,
                expected_input, why) ||
            barrier.input != expected_input) {
            return Fail(
                why, "barrier_input_substitution_" +
                    std::to_string(barrier_index));
        }
        out.barrier_manifest_commitments.push_back(
            barrier.manifest.commitment);
        out.barrier_input_memory_roots.push_back(
            expected_input.semantic_memory_root);
    }

    uint32_t canonical_relation_rows{0};
    uint32_t canonical_n_coeffs{0};
    for (uint64_t instance = 0;
         instance < extract_instances; ++instance) {
        const auto& shard = extract_outputs.shards[instance];
        uint32_t relation_rows{0};
        uint32_t n_coeffs{0};
        if (shard.instance_begin != instance ||
            !PinRequestIsExact(
                shard.pin, shape, statement_commitment,
                instance, extract_instances, relation_rows,
                n_coeffs, why) ||
            shard.proof.batch.n_coeffs != n_coeffs) {
            return Fail(
                why, "extract_order_or_shape_" +
                    std::to_string(instance));
        }
        if (instance == 0) {
            canonical_relation_rows = relation_rows;
            canonical_n_coeffs = n_coeffs;
        } else if (
            relation_rows != canonical_relation_rows ||
            n_coeffs != canonical_n_coeffs) {
            return Fail(why, "nonuniform_extract_commitment_shape");
        }
        const uint64_t global_begin =
            instance * kRCMxBlockLen;
        const uint64_t barrier_index =
            global_begin / state_bytes_per_barrier;
        const uint64_t local_begin =
            global_begin % state_bytes_per_barrier;
        if (barrier_index >= barriers.size()) {
            return Fail(why, "extract_address");
        }
        uint256 expected_root;
        if (!ExpectedExtractOutputRoot(
                barriers[barrier_index].manifest.state_bytes,
                local_begin, relation_rows, n_coeffs,
                expected_root, why) ||
            shard.pin.value_column_roots[1] != expected_root) {
            return Fail(
                why, "extract_output_root_" +
                    std::to_string(instance));
        }
        out.extract_output_block_roots.push_back(expected_root);
    }
    out.extract_relation_rows = canonical_relation_rows;
    out.extract_n_coeffs = canonical_n_coeffs;
    out.link_commitment =
        CommitRCStage3ExtractBarrierLinkPin(out);
    if (out.link_commitment.IsNull()) {
        return Fail(why, "null_link_commitment");
    }
    if (why != nullptr) {
        *why =
            "stage3:extract_barrier_link:exact_ordered_"
            "signed_byte_root_product_ok";
    }
    return true;
}

bool VerifyRCStage3ExtractBarrierLinkExecution(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3ExtractBarrierLinkExecution& execution,
    std::string* why)
{
    RCStage3ExtractBarrierLinkPin expected;
    if (!BuildRCStage3ExtractBarrierLinkPin(
            statement, shape, execution.extract_outputs,
            execution.barriers, expected, why) ||
        execution.pin != expected) {
        return Fail(why, "public_pin");
    }
    if (!VerifyRCStage3CoupledSemanticFlatBundle(
            statement, execution.extract_outputs, why)) {
        return Fail(why, "extract_proof_product");
    }
    for (uint32_t i = 0; i < execution.barriers.size(); ++i) {
        if (!VerifyRCStage3CoupledBarrierEndpointExecution(
                statement, shape, execution.barriers[i], why)) {
            return Fail(
                why, "barrier_proof_" + std::to_string(i));
        }
    }
    if (why != nullptr) {
        *why =
            "stage3:extract_barrier_link:all_extract_and_barrier_"
            "proofs_executed_exact_endpoint_47_producer_complete";
    }
    return true;
}

RCStage3ExtractBarrierLinkAudit
CurrentRCStage3ExtractBarrierLinkAudit(
    const RCStage3CoupledShape& shape)
{
    RCStage3ExtractBarrierLinkAudit out;
    uint64_t state_bytes_per_barrier{0};
    std::string why;
    if (!ResolveGeometry(
            shape, out.expected_extract_instances,
            state_bytes_per_barrier,
            out.expected_total_state_bytes, &why)) {
        out.remaining = why;
        return out;
    }
    out.expected_barriers = shape.barriers;
    out.consensus_shape_resolved = true;
    out.exact_extract_order_enforced = true;
    out.exact_barrier_order_enforced = true;
    out.signed_byte_embedding_bound = true;
    out.all_instance_proof_product_executable =
        kRCStage3ExtractBarrierLinkProductExecutable;
    out.recursive_child_consumption_complete = false;
    out.strict_semantic_complete =
        out.consensus_shape_resolved &&
        out.exact_extract_order_enforced &&
        out.exact_barrier_order_enforced &&
        out.signed_byte_embedding_bound &&
        out.all_instance_proof_product_executable &&
        out.recursive_child_consumption_complete;
    out.remaining =
        "the exact flat proof product closes the endpoint-47 producer "
        "edge; its roots are not yet consumed by the normalized recursive "
        "unified-root child";
    return out;
}

} // namespace matmul::v4::rc
