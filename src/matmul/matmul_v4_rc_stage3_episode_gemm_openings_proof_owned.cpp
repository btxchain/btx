// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_episode_gemm_openings_proof_owned.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_gkr.h>
#include <matmul/matmul_v4_rc_stage3_role_bytecode.h>

#include <hash.h>

#include <algorithm>
#include <limits>

namespace matmul::v4::rc::episode_gemm_openings_proof_owned {

namespace {

constexpr char STATEMENT_DOMAIN_V1[] =
    "BTX_RC_STAGE3_EPISODE_GEMM_OPENINGS_PROOF_OWNED_STATEMENT_V1";
constexpr char PROOF_SET_DOMAIN_V1[] =
    "BTX_RC_STAGE3_EPISODE_GEMM_OPENINGS_PROOF_SET_V1";

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:episode_gemm_openings_proof_owned:" +
            detail;
    }
    return false;
}

uint32_t NextPowerOfTwo(uint32_t value)
{
    uint32_t out = 2;
    while (out < value) {
        if (out >
            std::numeric_limits<uint32_t>::max() / 2U) {
            return 0;
        }
        out *= 2U;
    }
    return out;
}

bool CheckedAdd(uint64_t left, uint64_t right, uint64_t& out)
{
    if (left >
        std::numeric_limits<uint64_t>::max() - right) {
        return false;
    }
    out = left + right;
    return true;
}

bool CheckedMul(uint64_t left, uint64_t right, uint64_t& out)
{
    if (left != 0 &&
        right >
            std::numeric_limits<uint64_t>::max() / left) {
        return false;
    }
    out = left * right;
    return true;
}

uint64_t RefCells(
    const RCGkrLayout& layout,
    const RCGkrOperandRef& ref)
{
    if (ref.n_chunks == 0 ||
        ref.first_column > layout.columns.size() ||
        ref.n_chunks >
            layout.columns.size() - ref.first_column) {
        return 0;
    }
    uint64_t out = 0;
    for (uint32_t index = 0;
         index < ref.n_chunks; ++index) {
        uint64_t next = 0;
        if (!CheckedAdd(
                out,
                layout.columns[
                    ref.first_column + index].len,
                next)) {
            return 0;
        }
        out = next;
    }
    return out;
}

bool CanonicalFamily(
    uint32_t& family_index,
    constraint_bytecode::ProgramTableCommitmentPair& program,
    std::string* why)
{
    const auto site_manifest =
        sites::BuildProductionProofSiteManifest(
            sites::SelectedProductionProofSitePolicy());
    std::string local_why;
    if (!sites::ValidateProductionProofSiteManifest(
            site_manifest, &local_why)) {
        return Fail(why, "site_manifest:" + local_why);
    }
    const auto sources =
        topo::BuildProductionFamilyProgramSourcesV1(
            site_manifest);
    if (!topo::ValidateProductionFamilyProgramSourcesV1(
            site_manifest, sources, &local_why)) {
        return Fail(why, "family_sources:" + local_why);
    }
    const auto it = std::find_if(
        sources.begin(), sources.end(),
        [](const auto& source) {
            return source.kind ==
                sites::ProductionProofSiteKind::
                    EpisodeGemmOpenings;
        });
    if (it == sources.end() ||
        it->role != RCStage3RelationRole::EpisodeGemm ||
        it->semantic_relation_complete ||
        !it->semantic_endpoints.empty()) {
        return Fail(why, "canonical_family_identity");
    }
    constraint_bytecode::ProgramTable expected;
    if (!BuildRCStage3EpisodeSemanticMemoryProgramTable(
            RCStage3RelationRole::EpisodeGemm,
            expected, &local_why) ||
        !(it->program == expected)) {
        return Fail(why, "canonical_family_program");
    }
    family_index = it->family_index;
    program =
        constraint_bytecode::
            CommitProgramTableForExternalAndRecursiveUse(
                it->program);
    if (program.external_sha256d.IsNull() ||
        !program.same_canonical_serialization) {
        return Fail(why, "canonical_program_commitment");
    }
    return true;
}

void HashAlgDigest(
    HashWriter& hash,
    const alg_hash::Digest& digest)
{
    for (const auto& lane : digest) {
        hash << gf::Canonical(lane);
    }
}

bool CanonicalStatementShape(
    const StatementV1& statement,
    std::string* why)
{
    if (statement.version != kVersionV1 ||
        statement.episode_statement_commitment.IsNull() ||
        statement.statement_commitment.IsNull()) {
        return Fail(why, "statement_format");
    }
    uint32_t family_index = UINT32_MAX;
    constraint_bytecode::ProgramTableCommitmentPair program;
    if (!CanonicalFamily(
            family_index, program, why) ||
        statement.family_index != family_index ||
        !(statement.program == program)) {
        return Fail(why, "statement_family");
    }
    const auto& order = CanonicalEndpointOrderV1();
    for (uint32_t index = 0;
         index < kEndpointCountV1; ++index) {
        const auto& endpoint = statement.endpoints[index];
        if (endpoint.endpoint != order[index] ||
            endpoint.total_instance_count == 0 ||
            endpoint.address_stride == 0) {
            return Fail(why, "statement_endpoint_shape");
        }
        const uint64_t expected_shards =
            (endpoint.total_instance_count +
             kRCStage3EpisodeSemanticMaxRows - 1U) /
            kRCStage3EpisodeSemanticMaxRows;
        if (endpoint.canonical_value_roots.size() !=
                expected_shards ||
            std::any_of(
                endpoint.canonical_value_roots.begin(),
                endpoint.canonical_value_roots.end(),
                [](const uint256& root) {
                    return root.IsNull();
                })) {
            return Fail(why, "statement_endpoint_roots");
        }
        const uint64_t last =
            endpoint.total_instance_count - 1U;
        if (last >
            (std::numeric_limits<uint64_t>::max() -
             endpoint.address_begin) /
                endpoint.address_stride) {
            return Fail(why, "statement_address_overflow");
        }
    }
    const ProductionShapeV1 production =
        BuildProductionShapeV1();
    const bool production_counts =
        production.exact_manifest_total &&
        std::equal(
            production.endpoint_instances.begin(),
            production.endpoint_instances.end(),
            statement.endpoints.begin(),
            [](uint64_t count,
               const EndpointStatementV1& endpoint) {
                return
                    endpoint.total_instance_count == count &&
                    endpoint.address_begin == 0 &&
                    endpoint.address_stride == 1;
            });
    if (statement.production_manifest_counts_bound !=
            production_counts ||
        (production_counts &&
         statement.production_site_manifest_commitment !=
             production.site_manifest_commitment) ||
        (!production_counts &&
         !statement.production_site_manifest_commitment.IsNull())) {
        return Fail(why, "statement_production_shape");
    }
    if (statement.statement_commitment !=
        ComputeStatementCommitmentV1(statement)) {
        return Fail(why, "statement_commitment");
    }
    return true;
}

} // namespace

const std::array<
    RCStage3RelationEndpoint, kEndpointCountV1>&
CanonicalEndpointOrderV1()
{
    static constexpr std::array<
        RCStage3RelationEndpoint, kEndpointCountV1> order{{
        RCStage3RelationEndpoint::EpisodeGemmOperandA,
        RCStage3RelationEndpoint::EpisodeGemmOperandB,
        RCStage3RelationEndpoint::EpisodeGemmOutputY,
    }};
    return order;
}

ProductionShapeV1 BuildProductionShapeV1()
{
    ProductionShapeV1 out;
    const auto site_manifest =
        sites::BuildProductionProofSiteManifest(
            sites::SelectedProductionProofSitePolicy());
    if (!sites::ValidateProductionProofSiteManifest(
            site_manifest, nullptr)) {
        return out;
    }
    const auto site = std::find_if(
        site_manifest.entries.begin(),
        site_manifest.entries.end(),
        [](const auto& entry) {
            return entry.kind ==
                sites::ProductionProofSiteKind::
                    EpisodeGemmOpenings;
        });
    if (site == site_manifest.entries.end()) {
        return out;
    }
    const RCEpisodeParams episode =
        MakeDatacenterRCEpisodeParams();
    const RCGkrLayout layout = RCGkrTraceLayout(episode);
    if (layout.layers.empty()) return out;
    for (const auto& layer : layout.layers) {
        const uint64_t a = RefCells(layout, layer.a);
        const uint64_t b = RefCells(layout, layer.b);
        uint64_t y = 0;
        uint64_t next = 0;
        if (a == 0 || b == 0 ||
            !CheckedMul(layer.m, layer.n, y) ||
            !CheckedAdd(
                out.endpoint_instances[0], a, next)) {
            return {};
        }
        out.endpoint_instances[0] = next;
        if (!CheckedAdd(
                out.endpoint_instances[1], b, next)) {
            return {};
        }
        out.endpoint_instances[1] = next;
        if (!CheckedAdd(
                out.endpoint_instances[2], y, next)) {
            return {};
        }
        out.endpoint_instances[2] = next;
    }
    for (const uint64_t count : out.endpoint_instances) {
        uint64_t next = 0;
        if (count == 0 ||
            !CheckedAdd(out.total_instances, count, next)) {
            return {};
        }
        out.total_instances = next;
    }
    out.site_manifest_commitment =
        site_manifest.commitment;
    out.exact_manifest_total =
        !out.site_manifest_commitment.IsNull() &&
        out.total_instances == site->logical_units;
    return out;
}

bool ComputeCanonicalShardRootsV1(
    const std::vector<gf::Fp3>& values,
    std::vector<uint256>& out,
    std::string* why)
{
    out.clear();
    if (values.empty() ||
        values.size() >
            uint64_t{kRCStage3EpisodeSemanticMaxRows} *
                kRCStage3EpisodeSemanticMaxRows) {
        return Fail(why, "root_value_count");
    }
    uint64_t begin = 0;
    while (begin < values.size()) {
        const uint32_t logical_rows =
            static_cast<uint32_t>(
                std::min<uint64_t>(
                    kRCStage3EpisodeSemanticMaxRows,
                    values.size() - begin));
        std::vector<gf::Fp3> shard(
            values.begin() + begin,
            values.begin() + begin + logical_rows);
        const auto root =
            ComputeRCStage3EpisodeSemanticValueRoot(
                shard, logical_rows,
                NextPowerOfTwo(logical_rows), why);
        if (!root.has_value() || root->IsNull()) {
            out.clear();
            return Fail(why, "root_compute");
        }
        out.push_back(*root);
        begin += logical_rows;
    }
    return true;
}

bool BuildStatementV1(
    const uint256& episode_statement_commitment,
    const std::array<
        EndpointStatementV1, kEndpointCountV1>& endpoints,
    StatementV1& out,
    std::string* why)
{
    out = {};
    if (episode_statement_commitment.IsNull()) {
        return Fail(why, "statement_root");
    }
    out.episode_statement_commitment =
        episode_statement_commitment;
    out.endpoints = endpoints;
    if (!CanonicalFamily(
            out.family_index, out.program, why)) {
        out = {};
        return false;
    }
    const ProductionShapeV1 production =
        BuildProductionShapeV1();
    out.production_manifest_counts_bound =
        production.exact_manifest_total &&
        std::equal(
            production.endpoint_instances.begin(),
            production.endpoint_instances.end(),
            out.endpoints.begin(),
            [](uint64_t count,
               const EndpointStatementV1& endpoint) {
                return
                    endpoint.total_instance_count == count &&
                    endpoint.address_begin == 0 &&
                    endpoint.address_stride == 1;
            });
    if (out.production_manifest_counts_bound) {
        out.production_site_manifest_commitment =
            production.site_manifest_commitment;
    }
    out.statement_commitment =
        ComputeStatementCommitmentV1(out);
    if (out.statement_commitment.IsNull() ||
        !CanonicalStatementShape(out, why)) {
        out = {};
        return false;
    }
    return true;
}

uint256 ComputeStatementCommitmentV1(
    const StatementV1& statement)
{
    if (statement.version != kVersionV1 ||
        statement.episode_statement_commitment.IsNull() ||
        statement.family_index == UINT32_MAX ||
        statement.program.external_sha256d.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << STATEMENT_DOMAIN_V1;
    hash << statement.version;
    hash << statement.episode_statement_commitment;
    hash << statement.family_index;
    hash << statement.program.external_sha256d;
    HashAlgDigest(
        hash, statement.program.recursive_alg_hash);
    hash <<
        statement.program.same_canonical_serialization;
    hash << statement.production_site_manifest_commitment;
    hash << statement.production_manifest_counts_bound;
    hash << kEndpointCountV1;
    for (const auto& endpoint : statement.endpoints) {
        hash << static_cast<uint16_t>(endpoint.endpoint);
        hash << endpoint.total_instance_count;
        hash << endpoint.address_begin;
        hash << endpoint.address_stride;
        hash << static_cast<uint32_t>(
            endpoint.canonical_value_roots.size());
        for (const auto& root :
             endpoint.canonical_value_roots) {
            hash << root;
        }
    }
    return hash.GetHash();
}

uint256 ComputeOrderedProofSetCommitmentV1(
    const ProofV1& proof)
{
    if (proof.version != kVersionV1 ||
        proof.statement_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << PROOF_SET_DOMAIN_V1;
    hash << proof.version;
    hash << proof.statement_commitment;
    hash << kEndpointCountV1;
    for (const auto& bundle : proof.endpoint_bundles) {
        hash << static_cast<uint16_t>(bundle.endpoint);
        hash << bundle.bundle_commitment;
    }
    return hash.GetHash();
}

bool ProveV1(
    const StatementV1& statement,
    const std::array<
        std::vector<gf::Fp3>, kEndpointCountV1>& values,
    ProofV1& out,
    std::string* why)
{
    out = {};
    if (!CanonicalStatementShape(statement, why)) {
        return false;
    }
    for (uint32_t index = 0;
         index < kEndpointCountV1; ++index) {
        const auto& expected = statement.endpoints[index];
        std::vector<uint256> roots;
        if (values[index].size() !=
                expected.total_instance_count ||
            !ComputeCanonicalShardRootsV1(
                values[index], roots, why) ||
            roots != expected.canonical_value_roots ||
            !ProveRCStage3EpisodeSemanticMemoryBundle(
                expected.endpoint,
                statement.statement_commitment,
                expected.address_begin,
                expected.address_stride,
                values[index],
                out.endpoint_bundles[index],
                why)) {
            out = {};
            return Fail(why, "prove_endpoint");
        }
    }
    out.version = kVersionV1;
    out.statement_commitment =
        statement.statement_commitment;
    out.ordered_proof_set_commitment =
        ComputeOrderedProofSetCommitmentV1(out);
    if (out.ordered_proof_set_commitment.IsNull() ||
        !VerifyV1(statement, out, why)) {
        out = {};
        return Fail(why, "prove_self_verify");
    }
    return true;
}

bool VerifyV1(
    const StatementV1& expected_statement,
    const ProofV1& proof,
    std::string* why)
{
    if (!CanonicalStatementShape(
            expected_statement, why) ||
        proof.version != kVersionV1 ||
        proof.statement_commitment !=
            expected_statement.statement_commitment) {
        return Fail(why, "verify_statement");
    }
    for (uint32_t index = 0;
         index < kEndpointCountV1; ++index) {
        const auto& expected =
            expected_statement.endpoints[index];
        if (!VerifyRCStage3EpisodeSemanticMemoryBundle(
                expected.endpoint,
                expected_statement.statement_commitment,
                expected.total_instance_count,
                expected.address_begin,
                expected.address_stride,
                expected.canonical_value_roots,
                proof.endpoint_bundles[index],
                why)) {
            return Fail(why, "verify_endpoint");
        }
    }
    if (proof.ordered_proof_set_commitment.IsNull() ||
        proof.ordered_proof_set_commitment !=
            ComputeOrderedProofSetCommitmentV1(proof)) {
        return Fail(why, "verify_proof_set");
    }
    return true;
}

AuditV1 AssessV1(
    const StatementV1& expected_statement,
    const ProofV1& proof)
{
    AuditV1 out;
    std::string why;
    if (!VerifyV1(expected_statement, proof, &why)) {
        out.note = why;
        return out;
    }
    out.canonical_family_selected = true;
    out.exact_endpoint_order = true;
    out.exact_shard_partition = true;
    out.every_memory_child_proof_verified = true;
    out.source_roots_proof_owned = true;
    out.exact_all_instance_aggregation = true;
    out.production_all_instance_aggregation =
        expected_statement
            .production_manifest_counts_bound;

    auto tampered = proof;
    auto& child =
        tampered.endpoint_bundles[0].shards[0].proof;
    if (!child.quotient.batch.queries.empty() &&
        !child.quotient.batch.queries[0]
             .columns.empty()) {
        child.quotient.batch.queries[0]
            .columns[0].value =
            gf::Add(
                child.quotient.batch.queries[0]
                    .columns[0].value,
                gf::Fp3::One());
        tampered.endpoint_bundles[0].bundle_commitment =
            ComputeRCStage3EpisodeSemanticMemoryBundleCommitment(
                tampered.endpoint_bundles[0]);
        tampered.ordered_proof_set_commitment =
            ComputeOrderedProofSetCommitmentV1(tampered);
        out.proof_level_tamper_rejected =
            !VerifyV1(expected_statement, tampered, nullptr);
    }

    // The exact children above are default/SHA FRI proofs. The normalized
    // parent currently accepts AirFriBackendAlg children only. There is no
    // sound conversion from one digest root to the other without proving
    // equality of the committed values in a hash bridge.
    out.normalized_parent_accepts_sha_children = false;
    out.cross_hash_value_equality_proved = false;
    out.recursively_consumed = false;
    out.residual_obligations =
        topo::ProductionResidualRecursiveConsumption |
        (out.production_all_instance_aggregation
             ? 0U
             : topo::
                 ProductionResidualExactAllInstanceAggregation);
    out.valid =
        out.canonical_family_selected &&
        out.exact_endpoint_order &&
        out.exact_shard_partition &&
        out.every_memory_child_proof_verified &&
        out.source_roots_proof_owned &&
        out.exact_all_instance_aggregation &&
        out.proof_level_tamper_rejected &&
        !out.normalized_parent_accepts_sha_children &&
        !out.cross_hash_value_equality_proved &&
        !out.recursively_consumed;
    out.note =
        out.valid
        ? "stage3:episode_gemm_openings_proof_owned:"
          "source_roots_and_statement_instances_closed;"
          "recursive_sha_child_to_alg_parent_bridge_pending"
        : "stage3:episode_gemm_openings_proof_owned:"
          "assessment_incomplete";
    return out;
}

} // namespace matmul::v4::rc::episode_gemm_openings_proof_owned
