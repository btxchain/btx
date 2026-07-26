// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_SEMANTIC_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_SEMANTIC_H

#include <matmul/matmul_v4_rc_stage3_relation_closure.h>
#include <matmul/matmul_v4_rc_stage3_hash_semantic.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc {

/**
 * Version-one commit-and-prove memory boundary for coupled endpoints.
 *
 * The immutable relation AIR is the left side of a direct product.  For every
 * semantic word exported by the endpoint the product appends one VALUE
 * column and enforces, on every row,
 *
 *     semantic.VALUE[p] = relation[source_column[p]].
 *
 * ROLE, endpoint-local PORT and ADDRESS are verifier-derived rather than
 * witness supplied.  The endpoint memory root commits their canonical
 * schedule together with the AlgHash commitment of every VALUE column.  It
 * is therefore a vector opening of proof-owned cells, not a claimed uint256.
 *
 * This layer deliberately does not manufacture absent relations.  Hash/XOF
 * and root-composition endpoints must execute their registered fixed-program
 * children before their audit entry becomes complete.
 */
inline constexpr uint16_t kRCStage3CoupledSemanticVersion = 1;
inline constexpr uint64_t kRCStage3CoupledSemanticMaxFlatShards =
    uint64_t{1} << 24;

struct RCStage3CoupledSemanticEndpointSpec {
    RCStage3RelationEndpoint endpoint{};
    RCStage3RelationRole role{};
    std::vector<uint32_t> source_columns;
    uint32_t relation_rows{0};
    uint64_t required_instances{0};
    uint256 shape_commitment{};
    uint256 schedule_commitment{};
    bool relation_air_available{false};
    bool full_vector_export{false};
    bool canonical_schedule{false};
    bool complete_instance_aggregation{false};
    std::string relation_family;
    std::string remaining;
};

struct RCStage3CoupledSemanticLayout {
    RCStage3RelationEndpoint endpoint{};
    RCStage3RelationRole role{};
    uint32_t relation_columns{0};
    /** Three columns per port: verifier-owned ROLE, ADDRESS, then VALUE. */
    uint32_t memory_column_base{0};
    uint32_t total_columns{0};
    std::vector<uint32_t> source_columns;
    uint256 schedule_commitment{};

    [[nodiscard]] uint32_t RoleColumn(uint32_t port) const
    {
        return memory_column_base + 3U * port;
    }
    [[nodiscard]] uint32_t AddressColumn(uint32_t port) const
    {
        return RoleColumn(port) + 1U;
    }
    [[nodiscard]] uint32_t ValueColumn(uint32_t port) const
    {
        return RoleColumn(port) + 2U;
    }
};

struct RCStage3CoupledSemanticPublicPin {
    uint16_t version{kRCStage3CoupledSemanticVersion};
    RCStage3RelationEndpoint endpoint{};
    RCStage3CoupledAirRequest request{};
    uint256 statement_commitment{};
    uint256 shape_commitment{};
    uint256 schedule_commitment{};
    /** Zero span is the standalone local-kernel form. Flat bundles set span
     * to one and bind begin/total into the schedule and proof seed. */
    uint64_t instance_begin{0};
    uint64_t instance_span{0};
    uint64_t instance_count{0};
    std::vector<uint256> relation_column_roots;
    std::vector<uint256> value_column_roots;
    uint256 semantic_memory_root{};
};

struct RCStage3CoupledSemanticShard {
    uint64_t instance_begin{0};
    RCStage3CoupledSemanticPublicPin pin;
    air_quotient::AirQuotientProof<gkr_field::Fp3> proof;
};

struct RCStage3CoupledSemanticFlatBundle {
    uint16_t version{kRCStage3CoupledSemanticVersion};
    RCStage3RelationEndpoint endpoint{};
    uint256 statement_commitment{};
    uint64_t total_instances{0};
    std::vector<RCStage3CoupledSemanticShard> shards;
    uint256 bundle_commitment{};
};

struct RCStage3CoupledSemanticAudit {
    RCStage3RelationEndpoint endpoint{};
    RCStage3RelationRole role{};
    bool relation_air_cell{false};
    bool full_vector_export{false};
    bool canonical_memory_schedule{false};
    bool proof_owned_memory_root{false};
    bool complete_instance_aggregation{false};
    bool hash_or_xof_child_executable{false};
    bool canonical_root_chain_link{false};
    bool semantic_relation_complete{false};
    std::string construction;
    std::string remaining;
};

/**
 * Public memory binding for one exact all-instance fixed-program bundle.
 * `boundary_value_root` is recomputed from the registered manifest adapter;
 * `semantic_memory_root` additionally binds endpoint, role, shape, schedule
 * and exact boundary count.
 */
struct RCStage3CoupledHashSemanticPin {
    uint16_t version{kRCStage3CoupledSemanticVersion};
    RCStage3RelationEndpoint endpoint{};
    stage3_hash_semantic::BoundaryPort port{
        stage3_hash_semantic::BoundaryPort::ExternalThenFinal};
    uint256 statement_commitment{};
    uint256 shape_commitment{};
    uint256 manifest_commitment{};
    uint256 schedule_commitment{};
    uint64_t instance_count{0};
    uint32_t logical_rows{0};
    uint32_t n_rows{0};
    uint256 boundary_value_root{};
    uint256 semantic_memory_root{};
};

/** Resolve an immutable endpoint-to-column mapping. */
[[nodiscard]] bool ResolveRCStage3CoupledSemanticEndpointSpec(
    RCStage3RelationEndpoint endpoint,
    const RCStage3CoupledAirRequest& request,
    RCStage3CoupledSemanticEndpointSpec& out,
    std::string* why = nullptr);

/** Build the direct-product relation+memory AIR. */
[[nodiscard]] bool BuildRCStage3CoupledSemanticConstraintSystem(
    const RCStage3CoupledSemanticEndpointSpec& spec,
    const air_quotient::AirConstraintSystem<gkr_field::Fp3>& relation_cs,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    RCStage3CoupledSemanticLayout* layout = nullptr,
    std::string* why = nullptr);

/** Append exact aliases of all registered source columns. */
[[nodiscard]] bool BuildRCStage3CoupledSemanticWitness(
    const RCStage3CoupledSemanticLayout& layout,
    const std::vector<std::vector<gkr_field::Fp3>>& relation_columns,
    std::vector<std::vector<gkr_field::Fp3>>& out,
    std::string* why = nullptr);

/**
 * The semantic root is derived from proof-column roots and the canonical
 * schedule.  A null or host-selected relation/value root is rejected.
 */
[[nodiscard]] uint256 ComputeRCStage3CoupledSemanticMemoryRoot(
    RCStage3RelationEndpoint endpoint,
    RCStage3RelationRole role,
    uint64_t instance_count,
    const uint256& shape_commitment,
    const uint256& schedule_commitment,
    const std::vector<uint256>& value_column_roots);

[[nodiscard]] uint256 ComputeRCStage3CoupledSemanticProofSeed(
    const RCStage3CoupledSemanticPublicPin& pin);

[[nodiscard]] uint256 ComputeRCStage3CoupledSemanticShardSchedule(
    const uint256& base_schedule_commitment,
    uint64_t instance_begin,
    uint64_t instance_span,
    uint64_t total_instances);

/** Verify the complete local quotient proof and its proof-derived memory root. */
[[nodiscard]] bool VerifyRCStage3CoupledSemanticProof(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledSemanticPublicPin& pin,
    const air_quotient::AirQuotientProof<gkr_field::Fp3>& proof,
    std::string* why = nullptr);

[[nodiscard]] uint256 ComputeRCStage3CoupledSemanticFlatBundleCommitment(
    const RCStage3CoupledSemanticFlatBundle& bundle);

/** Exact V1 flat aggregation: one schedule-bound quotient per instance. */
[[nodiscard]] bool VerifyRCStage3CoupledSemanticFlatBundle(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledSemanticFlatBundle& bundle,
    std::string* why = nullptr);

/** Exact deterministic audit of endpoints 27..52. */
[[nodiscard]] std::vector<RCStage3CoupledSemanticAudit>
CurrentRCStage3CoupledSemanticAudit(
    const RCStage3CoupledShape& shape,
    const gkr_field::Fp3& gamma,
    const gkr_field::Fp3& alpha,
    uint8_t extract_scale_e = 0);

/** Prover helper; the verifier always regenerates `boundaries` from a typed
 * manifest and never trusts this helper's output. */
[[nodiscard]] bool BuildRCStage3CoupledHashSemanticPin(
    RCStage3RelationEndpoint endpoint,
    const RCStage3CoupledShape& shape,
    const uint256& statement_commitment,
    const uint256& manifest_commitment,
    const std::vector<stage3_hash_air::FixedProgramBoundaryInstance>& boundaries,
    stage3_hash_semantic::BoundaryPort port,
    RCStage3CoupledHashSemanticPin& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyRCStage3CoupledCounterXofSemantic(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const stage3_hash_air::CounterXofManifest& manifest,
    const stage3_hash_semantic::FlatBoundaryProofBundle& bundle,
    const RCStage3CoupledHashSemanticPin& pin,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyRCStage3CoupledChaChaSemantic(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const stage3_hash_air::ChaChaConsumptionManifest& manifest,
    const stage3_hash_semantic::FlatBoundaryProofBundle& bundle,
    const RCStage3CoupledHashSemanticPin& pin,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyRCStage3CoupledBarrierHashSemantic(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const stage3_hash_air::CoupledBarrierManifest& manifest,
    const stage3_hash_semantic::FlatBoundaryProofBundle& bundle,
    const RCStage3CoupledHashSemanticPin& pin,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyRCStage3CoupledDigestHashSemantic(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const stage3_hash_air::CoupledDigestManifest& manifest,
    const stage3_hash_semantic::FlatBoundaryProofBundle& bundle,
    const RCStage3CoupledHashSemanticPin& pin,
    std::string* why = nullptr);

inline constexpr bool kRCStage3CoupledSemanticMemoryLayerExecutable = true;
inline constexpr bool kRCStage3CoupledAllSemanticEndpointsComplete = false;
static_assert(kRCStage3CoupledSemanticMemoryLayerExecutable);
static_assert(!kRCStage3CoupledAllSemanticEndpointsComplete);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_SEMANTIC_H
