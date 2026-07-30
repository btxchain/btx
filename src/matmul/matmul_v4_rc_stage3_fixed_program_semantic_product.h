// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_FIXED_PROGRAM_SEMANTIC_PRODUCT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_FIXED_PROGRAM_SEMANTIC_PRODUCT_H

#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_stage3_hash_air.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>
#include <matmul/matmul_v4_rc_stage3_soundness_scenarios.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace matmul::v4::rc::fixed_program_semantic_product {

namespace ha = stage3_hash_air;
namespace sites = soundness_scenarios;
using gkr_field::Fp3;

inline constexpr uint16_t kVersionV1 = 1;
inline constexpr uint16_t kWitnessVersionV2 = 2;
inline constexpr uint16_t kWitnessVersionV3 = 3;
inline constexpr uint32_t kFamilyCountV1 = 11;
inline constexpr uint32_t kMaxBoundariesPerChildV1 =
    ha::kFixedProgramVerticalSemanticInstances;
/** SHA witness-boundary children use linked auxiliary sinks; thirty-two
 * sources plus linked and explicit power-of-two padding sinks fit the
 * canonical 64-instance schedule.  Independent ChaCha blocks require no
 * auxiliary sinks and use the same complete vertical internal-SSA AIR. */
inline constexpr uint32_t kMaxWitnessSourcesPerChildV2 = 32;
/**
 * ChaCha uses the complete vertical fixed-program AIR as well.  Unlike the
 * SHA chain it needs no auxiliary sink rows: each independent block retains
 * its own instance-tagged internal-SSA bus, external-input export and output
 * terminal.  The underlying vertical builder has an exact 64-instance cap.
 */
inline constexpr uint32_t kMaxPrivateChaChaSourcesPerChildV2 = 1;
inline constexpr uint32_t kMaxPrivateChaChaSourcesPerChildV3 = 64;
static_assert(
    kMaxWitnessSourcesPerChildV2 ==
    sites::kProductionPrivateShaSourcesPerProofSiteV1);
// The currently selected inventory still names the singleton V2 capacity.
// It may move to V3 only after this batched proof is consumed by the recursive
// scheduler; until then the one-source accounting remains conservative.
static_assert(
    kMaxPrivateChaChaSourcesPerChildV2 ==
    sites::kProductionPrivateChaChaSourcesPerProofSiteV1);
static_assert(
    kMaxPrivateChaChaSourcesPerChildV3 >
    kMaxPrivateChaChaSourcesPerChildV2);

/**
 * These are exactly the eleven fixed SHA/XOF/ChaCha sites which remain
 * partial in ProductionFamilyProgramSourceV1.  Array order is consensus
 * metadata: the verifier regenerates it and never accepts a prover-selected
 * family order.
 */
using FamilyPayloadV1 = std::variant<
    ha::ShaManifest,
    ha::CounterXofManifest,
    ha::ChaChaConsumptionManifest>;

struct FamilyInputV1 {
    sites::ProductionProofSiteKind kind{
        sites::ProductionProofSiteKind::EpisodeScaleSha};
    FamilyPayloadV1 payload{};
};

using FamilyInputsV1 = std::array<FamilyInputV1, kFamilyCountV1>;

struct FamilyStatementV1 {
    sites::ProductionProofSiteKind kind{};
    RCStage3RelationRole role{};
    RCStage3RelationEndpoint endpoint{};
    ha::ProgramKind program_kind{};
    uint32_t family_ordinal{0};
    uint32_t program_boundary_begin{0};
    uint32_t boundary_count{0};
    uint32_t output_logical_rows{0};
    uint32_t output_padded_rows{0};
    uint256 typed_domain{};
    uint256 manifest_commitment{};
    uint256 immutable_schedule_commitment{};
    /** Root of final words which are public boundary pins in this V1 child. */
    uint256 boundary_pinned_output_root{};

    bool operator==(const FamilyStatementV1&) const = default;
};

struct ProductManifestV1 {
    uint16_t version{kVersionV1};
    std::array<FamilyStatementV1, kFamilyCountV1> families{};
    uint32_t sha_boundary_count{0};
    uint32_t chacha_boundary_count{0};
    uint256 production_site_manifest_commitment{};
    uint256 exact_all_instance_root{};
    uint256 statement_commitment{};

    bool canonical_family_order{false};
    bool immutable_schedule_derived{false};
    bool opcode_selector_children_required{false};
    bool internal_ssa_copy_children_required{false};
    bool boundary_public_pins_required{false};
    /** Exact only relative to the caller's eleven typed manifests. */
    bool exact_input_manifest_aggregation{false};
    /** False until those manifests are derived from production role proofs. */
    bool production_manifest_derived{false};
    bool production_all_instance_aggregation{false};
    bool public_boundary_values{false};
    bool proof_owned_output_exports{false};
    bool caller_manifests_bound_to_role_proofs{false};
    /** False until the normalized V11 parent verifies every child below. */
    bool recursive_child_consumed{false};
    bool semantic_closure{false};
    bool production_authority{false};

    bool operator==(const ProductManifestV1&) const = default;
};

struct ProgramBatchProofV1 {
    ha::ProgramKind program_kind{};
    uint32_t boundary_count{0};
    std::vector<ha::FixedProgramVerticalProvenanceAirProof> children;
};

struct ProductProofV1 {
    uint16_t version{kVersionV1};
    ProductManifestV1 manifest;
    ProgramBatchProofV1 sha;
    ProgramBatchProofV1 chacha;
    bool valid{false};
    std::string note;
};

/**
 * A typed handle to ordinary epoch-R0 cells in one witness-boundary child.
 * This is deliberately not described as a value-vector Merkle root: the
 * binding object is the child's complete ordered R0 row commitment plus the
 * canonical cell schedule hashed below.  A recursive consumer can therefore
 * open/equality-link the exact cells without trusting caller-supplied values.
 */
struct FamilyExportFragmentV2 {
    uint32_t child_ordinal{0};
    uint32_t family_ordinal{0};
    uint32_t family_boundary_begin{0};
    uint32_t source_instance_begin{0};
    uint32_t source_instance_count{0};
    uint64_t input_cell_count{0};
    uint64_t output_cell_count{0};
    uint256 typed_input_cell_handle_root{};
    uint256 typed_output_producer_root{};

    bool operator==(const FamilyExportFragmentV2&) const = default;
};

struct FamilyWitnessStatementV2 {
    sites::ProductionProofSiteKind kind{};
    RCStage3RelationRole role{};
    RCStage3RelationEndpoint endpoint{};
    ha::ProgramKind program_kind{};
    uint32_t family_ordinal{0};
    uint32_t boundary_count{0};
    uint32_t fragment_count{0};
    uint256 caller_manifest_commitment{};
    uint256 typed_domain{};
    uint256 proof_owned_input_root{};
    uint256 proof_owned_output_producer_root{};

    bool operator==(const FamilyWitnessStatementV2&) const = default;
};

struct DualFp3ProducerTerminalV2 {
    Fp3 lane1{};
    Fp3 lane2{};

    bool operator==(const DualFp3ProducerTerminalV2& other) const
    {
        return gkr_field::Eq(lane1, other.lane1) &&
            gkr_field::Eq(lane2, other.lane2);
    }
};

/**
 * Canonical public-consumer side of one caller family.  The verifier
 * regenerates every (typed family, boundary, external address, value) event
 * from the caller's validated manifest and recomputes both the schedule root
 * and dual-Fp3 terminal.  The matching producer terminal is constrained
 * inside the private fixed-program child.
 */
struct CallerInputConsumerFragmentV3 {
    uint32_t family_ordinal{0};
    uint32_t family_boundary_begin{0};
    uint32_t source_instance_begin{0};
    uint32_t source_instance_count{0};
    uint64_t event_count{0};
    uint256 typed_schedule_root{};
    DualFp3ProducerTerminalV2 terminal{};

    bool operator==(const CallerInputConsumerFragmentV3&) const =
        default;
};

struct CallerInputReceiptV3 {
    uint16_t version{3};
    uint64_t event_count{0};
    uint256 producer_r0_root{};
    uint256 exact_consumer_schedule_root{};
    DualFp3ProducerTerminalV2 producer_terminal{};
    DualFp3ProducerTerminalV2 consumer_terminal{};
    std::vector<CallerInputConsumerFragmentV3> fragments;
    uint256 receipt_commitment{};

    bool operator==(const CallerInputReceiptV3&) const = default;
};

struct WitnessChildStatementV2 {
    ha::ProgramKind program_kind{};
    uint32_t child_ordinal{0};
    uint32_t global_source_begin{0};
    uint32_t source_instance_count{0};
    uint32_t sink_instance_count{0};
    uint32_t scheduled_instances{0};
    uint32_t output_event_count{0};
    uint256 public_boundary_statement{};
    uint256 base_row_commitment{};
    CallerInputReceiptV3 caller_input_receipt{};
    DualFp3ProducerTerminalV2 output_producer_terminal{};
    uint256 typed_fragment_root{};
    std::vector<FamilyExportFragmentV2> fragments;

    bool operator==(const WitnessChildStatementV2&) const = default;
};

struct WitnessProductManifestV2 {
    /** V3 selects vertically batched private ChaCha children.  The retained
     * type name reflects the stable field layout, not the protocol version. */
    uint16_t version{kWitnessVersionV3};
    uint256 caller_input_statement_commitment{};
    std::array<FamilyWitnessStatementV2, kFamilyCountV1> families{};
    std::vector<WitnessChildStatementV2> children;
    uint256 exact_instance_schedule_root{};
    uint256 statement_commitment{};

    bool canonical_family_order{false};
    bool private_boundary_inputs{false};
    bool private_boundary_outputs{false};
    bool proof_owned_input_exports{false};
    bool proof_owned_output_exports{false};
    bool dual_fp3_external_input_copy_ctl{false};
    bool dual_fp3_output_producer_ctl{false};
    bool auxiliary_sinks_equality_constrained{false};
    bool private_chacha_internal_ssa_ctl{false};
    bool caller_manifests_bound_to_role_proofs{false};
    bool consumer_ctl_linked{false};
    bool recursive_child_consumed{false};
    bool semantic_closure{false};
    bool production_authority{false};

    bool operator==(const WitnessProductManifestV2&) const = default;
};

struct WitnessChildProofV2 {
    WitnessChildStatementV2 statement;
    air_quotient::AirQuotientSplitRapRowsProof quotient;
};

struct WitnessProductProofV2 {
    uint16_t version{kWitnessVersionV3};
    WitnessProductManifestV2 manifest;
    std::vector<WitnessChildProofV2> children;
    bool valid{false};
    std::string note;
};

inline constexpr uint32_t
    kWitnessProductCodecMagicV3 = 0x33575046U; // "FWP3"
inline constexpr uint16_t
    kWitnessProductCodecVersionV3 = 3;

/**
 * Canonical durable V3 envelope for the complete proof-owned fixed-program
 * product.  Derived manifest fields are omitted from the wire and rebuilt
 * from `inputs`; every proof-owned statement, terminal, fragment and complete
 * split-RAP child proof is encoded exactly once.
 */
[[nodiscard]] size_t SerializeWitnessProductProofV3(
    const WitnessProductProofV2& proof,
    std::vector<unsigned char>& out);
[[nodiscard]] std::optional<WitnessProductProofV2>
DeserializeWitnessProductProofV3(
    const FamilyInputsV1& inputs,
    const std::vector<unsigned char>& in,
    std::string* why = nullptr);

inline constexpr uint16_t kShardSetVersionV4 = 4;

/**
 * One verified split-RAP child reduced to the proof-owned cells needed by the
 * all-instance scheduler.  `coverage` is the exact ordered family interval
 * list carried by the child statement.  Both terminals are constrained by
 * the child's R0-bound AIR; they are not copied from an unproved caller
 * manifest.
 */
struct ProofOwnedBoundaryShardV4 {
    uint32_t child_ordinal{0};
    ha::ProgramKind program_kind{};
    uint32_t source_instance_count{0};
    uint256 child_statement_commitment{};
    uint256 base_row_commitment{};
    uint256 exact_input_schedule_root{};
    DualFp3ProducerTerminalV2 input_terminal{};
    DualFp3ProducerTerminalV2 output_terminal{};
    std::vector<FamilyExportFragmentV2> coverage;
    uint256 shard_commitment{};

    bool operator==(const ProofOwnedBoundaryShardV4&) const = default;
};

/**
 * Exact ordered set of all proof-owned shards in one V2 caller product.
 *
 * The bounded counts are derived from the validated caller manifests.  The
 * production counts are independently regenerated from the canonical global
 * proof-site manifest, so a bounded fixture can exercise the construction
 * without being mislabeled production complete.
 */
struct ProofOwnedShardSetV4 {
    uint16_t version{kShardSetVersionV4};
    uint256 caller_statement_commitment{};
    uint256 production_site_manifest_commitment{};
    std::array<uint64_t, kFamilyCountV1>
        caller_boundary_counts{};
    std::array<uint64_t, kFamilyCountV1>
        production_boundary_counts{};
    std::vector<ProofOwnedBoundaryShardV4> shards;
    DualFp3ProducerTerminalV2 aggregate_input_terminal{};
    DualFp3ProducerTerminalV2 aggregate_output_terminal{};
    uint256 exact_coverage_root{};
    uint256 statement_commitment{};

    bool exact_ordered_caller_coverage{false};
    bool proof_owned_dual_fp3_terminals{false};
    bool production_manifest_derived{false};
    bool production_all_instance_aggregation{false};
    /** Remains false until the owning role AIR exports and equality-links the
     * exact same schedule root and dual-Fp3 terminals. */
    bool role_export_equality_constrained{false};
    bool recursive_child_consumed{false};
    bool semantic_closure{false};
    bool production_authority{false};

    bool operator==(const ProofOwnedShardSetV4&) const = default;
};

/**
 * Canonically derive all typed roles, endpoints, program kinds, boundaries,
 * offsets and public-boundary output roots from the eleven typed manifests.
 * The caller manifests are not yet equality-linked to owning role proofs;
 * this is deliberately recorded in ProductManifestV1.
 */
[[nodiscard]] bool BuildProductManifestV1(
    const FamilyInputsV1& inputs,
    ProductManifestV1& out,
    std::string* why = nullptr);

/**
 * Prove every canonical boundary in chunks of at most 63.  Every child is the
 * executable selector/boundary/internal-SSA provenance AIR.  Chunk seeds bind
 * the complete product statement, kind, exact offset and exact count.
 */
[[nodiscard]] bool ProveProductV1(
    const FamilyInputsV1& inputs,
    const uint256& fs_seed,
    ProductProofV1& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyProductV1(
    const FamilyInputsV1& inputs,
    const uint256& fs_seed,
    const ProductProofV1& proof,
    std::string* why = nullptr);

/**
 * V2 replaces V1's public final-word pins with the existing split-RAP
 * witness-boundary AIR.  Source externals and finals are ordinary R0-bound
 * proof cells.  A dual-Fp3 external-address copy relation makes every use of
 * one canonical private boundary word equal.  Canonical auxiliary sink
 * instances consume every source final word through the witness-boundary
 * dual-Fp3 equality bus, while an additional domain-separated dual-Fp3
 * producer accumulator exports the exact output-cell multiset for a later
 * real consumer.
 *
 * The caller's validated typed manifests also regenerate a canonical public
 * consumer terminal.  Equality with the child-constrained private input
 * producer terminal proves the exact caller values enter each program.  The
 * manifests are not yet derived from authenticated upstream role proofs, and
 * neither the output consumer nor recursive parent is closed; those residuals
 * remain explicitly false.
 */
[[nodiscard]] bool ProveWitnessProductV2(
    const FamilyInputsV1& inputs,
    const uint256& fs_seed,
    WitnessProductProofV2& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyWitnessProductV2(
    const FamilyInputsV1& inputs,
    const uint256& fs_seed,
    const WitnessProductProofV2& proof,
    std::string* why = nullptr);

/**
 * Verify the complete V2 split-RAP proof first, then reduce its ordered child
 * statements into a streaming-friendly exact shard set and aggregate their
 * two independently challenged Fp3 input/output terminals.
 */
[[nodiscard]] bool BuildProofOwnedShardSetV4(
    const FamilyInputsV1& inputs,
    const uint256& fs_seed,
    const WitnessProductProofV2& proof,
    ProofOwnedShardSetV4& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyProofOwnedShardSetV4(
    const FamilyInputsV1& inputs,
    const uint256& fs_seed,
    const WitnessProductProofV2& proof,
    const ProofOwnedShardSetV4& shard_set,
    std::string* why = nullptr);

/**
 * Receipt cells must be unreduced canonical u32 base-field representatives.
 * In particular x+p is rejected before field arithmetic can alias it to x.
 */
[[nodiscard]] bool DecodeCanonicalU32V1(
    const Fp3& cell,
    uint32_t& out,
    std::string* why = nullptr);

inline constexpr bool kRecursiveConsumptionReadyV1 = false;
inline constexpr bool kSemanticClosureReadyV1 = false;
inline constexpr bool kProductionAuthorityV1 = false;
inline constexpr bool kWitnessRecursiveConsumptionReadyV2 = false;
inline constexpr bool kWitnessSemanticClosureReadyV2 = false;
inline constexpr bool kWitnessProductionAuthorityV2 = false;
inline constexpr bool kShardSetRoleExportEqualityReadyV4 = false;
inline constexpr bool kShardSetRecursiveConsumptionReadyV4 = false;
inline constexpr bool kShardSetProductionAuthorityV4 = false;
static_assert(!kRecursiveConsumptionReadyV1);
static_assert(!kSemanticClosureReadyV1);
static_assert(!kProductionAuthorityV1);
static_assert(!kWitnessRecursiveConsumptionReadyV2);
static_assert(!kWitnessSemanticClosureReadyV2);
static_assert(!kWitnessProductionAuthorityV2);
static_assert(!kShardSetRoleExportEqualityReadyV4);
static_assert(!kShardSetRecursiveConsumptionReadyV4);
static_assert(!kShardSetProductionAuthorityV4);

} // namespace matmul::v4::rc::fixed_program_semantic_product

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_FIXED_PROGRAM_SEMANTIC_PRODUCT_H
