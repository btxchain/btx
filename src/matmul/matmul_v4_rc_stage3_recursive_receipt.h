// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_RECURSIVE_RECEIPT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_RECURSIVE_RECEIPT_H

#include <matmul/matmul_v4_rc_stage3_recursive_fixedpoint.h>
#include <matmul/matmul_v4_rc_stage3_recursive_hierarchy.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace matmul::v4::rc::recursive_receipt {

namespace aq = air_quotient;
namespace fp = recursive_fixedpoint;
namespace gf = gkr_field;
namespace rh = recursive_hierarchy;

inline constexpr uint16_t kShardReceiptVersionV1 = 1;
/** "RQR1" in little-endian wire order. */
inline constexpr uint32_t kShardReceiptMagicV1 = 0x31525152U;

/**
 * Two verifier-owned columns appended to an attached free-row L1 shard.
 *
 * `expected_local_q` is nonzero only on canonical bytecode Quotient rows and
 * contains the public terminal q for that query. `query_index` carries the
 * original child-FRI query index on the same rows. Both are preprocessed
 * columns, so the row-wise backend binds their canonical values through the
 * dual-OOD preprocessed-column argument.
 */
struct ShardTerminalLayoutV1 {
    uint32_t expected_local_q{0};
    uint32_t query_index{0};

    explicit constexpr ShardTerminalLayoutV1(uint32_t start = 0)
        : expected_local_q(start), query_index(start + 1)
    {
    }

    [[nodiscard]] constexpr uint32_t End() const
    {
        return query_index + 1;
    }
};

/**
 * Public statement installed before the L1 shard is proved.
 *
 * This is deliberately proof-independent: it commits the exact sliced
 * ProgramTable, shard position, inherited child query indices and the local
 * quotient terminals that the added AIR constraint equality-links to
 * BytecodeBusLayout::Value(3) on Quotient rows.
 */
struct ShardTerminalBindingV1 {
    uint16_t version{kShardReceiptVersionV1};
    uint32_t shard_index{0};
    uint32_t program_count{0};
    uint32_t queries{0};
    uint32_t original_columns{0};
    ShardTerminalLayoutV1 layout;
    uint256 program_commitment{};
    uint256 bytecode_prechallenge_commitment{};
    uint256 statement_commitment{};
    std::vector<uint32_t> query_indices;
    std::vector<gf::Fp3> local_q_per_query;
    bool canonical_quotient_rows{false};
    bool expected_q_preprocessed{false};
    bool query_indices_preprocessed{false};
    bool q_terminal_equality_constrained{false};
    bool valid{false};
    std::string note;
};

/**
 * Canonical, proof-carrying L1 receipt.
 *
 * The proof is stored as canonical whole-proof bytes. This avoids a second
 * serialization convention and makes the byte count used by the relay gate
 * exactly the bytes the verifier parses.
 */
struct ShardReceiptV1 {
    uint16_t version{kShardReceiptVersionV1};
    uint32_t shard_index{0};
    uint32_t program_count{0};
    uint32_t queries{0};
    uint32_t n_rows{0};
    uint32_t n_columns{0};
    uint32_t n_constraints{0};
    uint256 program_commitment{};
    uint256 bytecode_prechallenge_commitment{};
    uint256 statement_commitment{};
    uint256 fs_seed{};
    uint256 proof_commitment{};
    uint256 receipt_root{};
    std::vector<uint32_t> query_indices;
    std::vector<gf::Fp3> local_q_per_query;
    std::vector<unsigned char> proof_bytes;
};

struct ShardReceiptProveResultV1 {
    bool valid{false};
    bool terminal_binding_valid{false};
    bool proof_retained{false};
    bool proved{false};
    bool verified{false};
    bool canonical_codec_round_trip{false};
    bool wire_fits{false};
    bool forgery_rejected{false};
    uint64_t prove_micros{0};
    uint64_t verify_micros{0};
    uint64_t encoded_bytes{0};
    ShardReceiptV1 receipt;
    std::string note;
};

struct ShardReceiptOwnershipAuditV1 {
    bool valid{false};
    bool canonical_receipt{false};
    bool native_child_proof_verified{false};
    bool local_q_public_statement_bound{false};
    bool program_and_query_identity_bound{false};
    bool receipt_root_recomputed{false};
    bool wire_fits{false};
    /** Remains false until an L2 verifier AIR consumes this receipt. */
    bool recursively_consumed_by_parent{false};
    std::vector<std::string> residuals;
    std::string note;
};

/**
 * Parent-AIR pin of the ordered receipt-set root.
 *
 * Installs eight public/preprocessed limb cells (LE u32 of the uint256 root)
 * and equality-constrains a claimed witness column to them. Light prove /
 * verify / forgery rejects. Does NOT flip Ready / AggregationReady /
 * CompleteFP / kShardReceiptRecursiveOwnershipReadyV1.
 */
struct OrderedReceiptSetRootParentAirPinV1 {
    bool valid{false};
    bool public_cells_installed{false};
    bool equality_constrained{false};
    bool proved{false};
    bool verified{false};
    bool forgery_rejected{false};
    uint32_t n_rows{0};
    uint32_t n_columns{0};
    uint256 ordered_receipt_set_root{};
    std::string note;
};

/**
 * Receipt-to-L2 integration result.
 *
 * This is the canonical bridge between serialized proof-aware cache entries
 * and ExecuteNarrowMultiChildL2FriConsumeV1. It verifies and decodes every
 * receipt before passing its real child proof, constraint system and seed to
 * the native multi-child fold-bus, then pins the ordered receipt-set root as
 * a parent-AIR public cell (residual 1 closed on this type).
 *
 * `full_parent_q_join_recursively_consumed` remains false here: the
 * receipt-owned quotient-join recursive consume lives on
 * ShardReceiptQuotientJoinV1 (residual 2). Ready stays false.
 */
struct ShardReceiptL2ConsumeV1 {
    bool valid{false};
    bool receipts_verified{false};
    bool canonical_shard_order{false};
    bool unique_receipt_roots{false};
    bool common_query_schedule{false};
    bool child_prechallenges_bound{false};
    bool child_proofs_decoded{false};
    bool child_proofs_cryptographically_consumed{false};
    bool local_q_cells_child_air_bound{false};
    bool ordered_receipt_root_parent_air_bound{false};
    bool full_parent_q_join_recursively_consumed{false};
    bool reordered_receipts_rejected{false};
    uint32_t arity{0};
    uint64_t encoded_child_bytes{0};
    uint256 ordered_receipt_set_root{};
    fp::NarrowMultiChildL2FriConsumeV1 l2;
    OrderedReceiptSetRootParentAirPinV1 ordered_root_pin;
    std::vector<std::string> residuals;
    std::string note;
};

/**
 * Recursively consume a retained receipt-owned quotient-join AIR proof as a
 * normalized-parent child (plus a tiny companion boolean child for arity≥2
 * multi-child fold-bus). Light prove=false by default. Does NOT flip Ready.
 */
struct ReceiptOwnedQuotientJoinParentConsumeV1 {
    bool valid{false};
    bool join_air_proof_retained{false};
    bool join_operands_preprocessed{false};
    bool compensated_forgery_rejected{false};
    bool companion_child_built{false};
    bool parent_fold_bus_built{false};
    bool cryptographically_consumed{false};
    bool forgery_rejected{false};
    uint32_t join_n_rows{0};
    uint32_t join_n_columns{0};
    fp::NarrowMultiChildL2FriConsumeV1 parent;
    std::string note;
};

/**
 * Proof-level Σ(local shard q) = full-parent q bridge whose local operands
 * come only from verified receipts.
 *
 * After the AIR-mirrored join closes, the retained join proof is recursively
 * consumed as a normalized-parent child (residual 2 closed on this type).
 * Ownership Ready / AggregationReady / CompleteFP remain false: hier L2
 * still needs real free-row L1 receipts end-to-end (vs boolean stand-ins).
 */
struct ShardReceiptQuotientJoinV1 {
    bool valid{false};
    bool receipts_verified{false};
    bool canonical_shard_order{false};
    bool common_query_schedule{false};
    bool authenticated_parent_q_extracted{false};
    bool program_partition_full{false};
    bool parent_q_absolute{false};
    bool air_join_proved{false};
    bool air_join_verified{false};
    bool air_join_forgery_rejected{false};
    bool recursively_consumed_by_parent{false};
    uint32_t shard_count{0};
    uint32_t queries{0};
    uint256 ordered_receipt_set_root{};
    fp::NarrowBytecodeShardQuotientJoinAirMirrorV1 air_join;
    ReceiptOwnedQuotientJoinParentConsumeV1 parent_consume;
    std::vector<std::string> residuals;
    std::string note;
};

/**
 * One proof-owning L2 parent over:
 *
 *   source parent proof || ordered shard receipts || receipt-owned q join.
 *
 * The exact-set V2 ordinal manifest supports the production FFD shard packer:
 * every global program ordinal is named exactly once, and each entry is tied
 * to the verifier-reconstructed shard statement commitment.  The q-join seed
 * commits the manifest, source proof, ordered receipt set, query schedule and
 * every q operand before the unified parent is proved.
 *
 * This closes the previous "three independent proofs" construction gap. It
 * deliberately does not claim production authority until the active-P2
 * transcript is consumed inside the same parent and every child constraint
 * system is reconstructed from the canonical registry.
 */
struct UnifiedShardReceiptL2ParentV1 {
    bool valid{false};
    bool source_child_verified{false};
    bool receipts_verified{false};
    bool exact_set_manifest_verified{false};
    bool manifest_statement_roots_match{false};
    bool common_query_schedule{false};
    bool q_join_operands_preprocessed{false};
    bool compensated_q_forgery_rejected{false};
    bool ownership_context_bound_to_q_join_seed{false};
    bool q_join_child_tamper_rejected{false};
    bool one_parent_consumes_source_receipts_and_q_join{false};
    bool parent_proof_retained{false};
    bool parent_proof_reentry_verified{false};
    bool parent_proof_tamper_rejected{false};
    bool canonical_whole_parent_codec{false};
    bool within_relay_budget{false};
    bool within_wire_budget{false};
    /** Still false until the active P2 transcript/consumer CTLs are in-parent. */
    bool active_p2_transcript_owned_in_same_parent{false};
    /** Still false until all CSs are rebuilt from the consensus registry. */
    bool verifier_reconstructed_constraint_systems{false};
    bool production_complete{false};
    uint32_t receipt_count{0};
    uint32_t parent_arity{0};
    uint32_t queries{0};
    uint64_t parent_proof_bytes{0};
    uint256 exact_set_manifest_commitment{};
    uint256 ordered_receipt_set_root{};
    uint256 query_schedule_commitment{};
    uint256 source_proof_commitment{};
    uint256 ownership_context{};
    fp::NarrowMultiChildL2FriConsumeV1 parent;
    std::vector<std::string> residuals;
    std::string note;
};

/**
 * Append the two public terminal columns and the load-bearing alias
 *
 *   is_quotient_row * (Value(3) - expected_local_q) = 0.
 *
 * No readiness flag is changed. The caller must execute this before
 * AirQuotientProveRows.
 */
[[nodiscard]] ShardTerminalBindingV1
BindShardLocalQuotientTerminalsV1(
    fp::FoldBusComposition& attached_shard,
    const fp::BytecodeInterpreterAttachment& interpreter,
    uint32_t shard_index);

[[nodiscard]] uint256 ComputeShardTerminalStatementCommitmentV1(
    const ShardTerminalBindingV1& binding,
    uint32_t n_rows,
    uint32_t n_columns,
    uint32_t n_constraints);

[[nodiscard]] uint256 ComputeShardReceiptFsSeedV1(
    const ShardTerminalBindingV1& binding,
    uint32_t n_rows,
    uint32_t n_columns,
    uint32_t n_constraints);

[[nodiscard]] uint256 ComputeShardReceiptRootV1(
    const ShardReceiptV1& receipt);

/**
 * Canonical commitment to a strictly shard-index-ordered receipt vector.
 * Returns null for an empty, duplicate, unordered or internally inconsistent
 * vector.
 */
[[nodiscard]] uint256 ComputeOrderedShardReceiptSetRootV1(
    const std::vector<ShardReceiptV1>& receipts);

/**
 * Prove an already-attached and terminal-bound L1 shard. The receipt remains
 * fail-closed if its canonical encoding exceeds kRCStage3MaxProofBytes.
 */
[[nodiscard]] ShardReceiptProveResultV1 ProveShardReceiptV1(
    const fp::FoldBusComposition& attached_shard,
    const ShardTerminalBindingV1& binding);

/**
 * Verify every receipt field, canonical proof bytes, statement/seed/root
 * recomputation and the unmodified AirQuotient verifier against the supplied
 * canonical child constraint system.
 */
[[nodiscard]] bool VerifyShardReceiptV1(
    const aq::AirConstraintSystem<gf::Fp3>& child_cs,
    const ShardTerminalBindingV1& expected_binding,
    const ShardReceiptV1& receipt,
    std::string* why = nullptr);

[[nodiscard]] ShardReceiptOwnershipAuditV1
AssessShardReceiptOwnershipV1(
    const aq::AirConstraintSystem<gf::Fp3>& child_cs,
    const ShardTerminalBindingV1& expected_binding,
    const ShardReceiptV1& receipt);

/**
 * Verify canonical receipts and feed their decoded proofs to the executable
 * arity≥2 L2 FRI consumer. `prove=false` performs the light native-child,
 * fold-bus, FRI-shape and forgery checks. `prove=true` additionally produces
 * and verifies the L2 proof. On success, pins the ordered receipt-set root
 * as a parent-AIR public cell (residual 1).
 */
[[nodiscard]] ShardReceiptL2ConsumeV1
ConsumeShardReceiptsL2V1(
    const std::vector<aq::AirConstraintSystem<gf::Fp3>>& child_css,
    const std::vector<ShardTerminalBindingV1>& bindings,
    const std::vector<ShardReceiptV1>& receipts,
    bool prove = false);

/**
 * Equality-constrain `ordered_receipt_set_root` as eight public/preprocessed
 * LE-u32 limb cells in a tiny parent AIR. Light prove/verify/forgery.
 */
[[nodiscard]] OrderedReceiptSetRootParentAirPinV1
PinOrderedReceiptSetRootParentAirV1(
    const uint256& ordered_receipt_set_root);

/**
 * Extract the full-parent quotient opening from an accepted fold-bus, verify
 * the receipt-owned local q cells cover `programs_total`, prove their
 * pointwise sum equals that authenticated opening, and recursively consume
 * the retained join AIR proof as a normalized-parent child (residual 2).
 */
[[nodiscard]] ShardReceiptQuotientJoinV1
JoinShardReceiptLocalQuotientsV1(
    const fp::FoldBusComposition& authenticated_parent,
    uint32_t parent_current_width,
    uint32_t programs_total,
    const std::vector<aq::AirConstraintSystem<gf::Fp3>>& child_css,
    const std::vector<ShardTerminalBindingV1>& bindings,
    const std::vector<ShardReceiptV1>& receipts);

/**
 * Retain the AIR-mirrored receipt-owned q-join proof and consume it (with a
 * companion boolean child) via ExecuteNarrowMultiChildL2FriConsumeV1.
 */
[[nodiscard]] ReceiptOwnedQuotientJoinParentConsumeV1
ConsumeReceiptOwnedQuotientJoinAsNormalizedParentChildV1(
    const std::vector<gf::Fp3>& bound_q_per_query,
    const std::vector<std::vector<gf::Fp3>>& shard_local_q,
    bool absolute_parent_bound,
    bool prove = false);

/**
 * Execute the unified proof-owned L2 parent described above. `source_child_*`
 * identify the proof from which the authenticated full-parent q openings are
 * reconstructed; it is included as the first child of the resulting parent.
 */
[[nodiscard]] UnifiedShardReceiptL2ParentV1
ConsumeUnifiedShardReceiptL2ParentV1(
    const aq::AirConstraintSystem<gf::Fp3>& source_child_cs,
    const fp::AlgAirProof& source_child_proof,
    const uint256& source_child_fs_seed,
    uint32_t source_parent_current_width,
    const rh::ShardOrdinalManifestV2& exact_set_manifest,
    const std::vector<aq::AirConstraintSystem<gf::Fp3>>& child_css,
    const std::vector<ShardTerminalBindingV1>& bindings,
    const std::vector<ShardReceiptV1>& receipts,
    bool prove = true);

[[nodiscard]] bool SerializeShardReceiptV1(
    const ShardReceiptV1& receipt,
    std::vector<unsigned char>& out,
    std::string* why = nullptr);

[[nodiscard]] std::optional<ShardReceiptV1>
DeserializeShardReceiptV1(
    const std::vector<unsigned char>& bytes,
    std::string* why = nullptr);

inline constexpr bool kShardReceiptExecutableV1 = true;
inline constexpr bool kShardReceiptL2ConsumeExecutableV1 = true;
inline constexpr bool kShardReceiptRecursiveOwnershipReadyV1 = false;

static_assert(kShardReceiptExecutableV1);
static_assert(kShardReceiptL2ConsumeExecutableV1);
static_assert(!kShardReceiptRecursiveOwnershipReadyV1);

} // namespace matmul::v4::rc::recursive_receipt

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_RECURSIVE_RECEIPT_H
