// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_RECURSIVE_RECEIPT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_RECURSIVE_RECEIPT_H

#include <matmul/matmul_v4_rc_stage3_recursive_fixedpoint.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace matmul::v4::rc::recursive_receipt {

namespace aq = air_quotient;
namespace fp = recursive_fixedpoint;
namespace gf = gkr_field;

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
 * Receipt-to-L2 integration result.
 *
 * This is the canonical bridge between serialized proof-aware cache entries
 * and ExecuteNarrowMultiChildL2FriConsumeV1. It verifies and decodes every
 * receipt before passing its real child proof, constraint system and seed to
 * the native multi-child fold-bus.
 *
 * `ordered_receipt_root_parent_air_bound` deliberately remains false: the
 * current L2 construction consumes each child proof, but has no public parent
 * cell that equality-constrains the ordered receipt-set root. Consequently
 * this type is an executable integration milestone, not a readiness flag.
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
    std::vector<std::string> residuals;
    std::string note;
};

/**
 * Proof-level Σ(local shard q) = full-parent q bridge whose local operands
 * come only from verified receipts.
 *
 * This removes the compensated-value freedom of the older raw host-vector
 * mirror. The join proof itself still has to become another recursively
 * consumed child at the normalized parent, so readiness remains false.
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
 * arity>=2 L2 FRI consumer. `prove=false` performs the light native-child,
 * fold-bus, FRI-shape and forgery checks. `prove=true` additionally produces
 * and verifies the L2 proof.
 */
[[nodiscard]] ShardReceiptL2ConsumeV1
ConsumeShardReceiptsL2V1(
    const std::vector<aq::AirConstraintSystem<gf::Fp3>>& child_css,
    const std::vector<ShardTerminalBindingV1>& bindings,
    const std::vector<ShardReceiptV1>& receipts,
    bool prove = false);

/**
 * Extract the full-parent quotient opening from an accepted fold-bus, verify
 * the receipt-owned local q cells cover `programs_total`, and prove their
 * pointwise sum equals that authenticated opening.
 */
[[nodiscard]] ShardReceiptQuotientJoinV1
JoinShardReceiptLocalQuotientsV1(
    const fp::FoldBusComposition& authenticated_parent,
    uint32_t parent_current_width,
    uint32_t programs_total,
    const std::vector<aq::AirConstraintSystem<gf::Fp3>>& child_css,
    const std::vector<ShardTerminalBindingV1>& bindings,
    const std::vector<ShardReceiptV1>& receipts);

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
