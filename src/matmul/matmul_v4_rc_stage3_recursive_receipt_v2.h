// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_RECURSIVE_RECEIPT_V2_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_RECURSIVE_RECEIPT_V2_H

#include <matmul/matmul_v4_rc_stage3_recursive_receipt.h>

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace matmul::v4::rc::recursive_receipt_v2 {

namespace aq = air_quotient;
namespace fp = recursive_fixedpoint;
namespace gf = gkr_field;
namespace rr = recursive_receipt;

inline constexpr uint16_t kShardReceiptVersionV2 = 2;
/** "RQR2" in little-endian wire order. */
inline constexpr uint32_t kShardReceiptMagicV2 = 0x32525152U;
inline constexpr uint32_t kIdentityLimbsV2 = 8;
inline constexpr uint32_t kSourceOpeningLanesV2 =
    alg_hash::kAlgHashRate;

/**
 * One actual hash-opening cell which carries a coordinate of the source
 * parent's authenticated quotient opening.
 *
 * `value` is a base-field coordinate and MUST be canonical.  The binding
 * installs it as a preprocessed export at (`row`, `lane`) and adds the direct
 * same-row identity
 *
 *   mask * (hash.absorbed_pin[lane] - exported_value[lane]) = 0.
 *
 * There are exactly three entries, coordinates 0,1,2, for every query.
 */
struct SourceOpeningExportV2 {
    uint32_t query{0};
    uint32_t row{0};
    uint32_t lane{0};
    uint32_t coordinate{0};
    gf::Fp value{0};

    bool operator==(const SourceOpeningExportV2&) const = default;
};

/**
 * V2 public columns appended after the V1 local-quotient terminal columns.
 *
 * All columns are verifier-owned preprocessed columns.  Source opening lane
 * values/masks live on the actual hash-opening rows.  The source q,
 * coordinate cells and every identity limb live on every canonical shard
 * Quotient row.
 */
struct ShardSourceTerminalLayoutV2 {
    uint32_t base{0};
    uint32_t source_opening_value_base{0};
    uint32_t source_opening_mask_base{0};
    uint32_t source_coordinate_base{0};
    uint32_t source_parent_q{0};
    uint32_t source_proof_identity_base{0};
    uint32_t source_fs_seed_identity_base{0};
    uint32_t source_prechallenge_identity_base{0};
    uint32_t shard_program_identity_base{0};
    uint32_t shard_prechallenge_identity_base{0};
    uint32_t shard_index{0};
    uint32_t program_count{0};

    explicit constexpr ShardSourceTerminalLayoutV2(
        uint32_t start = 0)
        : base(start),
          source_opening_value_base(base),
          source_opening_mask_base(
              source_opening_value_base +
              kSourceOpeningLanesV2),
          source_coordinate_base(
              source_opening_mask_base +
              kSourceOpeningLanesV2),
          source_parent_q(source_coordinate_base + 3),
          source_proof_identity_base(source_parent_q + 1),
          source_fs_seed_identity_base(
              source_proof_identity_base +
              kIdentityLimbsV2),
          source_prechallenge_identity_base(
              source_fs_seed_identity_base +
              kIdentityLimbsV2),
          shard_program_identity_base(
              source_prechallenge_identity_base +
              kIdentityLimbsV2),
          shard_prechallenge_identity_base(
              shard_program_identity_base +
              kIdentityLimbsV2),
          shard_index(
              shard_prechallenge_identity_base +
              kIdentityLimbsV2),
          program_count(shard_index + 1)
    {
    }

    [[nodiscard]] constexpr uint32_t SourceOpeningValue(
        uint32_t lane) const
    {
        return source_opening_value_base + lane;
    }
    [[nodiscard]] constexpr uint32_t SourceOpeningMask(
        uint32_t lane) const
    {
        return source_opening_mask_base + lane;
    }
    [[nodiscard]] constexpr uint32_t SourceCoordinate(
        uint32_t coordinate) const
    {
        return source_coordinate_base + coordinate;
    }
    [[nodiscard]] constexpr uint32_t End() const
    {
        return program_count + 1;
    }
};

/**
 * Production arity-two receipt prerequisite.
 *
 * This extends V1 rather than replacing its local-q relation.  In addition
 * to V1's `BytecodeBusLayout::Value(3) == expected_local_q`, it binds the
 * common source-parent q to the actual shard FoldBus hash-opening columns and
 * exports the source proof/FS/prechallenge plus shard program/prechallenge
 * identities as injective u32 limbs on every query.
 */
struct ShardSourceTerminalBindingV2 {
    uint16_t version{kShardReceiptVersionV2};
    uint32_t source_current_width{0};
    uint32_t source_hash_column_base{0};
    rr::ShardTerminalBindingV1 local;
    ShardSourceTerminalLayoutV2 layout;
    uint256 source_proof_commitment{};
    uint256 source_fs_seed{};
    uint256 source_prechallenge_commitment{};
    uint256 statement_commitment{};
    std::vector<gf::Fp3> source_parent_q_per_query;
    std::vector<std::array<gf::Fp, 3>>
        source_parent_q_coordinates;
    std::vector<SourceOpeningExportV2> source_opening_exports;
    bool source_child_native_verified{false};
    bool source_opening_direct_aliases{false};
    bool source_q_reconstruction_constrained{false};
    bool identities_u32_preprocessed{false};
    bool local_q_v1_constrained{false};
    bool valid{false};
    std::string note;
};

struct ShardReceiptV2 {
    uint16_t version{kShardReceiptVersionV2};
    uint32_t shard_index{0};
    uint32_t program_count{0};
    uint32_t queries{0};
    uint32_t n_rows{0};
    uint32_t n_columns{0};
    uint32_t n_constraints{0};
    uint32_t source_current_width{0};
    uint256 program_commitment{};
    uint256 bytecode_prechallenge_commitment{};
    uint256 source_proof_commitment{};
    uint256 source_fs_seed{};
    uint256 source_prechallenge_commitment{};
    uint256 statement_commitment{};
    uint256 receipt_fs_seed{};
    uint256 proof_commitment{};
    uint256 receipt_root{};
    std::vector<uint32_t> query_indices;
    std::vector<gf::Fp3> local_q_per_query;
    std::vector<gf::Fp3> source_parent_q_per_query;
    std::vector<unsigned char> proof_bytes;
};

struct ShardReceiptProveResultV2 {
    bool valid{false};
    bool binding_valid{false};
    bool proved{false};
    bool verified{false};
    bool canonical_codec_round_trip{false};
    bool proof_tamper_rejected{false};
    bool source_opening_forgery_rejected{false};
    bool wire_fits{false};
    /** Intentionally false until this receipt is consumed by the L2 parent. */
    bool recursively_consumed_by_parent{false};
    uint64_t prove_micros{0};
    uint64_t verify_micros{0};
    uint64_t encoded_bytes{0};
    ShardReceiptV2 receipt;
    std::string note;
};

/**
 * Build and append the V2 relation.  The source proof is natively verified,
 * its canonical fold-bus is reconstructed, and the attached shard must carry
 * the identical source q coordinates before any public columns are added.
 */
[[nodiscard]] ShardSourceTerminalBindingV2
BindShardSourceTerminalsV2(
    fp::FoldBusComposition& attached_shard,
    const fp::BytecodeInterpreterAttachment& interpreter,
    uint32_t shard_index,
    const aq::AirConstraintSystem<gf::Fp3>& source_child_cs,
    const fp::AlgAirProof& source_child_proof,
    const uint256& source_child_fs_seed,
    uint32_t source_current_width);

[[nodiscard]] uint256
ComputeShardSourceStatementCommitmentV2(
    const ShardSourceTerminalBindingV2& binding,
    uint32_t n_rows,
    uint32_t n_columns,
    uint32_t n_constraints);

[[nodiscard]] uint256 ComputeShardReceiptFsSeedV2(
    const ShardSourceTerminalBindingV2& binding,
    uint32_t n_rows,
    uint32_t n_columns,
    uint32_t n_constraints);

[[nodiscard]] uint256 ComputeShardReceiptRootV2(
    const ShardReceiptV2& receipt);

[[nodiscard]] ShardReceiptProveResultV2 ProveShardReceiptV2(
    const fp::FoldBusComposition& attached_shard,
    const ShardSourceTerminalBindingV2& binding);

/**
 * The source proof is an explicit verifier input.  Replacing it with another
 * valid proof (even one paired with identical shard-local q values) changes
 * the committed identity and is rejected.
 */
[[nodiscard]] bool VerifyShardReceiptV2(
    const aq::AirConstraintSystem<gf::Fp3>& source_child_cs,
    const fp::AlgAirProof& source_child_proof,
    const uint256& source_child_fs_seed,
    const aq::AirConstraintSystem<gf::Fp3>& shard_cs,
    const ShardSourceTerminalBindingV2& expected_binding,
    const ShardReceiptV2& receipt,
    std::string* why = nullptr);

[[nodiscard]] bool SerializeShardReceiptV2(
    const ShardReceiptV2& receipt,
    std::vector<unsigned char>& out,
    std::string* why = nullptr);

[[nodiscard]] std::optional<ShardReceiptV2>
DeserializeShardReceiptV2(
    const std::vector<unsigned char>& bytes,
    std::string* why = nullptr);

inline constexpr bool kShardReceiptExecutableV2 = true;
inline constexpr bool kShardReceiptRecursiveOwnershipReadyV2 = false;
static_assert(kShardReceiptExecutableV2);
static_assert(!kShardReceiptRecursiveOwnershipReadyV2);

} // namespace matmul::v4::rc::recursive_receipt_v2

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_RECURSIVE_RECEIPT_V2_H
