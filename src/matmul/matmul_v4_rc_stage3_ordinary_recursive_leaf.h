// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_ORDINARY_RECURSIVE_LEAF_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_ORDINARY_RECURSIVE_LEAF_H

#include <matmul/matmul_v4_rc_stage3_recursive_fixedpoint.h>
#include <matmul/matmul_v4_rc_stage3_recursive_hierarchy.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v13_proof_tape_air.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_ordinary_recursive_leaf {

namespace aq = air_quotient;
namespace fixedpoint = recursive_fixedpoint;
namespace gf = gkr_field;
namespace tape =
    stage3_multirow_v13_proof_tape_air;

inline constexpr uint16_t kVersionV1 = 1;

/**
 * Verifier-owned identity of one ordinary AlgAir leaf.
 *
 * `fs_seed` is supplied by the leaf protocol and must be independently
 * reconstructed by its verifier (for example, V3 tape derives it from the
 * public tape root, source inventory, shard schedule and terminal).  The
 * wrapper commits the recursive position and program identity without
 * changing that protocol transcript.
 */
struct PublicBindingV1 {
    uint16_t version{kVersionV1};
    uint256 node_binding{};
    uint256 program_binding{};
    uint256 proof_context_binding{};
    uint256 public_statement_binding{};
    uint256 fs_seed{};

    bool operator==(const PublicBindingV1&) const = default;
};

[[nodiscard]] uint256 CommitPublicBindingV1(
    const PublicBindingV1& binding,
    const uint256& constraint_system_commitment);

/**
 * Reconstruct the complete expected binding consumed by the V2 recursive
 * parent entry.  All fields come from the verifier-owned AIR and child
 * protocol statement, never from a receipt.
 */
[[nodiscard]] fixedpoint::NarrowRecursiveProofExpectedBindingV2
BuildExpectedRecursiveBindingV2(
    const aq::AirConstraintSystem<gf::Fp3>& expected_cs,
    const PublicBindingV1& expected_binding);

struct ProofV1 {
    PublicBindingV1 binding{};
    fixedpoint::NarrowRecursiveProofReceiptV1 receipt{};
    bool native_streaming_proof_verified{false};
    bool ordinary_reentry_verified{false};
    bool proof_tamper_rejected{false};
    bool valid{false};
    std::string note;
};

/**
 * Convert an already-produced ordinary streaming-row proof into the exact
 * canonical AlgAir receipt consumed by the existing narrow recursive parent.
 * No proof claim is replaced by a host boolean: both backend forms are
 * verified against the independently rebuilt AIR and the same FS seed.
 */
[[nodiscard]] ProofV1 RetainProofV1(
    const aq::AirConstraintSystem<gf::Fp3>& expected_cs,
    const aq::AirQuotientRowsProof& streaming_proof,
    const PublicBindingV1& binding);

/**
 * Retain a native Alg-FRI proof without routing it through the unrelated
 * streaming-row backend.  The proof is independently verified, canonically
 * serialized/decoded, and rebound to the same verifier-owned recursive
 * identity as RetainProofV1.
 */
[[nodiscard]] ProofV1 RetainAlgProofV1(
    const aq::AirConstraintSystem<gf::Fp3>& expected_cs,
    const fixedpoint::AlgAirProof& alg_proof,
    const PublicBindingV1& binding);

/** Convenience prover for ordinary one-epoch relations. */
[[nodiscard]] ProofV1 ProveV1(
    const aq::AirConstraintSystem<gf::Fp3>& expected_cs,
    const std::vector<std::vector<gf::Fp3>>& columns,
    const PublicBindingV1& binding);

/**
 * Reconstruct and validate the complete wrapper and proof.  The callback
 * bearing AIR stored in the receipt is never authoritative.
 */
[[nodiscard]] bool VerifyV1(
    const ProofV1& proof,
    const aq::AirConstraintSystem<gf::Fp3>& expected_cs,
    const PublicBindingV1& expected_binding,
    std::string* why = nullptr);

/**
 * Canonical V3 tape-shard specialization.  Its recursive identity is derived
 * entirely from the public shard statement and its AIR-constrained source
 * terminal; callers cannot supply or relabel a node/context binding.
 */
[[nodiscard]] PublicBindingV1
BuildTapeShardPublicBindingV1(
    const tape::ShardStatementV2& statement,
    const std::array<gf::Fp3, 2>& source_terminal);

struct TapeShardReceiptV1 {
    uint16_t version{kVersionV1};
    uint32_t shard_index{0};
    std::array<gf::Fp3, 2> source_terminal{};
    ProofV1 ordinary{};
    bool native_tape_verifier_accepted{false};
    bool canonical_payload_equal{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] TapeShardReceiptV1
RetainTapeShardProofV1(
    const tape::ShardStatementV2& statement,
    const tape::ShardProofV3& proof);

[[nodiscard]] bool VerifyTapeShardReceiptV1(
    const TapeShardReceiptV1& receipt,
    const tape::ShardStatementV2& expected_statement,
    std::string* why = nullptr);

} // namespace matmul::v4::rc::stage3_ordinary_recursive_leaf

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_ORDINARY_RECURSIVE_LEAF_H
