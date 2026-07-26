// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_RECURSIVE_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_RECURSIVE_H

#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_stage3.h>
#include <matmul/matmul_v4_rc_stage3_ctl.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace matmul::v4::rc {

inline constexpr uint32_t kRCStage3RecursiveMagic = 0x33524741U; // "AGR3"
inline constexpr uint16_t kRCStage3RecursiveVersion = 2;
inline constexpr uint16_t kRCStage3ConstraintRegistryVersion = 2;
inline constexpr uint32_t kRCStage3RecursiveMaxChildren = 4;
inline constexpr size_t kRCStage3RecursiveMaxBytes = kRCStage3MaxProofBytes;
inline constexpr uint32_t kRCStage3RecursiveTargetSoundnessBits = 100;

/**
 * One child verifier's serializable public pins.
 *
 * ChildPublicInputs::child_constraints is required to be empty on the wire.
 * The verifier reconstructs callbacks from (registry_version, role) locally;
 * serializing std::function targets would be process-dependent and unsafe.
 */
struct RCStage3RecursiveChildPin {
    air_recurse::ChildPublicInputs public_inputs;

    bool operator==(const RCStage3RecursiveChildPin& other) const;
};

/**
 * One recursive root for one fixed Stage-3 relation role.
 *
 * fixed_role_commitment is the canonical commitment to the role plus all
 * serializable child pins. Those pins include the child row/fold/trace roots
 * and exist before the aggregate root is proved. It must never be a hash of
 * `root`, of a Stage-3 proof section, or of this carrier.
 */
struct RCStage3RecursiveProof {
    using AlgB3 = air_quotient::AirFriBackendAlg<gkr_field::Fp3>;

    uint32_t magic{kRCStage3RecursiveMagic};
    uint16_t version{kRCStage3RecursiveVersion};
    uint16_t registry_version{kRCStage3ConstraintRegistryVersion};
    RCStage3RelationRole role{};
    uint256 fixed_role_commitment{};
    /** Canonical CommitRCStage3CtlChildPin for this relation role. It is
     * absorbed into fixed_role_commitment and therefore into the role seed. */
    uint256 ctl_child_commitment{};
    std::vector<RCStage3RecursiveChildPin> children;
    air_quotient::AirQuotientProof<gkr_field::Fp3, AlgB3> root;
};

/**
 * Local-only role registry callback. Implementations must return the complete,
 * immutable AIR for `role` and must derive every shape/public constant from
 * `pin`; the callback itself is never serialized.
 */
using RCStage3ConstraintResolver = std::function<bool(
    RCStage3RelationRole role,
    const air_recurse::ChildPublicInputs& pin,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    std::string* why)>;

/** Built-in immutable registry. It currently fails closed for every role
 * because the tree has no complete proof-only role AIR. */
[[nodiscard]] bool ResolveCurrentRCStage3RelationConstraintSystem(
    RCStage3RelationRole role,
    const air_recurse::ChildPublicInputs& pin,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    std::string* why = nullptr);

/** Mandatory family selection. There is no serialized family toggle. */
[[nodiscard]] constexpr air_recurse::VerifierAirFamilies
RCStage3MandatoryVerifierAirFamilies()
{
    return {true, true, true, true, true, true};
}

/** Canonical codec. The root FRI proof and supplemental row-wise openings are
 * bounded independently before allocation. */
[[nodiscard]] bool SerializeRCStage3RecursiveProof(
    const RCStage3RecursiveProof& proof,
    std::vector<unsigned char>& out,
    std::string* why = nullptr);
[[nodiscard]] std::optional<RCStage3RecursiveProof>
DeserializeRCStage3RecursiveProof(const std::vector<unsigned char>& bytes,
                                  std::string* why = nullptr);

/**
 * Immutable position of a recursion node (and, for a child, its slot within the
 * parent) in the Stage-3 aggregation tree.
 *
 * Binding it into every Fiat-Shamir point makes each node/slot derive
 * position-unique challenges and makes a child receipt non-transferable across
 * slots (soundness blocker P4). `node_id` is the identity of THIS recursion node
 * in the tree; `slot_index` is the child's ordinal in its parent's arity-<=4
 * layout. The position is supplied by the tree walker / parent layout (NOT
 * self-declared inside a carrier), so an adversary cannot relabel a receipt into
 * whatever slot it is being replayed at.
 */
struct RCStage3RecursivePosition {
    uint64_t node_id{0};
    uint32_t slot_index{0};

    bool operator==(const RCStage3RecursivePosition& other) const
    {
        return node_id == other.node_id && slot_index == other.slot_index;
    }
    bool operator!=(const RCStage3RecursivePosition& other) const
    {
        return !(*this == other);
    }
};

/**
 * Role-specific aggregate seed. The base is exactly
 * ComputeRCStage3AggregationSeed(statement), then domain-separated by role, its
 * pre-proof commitment, and the node's tree position (node_id, slot_index).
 * Root bytes, proof sections, and the transcript commitment are excluded, so
 * proving has no fixed-point dependency. Binding the position (P4) makes two
 * distinct tree nodes derive distinct FS bases even at the same role/commitment.
 */
[[nodiscard]] uint256 ComputeRCStage3RecursiveRoleSeed(
    const RCStage3SuccinctProof& statement,
    RCStage3RelationRole role,
    const uint256& fixed_role_commitment,
    const RCStage3RecursivePosition& position = {});

/**
 * Position-bound Fiat-Shamir point for a single child receipt. It
 * domain-separates the base child FS seed by (role, node_id, slot_index) so the
 * per-child challenges a child proof commits (air_lambda, fold challenges, ...)
 * only re-derive at the exact tree slot they were proved for. A receipt lifted
 * to a different node or slot re-derives to different challenges and is rejected.
 */
[[nodiscard]] uint256 ComputeRCStage3RecursiveChildFsPoint(
    const uint256& base_child_fs_seed,
    RCStage3RelationRole role,
    const RCStage3RecursivePosition& position);

/**
 * Re-derive the child's pinned AIR-batching challenge (air_lambda) from the
 * position-bound child FS point and check it matches the value the receipt
 * committed. This is the concrete P4 cross-slot replay check: it returns false
 * when `pin` is presented at a (node_id, slot_index) other than the one whose FS
 * point produced its committed challenge.
 */
[[nodiscard]] bool VerifyRCStage3RecursiveChildFsBinding(
    const uint256& base_child_fs_seed,
    RCStage3RelationRole role,
    const RCStage3RecursivePosition& position,
    const air_recurse::ChildPublicInputs& pin,
    std::string* why = nullptr);

/** Proof-independent commitment to the role and canonical child pins. */
[[nodiscard]] uint256 ComputeRCStage3RecursiveChildPinsCommitment(
    RCStage3RelationRole role,
    const uint256& ctl_child_commitment,
    const std::vector<RCStage3RecursiveChildPin>& children);

/** Exact bridge from a recursive role proof to the CTL terminal public data
 * carried by the unified root. This validates only the binding, not the AIR. */
[[nodiscard]] bool ValidateRCStage3RecursiveCtlBinding(
    const RCStage3RecursiveProof& proof,
    const RCStage3CtlChildPin& ctl_pin,
    std::string* why = nullptr);

enum class RCStage3RecursiveGapCode : uint8_t {
    MalformedCarrier = 1,
    RoleNotRequired = 2,
    FixedCommitmentMismatch = 3,
    ConstraintRegistryUnavailable = 4,
    BackendColumnCapExceeded = 5,
    BackendLdeCapExceeded = 6,
    SoundnessTargetNotMet = 7,
    ChildFiatShamirReplayNotClosed = 8,
    SelfSimilarFixedPointNotClosed = 9,
    ProductionPerformanceUnmeasured = 10,
    AuthorityDisabled = 11,
};

struct RCStage3RecursiveGap {
    RCStage3RecursiveGapCode code{};
    RCStage3RelationRole role{};
    std::string detail;
};

struct RCStage3RecursiveReadiness {
    bool structurally_valid{false};
    bool mandatory_families{true};
    bool constraints_resolved{false};
    bool backend_shape_supported{false};
    /** Mathematical verifier preconditions only. This deliberately excludes
     * activation and performance policy, so verification readiness cannot
     * depend circularly on the consensus-authority gate it is meant to
     * justify. */
    bool cryptographic_verification_ready{false};
    bool production_ready{false};
    uint32_t soundness_bits{0};
    air_recurse::VerifierAirMeasurement measurement{};
    std::vector<RCStage3RecursiveGap> gaps;
};

/** Exact, deterministic readiness report. This does not run a prover or native
 * episode/coupled replay. */
[[nodiscard]] RCStage3RecursiveReadiness AssessRCStage3RecursiveReadiness(
    const RCStage3SuccinctProof& statement,
    const RCStage3RecursiveProof& proof,
    const RCStage3ConstraintResolver& resolver =
        ResolveCurrentRCStage3RelationConstraintSystem);

/**
 * Proof verification entry point. It calls air_recurse::VerifyAggregate only
 * after the readiness report has no gaps, all child constraints have been
 * locally reconstructed, and current backend caps are satisfied.
 */
[[nodiscard]] bool VerifyRCStage3RecursiveProof(
    const RCStage3SuccinctProof& statement,
    const RCStage3RecursiveProof& proof,
    std::string* why = nullptr,
    const RCStage3RecursivePosition& position = {});

struct RCStage3RecursiveProveResult {
    bool ok{false};
    std::string note;
    RCStage3RecursiveProof proof;
    RCStage3RecursiveReadiness readiness;
};

/**
 * R&D prover seam over the existing ProveAggregate. `resolver` reconstructs
 * the role AIR locally and must agree with every child shape. The built-in
 * registry therefore returns fail-closed today; this function does not enable
 * consensus authority.
 */
[[nodiscard]] RCStage3RecursiveProveResult ProveRCStage3RecursiveProof(
    const RCStage3SuccinctProof& statement,
    RCStage3RelationRole role,
    const uint256& fixed_role_commitment,
    const uint256& ctl_child_commitment,
    const std::vector<air_quotient::AirQuotientProof<
        gkr_field::Fp3, air_quotient::AirFriBackendAlg<gkr_field::Fp3>>>& children,
    const uint256& child_fs_seed,
    const air_recurse::ChildPublicInputs& child_shape,
    const RCStage3ConstraintResolver& resolver =
        ResolveCurrentRCStage3RelationConstraintSystem,
    const RCStage3RecursivePosition& position = {});

/** Separate hard gate. Recursive codecs and diagnostics may ship while false. */
inline constexpr bool kRCStage3RecursiveAggregationReady = false;

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_RECURSIVE_H
