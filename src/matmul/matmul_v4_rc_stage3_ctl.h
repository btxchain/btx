// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_CTL_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_CTL_H

#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_stage3.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace matmul::v4::rc {

inline constexpr uint32_t kRCStage3CtlPinMagic = 0x314C5443U; // "CTL1"
inline constexpr uint16_t kRCStage3CtlVersion = 3;
inline constexpr uint32_t kRCStage3CtlRelationExportMagic =
    0x31585443U; // "CTX1"
inline constexpr uint16_t kRCStage3CtlRelationExportVersion = 1;
inline constexpr size_t kRCStage3CtlRelationExportBytes = 252;
inline constexpr uint32_t kRCStage3CtlMaxEvents = 1U << 24;
inline constexpr size_t kRCStage3CtlRecursivePinElements = 44;
/** Each Fp3 candidate scans the eight u64 words in exactly two SHA256d
 * blocks and takes the first three words below p.  Conditioned on finding
 * three, the coordinates are independent uniform Fp elements. */
inline constexpr uint32_t kRCStage3CtlChallengeBlockCount = 2;
inline constexpr uint32_t kRCStage3CtlChallengeWordsPerBlock = 4;
inline constexpr uint32_t kRCStage3CtlChallengeMaxCandidates = 8;
inline constexpr bool kRCStage3CtlUniformChallengeSampling = true;
[[nodiscard]] constexpr bool RCStage3CtlChallengeWordIsAccepted(uint64_t word)
{
    return word < gkr_field::kP;
}

/**
 * One fixed-IR bus port. Namespace, stage and address are public/preprocessed;
 * only the Fp3 value is witness data. Positive multiplicity sends a value,
 * negative multiplicity receives it. There are no mutable cells: callers use
 * a fresh stage-qualified address for every write.
 */
struct RCStage3CtlEvent {
    uint32_t namespace_id{0};
    uint32_t stage{0};
    uint32_t address{0};
    int8_t multiplicity{0}; // exactly +1 or -1

    bool operator==(const RCStage3CtlEvent&) const = default;
};

struct RCStage3CtlSchedule {
    std::vector<RCStage3CtlEvent> events;

    bool operator==(const RCStage3CtlSchedule&) const = default;
};

struct RCStage3CtlChallenges {
    gkr_field::Fp3 gamma1{};
    gkr_field::Fp3 gamma2{};
    gkr_field::Fp3 alpha1{};
    gkr_field::Fp3 alpha2{};

    bool operator==(const RCStage3CtlChallenges& other) const
    {
        return gkr_field::Eq(gamma1, other.gamma1) &&
               gkr_field::Eq(gamma2, other.gamma2) &&
               gkr_field::Eq(alpha1, other.alpha1) &&
               gkr_field::Eq(alpha2, other.alpha2);
    }
};

struct RCStage3CtlTerminal {
    gkr_field::Fp3 alpha1_sum{};
    gkr_field::Fp3 alpha2_sum{};

    bool operator==(const RCStage3CtlTerminal& other) const
    {
        return gkr_field::Eq(alpha1_sum, other.alpha1_sum) &&
               gkr_field::Eq(alpha2_sum, other.alpha2_sum);
    }
};

/**
 * Immutable expected participant. This is consensus/public-program data, not
 * supplied by the prover. The schedule commitment binds every ordered
 * namespace/stage/address/multiplicity port.
 */
struct RCStage3CtlParticipantSpec {
    RCStage3RelationRole role{};
    uint64_t event_count{0};
    uint64_t send_count{0};
    uint64_t receive_count{0};
    uint256 schedule_commitment{};

    bool operator==(const RCStage3CtlParticipantSpec&) const = default;
};

struct RCStage3CtlManifest {
    uint32_t bus_id{0};
    uint256 transcript_seed{};
    std::vector<RCStage3CtlParticipantSpec> participants;

    bool operator==(const RCStage3CtlManifest&) const = default;
};

/**
 * Per-child public data required by recursion. trace_commitment is absorbed
 * before lookup challenges. auxiliary_commitment and terminal sums are
 * produced after the challenges, avoiding a Fiat-Shamir fixed point.
 */
struct RCStage3CtlChildPin {
    uint32_t magic{kRCStage3CtlPinMagic};
    uint16_t version{kRCStage3CtlVersion};
    RCStage3RelationRole role{};
    uint32_t bus_id{0};
    uint64_t event_count{0};
    uint64_t send_count{0};
    uint64_t receive_count{0};
    uint256 schedule_commitment{};
    uint256 trace_commitment{};
    uint256 auxiliary_commitment{};
    uint256 challenge_commitment{};
    RCStage3CtlTerminal terminal{};

    bool operator==(const RCStage3CtlChildPin&) const = default;
};

/**
 * Public commitment bridge from one registered relation leaf to the five
 * prechallenge columns consumed by its CTL child proof.
 *
 * `prechallenge_column_roots` are NAMESPACE, STAGE, ADDRESS, VALUE and
 * MULTIPLICITY. The CTL verifier checks them against the executed child AIR.
 * A role-specific relation verifier must still prove that VALUE is its own
 * witness column; a generic public hash cannot establish that last equality.
 */
struct RCStage3CtlRelationExportPin {
    uint32_t magic{kRCStage3CtlRelationExportMagic};
    uint16_t version{kRCStage3CtlRelationExportVersion};
    RCStage3RelationRole role{};
    uint32_t bus_id{0};
    uint64_t event_count{0};
    uint256 relation_commitment{};
    uint256 schedule_commitment{};
    uint32_t n_rows{0};
    uint32_t n_coeffs{0};
    std::array<uint256, 5> prechallenge_column_roots{};

    bool operator==(const RCStage3CtlRelationExportPin&) const = default;
};

/** Column layout of the generic CTL accumulator AIR. */
namespace stage3_ctl_col {
enum : uint32_t {
    NAMESPACE = 0,
    STAGE,
    ADDRESS,
    VALUE,
    MULTIPLICITY,
    INVERSE1,
    INVERSE2,
    RUNNING1,
    RUNNING2,
    NUM_COLUMNS,
};
} // namespace stage3_ctl_col

struct RCStage3CtlAirSpec {
    RCStage3CtlSchedule schedule;
    RCStage3CtlChallenges challenges;
    RCStage3CtlTerminal expected_terminal;
};

struct RCStage3CtlWitness {
    bool ok{false};
    std::string note;
    RCStage3CtlTerminal terminal{};
    std::vector<std::vector<gkr_field::Fp3>> columns;
};

/**
 * Degree-two, no-padding CTL used by normalized Stage-3 leaves.
 *
 * The older generic CTL supports a zero-multiplicity padding tail.  Its
 * active selector is M^2, which raises the inverse relation to degree four
 * and therefore pads the quotient commitment to 4N.  Normalized relation
 * leaves already have exact power-of-two schedules with every row active.
 * For that case M is immutable public data in {+1,-1}; the inverse identity
 * is simply INV*(alpha-compressed)=1.  TERM=M*INV is materialized as a
 * witness column, keeping the accumulator transition and terminal rules
 * linear.  Every constraint has algebraic degree at most two and
 * QuotientLen() <= N, so the common commitment coefficient count is exactly
 * N.
 *
 * This is a new, explicitly versioned layout.  It does not reinterpret old
 * CTL proofs.
 */
inline constexpr uint16_t kRCStage3CtlDegree2Version = 1;

namespace stage3_ctl_degree2_col {
enum : uint32_t {
    NAMESPACE = 0,
    STAGE,
    ADDRESS,
    VALUE,
    MULTIPLICITY,
    INVERSE1,
    INVERSE2,
    TERM1,
    TERM2,
    RUNNING1,
    RUNNING2,
    NUM_COLUMNS,
};
} // namespace stage3_ctl_degree2_col

struct RCStage3CtlDegree2AirSpec {
    uint16_t version{kRCStage3CtlDegree2Version};
    RCStage3CtlSchedule schedule;
    RCStage3CtlChallenges challenges;
    RCStage3CtlTerminal expected_terminal;
};

struct RCStage3CtlDegree2Witness {
    uint16_t version{kRCStage3CtlDegree2Version};
    bool ok{false};
    std::string note;
    RCStage3CtlTerminal terminal{};
    std::vector<std::vector<gkr_field::Fp3>> columns;
};

/** Exact schedules only: event count must itself be a power of two. */
[[nodiscard]] air_quotient::AirConstraintSystem<gkr_field::Fp3>
BuildRCStage3CtlDegree2ConstraintSystem(
    const RCStage3CtlDegree2AirSpec& spec);
[[nodiscard]] RCStage3CtlDegree2Witness
BuildRCStage3CtlDegree2Witness(
    const RCStage3CtlSchedule& schedule,
    const std::vector<gkr_field::Fp3>& values,
    const RCStage3CtlChallenges& challenges);

/**
 * Epoch-one commitment for the exact-row degree-two layout.  The five
 * prechallenge columns have the same order as the generic CTL, but their
 * common coefficient count is exactly N rather than 4N.  These helpers let a
 * same-trace relation product bind the child pin without silently changing
 * the relation column roots.
 */
[[nodiscard]] uint256
ComputeRCStage3CtlDegree2PrechallengeTraceCommitment(
    const RCStage3CtlSchedule& schedule,
    const std::vector<gkr_field::Fp3>& values);
[[nodiscard]] uint256
ComputeRCStage3CtlDegree2PrechallengeTraceCommitmentFromRoots(
    const RCStage3CtlSchedule& schedule,
    uint32_t n_rows,
    uint32_t n_coeffs,
    const std::array<uint256, 5>& roots);

/**
 * Exact algebraic accounting for a set of independently domain-separated
 * CTL buses.  This is deliberately separate from FRI/AIR and random-oracle
 * soundness:
 *
 *  - every bus' base tuple/value commitment must precede gamma/alpha;
 *  - each event_count is manifest-bound and strictly below char(Fp3);
 *  - the two (gamma, alpha) lanes are independently domain-separated;
 *  - alpha hitting a denominator pole makes the AIR unsatisfiable.  It is an
 *    honest-prover/completeness loss, not a false-accept soundness term.
 *
 * For a malformed fixed bus with E signed events, one lane has at most
 * 3(E-1) bad tuple-compression challenges and E-1 bad rational-identity
 * evaluation challenges.  Two independent lanes therefore contribute at
 * most [4(E-1)]^2 / |Fp3|^2.  The ledger sums this exact numerator over
 * buses before charging the declared invocation union and grinding losses.
 */
struct RCStage3CtlSoundnessLedger {
    uint64_t bus_count{0};
    uint64_t total_events{0};
    uint64_t dual_lane_false_accept_numerator{0};
    uint64_t pole_completeness_numerator{0};
    uint32_t algebraic_bits_before_losses{0};
    uint32_t false_accept_bits_after_losses{0};
    uint32_t pole_completeness_bits_after_losses{0};
    uint32_t sampler_exhaustion_bits_after_losses{0};
    bool manifests_exact{false};
    bool commit_then_challenge{false};
    bool independent_domain_separated_lanes{false};
    bool uniform_challenge_sampling{false};
    bool bounded_challenge_sampling{false};
    /** Remains false until these child proofs are consumed by the unified
     * recursive root and its Fiat-Shamir/BCS reduction is complete. */
    bool reduction_complete{false};
};

[[nodiscard]] RCStage3CtlSoundnessLedger AssessRCStage3CtlSoundness(
    const std::vector<RCStage3CtlManifest>& manifests,
    uint32_t grinding_bits,
    uint64_t invocation_union_bound = 1);

/** Canonical fixed-schedule validation and commitment. */
[[nodiscard]] bool ValidateRCStage3CtlSchedule(
    const RCStage3CtlSchedule& schedule,
    std::string* why = nullptr);
[[nodiscard]] uint256 CommitRCStage3CtlSchedule(
    const RCStage3CtlSchedule& schedule);

/** Deterministic tuple compression for one challenge:
 * namespace + gamma*stage + gamma^2*address + gamma^3*value.
 *
 * The v3 bus evaluates this map at two independently derived gamma values.
 * Merely checking two denominator points for one compressed tuple would not
 * square the tuple-collision term: one gamma collision defeats both points. */
[[nodiscard]] gkr_field::Fp3 CompressRCStage3CtlTuple(
    const RCStage3CtlEvent& event,
    const gkr_field::Fp3& value,
    const gkr_field::Fp3& gamma);

/**
 * Challenge derivation absorbs the manifest and each ordered child trace root,
 * but excludes auxiliary roots and terminal sums.
 */
[[nodiscard]] bool DeriveRCStage3CtlChallenges(
    const RCStage3CtlManifest& manifest,
    const std::vector<RCStage3CtlChildPin>& prechallenge_pins,
    RCStage3CtlChallenges& out,
    std::string* why = nullptr);
[[nodiscard]] uint256 CommitRCStage3CtlChallenges(
    const RCStage3CtlChallenges& challenges);

/** Reusable proof-only AIR and honest prover witness builder. The verifier
 * rebuilds the AIR from the public schedule/challenges/terminal. */
[[nodiscard]] air_quotient::AirConstraintSystem<gkr_field::Fp3>
BuildRCStage3CtlConstraintSystem(const RCStage3CtlAirSpec& spec);
[[nodiscard]] RCStage3CtlWitness BuildRCStage3CtlWitness(
    const RCStage3CtlSchedule& schedule,
    const std::vector<gkr_field::Fp3>& values,
    const RCStage3CtlChallenges& challenges);

/**
 * Executable native CTL child proof.
 *
 * Columns NAMESPACE..MULTIPLICITY form epoch 1.  Their roots are committed
 * before gamma/alpha and hash to child.trace_commitment.  Columns
 * INVERSE1..RUNNING2 and the quotient form epoch 2 and hash to
 * child.auxiliary_commitment.  This split removes the otherwise circular
 * dependency between lookup challenges and inverse/running-sum columns.
 *
 * This uses the current SHA256d-Merkle Fp3 AIR backend.  Native verification
 * is real, but recursive consumption by the normalized root is still a
 * separate, fail-closed obligation.
 */
using RCStage3CtlAirProof =
    air_quotient::AirQuotientProof<gkr_field::Fp3>;

[[nodiscard]] uint256 ComputeRCStage3CtlPrechallengeTraceCommitment(
    const RCStage3CtlSchedule& schedule,
    const std::vector<gkr_field::Fp3>& values);
[[nodiscard]] uint256 ComputeRCStage3CtlPrechallengeTraceCommitmentFromRoots(
    const RCStage3CtlSchedule& schedule,
    uint32_t n_rows,
    uint32_t n_coeffs,
    const std::array<uint256, 5>& roots);
[[nodiscard]] uint256 ComputeRCStage3CtlAuxiliaryCommitment(
    const RCStage3CtlAirProof& proof);
[[nodiscard]] uint256 ComputeRCStage3CtlAirSeed(
    const RCStage3CtlManifest& manifest,
    const RCStage3CtlChildPin& pin);
[[nodiscard]] bool VerifyRCStage3CtlChildAirProof(
    const RCStage3CtlManifest& manifest,
    const std::vector<RCStage3CtlChildPin>& pins,
    size_t child_index,
    const RCStage3CtlSchedule& schedule,
    const RCStage3CtlAirProof& proof,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyRCStage3CtlBusAirProofs(
    const RCStage3CtlManifest& manifest,
    const std::vector<RCStage3CtlChildPin>& pins,
    const std::vector<RCStage3CtlSchedule>& schedules,
    const std::vector<RCStage3CtlAirProof>& proofs,
    std::string* why = nullptr);

/** Canonical bounded child-pin codec and binding. */
[[nodiscard]] bool SerializeRCStage3CtlChildPin(
    const RCStage3CtlChildPin& pin,
    std::vector<unsigned char>& out,
    std::string* why = nullptr);
[[nodiscard]] std::optional<RCStage3CtlChildPin>
DeserializeRCStage3CtlChildPin(const std::vector<unsigned char>& bytes,
                               std::string* why = nullptr);
[[nodiscard]] uint256 CommitRCStage3CtlChildPin(
    const RCStage3CtlChildPin& pin);

[[nodiscard]] bool SerializeRCStage3CtlRelationExportPin(
    const RCStage3CtlRelationExportPin& pin,
    std::vector<unsigned char>& out,
    std::string* why = nullptr);
[[nodiscard]] std::optional<RCStage3CtlRelationExportPin>
DeserializeRCStage3CtlRelationExportPin(
    const std::vector<unsigned char>& bytes,
    std::string* why = nullptr);
[[nodiscard]] uint256 CommitRCStage3CtlRelationExportPin(
    const RCStage3CtlRelationExportPin& pin);
[[nodiscard]] bool VerifyRCStage3CtlRelationExportBinding(
    const RCStage3CtlRelationExportPin& relation_export,
    const RCStage3CtlChildPin& child,
    const RCStage3CtlSchedule& schedule,
    const RCStage3CtlAirProof& proof,
    const uint256& expected_relation_commitment,
    std::string* why = nullptr);

/** Collision-free base-field representation for the recursive verifier:
 * uint64 counts are split into uint32 limbs and 256-bit hashes into eight
 * uint32 limbs. */
[[nodiscard]] bool EncodeRCStage3CtlChildPinForRecursion(
    const RCStage3CtlChildPin& pin,
    std::vector<gkr_field::Fp3>& out,
    std::string* why = nullptr);

/**
 * Public-pin composition only. This is not an AIR-proof verifier.
 *
 * Requires exact ordered manifest coverage, identical bus/challenge binding,
 * exact schedule/count pins, and both signed LogUp terminal sums equal zero.
 * No native episode/coupled witness is consulted.
 */
[[nodiscard]] bool VerifyRCStage3CtlPublicPinComposition(
    const RCStage3CtlManifest& manifest,
    const std::vector<RCStage3CtlChildPin>& pins,
    std::string* why = nullptr);
[[nodiscard]] uint256 CommitRCStage3CtlComposition(
    const RCStage3CtlManifest& manifest,
    const std::vector<RCStage3CtlChildPin>& pins);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_CTL_H
