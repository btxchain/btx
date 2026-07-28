// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_UNIFIED_ROOT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_UNIFIED_ROOT_H

#include <matmul/matmul_v4_rc_fri_ext3_alg.h>
#include <matmul/matmul_v4_rc_stage3.h>
#include <matmul/matmul_v4_rc_stage3_ctl.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace matmul::v4::rc {

inline constexpr uint32_t kRCStage3UnifiedRootMagic = 0x31524D55U; // "UMR1"
inline constexpr uint16_t kRCStage3UnifiedRootVersion = 4;
inline constexpr uint16_t kRCStage3UnifiedRootRegistryVersion = 2;
inline constexpr size_t kRCStage3UnifiedRootMaxProofBytes =
    kRCStage3MaxProofBytes - 4096;
inline constexpr uint16_t kRCStage3UnifiedRoleCount = 14;
inline constexpr uint16_t kRCStage3UnifiedNormalizedLeafCount = 16;
inline constexpr uint16_t kRCStage3UnifiedInternalNodeCount = 15;
inline constexpr uint16_t kRCStage3UnifiedSoundnessSiteCount = 29;
/** Exact power-of-two union cap derived from the selected packed-four,
 * bounded-rejection production manifest. Root validation also recomputes it
 * from that manifest, so this format pin cannot silently become stale. */
inline constexpr uint64_t kRCStage3UnifiedMaxTotalProofSites = 1ULL << 36;
/**
 * Consensus security class for the site-unioned V1 authority.
 *
 * This is intentionally distinct from kRCFri3AlgTargetSoundnessBits: that
 * constant is the 100-bit per-proof FRI/backend screen, while the executable
 * global composition ledger certifies a 68-bit floor after charging the full
 * production site union. V1 selects the 64-bit class for that composed
 * result. Keeping the thresholds separate prevents a correctly composed
 * 68-bit proof from being permanently ineligible because a per-proof
 * diagnostic was reused as the global consensus threshold.
 */
inline constexpr uint16_t kRCStage3UnifiedV1SecurityClassBits = 64;
static_assert(
    kRCStage3UnifiedV1SecurityClassBits <
    kRCFri3AlgTargetSoundnessBits);
inline constexpr uint32_t kRCStage3UnifiedCtlBundleMagic = 0x42544355U; // "UCTB"
inline constexpr uint16_t kRCStage3UnifiedCtlBundleVersion = 2;
inline constexpr size_t kRCStage3UnifiedCtlBundleMaxBytes =
    kRCStage3MaxProofBytes;

/**
 * Versioned aggregation topology. This is format data, not a prover-selected
 * policy switch. Version 1 normalizes the fourteen relation leaves to sixteen
 * leaves and reduces them through one fixed binary tree.
 */
enum class RCStage3UnifiedTopology : uint8_t {
    NormalizedBinary16 = 1,
};

enum class RCStage3UnifiedFriBatchingMode : uint8_t {
    SinglePowerChallenge = 0,
    IndependentCoefficients = 1,
};

/**
 * Explicit proof-system and topology pins for the proposed single-root path.
 *
 * The 29 final-tree soundness sites are the fourteen relation leaves plus
 * fifteen internal nodes in the normalized sixteen-leaf binary tree. They are
 * only a sub-manifest: all-tile sharding creates far more lower-level proof
 * sites. The selected packed-four manifest derives an exact 2^26 union cap.
 * At Q=192 its legacy proximity diagnostic is
 *
 *   floor(192*log2(32/17)) - 40 - 26 = 109 bits.
 *
 * This is a parameter/schema result only. It is not evidence that the
 * corresponding recursive verifier AIR exists or meets its performance cap.
 */
struct RCStage3UnifiedRootParameters {
    RCStage3UnifiedTopology topology{
        RCStage3UnifiedTopology::NormalizedBinary16};
    uint8_t aggregation_arity{2};
    uint8_t aggregation_depth{4};
    uint16_t role_leaf_count{kRCStage3UnifiedRoleCount};
    uint16_t normalized_leaf_count{16};
    uint16_t fri_queries{
        static_cast<uint16_t>(kRCFri3AlgNumQueries)};
    /** Explicit V5 repetition pins. `fri_queries` above remains the legacy
     * single-Q192 integration parameter and is not reinterpreted as 2*Q128. */
    uint8_t fri_repetition_lanes{
        static_cast<uint8_t>(kRCFri3AlgDualNumLanes)};
    RCStage3UnifiedFriBatchingMode fri_batching_mode{
        RCStage3UnifiedFriBatchingMode::IndependentCoefficients};
    Fri3AlgDualCommitmentScenario fri_commitment_scenario{
        Fri3AlgDualCommitmentScenario::SharedMasterDerivedChildren};
    uint16_t fri_queries_per_lane{
        static_cast<uint16_t>(kRCFri3AlgDualQueriesPerLane)};
    uint16_t grinding_bits{
        static_cast<uint16_t>(kRCFriGrindingBits)};
    uint16_t target_soundness_bits{
        kRCStage3UnifiedV1SecurityClassBits};
    uint64_t soundness_union_bound_instances{
        kRCStage3UnifiedMaxTotalProofSites};
    uint32_t max_recursive_air_columns{16'384};

    bool operator==(const RCStage3UnifiedRootParameters&) const = default;
};

/**
 * One canonical role leaf. relation_commitment is the matching commitment in
 * the composed Stage-3 statement. ctl_child_commitment binds the role's
 * immutable CTL public pin; it is never inferred from process-local state.
 */
struct RCStage3UnifiedRolePin {
    RCStage3RelationRole role{};
    uint256 relation_commitment{};
    uint256 ctl_child_commitment{};

    bool operator==(const RCStage3UnifiedRolePin&) const = default;
};

enum class RCStage3UnifiedSoundnessSiteKind : uint8_t {
    RelationLeaf = 1,
    AggregationNode = 2,
};

/**
 * One explicitly charged soundness site. Padding leaves are deterministic
 * hashes and do not have proof sites. Internal nodes are ordered bottom-up,
 * left-to-right: 8 at level 1, then 4, 2 and 1.
 */
struct RCStage3UnifiedSoundnessSite {
    RCStage3UnifiedSoundnessSiteKind kind{};
    uint8_t tree_level{0};
    uint16_t tree_index{0};
    RCStage3RelationRole role{};
    uint16_t fri_queries{0};

    bool operator==(const RCStage3UnifiedSoundnessSite&) const = default;
};

enum class RCStage3UnifiedSoundnessTermKind : uint8_t {
    FriProximityAndGrinding = 1,
    Fp3TraceBatching = 2,
    Fp3ConstraintBatching = 3,
    CtlTupleCompression = 4,
    CtlDenominatorPoles = 5,
    HashCollision = 6,
    FiatShamirModel = 7,
    PowGrindingComposition = 8,
    FriFieldDomain = 9,
    GlobalFalseAcceptUnion = 10,
};

struct RCStage3UnifiedSoundnessTerm {
    RCStage3UnifiedSoundnessTermKind kind{};
    uint64_t charged_instances{0};
    uint32_t conservative_bits{0};
    bool quantitatively_accounted{false};
    bool reduction_complete{false};
    std::string detail;
};

/**
 * Conservative global ledger. certified_bits is deliberately zero until
 * every contributing term has both an explicit quantitative bound and a
 * complete reduction, including the additive union of distinct failure
 * events. provisional_known_term_bits is only the smallest known individual
 * exponent; it is diagnostic and is not a global soundness bound.
 */
struct RCStage3UnifiedSoundnessLedger {
    std::vector<RCStage3UnifiedSoundnessTerm> terms;
    uint32_t provisional_known_term_bits{0};
    uint32_t certified_bits{0};
    bool theorem_complete{false};
    bool authority_eligible{false};
};

/**
 * Public carrier for a future one-root recursive proof.
 *
 * Exactly fourteen role leaves are present in fixed registry order.
 * CompositionLink is deliberately separate: it binds the fifteenth relation
 * commitment without pretending that it is an independently witnessed
 * episode/coupled leaf. The CTL composition commitment binds the cross-role
 * terminal composition.
 *
 * The root Fiat-Shamir seed commits to every field above
 * normalized_recursive_root_commitment and recursive_proof. Excluding those
 * two proof outputs makes the dependency graph acyclic.
 */
struct RCStage3UnifiedRootPublicPin {
    uint32_t magic{kRCStage3UnifiedRootMagic};
    uint16_t version{kRCStage3UnifiedRootVersion};
    uint16_t registry_version{kRCStage3UnifiedRootRegistryVersion};
    RCStage3UnifiedRootParameters parameters{};
    uint256 statement_commitment{};
    uint256 final_digest{};
    std::vector<RCStage3UnifiedRolePin> roles;
    uint256 composition_link_commitment{};
    RCStage3CtlManifest ctl_manifest{};
    std::vector<RCStage3CtlChildPin> ctl_children;
    uint256 ctl_composition_commitment{};
    /** Commitment to the legacy fourteen-leaf/fifteen-node root sub-manifest. */
    uint256 soundness_manifest_commitment{};
    /** Commitment to the complete conditional V1 production-site inventory:
     * all relation leaves, below-root arity-four aggregation sites and the
     * final normalized tree. The verifier recomputes this value from frozen
     * production dimensions and the bounded-rejection policy. */
    uint256 production_site_manifest_commitment{};
    /** Commitment to the verifier-recomputed compact arity-four schedule for
     * every below-root site in production_site_manifest_commitment.  It fixes
     * all 28 family ranges and all 14 per-role reduction levels without
     * materializing the multi-million-site inventory. */
    uint256 production_aggregation_schedule_commitment{};
    uint256 normalized_leaf_tree_commitment{};
    uint256 normalized_recursive_root_commitment{};
    std::vector<unsigned char> recursive_proof;

    bool operator==(const RCStage3UnifiedRootPublicPin&) const = default;
};

/**
 * Native CTL proof object carried at one fixed unified-root role leaf.
 *
 * This is an executable bridge into the recursive seam, not an in-circuit
 * recursive verifier: the schedule and AirQuotient proof are verified
 * natively against the manifest and RCStage3CtlChildPin.
 */
struct RCStage3UnifiedCtlChildProof {
    RCStage3RelationRole role{};
    RCStage3CtlRelationExportPin relation_export{};
    RCStage3CtlSchedule schedule{};
    RCStage3CtlAirProof proof{};
};

/**
 * Canonical fixed-order bundle of all fourteen native CTL child proofs.
 * root_seed and ctl_composition_commitment bind the bundle to one exact
 * RCStage3UnifiedRootPublicPin without duplicating its manifest or pins.
 */
struct RCStage3UnifiedCtlProofBundle {
    uint32_t magic{kRCStage3UnifiedCtlBundleMagic};
    uint16_t version{kRCStage3UnifiedCtlBundleVersion};
    uint16_t registry_version{kRCStage3UnifiedRootRegistryVersion};
    uint256 root_seed{};
    uint256 ctl_composition_commitment{};
    std::vector<RCStage3UnifiedCtlChildProof> children;
};

/** Fourteen episode+coupled roles, excluding CompositionLink, in the only
 * permitted wire order. */
[[nodiscard]] const std::array<RCStage3RelationRole,
                               kRCStage3UnifiedRoleCount>&
RCStage3UnifiedRoleOrder();

/** Exact final-tree 14-leaf + 15-node sub-manifest in canonical order. */
[[nodiscard]] const std::array<RCStage3UnifiedSoundnessSite,
                               kRCStage3UnifiedSoundnessSiteCount>&
RCStage3UnifiedSoundnessSiteManifest();
[[nodiscard]] uint256 ComputeRCStage3UnifiedSoundnessManifestCommitment();
/** Recompute the selected complete conditional V1 production-site manifest
 * commitment. A null result means the checked manifest construction failed. */
[[nodiscard]] uint256
ComputeRCStage3UnifiedProductionSiteManifestCommitment();
/** Recompute and commit the exact compact arity-four consumption schedule for
 * the selected production-site manifest. */
[[nodiscard]] uint256
ComputeRCStage3UnifiedProductionAggregationScheduleCommitment();
[[nodiscard]] RCStage3UnifiedSoundnessLedger
AssessRCStage3UnifiedGlobalSoundness(
    const RCStage3UnifiedRootPublicPin& pin);

[[nodiscard]] constexpr RCStage3UnifiedRootParameters
CanonicalRCStage3UnifiedRootParameters()
{
    return {};
}

/** Integer post-grinding, post-candidate-budget proximity diagnostic. This is
 * not a certified global lower bound. */
[[nodiscard]] uint32_t RCStage3UnifiedRootSoundnessBits(
    const RCStage3UnifiedRootParameters& parameters);

/**
 * Proof-independent commitment to the composed public statement and all
 * fifteen ordered relation commitments. It excludes relation proof bytes and
 * transcript_commitment, so placing this carrier in a Stage-3 section cannot
 * create a commitment fixed point.
 */
[[nodiscard]] uint256 ComputeRCStage3UnifiedStatementCommitment(
    const RCStage3SuccinctProof& statement);

/**
 * Root Fiat-Shamir seed. It binds the statement/final digest, every ordered
 * relation and CTL child pin, the composition-link and CTL-composition pins,
 * and all topology/Q parameters. It excludes the recursive root and proof.
 */
[[nodiscard]] uint256 ComputeRCStage3UnifiedRootSeed(
    const RCStage3UnifiedRootPublicPin& pin);

/** Commitment to one role leaf's exact relation and CTL public data. */
[[nodiscard]] uint256 ComputeRCStage3UnifiedRoleLeafCommitment(
    const RCStage3UnifiedRolePin& role);

/**
 * Deterministic sixteen-leaf pre-proof tree. Leaves 0..13 are relation leaves;
 * leaf 14 binds CompositionLink and leaf 15 binds the CTL composition and
 * statement/final digest. This tree is part of the root seed.
 */
[[nodiscard]] uint256 ComputeRCStage3UnifiedNormalizedLeafTreeCommitment(
    const RCStage3UnifiedRootPublicPin& pin);

/**
 * Per-node Fiat-Shamir seed for executable bottom-up aggregation. It absorbs
 * the proof-independent root seed, level/index and both ordered child
 * commitments, while excluding the node proof and its output commitment.
 */
[[nodiscard]] uint256 ComputeRCStage3UnifiedAggregationNodeSeed(
    const uint256& root_seed,
    uint8_t tree_level,
    uint16_t tree_index,
    const uint256& left_child_commitment,
    const uint256& right_child_commitment);

/** Canonical binding between the advertised recursive root and proof bytes. */
[[nodiscard]] uint256 CommitRCStage3UnifiedRecursiveProof(
    const std::vector<unsigned char>& recursive_proof);

/** Structural carrier validation without consulting a Stage-3 statement or
 * running a proof verifier. */
[[nodiscard]] bool ValidateRCStage3UnifiedRootStructure(
    const RCStage3UnifiedRootPublicPin& pin,
    std::string* why = nullptr);

/** Exact public binding against a canonical composed Stage-3 statement. */
[[nodiscard]] bool ValidateRCStage3UnifiedRootPublicBinding(
    const RCStage3SuccinctProof& statement,
    const RCStage3UnifiedRootPublicPin& pin,
    std::string* why = nullptr);

/** Canonical bounded little-endian codec. */
[[nodiscard]] bool SerializeRCStage3UnifiedRootPublicPin(
    const RCStage3UnifiedRootPublicPin& pin,
    std::vector<unsigned char>& out,
    std::string* why = nullptr);
[[nodiscard]] std::optional<RCStage3UnifiedRootPublicPin>
DeserializeRCStage3UnifiedRootPublicPin(
    const std::vector<unsigned char>& bytes,
    std::string* why = nullptr);

/**
 * Strict native-CTL proof bridge for the unified root. It requires exact
 * role order/count, exact schedule/pin/manifest binding, verifies every
 * RCStage3CtlAirProof, and finally verifies the signed LogUp terminal
 * composition. Success does not imply recursive in-circuit consumption.
 */
[[nodiscard]] bool VerifyRCStage3UnifiedCtlProofBundle(
    const RCStage3UnifiedRootPublicPin& pin,
    const RCStage3UnifiedCtlProofBundle& bundle,
    std::string* why = nullptr);

/** Canonical bounded codec. Deserialization rejects trailing bytes and
 * non-canonical field encodings. Public-pin binding is checked by the
 * verifier above. */
[[nodiscard]] bool SerializeRCStage3UnifiedCtlProofBundle(
    const RCStage3UnifiedCtlProofBundle& bundle,
    std::vector<unsigned char>& out,
    std::string* why = nullptr);
[[nodiscard]] std::optional<RCStage3UnifiedCtlProofBundle>
DeserializeRCStage3UnifiedCtlProofBundle(
    const std::vector<unsigned char>& bytes,
    std::string* why = nullptr);
[[nodiscard]] uint256 CommitRCStage3UnifiedCtlProofBundle(
    const RCStage3UnifiedCtlProofBundle& bundle);

inline constexpr bool kRCStage3UnifiedCtlNativeProofBridgeExecutable = true;
// The declared relation export is equality-constrained to all five
// prechallenge columns of the executed CTL proof.
inline constexpr bool
    kRCStage3UnifiedCtlRelationExportCommitmentBridgeExecutable = true;
// Some role-specific relation verifiers now expose/equality-constrain their
// witness cells to CTL::VALUE, but this gate means every required semantic
// endpoint and every role. The current endpoint audit is still incomplete.
inline constexpr bool kRCStage3UnifiedCtlRelationWitnessBindingReady = false;
inline constexpr bool kRCStage3UnifiedCtlRecursiveConsumptionReady = false;
inline constexpr bool
    kRCStage3UnifiedProductionSiteManifestPublicBindingExecutable = true;
// The root-bound structural scheduler recomputes every family range and every
// below-root parent, but the recursive backend does not yet consume and verify
// a child proof at each scheduled site.
inline constexpr bool
    kRCStage3UnifiedProductionSiteManifestStructuralSchedulerExecutable =
        true;
inline constexpr bool
    kRCStage3UnifiedProductionSiteManifestSchedulerConsumptionReady = false;

/**
 * Complete-verifier seam. It validates every public pin and requires a
 * complete global soundness ledger first, then requires the executable
 * normalized multi-role recursive proof engine. Both remain fail-closed. No
 * native replay or sampled-carrier fallback exists.
 */
[[nodiscard]] bool VerifyRCStage3UnifiedRootProof(
    const RCStage3SuccinctProof& statement,
    const RCStage3UnifiedRootPublicPin& pin,
    std::string* why = nullptr);

inline constexpr bool kRCStage3UnifiedRootExecutable = false;
inline constexpr bool kRCStage3UnifiedRootAuthorityReady = false;

static_assert(!kRCStage3UnifiedRootExecutable);
static_assert(!kRCStage3UnifiedRootAuthorityReady);
static_assert(kRCStage3UnifiedCtlNativeProofBridgeExecutable);
static_assert(
    kRCStage3UnifiedCtlRelationExportCommitmentBridgeExecutable);
static_assert(!kRCStage3UnifiedCtlRelationWitnessBindingReady);
static_assert(!kRCStage3UnifiedCtlRecursiveConsumptionReady);
static_assert(kRCStage3UnifiedProductionSiteManifestPublicBindingExecutable);
static_assert(
    kRCStage3UnifiedProductionSiteManifestStructuralSchedulerExecutable);
static_assert(
    !kRCStage3UnifiedProductionSiteManifestSchedulerConsumptionReady);
static_assert(kRCFri3AlgNumQueries <= UINT16_MAX);
static_assert(kRCFriGrindingBits <= UINT16_MAX);
static_assert(kRCFri3AlgTargetSoundnessBits <= UINT16_MAX);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_UNIFIED_ROOT_H
