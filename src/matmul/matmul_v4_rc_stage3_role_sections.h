// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_ROLE_SECTIONS_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_ROLE_SECTIONS_H

// ============================================================================
// Stage-3 ROLE SECTION assembly + section-level verification.
//
// Everything else in the tree either (a) builds a role AIR C_rho and proves it
// in a test with a hard-coded Fiat-Shamir seed, or (b) hands an
// RCStage3SuccinctProof around with hand-filled `sections` byte blobs. Nothing
// connected the two: no code took the per-role AirQuotientProof produced from
// real episode/coupled data and populated RCStage3SuccinctProof::sections, and
// consequently nothing could verify a Stage-3 proof object's sections.
//
// This module is exactly that missing seam:
//
//   real role C_rho + witness
//     -> ProveRCStage3RoleAirSection (statement-derived FS seed)
//       -> RCStage3RoleAirSection (role, CS shape pins, endpoint authority
//          roots, real AirQuotientProof)
//         -> AssembleRCStage3SuccinctProofSections (canonical registry order,
//            per-section commitments, transcript commitment)
//           -> VerifyRCStage3RoleAirSections (decode -> REBUILD C_rho from the
//              immutable registry using ONLY section-carried public pins ->
//              real AirQuotientVerify)
//
// SOUNDNESS SCOPE — read before believing anything:
//
//  * The verifier never sees a witness and never replays the episode. It
//    rebuilds each role's constraint system with the SAME immutable registry
//    the recursive verifier uses (ResolveCurrentRCStage3RelationConstraintSystem)
//    from the section's public pins, then runs the real, unmodified
//    AirQuotientVerify. A tampered section fails FRI — this is a PROOF-LEVEL
//    reject, not a witness-side CountWitnessViolationsOnH check.
//
//  * It verifies that each required role's C_rho is satisfiable and that the
//    proof is bound to this statement (the FS seed is derived from the
//    statement's aggregation seed). It does NOT prove that the role AIRs
//    collectively imply the episode/coupled digest: the endpoint authority
//    roots a section pins are public inputs of that section, and binding them
//    to the block's committed roots is a separate obligation
//    (kRCStage3RoleSectionEndpointProvenanceReady, below, is FALSE).
//
//  * RCStage3RelationRole::CompositionLink has no role AIR at all
//    (RCStage3RoleIsInCsClosable(CompositionLink) == false), so a Composed
//    statement can NEVER be fully section-verified here. Composed fails closed
//    with an explicit reason. Episode / Coupled statements are fully covered.
//
// No consensus authority is granted by anything in this file.
// ============================================================================

#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_fri_ext3_alg.h>
#include <matmul/matmul_v4_rc_gkr_field_ext3.h>
#include <matmul/matmul_v4_rc_stage3.h>
#include <matmul/matmul_v4_rc_stage3_recursive.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>
#include <matmul/matmul_v4_rc_stage3_root_chain.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

class CBlockHeader;

namespace Consensus {
struct Params;
}

namespace matmul::v4::rc {

inline constexpr uint32_t kRCStage3RoleSectionMagic = 0x3353414FU; // "OAS3"
inline constexpr uint16_t kRCStage3RoleSectionVersion = 1;

/**
 * One Stage-3 proof section: a real FRI proof of one relation role's C_rho,
 * plus exactly the public pins a verifier needs to REBUILD that C_rho.
 *
 * `endpoint_authority_roots` are the committed VectorRootAlg roots the role's
 * in-trace opening blocks authenticate, in RequiredRCStage3RelationEndpoints
 * order. They are public inputs: the section is only meaningful relative to
 * them, and they are absorbed into the section commitment.
 */
struct RCStage3RoleAirSection {
    using AlgB3 = air_quotient::AirFriBackendAlg<gkr_field::Fp3>;

    uint32_t magic{kRCStage3RoleSectionMagic};
    uint16_t version{kRCStage3RoleSectionVersion};
    uint16_t registry_version{kRCStage3ConstraintRegistryVersion};
    RCStage3RelationRole role{};
    /** C_rho shape pins. Must equal the rebuilt registry AIR exactly. */
    uint32_t n_rows{0};
    uint32_t n_columns{0};
    std::vector<alg_hash::Digest> endpoint_authority_roots;
    air_quotient::AirQuotientProof<gkr_field::Fp3, AlgB3> air;
};

/** Canonical codec for one section body (the bytes stored in
 * RCStage3ProofSection::proof). Deserialization is strict and canonical. */
[[nodiscard]] bool SerializeRCStage3RoleAirSection(
    const RCStage3RoleAirSection& section,
    std::vector<unsigned char>& out,
    std::string* why = nullptr);
[[nodiscard]] std::optional<RCStage3RoleAirSection>
DeserializeRCStage3RoleAirSection(const std::vector<unsigned char>& bytes,
                                  std::string* why = nullptr);

/**
 * Fixed-role commitment carried in RCStage3SuccinctProof::commitments.
 *
 * It binds the role, the C_rho shape, and every endpoint authority root — all
 * pre-proof, public data — plus the section's committed roots (trace commit and
 * batch row-commit root). It is NOT a hash of the section bytes: an outer
 * envelope hash would let any self-consistent blob commit to itself.
 */
[[nodiscard]] uint256
ComputeRCStage3RoleAirSectionCommitment(const RCStage3RoleAirSection& section);

/**
 * Statement-bound, proof-independent Fiat-Shamir seed for one role section.
 *
 * Base is ComputeRCStage3AggregationSeed(statement), which excludes sections,
 * section commitments, and the transcript commitment, so there is no
 * proof/seed fixed point. Domain-separated by registry version and role, so a
 * proof produced for role A cannot be replayed as role B, and a proof produced
 * for another block's statement cannot be replayed here.
 */
[[nodiscard]] uint256
ComputeRCStage3RoleAirSectionSeed(const RCStage3SuccinctProof& statement,
                                  RCStage3RelationRole role);

/**
 * Rebuild one role's C_rho from ONLY the section's public pins, using the
 * immutable registry. Fails closed for roles with no complete role AIR.
 */
[[nodiscard]] bool RebuildRCStage3RoleAirConstraintSystem(
    const RCStage3RoleAirSection& section,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    std::string* why = nullptr);

struct RCStage3RoleSectionProveResult {
    bool ok{false};
    std::string note;
    RCStage3RoleAirSection section;
    double prove_seconds{0.0};
};

/**
 * Prove one role section from a REAL role AIR product.
 *
 * `product` must be a satisfying (C_rho, witness) pair — typically built from
 * real MineRCEpisode / RecomputeCoupledPuzzleReference data. The prover:
 *   1. rebuilds C_rho from the registry using the product's committed endpoint
 *      roots and REQUIRES the rebuilt system to match the product's own C_rho
 *      shape (otherwise the emitted section could never verify);
 *   2. runs the real AirQuotientProve under the statement-derived seed;
 *   3. round-trips the section codec.
 * It never emits a section it has not itself just verified.
 */
[[nodiscard]] RCStage3RoleSectionProveResult ProveRCStage3RoleAirSection(
    const RCStage3SuccinctProof& statement,
    const RCStage3RoleAirProduct& product);

/**
 * Populate `proof`'s commitments and sections from the proved role sections,
 * in canonical RequiredRCStage3RelationRoles order, then recompute the
 * statement's transcript commitment over the assembled envelope.
 *
 * `proof` must already carry every other public input (see
 * BuildRCStage3StatementForHeader). Exactly one section per required role is
 * required; a missing or duplicated role fails closed.
 */
[[nodiscard]] bool AssembleRCStage3SuccinctProofSections(
    RCStage3SuccinctProof& proof,
    const std::vector<RCStage3RoleAirSection>& sections,
    std::string* why = nullptr);

/**
 * Verify ONE decoded section against a statement, with no envelope around it:
 * rebuild C_rho from the immutable registry using only the section's public
 * pins, then run the real, unmodified AirQuotientVerify under the
 * statement-derived Fiat-Shamir seed. No witness. No replay.
 *
 * This is the atom VerifyRCStage3RoleAirSections is built from; it is public
 * because the assembled Stage-3 envelope currently cannot hold six real
 * episode role proofs (see kRCStage3MaxProofBytes and the measured section
 * sizes), and the per-relation verdict is meaningful on its own.
 */
[[nodiscard]] bool VerifyRCStage3RoleAirSection(
    const RCStage3SuccinctProof& statement,
    const RCStage3RoleAirSection& section,
    std::string* why = nullptr);

/**
 * Section-level mathematical verification of a complete Stage-3 proof object.
 *
 * For every required role, in order: decode the section, check the carried
 * commitment, rebuild C_rho from the registry using only section pins, and run
 * the real AirQuotientVerify under the statement-derived seed. No witness, no
 * replay, no environment switch. See the soundness scope at the top of this
 * file for what this does and does not establish.
 */
[[nodiscard]] bool VerifyRCStage3RoleAirSections(
    const RCStage3SuccinctProof& proof,
    std::string* why = nullptr);

/**
 * Production statement builder — the missing header -> statement step.
 *
 * Fills every public input of an Episode (or Coupled) statement from a REAL
 * block header plus resolved consensus params, so the resulting object is the
 * one ValidateRCStage3ConsensusBinding checks. Section-dependent fields
 * (transcript_commitment) are filled by AssembleRCStage3SuccinctProofSections.
 *
 * `program_pin` is supplied by the caller because the ProgramTable authority
 * lives in Consensus::Params (hashMatMulRCStage3ProgramRegistry*) and is
 * currently UNCONFIGURED on every network; this function does not invent one.
 */
[[nodiscard]] bool BuildRCStage3StatementForHeader(
    const CBlockHeader& header,
    const Consensus::Params& params,
    int32_t height,
    RCStage3StatementKind kind,
    const ProductionProgramConsensusPinV1& program_pin,
    const uint256& episode_digest,
    const uint256& coupled_digest,
    RCStage3SuccinctProof& out,
    std::string* why = nullptr);

// ===========================================================================
// ENDPOINT PROVENANCE.
//
// A verified section proves its role's C_rho is satisfiable relative to the
// endpoint authority roots THE SECTION DECLARES. Without a provenance check a
// prover may simply declare convenient roots. This layer binds the declared
// roots to values the statement already commits.
//
// It applies to PURE-STREAM roles only (EpisodeTileTree, EpisodeDigest,
// CoupledBarrier, CoupledDigest). For those, the endpoint authority root is a
// pure repacking of a 32-byte SHA256d root: limb[i] is the little-endian
// uint64 read of root bytes [8i, 8i+8) — see PackStreamRoot/Root8 in
// matmul_v4_rc_stage3_relation_closure.cpp. The verifier therefore recomputes
// the expected Digest from a uint256 it already knows and requires equality.
//
// For scalar / wired roles the endpoint root is an alg-hash commitment to the
// OPENED VALUE, not a repacked block root, so this derivation does not apply
// at all; those endpoints are reported unanchored.
// ===========================================================================

enum class RCStage3EndpointAnchorSource : uint8_t {
    /** No statement-derivable source. Recorded, never silently accepted. */
    None = 0,
    StatementEpisodeDigest = 1,
    StatementHeaderCommitment = 2,
    StatementTarget = 3,
    StatementCoupledDigest = 4,
    /** One of the per-round transcript roots the episode digest root chain
     * binds to statement.public_inputs.episode_digest. */
    EpisodeRoundRoot = 5,
};

/** Immutable endpoint -> anchor table. This is the canonical definition of
 * what each pure-stream endpoint's authority root is REQUIRED to be. */
[[nodiscard]] RCStage3EndpointAnchorSource
RCStage3EndpointAnchorSourceFor(RCStage3RelationEndpoint endpoint);

/**
 * Canonical repacking of a 32-byte root into the four-limb authority Digest.
 *
 * Returns false when a limb is >= the Goldilocks modulus. Such a root is not
 * representable as an authority Digest at all; it is rejected rather than
 * reduced. (Roughly one root in 2^30 is affected — a liveness edge, recorded.)
 */
[[nodiscard]] bool RCStage3StreamAuthorityRootFromUint256(
    const uint256& root, alg_hash::Digest& out);

/**
 * Provenance material carried alongside the sections.
 *
 * `digest_chain` is the real, unmodified episode digest root chain
 * (ProveRCStage3EpisodeDigestRootChain). Verifying it establishes
 * round_roots -> typed preimage -> SHA256d provenance -> episode digest ->
 * statement.public_inputs.episode_digest, which is what lets an
 * EpisodeRoundRoot-anchored endpoint be checked at all.
 */
struct RCStage3EndpointProvenance {
    bool has_digest_chain{false};
    RCStage3EpisodeDigestRootChainProof digest_chain;
};

struct RCStage3EndpointProvenanceReport {
    uint32_t endpoints_total{0};
    uint32_t anchored_to_statement{0};
    uint32_t anchored_to_round_roots{0};
    uint32_t unanchored{0};
    std::vector<std::string> unanchored_reasons;
};

/**
 * Enforce endpoint provenance for ONE section.
 *
 * Every endpoint whose anchor is statement-derivable MUST match; a mismatch is
 * a hard reject. Endpoints with no anchor are counted and reported, never
 * accepted as if checked.
 *
 * RESIDUAL, stated plainly: EpisodeRoundRoot anchoring establishes MEMBERSHIP
 * (the declared root is some genuine committed round root of this episode's
 * verified digest chain), not POSITION (which round). The statement does not
 * pin a round index for these endpoints, so position cannot be checked here.
 */
[[nodiscard]] bool VerifyRCStage3RoleAirSectionEndpointProvenance(
    const RCStage3SuccinctProof& statement,
    const RCStage3RoleAirSection& section,
    const RCStage3EndpointProvenance& provenance,
    uint32_t expected_rounds,
    RCStage3EndpointProvenanceReport* report = nullptr,
    std::string* why = nullptr);

/** Section verification AND endpoint provenance, over a whole proof object. */
[[nodiscard]] bool VerifyRCStage3RoleAirSectionsWithProvenance(
    const RCStage3SuccinctProof& proof,
    const RCStage3EndpointProvenance& provenance,
    uint32_t expected_rounds,
    RCStage3EndpointProvenanceReport* report = nullptr,
    std::string* why = nullptr);

/**
 * Hard gate, separate from every other Stage-3 gate.
 *
 * STILL FALSE, now for an enumerated set of reasons rather than "no binding
 * exists". What IS closed: every pure-stream endpoint whose anchor is
 * statement-derivable is enforced against the statement, and
 * EpisodeRoundRoot-anchored endpoints are enforced against a really-verified
 * episode digest root chain. What remains open:
 *
 *   (1) scalar / wired role endpoints (EpisodeDeterministicBuilder,
 *       EpisodeGemm, EpisodeExtract, EpisodeWiring and their coupled
 *       counterparts) commit an alg-hash of the OPENED VALUE; there is no
 *       derivation from any statement public input, so nothing anchors them;
 *   (2) EpisodeTileTreeStream / LeafHash / InternalHash and the coupled
 *       bank/barrier roots have no statement-carried source;
 *   (3) EpisodeRoundRoot anchoring is membership-only, not position.
 *
 * Never flip this to make a test pass.
 */
inline constexpr bool kRCStage3RoleSectionEndpointProvenanceReady = false;

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_ROLE_SECTIONS_H
