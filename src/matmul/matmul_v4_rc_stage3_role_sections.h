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
//  * RCStage3RelationRole::CompositionLink DOES have a role AIR as of the g2
//    lane's c690764 — RCStage3RoleIsInCsClosable(CompositionLink) is now true,
//    so a Composed statement is no longer blocked here at the role-AIR level.
//    (It previously had none, and this file used to say so; that is stale.)
//
//    What is NOT automatic is its endpoint accounting. CompositionLink carries
//    no entry in RequiredRCStage3RelationEndpoints, so anything that sizes
//    itself off that registry sees ZERO endpoints for it — the same vacuity
//    shape c690764 avoided on the closer-count side by stating
//    kRCStage3CompositionLinkInCsClosers = 3 explicitly. The provenance layer
//    below therefore special-cases the role by NAME rather than by registry
//    size, so its three authority roots are counted, and reported, and can
//    never contribute a silent zero. Two of the three (the episode and coupled
//    leg roots) are anchored to the statement; the link digest is not. See the
//    CompositionLink branch of
//    VerifyRCStage3RoleAirSectionEndpointProvenance.
//
// No consensus authority is granted by anything in this file.
// ============================================================================

#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_fri_ext3_alg.h>
#include <matmul/matmul_v4_rc_gkr_field_ext3.h>
#include <matmul/matmul_v4_rc_stage3.h>
#include <matmul/matmul_v4_rc_stage3_hash_air.h>
#include <matmul/matmul_v4_rc_stage3_recursive.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>
#include <matmul/matmul_v4_rc_stage3_root_chain.h>
#include <primitives/block.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

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
 * Immutable work-relation context available before either workload leg emits
 * its terminal digest.
 *
 * This is not a proof or an authority receipt. `public_inputs` has the
 * episode/coupled/final/transcript terminal fields canonically zero. The two
 * nonzero relation precommitments are exactly the V3 seeds used by the
 * corresponding child provers. A statement kind that does not contain one of
 * the legs has that leg's precommitment zero.
 */
struct RCStage3RelationPrecommitV3 {
    RCStage3StatementKind statement{
        RCStage3StatementKind::Composed};
    RCStage3PublicInputs public_inputs{};
    uint256 episode_relation_precommit{};
    uint256 coupled_relation_precommit{};
};

/**
 * Build the immutable relation precommit before executing the candidate.
 *
 * This makes callback-time prove-and-discard possible: every child proof can
 * bind the finalized nonce/header projection, parameters, target, sigma and
 * registry before the terminal digests exist. The final statement builder
 * below reuses these exact inputs and adds the proof-owned terminal values.
 */
[[nodiscard]] bool BuildRCStage3RelationPrecommitForHeaderV3(
    const CBlockHeader& header,
    const Consensus::Params& params,
    int32_t height,
    RCStage3StatementKind kind,
    const ProductionProgramConsensusPinV1& program_pin,
    RCStage3RelationPrecommitV3& out,
    std::string* why = nullptr);

/**
 * Production finalized-statement builder — header -> statement step.
 *
 * Fills every public input of an Episode (or Coupled) statement from a REAL
 * block header plus resolved consensus params, so the resulting object is the
 * one ValidateRCStage3ConsensusBinding checks. Section-dependent fields
 * (transcript_commitment) are filled by AssembleRCStage3SuccinctProofSections.
 *
 * `program_pin` is supplied by the caller because the ProgramTable authority
 * lives in Consensus::Params (hashMatMulRCStage3ProgramRegistry*) and is
 * currently UNCONFIGURED on every network; this function does not invent one.
 *
 * The immutable portion is built by
 * BuildRCStage3RelationPrecommitForHeaderV3. This function only adds the
 * terminal digests and their composed final digest; it cannot silently select
 * a different child relation seed after the workload completes.
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
// TWO derivation shapes are used, and they are kept distinct on purpose.
//
//  (A) REPACK. For a stream endpoint the authority root is a pure repacking of
//      a 32-byte SHA256d root: limb[i] is the little-endian uint64 read of root
//      bytes [8i, 8i+8) — see PackStreamRoot/Root8 in
//      matmul_v4_rc_stage3_relation_closure.cpp. The verifier recomputes the
//      expected Digest from a uint256 it already knows and requires equality.
//
//  (B) CANONICAL REBUILD. For a scalar / wired endpoint the authority root is
//      an alg-hash commitment to the OPENED VALUE (a canonical opening
//      manifest, or a Poseidon ledger-fold of a wired leaf row), so (A) does
//      not apply. Instead the verifier re-runs the SAME shipped role builder a
//      producer must use — BuildRCStage3NoKernelRoleAir /
//      BuildRCStage3EpisodeGemmRoleAir / BuildRCStage3EpisodeWiringRoleAir —
//      on inputs it has itself derived from block material the statement binds,
//      and requires the whole endpoint_committed_roots vector to match
//      elementwise. Nothing is reimplemented here, so the provenance rule and
//      the producer cannot drift apart.
//
// The block material feeding (B) is carried in RCStage3EndpointProvenance and
// is itself verified against the statement before it is used: the header
// against statement.header_commitment, the ordered round roots against
// statement.episode_digest (digest root chain), and the round tile-tree
// manifest against the round root at the declared index. See
// RCStage3EndpointAnchorSource for the per-endpoint attribution.
// ===========================================================================

enum class RCStage3EndpointAnchorSource : uint8_t {
    /** No statement-derivable source. Recorded, never silently accepted. */
    None = 0,
    StatementEpisodeDigest = 1,
    StatementHeaderCommitment = 2,
    StatementTarget = 3,
    StatementCoupledDigest = 4,
    /** The per-round transcript root at the declared round index, in the
     * ordered list the episode digest root chain binds to
     * statement.public_inputs.episode_digest. POSITIONAL, not membership. */
    EpisodeRoundRoot = 5,
    /** A field of the real block header, whose preimage is bound by
     * RCStage3HeaderCommitment == statement.public_inputs.header_commitment. */
    HeaderPreimage = 6,
    /** A cell of the round byte stream, or a node of that round's tile tree.
     * Bound because the tile-tree manifest revalidates canonically from its own
     * stream AND its root is the committed round root at the declared index. */
    EpisodeStreamCell = 7,
    /** The resolved episode shape (round count), cross-checked by the digest
     * root chain, which only verifies at the right number of rounds. */
    EpisodeShapeParam = 8,
    /**
     * Fixed by the immutable role builder and carrying NO block data at all —
     * the wired ledger-fold leaf rows (EpisodeBuilderTrace, EpisodeGemmSumcheck,
     * EpisodeWiringTranspose/Residual/RoundOrder) are hard-coded constant rows.
     *
     * A prover has zero freedom here, which is what endpoint provenance is
     * about, but the committed value is a PLACEHOLDER, not the block's. This is
     * counted separately and is the whole remaining reason
     * kRCStage3RoleSectionEndpointProvenanceReady is false.
     */
    ProtocolConstant = 9,
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
 * Provenance material carried alongside the sections. NONE of it is trusted:
 * every member is checked against a statement public input by
 * VerifyRCStage3EndpointProvenanceMaterial before any expected root is derived
 * from it. A member that is absent does not weaken any check — the endpoints
 * that would have depended on it are reported unanchored instead.
 *
 * `digest_chain` is the real, unmodified episode digest root chain
 * (ProveRCStage3EpisodeDigestRootChain). Verifying it establishes
 * round_roots -> typed preimage -> SHA256d provenance -> episode digest ->
 * statement.public_inputs.episode_digest.
 */
struct RCStage3EndpointProvenance {
    bool has_digest_chain{false};
    RCStage3EpisodeDigestRootChainProof digest_chain;

    /**
     * The single episode round these role sections are about: an INDEX into the
     * verified chain's ORDERED round_roots, not a root.
     *
     * Every round-root-anchored endpoint of every section must equal
     * round_roots[round_index] exactly, so a proof cannot mix one round's
     * tile-tree root with another round's digest round root. The index itself
     * is declared, not statement-pinned — the statement carries no round index
     * — so what this closes is cross-round substitution, not absolute position;
     * and one round of `expected_rounds` is what the section set covers.
     */
    uint32_t round_index{0};

    /** The real block header. Bound by RCStage3HeaderCommitment(header) ==
     * statement.public_inputs.header_commitment. Supplies seed_a / seed_b. */
    bool has_header{false};
    CBlockHeader header;

    /** The round-`round_index` tile-tree manifest. Bound by canonical
     * revalidation (ValidateTileTreeManifest recomputes the whole tree from the
     * manifest's own stream) AND root == round_roots[round_index]. Supplies the
     * round byte stream and the tile-tree nodes. */
    bool has_tile_tree{false};
    stage3_hash_air::TileTreeManifest tile_tree;
};

/**
 * Per-endpoint attribution. The five `anchored_*` counters partition the
 * endpoints whose declared root was RE-DERIVED and matched; `unanchored`
 * counts those for which no derivation was available. The sum is always
 * `endpoints_total`.
 *
 * `anchored_to_protocol_constant` is deliberately NOT merged into the others:
 * those endpoints are pinned but their committed value is a placeholder rather
 * than block data.
 */
struct RCStage3EndpointProvenanceReport {
    uint32_t endpoints_total{0};
    uint32_t anchored_to_statement{0};
    uint32_t anchored_to_round_roots{0};
    uint32_t anchored_to_header_preimage{0};
    uint32_t anchored_to_episode_stream{0};
    uint32_t anchored_to_episode_shape{0};
    uint32_t anchored_to_protocol_constant{0};
    uint32_t unanchored{0};
    std::vector<std::string> unanchored_reasons;
};

/** Block material accepted by VerifyRCStage3EndpointProvenanceMaterial. Only
 * members whose `have_*` flag is set were verified against the statement. */
struct RCStage3VerifiedEndpointMaterial {
    bool have_round_roots{false};
    uint32_t round_index{0};
    uint256 round_root;
    std::vector<uint256> round_roots;

    bool have_header{false};
    CBlockHeader header;

    bool have_tile_tree{false};
    const stage3_hash_air::TileTreeManifest* tile_tree{nullptr};

    uint32_t episode_rounds{0};
};

/**
 * Check every piece of carried provenance against a statement public input.
 *
 * Returns false (hard reject) when a carried piece is present but does NOT
 * check out — a forged header preimage, a chain that does not verify, a
 * non-canonical tile tree, a tile tree whose root is not the committed round
 * root at the declared index, an out-of-range round index. Absent material is
 * not an error; it simply leaves `out`'s corresponding have_* flag false.
 */
[[nodiscard]] bool VerifyRCStage3EndpointProvenanceMaterial(
    const RCStage3SuccinctProof& statement,
    const RCStage3EndpointProvenance& provenance,
    uint32_t expected_rounds,
    RCStage3VerifiedEndpointMaterial& out,
    std::string* why = nullptr);

/**
 * The canonical, immutable rule for what an EPISODE role's endpoint authority
 * roots are REQUIRED to be, derived from verified block material only.
 *
 * This is the (B) CANONICAL REBUILD route and covers the four scalar/wired
 * episode roles only; it fails closed for EpisodeTileTree / EpisodeDigest,
 * whose every endpoint root is a pure repack handled by route (A). It also
 * returns false when the material the role needs was not supplied (`why` names
 * it), which is reported as unanchored rather than accepted.
 *
 * CONVENTION, stated plainly: this fixes which block cell each scalar endpoint
 * opens (round stream bytes 0/1 for the GEMM operands, 0/2/4/6 for Extract,
 * byte 0 for the wiring copy, tile-tree leaf 0 and the last internal node).
 * That convention did not previously exist anywhere; it is created here and it
 * matches the only producer in the tree. A producer that opens different cells
 * is now REJECTED, not silently accepted.
 */
[[nodiscard]] bool RCStage3CanonicalEpisodeRoleEndpointRoots(
    const RCStage3VerifiedEndpointMaterial& material,
    RCStage3RelationRole role,
    std::vector<alg_hash::Digest>& out,
    std::string* why = nullptr);

/**
 * Enforce endpoint provenance for ONE section.
 *
 * Every endpoint whose anchor is derivable MUST match; a mismatch is a hard
 * reject. Endpoints with no anchor are counted and reported, never accepted as
 * if checked.
 *
 * RESIDUALS, stated plainly:
 *  - the round INDEX is declared in the provenance, not pinned by the
 *    statement, so what is enforced is that every round-root-anchored endpoint
 *    of every section names the SAME committed round, at that position in the
 *    verified chain's ordered list. Cross-round substitution is closed;
 *    absolute position is not, and the section set covers one round of
 *    `expected_rounds`;
 *  - ProtocolConstant endpoints are pinned to a placeholder, not to block data;
 *  - CompositionLink contributes 3 more roots that no endpoint registry knows
 *    about. Two are anchored to the statement's episode / coupled digests; the
 *    LINK DIGEST is not, because the leg values the sponge absorbs are
 *    producer-chosen. Composed statements therefore carry at least one
 *    unanchored root on top of whatever their episode and coupled sections do.
 *
 * COST, MEASURED on real block 101 — a verifier-side check that cannot be
 * recomputed per call is not a check, so the expensive artefact is produced
 * ONCE by the producer and only VERIFIED here:
 *   episode digest root chain PROVE  161.6 s (1 round) / 250.9 s (2 rounds)
 *   whole provenance case wall       196.4 s, max RSS 1,101,848 KiB
 * The remaining 34.8 s covers 18 material verifications plus 7 FRI section
 * proves, 6 FRI section verifies, the episode recompute and the tile-tree
 * build, so ONE material verification is under ~1.9 s. That is an upper bound,
 * not a measurement of the verification alone.
 *
 * KNOWN INEFFICIENCY: VerifyRCStage3RoleAirSectionsWithProvenance re-verifies
 * the same digest chain once per section (6x per proof) because the material
 * check lives inside this per-section entry point. Hoisting it to one per proof
 * is a straightforward follow-up and changes no verdict.
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
 * STILL FALSE, for a much smaller and more precise residual than before.
 *
 * CLOSED for an Episode statement (MEASURED on a real mined block; the counts
 * are asserted in matmul_v4_rc_stage3_role_sections_tests so they cannot
 * drift):
 *   - scalar / wired role endpoints now DO have a derivation. The verifier
 *     re-runs the shipped role builder on cells it derived itself from the
 *     round tile-tree stream, from the header preimage, and from the resolved
 *     episode shape, and requires the declared roots to match elementwise;
 *   - EpisodeTileTreeStream / LeafHash / InternalHash are derived from a
 *     canonically revalidated tile-tree manifest whose root must be the
 *     committed round root;
 *   - round-root anchoring is POSITIONAL against one declared round index that
 *     is uniform across the whole proof, so a section can no longer be anchored
 *     to a different round than its siblings.
 *
 * STILL OPEN, and the only reason this is false:
 *   (1) five endpoints — EpisodeBuilderTrace, EpisodeGemmSumcheck,
 *       EpisodeWiringTranspose / Residual / RoundOrder — are wired ledger-fold
 *       leaf rows that the role builder hard-codes as CONSTANTS. A prover has
 *       no freedom in them, but they commit a placeholder rather than the
 *       block's wiring/sumcheck data, so calling them "bound to the block"
 *       would be false;
 *   (2) the round index is prover-declared (see RCStage3EndpointProvenance),
 *       and the section set covers one round of the episode;
 *   (3) Coupled statements are untouched by this work: the coupled roles have
 *       no canonical derivation and remain unanchored;
 *   (4) Composed statements additionally carry CompositionLink's LINK DIGEST,
 *       whose absorbed leg values have no statement-derivable source. Its two
 *       leg authority roots ARE anchored, so the CompositionLink contribution
 *       is 3 endpoints = 2 anchored + 1 unanchored.
 *
 * Never flip this to make a test pass.
 */
inline constexpr bool kRCStage3RoleSectionEndpointProvenanceReady = false;

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_ROLE_SECTIONS_H
