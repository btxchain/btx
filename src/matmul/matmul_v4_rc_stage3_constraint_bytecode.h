// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_CONSTRAINT_BYTECODE_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_CONSTRAINT_BYTECODE_H

#include <matmul/matmul_v4_rc_alg_hash.h>
#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_stage3.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::constraint_bytecode {

using gkr_field::Fp3;

// Bumped from 1 to 2 with the post-challenge column class: the canonical
// serialization now carries `challenge_width` and admits the `Challenge`
// opcode. Older (challenge-free) tables re-serialize under v2 with
// challenge_width == 0; no persisted golden bytes exist in-tree.
inline constexpr uint16_t kConstraintBytecodeVersion = 2;
/**
 * Additive scalar-challenge degree semantics.  V2 remains frozen with a
 * Challenge load counted as degree one.  V3 counts a verifier-owned
 * post-commitment Challenge as degree zero, matching its actual role in the
 * trace polynomial and allowing proof-visible quotient degree metadata to
 * match the native callback relation exactly.
 */
inline constexpr uint16_t
    kConstraintBytecodeScalarChallengeVersion = 3;
inline constexpr uint32_t kConstraintBytecodeMaxInstructions =
    1U << 20;

/**
 * Canonical SSA field-expression bytecode. Every instruction creates exactly
 * one register whose index is its position in Program::instructions.
 *
 * Column classes:
 *   - Current / Next load PROVER-COMMITTED trace columns (this row / next row).
 *   - Challenge loads a POST-CHALLENGE, VERIFIER-OWNED column: a value the
 *     verifier derives from the transcript AFTER the trace is committed
 *     (Fiat-Shamir challenges such as the CTL LogUp beta/gamma). It is NOT
 *     prover-committed and does NOT appear in the committed relation table, so
 *     the committed bytecode stays challenge-INDEPENDENT; the challenge enters
 *     only through this column class at evaluation time.
 */
enum class Opcode : uint8_t {
    Current = 1,
    Next = 2,
    Constant = 3,
    Add = 4,
    Sub = 5,
    Mul = 6,
    /** Verifier-owned, post-challenge column load; `lhs` is its column. */
    Challenge = 7,
};

struct Instruction {
    Opcode opcode{Opcode::Constant};
    /** Current/Next/Challenge source column, or the lhs register for binary
     * ops. */
    uint32_t lhs{0};
    /** Rhs register for binary ops; canonical zero for loads/constants. */
    uint32_t rhs{0};
    /** Nonzero only for Constant. */
    Fp3 constant{};

    bool operator==(const Instruction& other) const
    {
        return opcode == other.opcode &&
            lhs == other.lhs &&
            rhs == other.rhs &&
            gkr_field::Eq(constant, other.constant);
    }
};

struct Program {
    uint16_t version{kConstraintBytecodeVersion};
    RCStage3RelationRole role{};
    uint32_t constraint_ordinal{0};
    air_quotient::AirKind kind{
        air_quotient::AirKind::kEverywhere};
    uint32_t declared_degree{1};
    uint32_t current_width{0};
    uint32_t next_width{0};
    /** Width of the verifier-owned post-challenge column class. Zero for a
     * fully pre-challenge relation. A `Challenge` load must index below it. */
    uint32_t challenge_width{0};
    std::vector<Instruction> instructions;

    bool operator==(const Program&) const = default;
};

struct ProgramTable {
    uint16_t version{kConstraintBytecodeVersion};
    RCStage3RelationRole role{};
    uint32_t current_width{0};
    uint32_t next_width{0};
    /** Shared verifier-owned challenge-column width; every program's
     * challenge_width equals this. Zero for a pre-challenge table. */
    uint32_t challenge_width{0};
    std::vector<Program> programs;

    bool operator==(const ProgramTable&) const = default;
};

[[nodiscard]] bool ValidateProgram(
    const Program& program,
    std::string* why = nullptr);

/** Exact little-endian consensus-canonical encoding. */
[[nodiscard]] bool SerializeProgram(
    const Program& program,
    std::vector<unsigned char>& out,
    std::string* why = nullptr);

[[nodiscard]] bool DeserializeProgram(
    const std::vector<unsigned char>& bytes,
    Program& out,
    std::string* why = nullptr);

[[nodiscard]] uint256 CommitProgram(const Program& program);

[[nodiscard]] bool ValidateProgramTable(
    const ProgramTable& table,
    std::string* why = nullptr);

[[nodiscard]] bool SerializeProgramTable(
    const ProgramTable& table,
    std::vector<unsigned char>& out,
    std::string* why = nullptr);

[[nodiscard]] bool DeserializeProgramTable(
    const std::vector<unsigned char>& bytes,
    ProgramTable& out,
    std::string* why = nullptr);

[[nodiscard]] uint256 CommitProgramTable(
    const ProgramTable& table);

/**
 * Recursion-friendly commitment to the exact same canonical table bytes as
 * CommitProgramTable.  The AlgHash preimage is:
 *
 *   u32(domain_bytes) || u32(domain words...) ||
 *   u32(serialized_table_bytes) || u32(table words...)
 *
 * where every word is the little-endian packing of at most four bytes and
 * both byte lengths are explicit. This makes the field encoding injective
 * before hashing and cheap for the normalized AlgHash chip to replay.
 */
[[nodiscard]] alg_hash::Digest CommitProgramTableAlgHash(
    const ProgramTable& table);

/**
 * Exact field preimage consumed by `CommitProgramTableAlgHash`.
 *
 * Exposing the preimage lets the normalized recursive parent prove the
 * registry-selected ProgramTable commitment in AIR. Callers must still pin
 * the resulting digest to the selected registry entry.
 */
[[nodiscard]] bool BuildProgramTableAlgHashPreimage(
    const ProgramTable& table,
    std::vector<gkr_field::Fp>& out,
    std::string* why = nullptr);

struct ProgramTableCommitmentPair {
    uint256 external_sha256d{};
    alg_hash::Digest recursive_alg_hash{};
    bool same_canonical_serialization{false};
    /** Remains false until the global first-collision hybrid theorem binds
     * the external SHA and recursive AlgHash events. The POINTWISE hybrid
     * lemma (a claimed binding-failure witness yields a SHA256d or AlgHash
     * collision at the 128-bit floor) is machine-checked by
     * ClassifyCrossHashChannels / ExtractCrossHashCollision, but that only
     * discharges the commitment-function step; the accepted-proof
     * two-preimage extractor, adaptive Fiat-Shamir loss and PoW-grinding
     * accounting remain open (AssessCrossHashBindingReduction). */
    bool cross_hash_collision_binding_proved{false};

    bool operator==(const ProgramTableCommitmentPair&) const = default;
};

[[nodiscard]] ProgramTableCommitmentPair
CommitProgramTableForExternalAndRecursiveUse(
    const ProgramTable& table);

// ---------------------------------------------------------------------------
// Cross-hash (SHA256d <-> AlgHash) first-collision HYBRID reduction.
//
// A ProgramTable is pinned in the registry by the PAIR (S*, A*) where
//   S* = CommitProgramTable(T*)          [external SHA256d, 128-bit floor]
//   A* = CommitProgramTableAlgHash(T*)   [recursive AlgHash, 128-bit floor].
// The external world checks a candidate on the SHA256d channel; the recursive
// AIR checks a candidate on the AlgHash channel. A CROSS-HASH binding failure
// is a triple (T*, T_ext, T_rec) that drives the two channels with DIFFERENT
// tables but the same stored pair:
//   T_ext accepted by SHA256d:  CommitProgramTable(T_ext)       == S*
//   T_rec accepted by AlgHash:  CommitProgramTableAlgHash(T_rec) == A*
//   canonical bytes of T_ext and T_rec differ.
//
// Because both commitments are over the injective canonical serialization,
// T_ext != T* forces a SHA256d collision (S* reached on distinct bytes) and
// T_rec != T* forces an AlgHash collision (A* reached on distinct field
// preimages). Since T_ext != T_rec, at least one of them differs from T*, so a
// binding failure ALWAYS yields a collision in at least one primitive:
//
//   cross-hash binding holds at  min(SHA256d bits, AlgHash bits) = 128.
//
// The reduction below is a LOCAL, machine-checkable decision procedure: given
// a claimed witness it extracts WHICH underlying hash collided. It discharges
// only the pointwise commitment-function step of the hybrid argument; it does
// NOT supply the accepted-proof two-preimage extractor, the adaptive
// Fiat-Shamir loss, or the PoW-grinding accounting that the GLOBAL theorem
// still requires (see matmul_v4_rc_stage3_first_collision_audit.h). Hence it
// does not, on its own, flip cross_hash_collision_binding_proved.

inline constexpr uint32_t kSha256dCollisionFloorBits = 128;
inline constexpr uint32_t kAlgHashCollisionFloorBits = 128;
/** Cross-hash binding is only as strong as the weaker primitive. */
inline constexpr uint32_t kCrossHashBindingFloorBits =
    kSha256dCollisionFloorBits < kAlgHashCollisionFloorBits
        ? kSha256dCollisionFloorBits
        : kAlgHashCollisionFloorBits;

enum class CrossHashCollisionChannel : uint8_t {
    /** Not a collision: no distinct-preimage/equal-digest pair present. */
    None = 0,
    /** SHA256d(domain || bytes) reached on two distinct byte strings. */
    Sha256d = 1,
    /** AlgHash(field-preimage) reached on two distinct field preimages. */
    AlgHash = 2,
    /** Both channels collided simultaneously (single substituted table). */
    Both = 3,
};

/**
 * Derived facts about a claimed cross-hash binding-failure witness. Every
 * field is a boolean OBSERVATION recomputed from canonical bytes / digests by
 * `ExtractCrossHashCollision`; the classifier never re-hashes, mirroring the
 * extractor/recomputation split in the first-collision audit.
 */
struct CrossHashFacts {
    bool inputs_valid{false};
    bool ext_differs_from_honest{false};
    bool rec_differs_from_honest{false};
    bool ext_differs_from_rec{false};
    /** CommitProgramTable(T_ext) == CommitProgramTable(T*). */
    bool ext_sha_matches_honest{false};
    /** CommitProgramTableAlgHash(T_rec) == CommitProgramTableAlgHash(T*). */
    bool rec_alg_matches_honest{false};
};

struct CrossHashClassification {
    /** The three pairwise "differs" flags form a valid equality partition. */
    bool facts_consistent{false};
    /** Some table other than T* is accepted on a channel under the stored
     * pair (i.e. at least one channel collided): the pair no longer binds. */
    bool pair_binding_failure{false};
    /** The two channels are driven by DIFFERENT accepted tables (T_ext !=
     * T_rec, each matching the stored pair on its own channel): the min-hybrid
     * case the reduction lemma is about. */
    bool cross_channel_disagreement{false};
    bool sha256d_collision_extracted{false};
    bool alg_hash_collision_extracted{false};
    /** The theorem: cross_channel_disagreement ==> a SHA256d OR AlgHash
     * collision was extracted. Machine-checked over the whole event space. */
    bool reduction_lemma_holds{false};
    CrossHashCollisionChannel channel{CrossHashCollisionChannel::None};
    /** kCrossHashBindingFloorBits when a collision is extracted, else 0. */
    uint32_t certified_floor_bits{0};
};

/**
 * Pure structural core of the reduction. Total function over the boolean event
 * space: it decides binding failure, extracts the colliding channel, and
 * reports whether the hybrid lemma holds. Deliberately free of hashing so the
 * full accept/reject space (including the collision branches that cannot be
 * physically realized) is exhaustively machine-checkable.
 */
[[nodiscard]] CrossHashClassification
ClassifyCrossHashChannels(const CrossHashFacts& facts);

struct CrossHashCollisionWitness {
    ProgramTable honest;
    ProgramTable external_candidate;
    ProgramTable recursive_candidate;
};

/**
 * Recompute the canonical bytes and both commitments for the three tables of a
 * claimed witness, derive `CrossHashFacts`, and classify. Never fabricates a
 * collision: on real inputs the SHA256d/AlgHash channels only report agreement
 * when the recomputed digests are genuinely equal.
 */
[[nodiscard]] CrossHashClassification
ExtractCrossHashCollision(const CrossHashCollisionWitness& witness);

/**
 * Standing status of the cross-hash binding argument. The pointwise hybrid
 * lemma is machine-checked here; the global flag stays false until the
 * accepted-proof blockers in the first-collision audit are discharged.
 */
struct CrossHashBindingReductionStatus {
    uint16_t version{1};
    uint32_t sha256d_floor_bits{kSha256dCollisionFloorBits};
    uint32_t alg_hash_floor_bits{kAlgHashCollisionFloorBits};
    uint32_t cross_hash_floor_bits{kCrossHashBindingFloorBits};
    bool pointwise_hybrid_lemma_machine_checked{true};
    bool serialization_injective_on_valid_tables{true};
    bool alg_hash_preimage_injective{true};
    bool accepted_proof_two_preimage_extractor_executable{false};
    bool adaptive_fs_extraction_loss_proved{false};
    bool pow_grinding_loss_accounted{false};
    bool global_cross_hash_binding_proved{false};
    const char* first_blocker{
        "accepted proof has no cross-hash two-preimage extractor binding "
        "the registry-selected pair to the table an accepted proof uses"};
};

[[nodiscard]] CrossHashBindingReductionStatus
AssessCrossHashBindingReduction();

/** Native reference evaluator. The result is the last SSA register. Rejects
 * programs that reference the post-challenge column class (challenge_width>0);
 * use the challenge-carrying overload for those. */
[[nodiscard]] bool EvaluateProgram(
    const Program& program,
    const std::vector<Fp3>& current,
    const std::vector<Fp3>& next,
    Fp3& result,
    std::string* why = nullptr);

/**
 * Native reference evaluator with the verifier-owned post-challenge column
 * class supplied. `challenge` holds the transcript-derived values indexed by
 * `Challenge` loads; it must be at least `program.challenge_width` long. The
 * committed program is unchanged across challenge vectors: the challenge enters
 * only here, keeping the committed relation challenge-independent.
 */
[[nodiscard]] bool EvaluateProgram(
    const Program& program,
    const std::vector<Fp3>& current,
    const std::vector<Fp3>& next,
    const std::vector<Fp3>& challenge,
    Fp3& result,
    std::string* why = nullptr);

/**
 * Post-challenge / verifier-owned column class accounting. Records that the
 * challenge columns are verifier-derived (not prover-committed), that the
 * committed table stays challenge-independent, and that a LogUp
 * inverse/running-product lane written against the column class raises the raw
 * constraint degree from 2 to 3 (a challenge LOAD is degree 1, so
 * inv*(gamma - (v + beta*idx)) is degree 1*(1+1*1) = 3). The soundness ledger
 * must see the challenge columns as challenge-derived and must size the
 * quotient at the true degree 3, never the pre-challenge 2.
 */
struct PostChallengeColumnClassAudit {
    uint16_t version{1};
    bool challenge_columns_verifier_owned{true};
    bool challenge_columns_prover_committed{false};
    bool committed_table_challenge_independent{true};
    /** A single `Challenge` column load contributes algebraic degree 1. */
    uint32_t challenge_column_load_degree{1};
    /** LogUp denominator-inverse / running-product degree with beta/gamma as
     * baked constants (the pre-migration opaque callback form). */
    uint32_t logup_degree_with_baked_constant_challenge{2};
    /** The honest raw degree once beta/gamma are verifier-owned columns. */
    uint32_t logup_degree_with_challenge_column_class{3};
    /** Remains false: proving the challenge columns are sound in composition
     * needs the composition theorem + external audit, not this accounting. */
    bool global_soundness_composition_proved{false};

    bool operator==(const PostChallengeColumnClassAudit&) const = default;
};

[[nodiscard]] PostChallengeColumnClassAudit
AssessPostChallengeColumnClass();

/**
 * True iff the canonical serialized bytes of `table` do not depend on any
 * challenge value: no instruction stores a challenge as a `Constant`, the
 * challenge enters only through `Challenge` loads, and the serialization omits
 * the challenge vector entirely. This is the mechanical check that a migrated
 * transport table is committed challenge-independently.
 */
[[nodiscard]] bool ProgramTableIsChallengeIndependent(
    const ProgramTable& table);

/**
 * Construct the callback-shaped AirConstraintSystem required by the existing
 * quotient prover from a canonical program table.  The callbacks are only a
 * thin interpreter adapter: the serialized ProgramTable is the relation
 * source of truth.  This is the migration seam for registered builders that
 * cannot yet consume ProgramTable directly.
 */
[[nodiscard]] bool BuildAirConstraintSystemFromProgramTable(
    const ProgramTable& table,
    uint32_t n_rows,
    air_quotient::AirConstraintSystem<Fp3>& out,
    std::string* why = nullptr);

/**
 * Post-challenge adapter: builds the callback-shaped AirConstraintSystem for a
 * table that references the verifier-owned column class. `challenge` is the
 * transcript-derived challenge vector (length >= table.challenge_width) that
 * the verifier fixes AFTER trace commitment. Each constraint's `alg_degree` is
 * the program's declared degree (3 for a LogUp lane), so quotient sizing
 * reflects the real post-challenge-column degree. The committed table is the
 * same challenge-independent bytecode regardless of `challenge`.
 */
[[nodiscard]] bool BuildAirConstraintSystemFromProgramTable(
    const ProgramTable& table,
    uint32_t n_rows,
    const std::vector<Fp3>& challenge,
    air_quotient::AirConstraintSystem<Fp3>& out,
    std::string* why = nullptr);

enum class MigrationState : uint8_t {
    NotStarted = 0,
    Partial = 1,
    Complete = 2,
};

struct RoleMigrationInventory {
    RCStage3RelationRole role{};
    MigrationState state{MigrationState::NotStarted};
    uint32_t migrated_constraint_builders{0};
    /** Cross-shard-transport (CTL LogUp) lanes for this role now expressed as
     * challenge-INDEPENDENT executable bytecode over the post-challenge column
     * class, each with a passing differential test against its native builder.
     * This counts migrated transport LANES, not whole roles: a role stays
     * Partial (opaque_callbacks_remain) while its SHA/product builders remain. */
    uint32_t migrated_transport_ctl_lanes{0};
    /** True while any registered builder for the role still emits only an
     * opaque std::function callback. */
    bool opaque_callbacks_remain{true};
    const char* note{""};
};

/** Explicit inventory for the fourteen episode/coupled semantic roles:
 * no role is complete until every registered builder is converted and its
 * authenticated interpreter attachment executes. CompositionLink is an
 * aggregation relation and is tracked separately. */
[[nodiscard]] std::vector<RoleMigrationInventory>
CurrentRoleMigrationInventory();

/** Total transport CTL LogUp lanes migrated to challenge-independent bytecode
 * (summed over CurrentRoleMigrationInventory). This is honest transport-lane
 * progress and is DISTINCT from a role reaching MigrationState::Complete. */
[[nodiscard]] uint32_t MigratedTransportCtlLaneCount();

/**
 * Honest transport-CTL (beta/gamma LogUp) migration frontier.
 *
 * The prior audit named "7 transport roles". One of them, CoupledBank's
 * "narrow" builder, is NOT a beta/gamma fingerprint LogUp: it is a FRI-fold
 * recursive verifier (fold_beta/fold_x/sha_chain) handled by the
 * recursive-verifier path, not this post-challenge column class. So the honest
 * migratable target for THIS construction is 6 lanes, not 7.
 *
 * All SIX lanes are now migrated with passing differential tests (transpose,
 * CoupledPermutation, CoupledExchange, EpisodeExtract stream, EpisodeTileTree
 * producer, and CoupledExtract's T_M sampler LogUp). The former CoupledExtract
 * obstruction -- its committed relation carried kColTfp, a PREPROCESSED column
 * whose committed values baked gamma/gamma^2 against per-row table constants
 * inside the shared generic BuildRcSamplerConstraintSystem, violating the RAP
 * two-phase (commit-then-challenge) order -- is RESOLVED. The fingerprint is
 * no longer preprocessed: the challenge-independent table columns tbl_a=n,
 * tbl_b=acc[n], tbl_c=mu[n] are the preprocessed data, and the committed
 * fingerprint f (= kColTfp) is forced to tbl_a + gamma*tbl_b + gamma^2*tbl_c by
 * the in-circuit identity logup.tfp.bind. gamma/alpha enter only as verifier-
 * owned challenge loads (as in every other LogUp lane), so the whole relation
 * is challenge-independent bytecode. The re-plumb is applied to the shared
 * primitive across BOTH field instantiations (Fp2+Fp3) and EpisodeExtract's
 * sampler; honest phi/psi/S are bit-identical to the prior path and a
 * gamma-grinding table tamper is now rejected by ALGEBRA.
 */
struct TransportCtlMigrationFrontier {
    uint16_t version{1};
    /** == MigratedTransportCtlLaneCount(). */
    uint32_t migrated_lanes{0};
    /** beta/gamma LogUp lanes reachable by this column class. */
    uint32_t migratable_lane_target{6};
    /** FRI-fold verifier lanes excluded from this class (CoupledBank-narrow). */
    uint32_t fri_fold_out_of_scope_lanes{1};
    bool coupled_extract_migrated{false};
    const char* coupled_extract_obstruction{
        "RESOLVED: the gamma-baked preprocessed kColTfp is replaced by "
        "challenge-independent table columns (tbl_a/b/c) plus the in-circuit "
        "identity logup.tfp.bind f = tbl_a + gamma*tbl_b + gamma^2*tbl_c, "
        "re-plumbed across both field instantiations and EpisodeExtract's "
        "sampler; the T_M sampler LogUp lane is now differential-tested "
        "challenge-independent bytecode"};
    const char* coupled_bank_out_of_scope_reason{
        "CoupledBank-narrow is a FRI-fold recursive verifier "
        "(fold_beta/fold_x/sha_chain), not a beta/gamma LogUp transport lane; "
        "handled by the recursive-verifier path"};
    /** Stays false: needs the composition theorem + external audit. */
    bool global_soundness_composition_proved{false};

    bool operator==(const TransportCtlMigrationFrontier&) const = default;
};

[[nodiscard]] TransportCtlMigrationFrontier
AssessTransportCtlMigrationFrontier();

inline constexpr bool kConstraintBytecodeExecutable = true;
inline constexpr bool kAllRegisteredRoleBytecodeMigrated = false;

static_assert(kConstraintBytecodeExecutable);
static_assert(!kAllRegisteredRoleBytecodeMigrated);

} // namespace matmul::v4::rc::constraint_bytecode

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_CONSTRAINT_BYTECODE_H
