// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_HASH_AIR_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_HASH_AIR_H

#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_gkr_field_ext3.h>
#include <matmul/matmul_v4_rc_stage3_ctl.h>

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

// Proof-only instruction AIRs for the 32-bit operations shared by SHA-256 and
// ChaCha20.  Every word is range-bound by 32 boolean columns plus a
// recomposition constraint.  These are real AirConstraintSystem instances;
// native hash replay is never an acceptance condition.
//
// This module also fixes the complete SHA/ChaCha instruction schedules and
// exact byte-level manifests for padding, counter consumption, tile trees,
// episode/coupled barriers, and the composed final digest. Recursive child
// attachment of these tables and their CTL terminals remains a typed gap, so
// no complete hash or consensus flag is set.

namespace matmul::v4::rc {
struct Fri3AlgRowTreeCache;
}

namespace matmul::v4::rc::stage3_hash_air {

using gkr_field::Fp3;

inline constexpr uint16_t kRegistryVersion = 1;
inline constexpr uint32_t kWordColumns = 33; // value + 32 bits
inline constexpr uint32_t kMaxColumns = 132;
inline constexpr size_t kMaxHashManifestPreimage = 16U * 1024U * 1024U;

enum class Family : uint8_t {
    Add32 = 1,
    XorRot32 = 2,
    ShaChoice32 = 3,
    ShaMajority32 = 4,
    ShaXor3Transform32 = 5,
};

enum class BitTransformKind : uint8_t {
    RotateRight = 1,
    ShiftRight = 2,
};

struct BitTransform {
    BitTransformKind kind{BitTransformKind::RotateRight};
    uint8_t amount{0};
    bool operator==(const BitTransform&) const = default;
};

struct Spec {
    uint16_t registry_version{kRegistryVersion};
    Family family{Family::Add32};
    uint32_t n_rows{2};
    /** XorRot32 only: rotate-left amount. */
    uint8_t rotate_left{0};
    /** ShaXor3Transform32 only: three fixed right transforms. */
    std::array<BitTransform, 3> transforms{};
    bool operator==(const Spec&) const = default;
};

[[nodiscard]] const char* FamilyName(Family family);
[[nodiscard]] uint32_t NumWords(Family family);
[[nodiscard]] uint32_t NumColumns(Family family);
[[nodiscard]] uint32_t ValueColumn(uint32_t word);
[[nodiscard]] uint32_t BitColumn(uint32_t word, uint32_t bit);
[[nodiscard]] uint32_t AddCarryColumn();

[[nodiscard]] bool BuildConstraintSystem(
    const Spec& spec,
    air_quotient::AirConstraintSystem<Fp3>& out,
    std::string* why = nullptr);

struct Inputs {
    std::vector<uint32_t> a;
    std::vector<uint32_t> b;
    std::vector<uint32_t> c;
};

struct Witness {
    std::vector<std::vector<Fp3>> columns;
    std::vector<uint32_t> output;
};

[[nodiscard]] bool BuildWitness(const Spec& spec,
                                const Inputs& inputs,
                                Witness& out,
                                std::string* why = nullptr);

[[nodiscard]] bool VerifyShard(
    const Spec& spec,
    const air_quotient::AirQuotientProof<Fp3>& proof,
    const uint256& fs_seed,
    std::string* why = nullptr);

enum class ProgramKind : uint8_t {
    Sha256Compression = 1,
    ChaCha20Block = 2,
};

enum class ProgramOpcode : uint8_t {
    Add32 = 1,
    XorRot32 = 2,
    ShaChoice32 = 3,
    ShaMajority32 = 4,
    ShaSmallSigma0 = 5,
    ShaSmallSigma1 = 6,
    ShaBigSigma0 = 7,
    ShaBigSigma1 = 8,
};

struct ProgramRow {
    ProgramOpcode opcode{};
    uint16_t round{0};
    uint16_t step{0};
    uint8_t rotate_left{0};
    uint8_t input_count{0};
    std::array<uint32_t, 3> input_address{};
    uint32_t output_address{0};
    bool operator==(const ProgramRow&) const = default;
};

struct FixedProgram {
    ProgramKind kind{};
    uint32_t external_address_count{0};
    std::vector<ProgramRow> rows;
    std::vector<uint32_t> final_addresses;
    bool operator==(const FixedProgram&) const = default;
};

/** Exact operation schedules: one SHA-256 compression is 952 instruction
 * rows; one ChaCha20 block is 656 instruction rows.  These schedules close
 * omission/reordering at the program-description layer. The two-epoch
 * provenance AIR below closes the internal single-assignment wiring. */
[[nodiscard]] FixedProgram BuildCanonicalProgram(ProgramKind kind);
[[nodiscard]] bool ValidateCanonicalProgram(const FixedProgram& program,
                                            std::string* why = nullptr);
[[nodiscard]] Spec ProgramRowSpec(const ProgramRow& row, uint32_t n_rows);

/** Two ordered CTL ports per program operand: a send from the canonical SSA
 * address followed by the consuming instruction's receive.  The schedule is
 * immutable and commit-able through CommitRCStage3CtlSchedule; actual values
 * must be supplied from proof columns by the recursive child. */
[[nodiscard]] RCStage3CtlSchedule BuildProgramCtlSchedule(
    const FixedProgram& program, uint32_t namespace_id);

struct ProgramWitness {
    /** Address zero is unused; external inputs occupy
     * [1, external_address_count], then one address per instruction row. */
    std::vector<uint32_t> address_values;
    std::vector<uint32_t> instruction_outputs;
    std::vector<uint32_t> final_words;
    /** Values in exactly BuildProgramCtlSchedule order: source, consumer for
     * each operand edge.  Each pair is equal by construction. */
    std::vector<Fp3> ctl_values;
};

/** Execute the canonical SSA program using one value per external address.
 * This is an honest witness builder/differential oracle, not verifier replay.
 * The immutable instruction AIRs and CTL child prove its emitted cells. */
[[nodiscard]] bool BuildProgramWitness(
    const FixedProgram& program,
    const std::vector<uint32_t>& external_values,
    ProgramWitness& out,
    std::string* why = nullptr);

struct ProgramInstructionShard {
    Spec spec;
    std::vector<uint32_t> program_rows;
    Witness witness;
};

/** Partition an honest fixed-program witness into canonical opcode/rotation
 * shards. Each returned shard is directly provable by BuildConstraintSystem
 * and AirQuotientProve. Padding rows are deterministic zero operations. */
[[nodiscard]] bool BuildProgramInstructionShards(
    const FixedProgram& program,
    const ProgramWitness& witness,
    std::vector<ProgramInstructionShard>& out,
    std::string* why = nullptr);

inline constexpr uint32_t kFixedProgramOpcodeCount = 11;
inline constexpr uint32_t kFixedProgramCarryColumn = 132;
inline constexpr uint32_t kFixedProgramSelectorBase = 133;
inline constexpr uint32_t kFixedProgramColumns =
    kFixedProgramSelectorBase + kFixedProgramOpcodeCount;
inline constexpr uint32_t kFixedProgramBoundaryExpectedBase =
    kFixedProgramColumns;
inline constexpr uint32_t kFixedProgramBoundaryMaskBase =
    kFixedProgramBoundaryExpectedBase + 4;
inline constexpr uint32_t kFixedProgramBoundaryColumns =
    kFixedProgramBoundaryMaskBase + 4;

/** One selector-pinned AIR table for the complete canonical program. Four
 * range-bound word slots are shared by every opcode. Canonical preprocessed
 * selectors fix every active row and power-of-two padding row. */
[[nodiscard]] bool BuildFixedProgramConstraintSystem(
    const FixedProgram& program,
    air_quotient::AirConstraintSystem<Fp3>& out,
    std::string* why = nullptr);
[[nodiscard]] bool BuildFixedProgramAirWitness(
    const FixedProgram& program,
    const ProgramWitness& witness,
    std::vector<std::vector<Fp3>>& columns,
    std::string* why = nullptr);

/**
 * Public-boundary form of the fixed-program AIR.
 *
 * Every use of an external SSA address and every declared final SSA address
 * is pinned by canonical preprocessed expected-value/mask columns.  This
 * prevents a quotient proof for one block/key/digest boundary from being
 * replayed as another. This API proves the scheduled 32-bit instructions and
 * their public boundaries. BuildFixedProgramProvenanceInstance adds internal
 * SSA copy provenance; equality links from those boundaries to the episode
 * producer/consumer relation proofs remain a separate recursive obligation.
 */
[[nodiscard]] bool BuildFixedProgramBoundaryConstraintSystem(
    const FixedProgram& program,
    const std::vector<uint32_t>& external_values,
    const std::vector<uint32_t>& final_words,
    air_quotient::AirConstraintSystem<Fp3>& out,
    std::string* why = nullptr);
[[nodiscard]] bool BuildFixedProgramBoundaryAirWitness(
    const FixedProgram& program,
    const ProgramWitness& witness,
    const std::vector<uint32_t>& external_values,
    const std::vector<uint32_t>& final_words,
    std::vector<std::vector<Fp3>>& columns,
    std::string* why = nullptr);

struct FixedProgramBoundaryAirProof {
    uint16_t registry_version{kRegistryVersion};
    ProgramKind kind{ProgramKind::Sha256Compression};
    uint256 program_commitment{};
    uint256 statement_commitment{};
    air_quotient::AirQuotientProof<Fp3> quotient;
};

/**
 * Complete internal-SSA provenance layout for one fixed SHA/ChaCha program.
 *
 * The first kFixedProgramProvenanceBaseColumns are committed before the
 * lookup challenges. They contain the complete operation/boundary trace plus
 * immutable address/use metadata. Ten post-challenge columns implement two
 * independent logarithmic-derivative lanes:
 *
 *   sum_{producer address a} uses(a)/(alpha - (a + gamma*v_a))
 *     =
 *   sum_{consumer edge (a,v)} 1/(alpha - (a + gamma*v)).
 *
 * External reads are already pinned by the boundary AIR. Internal addresses
 * are single-assignment, so equality of these multisets proves that every
 * instruction operand is the value emitted by its unique producer. Final
 * words remain boundary-pinned. Challenges are derived only after committing
 * the base-column roots.
 */
inline constexpr uint32_t kFixedProgramProvenanceOutputAddress =
    kFixedProgramBoundaryColumns;
inline constexpr uint32_t kFixedProgramProvenanceOutputUseCount =
    kFixedProgramProvenanceOutputAddress + 1;
inline constexpr uint32_t kFixedProgramProvenanceOutputHasUse =
    kFixedProgramProvenanceOutputUseCount + 1;
inline constexpr uint32_t kFixedProgramProvenanceInputAddressBase =
    kFixedProgramProvenanceOutputHasUse + 1;
inline constexpr uint32_t kFixedProgramProvenanceInputMaskBase =
    kFixedProgramProvenanceInputAddressBase + 3;
inline constexpr uint32_t kFixedProgramProvenanceBaseColumns =
    kFixedProgramProvenanceInputMaskBase + 3;
inline constexpr uint32_t kFixedProgramProvenanceProducerInverse1 =
    kFixedProgramProvenanceBaseColumns;
inline constexpr uint32_t kFixedProgramProvenanceProducerInverse2 =
    kFixedProgramProvenanceProducerInverse1 + 1;
inline constexpr uint32_t kFixedProgramProvenanceConsumerInverse1Base =
    kFixedProgramProvenanceProducerInverse2 + 1;
inline constexpr uint32_t kFixedProgramProvenanceConsumerInverse2Base =
    kFixedProgramProvenanceConsumerInverse1Base + 3;
inline constexpr uint32_t kFixedProgramProvenanceRunning1 =
    kFixedProgramProvenanceConsumerInverse2Base + 3;
inline constexpr uint32_t kFixedProgramProvenanceRunning2 =
    kFixedProgramProvenanceRunning1 + 1;
inline constexpr uint32_t kFixedProgramProvenanceColumns =
    kFixedProgramProvenanceRunning2 + 1;

struct FixedProgramProvenanceInstance {
    bool valid{false};
    std::string note;
    uint256 boundary_statement{};
    RCStage3CtlChallenges challenges{};
    air_quotient::AirConstraintSystem<Fp3> cs;
    std::vector<std::vector<Fp3>> columns;
};

struct FixedProgramProvenanceAirProof {
    uint16_t version{1};
    uint256 boundary_statement{};
    uint256 challenge_commitment{};
    air_quotient::AirQuotientProof<Fp3> quotient;
    bool valid{false};
    std::string note;
};

struct FixedProgramBoundaryInstance;

/**
 * Width-bounded vertical provenance AIR for up to 63 semantic SHA compression
 * instances plus canonical padding instances.  The fixed 1024-row program is
 * repeated to the smallest power-of-two schedule (minimum two, maximum 64)
 * containing the semantic instances. Internal SSA addresses are namespaced by
 * the immutable instance-id column before entering the two LogUp lanes, so no
 * producer/consumer edge can be substituted across compression instances.
 */
inline constexpr uint32_t kFixedProgramVerticalSemanticInstances = 63;
/** Maximum scheduled width; partial bundles use the canonical smaller power. */
inline constexpr uint32_t kFixedProgramVerticalScheduledInstances = 64;
inline constexpr uint32_t kFixedProgramVerticalInstanceIdColumn =
    kFixedProgramProvenanceColumns;
inline constexpr uint32_t kFixedProgramVerticalPhaseColumn =
    kFixedProgramVerticalInstanceIdColumn + 1;
inline constexpr uint32_t kFixedProgramVerticalActiveColumn =
    kFixedProgramVerticalPhaseColumn + 1;
inline constexpr uint32_t kFixedProgramVerticalProvenanceColumns =
    kFixedProgramVerticalActiveColumn + 1;

struct FixedProgramVerticalProvenanceInstance {
    bool valid{false};
    std::string note;
    uint32_t semantic_instances{0};
    uint32_t scheduled_instances{0};
    uint256 boundary_statement{};
    RCStage3CtlChallenges challenges{};
    air_quotient::AirConstraintSystem<Fp3> cs;
    std::vector<std::vector<Fp3>> columns;
    /** Checked AirQuotientProve hints for the pre-challenge base columns. */
    std::vector<uint256> checked_trace_root_hints;
};

struct FixedProgramVerticalProvenanceAirProof {
    uint16_t version{1};
    uint32_t semantic_instances{0};
    uint256 boundary_statement{};
    uint256 challenge_commitment{};
    air_quotient::AirQuotientProof<
        Fp3,
        air_quotient::AirFriBackendFp3StreamingColumns>
        quotient;
    bool valid{false};
    std::string note;
};

struct FixedProgramWitnessBoundaryLink {
    uint32_t source_instance{0};
    uint32_t source_final_word{0};
    uint32_t target_instance{0};
    /** One-based canonical external SSA address. */
    uint32_t target_external_address{0};
    /**
     * Optional explicit nonzero bus ID. Reuse the same ID for every target
     * of one source word to obtain a fan-out-safe LogUp multiplicity. Zero
     * requests the legacy link-index-derived unique ID.
     */
    uint64_t link_id{0};
};

struct FixedProgramVerticalWitnessBoundaryInstance {
    bool valid{false};
    std::string note;
    uint32_t semantic_instances{0};
    uint32_t scheduled_instances{0};
    uint256 public_statement{};
    /**
     * Epoch-R0 row commitment over exactly `base_column_indices`.  All
     * internal-SSA and boundary-link LogUp challenges are derived from this
     * commitment before their inverse/running columns are filled.
     */
    uint256 base_row_commitment{};
    std::vector<uint32_t> base_column_indices;
    /** Prover-local R0 tree retained for later shared-query openings. */
    std::shared_ptr<Fri3AlgRowTreeCache>
        base_row_tree_cache;
    RCStage3CtlChallenges challenges{};
    air_quotient::AirConstraintSystem<Fp3> cs;
    std::vector<std::vector<Fp3>> columns;
    std::vector<uint32_t> final_output_rows;
    /**
     * The final eight words, their 256 little-endian word bits, and their
     * canonical SHA digest bytes are epoch-R0 columns.  A SHA digest byte at
     * offset 4*w+lane is reconstructed from word w bits
     * [8*(3-lane),8*(3-lane)+7], i.e. SHA's big-endian word serialization.
     */
    uint32_t output_export_base{0};
    /** Eight little-endian groups of 32 boolean digest bits. */
    uint32_t output_bit_base{0};
    uint32_t output_byte_base{0};
    /**
     * Canonical first-pass SHA message-word export.  Exactly one row per
     * external message word is active. `input_address_column` is the global
     * word address instance*16+word, `input_word_base` is equality-bound to
     * the selected fixed-program input, and four big-endian bytes plus 32
     * little-endian word bits reconstruct that word.
     */
    uint32_t input_word_base{0};
    uint32_t input_byte_base{0};
    uint32_t input_bit_base{0};
    uint32_t input_active_column{0};
    uint32_t input_address_column{0};
};

/**
 * Verifier-only reconstruction of the challenge-dependent SHA/ChaCha CS.
 * Private external words and every final word supplied by the caller are
 * ignored. The builder deterministically fills private words with zero,
 * propagates declared links in instance order, executes only that dummy
 * program to obtain structurally valid placeholder finals, and instantiates
 * the CS from the caller-authenticated R0 commitment. No honest private SHA
 * witness or native digest is needed by the verifier.
 */
struct FixedProgramVerticalWitnessBoundaryVerifierInstance {
    bool valid{false};
    std::string note;
    uint32_t semantic_instances{0};
    uint32_t scheduled_instances{0};
    uint256 public_statement{};
    uint256 base_row_commitment{};
    std::vector<uint32_t> base_column_indices;
    RCStage3CtlChallenges challenges{};
    air_quotient::AirConstraintSystem<Fp3> cs;
    std::vector<uint32_t> final_output_rows;
    uint32_t output_export_base{0};
    uint32_t output_bit_base{0};
    uint32_t output_byte_base{0};
    uint32_t input_word_base{0};
    uint32_t input_byte_base{0};
    uint32_t input_bit_base{0};
    uint32_t input_active_column{0};
    uint32_t input_address_column{0};
};

[[nodiscard]]
FixedProgramVerticalWitnessBoundaryVerifierInstance
BuildFixedProgramVerticalWitnessBoundaryVerifierInstance(
    const FixedProgram& program,
    const std::vector<FixedProgramBoundaryInstance>&
        public_boundary_templates,
    const std::vector<std::vector<uint8_t>>&
        public_external_masks,
    const std::vector<FixedProgramWitnessBoundaryLink>& links,
    const uint256& fs_seed,
    const uint256& base_row_commitment);

[[nodiscard]] uint256
CommitFixedProgramVerticalWitnessBoundaryStatement(
    const FixedProgram& program,
    const std::vector<FixedProgramBoundaryInstance>& boundaries,
    const std::vector<std::vector<uint8_t>>& public_external_masks,
    const std::vector<FixedProgramWitnessBoundaryLink>& links);

/**
 * Witness-owned vertical boundary mode. Public masks pin only verifier-known
 * external words. Final words and mask-zero external words remain witness
 * data; `links` equality-bind final cells to every use of the target external
 * address through two instance-independent LogUp lanes. The eight final
 * output exports are also reconstructed from 256 witness-owned boolean
 * columns, giving downstream recursive consumers a canonical bit interface.
 */
[[nodiscard]] FixedProgramVerticalWitnessBoundaryInstance
BuildFixedProgramVerticalWitnessBoundaryInstance(
    const FixedProgram& program,
    const std::vector<FixedProgramBoundaryInstance>& honest_boundaries,
    const std::vector<std::vector<uint8_t>>& public_external_masks,
    const std::vector<FixedProgramWitnessBoundaryLink>& links,
    const uint256& fs_seed,
    /**
     * Verifier-only override. When non-null, challenges are reconstructed
     * from this already-bound R0 commitment rather than from the supplied
     * (possibly dummy-private) witness columns.
     */
    const uint256& precommitted_base_row = {});

[[nodiscard]] FixedProgramVerticalProvenanceInstance
BuildFixedProgramVerticalProvenanceInstance(
    const FixedProgram& program,
    const std::vector<FixedProgramBoundaryInstance>& boundaries,
    const uint256& fs_seed);

[[nodiscard]] bool ProveFixedProgramVerticalProvenanceAir(
    const FixedProgram& program,
    const std::vector<FixedProgramBoundaryInstance>& boundaries,
    const uint256& fs_seed,
    FixedProgramVerticalProvenanceAirProof& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyFixedProgramVerticalProvenanceAir(
    const FixedProgram& program,
    const std::vector<FixedProgramBoundaryInstance>& boundaries,
    const uint256& fs_seed,
    const FixedProgramVerticalProvenanceAirProof& proof,
    std::string* why = nullptr);

[[nodiscard]] FixedProgramProvenanceInstance
BuildFixedProgramProvenanceInstance(
    const FixedProgram& program,
    const ProgramWitness& witness,
    const std::vector<uint32_t>& external_values,
    const std::vector<uint32_t>& final_words,
    const uint256& fs_seed);

[[nodiscard]] bool ProveFixedProgramProvenanceAir(
    const FixedProgram& program,
    const ProgramWitness& witness,
    const std::vector<uint32_t>& external_values,
    const std::vector<uint32_t>& final_words,
    const uint256& fs_seed,
    FixedProgramProvenanceAirProof& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyFixedProgramProvenanceAir(
    const FixedProgram& program,
    const std::vector<uint32_t>& external_values,
    const std::vector<uint32_t>& final_words,
    const uint256& fs_seed,
    const FixedProgramProvenanceAirProof& proof,
    std::string* why = nullptr);

struct FixedProgramBoundaryInstance {
    std::vector<uint32_t> external_values;
    std::vector<uint32_t> final_words;
    bool operator==(const FixedProgramBoundaryInstance&) const = default;
};

/**
 * Public SHA-compression boundary adapter used by streaming manifests.
 *
 * It maps one already-padded 64-byte block, an input chaining state and an
 * asserted output state to the canonical fixed-program external/final word
 * vectors, including the immutable SHA round constants.  It does not execute
 * SHA compression.
 */
[[nodiscard]] std::array<uint32_t, 8>
CanonicalSha256InitialState();
[[nodiscard]] bool BuildSha256CompressionBoundaryInstance(
    const std::array<uint8_t, 64>& padded_block,
    const std::array<uint32_t, 8>& h_in,
    const std::array<uint32_t, 8>& h_out,
    FixedProgramBoundaryInstance& out,
    std::string* why = nullptr);

/**
 * Four-way direct-product packing for fixed-program hash AIRs.  Each lane has
 * an independent word/carry/selector/public-boundary column block and a
 * distinct CTL namespace.  The lanes share only the trace domain and one
 * quotient proof; no row or boundary value is reused between lanes.
 *
 * 4 * 152 = 608 columns is below the normalized recursive verifier's
 * 1,092-column V1 cap.  This is genuine trace packing, so four hash program
 * instances count as one proof site once this exact construction is used.
 */
inline constexpr uint32_t kFixedProgramPackedLanes = 4;
inline constexpr uint32_t kFixedProgramMaxPackedLanes = 7;
inline constexpr uint32_t kFixedProgramPackedBoundaryColumns =
    kFixedProgramPackedLanes * kFixedProgramBoundaryColumns;
inline constexpr uint32_t kFixedProgramRecursiveWidthCap = 1092;
static_assert(
    kFixedProgramPackedBoundaryColumns <= kFixedProgramRecursiveWidthCap);

struct FixedProgramPackedBoundaryInstance {
    uint32_t ctl_namespace_id{0};
    std::vector<uint32_t> external_values;
    std::vector<uint32_t> final_words;
    bool operator==(const FixedProgramPackedBoundaryInstance&) const = default;
};

struct FixedProgramPackedBoundaryAirProof {
    uint16_t registry_version{kRegistryVersion};
    ProgramKind kind{ProgramKind::Sha256Compression};
    uint256 program_commitment{};
    uint256 statement_commitment{};
    air_quotient::AirQuotientProof<Fp3> quotient;
};

/**
 * Genuine four-lane fixed-program provenance direct product.
 *
 * Each lane retains its complete 171-column operation, boundary, and
 * two-epoch internal-SSA trace.  Lane lookup challenges are derived from the
 * commitment to every lane's base columns, the packed public statement, the
 * lane index, and its unique CTL namespace.  Thus the lanes share one
 * quotient/FRI proof without sharing an address or lookup namespace.
 *
 * 4 * 171 = 684 columns, below the normalized recursive verifier's
 * 1,092-column V1 cap.
 */
inline constexpr uint32_t kFixedProgramPackedProvenanceColumns =
    kFixedProgramPackedLanes * kFixedProgramProvenanceColumns;
static_assert(
    kFixedProgramPackedProvenanceColumns <=
    kFixedProgramRecursiveWidthCap);

struct FixedProgramPackedProvenanceInstance {
    bool valid{false};
    std::string note;
    uint256 statement_commitment{};
    uint256 trace_commitment{};
    std::array<RCStage3CtlChallenges,
               kFixedProgramPackedLanes> challenges{};
    air_quotient::AirConstraintSystem<Fp3> cs;
    std::vector<std::vector<Fp3>> columns;
};

struct FixedProgramPackedProvenanceAirProof {
    uint16_t registry_version{kRegistryVersion};
    ProgramKind kind{ProgramKind::Sha256Compression};
    uint256 program_commitment{};
    uint256 statement_commitment{};
    uint256 trace_commitment{};
    std::array<uint256, kFixedProgramPackedLanes>
        challenge_commitments{};
    air_quotient::AirQuotientProof<Fp3> quotient;
    bool valid{false};
};

[[nodiscard]] FixedProgramPackedProvenanceInstance
BuildFixedProgramPackedProvenanceInstance(
    const FixedProgram& program,
    const std::array<ProgramWitness,
                     kFixedProgramPackedLanes>& witnesses,
    const std::array<FixedProgramPackedBoundaryInstance,
                     kFixedProgramPackedLanes>& instances,
    const uint256& fs_seed);
[[nodiscard]] bool ProveFixedProgramPackedProvenanceAir(
    const FixedProgram& program,
    const std::array<ProgramWitness,
                     kFixedProgramPackedLanes>& witnesses,
    const std::array<FixedProgramPackedBoundaryInstance,
                     kFixedProgramPackedLanes>& instances,
    const uint256& fs_seed,
    FixedProgramPackedProvenanceAirProof& out,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyFixedProgramPackedProvenanceAir(
    const FixedProgram& program,
    const std::array<FixedProgramPackedBoundaryInstance,
                     kFixedProgramPackedLanes>& instances,
    const uint256& fs_seed,
    const FixedProgramPackedProvenanceAirProof& proof,
    std::string* why = nullptr);

/** Runtime-width research surface used to compare 4/6/7 direct products.
 * Consensus policy may select only a lane count with a fixed round-trip test. */
[[nodiscard]] bool BuildFixedProgramParallelBoundaryConstraintSystem(
    const FixedProgram& program,
    const std::vector<FixedProgramPackedBoundaryInstance>& instances,
    air_quotient::AirConstraintSystem<Fp3>& out,
    std::string* why = nullptr);
[[nodiscard]] bool BuildFixedProgramParallelBoundaryAirWitness(
    const FixedProgram& program,
    const std::vector<ProgramWitness>& witnesses,
    const std::vector<FixedProgramPackedBoundaryInstance>& instances,
    std::vector<std::vector<Fp3>>& columns,
    std::string* why = nullptr);

[[nodiscard]] uint32_t FixedProgramPackedColumn(
    uint32_t lane, uint32_t lane_column);
[[nodiscard]] bool BuildFixedProgramPackedBoundaryConstraintSystem(
    const FixedProgram& program,
    const std::array<FixedProgramPackedBoundaryInstance,
                     kFixedProgramPackedLanes>& instances,
    air_quotient::AirConstraintSystem<Fp3>& out,
    std::string* why = nullptr);
[[nodiscard]] bool BuildFixedProgramPackedBoundaryAirWitness(
    const FixedProgram& program,
    const std::array<ProgramWitness, kFixedProgramPackedLanes>& witnesses,
    const std::array<FixedProgramPackedBoundaryInstance,
                     kFixedProgramPackedLanes>& instances,
    std::vector<std::vector<Fp3>>& columns,
    std::string* why = nullptr);
[[nodiscard]] bool BuildFixedProgramPackedCtlSchedules(
    const FixedProgram& program,
    const std::array<FixedProgramPackedBoundaryInstance,
                     kFixedProgramPackedLanes>& instances,
    std::array<RCStage3CtlSchedule, kFixedProgramPackedLanes>& out,
    std::string* why = nullptr);
[[nodiscard]] uint256 CommitFixedProgramPackedBoundaryStatement(
    const FixedProgram& program,
    const std::array<FixedProgramPackedBoundaryInstance,
                     kFixedProgramPackedLanes>& instances);
[[nodiscard]] bool ProveFixedProgramPackedBoundaryAir(
    const FixedProgram& program,
    const std::array<ProgramWitness, kFixedProgramPackedLanes>& witnesses,
    const std::array<FixedProgramPackedBoundaryInstance,
                     kFixedProgramPackedLanes>& instances,
    const uint256& fs_seed,
    FixedProgramPackedBoundaryAirProof& out,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyFixedProgramPackedBoundaryAir(
    const FixedProgram& program,
    const std::array<FixedProgramPackedBoundaryInstance,
                     kFixedProgramPackedLanes>& instances,
    const FixedProgramPackedBoundaryAirProof& proof,
    const uint256& fs_seed,
    std::string* why = nullptr);

[[nodiscard]] uint256 CommitFixedProgram(const FixedProgram& program);
[[nodiscard]] uint256 CommitFixedProgramBoundaryStatement(
    const FixedProgram& program,
    const std::vector<uint32_t>& external_values,
    const std::vector<uint32_t>& final_words);
[[nodiscard]] bool ProveFixedProgramBoundaryAir(
    const FixedProgram& program,
    const ProgramWitness& witness,
    const std::vector<uint32_t>& external_values,
    const std::vector<uint32_t>& final_words,
    const uint256& fs_seed,
    FixedProgramBoundaryAirProof& out,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyFixedProgramBoundaryAir(
    const FixedProgram& program,
    const std::vector<uint32_t>& external_values,
    const std::vector<uint32_t>& final_words,
    const FixedProgramBoundaryAirProof& proof,
    const uint256& fs_seed,
    std::string* why = nullptr);

enum class ShaMode : uint8_t {
    Single = 1,
    Double = 2,
};

struct ShaPassManifest {
    uint64_t message_size{0};
    std::vector<std::array<uint8_t, 64>> padded_blocks;
    std::vector<std::array<uint32_t, 8>> h_in;
    std::vector<std::array<uint32_t, 8>> h_out;
    bool operator==(const ShaPassManifest&) const = default;
};

/**
 * Exact SHA-256/SHA256d witness manifest. `preimage` is prover witness data;
 * the canonical commitment binds it without making verifier-native replay an
 * acceptance path. Every padded block and chaining boundary is explicit.
 */
struct ShaManifest {
    ShaMode mode{ShaMode::Single};
    std::vector<uint8_t> preimage;
    ShaPassManifest first;
    ShaPassManifest second; // empty for Single; one 32-byte pass for Double
    std::array<uint8_t, 32> digest{};
    uint256 commitment{};
    bool operator==(const ShaManifest&) const = default;
};

[[nodiscard]] bool BuildShaManifest(const std::vector<uint8_t>& preimage,
                                    ShaMode mode,
                                    ShaManifest& out,
                                    std::string* why = nullptr);
[[nodiscard]] bool ValidateShaManifest(const ShaManifest& manifest,
                                       std::string* why = nullptr);
[[nodiscard]] uint256 CommitShaManifest(const ShaManifest& manifest);

enum class CounterXofMode : uint8_t {
    RawBytes = 1,
    MantissaE2M1 = 2,
    Scale2Bit = 3,
};

struct CounterXofManifest {
    uint256 seed{};
    uint8_t domain{0};
    CounterXofMode mode{CounterXofMode::RawBytes};
    uint64_t output_count{0};
    /** One single-SHA manifest per exact counter, starting at zero. */
    std::vector<ShaManifest> counter_hashes;
    /** Raw bytes, signed mantissas in two's-complement byte form, or 2-bit
     * scale codes according to mode. */
    std::vector<uint8_t> output;
    uint256 commitment{};
    bool operator==(const CounterXofManifest&) const = default;
};

[[nodiscard]] bool BuildCounterXofManifest(
    const uint256& seed, uint8_t domain, CounterXofMode mode,
    uint64_t output_count, CounterXofManifest& out,
    std::string* why = nullptr);
[[nodiscard]] bool ValidateCounterXofManifest(
    const CounterXofManifest& manifest, std::string* why = nullptr);
[[nodiscard]] uint256 CommitCounterXofManifest(
    const CounterXofManifest& manifest);
[[nodiscard]] bool BuildCounterXofManifestBoundaryInstances(
    const CounterXofManifest& manifest,
    std::vector<FixedProgramBoundaryInstance>& out,
    std::string* why = nullptr);

struct ChaChaConsumptionManifest {
    std::array<uint8_t, 32> key{};
    uint32_t nonce_first{0};
    uint64_t nonce_second{0};
    uint32_t first_counter{0};
    uint64_t output_bytes{0};
    /** Complete 64-byte block outputs in counter order. */
    std::vector<std::array<uint8_t, 64>> blocks;
    /** Exact consumed prefix; no uncommitted trailing block is permitted. */
    std::vector<uint8_t> output;
    uint256 commitment{};
    bool operator==(const ChaChaConsumptionManifest&) const = default;
};

[[nodiscard]] bool BuildChaChaConsumptionManifest(
    const std::array<uint8_t, 32>& key, uint32_t nonce_first,
    uint64_t nonce_second, uint32_t first_counter, uint64_t output_bytes,
    ChaChaConsumptionManifest& out, std::string* why = nullptr);
[[nodiscard]] bool ValidateChaChaConsumptionManifest(
    const ChaChaConsumptionManifest& manifest, std::string* why = nullptr);
[[nodiscard]] uint256 CommitChaChaConsumptionManifest(
    const ChaChaConsumptionManifest& manifest);

/**
 * Convert exact registered manifests into the public boundary statements
 * consumed by the executable fixed-program AIR.  These adapters validate
 * padding/counter/chaining/stream structure and commitments without
 * recomputing SHA-256 or ChaCha20 natively.  The returned instances are in
 * exact compression/block order.
 */
[[nodiscard]] bool BuildShaManifestBoundaryInstances(
    const ShaManifest& manifest,
    std::vector<FixedProgramBoundaryInstance>& out,
    std::string* why = nullptr);
[[nodiscard]] bool BuildChaChaManifestBoundaryInstances(
    const ChaChaConsumptionManifest& manifest,
    std::vector<FixedProgramBoundaryInstance>& out,
    std::string* why = nullptr);

enum class DirectHashRelation : uint8_t {
    CoupledBarrier = 1,
    EpisodeDigest = 2,
    CoupledDigest = 3,
    FinalDigest = 4,
};

struct DirectSha256dManifest {
    DirectHashRelation relation{DirectHashRelation::FinalDigest};
    std::vector<uint8_t> preimage;
    ShaManifest sha256d;
    uint256 digest{};
    uint256 commitment{};
    bool operator==(const DirectSha256dManifest&) const = default;
};

[[nodiscard]] bool BuildDirectSha256dManifest(
    DirectHashRelation relation, const std::vector<uint8_t>& preimage,
    DirectSha256dManifest& out, std::string* why = nullptr);
[[nodiscard]] bool ValidateDirectSha256dManifest(
    const DirectSha256dManifest& manifest, std::string* why = nullptr);
[[nodiscard]] uint256 CommitDirectSha256dManifest(
    const DirectSha256dManifest& manifest);
[[nodiscard]] bool BuildDirectSha256dManifestBoundaryInstances(
    const DirectSha256dManifest& manifest,
    std::vector<FixedProgramBoundaryInstance>& out,
    std::string* why = nullptr);

enum class TileTreeNodeKind : uint8_t {
    Leaf = 1,
    PadLeaf = 2,
    Internal = 3,
};

struct TileTreeHashNode {
    TileTreeNodeKind kind{TileTreeNodeKind::Leaf};
    uint32_t level{0};
    uint64_t index{0};
    ShaManifest sha256d;
    uint256 digest{};
    bool operator==(const TileTreeHashNode&) const = default;
};

struct TileTreeManifest {
    uint32_t t_leaf{0};
    std::vector<uint8_t> stream;
    uint64_t logical_leaf_count{0};
    uint64_t padded_leaf_count{0};
    std::vector<uint256> leaf_hashes;
    /** Regular leaf hashes, at most one canonical pad-leaf hash, then every
     * internal node in level/index order. */
    std::vector<TileTreeHashNode> hash_nodes;
    uint256 root{};
    uint256 commitment{};
    bool operator==(const TileTreeManifest&) const = default;
};

[[nodiscard]] bool BuildTileTreeManifest(
    const std::vector<uint8_t>& stream, uint32_t t_leaf,
    TileTreeManifest& out, std::string* why = nullptr);
[[nodiscard]] bool ValidateTileTreeManifest(
    const TileTreeManifest& manifest, std::string* why = nullptr);
[[nodiscard]] uint256 CommitTileTreeManifest(
    const TileTreeManifest& manifest);
[[nodiscard]] bool BuildTileTreeManifestBoundaryInstances(
    const TileTreeManifest& manifest,
    std::vector<FixedProgramBoundaryInstance>& out,
    std::string* why = nullptr);

struct EpisodeDigestManifest {
    uint32_t expected_rounds{0};
    std::vector<uint256> round_roots;
    DirectSha256dManifest direct;
    uint256 commitment{};
    bool operator==(const EpisodeDigestManifest&) const = default;
};

struct CoupledBarrierManifest {
    uint32_t transcript_version{0};
    uint32_t expected_barriers{0};
    uint32_t barrier_index{0};
    std::vector<uint8_t> state_bytes;
    DirectSha256dManifest direct;
    uint256 commitment{};
    bool operator==(const CoupledBarrierManifest&) const = default;
};

struct CoupledDigestManifest {
    uint32_t transcript_version{0};
    uint32_t expected_barriers{0};
    uint256 bank_root{};
    std::vector<uint256> barrier_roots;
    DirectSha256dManifest direct;
    uint256 commitment{};
    bool operator==(const CoupledDigestManifest&) const = default;
};

struct ComposedFinalDigestManifest {
    uint16_t proof_version{0};
    int32_t height{0};
    uint256 header_commitment{};
    uint256 params_commitment{};
    uint32_t episode_profile{0};
    uint32_t coupled_profile{0};
    uint32_t transcript_version{0};
    uint256 episode_digest{};
    uint256 coupled_digest{};
    DirectSha256dManifest direct;
    uint256 commitment{};
    bool operator==(const ComposedFinalDigestManifest&) const = default;
};

/** Typed preimage builders prevent a prover choosing an arbitrary direct-hash
 * byte string with the right digest. */
[[nodiscard]] bool BuildEpisodeDigestManifest(
    uint32_t expected_rounds, const std::vector<uint256>& round_roots,
    EpisodeDigestManifest& out, std::string* why = nullptr);
[[nodiscard]] bool ValidateEpisodeDigestManifest(
    const EpisodeDigestManifest& manifest, std::string* why = nullptr);
[[nodiscard]] uint256 CommitEpisodeDigestManifest(
    const EpisodeDigestManifest& manifest);
[[nodiscard]] bool BuildCoupledBarrierManifest(
    uint32_t transcript_version, uint32_t expected_barriers,
    uint32_t barrier_index, const std::vector<uint8_t>& state_bytes,
    CoupledBarrierManifest& out, std::string* why = nullptr);
[[nodiscard]] bool ValidateCoupledBarrierManifest(
    const CoupledBarrierManifest& manifest, std::string* why = nullptr);
[[nodiscard]] uint256 CommitCoupledBarrierManifest(
    const CoupledBarrierManifest& manifest);
[[nodiscard]] bool BuildCoupledDigestManifest(
    uint32_t transcript_version, uint32_t expected_barriers,
    const uint256& bank_root, const std::vector<uint256>& barrier_roots,
    CoupledDigestManifest& out, std::string* why = nullptr);
[[nodiscard]] bool ValidateCoupledDigestManifest(
    const CoupledDigestManifest& manifest, std::string* why = nullptr);
[[nodiscard]] uint256 CommitCoupledDigestManifest(
    const CoupledDigestManifest& manifest);
[[nodiscard]] bool BuildComposedFinalDigestManifest(
    uint16_t proof_version, int32_t height,
    const uint256& header_commitment, const uint256& params_commitment,
    uint32_t episode_profile, uint32_t coupled_profile,
    uint32_t transcript_version, const uint256& episode_digest,
    const uint256& coupled_digest, ComposedFinalDigestManifest& out,
    std::string* why = nullptr);
[[nodiscard]] bool ValidateComposedFinalDigestManifest(
    const ComposedFinalDigestManifest& manifest,
    std::string* why = nullptr);
[[nodiscard]] uint256 CommitComposedFinalDigestManifest(
    const ComposedFinalDigestManifest& manifest);

// ============================================================================
// PR-89 certified_bits: manifest recursive bindings.
//
// Each hash relation already maps its manifest sequence to an ordered vector of
// executable SHA/ChaCha boundary instances (Build*ManifestBoundaryInstances) --
// these ARE the committed columns consumed by the producer/consumer proofs.
// What the {Xof,ChaChaInitAndBlock,CompleteStream}Manifest gaps flagged is that
// this ordered committed-column stream was not recursively BOUND to the
// committed manifest root: nothing forced "column i opens to manifest element i
// under the manifest commitment".
//
// The binding below closes exactly that. It folds the ordered boundary-column
// stream into a Merkle root (reusing the in-AIR SHA256d 2->1 compression, the
// same primitive that commits every manifest) where leaf i binds its stream
// index i, and then commits (manifest_commitment || stream_column_root ||
// instance_count) into one binding value. Because the leaf index is part of the
// preimage and the manifest commitment is folded in, a wrong element value OR a
// reordering of the committed columns changes stream_column_root and the
// binding fails closed. This is the commitment-opening mechanism shared with
// the CopyAndCtlWiring lane: each committed column opens to stream_column_root,
// and stream_column_root is bound to the committed manifest root.
//
// It does NOT by itself flip relation_complete: that also needs the
// CopyAndCtlWiring boundary CTLs and the RecursiveAggregation fold to close for
// the same relation (see CurrentRelationReadiness()).
// ============================================================================
struct HashManifestRecursiveBinding {
    /** Committed manifest root (Commit*Manifest): the value the stream opens under. */
    uint256 manifest_commitment{};
    /** Merkle root over the ordered committed boundary-column stream; leaf i
     * binds stream index i, so a wrong value or reordering changes it. */
    uint256 stream_column_root{};
    /** Number of committed boundary columns folded into the root. */
    uint64_t instance_count{0};
    /** Sha256d binding tying the committed column stream to the committed
     * manifest root: the recursive opening witness. */
    uint256 binding_commitment{};
    bool operator==(const HashManifestRecursiveBinding&) const = default;
};

/** Generic binding over an already-materialized committed-column stream.
 * `family_domain` separates the three manifest families. */
[[nodiscard]] bool BuildHashManifestRecursiveBinding(
    const char* family_domain, const uint256& manifest_commitment,
    const std::vector<FixedProgramBoundaryInstance>& stream,
    HashManifestRecursiveBinding& out, std::string* why = nullptr);
[[nodiscard]] bool VerifyHashManifestRecursiveBinding(
    const char* family_domain, const uint256& manifest_commitment,
    const std::vector<FixedProgramBoundaryInstance>& stream,
    const HashManifestRecursiveBinding& binding, std::string* why = nullptr);

/** XofCounterManifest: bind the XOF counter sequence to its counter columns. */
[[nodiscard]] bool BuildXofCounterManifestRecursiveBinding(
    const CounterXofManifest& manifest, HashManifestRecursiveBinding& out,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyXofCounterManifestRecursiveBinding(
    const CounterXofManifest& manifest,
    const HashManifestRecursiveBinding& binding, std::string* why = nullptr);

/** ChaChaInitAndBlockManifest: bind the ChaCha init+block manifest to its columns. */
[[nodiscard]] bool BuildChaChaInitAndBlockManifestRecursiveBinding(
    const ChaChaConsumptionManifest& manifest,
    HashManifestRecursiveBinding& out, std::string* why = nullptr);
[[nodiscard]] bool VerifyChaChaInitAndBlockManifestRecursiveBinding(
    const ChaChaConsumptionManifest& manifest,
    const HashManifestRecursiveBinding& binding, std::string* why = nullptr);

/** CompleteStreamManifest: bind the complete leaf/node stream to its columns. */
[[nodiscard]] bool BuildCompleteStreamManifestRecursiveBinding(
    const TileTreeManifest& manifest, HashManifestRecursiveBinding& out,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyCompleteStreamManifestRecursiveBinding(
    const TileTreeManifest& manifest,
    const HashManifestRecursiveBinding& binding, std::string* why = nullptr);
/** CompleteStreamManifest: bind the complete digest stream to its columns. */
[[nodiscard]] bool BuildCompleteStreamManifestRecursiveBinding(
    const DirectSha256dManifest& manifest, HashManifestRecursiveBinding& out,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyCompleteStreamManifestRecursiveBinding(
    const DirectSha256dManifest& manifest,
    const HashManifestRecursiveBinding& binding, std::string* why = nullptr);

/** The three manifest recursive bindings are implemented and round-trip/tamper
 * tested (matmul_v4_rc_stage3_hash_air_tests). Each closes the per-relation
 * manifest gap only; relation_complete stays false until CopyAndCtlWiring and
 * RecursiveAggregation also close. */
inline constexpr bool kHashXofCounterManifestBindingExecutable = true;
inline constexpr bool kHashChaChaInitAndBlockManifestBindingExecutable = true;
inline constexpr bool kHashCompleteStreamManifestBindingExecutable = true;

enum class Relation : uint8_t {
    BuilderShaCounterXof = 1,
    BuilderChaCha20 = 2,
    ExtractChaCha20 = 3,
    TileTreeSha256d = 4,
    CoupledBarrierSha256d = 5,
    FinalDigestSha256d = 6,
};

enum class GapCode : uint8_t {
    FixedRoundScheduler = 1,
    CopyAndCtlWiring = 2,
    ShaPaddingAndChaining = 3,
    XofCounterManifest = 4,
    ChaChaInitAndBlockManifest = 5,
    CompleteStreamManifest = 6,
    RecursiveAggregation = 7,
};

struct Gap {
    GapCode code{};
    std::string detail;
};

struct RelationReadiness {
    Relation relation{};
    bool instruction_air_complete{false};
    bool relation_complete{false};
    std::vector<Family> required_families;
    std::vector<Gap> gaps;
};

[[nodiscard]] std::vector<RelationReadiness> CurrentRelationReadiness();

inline constexpr bool kHashInstructionAirExecutable = true;
inline constexpr bool kHashFixedProgramAirExecutable = true;
inline constexpr bool kHashMultiBlockManifestsExecutable = true;
inline constexpr bool kHashManifestBoundaryAirExecutable = true;
inline constexpr bool kHashPackedBoundaryAirExecutable = true;
inline constexpr bool kHashInternalSsaProvenanceExecutable = true;
// O-EXACT (SHA-256 AIR functional exactness) — the obligation the T-ALIGN
// dichotomy (lemma 4) depends on: that ANY assignment satisfying the SHA AIR IS a
// genuine SHA256d compression pair. STATUS (PR-89 residual B.2): the per-
// instruction AIRs and the 952-row fixed compression schedule are executable
// (kHashInstructionAirExecutable / kHashFixedProgramAirExecutable == true), so
// omission/reordering is closed at the program-description layer. What remains
// OPEN for every Relation (see CurrentRelationReadiness(); each has
// relation_complete == false) is the BOUNDARY BINDING + RECURSIVE AGGREGATION:
//   - CopyAndCtlWiring: the two-epoch provenance proof closes INTERNAL SSA copies,
//     but the external/final boundary cells are not yet equality-linked (CTL) to
//     the producer/consumer role-proof columns at the recursive root;
//   - {Xof,ChaChaInitAndBlock,CompleteStream}Manifest: the exact key/nonce/counter
//     and leaf/node/digest stream manifests map to executable boundary instances
//     but are not recursively BOUND to their producer/consumer columns;
//   - RecursiveAggregation: boundary-pinned instruction proofs + their CTL
//     children are not folded into the normalized recursive root.
// Closing O-EXACT = wiring those boundary CTLs end-to-end and folding all shards
// into one normalized recursive root, then the extractor argument (A-EXTRACT) that
// a satisfying assignment yields the genuine compression pair. Until then this
// stays false and promotes no bits; consensus authority remains ExactReplay.
inline constexpr bool kHashRelationsComplete = false;
inline constexpr bool kHashConsensusAuthority = false;

} // namespace matmul::v4::rc::stage3_hash_air

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_HASH_AIR_H
