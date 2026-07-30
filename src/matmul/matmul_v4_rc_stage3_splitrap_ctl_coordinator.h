// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_SPLITRAP_CTL_COORDINATOR_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_SPLITRAP_CTL_COORDINATOR_H

#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_stage3_coupled_bank_product.h>
#include <matmul/matmul_v4_rc_stage3_ctl.h>
#include <matmul/matmul_v4_rc_stage3_verifier_air.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::splitrap_ctl {

namespace aq = air_quotient;
using gkr_field::Fp3;

inline constexpr uint16_t kCoupledBankEqualityReceiptVersion = 1;
inline constexpr uint32_t kCoupledBankEqualityBusId =
    0x43324232U; // "C2B2"

/**
 * One challenge-dependent child whose CTL VALUE is a direct same-trace alias
 * of a relation column. R0 is the ordered relation trace followed by
 * NAMESPACE/STAGE/ADDRESS/VALUE/MULTIPLICITY. Rdep is exactly
 * INVERSE1/INVERSE2/TERM1/TERM2/RUNNING1/RUNNING2.
 */
struct CoupledBankEqualityChildV1 {
    RCStage3CtlChildPin pin;
    aq::AirQuotientSplitRapRowsProof proof;
    uint256 proof_commitment{};
};

struct Arity4TerminalSlotV1 {
    bool active{false};
    uint256 child_proof_commitment{};
    RCStage3CtlTerminal terminal{};
};

/**
 * Executable one-role coordinator/cancellation receipt.
 *
 * Slot 0 is the registered CoupledBank relation proof. Slot 1 is a canonical
 * projection relation with opposite row tags. Slots 2 and 3 are canonical
 * inactive padding. The parent AIR pins all four public terminal rows and
 * proves both Fp3 lane sums are zero.
 *
 * This is intentionally not advertised as a recursive fixed point: child
 * Split-RAP proofs execute natively before the parent AIR is accepted.
 */
struct CoupledBankEqualityReceiptV1 {
    uint16_t version{kCoupledBankEqualityReceiptVersion};
    RCStage3CtlManifest manifest;
    std::array<RCStage3CtlSchedule, 2> schedules;
    RCStage3CtlChallenges challenges;
    std::array<CoupledBankEqualityChildV1, 2> children;
    std::array<Arity4TerminalSlotV1, 4> terminal_slots;
    aq::AirQuotientRowsProof parent_proof;
    uint256 parent_seed{};
    uint256 receipt_commitment{};
};

struct CoupledBankEqualityAuditV1 {
    uint32_t rows{0};
    bool ordered_phase0_roots{false};
    bool challenges_after_all_phase0_roots{false};
    bool producer_relation_output_same_trace{false};
    bool receiver_projection_same_trace{false};
    bool producer_split_rap_verified{false};
    bool receiver_split_rap_verified{false};
    bool dependent_columns_are_exact_ctl_suffix{false};
    bool proof_owned_terminals{false};
    bool dual_lane_public_composition_zero{false};
    bool arity4_parent_air_verified{false};
    bool child_commitments_bound_in_parent_seed{false};
    bool producer_registered_column_roots_bound{false};
    bool registered_receiver_semantics_bound{false};
    bool child_verifiers_execute_in_parent_air{false};
    bool recursive_fixed_point{false};
    bool production_authority{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] bool ProveCoupledBankEqualityReceiptV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    const std::vector<std::vector<Fp3>>& relation_columns,
    const uint256& public_seed,
    CoupledBankEqualityReceiptV1& out,
    std::string* why = nullptr);

[[nodiscard]] CoupledBankEqualityAuditV1
VerifyCoupledBankEqualityReceiptV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    const CoupledBankEqualityReceiptV1& receipt,
    const uint256& public_seed);

// -------------------------------------------------------------------------
// Normalized recursive-consumption seam.
// -------------------------------------------------------------------------

inline constexpr uint16_t
    kCoupledBankEqualityReceiptCellMapVersion = 1;

enum class ReceiptCellSectionV1 : uint8_t {
    HeaderAndSourcePin = 1,
    Manifest = 2,
    Schedules = 3,
    Challenges = 4,
    ChildPins = 5,
    TerminalSlots = 6,
    ChildSplitRapCodec = 7,
    ParentRowsProof = 8,
};

struct ReceiptCellSpanV1 {
    ReceiptCellSectionV1 section{
        ReceiptCellSectionV1::HeaderAndSourcePin};
    uint32_t item{0};
    uint32_t begin{0};
    uint32_t count{0};

    bool operator==(const ReceiptCellSpanV1&) const = default;
};

/**
 * Collision-free field transport for the complete executable receipt.
 *
 * Every byte of both canonical Split-RAP child codecs is packed into a u32
 * field with an explicit byte length.  The parent row proof maps the exact
 * canonical batch codec plus its trace commitment and every supplemental
 * next-row opening.  Public manifest, schedule, challenge, pin and terminal
 * cells precede the proof payloads in a fixed order.
 *
 * This is a transport map, not a recursive verifier.  The cells are not
 * counted as consumed until equality constraints source them from verifier
 * chips inside the normalized parent.
 */
struct CoupledBankEqualityReceiptCellMapV1 {
    uint16_t version{
        kCoupledBankEqualityReceiptCellMapVersion};
    std::vector<gkr_field::Fp> cells;
    std::vector<ReceiptCellSpanV1> spans;
    std::array<uint32_t, 2> child_codec_bytes{};
    std::array<uint32_t, 2> child_codec_words{};
    uint32_t parent_batch_codec_bytes{0};
    uint32_t parent_batch_codec_words{0};
    uint32_t parent_supplemental_fields{0};
    uint256 transport_commitment{};
    bool child_codecs_canonical{false};
    bool parent_batch_codec_canonical{false};
    bool all_values_canonical{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] CoupledBankEqualityReceiptCellMapV1
BuildCoupledBankEqualityReceiptCellMapV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    const CoupledBankEqualityReceiptV1& receipt,
    const uint256& public_seed);

[[nodiscard]] bool
ValidateCoupledBankEqualityReceiptCellMapV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    const CoupledBankEqualityReceiptV1& receipt,
    const uint256& public_seed,
    const CoupledBankEqualityReceiptCellMapV1& map,
    std::string* why = nullptr);

struct RecursiveReceiptGapV1 {
    std::string family;
    std::string unit;
    uint64_t required{0};
    uint64_t mapped_in_normalized_parent{0};
    bool exact_count{false};
    std::string detail;

    bool operator==(const RecursiveReceiptGapV1&) const = default;
};

/**
 * Public construction adapter for one canonical child-verifier relation.
 *
 * This exposes the exact relation/program/witness triple already used by the
 * recursive-consumption audit, so a normalized parent can prove the mirror
 * instead of rebuilding an equivalent host-only fixture. It does not promote
 * recursive ownership: V1's proof-operand copy and SHA gates remain false in
 * `MultiRowV2SplitRapVerifierWitnessV1`.
 */
struct CoupledBankEqualityChildVerifierV1 {
    uint32_t child_index{0};
    aq::AirConstraintSystem<Fp3> child_relation;
    stage3_verifier_air::MultiRowV2SplitRapProgramV1 program;
    stage3_verifier_air::MultiRowV2SplitRapVerifierWitnessV1 witness;
    bool valid{false};
    std::string note;
};

[[nodiscard]] CoupledBankEqualityChildVerifierV1
BuildCoupledBankEqualityChildVerifierV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    const CoupledBankEqualityReceiptV1& receipt,
    const uint256& public_seed,
    uint32_t child_index);

/**
 * Registry-program form for the producer child. The base relation is built
 * exclusively by the canonical bytecode interpreter before the CTL alias
 * suffix and verifier mirror are constructed. A changed opcode/constant
 * therefore changes the verified child relation rather than merely a
 * side-car program commitment.
 */
[[nodiscard]] CoupledBankEqualityChildVerifierV1
BuildCoupledBankEqualityChildVerifierFromProgramV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    const CoupledBankEqualityReceiptV1& receipt,
    const uint256& public_seed,
    uint32_t child_index,
    const constraint_bytecode::ProgramTable& program);

/**
 * Fail-closed capability audit for consuming the receipt in the normalized
 * arity parent.  The existing MultiRow-V2 verifier mirror is executed for
 * both child proofs and its exact check/SHA/Poseidon schedules are counted.
 * That mirror still uses verifier-owned preprocessed replay cells: SHA
 * Fiat-Shamir, proof-row aliases, the parent proof verifier and normalized
 * semantic-root buses do not execute inside a recursively proved parent.
 */
struct CoupledBankEqualityRecursiveConsumptionAuditV1 {
    uint16_t version{1};
    uint32_t receipt_cells{0};
    uint32_t receipt_cells_mapped_in_parent{0};
    uint32_t local_child_verifier_rows{0};
    uint32_t local_child_verifier_constraints{0};
    uint32_t local_child_verifier_output_cells{0};
    uint32_t poseidon_permutations{0};
    uint64_t poseidon_semantic_alias_cells{0};
    uint32_t sha256d_calls{0};
    uint64_t sha256_compressions{0};
    uint32_t sha_shards{0};
    uint32_t sha_recursive_nodes{0};
    uint32_t normalized_proof_terminal_lanes{16};
    uint32_t normalized_proof_terminal_lanes_mapped{0};
    bool native_receipt_verified{false};
    bool canonical_cell_map_verified{false};
    bool both_child_programs_canonical{false};
    bool both_local_verifier_relations_execute{false};
    bool parent_proof_verified_natively{false};
    bool proof_cells_equality_mapped_in_parent{false};
    bool child_fiat_shamir_replayed_in_parent{false};
    bool child_hash_chips_execute_in_parent{false};
    bool parent_proof_verifier_executes_in_parent{false};
    bool terminal_bus_mapped_to_normalized_root{false};
    bool producer_registered_roots_bound{false};
    bool registered_receiver_semantics_bound{false};
    uint16_t recursively_consumed_endpoints{0};
    uint16_t recursively_consumed_roles{0};
    bool recursive_fixed_point{false};
    bool authority{false};
    std::vector<RecursiveReceiptGapV1> gaps;
    bool valid{false};
    std::string note;

    bool operator==(
        const CoupledBankEqualityRecursiveConsumptionAuditV1&) const =
        default;
};

[[nodiscard]] CoupledBankEqualityRecursiveConsumptionAuditV1
AssessCoupledBankEqualityRecursiveConsumptionV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    const CoupledBankEqualityReceiptV1& receipt,
    const uint256& public_seed);

[[nodiscard]] bool
ValidateCoupledBankEqualityRecursiveConsumptionV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    const CoupledBankEqualityReceiptV1& receipt,
    const uint256& public_seed,
    const CoupledBankEqualityRecursiveConsumptionAuditV1& audit,
    std::string* why = nullptr);

} // namespace matmul::v4::rc::splitrap_ctl

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_SPLITRAP_CTL_COORDINATOR_H
