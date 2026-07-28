// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_RECURSIVE_FIXEDPOINT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_RECURSIVE_FIXEDPOINT_H

#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>
#include <matmul/matmul_v4_rc_stage3_coupled_bank_product.h>
#include <matmul/matmul_v4_rc_stage3_narrow_recurse.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::recursive_fixedpoint {

namespace aq = air_quotient;
namespace ar = air_recurse;
namespace nr = narrow_recurse;
namespace ah = alg_hash;

using gkr_field::Fp3;
using AlgAirProof =
    aq::AirQuotientProof<Fp3, aq::AirFriBackendAlg<Fp3>>;

/**
 * A corrected fixed-point screen.  Unlike the original narrow planner this
 * charges all three row openings required by the quotient verifier:
 *
 *   - current full row -> row_commit_root;
 *   - shifted full row -> row_commit_root; and
 *   - current trace-only row -> R_T.
 *
 * It also charges every fold opening, DEEP, per-point quotient,
 * transition/boundary selector and Fiat-Shamir row.  The screen is deliberately
 * separate from the older planner so historical measurements cannot silently
 * change.  A scenario is eligible only when leaf, level-1 and level-2 shapes
 * all fit the real column and LDE caps.
 */
struct CompleteFixedPointLevel {
    uint32_t child_width{0};
    uint32_t child_rows{0};
    uint32_t child_coeffs{0};
    uint32_t child_lde{0};
    uint32_t parent_width{0};
    uint64_t active_rows{0};
    uint32_t trace_rows{0};
    uint32_t max_degree{0};
    uint32_t quotient_len{0};
    uint32_t parent_coeffs{0};
    uint32_t parent_lde{0};
    uint32_t parent_constraints{0};
    uint64_t current_row_rows{0};
    uint64_t next_row_rows{0};
    uint64_t trace_binding_rows{0};
    uint64_t fold_rows{0};
    uint64_t deep_rows{0};
    uint64_t per_point_rows{0};
    uint64_t fiat_shamir_rows{0};
    bool columns_supported{false};
    bool lde_supported{false};
    bool valid{false};
};

struct CompleteFixedPointScenario {
    nr::PoseidonLaneStrategy poseidon_strategy{
        nr::PoseidonLaneStrategy::DirectX7};
    nr::ChildPacking child_packing{
        nr::ChildPacking::VerticalRows};
    /** Binary aggregation children. */
    uint32_t logical_children{2};
    /** Ordered V5 repetitions per logical child. */
    uint32_t repeated_lanes_per_child{2};
    /** logical_children * repeated_lanes_per_child = 4. */
    uint32_t verifier_lanes{4};
    /** Physical verifier lanes executed side-by-side: 1, 2 or 4. */
    uint32_t physical_lanes{1};
    CompleteFixedPointLevel leaf;
    CompleteFixedPointLevel level1;
    CompleteFixedPointLevel level2;
    bool charges_current_next_trace{false};
    bool width_fixed_point{false};
    bool trace_fixed_point{false};
    bool backend_shape_supported{false};
    bool selected_v1_topology{false};
    bool executable_hash_opening_air{false};
    bool executable_scalar_air{false};
    // True only after every verifier family is joined through the bus. The
    // executable fold hash-to-scalar join alone does not close this flag.
    bool executable_memory_bus{false};
    bool complete_recursive_parent{false};
    std::string note;
};

/** Nine scenarios: three x^7 layouts times 1/2/4 physical V5 lane packing. */
[[nodiscard]] std::vector<CompleteFixedPointScenario>
AssessCompleteFixedPointScenarios(
    const nr::NarrowChildShape& leaf =
        nr::ProductionEpisodeChildShape());

/**
 * The selected V1 topology is a 2,184-column fully-quadratic x^7 parent with
 * all four physical verifier lanes in parallel: two binary aggregation
 * children times the two ordered V5 repetitions. One- and two-physical-lane
 * execution exceeds the recursive LDE cap once all current/next/trace
 * openings are charged. Arity four is represented as two binary parents
 * followed by a binary parent.
 */
[[nodiscard]] CompleteFixedPointScenario
SelectCompleteFixedPointV1(
    const nr::NarrowChildShape& leaf =
        nr::ProductionEpisodeChildShape());

// -------------------------------------------------------------------------
// Executable vertical hash-opening chip.
// -------------------------------------------------------------------------

enum class HashRowKind : uint8_t {
    SpongeFirst = 0,
    SpongeContinue = 1,
    SingleValueLeaf = 2,
    MerkleCompress = 3,
    Padding = 4,
    Count = 5,
};

inline constexpr uint32_t kHashRowKindCount =
    static_cast<uint32_t>(HashRowKind::Count);

struct HashOpeningProgramRow {
    HashRowKind kind{HashRowKind::Padding};
    bool link_to_sponge{false};
    bool link_to_merkle{false};
    bool terminal{false};
    bool direction{false};
    /**
     * Which child of a multi-child (vertically packed) narrow node this row
     * belongs to. Always 0 for the single-child construction, so every existing
     * schedule, witness and canonicity comparison is bit-identical.
     */
    uint32_t child{0};
    uint32_t index{0};
    uint32_t query{0};
    uint32_t fold_layer{0};
    /** 0 = not a fold leaf/path, 1 = even, 2 = odd. */
    uint8_t fold_side{0};
    /** Last row of one fold even/odd authentication path. */
    bool fold_terminal{false};
    /** This sponge row absorbs the authenticated current full row used by
     * U(x) in the initial DEEP identity. */
    bool current_row_sponge{false};
    /** This sponge row absorbs the authenticated shifted row consumed by
     * transition constraints in the per-point interpreter. */
    bool next_row_sponge{false};
    uint32_t current_word_offset{0};
    std::array<Fp3, ah::kAlgHashRate> absorbed_pin{};
    std::array<bool, ah::kAlgHashRate> absorbed_is_pinned{};
    ah::Digest expected_root{};
};

struct DeepInitialLayout {
    uint32_t base;
    uint32_t running;
    uint32_t reset_next;
    uint32_t identity_selector;
    uint32_t coefficient_base;
    /**
     * The DEEP weight ALREADY MULTIPLIED INTO the inverse denominator:
     * w1/(x - z1) and w2/(x - z2). Both factors are public and are recomputed
     * by the verifier from the child's public inputs, so pinning the product
     * pins exactly what pinning the two factors did.
     *
     * They are products rather than the bare inverses because a multi-child
     * node packs children with DIFFERENT w1/w2 into ONE trace: as whole-node
     * constants the weights could no longer be captured, and carrying them as
     * separate per-row columns would raise the identity from algebraic degree
     * 3 to 4 — which doubles the node's own FRI domain and halves the arity
     * that fits under kRCFriMaxLdeLog2. The product keeps degree 3.
     */
    uint32_t w1_invd1;
    uint32_t w2_invd2;
    uint32_t v1;
    uint32_t v2;
    /**
     * PER-ROW public pin of the child's terminal FRI value. Per-row for the
     * same reason: with one child every row carries the same value, so the
     * arity-1 relation is unchanged.
     */
    uint32_t child_final_value;

    explicit constexpr DeepInitialLayout(uint32_t start = 0)
        : base(start),
          running(base),
          reset_next(running + 1),
          identity_selector(reset_next + 1),
          coefficient_base(identity_selector + 1),
          w1_invd1(coefficient_base + ah::kAlgHashRate),
          w2_invd2(w1_invd1 + 1),
          v1(w2_invd2 + 1),
          v2(v1 + 1),
          child_final_value(v2 + 1)
    {
    }

    [[nodiscard]] uint32_t Coefficient(uint32_t lane) const
    {
        return coefficient_base + lane;
    }
    [[nodiscard]] uint32_t End() const
    {
        return child_final_value + 1;
    }
};

struct HashOpeningProgram {
    /** children[0]; kept for every single-child caller. */
    ar::ChildPublicInputs public_inputs;
    /**
     * Ordered children packed into ONE narrow node. The single-child builder
     * fills this with exactly one entry equal to `public_inputs`, so nothing
     * downstream has to special-case arity 1. Arity multiplies ROWS and never
     * columns — that is the whole point of the vertical lane.
     */
    std::vector<ar::ChildPublicInputs> children;
    /** Row at which each child's schedule starts (children.size() entries). */
    std::vector<uint32_t> child_row_offsets;
    uint32_t active_rows{0};
    uint32_t trace_rows{0};
    std::vector<HashOpeningProgramRow> rows;
    bool current_row_opening{false};
    bool next_row_opening{false};
    bool trace_root_opening{false};
    bool every_fold_opening{false};
    bool valid{false};
    std::string note;
};

/**
 * Column layout.  The permutation is fully quadratic:
 *
 *   x2=x*x, x4=x2*x2, x6=x4*x2, y=x6*x.
 *
 * Hence all 472 permutation identities have degree two without selector
 * gating.  Program-dependent routing/root identities have degree at most two.
 */
struct HashOpeningLayout {
    ar::PermLayout perm;
    uint32_t x2_base;
    uint32_t x4_base;
    uint32_t x6_base;
    uint32_t kind_selector_base;
    uint32_t link_sponge_col;
    uint32_t link_merkle_col;
    uint32_t terminal_col;
    uint32_t direction_col;
    uint32_t index_col;
    uint32_t absorbed_pin_base;
    uint32_t absorbed_mask_base;
    uint32_t absorbed_expected_base;
    uint32_t expected_root_base;
    uint32_t route_selected_base;

    explicit constexpr HashOpeningLayout(uint32_t start = 0)
        : perm(start),
          x2_base(perm.End()),
          x4_base(x2_base + ar::kPermSboxCells),
          x6_base(x4_base + ar::kPermSboxCells),
          kind_selector_base(x6_base + ar::kPermSboxCells),
          link_sponge_col(kind_selector_base + kHashRowKindCount),
          link_merkle_col(link_sponge_col + 1),
          terminal_col(link_merkle_col + 1),
          direction_col(terminal_col + 1),
          index_col(direction_col + 1),
          absorbed_pin_base(index_col + 1),
          absorbed_mask_base(absorbed_pin_base + ah::kAlgHashRate),
          absorbed_expected_base(absorbed_mask_base + ah::kAlgHashRate),
          expected_root_base(absorbed_expected_base + ah::kAlgHashRate),
          route_selected_base(
              expected_root_base + ah::kAlgHashDigestLen)
    {
    }

    [[nodiscard]] uint32_t KindSelector(HashRowKind kind) const
    {
        return kind_selector_base + static_cast<uint32_t>(kind);
    }
    [[nodiscard]] uint32_t End() const
    {
        return route_selected_base + ah::kAlgHashDigestLen;
    }
};

[[nodiscard]] constexpr HashOpeningLayout
CanonicalHashOpeningLayout()
{
    return HashOpeningLayout(0);
}

[[nodiscard]] constexpr HashOpeningLayout
HashOpeningLayoutAt(uint32_t start)
{
    return HashOpeningLayout(start);
}

struct HashOpeningWitness {
    HashOpeningProgram program;
    std::vector<std::vector<Fp3>> columns;
    uint32_t column_base{0};
    uint32_t violations{0};
    bool proof_derived{false};
    bool native_child_accepted{false};
    bool valid{false};
    std::string note;
};

/**
 * Build the proof-independent hash schedule from public roots, query indices
 * and dimensions.  No sibling/value from the child proof is placed in a
 * preprocessed column.
 */
[[nodiscard]] HashOpeningProgram
BuildHashOpeningProgram(const ar::ChildPublicInputs& pi);

/**
 * ARITY-N variant: pack `children` into ONE narrow node by concatenating their
 * schedules vertically. The column layout is byte-identical to the single-child
 * one (CanonicalHashOpeningLayout), because every child-dependent quantity is a
 * per-ROW pin. With one child the result is bit-identical to the overload above.
 */
[[nodiscard]] HashOpeningProgram
BuildHashOpeningProgram(
    const std::vector<ar::ChildPublicInputs>& children);

/** Build the exact quadratic AIR for the canonical schedule. */
[[nodiscard]] bool BuildHashOpeningConstraintSystem(
    const HashOpeningProgram& program,
    aq::AirConstraintSystem<Fp3>& out,
    std::string* why = nullptr,
    uint32_t column_base = 0);

/**
 * Materialize every current/next/trace and fold Merkle path from a real child
 * proof.  Siblings and absorbed values remain witness data.  `valid` requires
 * native acceptance and zero AIR violations.
 */
[[nodiscard]] HashOpeningWitness BuildHashOpeningWitness(
    const aq::AirConstraintSystem<Fp3>& child_cs,
    const AlgAirProof& child,
    const uint256& child_fs_seed);

/**
 * ARITY-N counterpart. Every child is FIRST accepted by the real, unmodified
 * native verifier under its own constraint system and its own Fiat-Shamir seed;
 * only then is its transcript materialized into the shared vertical trace. The
 * three vectors must be the same length and non-empty.
 */
[[nodiscard]] HashOpeningWitness BuildHashOpeningWitnessMulti(
    const std::vector<aq::AirConstraintSystem<Fp3>>& child_css,
    const std::vector<AlgAirProof>& children,
    const std::vector<uint256>& child_fs_seeds);

/**
 * V5-safe adapter for one ordered lane of a dual-Q128 child.  The complete
 * dual envelope and its ordered transcript are checked before the lane view
 * is used to materialize the vertical hash-opening witness.  This avoids
 * treating either detached lane as an independently valid legacy proof.
 */
[[nodiscard]] HashOpeningWitness BuildDualV5HashOpeningWitness(
    const aq::AirConstraintSystem<Fp3>& child_cs,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    uint32_t lane);

[[nodiscard]] HashOpeningWitness BuildDualV5HashOpeningWitnessAtBase(
    const aq::AirConstraintSystem<Fp3>& child_cs,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    uint32_t lane,
    uint32_t column_base);

[[nodiscard]] uint32_t CountHashOpeningViolations(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns,
    uint32_t* first_row = nullptr,
    std::string* first_constraint = nullptr);

// -------------------------------------------------------------------------
// Same-trace fold memory bus.
// -------------------------------------------------------------------------

struct FoldBusChallenges {
    Fp3 gamma1{};
    Fp3 gamma2{};
    Fp3 alpha1{};
    Fp3 alpha2{};
};

/**
 * Separate proof-owned memory channel for the DEEP fold chain:
 * folded(q,l) == selected_authenticated_leaf(q,l+1).
 *
 * A distinct address namespace prevents the ordinary even/odd fold operands
 * from cancelling a missing chain edge.
 */
struct FoldChainBusLayout {
    uint32_t base;
    uint32_t value;
    uint32_t inverse1;
    uint32_t inverse2;
    uint32_t address;
    uint32_t multiplicity;
    uint32_t send;
    uint32_t receive;
    uint32_t running1;
    uint32_t running2;
    uint32_t final_selector;

    explicit constexpr FoldChainBusLayout(uint32_t start = 0)
        : base(start),
          value(base),
          inverse1(value + 1),
          inverse2(inverse1 + 1),
          address(inverse2 + 1),
          multiplicity(address + 1),
          send(multiplicity + 1),
          receive(send + 1),
          running1(receive + 1),
          running2(running1 + 1),
          final_selector(running2 + 1)
    {
    }

    [[nodiscard]] uint32_t End() const
    {
        return final_selector + 1;
    }
};

struct FoldBusLayout {
    static constexpr uint32_t kPorts = 2;
    static constexpr uint32_t kPortColumns = 8;

    uint32_t base;
    uint32_t running1;
    uint32_t running2;
    uint32_t consumer_even;
    uint32_t consumer_odd;
    uint32_t folded;
    uint32_t x;
    uint32_t beta;

    explicit constexpr FoldBusLayout(uint32_t start = 0)
        : base(start),
          running1(base + kPorts * kPortColumns),
          running2(running1 + 1),
          consumer_even(running2 + 1),
          consumer_odd(consumer_even + 1),
          folded(consumer_odd + 1),
          x(folded + 1),
          beta(x + 1)
    {
    }

    [[nodiscard]] uint32_t Value(uint32_t port) const
    {
        return base + port * kPortColumns;
    }
    [[nodiscard]] uint32_t Inverse1(uint32_t port) const
    {
        return Value(port) + 1;
    }
    [[nodiscard]] uint32_t Inverse2(uint32_t port) const
    {
        return Value(port) + 2;
    }
    [[nodiscard]] uint32_t Address(uint32_t port) const
    {
        return Value(port) + 3;
    }
    [[nodiscard]] uint32_t Multiplicity(uint32_t port) const
    {
        return Value(port) + 4;
    }
    [[nodiscard]] uint32_t Send(uint32_t port) const
    {
        return Value(port) + 5;
    }
    [[nodiscard]] uint32_t ReceiveEven(uint32_t port) const
    {
        return Value(port) + 6;
    }
    [[nodiscard]] uint32_t ReceiveOdd(uint32_t port) const
    {
        return Value(port) + 7;
    }
    [[nodiscard]] uint32_t End() const { return beta + 1; }
};

struct FoldBusComposition {
    HashOpeningWitness hash;
    FoldBusChallenges challenges;
    uint256 prechallenge_commitment{};
    aq::AirConstraintSystem<Fp3> combined;
    std::vector<std::vector<Fp3>> columns;
    FoldBusLayout bus;
    FoldChainBusLayout chain;
    DeepInitialLayout deep;
    uint32_t fold_pairs{0};
    uint32_t fold_chain_pairs{0};
    uint32_t fold_final_rows{0};
    uint32_t violations{0};
    bool direct_hash_alias{false};
    bool commit_then_challenge{false};
    bool dual_logup_terminal{false};
    bool fold_equations{false};
    bool fold_chain_and_final_equations{false};
    bool initial_deep_identity{false};
    bool deep_per_point_transition_join{false};
    bool valid{false};
    std::string note;
};

struct BytecodeBusLayout {
    static constexpr uint32_t kPorts = ah::kAlgHashRate;
    static constexpr uint32_t kPortColumns = 6;
    static constexpr uint32_t kRowKinds = 9;

    uint32_t base;
    uint32_t running1;
    uint32_t running2;
    uint32_t constraint_accumulator;
    uint32_t reset_next;
    uint32_t row_kind_base;
    uint32_t constant;
    uint32_t result_selector;
    uint32_t constraint_weight;
    uint32_t zh;

    explicit constexpr BytecodeBusLayout(uint32_t start = 0)
        : base(start),
          running1(base + kPorts * kPortColumns),
          running2(running1 + 1),
          constraint_accumulator(running2 + 1),
          reset_next(constraint_accumulator + 1),
          row_kind_base(reset_next + 1),
          constant(row_kind_base + kRowKinds),
          result_selector(constant + 1),
          constraint_weight(result_selector + 1),
          zh(constraint_weight + 1)
    {
    }

    [[nodiscard]] uint32_t Value(uint32_t port) const
    {
        return base + port * kPortColumns;
    }
    [[nodiscard]] uint32_t Inverse1(uint32_t port) const
    {
        return Value(port) + 1;
    }
    [[nodiscard]] uint32_t Inverse2(uint32_t port) const
    {
        return Value(port) + 2;
    }
    [[nodiscard]] uint32_t Address(uint32_t port) const
    {
        return Value(port) + 3;
    }
    [[nodiscard]] uint32_t Multiplicity(uint32_t port) const
    {
        return Value(port) + 4;
    }
    [[nodiscard]] uint32_t Active(uint32_t port) const
    {
        return Value(port) + 5;
    }
    [[nodiscard]] uint32_t RowKind(uint32_t kind) const
    {
        return row_kind_base + kind;
    }
    [[nodiscard]] uint32_t End() const
    {
        return zh + 1;
    }
};

struct BytecodeInterpreterAttachment {
    constraint_bytecode::Program program;
    constraint_bytecode::ProgramTable program_table;
    uint256 program_commitment{};
    uint256 prechallenge_commitment{};
    FoldBusChallenges challenges;
    BytecodeBusLayout layout;
    uint32_t instruction_rows{0};
    uint32_t constraint_result_rows{0};
    uint32_t quotient_rows{0};
    uint32_t authenticated_source_coordinates{0};
    uint32_t violations{0};
    bool canonical_program{false};
    bool authenticated_row_memory_bus{false};
    bool dual_logup_terminal{false};
    bool result_zero_constrained{false};
    bool quotient_opening_equality{false};
    /** Every authenticated current/next relation cell is exported into the
     * same normalized trace through the dual rational-identity bus. */
    bool same_trace_relation_cell_logup_export{false};
    /** Remains false until the bus terminal is equality-constrained to the
     * registered role's semantic endpoint roots at unified root. */
    bool role_semantic_root_terminal_equality{false};
    /** Additive V1 cutover: the verifier recomputes a normalized semantic
     * root over this exact program, child proof and CTL terminal bus, and
     * pins its eight u32 limbs in the parent AIR. This does not assert
     * equality with the legacy per-column SHA semantic root. */
    bool normalized_v1_role_terminal_binding{false};
    uint256 normalized_v1_semantic_root{};
    bool valid{false};
    std::string note;
};

/**
 * Additive V1 pin for a CoupledBank dequant proof on the normalized AlgHash
 * row-wise backend. It intentionally does not claim equality with the old
 * per-column SHA roots: the whole-trace row commitment is the proof binding,
 * and the role-root CTL terminal is a separate named gate.
 */
struct NormalizedCoupledBankRowPin {
    uint16_t version{1};
    uint256 source_pin_commitment{};
    uint32_t n_rows{0};
    uint32_t n_coeffs{0};
    uint256 trace_row_commitment{};
    uint256 pin_commitment{};
};

[[nodiscard]] uint256
ComputeNormalizedCoupledBankRowPinCommitment(
    const NormalizedCoupledBankRowPin& pin);

/** Build the exact registered five-constraint kernel for the row-wise
 * backend, replacing only the unsupported old per-column root pin. */
[[nodiscard]] bool
BuildNormalizedCoupledBankConstraintSystem(
    const RCStage3CoupledBankDequantPin& source_pin,
    aq::AirConstraintSystem<Fp3>& out,
    std::string* why = nullptr);

[[nodiscard]] bool BuildNormalizedCoupledBankRowPin(
    const RCStage3CoupledBankDequantPin& source_pin,
    const AlgAirProof& proof,
    NormalizedCoupledBankRowPin& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyNormalizedCoupledBankProof(
    const RCStage3CoupledBankDequantPin& source_pin,
    const NormalizedCoupledBankRowPin& row_pin,
    const AlgAirProof& proof,
    const uint256& fs_seed,
    std::string* why = nullptr);

// -------------------------------------------------------------------------
// Versioned normalized semantic roots and canonical fourteen-role registry.
// -------------------------------------------------------------------------

inline constexpr uint16_t kNormalizedSemanticRootV1Version = 1;
inline constexpr uint16_t kNormalizedRoleChildRegistryVersion = 1;

enum class NormalizedSemanticRootScheme : uint8_t {
    NormalizedAlgHashTerminalV1 = 1,
};

struct NormalizedRoleChildSlot {
    uint16_t version{kNormalizedSemanticRootV1Version};
    NormalizedSemanticRootScheme scheme{
        NormalizedSemanticRootScheme::NormalizedAlgHashTerminalV1};
    uint16_t ordinal{0};
    RCStage3RelationRole role{};
    /** Inclusive first endpoint ABI id and exact contiguous endpoint count. */
    uint16_t first_endpoint{0};
    uint16_t endpoint_count{0};
    uint256 statement_commitment{};
    uint256 program_table_commitment{};
    uint256 child_trace_row_root{};
    uint256 child_proof_commitment{};
    uint256 terminal_bus_commitment{};
    uint256 normalized_semantic_root{};
    uint256 slot_commitment{};

    bool operator==(const NormalizedRoleChildSlot&) const = default;
};

/**
 * Exactly fourteen slots in RCStage3UnifiedRoleOrder. A skeleton is useful
 * for deterministic scheduling but has a null registry commitment. A full
 * binding is accepted only when every slot uses the normalized-V1 scheme and
 * every semantic root/slot commitment recomputes exactly. Legacy SHA roots
 * cannot be mixed into this container.
 *
 * Structural acceptance is not recursive proof consumption. The latter
 * remains zero until the normalized parent executes each child verifier.
 */
struct NormalizedRoleChildRegistry {
    uint16_t version{kNormalizedRoleChildRegistryVersion};
    std::vector<NormalizedRoleChildSlot> slots;
    uint256 registry_commitment{};
};

struct NormalizedRoleChildRegistryAudit {
    uint16_t scheduled_roles{0};
    uint16_t normalized_v1_bound_roles{0};
    uint16_t missing_or_invalid_roles{0};
    uint16_t recursively_consumed_roles{0};
    bool canonical_order_and_intervals{false};
    bool normalized_v1_only{false};
    bool binding_complete{false};
    bool recursive_consumption_complete{false};
    std::string note;
};

/** Canonical commitment to every serialized field of a single-lane AlgHash
 * AIR proof, including supplemental next/trace openings. */
[[nodiscard]] uint256 ComputeNormalizedAlgAirProofCommitment(
    const AlgAirProof& proof);

/** Exact selected-role CTL terminal-bus commitment. It binds the global
 * balanced composition, the selected child pin and its immutable schedule. */
[[nodiscard]] uint256 ComputeNormalizedTerminalBusCommitment(
    const RCStage3CtlManifest& manifest,
    const std::vector<RCStage3CtlChildPin>& pins,
    size_t child_index,
    const RCStage3CtlSchedule& schedule);

[[nodiscard]] uint256 ComputeNormalizedSemanticRootV1(
    const NormalizedRoleChildSlot& slot);
[[nodiscard]] uint256 ComputeNormalizedRoleChildSlotCommitment(
    const NormalizedRoleChildSlot& slot);
[[nodiscard]] uint256 ComputeNormalizedRoleChildRegistryCommitment(
    const NormalizedRoleChildRegistry& registry);

/** Return all fourteen exact role/endpoint intervals with empty proof fields. */
[[nodiscard]] NormalizedRoleChildRegistry
BuildCanonicalNormalizedRoleChildRegistrySchedule();

/** Install one complete proof-derived slot at its immutable ordinal. */
[[nodiscard]] bool InstallNormalizedRoleChildSlot(
    NormalizedRoleChildRegistry& registry,
    const NormalizedRoleChildSlot& slot,
    std::string* why = nullptr);

/** Structural binding audit; never counts a commitment as proof consumption. */
[[nodiscard]] NormalizedRoleChildRegistryAudit
AssessNormalizedRoleChildRegistry(
    const NormalizedRoleChildRegistry& registry);

/** Full binding verifier. It fails closed on a missing/unproved slot, a
 * legacy/mixed root, noncanonical role order, or interval substitution. */
[[nodiscard]] bool VerifyNormalizedRoleChildRegistryBinding(
    const NormalizedRoleChildRegistry& registry,
    std::string* why = nullptr);

// -------------------------------------------------------------------------
// Canonical vertical transcript for all fourteen roles / fifty-two endpoints.
// -------------------------------------------------------------------------

inline constexpr uint16_t kNormalizedTerminalTranscriptV1Version = 1;
inline constexpr uint16_t kNormalizedTerminalTranscriptRoleCount =
    kRCStage3RelationClosureRoleCount;
inline constexpr uint16_t kNormalizedTerminalTranscriptEndpointCount =
    kRCStage3RelationClosureEndpointCount;

/**
 * One exact endpoint terminal.  This is a lossless normalization of
 * RCStage3RelationEndpointPin: no digest is dropped or combined before the
 * parent sees it.  `terminal_commitment` is a domain-separated commitment to
 * every preceding field.
 */
struct NormalizedEndpointTerminalBusV1 {
    uint16_t version{kNormalizedTerminalTranscriptV1Version};
    uint16_t global_ordinal{0};
    uint16_t role_ordinal{0};
    uint16_t endpoint_ordinal{0};
    RCStage3RelationRole role{};
    RCStage3RelationEndpoint endpoint{};
    uint64_t instance_count{0};
    uint256 manifest_root{};
    uint256 proof_root{};
    uint256 semantic_root{};
    uint256 proof_column_root{};
    uint256 recursive_child_commitment{};
    uint256 terminal_commitment{};

    bool operator==(const NormalizedEndpointTerminalBusV1&) const = default;
};

/**
 * One role terminal and its exact contiguous endpoint interval.  The endpoint
 * vector is not duplicated here; the interval addresses the canonical global
 * endpoint vector in NormalizedTerminalTranscriptV1.
 */
struct NormalizedRoleTerminalBusV1 {
    uint16_t version{kNormalizedTerminalTranscriptV1Version};
    uint16_t role_ordinal{0};
    RCStage3RelationRole role{};
    uint16_t first_endpoint_ordinal{0};
    uint16_t endpoint_count{0};
    uint256 relation_commitment{};
    uint256 relation_statement_root{};
    uint256 endpoint_multiproof_root{};
    uint256 terminal_commitment{};

    bool operator==(const NormalizedRoleTerminalBusV1&) const = default;
};

/**
 * Canonical transcript rows:
 *
 *   0..51  endpoint buses, in role order then endpoint ABI order
 *   52..65 role buses
 *   66     closure header
 *   67     final-digest/composition-link record
 *   68     transcript registry record
 *
 * This is a binding transcript.  It does not claim that any opaque recursive
 * child commitment was executed.
 */
struct NormalizedTerminalTranscriptV1 {
    uint16_t version{kNormalizedTerminalTranscriptV1Version};
    std::vector<NormalizedEndpointTerminalBusV1> endpoints;
    std::vector<NormalizedRoleTerminalBusV1> roles;
    uint256 unified_root_seed{};
    uint256 statement_commitment{};
    uint256 ctl_proof_bundle_commitment{};
    uint256 composition_link_commitment{};
    uint256 final_digest_manifest_root{};
    uint256 final_digest_proof_root{};
    uint256 final_digest_semantic_root{};
    uint256 final_digest_recursive_child_commitment{};
    uint256 source_closure_commitment{};
    uint256 transcript_commitment{};
};

struct NormalizedTerminalTranscriptAudit {
    uint16_t scheduled_roles{0};
    uint16_t scheduled_endpoints{0};
    uint16_t locally_semantic_complete_endpoints{0};
    uint16_t recursively_child_proof_owned_endpoints{0};
    uint16_t recursively_child_proof_owned_roles{0};
    bool canonical_role_order{false};
    bool canonical_endpoint_order{false};
    bool all_terminal_commitments_recomputed{false};
    bool source_closure_binding{false};
    bool binding_complete{false};
    bool recursive_consumption_complete{false};
    std::string blocker;
};

[[nodiscard]] uint256 ComputeNormalizedEndpointTerminalBusCommitment(
    const NormalizedEndpointTerminalBusV1& terminal);
[[nodiscard]] uint256 ComputeNormalizedRoleTerminalBusCommitment(
    const NormalizedRoleTerminalBusV1& terminal,
    const std::vector<NormalizedEndpointTerminalBusV1>& endpoints);
[[nodiscard]] uint256 ComputeNormalizedTerminalTranscriptCommitment(
    const NormalizedTerminalTranscriptV1& transcript);

/** Losslessly normalize a structurally complete relation-closure ledger. */
[[nodiscard]] bool BuildNormalizedTerminalTranscriptV1(
    const RCStage3RelationClosureV1& closure,
    NormalizedTerminalTranscriptV1& out,
    std::string* why = nullptr);

/**
 * Reports local semantic closure separately from recursive proof ownership.
 * The former is taken only from the immutable 52-entry relation-cell audit;
 * the latter remains zero until executable multi-segment child verifiers are
 * supplied to this API.
 */
[[nodiscard]] NormalizedTerminalTranscriptAudit
AssessNormalizedTerminalTranscriptV1(
    const NormalizedTerminalTranscriptV1& transcript);

enum class NormalizedTerminalTranscriptRowKind : uint8_t {
    Padding = 0,
    Endpoint = 1,
    Role = 2,
    ClosureHeader = 3,
    FinalDigest = 4,
    Registry = 5,
};

/**
 * Fifty-eight lossless cells are multiplexed vertically rather than
 * allocating one column group per endpoint.  The witness half is constrained
 * equal to a verifier-owned preprocessed half on every row.
 */
struct NormalizedTerminalTranscriptLayout {
    static constexpr uint32_t kDigestCount = 6;
    static constexpr uint32_t kDigestLimbs = 8;
    static constexpr uint32_t kScalarCells = 10;
    static constexpr uint32_t kCells =
        kScalarCells + kDigestCount * kDigestLimbs;
    static constexpr uint32_t kRequiredRows =
        kNormalizedTerminalTranscriptEndpointCount +
        kNormalizedTerminalTranscriptRoleCount + 3;

    uint32_t witness_base{0};
    uint32_t expected_base{kCells};

    explicit constexpr NormalizedTerminalTranscriptLayout(
        uint32_t start = 0)
        : witness_base(start),
          expected_base(start + kCells)
    {
    }
    [[nodiscard]] constexpr uint32_t Witness(uint32_t cell) const
    {
        return witness_base + cell;
    }
    [[nodiscard]] constexpr uint32_t Expected(uint32_t cell) const
    {
        return expected_base + cell;
    }
    [[nodiscard]] constexpr uint32_t DigestCell(
        uint32_t digest, uint32_t limb) const
    {
        return kScalarCells + digest * kDigestLimbs + limb;
    }
    [[nodiscard]] constexpr uint32_t End() const
    {
        return expected_base + kCells;
    }
};

struct NormalizedTerminalTranscriptAttachment {
    NormalizedTerminalTranscriptLayout layout;
    uint16_t locally_constrained_roles{0};
    uint16_t locally_constrained_endpoints{0};
    uint16_t locally_semantic_complete_endpoints{0};
    uint16_t recursively_child_proof_owned_roles{0};
    uint16_t recursively_child_proof_owned_endpoints{0};
    uint32_t equality_constraints{0};
    bool ordered_coverage{false};
    bool transcript_commitment_bound{false};
    bool valid{false};
    std::string blocker;
};

/**
 * Append the complete 69-row normalized transcript to a parent AIR.  Every
 * mapped witness cell has an explicit degree-one equality to its verifier
 * preprocessed peer.  This proves parent-local transcript equality only;
 * recursive proof-ownership counters intentionally remain zero.
 */
[[nodiscard]] NormalizedTerminalTranscriptAttachment
AttachNormalizedTerminalTranscriptV1(
    FoldBusComposition& composition,
    const NormalizedTerminalTranscriptV1& transcript);

struct NormalizedCoupledBankTerminalExecution {
    NormalizedRoleChildSlot slot;
    uint32_t ctl_child_index{0};
    bool normalized_child_proof_verified{false};
    bool ctl_child_proof_verified{false};
    bool public_terminal_composition_verified{false};
    bool parent_terminal_bound{false};
    /** Explicit roadmap gate: the V1 root does not alias the legacy SHA
     * per-column semantic root. */
    bool legacy_sha_alg_bridge{false};
    bool valid{false};
    std::string note;
};

/**
 * Execute the CoupledBank normalized child and its selected native CTL child,
 * require the exact global terminal composition, then derive the additive
 * normalized-V1 semantic root. This is an explicit protocol cutover and does
 * not claim interoperability with legacy SHA semantic roots.
 */
[[nodiscard]] NormalizedCoupledBankTerminalExecution
ExecuteNormalizedCoupledBankTerminal(
    const RCStage3CoupledBankDequantPin& source_pin,
    const NormalizedCoupledBankRowPin& row_pin,
    const AlgAirProof& proof,
    const uint256& fs_seed,
    const RCStage3CtlManifest& ctl_manifest,
    const std::vector<RCStage3CtlChildPin>& ctl_pins,
    size_t ctl_child_index,
    const RCStage3CtlSchedule& schedule,
    const RCStage3CtlAirProof& ctl_proof);

struct NormalizedRoleTerminalLayout {
    uint32_t normalized_root_limb_base{0};

    explicit constexpr NormalizedRoleTerminalLayout(uint32_t start = 0)
        : normalized_root_limb_base(start)
    {
    }
    [[nodiscard]] constexpr uint32_t RootLimb(uint32_t limb) const
    {
        return normalized_root_limb_base + limb;
    }
    [[nodiscard]] constexpr uint32_t End() const
    {
        return normalized_root_limb_base + 8;
    }
};

/**
 * Pin the verifier-recomputed normalized semantic root into eight
 * verifier-owned u32 columns of the same parent AIR as the bytecode
 * interpreter. The legacy equality flag remains false by construction.
 */
[[nodiscard]] bool AttachNormalizedCoupledBankTerminalBinding(
    FoldBusComposition& composition,
    BytecodeInterpreterAttachment& interpreter,
    const NormalizedCoupledBankRowPin& row_pin,
    NormalizedCoupledBankTerminalExecution& execution,
    NormalizedRoleTerminalLayout* layout = nullptr,
    std::string* why = nullptr);

enum class NormalizedAlgHashInputSource : uint8_t {
    VerifierConstant = 1,
    ProofAuthenticated = 2,
    MissingProofBus = 3,
};

struct NormalizedAlgHashFieldAudit {
    std::string field;
    uint32_t input_lanes{0};
    NormalizedAlgHashInputSource source{
        NormalizedAlgHashInputSource::MissingProofBus};
    bool all_lanes_bound{false};
    std::string detail;
};

/**
 * Exact preflight for replacing the externally computed canonical AlgHash
 * root by the same sponge inside the parent AIR.
 *
 * Candidate encoding:
 *   2 fixed domain lanes
 * + 6 scalar metadata lanes
 * + 5 collision-free uint256 encodings of eight u32 lanes each
 * = 48 field inputs, hence seven rate-8 permutations after mandatory 10*
 * padding. The existing permutation gadget would add 7*130 = 910 columns.
 *
 * The construction is executable only when every input is either a
 * verifier-owned constant or equality-constrained to a proof-authenticated
 * parent cell. Supplying a commitment as a constant does not authenticate
 * the proof behind it.
 */
struct NormalizedSemanticAlgHashParentAudit {
    std::vector<NormalizedAlgHashFieldAudit> fields;
    uint32_t required_input_lanes{0};
    uint32_t verifier_constant_lanes{0};
    uint32_t proof_authenticated_lanes{0};
    uint32_t missing_proof_bus_lanes{0};
    uint32_t sponge_blocks{0};
    uint32_t additional_permutation_columns{0};
    bool canonical_alg_hash_available{false};
    bool slot_binding_valid{false};
    bool child_trace_root_mapped{false};
    bool child_proof_commitment_mapped{false};
    bool terminal_bus_commitment_mapped{false};
    bool external_root_pin_only{false};
    bool in_parent_derivation_complete{false};
    std::string blocker;
};

[[nodiscard]] NormalizedSemanticAlgHashParentAudit
AssessNormalizedSemanticAlgHashParentClosure(
    const FoldBusComposition& composition,
    const BytecodeInterpreterAttachment& interpreter,
    const NormalizedCoupledBankRowPin& row_pin,
    const NormalizedCoupledBankTerminalExecution& execution);

// -------------------------------------------------------------------------
// Executable normalized semantic-root AlgHash sponge seam.
// -------------------------------------------------------------------------

inline constexpr uint32_t kNormalizedSemanticRootInputLanes = 48;
inline constexpr uint32_t kNormalizedSemanticRootSpongeBlocks = 7;
inline constexpr uint32_t kNormalizedSemanticRootPermutationColumns =
    kNormalizedSemanticRootSpongeBlocks * ar::kPermCellsPerPerm;

/**
 * Collision-free V1 encoding:
 *
 *   2 domain lanes;
 *   6 scalar metadata lanes; and
 *   5 uint256 values, each decomposed into eight little-endian u32 lanes.
 *
 * Exactly 48 lanes are absorbed, followed by a mandatory full 10* padding
 * block. The two constants encode "BTXROOT1" and "EMANTIC1" in little-endian
 * byte order and are below the Goldilocks modulus.
 */
inline constexpr gkr_field::Fp
    kNormalizedSemanticRootDomainLane0 =
        UINT64_C(0x31544f4f52585442);
inline constexpr gkr_field::Fp
    kNormalizedSemanticRootDomainLane1 =
        UINT64_C(0x314349544e414d45);
static_assert(
    kNormalizedSemanticRootDomainLane0 < gkr_field::kP);
static_assert(
    kNormalizedSemanticRootDomainLane1 < gkr_field::kP);
static_assert(
    kNormalizedSemanticRootPermutationColumns == 910);

struct NormalizedSemanticRootSpongeLayout {
    uint32_t input_base{0};
    uint32_t permutation_base{
        kNormalizedSemanticRootInputLanes};

    explicit constexpr NormalizedSemanticRootSpongeLayout(
        uint32_t start = 0)
        : input_base(start),
          permutation_base(
              start + kNormalizedSemanticRootInputLanes)
    {
    }
    [[nodiscard]] constexpr uint32_t Input(uint32_t lane) const
    {
        return input_base + lane;
    }
    [[nodiscard]] constexpr ar::PermLayout Permutation(
        uint32_t block) const
    {
        return ar::PermLayout{
            permutation_base +
            block * ar::kPermCellsPerPerm};
    }
    [[nodiscard]] constexpr uint32_t End() const
    {
        return permutation_base +
            kNormalizedSemanticRootPermutationColumns;
    }
};

struct NormalizedSemanticRootSpongeAttachmentV1 {
    uint16_t version{kNormalizedSemanticRootV1Version};
    NormalizedSemanticRootSpongeLayout layout;
    uint256 output_root{};
    uint32_t input_lanes{0};
    uint32_t sponge_blocks{0};
    uint32_t permutation_columns{0};
    uint32_t constraint_base{0};
    uint32_t added_constraints{0};
    uint32_t input_equality_constraints{0};
    uint32_t padding_constraints{0};
    uint32_t capacity_carry_constraints{0};
    uint32_t output_constraints{0};
    uint32_t verifier_constant_lanes{0};
    uint32_t proof_authenticated_lanes{0};
    uint32_t externally_pinned_missing_bus_lanes{0};
    uint32_t violations{0};
    bool exact_order{false};
    bool exact_full_padding_block{false};
    bool all_inputs_constrained{false};
    bool output_equals_candidate_semantic_root{false};
    /** False: the final sixteen lanes are canonical local pins, not outputs
     * of recursively verified child-proof/CTL buses. */
    bool all_inputs_recursively_proof_owned{false};
    bool valid{false};
    std::string note;
};

/** Build the exact 48-lane canonical preimage independently of the sponge. */
[[nodiscard]] bool BuildNormalizedSemanticRootInputsV1(
    const NormalizedRoleChildSlot& slot,
    std::vector<gkr_field::Fp>& out,
    std::string* why = nullptr);

/**
 * Append 48 verifier-owned input columns and seven complete 130-column
 * permutation gadgets to the parent. Every input is equality-wired in
 * canonical order, the seventh block is exactly [1,0,...,0] plus carried
 * state, and the final four outputs equal the candidate semantic root.
 *
 * This closes the sponge computation only. The child-proof commitment and
 * CTL-terminal inputs remain externally pinned, so recursive counters stay
 * zero.
 */
[[nodiscard]] NormalizedSemanticRootSpongeAttachmentV1
AttachNormalizedSemanticRootSpongeV1(
    FoldBusComposition& composition,
    const NormalizedRoleChildSlot& slot);

/** Revalidate canonical input pins, layout, padding/output constraints and
 * the complete parent witness. */
[[nodiscard]] bool ValidateNormalizedSemanticRootSpongeV1(
    const FoldBusComposition& composition,
    const NormalizedRoleChildSlot& slot,
    const NormalizedSemanticRootSpongeAttachmentV1& attachment,
    std::string* why = nullptr);

// -------------------------------------------------------------------------
// Canonical all-proof-field bus for the endpoint-28 AlgAir child.
// -------------------------------------------------------------------------

inline constexpr uint16_t kNormalizedAlgAirProofFieldBusVersion = 1;
inline constexpr uint32_t kNormalizedAlgAirProofFieldBusRate =
    ah::kAlgHashRate;

struct NormalizedAlgAirProofFieldBusLayout {
    uint32_t field_base{0};
    uint32_t active{8};
    uint32_t terminal{9};
    ar::PermLayout permutation{10};

    explicit constexpr NormalizedAlgAirProofFieldBusLayout(
        uint32_t start = 0)
        : field_base(start),
          active(start + kNormalizedAlgAirProofFieldBusRate),
          terminal(active + 1),
          permutation{terminal + 1}
    {
    }
    [[nodiscard]] constexpr uint32_t Field(uint32_t lane) const
    {
        return field_base + lane;
    }
    [[nodiscard]] constexpr uint32_t End() const
    {
        return permutation.End();
    }
};

/**
 * Lossless proof transcript:
 *  - exact canonical Fri3Alg batch codec bytes, packed four bytes per field
 *    with the byte length committed separately;
 *  - trace commitment as eight little-endian u32 fields; and
 *  - every supplemental next-opening index, Fp3 value and AlgHash sibling,
 *    with exact vector lengths and ordering.
 *
 * The batch codec already includes all row/fold roots, OOD/DEEP values,
 * challenge claims, query indices and authentication paths.
 */
[[nodiscard]] bool BuildNormalizedAlgAirProofFieldTranscriptV1(
    const AlgAirProof& proof,
    std::vector<gkr_field::Fp>& out,
    uint32_t* batch_codec_bytes = nullptr,
    uint32_t* batch_codec_words = nullptr,
    uint32_t* supplemental_field_count = nullptr,
    std::string* why = nullptr);

struct NormalizedAlgAirProofFieldBusAttachmentV1 {
    uint16_t version{kNormalizedAlgAirProofFieldBusVersion};
    NormalizedAlgAirProofFieldBusLayout layout;
    uint256 proof_commitment{};
    uint32_t transcript_fields{0};
    uint32_t batch_codec_bytes{0};
    uint32_t batch_codec_words{0};
    uint32_t supplemental_fields{0};
    uint32_t active_sponge_rows{0};
    uint32_t parent_rows{0};
    uint32_t added_columns{0};
    uint32_t constraint_base{0};
    uint32_t added_constraints{0};
    bool exact_codec_bytes_bound{false};
    bool all_supplemental_fields_bound{false};
    bool row_fold_ood_deep_query_path_fields_present{false};
    bool proof_commitment_derived_in_parent{false};
    bool proof_commitment_semantic_lanes_linked{false};
    /** Still false: canonical field columns are verifier pins until every
     * field is equality-mapped to an authenticated verifier-chip output. */
    bool proof_fields_sourced_from_verifier_chips{false};
    bool complete_fiat_shamir_replay_in_parent{false};
    bool ctl_commitment_sourced_from_child_verifier{false};
    bool recursively_consumed{false};
    uint32_t violations{0};
    std::vector<std::string> residuals;
    bool valid{false};
    std::string note;
};

/**
 * Stream the complete proof transcript vertically through one 130-column
 * AlgHash permutation. The resulting proof commitment is equality-linked to
 * the eight u32 lanes already consumed by the semantic-root sponge.
 *
 * This executes proof commitment derivation but not proof verification:
 * transcript fields remain verifier-owned pins pending proof-cell equality
 * maps, SHA256d Fiat-Shamir remains absent, and the CTL proof has no child
 * verifier in this parent.
 */
[[nodiscard]] NormalizedAlgAirProofFieldBusAttachmentV1
AttachNormalizedAlgAirProofFieldBusV1(
    FoldBusComposition& composition,
    const AlgAirProof& proof,
    const NormalizedRoleChildSlot& slot,
    const NormalizedSemanticRootSpongeAttachmentV1&
        semantic_sponge);

[[nodiscard]] bool ValidateNormalizedAlgAirProofFieldBusV1(
    const FoldBusComposition& composition,
    const AlgAirProof& proof,
    const NormalizedRoleChildSlot& slot,
    const NormalizedSemanticRootSpongeAttachmentV1&
        semantic_sponge,
    const NormalizedAlgAirProofFieldBusAttachmentV1& attachment,
    std::string* why = nullptr);

// -------------------------------------------------------------------------
// Canonical batch-codec byte/field map and executable range decoder.
// -------------------------------------------------------------------------

inline constexpr uint16_t
    kNormalizedAlgAirBatchCodecMapVersion = 1;

enum class NormalizedAlgAirCodecWordKind : uint8_t {
    U32 = 0,
    U64Low = 1,
    U64High = 2,
    FpLow = 3,
    FpHigh = 4,
};

/**
 * One exact four-byte word of SerializeFri3AlgBatchProof.  The map is dense:
 * entry i must have word_index=i and byte_offset=4*i.  FpLow/FpHigh entries
 * are adjacent and identify a canonical little-endian Goldilocks element.
 */
struct NormalizedAlgAirCodecWordMapEntryV1 {
    uint32_t word_index{0};
    uint32_t byte_offset{0};
    uint32_t value{0};
    uint32_t semantic_ordinal{0};
    NormalizedAlgAirCodecWordKind kind{
        NormalizedAlgAirCodecWordKind::U32};
    bool consumed_by_existing_verifier_chip{false};
};

enum class NormalizedAlgAirCodecTokenKind : uint8_t {
    U32 = 0,
    Fp = 1,
    Fp3 = 2,
};

enum class NormalizedAlgAirCodecOwnerFamily : uint8_t {
    None = 0,
    Scheduler = 1,
    HashOpening = 2,
    Fold = 3,
    Deep = 4,
    FiatShamir = 5,
};

struct NormalizedAlgAirCodecSemanticTokenV1 {
    uint32_t address{0};
    uint32_t word_index{0};
    gkr_field::Fp3 value{};
    NormalizedAlgAirCodecTokenKind kind{
        NormalizedAlgAirCodecTokenKind::U32};
    NormalizedAlgAirCodecOwnerFamily owner{
        NormalizedAlgAirCodecOwnerFamily::None};
    bool consumed_by_existing_verifier_chip{false};
};

struct NormalizedAlgAirBatchCodecMapV1 {
    uint16_t version{kNormalizedAlgAirBatchCodecMapVersion};
    uint32_t codec_bytes{0};
    uint32_t codec_words{0};
    uint32_t fp_elements{0};
    uint32_t chip_consumed_words{0};
    std::vector<NormalizedAlgAirCodecWordMapEntryV1> entries;
    std::vector<NormalizedAlgAirCodecSemanticTokenV1>
        semantic_tokens;
    bool exact_dense_coverage{false};
    bool exact_little_endian{false};
    bool canonical_roundtrip{false};
    bool no_trailing_bytes{false};
    bool valid{false};
    std::string note;
};

/**
 * Parse the exact canonical batch codec and construct its dense word map.
 * Canonical deserialization plus byte-identical reserialization rejects
 * non-canonical field encodings, alternate encodings and trailing bytes.
 */
[[nodiscard]] bool BuildNormalizedAlgAirBatchCodecMapV1(
    const Fri3AlgBatchProof& proof,
    NormalizedAlgAirBatchCodecMapV1& out,
    std::string* why = nullptr);

/** Validate externally supplied bytes against the unique canonical encoding
 * of `proof`; useful for fail-closed ingress and mutation tests. */
[[nodiscard]] bool ValidateNormalizedAlgAirBatchCodecBytesV1(
    const Fri3AlgBatchProof& proof,
    const std::vector<unsigned char>& encoded,
    std::string* why = nullptr);

inline constexpr uint32_t kNormalizedAlgAirCodecWordLanes = 8;
inline constexpr uint32_t kNormalizedAlgAirCodecBytesPerWord = 4;
inline constexpr uint32_t kNormalizedAlgAirCodecBitsPerByte = 8;

struct NormalizedAlgAirCodecDecoderLayout {
    uint32_t base{0};
    uint32_t byte_base{0};
    uint32_t bit_base{32};
    uint32_t active_base{288};
    uint32_t valid_byte_base{296};
    uint32_t fp_low_base{328};
    uint32_t high_is_max_base{336};
    uint32_t high_delta_inverse_base{344};

    explicit constexpr NormalizedAlgAirCodecDecoderLayout(
        uint32_t start = 0)
        : base(start),
          byte_base(start),
          bit_base(byte_base + 32),
          active_base(bit_base + 256),
          valid_byte_base(active_base + 8),
          fp_low_base(valid_byte_base + 32),
          high_is_max_base(fp_low_base + 8),
          high_delta_inverse_base(high_is_max_base + 8)
    {
    }
    [[nodiscard]] constexpr uint32_t Byte(
        uint32_t lane, uint32_t byte) const
    {
        return byte_base + 4 * lane + byte;
    }
    [[nodiscard]] constexpr uint32_t Bit(
        uint32_t lane, uint32_t byte,
        uint32_t bit) const
    {
        return bit_base + 32 * lane + 8 * byte + bit;
    }
    [[nodiscard]] constexpr uint32_t Active(
        uint32_t lane) const
    {
        return active_base + lane;
    }
    [[nodiscard]] constexpr uint32_t ValidByte(
        uint32_t lane, uint32_t byte) const
    {
        return valid_byte_base + 4 * lane + byte;
    }
    [[nodiscard]] constexpr uint32_t FpLow(
        uint32_t lane) const
    {
        return fp_low_base + lane;
    }
    [[nodiscard]] constexpr uint32_t HighIsMax(
        uint32_t lane) const
    {
        return high_is_max_base + lane;
    }
    [[nodiscard]] constexpr uint32_t HighDeltaInverse(
        uint32_t lane) const
    {
        return high_delta_inverse_base + lane;
    }
    [[nodiscard]] constexpr uint32_t End() const
    {
        return high_delta_inverse_base + 8;
    }
};

static_assert(
    NormalizedAlgAirCodecDecoderLayout{}.End() == 352);

struct NormalizedAlgAirCodecDecoderAttachmentV1 {
    uint16_t version{kNormalizedAlgAirBatchCodecMapVersion};
    NormalizedAlgAirCodecDecoderLayout layout;
    NormalizedAlgAirBatchCodecMapV1 map;
    uint32_t parent_rows{0};
    uint32_t active_word_slots{0};
    uint32_t valid_byte_slots{0};
    uint32_t canonical_fp_elements{0};
    uint32_t added_columns{0};
    uint32_t constraint_base{0};
    uint32_t added_constraints{0};
    uint32_t violations{0};
    bool exact_length_constrained{false};
    bool every_word_decomposed{false};
    bool every_byte_range_checked{false};
    bool little_endian_recomposition_constrained{false};
    bool final_word_padding_zero{false};
    bool every_fp_encoding_canonical{false};
    bool no_unconsumed_codec_bytes{false};
    /** False until decoded values are equality-exported to every remote
     * hash/fold/DEEP/query/path cell, rather than merely decoded in-parent. */
    bool every_chip_consumer_equality_mapped{false};
    bool complete_fiat_shamir_replay_in_parent{false};
    bool recursively_consumed{false};
    std::vector<std::string> residuals;
    bool valid{false};
    std::string note;
};

/**
 * Decode every packed batch-codec word already committed by `proof_bus`.
 * All 32 bits of all eight word lanes are boolean constrained.  Exact byte
 * length, zero terminal padding, LE32 reconstruction and the Goldilocks
 * canonical condition (high==0xffffffff => low==0) are enforced in AIR.
 */
[[nodiscard]] NormalizedAlgAirCodecDecoderAttachmentV1
AttachNormalizedAlgAirCodecDecoderV1(
    FoldBusComposition& composition,
    const AlgAirProof& proof,
    const NormalizedAlgAirProofFieldBusAttachmentV1& proof_bus);

[[nodiscard]] bool ValidateNormalizedAlgAirCodecDecoderV1(
    const FoldBusComposition& composition,
    const AlgAirProof& proof,
    const NormalizedAlgAirProofFieldBusAttachmentV1& proof_bus,
    const NormalizedAlgAirCodecDecoderAttachmentV1& attachment,
    std::string* why = nullptr);

// -------------------------------------------------------------------------
// Decoder-to-consumer dual rational-identity equality bus.
// -------------------------------------------------------------------------

struct NormalizedAlgAirCodecCtlLayout {
    static constexpr uint32_t kPorts = 8;
    static constexpr uint32_t kColumnsPerPort = 5;

    uint32_t base{0};
    uint32_t producer_base{0};
    uint32_t consumer_base{40};
    uint32_t running1{80};
    uint32_t running2{81};
    uint32_t producer_fp3_base{82};

    explicit constexpr NormalizedAlgAirCodecCtlLayout(
        uint32_t start = 0)
        : base(start),
          producer_base(start),
          consumer_base(
              producer_base +
              kPorts * kColumnsPerPort),
          running1(
              consumer_base +
              kPorts * kColumnsPerPort),
          running2(running1 + 1),
          producer_fp3_base(running2 + 1)
    {
    }
    [[nodiscard]] constexpr uint32_t PortBase(
        bool consumer, uint32_t port) const
    {
        return (consumer
                    ? consumer_base
                    : producer_base) +
            port * kColumnsPerPort;
    }
    [[nodiscard]] constexpr uint32_t Value(
        bool consumer, uint32_t port) const
    {
        return PortBase(consumer, port);
    }
    [[nodiscard]] constexpr uint32_t Address(
        bool consumer, uint32_t port) const
    {
        return PortBase(consumer, port) + 1;
    }
    [[nodiscard]] constexpr uint32_t Inverse1(
        bool consumer, uint32_t port) const
    {
        return PortBase(consumer, port) + 2;
    }
    [[nodiscard]] constexpr uint32_t Inverse2(
        bool consumer, uint32_t port) const
    {
        return PortBase(consumer, port) + 3;
    }
    [[nodiscard]] constexpr uint32_t Active(
        bool consumer, uint32_t port) const
    {
        return PortBase(consumer, port) + 4;
    }
    [[nodiscard]] constexpr uint32_t End() const
    {
        return producer_fp3_base + kPorts;
    }
    [[nodiscard]] constexpr uint32_t ProducerFp3(
        uint32_t port) const
    {
        return producer_fp3_base + port;
    }
};

static_assert(
    NormalizedAlgAirCodecCtlLayout{}.End() == 90);

struct NormalizedAlgAirCodecCtlAttachmentV1 {
    uint16_t version{kNormalizedAlgAirBatchCodecMapVersion};
    NormalizedAlgAirCodecCtlLayout layout;
    FoldBusChallenges challenges;
    uint256 prechallenge_commitment{};
    uint32_t semantic_events{0};
    uint32_t producer_events{0};
    uint32_t consumer_events{0};
    uint32_t parent_rows{0};
    uint32_t added_columns{0};
    uint32_t constraint_base{0};
    uint32_t added_constraints{0};
    uint32_t violations{0};
    bool exact_semantic_addresses{false};
    bool exact_multiplicity_one{false};
    bool dual_rational_identity_terminal_zero{false};
    bool denominator_nonzero{false};
    bool decoder_values_aliased{false};
    /**
     * False in this additive seam: consumer values are an exact canonical
     * schedule, but still verifier-owned pins. The next cut must replace each
     * pin with the actual owning hash/fold/DEEP/query/path cell at the same
     * event address.
     */
    bool consumer_values_sourced_from_remote_chips{false};
    bool complete_fiat_shamir_replay_in_parent{false};
    bool recursively_consumed{false};
    std::vector<std::string> residuals;
    bool valid{false};
    std::string note;
};

/**
 * Execute the exact dual LogUp/rational-identity multiset equality between
 * decoder-produced semantic scalars and a canonical consumer schedule.
 * Addresses are semantic ordinals plus one; every address has multiplicity
 * +1 on the decoder side and -1 on the consumer side.
 *
 * This closes the equality-bus algebra and its adversarial edge cases, but
 * deliberately leaves recursive ownership false until consumer values are
 * direct aliases of their remote chip cells.
 */
[[nodiscard]] NormalizedAlgAirCodecCtlAttachmentV1
AttachNormalizedAlgAirCodecCtlV1(
    FoldBusComposition& composition,
    const NormalizedAlgAirProofFieldBusAttachmentV1& proof_bus,
    const NormalizedAlgAirCodecDecoderAttachmentV1& decoder);

[[nodiscard]] bool ValidateNormalizedAlgAirCodecCtlV1(
    const FoldBusComposition& composition,
    const NormalizedAlgAirProofFieldBusAttachmentV1& proof_bus,
    const NormalizedAlgAirCodecDecoderAttachmentV1& decoder,
    const NormalizedAlgAirCodecCtlAttachmentV1& attachment,
    std::string* why = nullptr);

// -------------------------------------------------------------------------
// Literal same-row exports from the existing verifier chips.
// -------------------------------------------------------------------------

inline constexpr uint32_t
    kNormalizedAlgAirRemoteSourceKindCount = 31;

struct NormalizedAlgAirRemoteExportLayout {
    NormalizedAlgAirCodecCtlLayout bus;
    uint32_t source_selector_base{90};

    explicit constexpr NormalizedAlgAirRemoteExportLayout(
        uint32_t start = 0)
        : bus(start),
          source_selector_base(bus.End())
    {
    }
    [[nodiscard]] constexpr uint32_t SourceSelector(
        uint32_t port, uint32_t kind) const
    {
        return source_selector_base +
            port *
                kNormalizedAlgAirRemoteSourceKindCount +
            kind;
    }
    [[nodiscard]] constexpr uint32_t End() const
    {
        return source_selector_base +
            NormalizedAlgAirCodecCtlLayout::kPorts *
                kNormalizedAlgAirRemoteSourceKindCount;
    }
};

static_assert(
    NormalizedAlgAirRemoteExportLayout{}.End() == 338);

struct NormalizedAlgAirRemoteExportAttachmentV1 {
    uint16_t version{kNormalizedAlgAirBatchCodecMapVersion};
    NormalizedAlgAirRemoteExportLayout layout;
    FoldBusChallenges challenges;
    uint256 prechallenge_commitment{};
    uint32_t remote_events{0};
    uint32_t hash_opening_value_events{0};
    uint32_t query_index_events{0};
    uint32_t authentication_path_events{0};
    uint32_t root_events{0};
    uint32_t fold_value_events{0};
    uint32_t deep_tokens_remaining{0};
    uint32_t scheduler_tokens_remaining{0};
    uint32_t fiat_shamir_tokens_remaining{0};
    uint32_t parent_rows{0};
    uint32_t added_columns{0};
    uint32_t constraint_base{0};
    uint32_t added_constraints{0};
    uint32_t violations{0};
    bool literal_same_row_aliases{false};
    bool every_direct_opening_query_path_root_fold_owned{false};
    bool dual_rational_identity_terminal_zero{false};
    bool denominator_nonzero{false};
    bool derived_deep_inputs_remote_owned{false};
    bool every_codec_consumer_remote_owned{false};
    bool complete_fiat_shamir_replay_in_parent{false};
    bool recursively_consumed{false};
    std::vector<std::string> residuals;
    bool valid{false};
    std::string note;
};

/**
 * Export the direct proof-owned cells from the already executing
 * hash/fold verifier: current row Fp3 values, query indices, every current
 * and fold authentication sibling, row/fold roots, fold operands,
 * fold challenges and the terminal folded value. A second dual LogUp bus
 * ties those literal same-row exports to the corresponding codec addresses.
 *
 * Derived DEEP inputs (lambda/z/evals/weights/lengths) and pure scheduler
 * metadata remain explicit counters, not silently treated as direct cells.
 */
[[nodiscard]] NormalizedAlgAirRemoteExportAttachmentV1
AttachNormalizedAlgAirRemoteExportsV1(
    FoldBusComposition& composition,
    const AlgAirProof& proof,
    const NormalizedAlgAirCodecDecoderAttachmentV1& decoder,
    const NormalizedAlgAirCodecCtlAttachmentV1& codec_ctl);

[[nodiscard]] bool ValidateNormalizedAlgAirRemoteExportsV1(
    const FoldBusComposition& composition,
    const AlgAirProof& proof,
    const NormalizedAlgAirCodecDecoderAttachmentV1& decoder,
    const NormalizedAlgAirCodecCtlAttachmentV1& codec_ctl,
    const NormalizedAlgAirRemoteExportAttachmentV1& attachment,
    std::string* why = nullptr);

// -------------------------------------------------------------------------
// Canonical public-program ownership for scheduler/shape tokens.
// -------------------------------------------------------------------------

struct NormalizedAlgAirSchedulerTokenAttachmentV1 {
    uint16_t version{kNormalizedAlgAirBatchCodecMapVersion};
    NormalizedAlgAirCodecCtlLayout layout;
    FoldBusChallenges challenges;
    uint256 prechallenge_commitment{};
    uint32_t scheduler_tokens{0};
    uint32_t shape_tokens{0};
    uint32_t fold_schedule_tokens{0};
    uint32_t query_schedule_tokens{0};
    uint32_t path_length_tokens{0};
    uint32_t parent_rows{0};
    uint32_t added_columns{0};
    uint32_t constraint_base{0};
    uint32_t added_constraints{0};
    uint32_t violations{0};
    /** Remaining SHA-owned output inventory, including AIR lambda. */
    uint32_t sha256d_challenge_outputs_remaining{0};
    /** The PoW grinding nonce is an absorbed input, not a challenge output. */
    uint32_t sha256d_nonce_inputs_remaining{0};
    uint32_t ctl_child_terminal_items_remaining{0};
    bool values_derived_from_public_program{false};
    bool exact_scheduler_addresses{false};
    bool every_scheduler_token_owned{false};
    bool dual_rational_identity_terminal_zero{false};
    bool denominator_nonzero{false};
    bool complete_fiat_shamir_replay_in_parent{false};
    bool ctl_commitment_sourced_from_child_verifier{false};
    bool recursively_consumed{false};
    std::vector<std::string> residuals;
    bool valid{false};
    std::string note;
};

/**
 * Materialize every codec-carried shape/count/path-length word from the
 * canonical public verifier program, not from the proof witness. A dedicated
 * dual LogUp bus binds those public-program cells to their codec addresses.
 */
[[nodiscard]] NormalizedAlgAirSchedulerTokenAttachmentV1
AttachNormalizedAlgAirSchedulerTokensV1(
    FoldBusComposition& composition,
    const AlgAirProof& proof,
    const NormalizedAlgAirCodecDecoderAttachmentV1& decoder,
    const NormalizedAlgAirCodecCtlAttachmentV1& codec_ctl,
    const NormalizedAlgAirRemoteExportAttachmentV1& remote_exports);

[[nodiscard]] bool ValidateNormalizedAlgAirSchedulerTokensV1(
    const FoldBusComposition& composition,
    const AlgAirProof& proof,
    const NormalizedAlgAirCodecDecoderAttachmentV1& decoder,
    const NormalizedAlgAirCodecCtlAttachmentV1& codec_ctl,
    const NormalizedAlgAirRemoteExportAttachmentV1& remote_exports,
    const NormalizedAlgAirSchedulerTokenAttachmentV1& attachment,
    std::string* why = nullptr);

// -------------------------------------------------------------------------
// Exact-width plan for the remaining 64-port DEEP derivation chip.
// -------------------------------------------------------------------------

inline constexpr uint32_t
    kNormalizedDeepDerivationPorts = 64;
inline constexpr uint32_t
    kNormalizedDeepSharedPowerColumns = 161;
inline constexpr uint32_t
    kNormalizedDeepColumnsPerPort = 146;
inline constexpr uint32_t
    kNormalizedDeepInputReadOutputBusColumns = 246;
inline constexpr uint32_t
    kNormalizedDeepDerivationAddedColumns =
        kNormalizedDeepSharedPowerColumns +
        kNormalizedDeepDerivationPorts *
            kNormalizedDeepColumnsPerPort +
        kNormalizedDeepInputReadOutputBusColumns;
static_assert(
    kNormalizedDeepDerivationAddedColumns == 9751);

struct NormalizedDeepDerivationPlanV1 {
    uint16_t version{1};
    uint32_t ports{kNormalizedDeepDerivationPorts};
    uint32_t batch_width{0};
    uint32_t queries{0};
    uint64_t query_item_sites{0};
    uint32_t active_rows{0};
    uint32_t available_parent_rows{0};
    uint32_t current_parent_columns{0};
    uint32_t shared_power_columns{0};
    uint32_t columns_per_port{0};
    uint32_t bus_columns{0};
    uint32_t added_columns{0};
    uint32_t final_parent_columns{0};
    uint64_t input_table_tokens{0};
    uint64_t repeated_input_reads{0};
    uint64_t ux_output_events{0};
    uint64_t inverse_output_events{0};
    uint64_t aggregate_output_events{0};
    bool shared_z_power_tables{false};
    bool per_query_x_power_table{false};
    bool shift_binary_accumulators{false};
    bool lambda_item_recurrence{false};
    bool input_multiplicity_logup_required{false};
    bool output_logup_required{false};
    bool row_cap_supported{false};
    bool column_cap_supported{false};
    /** Planning only; set false until the described constraints execute. */
    bool executable{false};
    bool valid{false};
    std::string note;
};

/**
 * Dimension the sound 64-port construction:
 *  - shared z1/z2 square tables;
 *  - per-query proof of x=omega^index and x square table;
 *  - 32 shift bits and three selected-product accumulators per port;
 *  - lambda^i and v1/v2 recurrences; and
 *  - separate input/read/output dual-LogUp buses.
 *
 * Sharing square tables is essential: duplicating all three 32-step square
 * chains per port would exceed the 16,384-column production cap.
 */
[[nodiscard]] NormalizedDeepDerivationPlanV1
AssessNormalizedDeepDerivation64PlanV1(
    const AlgAirProof& proof,
    uint32_t available_parent_rows,
    uint32_t current_parent_columns);

/**
 * Standalone endpoint-28 DEEP chip pilot.  The shared 161-column table is
 * exactly the planner inventory: z1/z2 squares, query-index bits, query-x
 * squares and the 33-cell domain-generator product chain deriving x.
 */
struct NormalizedDeepSharedLayoutV1 {
    static constexpr uint32_t kExponentBits = 32;
    uint32_t base{0};
    uint32_t z1_square_base{0};
    uint32_t z2_square_base{32};
    uint32_t query_index_bit_base{64};
    uint32_t x_square_base{96};
    uint32_t query_product_base{128};

    explicit constexpr NormalizedDeepSharedLayoutV1(
        uint32_t start = 0)
        : base(start),
          z1_square_base(start),
          z2_square_base(
              z1_square_base + kExponentBits),
          query_index_bit_base(
              z2_square_base + kExponentBits),
          x_square_base(
              query_index_bit_base +
              kExponentBits),
          query_product_base(
              x_square_base +
              kExponentBits)
    {
    }
    [[nodiscard]] constexpr uint32_t Z1Square(
        uint32_t bit) const
    {
        return z1_square_base + bit;
    }
    [[nodiscard]] constexpr uint32_t Z2Square(
        uint32_t bit) const
    {
        return z2_square_base + bit;
    }
    [[nodiscard]] constexpr uint32_t QueryIndexBit(
        uint32_t bit) const
    {
        return query_index_bit_base + bit;
    }
    [[nodiscard]] constexpr uint32_t XSquare(
        uint32_t bit) const
    {
        return x_square_base + bit;
    }
    [[nodiscard]] constexpr uint32_t QueryProduct(
        uint32_t step) const
    {
        return query_product_base + step;
    }
    [[nodiscard]] constexpr uint32_t End() const
    {
        return query_product_base +
            kExponentBits + 1;
    }
};
static_assert(
    NormalizedDeepSharedLayoutV1{}.End() ==
    kNormalizedDeepSharedPowerColumns);

/** One 146-column item port.  Three 33-cell selected-product chains prove
 * x^shift, z1^shift and z2^shift from the same 32 shift bits. */
struct NormalizedDeepPortLayoutV1 {
    static constexpr uint32_t kExponentBits = 32;
    uint32_t base{0};
    uint32_t active{0};
    uint32_t item{1};
    uint32_t column_len{2};
    uint32_t row_value{3};
    uint32_t eval_z1{4};
    uint32_t eval_z2{5};
    uint32_t lambda_power{6};
    uint32_t shift_bit_base{7};
    uint32_t x_product_base{39};
    uint32_t z1_product_base{72};
    uint32_t z2_product_base{105};
    uint32_t v1_running{138};
    uint32_t v2_running{139};
    uint32_t ux_running{140};
    uint32_t invd1{141};
    uint32_t invd2{142};
    uint32_t deep_value{143};
    uint32_t opened_deep_value{144};
    uint32_t output_selector{145};

    explicit constexpr NormalizedDeepPortLayoutV1(
        uint32_t start = 0)
        : base(start),
          active(start),
          item(start + 1),
          column_len(start + 2),
          row_value(start + 3),
          eval_z1(start + 4),
          eval_z2(start + 5),
          lambda_power(start + 6),
          shift_bit_base(start + 7),
          x_product_base(
              shift_bit_base + kExponentBits),
          z1_product_base(
              x_product_base +
              kExponentBits + 1),
          z2_product_base(
              z1_product_base +
              kExponentBits + 1),
          v1_running(
              z2_product_base +
              kExponentBits + 1),
          v2_running(v1_running + 1),
          ux_running(v2_running + 1),
          invd1(ux_running + 1),
          invd2(invd1 + 1),
          deep_value(invd2 + 1),
          opened_deep_value(deep_value + 1),
          output_selector(opened_deep_value + 1)
    {
    }
    [[nodiscard]] constexpr uint32_t ShiftBit(
        uint32_t bit) const
    {
        return shift_bit_base + bit;
    }
    [[nodiscard]] constexpr uint32_t XProduct(
        uint32_t step) const
    {
        return x_product_base + step;
    }
    [[nodiscard]] constexpr uint32_t Z1Product(
        uint32_t step) const
    {
        return z1_product_base + step;
    }
    [[nodiscard]] constexpr uint32_t Z2Product(
        uint32_t step) const
    {
        return z2_product_base + step;
    }
    [[nodiscard]] constexpr uint32_t End() const
    {
        return output_selector + 1;
    }
};
static_assert(
    NormalizedDeepPortLayoutV1{}.End() ==
    kNormalizedDeepColumnsPerPort);

/** Eight event lanes, producer and consumer, plus two independent running
 * rational identities. Active is an Fp3 multiplicity, not just a boolean. */
struct NormalizedDeepLogUpLayoutV1 {
    static constexpr uint32_t kEventPorts = 8;
    static constexpr uint32_t kColumnsPerEvent = 5;
    uint32_t base{0};
    uint32_t producer_base{0};
    uint32_t consumer_base{40};
    uint32_t running1{80};
    uint32_t running2{81};

    explicit constexpr NormalizedDeepLogUpLayoutV1(
        uint32_t start = 0)
        : base(start),
          producer_base(start),
          consumer_base(
              producer_base +
              kEventPorts * kColumnsPerEvent),
          running1(
              consumer_base +
              kEventPorts * kColumnsPerEvent),
          running2(running1 + 1)
    {
    }
    [[nodiscard]] constexpr uint32_t EventBase(
        bool consumer, uint32_t port) const
    {
        return (consumer
                    ? consumer_base
                    : producer_base) +
            port * kColumnsPerEvent;
    }
    [[nodiscard]] constexpr uint32_t Value(
        bool consumer, uint32_t port) const
    {
        return EventBase(consumer, port);
    }
    [[nodiscard]] constexpr uint32_t Address(
        bool consumer, uint32_t port) const
    {
        return EventBase(consumer, port) + 1;
    }
    [[nodiscard]] constexpr uint32_t Inverse1(
        bool consumer, uint32_t port) const
    {
        return EventBase(consumer, port) + 2;
    }
    [[nodiscard]] constexpr uint32_t Inverse2(
        bool consumer, uint32_t port) const
    {
        return EventBase(consumer, port) + 3;
    }
    [[nodiscard]] constexpr uint32_t Multiplicity(
        bool consumer, uint32_t port) const
    {
        return EventBase(consumer, port) + 4;
    }
    [[nodiscard]] constexpr uint32_t End() const
    {
        return running2 + 1;
    }
};
static_assert(
    NormalizedDeepLogUpLayoutV1{}.End() == 82);

struct NormalizedDeepDerivationLayoutV1 {
    NormalizedDeepSharedLayoutV1 shared;
    uint32_t port_base{161};
    uint32_t ports{1};
    NormalizedDeepLogUpLayoutV1 input_bus;
    NormalizedDeepLogUpLayoutV1 read_bus;
    NormalizedDeepLogUpLayoutV1 output_bus;

    explicit constexpr NormalizedDeepDerivationLayoutV1(
        uint32_t port_count = 1,
        uint32_t start = 0)
        : shared(start),
          port_base(shared.End()),
          ports(port_count),
          input_bus(
              port_base +
              port_count *
                  kNormalizedDeepColumnsPerPort),
          read_bus(input_bus.End()),
          output_bus(read_bus.End())
    {
    }
    [[nodiscard]] constexpr
    NormalizedDeepPortLayoutV1 Port(
        uint32_t port) const
    {
        return NormalizedDeepPortLayoutV1(
            port_base +
            port *
                kNormalizedDeepColumnsPerPort);
    }
    [[nodiscard]] constexpr uint32_t End() const
    {
        return output_bus.End();
    }
};
static_assert(
    NormalizedDeepDerivationLayoutV1{64}.End() ==
    kNormalizedDeepDerivationAddedColumns);

struct NormalizedDeepDerivationAttachmentV1 {
    uint16_t version{1};
    uint32_t requested_ports{0};
    NormalizedDeepDerivationLayoutV1 layout;
    aq::AirConstraintSystem<Fp3> chip;
    std::vector<std::vector<Fp3>> columns;
    std::array<FoldBusChallenges, 3> bus_challenges;
    std::array<uint256, 3> bus_precommitments{};
    uint32_t batch_width{0};
    uint32_t queries{0};
    uint64_t query_item_sites{0};
    uint32_t active_derivation_rows{0};
    uint32_t trace_rows{0};
    uint32_t added_columns{0};
    uint32_t added_constraints{0};
    uint64_t input_table_events{0};
    uint64_t input_read_events{0};
    uint64_t query_x_events{0};
    uint64_t output_events{0};
    uint32_t violations{0};
    bool shared_z1_z2_square_tables{false};
    bool parameterized_query_x_table{false};
    bool shift_bits_and_three_products{false};
    bool lambda_v_inverse_recurrences{false};
    bool input_logup_terminal_zero{false};
    bool read_logup_terminal_zero{false};
    bool output_logup_terminal_zero{false};
    bool denominator_nonzero{false};
    bool witness_built{false};
    /** False until all 64 ports are attached to proof-owned decoded cells. */
    bool full_64_port_relation_closed{false};
    bool executable{false};
    uint32_t recursive_endpoints_consumed{0};
    uint32_t recursive_roles_consumed{0};
    bool recursively_consumed{false};
    std::vector<std::string> residuals;
    bool valid{false};
    std::string note;
};

/**
 * Build either the one-port adversarial pilot or the exact-width 64-port
 * standalone chip.  Only {1,64} are accepted, avoiding ambiguous schedules:
 * one port streams items vertically; 64 ports execute each query's item set
 * horizontally while sharing that row's x table.
 */
[[nodiscard]] NormalizedDeepDerivationAttachmentV1
BuildNormalizedDeepDerivationPilotV1(
    const AlgAirProof& proof,
    uint32_t requested_ports = 1);

[[nodiscard]] bool ValidateNormalizedDeepDerivationPilotV1(
    const AlgAirProof& proof,
    const NormalizedDeepDerivationAttachmentV1& attachment,
    std::string* why = nullptr);

/**
 * Sparse production-width execution witness for endpoint 28.  Exactly 64
 * records are present per query.  Inactive tail ports are explicit records,
 * so validation covers the physical arity without allocating a
 * 9,751-column-by-production-rows dense matrix.
 */
struct NormalizedDeep64PortWitnessV1 {
    static constexpr uint32_t kSourceAddresses = 11;
    uint32_t query{0};
    uint32_t port{0};
    uint32_t item{0};
    uint32_t query_index{0};
    uint32_t column_len{0};
    uint32_t shift{0};
    bool active{false};
    bool output{false};
    std::array<uint32_t, kSourceAddresses>
        source_address{};
    Fp3 x{};
    Fp3 row_value{};
    Fp3 eval_z1{};
    Fp3 eval_z2{};
    Fp3 lambda_power{};
    Fp3 x_shift{};
    Fp3 z1_shift{};
    Fp3 z2_shift{};
    Fp3 v1_running{};
    Fp3 v2_running{};
    Fp3 ux_running{};
    Fp3 invd1{};
    Fp3 invd2{};
    Fp3 deep_value{};
    Fp3 opened_deep_value{};
};

struct NormalizedDeepSparseLogUpAuditV1 {
    uint256 prechallenge_commitment{};
    FoldBusChallenges challenges;
    uint64_t producer_records{0};
    uint64_t consumer_records{0};
    uint64_t producer_multiplicity{0};
    uint64_t consumer_multiplicity{0};
    Fp3 terminal1{};
    Fp3 terminal2{};
    bool commit_then_challenge{false};
    bool denominator_nonzero{false};
    bool terminal_zero{false};
    bool valid{false};
};

/**
 * Production-local endpoint-28 integration.  This binds the DEEP input
 * table to canonical decoder semantic addresses, current-row/query/fold
 * consumers to literal existing verifier-chip exports, and checks all 64
 * physical ports per query.  `executable` is local endpoint execution only;
 * recursive counters intentionally remain zero until SHA Fiat-Shamir replay
 * and the unified CTL child terminal are attached.
 */
struct NormalizedDeep64IntegrationV1 {
    uint16_t version{1};
    uint32_t ports{kNormalizedDeepDerivationPorts};
    uint32_t batch_width{0};
    uint32_t queries{0};
    uint64_t physical_port_records{0};
    uint64_t active_port_records{0};
    uint32_t canonical_deep_tokens{0};
    uint32_t literal_remote_events{0};
    std::vector<NormalizedDeep64PortWitnessV1>
        port_witness;
    std::array<NormalizedDeepSparseLogUpAuditV1, 3>
        logup;
    bool canonical_decoder_input_table_bound{false};
    bool current_opening_values_literal_bound{false};
    bool query_indices_literal_bound{false};
    bool selected_fold_openings_literal_bound{false};
    bool root_path_fold_remote_bus_preserved{false};
    bool shared_power_tables_checked{false};
    bool all_64_ports_structurally_constrained{false};
    bool all_three_logup_terminals_zero{false};
    bool local_endpoint_executable{false};
    bool executable{false};
    uint32_t recursive_endpoints_consumed{0};
    uint32_t recursive_roles_consumed{0};
    bool recursively_consumed{false};
    std::vector<std::string> residuals;
    bool valid{false};
    std::string note;
};

[[nodiscard]] NormalizedDeep64IntegrationV1
BuildNormalizedDeep64IntegrationV1(
    const FoldBusComposition& composition,
    const AlgAirProof& proof,
    const NormalizedAlgAirCodecDecoderAttachmentV1& decoder,
    const NormalizedAlgAirCodecCtlAttachmentV1& codec_ctl,
    const NormalizedAlgAirRemoteExportAttachmentV1& remote_exports);

[[nodiscard]] bool ValidateNormalizedDeep64IntegrationV1(
    const FoldBusComposition& composition,
    const AlgAirProof& proof,
    const NormalizedAlgAirCodecDecoderAttachmentV1& decoder,
    const NormalizedAlgAirCodecCtlAttachmentV1& codec_ctl,
    const NormalizedAlgAirRemoteExportAttachmentV1& remote_exports,
    const NormalizedDeep64IntegrationV1& attachment,
    std::string* why = nullptr);

/**
 * Canonical endpoint-28 proof-root inventory transport.  Every committed
 * CoupledBank relation column root is split into eight ordered u32 limbs.
 *
 * This is deliberately not a semantic CTL export: the paired +1/-1 entries
 * self-cancel and therefore prove no producer-to-consumer row equality.  It
 * is retained only as a transcript/codec binding diagnostic while the real
 * tuple-export adapter below remains fail closed.
 */
[[nodiscard]] bool BuildNormalizedCoupledBankCtlRootScheduleV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    RCStage3CtlSchedule& schedule,
    std::vector<gkr_field::Fp3>& values,
    std::string* why = nullptr);

/**
 * Exact manifest for the missing endpoint-28 row-level CTL seam.
 *
 * The producer side is the proof-owned CoupledBank dequant OUTPUT column.
 * A complete adapter additionally needs the corresponding consumer/table
 * proof to export one value at the same (namespace, stage, address) for every
 * logical row, with the opposite multiplicity.  The current normalized proof
 * API exposes a row commitment but no whole-column projection/opening and
 * accepts no consumer proof, so this manifest must remain non-executable.
 */
struct NormalizedCoupledBankCtlTupleExportAdapterV1 {
    uint16_t version{1};
    RCStage3RelationRole role{
        RCStage3RelationRole::CoupledBank};
    RCStage3RelationEndpoint endpoint{
        RCStage3RelationEndpoint::CoupledBankPages};
    uint32_t namespace_id{0};
    uint32_t stage{0};
    uint32_t first_address{0};
    uint32_t producer_source_column{0};
    uint32_t logical_rows{0};
    uint32_t trace_rows{0};
    uint64_t required_event_count{0};
    uint64_t required_send_count{0};
    uint64_t required_receive_count{0};
    uint256 source_pin_commitment{};
    uint256 row_pin_commitment{};
    uint256 producer_trace_commitment{};
    uint256 producer_proof_commitment{};
    uint256 adapter_commitment{};
    bool canonical_tuple_manifest{false};
    bool producer_relation_proof_verified{false};
    bool producer_output_column_identified{false};
    bool producer_cells_exported{false};
    bool consumer_proof_bound{false};
    bool consumer_cells_exported{false};
    bool shared_post_commit_challenges{false};
    bool cross_proof_logup_identity{false};
    bool executable{false};
    bool semantic_closure{false};
    std::vector<std::string> residuals;
    bool valid{false};
    std::string note;

    bool operator==(
        const NormalizedCoupledBankCtlTupleExportAdapterV1&) const =
        default;
};

[[nodiscard]] uint256
ComputeNormalizedCoupledBankCtlTupleExportAdapterCommitmentV1(
    const NormalizedCoupledBankCtlTupleExportAdapterV1& adapter);

[[nodiscard]] NormalizedCoupledBankCtlTupleExportAdapterV1
BuildNormalizedCoupledBankCtlTupleExportAdapterV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    const NormalizedCoupledBankRowPin& row_pin,
    const AlgAirProof& proof,
    const uint256& fs_seed);

[[nodiscard]] bool
ValidateNormalizedCoupledBankCtlTupleExportAdapterV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    const NormalizedCoupledBankRowPin& row_pin,
    const AlgAirProof& proof,
    const uint256& fs_seed,
    const NormalizedCoupledBankCtlTupleExportAdapterV1& adapter,
    std::string* why = nullptr);

/**
 * Additive endpoint-28 OUTPUT-to-projection self-consistency bridge.
 *
 * The producer is one Split-RAP proof over the normalized six-column
 * CoupledBank relation plus a same-trace CTL child whose VALUE column is
 * constrained equal to relation OUTPUT.  Its R0 group commits all relation
 * columns and the five challenge-independent CTL columns before gamma/alpha.
 *
 * The second child is a separately committed mirror projection with the same
 * immutable tuple addresses and opposite multiplicity.  Both children
 * derive the same two domain-separated (gamma,alpha) lanes from their ordered
 * prechallenge commitments.  The mirror VALUE root is a new normalized
 * OUTPUT projection root.  It is not a registered consumer/table proof and
 * has no equality to the legacy SHA column root.  Consequently this artifact
 * is useful for exercising the Split-RAP/LogUp plumbing but is not endpoint
 * semantic closure.
 */
struct NormalizedCoupledBankCtlProjectionBridgeProofV1 {
    uint16_t version{1};
    RCStage3CtlManifest manifest;
    std::vector<RCStage3CtlChildPin> pins;
    RCStage3CtlSchedule producer_schedule;
    RCStage3CtlSchedule mirror_schedule;
    aq::AirQuotientSplitRapRowsProof producer_proof;
    RCStage3CtlAirProof mirror_proof;
    RCStage3CtlRelationExportPin mirror_export;
    uint256 output_projection_root{};
    uint256 producer_proof_commitment{};
    uint256 mirror_proof_commitment{};
    uint256 proof_commitment{};
    uint256 terminal_bus_commitment{};
};

struct NormalizedCoupledBankCtlProjectionBridgeAuditV1 {
    uint16_t version{1};
    uint32_t logical_rows{0};
    uint64_t producer_events{0};
    uint64_t mirror_events{0};
    uint256 output_projection_root{};
    uint256 proof_commitment{};
    uint256 terminal_bus_commitment{};
    bool exact_tuple_schedule{false};
    bool producer_relation_output_same_trace{false};
    bool producer_split_rap_verified{false};
    bool mirror_projection_root_verified{false};
    bool mirror_ctl_child_verified{false};
    bool shared_post_commit_challenges{false};
    bool dual_logup_terminal_equality{false};
    bool projection_self_consistency_verified{false};
    bool registered_consumer_relation_bound{false};
    bool producer_registered_roots_bound{false};
    bool signed_output_to_u8_mapping_verified{false};
    bool all_pages_aggregated{false};
    bool projection_child_soundness_at_least_100_bits{false};
    bool native_cross_proof_semantic_closure{false};
    bool production_semantic_closure{false};
    bool proof_and_projection_bound_in_semantic_slot{false};
    bool semantic_root_lanes_verified{false};
    bool complete_sha_fiat_shamir_replay_in_parent{false};
    bool all_child_verifiers_execute_in_parent{false};
    bool endpoint_promoted{false};
    bool authority{false};
    uint32_t recursive_endpoints_consumed{0};
    uint32_t recursive_roles_consumed{0};
    std::vector<std::string> residuals;
    bool valid{false};
    std::string note;
};

[[nodiscard]] bool
ProveNormalizedCoupledBankCtlProjectionBridgeV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    const std::vector<std::vector<gkr_field::Fp3>>&
        relation_columns,
    const uint256& fs_seed,
    NormalizedCoupledBankCtlProjectionBridgeProofV1& out,
    std::string* why = nullptr);

[[nodiscard]] NormalizedCoupledBankCtlProjectionBridgeAuditV1
VerifyNormalizedCoupledBankCtlProjectionBridgeV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    const NormalizedCoupledBankCtlProjectionBridgeProofV1& proof,
    const uint256& fs_seed,
    const FoldBusComposition& composition,
    const NormalizedRoleChildSlot& slot,
    const NormalizedSemanticRootSpongeAttachmentV1&
        semantic_sponge);

struct NormalizedDeep64CtlTerminalAttachmentV1 {
    uint16_t version{1};
    RCStage3CtlRelationExportPin relation_export;
    uint32_t child_index{0};
    uint64_t event_count{0};
    uint64_t send_count{0};
    uint64_t receive_count{0};
    uint32_t proof_codec_bytes{0};
    uint32_t proof_field_count{0};
    std::vector<gkr_field::Fp3> proof_fields;
    uint256 proof_transport_commitment{};
    uint256 terminal_bus_commitment{};
    bool canonical_relation_root_tuples{false};
    bool relation_value_column_bound{false};
    bool prechallenge_commitments_bound{false};
    bool challenges_after_commitments{false};
    bool denominator_nonzero_constraints_verified{false};
    bool multiplicity_accumulators_verified{false};
    bool selected_child_terminal_zero{false};
    /** All public pins sum to zero; other child AIR proofs are not supplied. */
    bool public_pin_terminal_equality_verified{false};
    bool all_participant_child_proofs_verified{false};
    bool global_terminal_equality_verified{false};
    bool proof_codec_canonical{false};
    bool proof_field_transport_bound{false};
    bool terminal_semantic_lanes_linked{false};
    bool semantic_slot_and_sponge_binding_verified{false};
    bool child_proof_verified_natively{false};
    /** True identifies this as proof-root inventory transport only. */
    bool root_inventory_transport_only{false};
    bool actual_producer_relation_tuples_bound{false};
    bool actual_consumer_proof_tuples_bound{false};
    bool cross_proof_logup_identity_verified{false};
    bool ctl_semantic_closure{false};
    /** False until the SHA-based CTL verifier transcript executes in AIR. */
    bool complete_sha_fiat_shamir_replay_in_parent{false};
    bool endpoint_promoted{false};
    bool authority{false};
    uint32_t recursive_endpoints_consumed{0};
    uint32_t recursive_roles_consumed{0};
    bool recursively_consumed{false};
    std::vector<std::string> residuals;
    bool valid{false};
    std::string note;
};

[[nodiscard]] NormalizedDeep64CtlTerminalAttachmentV1
BuildNormalizedDeep64CtlTerminalV1(
    const FoldBusComposition& composition,
    const RCStage3CoupledBankDequantPin& source_pin,
    const NormalizedRoleChildSlot& slot,
    const NormalizedSemanticRootSpongeAttachmentV1&
        semantic_sponge,
    const RCStage3CtlManifest& manifest,
    const std::vector<RCStage3CtlChildPin>& pins,
    size_t child_index,
    const RCStage3CtlSchedule& schedule,
    const RCStage3CtlAirProof& proof);

[[nodiscard]] bool ValidateNormalizedDeep64CtlTerminalV1(
    const FoldBusComposition& composition,
    const RCStage3CoupledBankDequantPin& source_pin,
    const NormalizedRoleChildSlot& slot,
    const NormalizedSemanticRootSpongeAttachmentV1&
        semantic_sponge,
    const RCStage3CtlManifest& manifest,
    const std::vector<RCStage3CtlChildPin>& pins,
    size_t child_index,
    const RCStage3CtlSchedule& schedule,
    const RCStage3CtlAirProof& proof,
    const NormalizedDeep64CtlTerminalAttachmentV1& attachment,
    std::string* why = nullptr);

// -------------------------------------------------------------------------
// Fail-closed recursive child-verifier capability audit.
// -------------------------------------------------------------------------

inline constexpr uint16_t
    kNormalizedRecursiveChildCapabilityAuditVersion = 1;

enum class NormalizedRecursiveVerifierGapCode : uint8_t {
    ChildProofPayloadBus = 1,
    FiatShamirReplayAir = 2,
    ChildProofCommitmentBus = 3,
    CtlChildVerifierAndTerminalBus = 4,
    NormalizedSemanticRootAlgHash = 5,
    SplitRapMultiRowVerifier = 6,
    EndpointTerminalEquality = 7,
};

/**
 * One independently necessary verifier component. `required_lanes` and
 * `mapped_lanes` count collision-free u32/Fp input lanes where that count is
 * protocol-fixed. `additional_columns` is populated only for a concrete
 * existing layout calculation; zero means "not yet designed", never "free".
 */
struct NormalizedRecursiveVerifierGap {
    NormalizedRecursiveVerifierGapCode code{
        NormalizedRecursiveVerifierGapCode::ChildProofPayloadBus};
    std::string chip;
    uint32_t required_lanes{0};
    uint32_t mapped_lanes{0};
    uint32_t additional_columns{0};
    bool present_in_parent_air{false};
    std::string detail;

    bool operator==(
        const NormalizedRecursiveVerifierGap&) const = default;
};

/**
 * Exact capability audit for the smallest current parent-AIR candidate:
 * CoupledBankPages (endpoint 28), whose six-column/five-constraint child has
 * executable authenticated row openings, fold/DEEP equations and canonical
 * constraint bytecode in a bounded parent.
 *
 * This audit deliberately distinguishes those algebraic equations from
 * cryptographic recursive consumption. The current parent still lacks an
 * in-AIR all-proof-field bus, the child-proof commitment/CTL-terminal inputs
 * to its semantic-root sponge, and endpoint terminal equality. Child
 * Fiat-Shamir replay is consumed from the ledger's g4 assessor
 * (`AssessChildFsReplayClosureV1().closed` via
 * `fiat_shamir_replay_complete`); `va::kVerifierFiatShamirAirExecutable`
 * may remain false. It also records that EpisodeGemmSignedRange's sound
 * three-group Split-RAP proof has no MultiRow-V2 recursive verifier adapter.
 *
 * `valid` means the audit was reconstructed from the supplied checked
 * composition. It never means the endpoint was recursively consumed.
 */
struct NormalizedRecursiveChildCapabilityAuditV1 {
    uint16_t version{
        kNormalizedRecursiveChildCapabilityAuditVersion};
    RCStage3RelationRole candidate_role{
        RCStage3RelationRole::CoupledBank};
    RCStage3RelationEndpoint candidate_endpoint{
        RCStage3RelationEndpoint::CoupledBankPages};
    uint16_t candidate_role_endpoint_count{0};
    uint16_t candidate_endpoint_count{0};
    uint32_t child_relation_columns{0};
    uint32_t child_relation_constraints{0};
    uint32_t parent_rows{0};
    uint32_t parent_columns{0};
    uint32_t parent_constraints{0};
    uint32_t normalized_root_required_input_lanes{0};
    uint32_t normalized_root_available_input_lanes{0};
    uint32_t normalized_root_missing_input_lanes{0};
    uint32_t normalized_root_additional_permutation_columns{0};
    bool native_child_host_verified{false};
    bool authenticated_opening_air{false};
    bool fold_deep_air{false};
    bool relation_bytecode_air{false};
    bool child_trace_root_mapped{false};
    bool child_proof_payload_bound_in_air{false};
    bool child_fiat_shamir_replayed_in_air{false};
    bool child_proof_commitment_mapped{false};
    bool ctl_child_verified_in_parent_air{false};
    bool terminal_bus_commitment_mapped{false};
    bool normalized_semantic_root_derived_in_parent{false};
    bool split_rap_native_verifier_executable{false};
    bool split_rap_multirow_parent_adapter{false};
    bool endpoint_terminal_equality{false};
    uint16_t recursively_consumed_endpoints{0};
    uint16_t recursively_consumed_roles{0};
    std::vector<NormalizedRecursiveVerifierGap> gaps;
    bool recursive_consumption_complete{false};
    bool valid{false};
    std::string note;

    bool operator==(
        const NormalizedRecursiveChildCapabilityAuditV1&) const = default;
};

[[nodiscard]] NormalizedRecursiveChildCapabilityAuditV1
AssessNormalizedRecursiveChildCapabilityV1(
    const FoldBusComposition& composition,
    const BytecodeInterpreterAttachment& interpreter,
    const NormalizedCoupledBankRowPin& row_pin,
    const NormalizedCoupledBankTerminalExecution& execution);

/**
 * Rebuild and compare every field. Counter promotion, candidate substitution,
 * gap omission/reordering and invented chip availability all fail closed.
 */
[[nodiscard]] bool ValidateNormalizedRecursiveChildCapabilityV1(
    const FoldBusComposition& composition,
    const BytecodeInterpreterAttachment& interpreter,
    const NormalizedCoupledBankRowPin& row_pin,
    const NormalizedCoupledBankTerminalExecution& execution,
    const NormalizedRecursiveChildCapabilityAuditV1& audit,
    std::string* why = nullptr);

/**
 * Exact shape/capacity preflight for proving the normalized parent itself.
 * `minimum_*_row_value_bytes` count canonical Fp3 values only; Merkle paths,
 * folds and framing are intentionally excluded and therefore cannot be used
 * as an upper bound. `current_batch_lde_bytes` is the unavoidable returned
 * `column_lde` matrix of the current row-wise BatchCommit API.
 */
struct NormalizedParentProofPreflight {
    uint32_t trace_rows{0};
    uint32_t trace_columns{0};
    uint32_t constraints{0};
    uint32_t max_alg_degree{0};
    uint64_t max_composed_degree{0};
    uint32_t quotient_len{0};
    uint32_t composition_rows{0};
    uint32_t n_coeffs{0};
    uint32_t n_lde{0};
    uint32_t queries{0};
    uint64_t raw_trace_bytes{0};
    uint64_t minimum_batch_row_value_bytes{0};
    uint64_t minimum_next_row_value_bytes{0};
    uint64_t minimum_total_row_value_bytes{0};
    uint64_t codec_bytes_per_lane{0};
    uint64_t current_batch_lde_bytes{0};
    bool degree_supported{false};
    bool lde_supported{false};
    bool backend_columns_supported{false};
    bool batch_codec_lower_bound_supported{false};
    bool spill_audit_available{false};
    bool spill_audit_materializes_dense_lde{true};
    bool two_pass_row_commit_executable{false};
    bool bounded_row_streaming_byte_identical{false};
    bool external_store_quotient_prover{false};
    bool streamed_row_commit_callback{false};
    bool safe_to_execute_current_prover{false};
    bool valid{false};
    std::string missing_streaming_callback;
    std::string note;
};

[[nodiscard]] NormalizedParentProofPreflight
AssessNormalizedParentProofPreflight(
    const aq::AirConstraintSystem<Fp3>& parent_cs);

/**
 * Measured budget for joining arbitrary bytecode / per-point evaluation (and
 * the ledger's g4 P2 Fiat-Shamir closure) into a fold-bus / narrow node.
 *
 * The production narrow multi-child measurement is 575 V_CS columns × 32,768
 * rows. Bytecode attach adds a fixed BytecodeBusLayout column delta and needs
 * `queries * (instructions + 1)` free vertical rows. This assessor never flips
 * kCompleteRecursiveFixedPointExecutable: that still requires the chips to be
 * differentially joined and forgery-tested inside the parent AIR
 * (va::kVerifierFiatShamirAirExecutable may remain false).
 *
 * When a single 575-col node cannot absorb the pad (capacity_closed), the
 * hierarchical fields reuse narrow_recurse::PlanHierarchicalNarrowAggregation
 * over per-program row leaves so the attach path is NOT required to pad one
 * node past the LDE cap. hierarchical_attach_fits is shape arithmetic only.
 */
struct NarrowBytecodePerPointJoinBudgetV1 {
    uint32_t fold_bus_columns{0};
    uint32_t fold_bus_rows{0};
    uint32_t reserved_sponge_rows{0};
    uint32_t free_rows{0};
    uint32_t bytecode_added_columns{0};
    uint32_t projected_columns{0};
    uint32_t queries{0};
    uint64_t instructions{0};
    uint64_t rows_needed{0};
    uint64_t projected_trace_rows{0};
    uint32_t projected_max_algebraic_degree{0};
    uint64_t projected_quotient_len{0};
    uint64_t projected_coefficient_rows{0};
    uint64_t projected_lde{0};
    bool exact_quotient_degree_accounting{false};
    bool rows_fit_without_pad{false};
    bool projected_lde_supported{false};
    bool projected_columns_narrow{false};
    bool p2_fs_replay_closed{false};
    bool capacity_closed{false};
    /** Single-node pad refuses under AssessNarrowNodeFriShape (degree-aware). */
    bool single_node_fri_representable{false};
    /** Hierarchy from PlanNarrowBytecodeHierarchicalAttachV1 is valid. */
    bool hierarchical_attach_planned{false};
    /** Every planned node fits column/LDE caps (shape only). */
    bool hierarchical_attach_fits{false};
    uint32_t hierarchical_depth{0};
    uint32_t hierarchical_node_count{0};
    uint64_t hierarchical_single_level_rows{0};
    bool valid{false};
    std::string note;
};

/**
 * Hierarchical row-budget plan for hash-kernel / bytecode vertical attach.
 *
 * Each ProgramTable program is a leaf charged
 * `queries * (instructions + 1)` active rows (conservative vs the table-wide
 * `queries * (sum_insn + 1)` attach formula). Packing reuses
 * PlanHierarchicalNarrowAggregation + AssessNarrowNodeFriShape so a single
 * 575-col fold-bus node is not required to absorb an LDE-over-cap pad.
 *
 * Shape / schedule only — does not attach, prove, or flip CompleteFP /
 * AggregationReady / within_relay_budget.
 */
struct NarrowBytecodeHierarchicalAttachPlanV1 {
    bool valid{false};
    bool single_node_fits{false};
    bool hierarchical_fits{false};
    bool all_programs_covered{false};
    uint32_t program_count{0};
    uint32_t queries{0};
    uint64_t instructions{0};
    uint64_t total_leaf_rows{0};
    uint32_t node_count{0};
    uint32_t depth{0};
    nr::NarrowNodeFriShape single_node_shape;
    nr::NarrowHierarchicalAggregationPlan hierarchy;
    std::string note;
};

/** Count ProgramTable SSA instructions (sum of each program's instruction list). */
[[nodiscard]] uint64_t CountProgramTableInstructions(
    const constraint_bytecode::ProgramTable& table);

/**
 * Count fold-bus rows currently reserved as hash-opening current/next sponges
 * (the only rows AttachConstraintBytecodeInterpreter marks non-free).
 */
[[nodiscard]] uint32_t CountFoldBusReservedSpongeRows(
    const FoldBusComposition& composition);

[[nodiscard]] NarrowBytecodePerPointJoinBudgetV1
AssessNarrowBytecodePerPointJoinBudgetV1(
    const FoldBusComposition& composition,
    const constraint_bytecode::ProgramTable& table);

/**
 * Build per-program hierarchy leaves for bytecode vertical attach.
 * `active_rows = queries * (program.instructions.size() + 1)`.
 */
[[nodiscard]] std::vector<nr::NarrowHierarchyLeaf>
BuildNarrowBytecodeHierarchyLeaves(
    const constraint_bytecode::ProgramTable& table,
    uint32_t queries);

/**
 * Plan a hierarchical attach tree for a ProgramTable under the measured
 * narrow FRI/column caps. Reuses PlanHierarchicalNarrowAggregation.
 */
[[nodiscard]] NarrowBytecodeHierarchicalAttachPlanV1
PlanNarrowBytecodeHierarchicalAttachV1(
    const constraint_bytecode::ProgramTable& table,
    uint32_t queries,
    const nr::NarrowHierarchyPlanConfig& config = {});

/**
 * One executed node from ExecuteNarrowBytecodeHierarchicalAttachV1.
 * Level-1 nodes may carry a real AttachConstraintBytecodeInterpreter result
 * against a child_constraints-sliced fold-bus pad. Level ≥2 composed nodes
 * schedule child_node_indices + FRI shape; when `wire_l2_fri_consume` is
 * enabled they invoke ExecuteNarrowMultiChildL2FriConsumeV1 (stand-in
 * boolean children until real free-row L1 AirProofs are available).
 */
struct NarrowBytecodeHierarchicalAttachNodeResultV1 {
    uint32_t level{0};
    uint32_t node_index{0};
    std::string label;
    uint32_t program_count{0};
    uint32_t child_node_count{0};
    uint64_t instructions{0};
    uint64_t rows_needed{0};
    uint64_t active_rows{0};
    uint32_t trace_rows{0};
    uint32_t n_lde{0};
    bool shape_representable{false};
    bool pad_ok{false};
    bool attached{false};
    bool dual_logup_terminal{false};
    bool quotient_opening_equality{false};
    bool forgery_rejected{false};
    bool l2_fri_consume_invoked{false};
    bool l2_fri_consume_valid{false};
    uint32_t l2_fri_consume_arity{0};
    uint32_t violations{0};
    std::string note;
};

/**
 * AIR-mirror of the L2 local-q join identity.
 *
 * Trace: one power-of-two row domain; column 0 is the bound opening
 * (authenticated parent q when absolute, Σ local_q when relative); columns
 * 1..S carry shard openings. Everywhere residual Σ shards − bound == 0 is
 * proved/verified via AirQuotientProve/Verify. Forgery mutates one shard
 * limb and must fail exact division or verify.
 *
 * Does NOT flip CompleteFP / AggregationReady / within_relay_budget.
 */
struct NarrowBytecodeShardQuotientJoinAirMirrorV1 {
    bool valid{false};
    bool proved{false};
    bool verified{false};
    bool forgery_rejected{false};
    bool absolute_parent_bound{false};
    uint32_t queries{0};
    uint32_t shard_count{0};
    uint32_t n_rows{0};
    uint32_t n_columns{0};
    uint64_t verify_micros{0};
    std::string note;
};

/**
 * L2 cryptographic join of shard-local quotients toward the authenticated
 * parent AIR q opening.
 *
 * When free-row shards partition the full ProgramTable and each L1 uses
 * global rho^ordinal weights, Σ_s local_q_s(y) must equal the authenticated
 * child AIR quotient opening at each query. Relative partition closure
 * (Σ parts == union local_q) holds for any covered subset. When the host
 * join closes, AirMirrorNarrowBytecodeShardLocalQuotientsV1 AIR-proves the
 * same identity.
 *
 * Does NOT flip CompleteFP / AggregationReady / within_relay_budget.
 * Runtime complete_verifier_mirror on the hierarchical execution may become
 * true once absolute sum_eq is AIR-mirrored; SHA-FS transcript chip and
 * real free-row L1 AirProof children for hierarchical L2/L3 consume remain
 * separate toward AggregationReady.
 */
struct NarrowBytecodeShardQuotientJoinV1 {
    bool valid{false};
    bool parent_extracted{false};
    bool shards_extracted{false};
    bool covers_full_table{false};
    bool sum_equals_parent{false};
    bool partition_closed{false};
    bool forgery_rejected{false};
    bool air_mirrored{false};
    uint32_t queries{0};
    uint32_t shard_count{0};
    uint32_t programs_covered{0};
    uint32_t programs_total{0};
    std::vector<Fp3> parent_q_per_query;
    std::vector<Fp3> sum_local_q_per_query;
    NarrowBytecodeShardQuotientJoinAirMirrorV1 air_mirror;
    std::string note;
};

/**
 * Execute the hierarchical bytecode attach plan against a hash-kernel
 * fold-bus. FRI L1/L2/L3 shape is recorded from
 * PlanNarrowBytecodeHierarchicalAttachV1. Actual L1 attach packs programs
 * into free-row shards (pad-after-challenge is forbidden), subsets
 * child_constraints, and runs AttachConstraintBytecodeInterpreterShard
 * with local synthesized q + forgery rejects. When all L1 shards attach,
 * JoinNarrowBytecodeShardLocalQuotientsV1 binds Σ local_q to the parent
 * authenticated opening (absolute iff shards cover the full table) and
 * AIR-mirrors that identity. When `wire_l2_fri_consume` is set, every
 * composed node with arity ≥2 invokes ExecuteNarrowMultiChildL2FriConsumeV1
 * (stand-in boolean children; real free-row L1 AirProof children + SHA-FS
 * remain open toward AggregationReady / CompleteFP).
 *
 * Does NOT flip kCompleteRecursiveFixedPointExecutable /
 * kNarrowHierarchicalAggregationReady / within_relay_budget. Runtime
 * complete_verifier_mirror may become true after absolute AIR-mirrored join.
 */
struct NarrowBytecodeHierarchicalAttachExecutionV1 {
    bool valid{false};
    bool plan_valid{false};
    bool all_l1_attached{false};
    bool all_l1_forgeries_rejected{false};
    bool all_composed_scheduled{false};
    bool all_composed_l2_wired{false};
    bool all_nodes_representable{false};
    bool p2_fs_replay_closed{false};
    bool complete_verifier_mirror{false};
    uint32_t l1_count{0};
    uint32_t l1_attached{0};
    uint32_t composed_count{0};
    uint32_t composed_l2_wired{0};
    uint32_t composed_l2_arity_lt2{0};
    uint32_t depth{0};
    uint32_t node_count{0};
    NarrowBytecodeHierarchicalAttachPlanV1 plan;
    NarrowBytecodeShardQuotientJoinV1 quotient_join;
    std::vector<NarrowBytecodeHierarchicalAttachNodeResultV1> nodes;
    std::string note;
};

/**
 * Slice `table.programs` by hierarchy leaf indices (stable order).
 * Fails closed on out-of-range indices.
 */
[[nodiscard]] bool SliceProgramTableByLeafIndices(
    const constraint_bytecode::ProgramTable& table,
    const std::vector<uint32_t>& leaf_indices,
    constraint_bytecode::ProgramTable& out,
    std::string* why = nullptr);

/**
 * Copy `base`, subset child_constraints to `leaf_indices`. Fails closed if
 * the shard needs more free rows than the bound fold-bus already has
 * (pad-after-challenge is forbidden).
 */
[[nodiscard]] bool PrepareFoldBusForBytecodeShard(
    const FoldBusComposition& base,
    const constraint_bytecode::ProgramTable& full_table,
    const std::vector<uint32_t>& leaf_indices,
    const constraint_bytecode::ProgramTable& shard_table,
    FoldBusComposition& out,
    std::string* why = nullptr);

/**
 * Read authenticated child AIR quotient openings (item == current_width)
 * from the fold-bus hash-opening current-row sponges. One Fp3 per query.
 */
[[nodiscard]] bool ExtractAuthenticatedParentQuotientOpenings(
    const FoldBusComposition& base,
    uint32_t current_width,
    std::vector<Fp3>& out_per_query,
    std::string* why = nullptr);

/**
 * Read synthesized local q openings from an attached shard fold-bus
 * (BytecodeBusLayout Value(3) on Quotient rows), in query order.
 */
[[nodiscard]] bool ExtractShardLocalQuotientOpenings(
    const FoldBusComposition& shard_bus,
    std::vector<Fp3>& out_per_query,
    std::string* why = nullptr);

/**
 * AirQuotientProve/Verify of one attached fold-bus + bytecode shard
 * composition (the combined V_CS + witness columns), with a column-mutate
 * forgery reject. Uses the row-streaming prover seam so hash-kernel free-row
 * shapes (≈131k×640) stay under a MemoryMax cgroup.
 *
 * Does NOT flip CompleteFP / AggregationReady / within_relay_budget.
 */
struct NarrowBytecodeShardCompositionAirProveV1 {
    bool valid{false};
    bool attached{false};
    bool proved{false};
    bool verified{false};
    bool forgery_rejected{false};
    bool streaming{true};
    uint32_t n_rows{0};
    uint32_t n_columns{0};
    uint32_t n_constraints{0};
    uint32_t program_count{0};
    uint32_t shard_index{0};
    uint64_t prove_micros{0};
    uint64_t verify_micros{0};
    std::string note;
};

/**
 * AIR-prove/verify Σ_s shard_local_q[s][q] == bound_q[q] for every query,
 * with a drop/mutate forgery reject. `absolute_parent_bound` is recorded
 * into the result note only (does not change the residual).
 */
[[nodiscard]] NarrowBytecodeShardQuotientJoinAirMirrorV1
AirMirrorNarrowBytecodeShardLocalQuotientsV1(
    const std::vector<Fp3>& bound_q_per_query,
    const std::vector<std::vector<Fp3>>& shard_local_q,
    bool absolute_parent_bound);

/**
 * Prove/verify an already-attached fold-bus+bytecode composition via
 * AirQuotientProveRows / AirQuotientVerifyRows. Forgery mutates a live
 * bytecode value limb and must fail exact division (or verify).
 */
[[nodiscard]] NarrowBytecodeShardCompositionAirProveV1
AirProveNarrowBytecodeShardCompositionV1(
    const FoldBusComposition& attached_shard);

/**
 * Pack free-row L1 shards under the bound fold-bus, attach one shard, then
 * AirProve the composition. `shard_index == UINT32_MAX` (default) selects
 * the smallest pack bin by program count; otherwise the indexed bin.
 */
[[nodiscard]] NarrowBytecodeShardCompositionAirProveV1
ExecuteNarrowBytecodeOneFreeRowShardCompositionAirProveV1(
    const FoldBusComposition& base,
    const constraint_bytecode::ProgramTable& table,
    uint32_t shard_index = UINT32_MAX);

/**
 * Join shard-local quotients: Σ_s local_q_s == parent opening when the
 * shards cover `programs_total`, else report relative extraction only.
 * Forgery: omitting any single shard breaks equality with the full sum
 * (and with parent when covers_full_table). On host closure, runs the
 * AIR mirror against parent (absolute) or Σ local_q (relative).
 */
[[nodiscard]] NarrowBytecodeShardQuotientJoinV1
JoinNarrowBytecodeShardLocalQuotientsV1(
    const std::vector<Fp3>& parent_q_per_query,
    const std::vector<std::vector<Fp3>>& shard_local_q,
    uint32_t programs_covered,
    uint32_t programs_total);

/**
 * Execute hierarchical shard attach. When `attach_l1` is false, only the
 * FRI plan + free-row shard capacity + L2/L3 schedule are checked. When
 * true, each free-row shard is attached sequentially with forgery rejects
 * and the L2 local-q join is measured against the parent opening.
 *
 * When `wire_l2_fri_consume` is true, every composed node with arity ≥2
 * calls ExecuteNarrowMultiChildL2FriConsumeV1 (stand-in boolean children;
 * `l2_prove=false` is shape-only). Does NOT flip Ready / AggregationReady.
 */
[[nodiscard]] NarrowBytecodeHierarchicalAttachExecutionV1
ExecuteNarrowBytecodeHierarchicalAttachV1(
    const FoldBusComposition& base,
    const constraint_bytecode::ProgramTable& table,
    bool attach_l1 = true,
    bool wire_l2_fri_consume = false,
    bool l2_prove = false);

/**
 * Light measured join path: attach an explicit partition of leaf indices
 * (each group one shard) and join local qs. Intended for small subsets so
 * the absolute/relative join can be remasured without the full 462-program
 * hierarchical free-row pack.
 */
[[nodiscard]] NarrowBytecodeShardQuotientJoinV1
ExecuteNarrowBytecodeShardQuotientJoinV1(
    const FoldBusComposition& base,
    const constraint_bytecode::ProgramTable& table,
    const std::vector<std::vector<uint32_t>>& shard_leaf_groups);

/** Planner+executor exist; readiness owned by measured complete mirror. */
inline constexpr bool kNarrowBytecodeHierarchicalAttachExecutable = true;
inline constexpr bool kNarrowBytecodeHierarchicalAttachReady = false;
/** Local-q join helper exists; absolute parent binding measured per run. */
inline constexpr bool kNarrowBytecodeShardQuotientJoinExecutable = true;
inline constexpr bool kNarrowBytecodeShardQuotientJoinReady = false;
/** Streaming L1 shard composition prove exists; Ready parked until multi-child
 *  FRI consume + SHA-FS + relay/serialize pins all measure green. */
inline constexpr bool kNarrowBytecodeShardCompositionAirProveExecutable = true;
inline constexpr bool kNarrowBytecodeShardCompositionAirProveReady = false;

/**
 * L2 cryptographic multi-child FRI consume — distinct from host Σ local_q /
 * AIR-mirror of openings (JoinNarrowBytecodeShardLocalQuotientsV1).
 *
 * Packs arity ≥2 independent L1 AlgAirProofs into ONE narrow fold-bus via
 * BuildFoldBusCompositionMulti (zero column expansion; arity paid in rows),
 * assesses AssessNarrowNodeFriShape on the measured active schedule, then
 * AirQuotientProveRows / AirQuotientVerifyRows the L2 node. A tampered
 * child must fail native fold-bus acceptance before any L2 witness exists.
 *
 * Does NOT flip CompleteFP / AggregationReady / Ready. Measured verify /
 * serialize may feed CurrentRCStage3TwoLevelRootVerifyBudgetV1 pins when the
 * light canary remeasures green; Ready constants stay fail-closed.
 */
struct NarrowMultiChildL2FriConsumeV1 {
    bool valid{false};
    bool fri_shape_representable{false};
    bool fold_bus_built{false};
    bool proved{false};
    bool verified{false};
    bool forgery_rejected{false};
    uint32_t arity{0};
    uint32_t n_rows{0};
    uint32_t n_columns{0};
    uint32_t n_constraints{0};
    uint64_t active_rows{0};
    uint32_t n_lde{0};
    uint64_t prove_micros{0};
    uint64_t verify_micros{0};
    /** SerializeFri3AlgBatchProof size of the L2 family-root batch. */
    uint64_t serialize_batch_bytes{0};
    /** Batch + trace_commit + next_openings estimate (wire-ish total). */
    uint64_t serialize_root_bytes{0};
    bool verify_within_relay_budget{false};
    bool serialize_within_fri_budget{false};
    nr::NarrowNodeFriShape fri_shape;
    std::string note;
};

/**
 * Cryptographic L2 join of ≥2 child proofs under FRI shape.
 * `prove=false` measures fold-bus + FRI shape + forgery only (light).
 * `prove=true` additionally AirQuotientProve/Verify the L2 node.
 */
[[nodiscard]] NarrowMultiChildL2FriConsumeV1
ExecuteNarrowMultiChildL2FriConsumeV1(
    const std::vector<aq::AirConstraintSystem<Fp3>>& child_css,
    const std::vector<AlgAirProof>& children,
    const std::vector<uint256>& child_fs_seeds,
    bool prove = true);

/** Multi-child L2 FRI consume exists; Ready parked until hier wiring +
 *  SHA-FS + relay/serialize pins all measure green. */
inline constexpr bool kNarrowMultiChildL2FriConsumeExecutable = true;
inline constexpr bool kNarrowMultiChildL2FriConsumeReady = false;

/**
 * Expand the fold-bus trace with trailing free rows so a subsequent
 * AttachConstraintBytecodeInterpreter has `rows_needed` free slots. Fails
 * closed if the projected power-of-two height's LDE would exceed
 * kRCFriMaxLdeLog2 (honest capacity-close — does not invent headroom).
 * On LDE-over-cap refusal the why string records whether a hierarchical
 * ProgramTable attach plan fits under AssessNarrowNodeFriShape.
 */
[[nodiscard]] bool PadFoldBusFreeRowsForBytecode(
    FoldBusComposition& composition,
    uint64_t rows_needed,
    std::string* why = nullptr);

/**
 * Same as PadFoldBusFreeRowsForBytecode, but when the single-node pad would
 * exceed the LDE cap and `table` is supplied, annotate `why` with the
 * PlanNarrowBytecodeHierarchicalAttachV1 summary (still returns false —
 * hierarchical attach is a different tree, not an in-place pad).
 */
[[nodiscard]] bool PadFoldBusFreeRowsForBytecode(
    FoldBusComposition& composition,
    uint64_t rows_needed,
    const constraint_bytecode::ProgramTable* table,
    std::string* why = nullptr);

/**
 * Append one canonical constraint program to the same trace as the
 * proof-derived current/next row Merkle openings. Raw authenticated Fp limbs
 * are memory producers; Current/Next instructions consume their three limbs,
 * and SSA registers are linked through a dual rational-identity memory bus.
 * The ordered-table overload applies verifier-owned rho powers and the exact
 * Everywhere/Transition/First/Last selector polynomials, then constrains the
 * accumulated numerator to q(y)·(y^N-1), where q is item W of the same
 * authenticated current-row opening.
 *
 * This function fails closed if the existing trace has too few vertical rows.
 * It covers exactly the supplied program, not any remaining opaque callbacks.
 */
[[nodiscard]] BytecodeInterpreterAttachment
AttachConstraintBytecodeInterpreter(
    FoldBusComposition& composition,
    const constraint_bytecode::Program& program);

[[nodiscard]] BytecodeInterpreterAttachment
AttachConstraintBytecodeInterpreter(
    FoldBusComposition& composition,
    const constraint_bytecode::ProgramTable& table);

/**
 * Hierarchical L1 shard attach. `shard_global_ordinals[i]` is the full-table
 * constraint ordinal of `table.programs[i]` (used for rho^ordinal weights).
 * The authenticated full-child AIR quotient opening is NOT required to equal
 * the shard accumulator — L1 synthesizes a local q = accumulator/zh so the
 * interpreter + dual-logup close on the shard alone. Binding shard locals
 * into the parent quotient is the later L2/L3 crypto join.
 */
[[nodiscard]] BytecodeInterpreterAttachment
AttachConstraintBytecodeInterpreterShard(
    FoldBusComposition& composition,
    const constraint_bytecode::ProgramTable& table,
    const std::vector<uint32_t>& shard_global_ordinals);

/**
 * Join every authenticated fold even/odd leaf to the fold scalar equation.
 * Producer bus values are literal affine expressions of the hash leaf input
 * lanes. Two independent rational-identity lanes enforce address/value
 * multiset equality; receiver values are literal aliases of the scalar fold
 * operands. A streaming accumulator over the authenticated current-row
 * sponge limbs additionally constrains the initial dual-OOD DEEP identity
 * against the selected layer-zero fold leaf. This removes detached host
 * metadata for the fold family and for the initial DEEP boundary; arbitrary
 * child-constraint evaluation in the per-point family is still separate.
 */
[[nodiscard]] FoldBusComposition BuildFoldBusComposition(
    const aq::AirConstraintSystem<Fp3>& child_cs,
    const AlgAirProof& child,
    const uint256& child_fs_seed);

/**
 * ARITY-N narrow node: ONE V_CS, ONE witness and therefore ONE root proof over
 * `children.size()` independent child proofs, each with its own constraint
 * system and its own Fiat-Shamir seed.
 *
 * The column count is the SAME as for one child (the measured zero-expansion
 * property); arity is paid entirely in rows. Bus addresses are offset per child
 * so two children can never alias one another's fold tuples, and the fold /
 * chain multiset identities close once, globally, over the whole node.
 *
 * SCOPE, unchanged by arity: this is the same partial verifier mirror the
 * single-child path is. kCompleteRecursiveFixedPointExecutable stays false —
 * arbitrary per-point child-constraint evaluation and the SHA256d Fiat-Shamir
 * transcript chip are still not joined — so an accepted node does NOT by itself
 * imply the children's native verifiers accept.
 */
[[nodiscard]] FoldBusComposition BuildFoldBusCompositionMulti(
    const std::vector<aq::AirConstraintSystem<Fp3>>& child_css,
    const std::vector<AlgAirProof>& children,
    const std::vector<uint256>& child_fs_seeds);

/** Dual-Q128/V5 counterpart of BuildFoldBusComposition. */
[[nodiscard]] FoldBusComposition BuildDualV5FoldBusComposition(
    const aq::AirConstraintSystem<Fp3>& child_cs,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    uint32_t lane);

[[nodiscard]] FoldBusComposition BuildDualV5FoldBusCompositionAtBase(
    const aq::AirConstraintSystem<Fp3>& child_cs,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    uint32_t lane,
    uint32_t column_base);

inline constexpr bool kHashOpeningAirExecutable = true;
inline constexpr bool kFoldHashScalarMemoryBusExecutable = true;
inline constexpr bool kCompleteRecursiveFixedPointExecutable = false;
inline constexpr bool kRecursiveFixedPointConsensusAuthority = false;

static_assert(kHashOpeningAirExecutable);
static_assert(kFoldHashScalarMemoryBusExecutable);
static_assert(!kCompleteRecursiveFixedPointExecutable);
static_assert(!kRecursiveFixedPointConsensusAuthority);
static_assert(kNarrowBytecodeHierarchicalAttachExecutable);
static_assert(!kNarrowBytecodeHierarchicalAttachReady);
static_assert(kNarrowBytecodeShardQuotientJoinExecutable);
static_assert(!kNarrowBytecodeShardQuotientJoinReady);
static_assert(kNarrowBytecodeShardCompositionAirProveExecutable);
static_assert(!kNarrowBytecodeShardCompositionAirProveReady);
static_assert(kNarrowMultiChildL2FriConsumeExecutable);
static_assert(!kNarrowMultiChildL2FriConsumeReady);

} // namespace matmul::v4::rc::recursive_fixedpoint

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_RECURSIVE_FIXEDPOINT_H
