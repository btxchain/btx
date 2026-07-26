// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_RECURSIVE_PARENT_AIR_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_RECURSIVE_PARENT_AIR_H

#include <matmul/matmul_v4_rc_stage3_splitrap_ctl_coordinator.h>
#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::recursive_parent_air {

namespace aq = air_quotient;
namespace ah = alg_hash;
namespace gf = gkr_field;
namespace va = stage3_verifier_air;
namespace sc = splitrap_ctl;
namespace cb = constraint_bytecode;

inline constexpr uint16_t kNormalizedUniversalParentVersionV1 = 1;
inline constexpr uint32_t kNormalizedUniversalParentArityV1 = 4;

/**
 * Constant-width vertical sponge used by the normalized parent.
 *
 * Rate cells are witness columns. Only the exact active/terminal schedule and
 * four caller-authenticated digest lanes are preprocessed. Consequently the
 * digest authenticates the private payload without making the payload itself
 * verifier-owned preprocessing.
 */
struct AuthenticatedVerticalSpongeLayoutV1 {
    uint32_t field_base{0};
    uint32_t active{8};
    uint32_t terminal{9};
    uint32_t first{10};
    uint32_t expected_root_base{11};
    air_recurse::PermLayout permutation{15};

    explicit constexpr AuthenticatedVerticalSpongeLayoutV1(
        uint32_t start = 0)
        : field_base(start),
          active(start + alg_hash::kAlgHashRate),
          terminal(active + 1),
          first(terminal + 1),
          expected_root_base(first + 1),
          permutation{expected_root_base +
                      alg_hash::kAlgHashDigestLen}
    {
    }

    [[nodiscard]] constexpr uint32_t Field(uint32_t lane) const
    {
        return field_base + lane;
    }
    [[nodiscard]] constexpr uint32_t ExpectedRoot(uint32_t lane) const
    {
        return expected_root_base + lane;
    }
    [[nodiscard]] constexpr uint32_t End() const
    {
        return permutation.End();
    }
};

struct AuthenticatedVerticalSpongeAuditV1 {
    uint32_t payload_fields{0};
    uint32_t active_rows{0};
    uint32_t parent_rows{0};
    uint32_t added_columns{0};
    uint32_t added_constraints{0};
    uint256 expected_root{};
    bool payload_columns_are_private_witness{false};
    bool exact_10star_padding{false};
    bool active_schedule_preprocessed{false};
    bool output_root_preprocessed{false};
    bool every_payload_field_hashed_once{false};
    bool in_air_permutation_and_state_transition{false};
    bool valid{false};
    std::string note;

    bool operator==(const AuthenticatedVerticalSpongeAuditV1&) const =
        default;
};

/**
 * Four-slot terminal/receipt ABI used by every family-parent step.
 *
 * The layout is constant width: family proof size and shard inventory live
 * behind each child receipt root. Rows 0..3 are the ordered child slots;
 * remaining rows are canonical inactive continuation rows.
 */
struct Arity4FamilyReceiptLayoutV1 {
    static constexpr uint32_t kChildRootWords = 8;
    uint32_t slot_index{0};
    uint32_t active{1};
    uint32_t terminal1{2};
    uint32_t terminal2{3};
    uint32_t running1{4};
    uint32_t running2{5};
    uint32_t child_root_base{6};

    explicit constexpr Arity4FamilyReceiptLayoutV1(
        uint32_t start = 0)
        : slot_index(start),
          active(start + 1),
          terminal1(start + 2),
          terminal2(start + 3),
          running1(start + 4),
          running2(start + 5),
          child_root_base(start + 6)
    {
    }

    [[nodiscard]] constexpr uint32_t ChildRoot(
        uint32_t lane) const
    {
        return child_root_base + lane;
    }
    [[nodiscard]] constexpr uint32_t End() const
    {
        return child_root_base +
            kChildRootWords;
    }
};

/**
 * First executable normalized-parent construction for the MultiRow-V2
 * verifier relation.
 *
 * `program_fields` are the canonical ProgramTable AlgHash preimage. They are
 * witness-owned and committed by the caller-selected `program_key` in AIR.
 * The child proof is represented by a fixed field-native row ABI containing
 * CLAIMED[0..3], ACTIVE, KIND, ITEM and ACTIVE_LANES. Those cells are direct
 * aliases of the local verifier columns and are committed by
 * `receipt_payload_root` in AIR. The legacy 14-span byte transport has a
 * separate caller-pinned root; its byte-to-field conversion is deliberately
 * not claimed by this relation.
 *
 * This object deliberately does not call itself a recursive verifier. The
 * CLAIMED operands are mapped, but the EXPECTED operands are still populated
 * by host replay rather than by in-parent FRI/Merkle/DEEP/Fiat-Shamir chips.
 * The SHA Fiat-Shamir path is a schedule rather than an AIR. Those exact gates
 * remain false.
 */
struct NormalizedUniversalParentCandidateV1 {
    uint16_t version{kNormalizedUniversalParentVersionV1};
    uint32_t arity{kNormalizedUniversalParentArityV1};
    uint32_t child_index{0};
    uint32_t parent_rows{0};
    uint32_t parent_columns{0};
    uint32_t local_verifier_rows{0};
    uint32_t local_verifier_columns{0};
    uint32_t local_verifier_constraints{0};
    uint32_t receipt_cells{0};
    uint32_t program_cells{0};
    uint32_t proof_cells_authenticated{0};
    uint32_t proof_cells_required{0};
    uint32_t proof_cells_semantically_mapped{0};
    uint32_t program_cells_mapped{0};
    uint32_t public_root_lanes{0};
    uint256 program_key{};
    /** Field-native recursive proof ABI root. */
    uint256 receipt_payload_root{};
    /** Exact legacy/outer-boundary 14-span transport root. */
    uint256 outer_transport_root{};
    uint256 public_input_root{};
    AuthenticatedVerticalSpongeLayoutV1 program_sponge;
    AuthenticatedVerticalSpongeLayoutV1 receipt_sponge;
    Arity4FamilyReceiptLayoutV1 family_receipts;
    AuthenticatedVerticalSpongeAuditV1 program_sponge_audit;
    AuthenticatedVerticalSpongeAuditV1 receipt_sponge_audit;
    va::MultiRowV2SplitRapProgramV1 child_program;
    va::MultiRowV2SplitRapVerifierWitnessV1 local_verifier;
    sc::CoupledBankEqualityReceiptCellMapV1 receipt_map;
    aq::AirConstraintSystem<gf::Fp3> parent_cs;
    std::vector<std::vector<gf::Fp3>> parent_columns_witness;
    bool canonical_program_key_bound_in_air{false};
    bool private_receipt_payload_bound_in_air{false};
    bool field_native_receipt_abi{false};
    bool outer_transport_root_pinned{false};
    bool outer_transport_to_field_root_in_parent{false};
    bool registry_program_key_selected_by_caller{false};
    bool registry_program_interpreter_executes_in_parent{false};
    bool registry_program_result_bound_to_quotient_identity{false};
    bool public_inputs_and_roots_bound{false};
    bool proof_cell_columns_collision_free{false};
    bool complete_proof_cell_decoder_in_air{false};
    bool complete_proof_cell_equality_map{false};
    bool complete_splitrap_verifier_in_air{false};
    bool complete_sha_fiat_shamir_replay_in_air{false};
    bool host_preprocessed_replay_eliminated{false};
    bool one_child_parent_relation_executable{false};
    uint32_t active_family_receipt_slots{0};
    uint32_t padding_family_receipt_slots{0};
    bool four_family_receipt_slots_materialized{false};
    bool family_terminal_composition_executes{false};
    bool family_child_roots_publicly_pinned{false};
    bool family_child_roots_sourced_from_verifier_outputs{false};
    bool self_similar_arity4_shape{false};
    bool recursive_fixed_point{false};
    bool authority{false};
    std::vector<std::string> residuals;
    bool valid{false};
    std::string note;
};

/**
 * Caller/root-owned statement. None of these roots may be inferred from the
 * witness being proved.
 */
struct NormalizedUniversalParentPublicStatementV1 {
    uint16_t version{kNormalizedUniversalParentVersionV1};
    alg_hash::Digest selected_registry_program_key{};
    alg_hash::Digest child_field_abi_root{};
    uint256 outer_transport_root{};
    alg_hash::Digest universal_parent_statement_root{};
    uint256 public_seed{};
    bool field_abi_is_recursive_consensus_codec{false};
};

enum class FamilyVerifierOutputKindV1 : uint8_t {
    CurrentOpening = 1,
    NextOpening = 2,
    QuotientOpening = 3,
    QueryIndex = 4,
    EvaluationPoint = 5,
    NextEvaluationPoint = 6,
    FiatShamirChallenge = 7,
    ChildReceiptRootWord = 8,
};

struct FamilyVerifierOutputCellV1 {
    uint32_t slot{0};
    FamilyVerifierOutputKindV1 kind{
        FamilyVerifierOutputKindV1::CurrentOpening};
    uint32_t item{0};
    uint32_t coordinate{0};
    gf::Fp3 verifier_output{};
    gf::Fp3 consumer_input{};
};

/**
 * Smallest fixed-arity parent-side adapter between child-verifier outputs and
 * relation/interpreter inputs. The tagged verifier stream is authenticated by
 * a caller-selected AlgHash root in AIR; all three Fp3 coordinates are direct
 * equalities to the consumer stream. The four slot ids and tags are immutable
 * preprocessing.
 */
struct AuthenticatedFamilyVerifierOutputBusV1 {
    uint16_t version{kNormalizedUniversalParentVersionV1};
    uint32_t cells{0};
    uint32_t air_rows{0};
    uint32_t active_slots{0};
    uint32_t padding_slots{0};
    uint32_t source_base{0};
    uint32_t consumer_base{0};
    uint32_t active{0};
    AuthenticatedVerticalSpongeLayoutV1 source_sponge;
    AuthenticatedVerticalSpongeAuditV1 source_sponge_audit;
    ah::Digest source_root{};
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> witness;
    bool exact_four_slot_tags{false};
    bool source_root_caller_pinned_in_air{false};
    bool current_next_q_points_and_fs_mapped{false};
    bool every_fp3_coordinate_equal{false};
    bool same_parent_verifies_child_receipt{false};
    bool self_similar{false};
    bool authority{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] ah::Digest
ComputeFamilyVerifierOutputBusRootV1(
    const std::vector<FamilyVerifierOutputCellV1>& cells);

[[nodiscard]] AuthenticatedFamilyVerifierOutputBusV1
BuildAuthenticatedFamilyVerifierOutputBusV1(
    const std::vector<FamilyVerifierOutputCellV1>& cells,
    const ah::Digest& expected_source_root);

[[nodiscard]] bool
ValidateAuthenticatedFamilyVerifierOutputBusV1(
    const std::vector<FamilyVerifierOutputCellV1>& cells,
    const ah::Digest& expected_source_root,
    const AuthenticatedFamilyVerifierOutputBusV1& candidate,
    std::string* why = nullptr);

/**
 * One active-slot normalized parent backed by the executable V_CS verifier
 * chips. Slots 1..3 retain the exact same tagged ABI and use canonical zero
 * receipt padding.
 *
 * Merkle row/next/trace paths, every FRI fold path and equation, DEEP, and the
 * child quotient identity are constraints in `parent_cs`. The exported
 * current/next/q/query/x/x*omega/challenge/root stream is selected directly
 * from those same cells and authenticated by `output_bus_root`.
 *
 * The AIR challenge is the exact public scalar consumed by vcs.perpoint, but
 * its SHA256d derivation is not yet an in-parent chip. Consequently this
 * construction closes the receipt-output and Merkle/fold trust seam without
 * claiming complete recursive consensus authority.
 */
struct OneSlotNormalizedFriParentV1 {
    using AlgBackend =
        aq::AirFriBackendAlg<gf::Fp3>;
    using ChildProof =
        aq::AirQuotientProof<gf::Fp3, AlgBackend>;

    uint16_t version{kNormalizedUniversalParentVersionV1};
    uint32_t arity{kNormalizedUniversalParentArityV1};
    uint32_t active_slots{0};
    uint32_t padding_slots{0};
    uint32_t output_cells{0};
    uint32_t output_selector_columns{0};
    uint32_t vcs_columns{0};
    uint32_t parent_columns{0};
    uint32_t parent_rows{0};
    uint32_t exact_child_proof_bytes{0};
    uint64_t fiat_shamir_preimage_bytes{0};
    uint64_t fiat_shamir_preimage_codec_alias_bytes{0};
    ah::Digest output_bus_root{};
    uint256 exact_child_proof_commitment{};
    std::vector<unsigned char> child_proof_codec;
    std::vector<air_recurse::VerifierAirParentOutput>
        verified_outputs;
    std::vector<FamilyVerifierOutputCellV1> bus_cells;
    va::FiatShamirShaExecutionPlanV1
        fiat_shamir_sha_execution;
    air_recurse::AggregateWitness child_verifier;
    AuthenticatedVerticalSpongeLayoutV1 output_sponge;
    AuthenticatedVerticalSpongeAuditV1 output_sponge_audit;
    aq::AirConstraintSystem<gf::Fp3> parent_cs;
    std::vector<std::vector<gf::Fp3>> parent_witness;
    bool all_vcs_families_execute{false};
    bool merkle_fold_deep_quotient_same_parent{false};
    bool exact_four_slot_layout{false};
    bool output_bus_exclusively_from_vcs_cells{false};
    bool output_bus_authenticated_in_parent{false};
    bool exact_child_proof_codec_roundtrip{false};
    bool exact_child_proof_bytes_parsed_at_ingress{false};
    bool child_proof_bytes_owned_by_parent_air{false};
    bool sha_preimage_codec_alias_map_complete{false};
    bool fiat_shamir_value_consumed_in_parent{false};
    bool exact_sha_call_preimages_inventoried{false};
    bool fiat_shamir_sha_replayed_in_parent{false};
    bool invalid_child_witness_rejected_by_parent{false};
    bool same_parent_verifies_child_receipt{false};
    bool recursive_fixed_point{false};
    bool authority{false};
    uint32_t witness_violations{0};
    bool valid{false};
    std::string note;
};

/**
 * Canonical one-slot receipt codec.  It includes the byte-exact
 * Fri3AlgBatchProof followed by trace_commit and every supplemental
 * next-opening value/path.  Deserialization is bounded, rejects noncanonical
 * Goldilocks limbs and trailing bytes, and requires byte-identical
 * reserialization.
 */
[[nodiscard]] bool SerializeOneSlotNormalizedFriChildProofV1(
    const OneSlotNormalizedFriParentV1::ChildProof& proof,
    std::vector<unsigned char>& out,
    std::string* why = nullptr);

[[nodiscard]] bool DeserializeOneSlotNormalizedFriChildProofV1(
    const std::vector<unsigned char>& encoded,
    OneSlotNormalizedFriParentV1::ChildProof& out,
    std::string* why = nullptr);

[[nodiscard]] OneSlotNormalizedFriParentV1
BuildOneSlotNormalizedFriParentV1(
    const aq::AirConstraintSystem<gf::Fp3>& child_cs,
    const OneSlotNormalizedFriParentV1::ChildProof& child_proof,
    const uint256& child_fs_seed,
    const ah::Digest& expected_output_bus_root);

/** Fail-closed ingress that parses the exact canonical child receipt bytes. */
[[nodiscard]] OneSlotNormalizedFriParentV1
BuildOneSlotNormalizedFriParentFromBytesV1(
    const aq::AirConstraintSystem<gf::Fp3>& child_cs,
    const std::vector<unsigned char>& exact_child_proof_bytes,
    const uint256& child_fs_seed,
    const ah::Digest& expected_output_bus_root);

/** Reduced-shape global public-context lane count (io_nu.pub). */
inline constexpr uint32_t kFourSlotPubLanesV1 = 2;

/**
 * Consensus-fixed node context for the arity-4 statement decomposition
 * (soundness-bridge io_nu = (pub, nu, rho_nu, A_nu)). All fields are public and
 * verifier-computable, never prover-chosen:
 *  - level/index: the node position nu = (l, k); children are (l+1, 4k+j);
 *  - pub: the reduced global public context, threaded unchanged to every child
 *    (block-header binding, episode digest, schedule commitment, seed — here a
 *    fixed-lane stand-in at reduced shape);
 *  - parent_receipt_root: rho_nu, the node's own eight receipt-root lanes.
 * The link accumulator A is confined to the leaf/CTL layer (A == 0 here) per the
 * bridge's allowed design; the f4 fold is still rendered as a constraint.
 */
struct FourSlotNodeContextV1 {
    uint32_t level{0};
    uint32_t index{0};
    std::array<gf::Fp3, kFourSlotPubLanesV1> pub{};
    std::array<
        gf::Fp3,
        Arity4FamilyReceiptLayoutV1::kChildRootWords>
        parent_receipt_root{};
};

/**
 * Four-active-slot self-similar arity-4 parent (PR-89 rung-4 closure of the
 * terminal-lane and child-root sourcing seam).
 *
 * ONE parent AIR — the k=4 V_CS verifier — checks all four child proofs'
 * Merkle, fold, DEEP and quotient equations in-constraint (not host-side).
 * Each slot's eight terminal receipt-root lanes (four row-root limbs, four
 * trace-root limbs) are read from that in-parent verifier's OWN terminal
 * permutation cells, and they are the only source of the four family child
 * roots: for every slot the identity
 *   active_s * selector_row * (child_root_lane - verifier_terminal_lane) = 0
 * is a parent constraint.  No child root is host-pinned.
 *
 * This is the self-similar shape (one arity-4 parent recomputes four children's
 * roots) with a tamper-sensitive terminal bus.  It deliberately does NOT claim
 * the recursive fixed point or consensus authority: the parent's OWN FRI proof
 * is not produced here (construct + constraint-evaluate only), and the child
 * Fiat-Shamir transcript (gamma/alpha) is still supplied by seed rather than
 * replayed by an in-parent SHA chip (child_fiat_shamir_replay, owned
 * separately).  Those exact gates stay false.
 */
struct FourSlotSelfSimilarCtlParentV1 {
    using AlgBackend = aq::AirFriBackendAlg<gf::Fp3>;
    using ChildProof =
        aq::AirQuotientProof<gf::Fp3, AlgBackend>;

    uint16_t version{kNormalizedUniversalParentVersionV1};
    uint32_t arity{kNormalizedUniversalParentArityV1};
    uint32_t active_slots{0};
    uint32_t terminal_lanes_per_slot{0};
    uint32_t sourced_root_lanes{0};
    uint32_t parent_rows{0};
    uint32_t parent_columns{0};
    uint32_t vcs_columns{0};
    air_recurse::AggregateWitness child_verifier;
    aq::AirConstraintSystem<gf::Fp3> parent_cs;
    std::vector<std::vector<gf::Fp3>> parent_witness;
    AuthenticatedVerticalSpongeLayoutV1 statement_sponge;
    AuthenticatedVerticalSpongeAuditV1 statement_sponge_audit;
    // Binding AlgHash (Poseidon2 sponge) commitment to the four children's full
    // public-IO tuples: the parent statement. Recomputed from the sourced
    // terminal roots and the pinned child public inputs.
    ah::Digest computed_parent_statement{};
    bool all_four_children_verified_in_parent_air{false};
    bool merkle_fold_deep_quotient_same_parent{false};
    bool terminal_lanes_sourced_from_in_parent_verifier{false};
    bool four_child_roots_sourced_from_verifier_outputs{false};
    // In-circuit statement decomposition (soundness-bridge D3), rendered as:
    //  - D3b binding: per-child h_cj = AlgHash(tag_io(l+1,4k+j) || enc(io_cj))
    //    and h_nu = AlgHash(tag_io(nu) || enc(io_nu) || h_c0..h_c3); the parent
    //    statement is the collision-resistant compression of the ordered 4-tuple
    //    of FULL child public-IO tuples (not the terminal root digests alone),
    //    with fixed-length domain-tagged injective enc; and
    //  - D3c relational: (f1) pub threading, (f2) position affineness,
    //    (f4) link-accumulator folding.
    bool statement_decomposition_enforced_in_air{false};
    bool statement_bound_by_alg_hash_sponge{false};
    bool full_child_pubio_absorbed{false};
    bool public_context_threaded{false};
    bool position_threading_affine{false};
    bool link_accumulator_folded{false};
    bool parent_statement_equals_child_aggregation{false};
    uint32_t node_sponge_count{0};
    uint32_t child_pubio_lanes_absorbed{0};
    bool self_similar_arity4_shape{false};
    // Edge 1 — cross-module Fiat–Shamir seed ownership bus.  The four per-slot
    // binding digests h_cj are packed to their canonical SHA-preimage seed
    // images so the child transcript seed can be bound by equality to the
    // parent binding digest.  `child_fs_seed_bound_to_parent_binding_digest`
    // is true iff the supplied child_fs_seed equals slot 0's owned seed image
    // (0 byte violations) — i.e. the caller genuinely seeded the child
    // transcript from the parent's binding of the child statement.  It is a
    // byte-boundary equality at the module seam, NOT yet an in-parent_cs AIR
    // constraint, so it does not by itself gate parent validity.
    std::array<ah::Digest, 4> child_binding_digests{};
    std::array<va::FiatShamirSeedOwnershipBusV1, 4>
        child_seed_ownership_bus{};
    bool child_seed_ownership_bus_canonical{false};
    bool child_fs_seed_bound_to_parent_binding_digest{false};
    // Edge 1 (in-circuit promotion): kAlgHashDigestLen owned-seed limb columns
    // are bound by an EVERYWHERE AIR equality to slot 0's h_cj sponge digest
    // cells (child_layout[0].ExpectedRoot(k)), so the parent-owned seed's
    // Goldilocks-limb representation is pinned to the in-circuit binding digest
    // — a prover cannot present a seed image that differs from h_c0 without
    // violating a constraint.  `fs_seed_ownership_limb_base` is the first such
    // column (for tamper tests); the byte image is the injective canonical
    // Fri3AlgDigestToUint256 packing of these bound limbs.
    uint32_t fs_seed_ownership_limb_base{0};
    bool seed_ownership_bound_in_parent_cs{false};
    // g4 (child Fiat-Shamir replay) — decoder half, in-circuit.
    // For every slot the child's AIR-quotient challenge air_lambda is
    // RE-DERIVED in the parent's own constraints from the 24 airq_lambda
    // transcript-digest bytes via the fs_selection_air direct decoder
    // (word_j = Σ byte·256^i ; challenge = word0 + word1·X + word2·X^2), and
    // an EVERYWHERE equality binds that reconstructed challenge to the exact
    // air_lambda the in-parent verifier AIR consumes.  The 24 digest bytes are
    // pinned as preprocessed (public) columns.  A prover who presents a child
    // whose consumed air_lambda is not the recompose of those pinned digest
    // bytes violates a parent constraint (tamper-tested).
    // `child_air_challenge_value_column[s]` is slot s's reconstructed-challenge
    // column (the tamper-test handle).
    // NOTE: this is the DECODER half only.  The digest-bytes ← SHA256d(seed)
    // compression is NOT yet a parent constraint (it is the documented
    // "sha256d_fiat_shamir_compression_shards scheduled but not attached"
    // residual / GPU scale-up lane), so `child_fiat_shamir_replayed_in_parent`
    // below stays false: the full seed→challenge transcript is not replayed.
    bool child_air_challenge_reconstructed_in_parent_cs{false};
    std::array<uint32_t, 4> child_air_challenge_value_column{};
    // Deliberately-open gates. Kept false; see the struct documentation.
    bool child_fiat_shamir_replayed_in_parent{false};
    bool parent_own_fri_proof_produced{false};
    bool recursive_fixed_point{false};
    bool authority{false};
    uint32_t witness_violations{0};
    bool valid{false};
    std::string note;
};

/**
 * Build the four-active-slot self-similar parent over four child proofs of the
 * identical child constraint system.  `child_proofs` are consumed by the
 * in-parent V_CS verifier; every slot's terminal root lanes are sourced from
 * that verifier's own cells, and the parent's claimed statement
 * (`expected_parent_statement`, eight lanes) is constrained in-circuit to equal
 * the order-weighted aggregation of the four sourced child statements.
 *
 * Returns witness_violations==0 and the sourcing + decomposition flags true
 * only when all four children's proofs satisfy the in-parent verifier, each
 * family child root equals its in-parent terminal lane, AND the claimed parent
 * statement equals the in-circuit aggregation of those four child statements.
 * A parent whose statement is not that aggregation is rejected (violations>0).
 */
[[nodiscard]] FourSlotSelfSimilarCtlParentV1
BuildFourSlotSelfSimilarCtlParentV1(
    const aq::AirConstraintSystem<gf::Fp3>& child_cs,
    const std::array<
        FourSlotSelfSimilarCtlParentV1::ChildProof, 4>&
        child_proofs,
    const uint256& child_fs_seed,
    const FourSlotNodeContextV1& context,
    const ah::Digest& expected_parent_statement);

/**
 * Compute the correct binding parent statement h_nu — the AlgHash sponge digest
 * over the parent's own io tuple and the four children's full public-IO digests
 * — that an honest caller must pin. Builds the in-parent verifier once with a
 * zero claim and returns h_nu.
 */
[[nodiscard]] ah::Digest
ComputeFourSlotSelfSimilarParentStatementV1(
    const aq::AirConstraintSystem<gf::Fp3>& child_cs,
    const std::array<
        FourSlotSelfSimilarCtlParentV1::ChildProof, 4>&
        child_proofs,
    const uint256& child_fs_seed,
    const FourSlotNodeContextV1& context);

/**
 * g4 MECHANISM closure (one slot, one kind, reduced shape): the child's
 * airq_lambda Fiat-Shamir challenge re-derived through a REAL in-circuit SHA256d
 * compression whose OUTPUT constrains the digest bytes.
 *
 * BuildFourSlotSelfSimilarCtlParentV1 pins the 24 airq_lambda digest bytes as
 * preprocessed columns — so a coordinated (seed', digest', challenge') tamper
 * that keeps decoder+challenge self-consistent is NOT caught (the digest bytes
 * are a free public input).  This builder removes that freedom: it constructs
 * the canonical airq_lambda transcript preimage buf = tag ‖ seed ‖ len ‖ label
 * ‖ nroots ‖ trace_commit ‖ nextra ‖ shape, executes SHA256d(buf) inside a real
 * fixed-program vertical AIR (hash_air), and:
 *   - the 32-byte SHA output (`sha_output_byte_base`) is a CONSTRAINED OUTPUT of
 *     the SHA compression rounds, not a free column;
 *   - three challenge-limb columns are bound to the first 24 output bytes by the
 *     in-AIR FromChallengeBytes3 map (word_j = Σ byte·256^i basis recompose);
 *   - those limbs are bound by equality to the consumed air_lambda.
 * The whole thing is ONE AirConstraintSystem (`cs`/`columns`) on the SHA trace
 * domain; `CountWitnessViolationsOnH(cs, columns)` is 0 iff every SHA round, the
 * digest→challenge map, and the challenge→consumed bind all hold.  A coordinated
 * forgery (tamper the output digest cells OR the consumed challenge) violates a
 * constraint.  Reduced shape: one slot's airq_lambda; full 4×8 challenge-kind
 * coverage is the compute scale-up over the identical builder.
 */
struct ChildAirChallengeShaReplayV1 {
    bool valid{false};
    std::string note;
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    // Reduced-shape airq_lambda digest reconstructed in-CS; equals the child's
    // consumed air_lambda when the real transcript preimage is used.
    gf::Fp3 reconstructed_challenge{};
    gf::Fp3 consumed_air_lambda{};
    uint256 digest{};              // native SHA256d(buf) cross-check
    uint32_t sha_output_byte_base{0};   // first of 32 SHA-output byte columns
    std::array<uint32_t, 3> challenge_limb_columns{};
    uint32_t sha_semantic_compressions{0};  // SHA256d compression instances
    uint32_t sha_rows{0};               // CS trace-domain rows (compute size)
    uint32_t sha_columns{0};
    uint32_t witness_violations{0};     // over the FULL cs (SHA + binds)
    // True: the digest bytes the decoder consumes are SHA-compression OUTPUTS
    // (0 violations over the whole SHA cs), not a free preprocessed column.
    bool sha_output_binds_digest_bytes{false};
    bool challenge_bound_to_consumed{false};
};

/**
 * Build the reduced-shape airq_lambda SHA-replay CS for one child slot.  Uses
 * the exact `child_fs_seed`, `trace_commit`, and child AIR shape so the in-CS
 * SHA256d output equals the child's real airq_lambda digest, hence the
 * reconstructed challenge equals `consumed_air_lambda`.
 */
[[nodiscard]] ChildAirChallengeShaReplayV1
BuildChildAirChallengeShaReplayV1(
    const uint256& child_fs_seed,
    const uint256& trace_commit,
    uint32_t child_n_rows,
    uint32_t child_quotient_len,
    uint32_t child_w,
    const gf::Fp3& consumed_air_lambda);

/**
 * PR-89 rung-4: a recursion parent's OWN FRI proof.
 *
 * The Build*ParentV1 builders construct and constraint-evaluate a parent V_CS
 * (children verified in-constraint) but deliberately do NOT prove THEMSELVES, so
 * a built parent is not yet a recursion node.  This result carries the parent's
 * own batched FRI proof: AirQuotientProve<Fp3, AirFriBackendAlg<Fp3>> is run over
 * (parent_cs, parent_witness) — the same parent V_CS — and AirQuotientVerify
 * round-trips it.  `parent_own_fri_proof_produced` is the scoped closure flag:
 * true iff the parent's own quotient divided exactly, the FRI proof was emitted,
 * AND that proof verifies against parent_cs.
 *
 * Use a REDUCED-shape parent.  The full production/36GB parent prove is the
 * GPU-integration lane's concern and is NOT run here.  Producing this proof does
 * NOT by itself claim the recursive fixed point or consensus authority: closing
 * self_similar_fixed_point additionally requires the child Fiat-Shamir replay
 * (SHA-FS chip) lane, owned separately.
 *
 * COLUMN-CAP NOTE.  AirFriBackendAlg<Fp3> caps a batch at kRCFri3AlgBatchMaxColumns.
 * The arity-4 four-slot parent verifies four 192-query FRI children in-AIR; even
 * at the minimal (toy) child shape that V_CS is ~16996 columns wide.  PR-89
 * rung-4 raised the cap 2^14 -> 2^15 = 32768 (W is not a soundness parameter here;
 * see the constant's definition), so the full four-slot parent now FITS and
 * within_backend_column_cap is true.  Its ~17k-column self-prove is CPU-heavy
 * (tens of minutes); the reduced-arity one-slot parent (one active child + three
 * padding slots, ~4.2k columns) round-trips cheaply, and ProveParentOwnFriV1 over
 * a compact V_CS advances parent_own_fri_proof_produced quickly.  Full-shape
 * proving is the GPU-integration lane's concern.
 */
struct ParentOwnFriResultV1 {
    bool prove_ok{false};
    bool verify_ok{false};
    bool division_exact{false};
    // True iff the parent V_CS columns fit the AirFriBackendAlg column cap.
    bool within_backend_column_cap{false};
    // Scoped closure flag advanced by this lane: prove_ok && verify_ok.
    bool parent_own_fri_proof_produced{false};
    uint32_t parent_rows{0};
    uint32_t parent_columns{0};
    FourSlotSelfSimilarCtlParentV1::ChildProof proof;
    std::string note;
};

/**
 * Core: run AirQuotientProve<Fp3, AirFriBackendAlg<Fp3>> over an arbitrary
 * parent V_CS (cs / witness, column-major) and AirQuotientVerify the emitted
 * proof.  within_backend_column_cap records whether cs.n_columns fits the alg
 * batch cap; when it does not, prove_ok stays false with a "bad column count"
 * note (the four-slot residual).  Callers gate on the parent's own in-AIR
 * validity before calling this.
 */
[[nodiscard]] ParentOwnFriResultV1
ProveParentOwnFriV1(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& witness,
    const uint256& parent_fs_seed);

/**
 * Four-slot self-similar (arity-4) parent self-proof.  Only an honest, in-AIR
 * valid parent (parent.valid, witness_violations==0) is proven.  NOTE: at every
 * shape down to the toy child the four-slot V_CS exceeds the alg column cap, so
 * this returns parent_own_fri_proof_produced=false, within_backend_column_cap
 * =false — an executable record of the four-slot column-cap residual.
 */
[[nodiscard]] ParentOwnFriResultV1
ProveFourSlotSelfSimilarParentOwnFriV1(
    const FourSlotSelfSimilarCtlParentV1& parent,
    const uint256& parent_fs_seed);

/**
 * Reduced-arity (one active + three padding slots) normalized-FRI parent
 * self-proof.  This parent V_CS verifies one 192-query FRI child in-AIR and
 * fits the alg column cap, so it produces AND verifies its own FRI proof — the
 * reduced-shape recursion-node round-trip that advances
 * parent_own_fri_proof_produced.  Only an in-AIR-valid parent is proven.
 */
[[nodiscard]] ParentOwnFriResultV1
ProveOneSlotNormalizedFriParentOwnFriV1(
    const OneSlotNormalizedFriParentV1& parent,
    const uint256& parent_fs_seed);

enum class HeterogeneousChildProgramIdV1 : uint32_t {
    EpisodeVerifier = 1,
    ShaCompressionVerifier = 2,
};

/**
 * Canonical sum-type child envelope. `program_root` commits the exact
 * consensus-canonical constraint bytecode selected from `registry_root`;
 * proof/public-input roots are field-native commitments consumed by the
 * corresponding verifier arm.
 */
struct HeterogeneousChildEnvelopeV1 {
    uint16_t version{1};
    HeterogeneousChildProgramIdV1 program_id{
        HeterogeneousChildProgramIdV1::
            EpisodeVerifier};
    ah::Digest registry_root{};
    ah::Digest program_root{};
    ah::Digest proof_bytes_root{};
    ah::Digest public_inputs_root{};
};

struct HeterogeneousChildDispatchParentV1 {
    uint16_t version{1};
    uint32_t parent_rows{0};
    uint32_t parent_columns{0};
    uint32_t constraints{0};
    ah::Digest registry_root{};
    ah::Digest envelope_root{};
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    AuthenticatedVerticalSpongeLayoutV1
        registry_sponge;
    AuthenticatedVerticalSpongeAuditV1
        registry_sponge_audit;
    AuthenticatedVerticalSpongeLayoutV1
        envelope_sponge;
    AuthenticatedVerticalSpongeAuditV1
        envelope_sponge_audit;
    bool both_program_tables_canonical{false};
    bool registry_root_pinned_in_air{false};
    bool exact_two_program_ids{false};
    bool dispatch_selectors_boolean{false};
    bool dispatch_selector_one_hot{false};
    bool selected_program_root_equality_constrained{
        false};
    bool proof_and_public_roots_authenticated{false};
    bool selected_child_proof_verified_in_parent{false};
    bool sha_child_proof_verified_in_parent{false};
    bool same_parent_verifies_child_receipt{false};
    bool recursive_fixed_point{false};
    bool authority{false};
    uint32_t witness_violations{0};
    bool valid{false};
    std::string note;
};

[[nodiscard]] ah::Digest
ComputeHeterogeneousProgramRegistryRootV1(
    const cb::ProgramTable& episode_program,
    const cb::ProgramTable& sha_program);

[[nodiscard]] ah::Digest
ComputeHeterogeneousChildEnvelopeRootV1(
    const HeterogeneousChildEnvelopeV1& envelope);

[[nodiscard]] HeterogeneousChildDispatchParentV1
BuildHeterogeneousChildDispatchParentV1(
    const cb::ProgramTable& episode_program,
    const cb::ProgramTable& sha_program,
    const HeterogeneousChildEnvelopeV1& envelope,
    const ah::Digest& expected_registry_root,
    const ah::Digest& expected_envelope_root);

/** Compute the root the caller must place in the parent public statement. */
[[nodiscard]] ah::Digest
ComputeOneSlotNormalizedFriParentOutputRootV1(
    const aq::AirConstraintSystem<gf::Fp3>& child_cs,
    const OneSlotNormalizedFriParentV1::ChildProof& child_proof,
    const uint256& child_fs_seed);

[[nodiscard]] alg_hash::Digest
ComputeNormalizedUniversalChildFieldAbiRootV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    const sc::CoupledBankEqualityReceiptV1& receipt,
    const uint256& public_seed,
    uint32_t child_index,
    const cb::ProgramTable& selected_program);

[[nodiscard]] NormalizedUniversalParentCandidateV1
BuildNormalizedUniversalParentCandidateV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    const sc::CoupledBankEqualityReceiptV1& receipt,
    uint32_t child_index,
    const cb::ProgramTable& selected_parent_program,
    const NormalizedUniversalParentPublicStatementV1&
        public_statement);

[[nodiscard]] bool ValidateNormalizedUniversalParentCandidateV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    const sc::CoupledBankEqualityReceiptV1& receipt,
    uint32_t child_index,
    const cb::ProgramTable& selected_parent_program,
    const NormalizedUniversalParentPublicStatementV1&
        public_statement,
    const NormalizedUniversalParentCandidateV1& candidate,
    std::string* why = nullptr);

inline constexpr bool
    kNormalizedUniversalParentOneChildRelationExecutableV1 = true;
inline constexpr bool
    kNormalizedUniversalParentRecursiveFixedPointV1 = false;
inline constexpr bool
    kNormalizedUniversalParentAuthorityV1 = false;

static_assert(
    kNormalizedUniversalParentOneChildRelationExecutableV1);
static_assert(
    !kNormalizedUniversalParentRecursiveFixedPointV1);
static_assert(!kNormalizedUniversalParentAuthorityV1);

} // namespace matmul::v4::rc::recursive_parent_air

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_RECURSIVE_PARENT_AIR_H
