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
    // NOTE: `complete_sha_fiat_shamir_replay_in_air` was RETIRED from this
    // scaffold (project owner decision).  It could never be set -- `valid`
    // asserted its negation -- and this candidate explores the
    // normalized-universal axis (program registry / receipt ABI / transport
    // root), which is independent of child Fiat-Shamir replay.  g4's obligation
    // is now sourced from the four-slot self-similar parent, where the SHA
    // replay and the g4 CTL bus actually live: see
    // AssessChildFsReplayClosureV1.
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
    // Decoder half is always wired when the parent builds. Full seed→challenge
    // ownership additionally requires the in-parent P2 sponge replay + limb
    // bus (see child_fiat_shamir_replayed_in_parent).
    bool child_air_challenge_reconstructed_in_parent_cs{false};
    std::array<uint32_t, 4> child_air_challenge_value_column{};
    // First of the 24 digest-byte columns per slot (the free preprocessed bytes
    // the cross-domain CTL boundary reconciles against the SHA output).
    std::array<uint32_t, 4> child_air_challenge_byte_base{};
    // COMPUTED: true only when BuildFourSlotSelfSimilarCtlParentV1 hosts an
    // in-parent Poseidon2 airq_lambda replay plus limb-mode CTL bus for every
    // active slot (same CS as the recursion-carrying parent). Fail-closed
    // otherwise — standalone companion proofs do not set this.
    bool child_fiat_shamir_replayed_in_parent{false};
    uint32_t child_fs_p2_limb_bus_slots_hosted{0};
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
    // Epoch-R0 base columns of the vertical SHA AIR.  This CS carries
    // preprocessed ROW-GROUP roots, which the plain AirQuotientVerify refuses
    // ("preprocessed row-group roots require Split-RAP",
    // air_quotient.cpp:1623); it must be proved with
    // AirQuotientProveRowsSplitRap / AirQuotientVerifyRowsSplitRap over these
    // base indices.  Any g4 bus lane appended afterwards is deliberately NOT in
    // this list, so it lands in the SECOND (post-challenge) epoch -- which is
    // exactly where a LogUp/CTL auxiliary lane belongs.
    std::vector<uint32_t> base_column_indices;
    std::array<uint32_t, 3> challenge_limb_columns{};
    uint32_t sha_semantic_compressions{0};  // SHA256d compression instances
    uint32_t sha_rows{0};               // CS trace-domain rows (compute size)
    uint32_t sha_columns{0};
    uint32_t witness_violations{0};     // over the FULL cs (SHA + challenge bind)
    // True: the digest bytes the decoder consumes are SHA-compression OUTPUTS
    // (0 violations over the whole SHA cs), not a free preprocessed column.
    bool sha_output_binds_digest_bytes{false};
    bool challenge_bound_to_consumed{false};
    // NOTE: this struct carries NO cross-domain binding on its own.  The bus
    // that binds these SHA output bytes to the parent decoder's 24 digest bytes
    // is the g4 CTL lane below; it is appended to BOTH tables only after the
    // joint challenge is drawn (post-commitment), and reconciled by
    // VerifyChildFsShaBoundV1.
};

// ---------------------------------------------------------------------------
// g4 CS-domain CTL bus: companion-SHA output bytes <-> parent decoder digest
// bytes.
//
// Bus id / tuple tags, mirroring the tile-tree hash CTL idiom
// (matmul_v4_rc_stage3_tile_tree_hash_ctl.cpp): the compressed tuple is
//   T(k, v) = NS + gamma*STAGE + gamma^2*k + gamma^3*v
// so the namespace/stage tags domain-separate this bus from every other CTL on
// the same challenge, and gamma^2*k separates byte positions.
inline constexpr uint32_t kChildFsDigestBusIdV1 = 0x46533234U;      // "FS24"
inline constexpr uint32_t kChildFsDigestBusNamespaceV1 = 0x46534E31U; // "FSN1"
inline constexpr uint32_t kChildFsDigestBusStageV1 = 24;
/** Bytes carried on the bus: exactly the 24 FromChallengeBytes3 digest bytes. */
inline constexpr uint32_t kChildFsDigestBusBytesV1 = 24;

/**
 * One dual-lane LogUp bus endpoint appended to a host AIR constraint system.
 *
 * Layout (appended at the host's current n_columns):
 *   inverse1_base .. +23   INV lane 1, one per bus byte
 *   inverse2_base .. +23   INV lane 2
 *   running1, running2     per-lane running sums
 * Constraints (identical on both endpoints, built by the SAME function so the
 * producer and consumer relations are literally the same relation):
 *   kFirstRow   inv_l[k] * (alpha_l - T(k, byte[k], gamma_l)) - 1 = 0
 *   kTransition next[inv_l[k]] = 0                     (padding rows carry 0)
 *   kFirstRow   running_l = 0
 *   kTransition next[running_l] - (running_l + sum_k inv_l[k]) = 0
 *   kLastRow    running_l + sum_k inv_l[k] - terminal_l = 0
 * so `terminal_l` is pinned by the host AIR to sum_k 1/(alpha_l - T(k, byte[k],
 * gamma_l)) — a value that determines the byte vector (see the soundness note
 * on VerifyChildFsShaBoundV1).
 */
struct ChildFsDigestBusLaneV1 {
    bool valid{false};
    std::string note;
    uint32_t byte_base{0};
    uint32_t inverse1_base{0};
    uint32_t inverse2_base{0};
    uint32_t running1{0};
    uint32_t running2{0};
    uint32_t columns{0};
    RCStage3CtlTerminal terminal{};
};

/**
 * Append the g4 bus endpoint over `byte_base .. byte_base+23` to `cs`.
 *
 * When `columns` is non-null the honest witness is filled and the observed
 * terminal is returned in `out.terminal`; the kLastRow constraint pins the host
 * AIR to exactly that terminal.  When `columns` is null only constraints are
 * built (verifier-side AIR reconstruction), and `expected` supplies the pinned
 * terminal.
 */
[[nodiscard]] bool AppendChildFsDigestBusLaneV1(
    uint32_t byte_base,
    const RCStage3CtlChallenges& challenges,
    const RCStage3CtlTerminal* expected,
    aq::AirConstraintSystem<gf::Fp3>& cs,
    std::vector<std::vector<gf::Fp3>>* columns,
    ChildFsDigestBusLaneV1& out,
    std::string* why = nullptr);

/**
 * Draw the g4 bus joint challenge AFTER both byte windows are fixed.
 *
 * FS ORDERING IS LOAD-BEARING.  The 24 bus cells are unrange-checked field
 * elements, so a challenge known in advance lets a forger solve
 * sum_k 1/(alpha - T(k, B_p[k])) = C_sha directly for some B_p != B_s.  This
 * therefore absorbs BOTH 24-cell windows (`parent_bus_cells`, `sha_bus_cells`:
 * the row-0 cells the lane relation reads) -- the CTL idiom's "trace_commitment
 * absorbed before lookup challenges" -- along with a domain tag, the bus
 * namespace/stage tags, the slot index, the parent's binding statement
 * (alg-hash of the full child public IO) and the companion SHA CS's claimed
 * 32-byte digest.  Lane columns and terminals are produced after, so there is no
 * Fiat-Shamir fixed point.  Rejection-samples four Fp3 values with the CTL
 * acceptance rule (each limb word < p), requiring gamma1 != gamma2, alpha1 !=
 * alpha2, all nonzero.
 */
[[nodiscard]] bool DeriveChildFsDigestBusChallengesV1(
    const ah::Digest& parent_statement,
    const uint256& sha_digest,
    uint32_t slot,
    const std::vector<gf::Fp3>& parent_bus_cells,
    const std::vector<gf::Fp3>& sha_bus_cells,
    RCStage3CtlChallenges& out,
    std::string* why = nullptr);

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
 * PR-89 g4 ACTIVATION.  The SAME companion construction over an ARBITRARY
 * self-contained preimage.
 *
 * BuildChildAirChallengeShaReplayV1 is now a thin front end over this: it
 * assembles airq_lambda's 113 bytes and calls here.  Nothing about the SHA
 * manifest, the boundary instances, the digest-byte binding or the
 * challenge-limb reconstruction was airq_lambda-specific; only the preimage
 * was, and before the short-transcript lane was activated no OTHER kind had a
 * preimage short enough to assemble.
 *
 * `consumed_challenge` is the scalar the in-parent verifier consumes for this
 * draw, so `challenge_bound_to_consumed` means the same thing here as there.
 * For a kind whose consumed object is an INDEX rather than an Fp3 (fra3_query)
 * pass the draw's Fp3 value: the index is a constrained function of it, decoded
 * by the challenge table, and binding the Fp3 is the stronger of the two.
 */
[[nodiscard]] ChildAirChallengeShaReplayV1
BuildChildFsChallengeShaReplayFromPreimageV1(
    const std::vector<unsigned char>& preimage,
    const uint256& expected_digest,
    const gf::Fp3& consumed_challenge,
    const uint256& child_fs_seed);

/**
 * g4 two-table CTL boundary: the parent decoder's 24 airq_lambda digest bytes
 * are bound to the companion SHA CS's output bytes, IN parent verification.
 *
 * THE GAP THIS CLOSES.  BuildFourSlotSelfSimilarCtlParentV1 pins the 24
 * airq_lambda digest bytes as preprocessed columns and decodes them to
 * air_lambda (word recompose -> basis reconstruction -> equality with the
 * consumed challenge).  Nothing in parent_cs says those bytes are
 * SHA256d(transcript): the decoder only constrains their FIELD IMAGE.  A prover
 * who wants a chosen air_lambda* simply writes 24 cells whose recomposition is
 * air_lambda*; no hash inversion is needed.  That is the coordinated
 * Fiat-Shamir forgery.
 *
 * THE CONSTRUCTION.  Two AIRs, one relation.  The SAME lane builder
 * (AppendChildFsDigestBusLaneV1) is appended to BOTH tables over their
 * respective 24-byte windows:
 *   producer = companion SHA CS at `sha_output_byte_base` (bytes that the
 *              in-AIR SHA256d compression rounds CONSTRAIN to be the digest of
 *              the canonical transcript preimage);
 *   consumer = parent_cs at `child_air_challenge_byte_base[slot]` (the exact
 *              cells the decoder consumes).
 * Each endpoint's AIR pins a dual-lane LogUp terminal
 *   C_l = sum_{k<24} 1 / (alpha_l - (NS + gamma_l*STAGE + gamma_l^2*k
 *                                    + gamma_l^3*byte[k]))    for l in {1,2}.
 * (alpha_l, gamma_l) are drawn by Fiat-Shamir AFTER BOTH BYTE WINDOWS ARE FIXED
 * (DeriveChildFsDigestBusChallengesV1 absorbs both 24-cell windows, the parent
 * statement and the companion SHA digest), so the lanes are post-commitment
 * auxiliary columns and there is no FS fixed point.  This ordering is
 * load-bearing, not hygiene: the cells are unrange-checked field elements, so a
 * forger who saw alpha first could solve for a matching B_p outright.
 *
 * This verifier checks three obligations:
 *   (1) parent_cs + consumer lane satisfied  (CountWitnessViolationsOnH == 0);
 *   (2) companion SHA cs + producer lane satisfied                 (== 0);
 *   (3) terminals reconcile: C_1^cons == C_1^prod and C_2^cons == C_2^prod.
 *
 * SOUNDNESS.  Write B_p for the parent's 24 cells and B_s for the SHA output
 * cells.  Suppose B_p != B_s, i.e. B_p[k] != B_s[k] for some k.  Fix gamma and
 * view f(X) = sum_k [1/(X - T(k,B_p[k])) - 1/(X - T(k,B_s[k]))] as a rational
 * function of alpha.  Positions are distinct constants 0..23 and the tuple map
 * is v -> NS + gamma*STAGE + gamma^2*k + gamma^3*v, injective in (k,v) for any
 * gamma outside a set of size <= 3*24^2 (the vanishing set of the degree-<=3
 * polynomial gamma^2*(k-k') + gamma^3*(v-v') for each of the <= 24^2 colliding
 * pairs).  For an injective tuple map the pole at T(k,B_p[k]) appears on the
 * left and not on the right, so f is not identically zero; clearing
 * denominators gives a nonzero polynomial in alpha of degree < 48.  alpha is
 * drawn (in the ROM) after B_p and B_s are absorbed, so Pr[f(alpha) = 0] <=
 * 48 / p^3 ~ 2^-186 per lane, plus <= 3*576/p^3 for a bad gamma; a forger who
 * grinds q candidate B_p values gets an independent challenge each time, for
 * q * 48/p^3.  Two lanes are drawn.  Hence (3) forces B_p = B_s cell for cell,
 * and B_s is the SHA256d output of the canonical transcript preimage.  To steer
 * air_lambda the forger would now need a SHA256d preimage.
 *
 * The bus reads ROW 0 of each window, which suffices: the parent's decoder
 * constraints (word recompose, basis reconstruction, bound-to-consumed) are all
 * kEverywhere, so the full cells -> air_lambda chain already holds at row 0.
 *
 * WHAT IS *NOT* CLAIMED.  Obligations (1) and (2) are discharged here by
 * scanning the honest witness on H, which is what a FRI proof of each AIR would
 * establish; the parent's own FRI proof is not produced in this path
 * (parent_own_fri_proof_produced is false), so the argument holds at the
 * constraint-system level, not yet at the succinct-proof level.  Reduced shape:
 * one slot, one challenge kind (airq_lambda).  The 4-slot x 8-kind extension is
 * a compute scale-up over the identical builder.
 */
struct ChildFsShaBoundVerifyV1 {
    bool valid{false};
    std::string note;
    bool parent_cs_satisfied{false};
    bool sha_cs_satisfied{false};
    bool boundary_reconciled{false};
    RCStage3CtlChallenges challenges{};
    ChildFsDigestBusLaneV1 consumer_lane{};
    ChildFsDigestBusLaneV1 producer_lane{};
    uint32_t parent_violations{0};
    uint32_t sha_violations{0};
    // Terminal lane-1 sums, exposed for adversarial tests.
    gf::Fp3 c_parent{};
    gf::Fp3 c_sha{};
};

[[nodiscard]] ChildFsShaBoundVerifyV1
VerifyChildFsShaBoundV1(
    const FourSlotSelfSimilarCtlParentV1& parent,
    const ChildAirChallengeShaReplayV1& replay,
    uint32_t slot);

/**
 * SINGLE SOURCE OF TRUTH for gate g4 (child Fiat-Shamir replay closed).
 *
 * Both the global soundness ledger's `fiat_shamir_replay_complete` and the
 * recursive readiness assessment's `child_fiat_shamir_replay_closed` are meant
 * to answer the same question, and were each a hard-coded `false` literal in a
 * different file.  This assessment replaces both with ONE computed conjunction
 * over the obligations g4 actually has, so that (i) the residual is enumerable
 * rather than a bare constant, and (ii) the gate can only flip when every
 * obligation is independently discharged.
 *
 * It reports what is BUILT, not what is hoped for.  `closed` is false today and
 * must stay false until each member below is separately earned; the members are
 * deliberately NOT collapsed into a single editable boolean.
 *
 * This is a static coverage assessment, not a live execution: running the
 * construction costs ~4.6 minutes per (slot, kind).  The executable evidence
 * lives in the env-gated test
 * `four_slot_child_airq_lambda_sha256d_replayed_in_cs_and_coordinated_forgery_
 * rejected` (BTX_RUN_HEAVY_CHILD_FS_SHA=1) and in the fast
 * `g4_digest_bus_lane_verifier_side_reconstruction_pins_the_terminal`.
 */
/**
 * PR-89 g4: the POSEIDON2 companion CS -- the replacement for the vertical
 * SHA256d replay that owns 57.3 s of the 58.6 s producer-endpoint floor.
 *
 * WHY THIS IS THE LEVER.  The endpoint cost was PROFILED (see
 * AssessChildFsReplayClosureV1) at 16.166 s of companion-CS build plus
 * 41.149 s of Split-RAP prove over a 591 x 4096 CS.  Both halves are driven by
 * hash_air's vertical schedule, which charges 1024 rows PER COMPRESSION; the
 * airq_lambda preimage is 3 compressions, so next_pow2(3) * 1024 = 4096 rows is
 * that chip's floor and no transcript change can move it.  The Poseidon2 route
 * charges ONE ROW PER PERMUTATION and the same preimage is 5 permutations.
 *
 * TWO STRUCTURAL WINS, not one:
 *
 *  (1) ROWS.  4096 -> 5 semantic rows.  The table is still padded to a
 *      query-sound height (see below), but the work per row is one permutation
 *      instead of a 1024-row lane.
 *
 *  (2) THE DECODE DISAPPEARS.  The SHA companion must pin 24 digest-BYTE
 *      columns and recompose three 64-bit words from them.  AirChallengeDigestP2
 *      packs four CANONICAL Goldilocks lanes little-endian into the uint256, so
 *      bytes[0..8) is exactly lane0 and FromChallengeBytes3's `w0 % p` is the
 *      identity on it.  The challenge limbs ARE output lanes 0,1,2 -- three
 *      degree-1 pins, no byte columns, no recompose lanes at all.
 *
 * QUERY SOUNDNESS IS A HARD FLOOR ON THE HEIGHT, and it is why this builder
 * defaults to 1024 rows rather than the 8 the permutation count would allow.
 * n_lde = n_rows * kRCFriBlowup must admit the configured query count; at 8
 * rows n_lde = 128 < 192 queries and the shape is QUERY-DEGENERATE -- it would
 * prove fast and mean nothing.  The transcript lane measured and then
 * DISCARDED that 1.664 s figure for exactly this reason; do not resurrect it.
 *
 * NOT ACTIVATED.  aq::kAirChallengeP2Activated is false, so every shipped proof
 * still derives airq_lambda by SHA256d and BuildChildAirChallengeShaReplayV1
 * remains the companion on the live path.  This builder replays the Poseidon2
 * route so its cost is MEASURABLE before anyone decides to switch.
 *
 * ALIASING.  The absorbed lanes come from aq::AirChallengeP2Lanes, which splits
 * every u64 into two 32-bit halves precisely because FromU64(x) = x mod p makes
 * x and x + p the same field element -- naive four-u64 absorption lets two
 * DIFFERENT trace-commitment roots derive the SAME challenge.  This builder
 * absorbs that lane vector verbatim and pins it as preprocessed columns; it
 * must never re-encode it.
 */
struct ChildAirChallengeP2ReplayV1 {
    uint256 digest{};
    gf::Fp3 reconstructed_challenge{};
    gf::Fp3 consumed_air_lambda{};
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    uint32_t n_lanes{0};
    uint32_t permutations{0};
    uint32_t n_rows{0};
    uint32_t n_columns{0};
    uint32_t n_constraints{0};
    uint32_t max_alg_degree{0};
    uint32_t witness_violations{1};
    /** n_rows * kRCFriBlowup; must be >= the configured query count or the
     *  shape is query-degenerate and the prove figure is meaningless. */
    uint32_t n_lde{0};
    bool query_sound_shape{false};
    /** First of the 8 preprocessed absorbed-lane columns (the tamper handle:
     *  these are the preimage, and a prover must not be able to vary them). */
    uint32_t absorbed_lane_base{0};
    std::array<uint32_t, 3> challenge_limb_columns{};
    /** Absorb-carry + capacity-carry are real constraints, not an assumption. */
    bool sponge_chained_in_cs{false};
    bool output_binds_digest{false};
    bool challenge_bound_to_consumed{false};
    bool valid{false};
    std::string note;
};

/**
 * Build the Poseidon2 companion for one child's airq_lambda draw.
 *
 * `n_rows_floor` pads the table (default kChildAirChallengeP2QuerySoundRowsV1);
 * pass a smaller value ONLY to demonstrate the degenerate shape being rejected.
 * `forced_limb` (when not nullptr) overwrites the reconstructed-challenge
 * columns so a test can observe the constraints rejecting a forgery rather
 * than assume they would.
 */
[[nodiscard]] ChildAirChallengeP2ReplayV1
BuildChildAirChallengeP2ReplayV1(
    const uint256& child_fs_seed,
    const uint256& trace_commit,
    uint32_t child_n_rows,
    uint32_t child_quotient_len,
    uint32_t child_w,
    const gf::Fp3& consumed_air_lambda,
    uint32_t n_rows_floor = 0,
    const gf::Fp3* forced_limb = nullptr);

/**
 * Same Poseidon2 airq_lambda sponge as BuildChildAirChallengeP2ReplayV1, but
 * appended into an EXISTING same-row-domain parent CS (column-shifted layout).
 * Fail-closed when parent rows are not a power of two large enough for the
 * sponge schedule. This is the same-parent ownership primitive for g4
 * obligation 4 — standalone companions do not satisfy it.
 */
struct ChildAirChallengeP2ReplayHostedInParentV1 {
    bool ok{false};
    uint32_t poseidon_base{0};
    uint32_t absorbed_lane_base{0};
    std::array<uint32_t, 3> challenge_limb_columns{};
    uint32_t permutations{0};
    uint256 digest{};
    std::string note;
};

[[nodiscard]] bool AppendChildAirChallengeP2ReplayToParentV1(
    aq::AirConstraintSystem<gf::Fp3>& parent_cs,
    std::vector<std::vector<gf::Fp3>>& parent_columns,
    const uint256& child_fs_seed,
    const uint256& trace_commit,
    uint32_t child_n_rows,
    uint32_t child_quotient_len,
    uint32_t child_w,
    const gf::Fp3& consumed_air_lambda,
    ChildAirChallengeP2ReplayHostedInParentV1& out,
    std::string* why = nullptr);

/**
 * Host airq_lambda Poseidon2 replay + limb-mode CTL bus for all four slots
 * inside an already-built four-slot parent whose P2 decoder limbs are present
 * (`child_air_challenge_byte_base`). Mutates parent_cs / parent_witness.
 */
struct FourSlotChildFsP2LimbBusHostV1 {
    bool ok{false};
    uint32_t slots_hosted{0};
    std::array<ChildAirChallengeP2ReplayHostedInParentV1, 4> slot_replay{};
    std::array<bool, 4> slot_bus_reconciled{};
    std::string note;
};

[[nodiscard]] bool HostFourSlotChildFsP2LimbBusReplayInParentV1(
    FourSlotSelfSimilarCtlParentV1& parent,
    const uint256& child_fs_seed,
    const std::array<FourSlotSelfSimilarCtlParentV1::ChildProof, 4>&
        child_proofs,
    FourSlotChildFsP2LimbBusHostV1& out,
    std::string* why = nullptr);

/**
 * Generic Poseidon2 sponge companion over an arbitrary Fp-lane preimage.
 * Used by the coverage assessor for the seven FRI challenge kinds under
 * kRCFri3AlgP2SqueezeActivatedV1 (lanes = Fri3AlgP2SqueezeAbsorbLanes).
 * `digest_packed` must equal the three-limb packing the transcript replay
 * stores for that draw.
 */
[[nodiscard]] ChildAirChallengeP2ReplayV1
BuildChildFsChallengeP2ReplayFromLanesV1(
    const std::vector<gkr_field::Fp>& lanes,
    const uint256& digest_packed,
    const gf::Fp3& consumed_challenge,
    uint32_t n_rows_floor = 0,
    const gf::Fp3* forced_limb = nullptr);

/** Smallest height whose n_lde = rows * kRCFriBlowup admits 192 queries. */
inline constexpr uint32_t kChildAirChallengeP2QuerySoundRowsV1 = 1024;

// ---------------------------------------------------------------------------
// g4 CS-domain CTL bus, LIMB MODE -- the Poseidon2 companion's analogue of
// AppendChildFsDigestBusLaneV1 / VerifyChildFsShaBoundV1.
//
// THE INTERFACE MISMATCH THIS CLOSES.  AppendChildFsDigestBusLaneV1 binds a
// 24-BYTE window because both the SHA companion's output and the parent's
// pinned digest cells are byte columns.  ChildAirChallengeP2ReplayV1
// deliberately has none: AirChallengeDigestP2's four output lanes are already
// CANONICAL Goldilocks elements, so BuildChildAirChallengeP2ReplayV1 pins the
// reconstructed challenge directly as three limb columns
// (`challenge_limb_columns`) with no byte decomposition and no recompose
// lanes -- that is the whole of win (2) documented on that struct. Reusing
// the byte-mode bus would mean adding 24 boolean byte columns plus recompose
// back onto the P2 companion, giving back most of that win. This is the
// SAME dual-lane LogUp CTL idiom (T(k,v) = NS + gamma*STAGE + gamma^2*k +
// gamma^3*v, two independent lanes, challenge drawn AFTER both windows are
// fixed) over a 3-CELL window instead of 24, with its OWN namespace/stage tag
// so a byte-mode transcript can never be replayed as a limb-mode one or vice
// versa.
// ---------------------------------------------------------------------------
inline constexpr uint32_t kChildFsLimbBusNamespaceV1 = 0x46534E32U; // "FSN2"
inline constexpr uint32_t kChildFsLimbBusStageV1 = 3;
inline constexpr uint32_t kChildFsLimbBusCellsV1 = 3;

/** Same fields as ChildFsDigestBusLaneV1, over `limb_base .. limb_base+2`. */
struct ChildFsLimbBusLaneV1 {
    bool valid{false};
    std::string note;
    uint32_t limb_base{0};
    uint32_t inverse1_base{0};
    uint32_t inverse2_base{0};
    uint32_t running1{0};
    uint32_t running2{0};
    uint32_t columns{0};
    RCStage3CtlTerminal terminal{};
};

/** Append the 3-cell limb-mode lane over `limb_base .. limb_base+2` to `cs`.
 *  Semantics identical to AppendChildFsDigestBusLaneV1 with the window
 *  narrowed from 24 to kChildFsLimbBusCellsV1 and the tuple's NS/STAGE tags
 *  swapped to the limb-mode constants above. */
[[nodiscard]] bool AppendChildFsLimbBusLaneV1(
    uint32_t limb_base,
    const RCStage3CtlChallenges& challenges,
    const RCStage3CtlTerminal* expected,
    aq::AirConstraintSystem<gf::Fp3>& cs,
    std::vector<std::vector<gf::Fp3>>* columns,
    ChildFsLimbBusLaneV1& out,
    std::string* why = nullptr);

/** Draw the limb-mode bus's joint challenge AFTER both 3-cell windows are
 *  fixed -- same FS-ordering discipline and same absorb shape as
 *  DeriveChildFsDigestBusChallengesV1, over `p2_digest` and the two 3-cell
 *  windows rather than a SHA digest and two 24-byte windows. */
[[nodiscard]] bool DeriveChildFsLimbBusChallengesV1(
    const ah::Digest& parent_statement,
    const uint256& p2_digest,
    uint32_t slot,
    const std::vector<gf::Fp3>& parent_limb_cells,
    const std::vector<gf::Fp3>& p2_limb_cells,
    RCStage3CtlChallenges& out,
    std::string* why = nullptr);

/**
 * Minimal CONSUMER-side decoder for the Poseidon2 route: pins
 * AirChallengeDigestP2's three canonical output lanes as preprocessed
 * columns and binds them, by EVERYWHERE equality, to `consumed_challenge`.
 * No byte columns and no word recompose -- the P2 digest's lanes already ARE
 * the three limbs, so the decoder that would consume them is strictly
 * smaller than the SHA route's (24 preprocessed bytes + 3 recompose
 * equalities + 1 bound-to-consumed equality) collapsing to (3 preprocessed
 * limbs + 3 bound-to-consumed equalities).
 *
 * THIS IS NOT THE REAL PARENT.  BuildFourSlotSelfSimilarCtlParentV1's decoder
 * still consumes the SHA route (aq::AirChallengeDigest); wiring a P2-native
 * decoder into it is real activation work, gated on
 * aq::kAirChallengeP2Activated, and is not done by this builder. This is a
 * standalone constraint system that lets the limb-mode bus be exercised, and
 * its cost measured, against a decoder shaped exactly like the real one would
 * be if it consumed the P2 digest -- the interface, not the activation.
 *
 * `forced_consumed` (when not nullptr) overwrites the comparison target
 * fed to the bound-to-consumed equalities, independent of the digest-derived
 * preprocessed columns, so a test can observe a coordinated
 * (real digest, wrong consumed challenge) tamper being rejected.
 */
struct ChildFsChallengeP2DecoderV1 {
    bool valid{false};
    std::string note;
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    uint32_t limb_base{0};
    uint32_t witness_violations{1};
};

[[nodiscard]] ChildFsChallengeP2DecoderV1
BuildChildFsChallengeP2DecoderV1(
    const uint256& digest_p2,
    const gf::Fp3& consumed_challenge,
    const gf::Fp3* forced_consumed = nullptr);

/**
 * g4 P2-route two-table CTL boundary, mirroring VerifyChildFsShaBoundV1's
 * three obligations (decoder_cs_satisfied, p2_cs_satisfied,
 * boundary_reconciled) but with the byte-mode bus/lane types replaced by
 * their limb-mode counterparts and no `slot` (this is the single-endpoint
 * interface demonstration, not the four-slot parent). The soundness argument
 * is VerifyChildFsShaBoundV1's, verbatim, with "24 bytes" read as "3
 * canonical Fp3 lanes": for an injective tuple map (true off a vanishing set
 * of size <= 3*9 per lane, negligible in Goldilocks^3), a coordinated
 * (producer, consumer) mismatch on even one lane makes the two lanes' terminal
 * sums disagree except with probability <= O(1)/p^3 per lane, and two
 * independent lanes are drawn.
 */
struct ChildFsP2BoundVerifyV1 {
    bool valid{false};
    std::string note;
    bool decoder_cs_satisfied{false};
    bool p2_cs_satisfied{false};
    bool boundary_reconciled{false};
    RCStage3CtlChallenges challenges{};
    ChildFsLimbBusLaneV1 consumer_lane{};
    ChildFsLimbBusLaneV1 producer_lane{};
    uint32_t decoder_violations{0};
    uint32_t p2_violations{0};
};

[[nodiscard]] ChildFsP2BoundVerifyV1
VerifyChildFsP2BoundV1(
    const ChildFsChallengeP2DecoderV1& decoder,
    const ChildAirChallengeP2ReplayV1& p2);

/**
 * PR-89 g4, parent side: the eight child challenge KINDS the parent must
 * decode.  The ordinals are the ledger's coverage vector index; do not
 * renumber them without moving the ledger's per-kind evidence with them.
 */
enum class ChildFsChallengeKindV1 : uint32_t {
    AirqLambda = 0,  // aq::AirChallengeDigest, "airq_lambda"
    Fra3Lambda = 1,  // ProtocolBatchCoefficients, "fra3_lambda" idx 0
    Fra3Z1 = 2,      // Fri3AlgBatchSampleZ, "fra3_z", first ACCEPTED draw
    Fra3Z2 = 3,      // Fri3AlgBatchSampleZ, "fra3_z", second ACCEPTED draw
    Fra3W1 = 4,      // "fra3_w" idx 0
    Fra3W2 = 5,      // "fra3_w" idx 1
    Fra3Fold = 6,    // "fra3_fold" idx l, l < n_folds
    Fra3Query = 7,   // "fra3_query" idx q, q < query_count
};
inline constexpr uint32_t kChildFsChallengeKindCountV1 = 8;

/** One re-derived challenge draw of the child's Fiat-Shamir transcript. */
struct ChildFsChallengeDrawV1 {
    ChildFsChallengeKindV1 kind{ChildFsChallengeKindV1::AirqLambda};
    std::string label;
    uint32_t index{0};
    /** SHA256d(buf || label || LE32(index)), re-derived here. */
    uint256 digest{};
    /** |buf| + |suffix| at this draw. */
    uint64_t preimage_bytes{0};
    /** ceil((preimage_bytes + 9) / 64) first-pass + 1 second-pass. */
    uint64_t sha_compressions{0};
    gf::Fp3 value{};
    /** fra3_query only: the shipped V3 128-bit-modulo index rule. */
    uint32_t index_value{0};
    /** True iff a `fra3_z` draw was REJECTED by the OOD sampler (no ext coord
     *  or equal to z1).  Rejected draws consume a counter but carry no kind. */
    bool ood_rejected{false};
    /** The re-derivation agrees with the value the child's proof ships. */
    bool matches_protocol{false};
    /** PR-89 g4 ACTIVATION.  The EXACT bytes hashed for this draw, retained
     *  only for the FIRST draw of each kind so a companion hash CS can be
     *  BUILT from them rather than costed from a byte count.  Empty on every
     *  other draw: at 192 query draws this would otherwise be the largest
     *  object in the replay. */
    std::vector<unsigned char> preimage;
};

/**
 * INDEPENDENT re-derivation of a child's whole Fri3Alg Q192-V3 Fiat-Shamir
 * transcript from the child's PUBLIC proof data plus the parent-owned seed.
 *
 * This does not call fri_ext3_alg's transcript object; it rebuilds `buf` from
 * the documented absorb order and hashes it with plain SHA256d.  The point is
 * the cross-check: every re-derived value is compared against the value the
 * child's proof actually carries, so if the protocol transcript and this
 * replay are ever edited apart, `all_kinds_match` goes false while each half
 * still looks internally consistent.  That is the same divergence-detector
 * discipline as BuildAlgebraicQueryIndexAirV1 in fs_selection_air.
 *
 * ABSORB ORDER REPLAYED (matmul_v4_rc_fri_ext3_alg.cpp, Fri3AlgFs ctor +
 * Fri3AlgBatchFsInit + Fri3AlgBatchCommitConfigured):
 *   domain_tag | seed | LE64(nonce) | LE32(blowup) | LE32(n_coeffs)
 *   | LE32(version) | LE32(|column_len|)
 *   | SHORT-FS ACTIVE: Fri3AlgShapeCommit(n_coeffs, column_len)(32)
 *     otherwise:       LE32(column_len[i])...
 *   | row_commit.root(32)
 *   -> draw fra3_lambda(0) ; absorb lambda
 *   -> draw fra3_z(ctr++) until accepted -> z1 ; continue -> z2
 *      absorb z1, absorb z2
 *   -> SHORT-FS ACTIVE: absorb Fri3AlgOodEvalCommit(z1,z2,e1,e2)(32)
 *      otherwise:       absorb evals_z1[i], evals_z2[i] interleaved, i < W
 *   -> draw fra3_w(0) -> w1, fra3_w(1) -> w2 ; absorb w1, absorb w2
 *   -> for fold in [0, n_folds]: absorb fold_layers[fold].root ;
 *      if fold < n_folds: draw fra3_fold(fold) (the beta is NOT absorbed)
 *   -> for q < query_count: draw fra3_query(q)  (nothing further absorbed)
 * airq_lambda is drawn OUTSIDE this transcript, from aq::AirChallengeDigest's
 * own self-contained 113-byte preimage.
 *
 * SCOPE.  Only the ACTIVE single-lane Q192 config is replayed:
 * uniform_challenges = false, independent_batching_coefficients = false,
 * joint_query = false.  A proof whose `version` is not
 * kRCFri3AlgActiveBatchProofVersion is refused rather than mis-replayed --
 * which is what stops a legacy-layout proof from being replayed under the
 * short-transcript absorb order and silently producing different challenges.
 */
struct ChildFsTranscriptReplayV1 {
    bool valid{false};
    uint32_t child_w{0};        // batch columns = |column_len|
    uint32_t n_coeffs{0};
    uint32_t n_lde{0};
    uint32_t n_folds{0};
    uint32_t queries{0};
    /** |buf| once the last fold root is absorbed -- the state every query
     *  index is drawn from, and the object a companion hash CS would have to
     *  reproduce. */
    uint64_t transcript_bytes_at_terminal{0};
    std::vector<ChildFsChallengeDrawV1> draws;
    std::array<uint32_t, kChildFsChallengeKindCountV1> kind_draw_count{};
    std::array<bool, kChildFsChallengeKindCountV1> kind_matches_protocol{};
    /** Every draw of every kind re-derived to the shipped value. */
    bool all_kinds_match{false};
    /** COMPUTED cost of replaying the whole transcript in a vertical SHA AIR,
     *  one compression per instance, 1024 rows per compression. */
    uint64_t total_sha_compressions{0};
    /** Same, when the shared transcript prefix is compressed once and each
     *  draw only pays its own divergent tail (the midstate fork the chip is
     *  known to support). */
    uint64_t forked_sha_compressions{0};
    uint64_t total_sha_rows{0};
    uint64_t forked_sha_rows{0};
    std::string note;
};

[[nodiscard]] ChildFsTranscriptReplayV1 ReplayChildFsTranscriptV1(
    const uint256& child_fs_seed,
    const FourSlotSelfSimilarCtlParentV1::ChildProof& child_proof,
    const air_recurse::ChildPublicInputs& pi);

/**
 * Per-kind evidence for the g4 coverage obligation, recomputed from a built
 * decoder table rather than asserted.
 *
 * THE THREE LEVELS ARE NOT THE SAME CLAIM and are deliberately not collapsed:
 *
 *  decoded_in_air[k]        a row of the parent-side decoder table decodes
 *                           kind k from 24 PINNED transcript bytes through the
 *                           FromChallengeBytes3 relation, the result is bound
 *                           by an EVERYWHERE equality to the scalar the
 *                           in-parent verifier consumes, the table has zero
 *                           violations, AND tampering that row's challenge
 *                           column produces violations > 0.
 *  transcript_replayed[k]   the pinned bytes were re-derived from the child's
 *                           transcript by ReplayChildFsTranscriptV1 and agreed
 *                           with the value the child's proof ships.
 *  transcript_bound_in_air[k]
 *                           the pinned bytes ARE a constrained output of an
 *                           in-AIR hash: kind k's preimage is self-contained
 *                           (MEASURED width-independent across two child
 *                           widths), its companion vertical SHA AIR fits
 *                           inside ONE constraint system, AND that companion
 *                           CS has been BUILT over the kind's real preimage
 *                           with zero violations and its output bound to the
 *                           consumed scalar.
 *
 *                           The third conjunct was added at ACTIVATION and is
 *                           strictly fail-closed: before it, this counter
 *                           measured AFFORDABILITY, and activating the
 *                           short-transcript lane would have moved it 1 -> 8
 *                           without a single new companion being built.  That
 *                           is precisely the "flipped rather than earned" jump
 *                           the test below was written to catch, so the
 *                           predicate was tightened rather than the test
 *                           relaxed.
 *
 * Only the third can make the bytes unforgeable in-circuit, and it is
 * deliberately COMPUTED from two measurements rather than written down as "the
 * airq_lambda one".  Its two conjuncts are:
 *
 *   (i)  width independence.  The replay is run on two children of DIFFERENT
 *        width and kind k's preimage length compared.  Every draw that reads
 *        the accumulated FRI transcript inherits the 4*W column_len block and
 *        the 48*W OOD evaluation block, so it moves; airq_lambda's
 *        AirChallengeDigest preimage is a fresh 113 bytes and does not.
 *   (ii) chip capacity.  hash_air pins lane_rows = 1024 and caps a vertical
 *        schedule at kFixedProgramVerticalSemanticInstances = 63 PER
 *        CONSTRAINT SYSTEM, so a companion that needs more than
 *        kAffordableCompanionShaRowsV1 rows cannot be built as one CS.
 *
 * A kind passing both is one whose transcript bytes this construction could
 * own.  It is NOT a claim that the companion CS has been built for that kind:
 * today exactly one has (BuildChildAirChallengeShaReplayV1 for airq_lambda,
 * reconciled through the g4 CTL bus).  Because the coverage conjunction
 * requires this counter at 8 and it measures 1, the direction of any residual
 * imprecision is fail-closed.
 *
 * A THIRD SCOPING CAVEAT, recorded because it is easy to read past.  The
 * decoder table is its OWN constraint system.  It is not appended to
 * parent_cs, and no CTL lane yet ties its 24 byte cells to the four-slot
 * parent's decoder windows the way VerifyChildFsShaBoundV1 ties the airq_lambda
 * companion.  So `decoded_in_air` means "the parent-side decoder relation for
 * kind k exists, is satisfied on H, and rejects a tamper on the value the
 * in-parent verifier consumes" -- NOT "the proven four-slot parent_cs contains
 * it".  Fusing them is the natural next step and is a BUS problem, not a new
 * construction: AppendChildFsDigestBusLaneV1 is kind-agnostic (it binds a
 * 24-byte window) and cost +50 columns on a 17,108-column parent and the same
 * +50 on the 384,984-column real one.  Until that fusion lands, read this
 * counter as covering the DECODER obligation, with the parent-fusion and
 * transcript-provenance obligations tracked separately.
 */
/** next_pow2(63 + 1) * 1024: the largest vertical SHA schedule that fits one
 *  constraint system, from hash_air's own structural cap. */
inline constexpr uint64_t kAffordableCompanionShaRowsV1 = 65536;

struct ChildFsChallengeDecoderCoverageV1 {
    std::array<bool, kChildFsChallengeKindCountV1> decoded_in_air{};
    std::array<bool, kChildFsChallengeKindCountV1> transcript_replayed{};
    std::array<bool, kChildFsChallengeKindCountV1>
        transcript_bound_in_air{};
    std::array<bool, kChildFsChallengeKindCountV1> tamper_rejected{};
    /** MEASURED across two child widths, not asserted. */
    std::array<bool, kChildFsChallengeKindCountV1>
        preimage_width_independent{};
    /** Longest preimage of any draw of this kind, at each probe width. */
    std::array<uint64_t, kChildFsChallengeKindCountV1> preimage_bytes_a{};
    std::array<uint64_t, kChildFsChallengeKindCountV1> preimage_bytes_b{};
    /** Vertical SHA rows one draw of this kind would cost. */
    std::array<uint64_t, kChildFsChallengeKindCountV1> companion_sha_rows{};
    /** PR-89 g4 ACTIVATION.  A companion hash CS for kind k was actually
     *  BUILT over that kind's real preimage, has ZERO witness violations, its
     *  in-CS hash output equals the digest the transcript replay derived, and
     *  its reconstructed challenge limbs are bound to the scalar the in-parent
     *  verifier consumes.  This is the conjunct that separates "the transcript
     *  bytes COULD be owned in-AIR" from "they ARE". */
    std::array<bool, kChildFsChallengeKindCountV1> companion_cs_built{};
    std::array<uint32_t, kChildFsChallengeKindCountV1>
        companion_cs_columns{};
    std::array<uint32_t, kChildFsChallengeKindCountV1> companion_cs_rows{};
    uint32_t probe_child_w_a{0};
    uint32_t probe_child_w_b{0};
    uint32_t kinds_decoded{0};
    uint32_t kinds_replayed{0};
    uint32_t kinds_companion_built{0};
    uint32_t kinds_transcript_bound{0};
    uint32_t table_rows{0};
    uint32_t table_columns{0};
    uint32_t table_constraints{0};
    uint32_t table_max_alg_degree{0};
    uint32_t table_violations{1};
    uint32_t draws_decoded{0};
    /** The child shape the evidence was taken at (toy today). */
    uint32_t child_w{0};
    uint32_t child_n_rows{0};
    bool valid{false};
    std::string note;
};

/**
 * Build a real toy child proof, replay its transcript, build the row-wise
 * decoder table over EVERY draw of all eight kinds bound to the public inputs
 * the in-parent verifier consumes, and report per-kind evidence.
 *
 * Cached in a function-local static: the g4 ledger calls this on every
 * assessment and the ledger is read by several suites.
 */
[[nodiscard]] const ChildFsChallengeDecoderCoverageV1&
AssessChildFsChallengeDecoderCoverageV1();

/**
 * Production evidence for `challenge_kinds_transcript_bound`.
 *
 * Distinct from AssessChildFsChallengeDecoderCoverageV1's per-kind
 * `kinds_transcript_bound`, which builds ONE representative companion per
 * kind.  g4 requires ownership of EVERY draw (all folds and all Q192 query
 * challenges).  This assessor therefore:
 *
 *   (1) commits a real V10/Q192/K=2 Fri3Alg toy proof;
 *   (2) rebuilds the proof-owned full event-prefix schedule via
 *       BuildProofOwnedTranscriptBindingV10;
 *   (3) builds the row-multiplexed stage3_p2_transcript_air over that
 *       complete schedule and requires local_air_complete (every event
 *       challenge + every query index constrained, zero violations);
 *   (4) counts the seven FRI challenge kinds only when the full event list
 *       for that kind is present in the canonical manifest; and
 *   (5) counts airq_lambda separately (intentionally absent from the FRI
 *       transcript AIR) when a Poseidon2 airq_lambda companion binds the
 *       real single draw — one draw IS full instance coverage for that kind.
 *
 * Fail-closed unless aq::kAirChallengeP2Activated && active P2 squeeze.
 * Cached; do not copy cov.kinds_transcript_bound into the production
 * counter.
 */
struct ChildFsFullEventP2TranscriptOwnershipV1 {
    bool fri_full_event_air_owned{false};
    bool airq_lambda_owned{false};
    bool binding_valid{false};
    bool air_local_complete{false};
    uint32_t event_count{0};
    uint32_t query_events{0};
    uint32_t fold_events{0};
    uint32_t fri_kinds_owned{0};
    uint32_t kinds_transcript_bound{0};
    uint32_t air_rows{0};
    uint32_t air_columns{0};
    uint32_t air_violations{1};
    std::array<bool, kChildFsChallengeKindCountV1> kind_owned{};
    bool valid{false};
    std::string note;
};

[[nodiscard]] const ChildFsFullEventP2TranscriptOwnershipV1&
AssessChildFsFullEventP2TranscriptOwnershipV1();

struct ChildFsReplayClosureV1 {
    // --- Obligation 1: the cross-domain bus exists and is adversarially sound.
    bool bus_constructed{false};
    bool bus_rejects_coordinated_forgery{false};
    // --- Obligation 2: COVERAGE.  g4 means every challenge of every child.
    //
    // WHAT MOVED, and what did not.  The parent now DECODES all eight kinds:
    // ReplayChildFsTranscriptV1 re-derives the child's whole Q192-V3 transcript
    // independently and BuildChallengeTableAirV1 decodes every draw in one
    // row-per-draw AIR bound to the scalars the in-parent verifier consumes.
    // MEASURED at the toy child shape (batch W=2, n_coeffs=2, n_lde=32,
    // n_folds=1, 192 queries): 199 draws, table 256 rows x 102 columns, 81
    // constraints, max alg degree 7, zero violations, and a per-kind tamper
    // rejected for all eight.  The decode is WIDTH-INDEPENDENT: the draw count
    // is 6 + n_folds + query_count (+ any rejected OOD re-draws) and never
    // reads W -- MEASURED 6 + 1 + 192 = 199 draws.  That is why one table
    // replaces the ~80k columns that one constraint system per draw would
    // need, and why the table's 102 columns do not move with the child.
    //
    // WHAT DID NOT MOVE is the other counter, and the reason is unchanged from
    // the analysis below: decoding a kind does not OWN its transcript bytes.
    // For seven of eight kinds those 24 bytes are still pinned public cells.
    // MEASURED width probe (batch W=2 vs W=4): airq_lambda's preimage stays at
    // 113 bytes; every FRI-transcript kind's preimage moves with W, because it
    // is the accumulated buffer carrying the two terms enumerated next.  The
    // whole toy transcript costs 1571 SHA compressions to replay naively and
    // 234 with the shared-midstate fork -- and that is at W=2.
    //
    // WHY THE SECOND COUNTER DOES NOT CLOSE BY MECHANICAL EXTENSION (measured).
    // The bus is kind-agnostic -- it binds a 24-byte window -- so adding kinds
    // is not a bus problem.  It is a TRANSCRIPT LENGTH problem:
    //
    //  * airq_lambda is uniquely cheap because AirChallengeDigest builds a
    //    FRESH, SELF-CONTAINED preimage: tag | seed | label | roots | shape =
    //    113 bytes = 3 SHA256d compressions, giving a companion SHA CS of
    //    4096 rows x 541 columns (MEASURED).
    //  * every OTHER child challenge (fri_lambda, z1, z2, w1, w2, fold betas,
    //    query indices) is drawn by Fri3AlgBatchProve/Verify's SEQUENTIAL
    //    transcript: ChallengeDigest(suffix) = SHA256d(buf | suffix) where
    //    `buf` is the whole accumulated transcript.  TWO W-proportional terms
    //    are in it, and BOTH must be removed or neither helps:
    //      (i)  4*W from Fri3AlgBatchFsInit (fri_ext3_alg.cpp:1309)
    //           `for (const uint32_t len : column_len) AppendLE32(fs.buf, len);`
    //           -- absorbed at FS INIT, so it precedes EVERY challenge,
    //           including the very first;
    //      (ii) 48*W from both full OOD evaluation vectors, 2*W Fp3 at 24 B
    //           each (AbsorbFp3 of evals_z1[i]/evals_z2[i] for all W columns,
    //           fri_ext3_alg.cpp:1942-1943), which precedes w1/w2 onward.
    //    Total >= 52*W bytes (plus preamble, roots, batch coefficients, z1, z2
    //    and the label suffix -- small beside 52*W).  Committing only (ii)
    //    leaves (i) and buys about 13x, which is nowhere near enough.
    //
    // The in-AIR cost follows EXACTLY, not by hand-waving.  A vertical SHA AIR
    // lays instances out in rows: hash_air.cpp
    // BuildFixedProgramVerticalWitnessBoundaryInstance sets
    //   scheduled_instances = next_pow2(compressions)      (>= 2)
    //   n_rows              = scheduled_instances * LANE_ROWS,  LANE_ROWS = 1024
    // so with compressions = ceil((52*W + 9) / 64) + 1:
    //
    //   airq_lambda   113 B  ->      3 comps -> sched      4 -> 4.10e3 rows
    //                                        (MEASURED: comps=3, 4096 x 541)
    //   W =  17108  0.89 MB  ->  13902 comps -> sched  16384 -> 1.68e7 rows
    //   W = 384984 20.02 MB  -> 312801 comps -> sched 524288 -> 5.37e8 rows
    //
    // (The power-of-two rounding absorbs the 48*W -> 52*W correction, so the
    // ROW figures are unchanged by it; only the compression counts move.)
    // Those are for ONE challenge of ONE slot.  This is not a labour problem.
    //
    // The route that closes this is a PROTOCOL change to the child transcript:
    // absorb COMMITMENTS (roots) to BOTH the OOD evaluation vectors AND
    // column_len, so every challenge's preimage becomes short and
    // self-contained the way AirChallengeDigest's already is.  That change
    // lives in matmul_v4_rc_fri_ext3_alg.cpp, is consensus-visible, and must
    // land in BOTH trees (stage3-build and the main repo) or the branches will
    // not merge.  It is NOT in this lane and must not be made here.  Do NOT
    // absorb the batched value v1,v2 instead: that is the known attack, with
    // the kernel exhibited in closed form in
    // matmul_v4_rc_fri_ext3_alg_order_audit.h:16-35.
    //
    // Even with the transcript fixed, coverage is W-INDEPENDENT but not free:
    // ~2412 compressions, of which ~2220 (92%) are the 148 fra3_query draws
    // that share an identical `buf` and differ only in a trailing 4 bytes.
    // Those collapse by FORKING a shared SHA midstate -- a pure companion-CS
    // change with no transcript, consensus or merge impact.  The chip DOES
    // support it: see g4_sha_chip_forks_a_shared_midstate_to_divergent_tails.
    //
    // THE COUNTER IS SPLIT, because "the parent decodes kind k" and "the
    // prover cannot choose kind k's transcript bytes" are different claims and
    // collapsing them is exactly how a gate ends up protecting nothing.
    // `challenge_kinds_covered` counts kinds with a parent DECODER bound to the
    // consumed scalar and a cross-checked transcript re-derivation;
    // `challenge_kinds_transcript_bound` counts kinds whose digest bytes are a
    // constrained output of an in-AIR hash over the FULL per-instance event
    // list (AssessChildFsFullEventP2TranscriptOwnershipV1) — not the
    // representative-per-kind companion affordability counter in
    // AssessChildFsChallengeDecoderCoverageV1.  Coverage requires BOTH at 8,
    // so adding the second counter can only ever remove a `true`.
    uint32_t slots_required{kNormalizedUniversalParentArityV1};
    uint32_t challenge_kinds_required{8};
    uint32_t slots_covered{0};
    uint32_t challenge_kinds_covered{0};
    uint32_t challenge_kinds_transcript_bound{0};
    bool real_child_shape_covered{false};
    bool covers_all_slots_and_kinds{false};
    // --- Obligation 3: PROOF LEVEL.  Each endpoint must be carried by a real
    // FRI proof, not by CountWitnessViolationsOnH.
    bool lane_relation_fri_proven{false};
    bool producer_endpoint_fri_proven{false};
    bool consumer_endpoint_fri_proven{false};
    bool discharged_by_fri_proof{false};
    // --- Obligation 4: the parent that CARRIES RECURSION must host the replay
    // and the bus.  This is the substantive parent obligation.
    bool recursion_parent_hosts_replay{false};
    // --- Obligation 4 is now the WHOLE parent question.  The scaffold flag
    // `complete_sha_fiat_shamir_replay_in_air` was retired from
    // NormalizedUniversalParentCandidateV1 (project owner decision), so there is
    // no longer a second, unsettable parent flag to reconcile against and no
    // ownership residual to report.
    bool closed{false};
    std::string note;
};

[[nodiscard]] ChildFsReplayClosureV1 AssessChildFsReplayClosureV1();

/**
 * PR-89 g4: recompute the PRODUCER endpoint FRI on the Poseidon2 companion.
 *
 * MEASURED replacement for the SHA companion's 58.6 s floor (build 16.2 s +
 * Split-RAP prove 41.1 s over 591 x 4096).  BuildChildAirChallengeP2ReplayV1
 * + plain AirQuotientProve/Verify over the query-sound P2 companion was
 * profiled at ~4.5 s end-to-end.  This assessor recomputes that path (no
 * persisted artifact) and is what AssessChildFsReplayClosureV1 consults for
 * producer_endpoint_fri_proven once aq::kAirChallengeP2Activated is true —
 * the live endpoint must be the P2 companion, not the SHA one.
 */
struct ProducerEndpointFriP2ResultV1 {
    bool prove_ok{false};
    bool verify_ok{false};
    bool query_sound_shape{false};
    bool companion_valid{false};
    uint32_t companion_rows{0};
    uint32_t companion_columns{0};
    double build_seconds{0};
    double prove_seconds{0};
    double verify_seconds{0};
    bool ok{false};
    std::string note;
};

[[nodiscard]] ProducerEndpointFriP2ResultV1
ProveProducerEndpointFriP2V1(const uint256& child_fs_seed,
                             const uint256& trace_commit,
                             uint32_t child_n_rows,
                             uint32_t child_quotient_len,
                             uint32_t child_w);

/**
 * PR-89 g4: recompute the CONSUMER endpoint FRI on the Poseidon2 decoder
 * (limb-mode bus-augmented). Parallel to ProveProducerEndpointFriP2V1: the
 * live consumer half under aq::kAirChallengeP2Activated is the 3-limb
 * decoder relation the four-slot parent embeds, not the SHA 24-byte window.
 * Query-sound height (1024 rows); process-lifetime memo in the closure
 * assessor.
 */
struct ConsumerEndpointFriP2ResultV1 {
    bool prove_ok{false};
    bool verify_ok{false};
    bool query_sound_shape{false};
    bool decoder_valid{false};
    bool bus_appended{false};
    uint32_t rows{0};
    uint32_t columns{0};
    double build_seconds{0};
    double prove_seconds{0};
    double verify_seconds{0};
    bool ok{false};
    std::string note;
};

[[nodiscard]] ConsumerEndpointFriP2ResultV1
ProveConsumerEndpointFriP2V1(const uint256& digest_p2,
                             const gf::Fp3& consumed_challenge);

/**
 * PR-89 g4: default-gate evidence that the g4 P2 limb bus reconciles on four
 * DISTINCT child transcripts whose AIR is a real coupled-bank dequant role
 * (not ToyFriChildCs), each with a distinct witness => distinct airq_lambda.
 */
struct RealChildShapeCoverageV1 {
    bool ok{false};
    uint32_t distinct_transcripts{0};
    uint32_t slots_bus_reconciled{0};
    uint32_t child_columns{0};
    uint32_t child_rows{0};
    std::string note;
};

[[nodiscard]] RealChildShapeCoverageV1
AssessRealChildShapeCoverageV1();

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
 * COLUMN-CAP NOTE.  AirFriBackendAlg<Fp3> caps a batch at
 * kRCFri3AlgBatchMaxColumns, which is CURRENTLY 1u << 20 = 1,048,576
 * (matmul_v4_rc_fri_ext3_alg.h; the static_assert ceiling is the same 2^20).
 * The 2^14 -> 2^15 = 32768 figure that used to appear here was PR-89 rung-4
 * and is HISTORY, not a live constraint: rung-5 raised it again to 2^20 so a
 * real-role arity-4 parent (384k-712k columns) could commit its own FRI proof.
 * Read it as history; four separate lanes have now misdiagnosed an over-cap
 * condition from the stale wording.
 *
 * The arity-4 four-slot parent verifies four 192-query FRI children in-AIR; at
 * the minimal (toy) child shape that V_CS is ~16996 columns wide and at real
 * role width it is 384,984 (385,034 bus-augmented).  BOTH fit, with ~2.7x
 * headroom at real width, so within_backend_column_cap is true at every shape
 * this lane builds.  What is expensive is TIME, not the cap: the ~17k-column
 * toy self-prove is tens of minutes and the real-width one was MEASURED at
 * 4,003.9 s of AirQuotientProve inside a 16.65 GiB peak (commit bec2c48).  The
 * reduced-arity one-slot parent (one active child + three padding slots, ~4.2k
 * columns) round-trips cheaply, and ProveParentOwnFriV1 over a compact V_CS
 * advances parent_own_fri_proof_produced quickly.
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
 * valid parent (parent.valid, witness_violations==0) is proven.
 *
 * CORRECTION.  This used to say the four-slot V_CS "exceeds the alg column cap
 * at every shape down to the toy child" and therefore always returned
 * within_backend_column_cap=false.  That is NOT what the implementation does
 * and has not been true since the cap became 2^20: the flag is COMPUTED as
 * `parent_cs.n_columns <= kRCFri3AlgBatchMaxColumns`, and both the toy
 * (~17k) and real-role (384,984) four-slot shapes satisfy it.  There is no
 * four-slot column-cap residual.
 *
 * The real residual is MEMORY and TIME, which the cap does not bound: at the
 * measured real shape a non-streaming BatchCommit would materialize ~303 GB,
 * and the streamed real-width self-prove was MEASURED at 4,003.9 s / 16.65 GiB
 * peak (commit bec2c48).  Read within_backend_column_cap as a backend-format
 * bound only, never as an OOM guard.
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
