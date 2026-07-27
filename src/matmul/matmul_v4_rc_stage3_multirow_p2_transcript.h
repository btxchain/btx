// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_P2_TRANSCRIPT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_P2_TRANSCRIPT_H

#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_fri_ext3_alg.h>
#include <matmul/matmul_v4_rc_stage3_poseidon_air.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_multirow_p2_transcript {

namespace aq = air_quotient;
namespace gf = gkr_field;
namespace pa = stage3_poseidon_air;

/**
 * This is an additive research protocol. It does not change the frozen FMR2
 * codec or any active selector. A future backend must allocate a new proof
 * envelope before this transcript can protect consensus.
 */
inline constexpr uint16_t kStatementVersionV1 = 1;
inline constexpr uint32_t kProtocolVersionV1 = 11;
inline constexpr uint32_t kLegacyMultiRowVersionV2 =
    kRCFri3AlgMultiRowBatchProofVersion;
inline constexpr uint64_t kProtocolDomainV1 =
    0x4d525032'51313932ull; // "MRP2Q192"
inline constexpr uint32_t kGroupsV1 = 3;
inline constexpr uint32_t kOodCandidatesV1 = 2;
inline constexpr uint32_t kQueriesV1 = 192;
inline constexpr uint32_t kQueryCandidatesV1 = 2;
inline constexpr uint32_t kMinLdeRowsV1 = 4096;
inline constexpr uint32_t kMaxLdeRowsV1 = 1U << 24;

struct GroupClaimV1 {
    Fri3AlgMultiRowGroupRole role{
        Fri3AlgMultiRowGroupRole::MainTrace};
    uint32_t first_column{0};
    uint32_t column_count{0};
    uint32_t n_leaves{0};
    Fri3AlgDigest root{};

    bool operator==(const GroupClaimV1&) const = default;
};

struct FoldClaimV1 {
    uint32_t n_leaves{0};
    Fri3AlgDigest root{};

    bool operator==(const FoldClaimV1&) const = default;
};

struct StatementV1 {
    uint16_t statement_version{kStatementVersionV1};
    uint32_t protocol_version{kProtocolVersionV1};
    uint64_t protocol_domain{kProtocolDomainV1};
    uint256 public_fs_seed{};
    uint64_t pow_grind_nonce{0};
    uint32_t trace_rows{0};
    uint32_t trace_columns{0};
    uint32_t quotient_len{0};
    uint32_t n_coeffs{0};
    uint32_t blowup{kRCFriBlowup};
    std::vector<uint32_t> base_column_indices;
    std::array<GroupClaimV1, kGroupsV1> groups{};
    std::vector<uint32_t> column_len;
    std::vector<gf::Fp3> evals_z1;
    std::vector<gf::Fp3> evals_z2;
    std::vector<FoldClaimV1> folds;
    gf::Fp3 final_value{};
};

struct QueryDerivationV1 {
    std::array<Fri3AlgDigest, kQueryCandidatesV1> candidate_digest{};
    uint32_t selected_ordinal{kQueryCandidatesV1};
    uint32_t index{0};
};

struct ReceiptV1 {
    uint16_t statement_version{kStatementVersionV1};
    uint32_t protocol_version{kProtocolVersionV1};
    uint64_t protocol_domain{kProtocolDomainV1};
    Fri3AlgDigest shape_commit{};
    gf::Fp3 air_lambda{};
    Fri3AlgDigest fri_seed{};
    std::array<gf::Fp3, kOodCandidatesV1> z1_candidates{};
    std::array<gf::Fp3, kOodCandidatesV1> z2_candidates{};
    uint32_t z1_selected{kOodCandidatesV1};
    uint32_t z2_selected{kOodCandidatesV1};
    gf::Fp3 z1{};
    gf::Fp3 z2{};
    Fri3AlgDigest ood_eval_commit{};
    Fri3AlgDigest batch_seed{};
    std::vector<gf::Fp3> batching_coefficients;
    gf::Fp3 w1{};
    gf::Fp3 w2{};
    std::vector<gf::Fp3> fold_challenges;
    Fri3AlgDigest query_seed{};
    std::array<QueryDerivationV1, kQueriesV1> queries{};
    bool q192_with_replacement{false};
    bool valid{false};
    std::string note;
};

/** Exact native derivation. No legacy SHA/FMR2 state is accepted. */
[[nodiscard]] ReceiptV1 DeriveV1(const StatementV1& statement);

/** Re-derive and compare every transcript cell, including all candidates. */
[[nodiscard]] bool VerifyReceiptV1(
    const StatementV1& statement,
    const ReceiptV1& receipt,
    std::string* why = nullptr);

/** Conservative -log2 bound on fail-closed query-candidate exhaustion. */
[[nodiscard]] double QueryExhaustionBitsV1(
    uint32_t n_lde = kMinLdeRowsV1,
    uint32_t queries = kQueriesV1,
    uint32_t candidates = kQueryCandidatesV1);

struct QuerySelectionAuditV1 {
    std::array<bool, kQueryCandidatesV1> candidate_valid{};
    std::array<bool, kQueryCandidatesV1> selected{};
    uint32_t selected_ordinal{kQueryCandidatesV1};
    uint32_t index{0};
    uint32_t constraint_violations{0};
    bool valid{false};
};

/** Executable scalar model of the quadratic K2 first-valid selector chip. */
[[nodiscard]] QuerySelectionAuditV1 AuditQuerySelectionV1(
    const std::array<Fri3AlgDigest, kQueryCandidatesV1>& candidates,
    uint32_t n_lde);

/**
 * Explicit boundary between this executable transcript and the frozen
 * MultiRow-V2 proof backend. These are integration requirements, not flags
 * that can be flipped by this module.
 */
struct BackendHookAuditV1 {
    bool additive_version_and_domain{false};
    bool commit_schedule_implemented{false};
    bool verify_schedule_implemented{false};
    bool unbiased_query_openings_implemented{false};
    bool versioned_codec_implemented{false};
    bool split_rap_dispatch_implemented{false};
    bool receipt_cells_match_backend{false};
    bool backend_executable{false};
    std::string exact_hooks;
};

[[nodiscard]] BackendHookAuditV1 AssessBackendHooksV1();

struct LayoutV1 {
    pa::Layout poseidon{};
    uint32_t absorb_base{0};
    uint32_t terminal{0};
    uint32_t digest_claim_base{0};
    uint32_t query_candidate_active{0};
    uint32_t query_candidate_first{0};
    uint32_t candidate_valid{0};
    uint32_t candidate_inverse{0};
    uint32_t candidate_prior_valid{0};
    uint32_t candidate_selected{0};
    uint32_t n_columns{0};

    [[nodiscard]] uint32_t Absorb(uint32_t lane) const
    {
        return absorb_base + lane;
    }
    [[nodiscard]] uint32_t DigestClaim(uint32_t limb) const
    {
        return digest_claim_base + limb;
    }
};

[[nodiscard]] LayoutV1 CanonicalLayoutV1();

/**
 * Constant-width replay of every Poseidon event. The exact event tape is R0:
 * eight absorb lanes, event terminal marker, and four claimed digest lanes.
 * The parent must eventually replace this statement-specialised tape with
 * proof-owned same-parent aliases; that readiness remains false here.
 */
struct ProductV1 {
    LayoutV1 layout{};
    StatementV1 statement{};
    ReceiptV1 receipt{};
    aq::AirConstraintSystem<gf::Fp3> cs{};
    std::vector<std::vector<gf::Fp3>> columns;
    std::vector<uint32_t> preprocessed_columns;
    uint256 preprocessed_row_group_root{};
    uint32_t hash_events{0};
    uint32_t real_sponge_rows{0};
    uint32_t trace_rows{0};
    uint32_t constraints{0};
    uint32_t max_constraint_degree{0};
    uint64_t violations{0};
    bool full_root_and_length_binding{false};
    bool full_ood_binding_before_batching{false};
    bool independent_batching_coefficients_host_derived{false};
    bool independent_batching_consumer_air_constrained{false};
    bool k2_ood_selection_host_derived{false};
    bool k2_ood_selection_air_constrained{false};
    bool q192_with_replacement_host_derived{false};
    bool q192_k2_first_valid_air_constrained{false};
    bool q192_selected_index_consumer_air_constrained{false};
    bool canonical_u64_split{false};
    bool exact_host_poseidon_air_equivalence{false};
    bool preprocessed_event_tape_root_pinned{false};
    bool proof_owned_sources_bound{false};
    bool frozen_v2_unchanged{true};
    bool production_authority_ready{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] ProductV1 BuildProductV1(const StatementV1& statement);

} // namespace matmul::v4::rc::stage3_multirow_p2_transcript

#endif
