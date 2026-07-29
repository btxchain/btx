// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_AIRQ_P2_TRANSCRIPT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_AIRQ_P2_TRANSCRIPT_H

#include <matmul/matmul_v4_rc_stage3_poseidon_air.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

// ============================================================================
// Exact AIRQ Poseidon2 transcript companion.
//
// This is intentionally separate from the Fri3Alg transcript AIR. It
// reproduces:
//
//   AirChallengeP2Lanes(seed, "airq_lambda", {trace_commit}, {N,Lq,W})
//   AirChallengeDigestP2(...)
//   FromChallengeBytes3(digest[0..24))
//
// with the existing quadratic Poseidon operation table and exact sponge
// chaining. Public source and consumer maps are appendable descriptions only;
// no same-parent/root ownership or recursive authority is claimed here.
// ============================================================================

namespace matmul::v4::rc::stage3_airq_p2_transcript {

namespace aq = air_quotient;
namespace gf = gkr_field;
namespace pa = stage3_poseidon_air;

using gf::Fp3;

inline constexpr char kLambdaLabel[] = "airq_lambda";

struct Statement {
    uint32_t route_version{
        aq::kAirChallengeP2RouteVersion};
    std::string domain_tag{
        aq::kAirChallengeP2DomainTag};
    std::string label{kLambdaLabel};
    uint256 fs_seed{};
    uint256 trace_commit{};
    uint32_t n_rows{0};
    uint32_t quotient_len{0};
    uint32_t trace_width{0};
};

struct Layout {
    pa::Layout poseidon;
    uint32_t message_base{0}; // rate-8 lanes
    uint32_t active_col{0};
    uint32_t start_col{0};
    uint32_t terminal_col{0};
    uint32_t digest_base{0}; // four canonical Goldilocks lanes
    uint32_t lambda_base{0}; // three Fp3 coordinates

    [[nodiscard]] uint32_t MessageCol(uint32_t lane) const;
    [[nodiscard]] uint32_t DigestCol(uint32_t lane) const;
    [[nodiscard]] uint32_t LambdaCol(uint32_t coord) const;
    [[nodiscard]] uint32_t End() const;
    [[nodiscard]] bool IsCanonical(std::string* why = nullptr) const;
};

[[nodiscard]] Layout CanonicalLayout();

struct SourceCellMap {
    std::array<uint32_t, 8> seed_u32{};
    std::array<uint32_t, 8> trace_commit_u32{};
    std::array<uint32_t, 3> shape_u32{};
    std::vector<gf::Fp> absorb_lanes;
    bool canonical_u32_encoding{false};
    bool appendable_layout_only{true};
    bool same_parent_bound{false};
};

struct ConsumerCellMap {
    uint32_t terminal_row{0};
    std::array<uint32_t, 3> lambda_columns{};
    Fp3 lambda{};
    bool appendable_layout_only{true};
    bool same_parent_bound{false};
};

struct BuildResult {
    Statement statement;
    Layout layout;
    aq::AirConstraintSystem<Fp3> cs;
    std::vector<std::vector<Fp3>> columns;
    SourceCellMap source_map;
    ConsumerCellMap consumer_map;
    std::vector<gf::Fp> native_lanes;
    uint256 native_digest{};
    Fp3 native_lambda{};
    uint32_t active_rows{0};
    uint32_t n_rows{0};
    uint32_t n_columns{0};
    uint32_t n_constraints{0};
    uint32_t max_alg_degree{0};
    uint32_t violations{1};

    bool canonical_statement{false};
    bool exact_air_challenge_lanes{false};
    bool exact_air_challenge_digest{false};
    bool exact_from_challenge_bytes3{false};
    bool absorb_lanes_preprocessed_pinned{false};
    bool poseidon_permutations_constrained{false};
    bool sponge_state_chain_constrained{false};
    bool digest_and_lambda_constrained{false};
    bool appendable_source_map_canonical{false};
    bool appendable_consumer_map_canonical{false};

    bool proof_owned_source_cells_bound{false};
    bool same_parent_consumer_cells_bound{false};
    bool recursive_authority{false};

    bool local_air_complete{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] BuildResult BuildAirqLambdaTranscriptAir(
    const Statement& statement);

[[nodiscard]] uint32_t CountViolations(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns);

} // namespace matmul::v4::rc::stage3_airq_p2_transcript

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_AIRQ_P2_TRANSCRIPT_H
