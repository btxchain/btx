// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_DECODER_JOIN_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_DECODER_JOIN_H

#include <matmul/matmul_v4_rc_stage3_multirow_v11_merkle_fold.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_parent_join.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_multirow_v11_decoder_join {

namespace abi = stage3_multirow_v11_proof_abi;
namespace aq = air_quotient;
namespace djp = stage3_multirow_v11_parent_join;
namespace gf = gkr_field;
namespace mf = stage3_multirow_v11_merkle_fold;

inline constexpr uint16_t kDecoderJoinVersionV1 = 1;
inline constexpr uint32_t kDecoderJoinBusLanesV1 = 2;
inline constexpr uint32_t kDecoderJoinRootWordsV1 = 8;

enum class ConsumerKindV1 : uint8_t {
    ParentTranscript = 1,
    ParentPublic = 2,
    ParentDerived = 3,
    ParentQueryIndex = 4,
    MerkleLiteral = 5,
    MerkleHashInput = 6,
    FoldChallenge = 7,
    FoldTerminal = 8,
};

/**
 * One occurrence, rather than merely one distinct address.  The occurrence
 * id is load-bearing: Q192 samples with replacement may open the same row
 * more than once, but every query occurrence must remain separately owned.
 */
struct OccurrenceV1 {
    ConsumerKindV1 kind{ConsumerKindV1::ParentTranscript};
    uint32_t occurrence_id{0};
    uint32_t source_address{0};
    uint32_t value{0};
    uint32_t query{0};
    uint32_t shard{0};
    uint32_t local_ordinal{0};
};

struct LayoutV1 {
    uint32_t active{0};
    uint32_t source_kind{0};
    uint32_t source_occurrence{0};
    uint32_t source_address{0};
    uint32_t source_value{0};
    uint32_t consumer_kind{0};
    uint32_t consumer_occurrence{0};
    uint32_t consumer_address{0};
    uint32_t consumer_pin{0};
    uint32_t consumer_claim{0};
    std::array<uint32_t, kDecoderJoinBusLanesV1> source_inverse{};
    std::array<uint32_t, kDecoderJoinBusLanesV1> consumer_inverse{};
    std::array<uint32_t, kDecoderJoinBusLanesV1> running{};
    uint32_t root_active{0};
    uint32_t root_kind{0};
    uint32_t root_index{0};
    uint32_t root_word{0};
    uint32_t root_value{0};
    uint32_t n_columns{0};
};

[[nodiscard]] LayoutV1 CanonicalLayoutV1();

struct ChildRootPinV1 {
    uint32_t kind{0};
    uint32_t index{0};
    uint256 root{};
};

struct ProductV1 {
    LayoutV1 layout{};
    aq::AirConstraintSystem<gf::Fp3> cs{};
    std::vector<std::vector<gf::Fp3>> columns;
    std::vector<uint32_t> preprocessed_columns;
    std::vector<OccurrenceV1> source_occurrences;
    std::vector<OccurrenceV1> consumer_occurrences;
    std::vector<ChildRootPinV1> child_roots;
    std::array<gf::Fp3, kDecoderJoinBusLanesV1> gamma{};
    std::array<gf::Fp3, kDecoderJoinBusLanesV1> alpha{};
    uint256 join_tuple_precommit_root{};
    uint256 preprocessed_row_group_root{};
    uint32_t real_rows{0};
    uint32_t trace_rows{0};
    uint32_t constraints{0};
    uint32_t max_constraint_degree{0};
    uint64_t violations{0};
    uint32_t duplicate_query_occurrences{0};
    bool canonical_abi{false};
    bool parent_replay_exactly_matches_decoded{false};
    bool parent_root_recomputed{false};
    bool child_roots_recomputed{false};
    bool exact_occurrence_inventory{false};
    bool all_logup_tuple_cells_precommitted{false};
    bool challenges_after_join_precommit{false};
    bool dual_rational_identity_air_constrained{false};
    bool terminal_sums_zero{false};
    bool consumer_claims_equal_root_pinned_cells{false};
    bool ordered_preprocessed_root_pinned{false};
    bool canonical_u32_and_fp_pairs{false};
    bool duplicate_query_identity_preserved{false};
    bool same_parent_decoder_aliases_executable{false};
    bool recursive_authority_ready{false};
    bool valid{false};
    std::string note;
};

/**
 * Build one same-parent ownership trace.
 *
 * `parent` is the exact V11 transcript/public join and `shards` are disjoint
 * Merkle/fold query ranges.  Their independently recomputed R0 roots are
 * embedded in this trace's ordered R0 schedule.  Every downstream occurrence
 * is then joined to the canonical decoder address/value by two independent
 * post-commit rational-identity lanes.  Expected values are preprocessed
 * cells, never free witnesses.
 *
 * This closes the decoder ownership seam only.  It deliberately does not
 * claim that the child verifiers have already been executed recursively.
 */
[[nodiscard]] ProductV1 BuildProductV1(
    const abi::DecodedV1& decoded,
    const djp::ProductV1& parent,
    const std::vector<mf::ShardProductV1>& shards);

[[nodiscard]] uint64_t RecountViolationsV1(
    const ProductV1& product,
    const std::vector<std::vector<gf::Fp3>>& columns);

struct ReadinessV1 {
    bool canonical_decoder_inventory_executable{true};
    bool parent_transcript_ownership_executable{true};
    bool merkle_fold_literal_ownership_executable{true};
    bool dual_rational_identity_executable{true};
    bool duplicate_query_occurrence_identity_executable{true};
    bool recursive_child_verifiers_executable{false};
    bool recursive_authority_ready{false};
};

[[nodiscard]] constexpr ReadinessV1 CurrentReadinessV1()
{
    return {};
}

} // namespace matmul::v4::rc::stage3_multirow_v11_decoder_join

#endif
