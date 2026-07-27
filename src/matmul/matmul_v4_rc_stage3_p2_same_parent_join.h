// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_P2_SAME_PARENT_JOIN_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_P2_SAME_PARENT_JOIN_H

#include <matmul/matmul_v4_rc_stage3_airq_p2_transcript.h>
#include <matmul/matmul_v4_rc_stage3_p2_transcript_binding.h>

#include <array>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

// ============================================================================
// Append-only, same-parent P2 transcript joins.
//
// A host comparison between a replayed challenge and a verifier consumer does
// not constrain a recursive proof.  This module instead transports each value
// through a proof-committed carrier column.  Public 0/1 row selectors enforce
//
//   carrier[source row] = source expression,
//   carrier[r + 1]      = carrier[r], and
//   carrier[sink row]   = sink expression.
//
// The selectors contain positions only.  No seed, root, proof value,
// challenge, or query index is installed as a preprocessed value.
//
// Existing parent column references are mandatory.  This file allocates only
// carrier and selector columns; it never manufactures a fallback copy of a
// proof-owned source or verifier consumer.
// ============================================================================

namespace matmul::v4::rc::stage3_p2_same_parent_join {

namespace aq = air_quotient;
namespace gf = gkr_field;
namespace p2air = stage3_p2_transcript_air;
namespace p2bind = stage3_p2_transcript_binding;
namespace airq = stage3_airq_p2_transcript;
namespace pa = stage3_poseidon_air;

using gf::Fp3;

inline constexpr uint16_t kSameParentJoinVersionV1 = 1;
inline constexpr uint32_t kInvalidColumn =
    std::numeric_limits<uint32_t>::max();

struct CellRefV1 {
    uint32_t column{kInvalidColumn};
    uint32_t row{0};
};

struct Fp3CellRefsV1 {
    std::array<CellRefV1, 3> coord{};
};

struct RootU32CellRefsV1 {
    std::array<CellRefV1, 8> word{};
};

struct BytesCellRefsV1 {
    std::vector<CellRefV1> byte;
};

enum class EndpointKindV1 : uint8_t {
    Cell = 1,
    PoseidonOutput = 2,
    LinearCombination = 3,
    PoseidonOutputFp3 = 4,
    Fp3Coordinates = 5,
};

struct LinearTermV1 {
    CellRefV1 cell{};
    uint32_t coefficient{0};
};

/**
 * An endpoint is either an existing parent cell or one output lane of an
 * existing Poseidon operation table.  Poseidon outputs are virtual
 * expressions in the current AIR layout, so naming them directly avoids an
 * unconstrained "export" witness.
 */
struct EndpointV1 {
    EndpointKindV1 kind{EndpointKindV1::Cell};
    CellRefV1 cell{};
    pa::Layout poseidon{};
    uint32_t output_lane{0};
    uint32_t row{0};
    Fp3CellRefsV1 fp3_coordinates{};
    Fp3 constant{};
    std::vector<LinearTermV1> linear_terms;
};

enum class EqualityRoleV1 : uint8_t {
    FriProofSource = 1,
    FriVerifierConsumer = 2,
    AirqProofSource = 3,
    AirqVerifierConsumer = 4,
};

struct EqualityV1 {
    EqualityRoleV1 role{EqualityRoleV1::FriProofSource};
    uint32_t semantic_ordinal{0};
    uint32_t coordinate{0};
    EndpointV1 source{};
    EndpointV1 sink{};
};

struct JoinPlanV1 {
    uint16_t version{kSameParentJoinVersionV1};
    std::vector<EqualityV1> equalities;
    uint32_t fri_source_equalities{0};
    uint32_t fri_consumer_equalities{0};
    uint32_t airq_source_equalities{0};
    uint32_t airq_consumer_equalities{0};
};

struct EqualityLayoutV1 {
    uint32_t carrier{kInvalidColumn};
    uint32_t source_selector{kInvalidColumn};
    uint32_t sink_selector{kInvalidColumn};
    uint32_t carry_selector{kInvalidColumn};
    bool same_row{false};
    std::vector<uint32_t> transport_carriers;
    std::vector<uint32_t> transport_source_selectors;
    std::vector<uint32_t> transport_carry_selectors;
};

struct AppendResultV1 {
    bool valid{false};
    bool column_refs_reused{false};
    bool row_tagged_equalities_constrained{false};
    bool cross_row_transport_constrained{false};
    bool selectors_only_preprocessed{false};
    bool actual_values_preprocessed{true};
    bool proof_owned_sources_equality_constrained{false};
    bool verifier_consumers_equality_constrained{false};

    // The append operation sees column addresses, not the verifier chip that
    // owns them.  These deliberately remain false until the integration
    // parent supplies executable source/consumer verifier AIRs.
    bool source_columns_proven_verifier_owned{false};
    bool consumer_columns_proven_verifier_owned{false};
    bool recursively_consumed{false};
    bool recursive_authority{false};

    uint32_t original_columns{0};
    uint32_t appended_columns{0};
    uint32_t equality_count{0};
    std::vector<EqualityLayoutV1> equality_layouts;
    std::vector<std::string> residuals;
    std::string note;
};

/**
 * Explicit proof-source columns exported by an existing V10 verifier parent.
 * `shape_commit` is the proof's canonical Fri3AlgShapeCommit; raw dimensions
 * remain separately bound through n_coeffs and width.
 */
struct FriProofSourceRefsV1 {
    /**
     * Exact proof-owned byte exports for each compact PrefixScheduleEntry.
     * Entry zero is the deliberately absent AIRQ/Fri prefix and must be
     * empty. Shared schedules (both OOD draws, both DEEP weights, all
     * queries) are exported once and reused.
     */
    std::vector<BytesCellRefsV1> prefix_schedule;

    // Auditable aliases into prefix_schedule. They do not duplicate witness
    // cells: BuildFriV10JoinPlanV1 requires exact CellRef equality at every
    // canonical byte position.
    BytesCellRefsV1 fs_seed;              // 32 bytes
    BytesCellRefsV1 shape_commit;         // 32 bytes
    BytesCellRefsV1 row_commit_root;      // 32 bytes
    BytesCellRefsV1 ood_eval_commit_root; // 32 bytes
    std::vector<BytesCellRefsV1> fold_roots; // 32 bytes each
};

/**
 * One explicit consumer address per canonical V10 event.  Fp3 events use
 * `fp3`; query events use `query_index`.  The unused member must stay invalid.
 */
struct FriConsumerRefsV1 {
    struct Event {
        Fp3CellRefsV1 fp3;
        CellRefV1 query_index;
    };
    std::vector<Event> events;
};

struct AirqProofSourceRefsV1 {
    RootU32CellRefsV1 fs_seed;
    RootU32CellRefsV1 trace_commit_root;
    std::array<CellRefV1, 3> shape{};
};

struct AirqConsumerRefsV1 {
    Fp3CellRefsV1 lambda;
};

/**
 * Append exact equality/copy constraints to an existing parent AIR.
 *
 * All referenced cells and Poseidon tables must already be resident in
 * `parent_cs`/`parent_columns`.  The function is append-only on success.
 */
[[nodiscard]] bool AppendSameParentJoinV1(
    aq::AirConstraintSystem<Fp3>& parent_cs,
    std::vector<std::vector<Fp3>>& parent_columns,
    const JoinPlanV1& plan,
    AppendResultV1& out,
    std::string* why = nullptr);

/**
 * Build every V10 FRI source and consumer equality against an already
 * resident stage3_p2_transcript_air table.
 */
[[nodiscard]] bool BuildFriV10JoinPlanV1(
    const p2bind::BindingResult& binding,
    const p2air::BuildResult& transcript,
    const FriProofSourceRefsV1& sources,
    const FriConsumerRefsV1& consumers,
    JoinPlanV1& out,
    std::vector<std::string>& residuals,
    std::string* why = nullptr);

/**
 * Build the exact AIRQ seed/root/shape and lambda-consumer equalities against
 * an already resident stage3_airq_p2_transcript table.
 */
[[nodiscard]] bool BuildAirqJoinPlanV1(
    const airq::BuildResult& transcript,
    const AirqProofSourceRefsV1& sources,
    const AirqConsumerRefsV1& consumers,
    JoinPlanV1& out,
    std::vector<std::string>& residuals,
    std::string* why = nullptr);

[[nodiscard]] uint32_t CountViolations(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns);

} // namespace matmul::v4::rc::stage3_p2_same_parent_join

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_P2_SAME_PARENT_JOIN_H
