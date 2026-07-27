// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_FS_SELECTION_AIR_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_FS_SELECTION_AIR_H

#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_stage3_poseidon_air.h>

#include <array>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_fs_selection_air {

namespace aq = air_quotient;
namespace gf = gkr_field;

/**
 * Bounded unbiased Fp3 decoder used by the MultiRow-V2 transcript.
 *
 * Eight little-endian uint64 words come from two SHA256d digests. A word is
 * accepted iff it is strictly below Goldilocks p. The first three accepted
 * words, in order, become (c0,c1,c2); fewer than three is unsatisfiable.
 *
 * For p = 0xffffffff00000001:
 *   word < p iff high32 < 0xffffffff
 *                    or (high32 == 0xffffffff and low32 == 0).
 * The comparison therefore needs only boolean decomposition, an AND prefix
 * for high32==0xffffffff, and one zero-test inverse for low32.
 */
inline constexpr uint32_t kCandidateWords = 8;
inline constexpr uint32_t kWordBits = 64;
inline constexpr uint32_t kCountStates = 4;
inline constexpr uint32_t kHighAndPrefix = 33;
inline constexpr uint32_t kColumnsPerWord =
    kWordBits + kHighAndPrefix + 3 + kCountStates;

struct LayoutV1 {
    uint32_t base{0};
    uint32_t selected{0};

    explicit constexpr LayoutV1(uint32_t start = 0)
        : base(start),
          selected(
              start +
              kCandidateWords *
                  kColumnsPerWord)
    {
    }

    [[nodiscard]] constexpr uint32_t WordBase(
        uint32_t word) const
    {
        return base + word * kColumnsPerWord;
    }
    [[nodiscard]] constexpr uint32_t Bit(
        uint32_t word, uint32_t bit) const
    {
        return WordBase(word) + bit;
    }
    [[nodiscard]] constexpr uint32_t HighAnd(
        uint32_t word, uint32_t step) const
    {
        return WordBase(word) +
            kWordBits + step;
    }
    [[nodiscard]] constexpr uint32_t LowIsZero(
        uint32_t word) const
    {
        return WordBase(word) +
            kWordBits + kHighAndPrefix;
    }
    [[nodiscard]] constexpr uint32_t LowInverse(
        uint32_t word) const
    {
        return LowIsZero(word) + 1;
    }
    [[nodiscard]] constexpr uint32_t Valid(
        uint32_t word) const
    {
        return LowInverse(word) + 1;
    }
    [[nodiscard]] constexpr uint32_t CountBefore(
        uint32_t word, uint32_t count) const
    {
        return Valid(word) + 1 + count;
    }
    [[nodiscard]] constexpr uint32_t End() const
    {
        return selected + 1;
    }
};

struct WitnessV1 {
    LayoutV1 layout;
    std::array<uint64_t, kCandidateWords> words{};
    gf::Fp3 selected_value{};
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    uint32_t accepted_words{0};
    bool first_three_selection_constrained{false};
    bool fewer_than_three_rejects{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] bool BuildConstraintSystemV1(
    uint32_t n_rows,
    aq::AirConstraintSystem<gf::Fp3>& out,
    std::string* why = nullptr);

[[nodiscard]] WitnessV1 BuildWitnessV1(
    const std::array<uint64_t, kCandidateWords>& words);

[[nodiscard]] uint32_t CountViolationsV1(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns);

/**
 * Exact V5 power-of-two query-index decoder.
 *
 * ChallengeIndexUniform reads the first four SHA256d bytes as one
 * little-endian uint32 and returns raw & (n_lde - 1).  Since n_lde is a
 * power of two, the AIR form is exactly the sum of the low log2(n_lde)
 * boolean bits.  The 32 digest bits remain explicit columns so the recursive
 * parent can equality-link them directly to the SHA output-bit exports.
 */
inline constexpr uint32_t kQueryDigestBits = 32;

struct QueryIndexLayoutV1 {
    uint32_t bit_base{0};
    uint32_t output{32};

    explicit constexpr QueryIndexLayoutV1(
        uint32_t start = 0)
        : bit_base(start),
          output(start + kQueryDigestBits)
    {
    }

    [[nodiscard]] constexpr uint32_t Bit(
        uint32_t bit) const
    {
        return bit_base + bit;
    }
    [[nodiscard]] constexpr uint32_t End() const
    {
        return output + 1;
    }
};

struct QueryIndexWitnessV1 {
    QueryIndexLayoutV1 layout;
    uint32_t raw{0};
    uint32_t modulus{0};
    uint32_t domain_bits{0};
    uint32_t query_index{0};
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    bool digest_bits_boolean{false};
    bool power_of_two_mask_constrained{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] bool BuildQueryIndexConstraintSystemV1(
    uint32_t n_rows,
    uint32_t modulus,
    aq::AirConstraintSystem<gf::Fp3>& out,
    std::string* why = nullptr);

[[nodiscard]] QueryIndexWitnessV1
BuildQueryIndexWitnessV1(
    const std::array<unsigned char, 4>& digest_prefix,
    uint32_t modulus);

/**
 * Direct byte->Fp3 challenge decoder (the FromChallengeBytes3 map): the
 * non-OOD, non-query challenges (airq-lambda, lambda, w1, w2, fold-beta) read
 * 24 SHA-output bytes as three little-endian uint64 words, each reduced mod p,
 * forming the challenge (w0, w1, w2) over the Fp3 basis {1, X, X^2}.  No
 * rejection sampling: it is exactly the recompose step the OOD/query decoders
 * contain.  Recompose is done in Fp arithmetic, which auto-reduces mod p, so
 * word_j = sum b[8j+i]*256^i (Fp) == FromChallengeBytes3's w_j % p; the Fp3 is
 * word0*1 + word1*X + word2*X^2.  The 24 byte columns are the seam the Edge-2
 * CTL binds to the committed SHA output-byte cells.
 */
struct DirectChallengeLayoutV1 {
    static constexpr uint32_t kBytes = 24;
    [[nodiscard]] constexpr uint32_t Byte(uint32_t i) const { return i; }
    [[nodiscard]] constexpr uint32_t Word(uint32_t j) const
    {
        return kBytes + j;
    }
    [[nodiscard]] constexpr uint32_t Challenge() const { return kBytes + 3; }
    [[nodiscard]] constexpr uint32_t End() const { return kBytes + 4; }
};

struct DirectChallengeWitnessV1 {
    DirectChallengeLayoutV1 layout;
    gf::Fp3 value{};
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    bool recompose_constrained{false};
    bool basis_reconstruction_constrained{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] DirectChallengeWitnessV1
BuildDirectChallengeWitnessV1(
    const std::array<unsigned char, 24>& bytes);

// ===========================================================================
// PR-89 Construction 2: in-AIR replay of the ALGEBRAIC (Poseidon2) query-index
// rule.  NOT ACTIVATED -- nothing in the protocol calls this, and no *_ready
// or k*Executable constant is flipped by it.  It exists so that the cost and
// the DIVERGENCE RISK of activating Fri3AlgAlgebraicQueryIndex are measurable
// instead of assumed.
//
// The shipped SHA rule is
//   index_j = LE32(SHA256d(fs || draw_domain || "fra3_query" || j)[0..4))
//             & (n_lde - 1)
// and its in-AIR half is BuildQueryIndexWitnessV1 above: 32 boolean bit
// columns fed from DIGEST BYTES, plus the power-of-two mask.
//
// The algebraic rule is
//   index_j = LE32(Canonical(Poseidon2(idx_domain || sigma || j)[0]))
//             & (n_lde - 1).
//
// THE SHAPE IS NOT THE SAME, and the difference is a soundness hole if it is
// glossed over.  The SHA chip's source is a byte string: "the first four
// bytes" is well defined and the remaining 28 bytes are irrelevant.  The
// algebraic chip's source is a GOLDILOCKS FIELD ELEMENT, which has no
// intrinsic 32-bit prefix.  Pinning only 32 bit columns and calling them
// "the low half of lane0" constrains nothing: the prover chooses the columns.
// The replay must therefore
//   (1) decompose the FULL 64 bits of the witnessed lane,
//   (2) recompose and equate to the lane value (binding the bits to lane0),
//   (3) enforce Goldilocks CANONICITY -- NOT(high32 all ones AND low32 != 0)
//       -- or the prover may present B = lane0 + p, whose low 32 bits differ,
//       and retarget the query index for free,
//   (4) and only then apply the power-of-two mask.
// (3) is the same vacuity trap documented at the tax predicate in
// matmul_v4_rc_fri_ext3_alg.h; it bites here for the same reason.
//
// What this chip does NOT do: it does not constrain that `lane` really is the
// Poseidon2 output.  That is the permutation half, and its cost is reported
// separately by MeasureAlgebraicQueryIndexReplayCostV1.
// ===========================================================================

/** Full 64-bit canonical decomposition + power-of-two mask. */
inline constexpr uint32_t kAlgebraicQueryLaneBits = 64;
inline constexpr uint32_t kAlgebraicQueryHighBits = 32;
inline constexpr uint32_t kAlgebraicQueryAndChunk = 6; // alg_degree 7
inline constexpr uint32_t kAlgebraicQueryAndSteps =
    (kAlgebraicQueryHighBits + kAlgebraicQueryAndChunk - 1) /
    kAlgebraicQueryAndChunk;

struct AlgebraicQueryIndexLayoutV1 {
    [[nodiscard]] constexpr uint32_t Bit(uint32_t bit) const { return bit; }
    [[nodiscard]] constexpr uint32_t Lane() const
    {
        return kAlgebraicQueryLaneBits;
    }
    [[nodiscard]] constexpr uint32_t And(uint32_t step) const
    {
        return Lane() + 1 + step;
    }
    [[nodiscard]] constexpr uint32_t Output() const
    {
        return And(kAlgebraicQueryAndSteps);
    }
    [[nodiscard]] constexpr uint32_t End() const { return Output() + 1; }
};

struct AlgebraicQueryIndexAirV1 {
    AlgebraicQueryIndexLayoutV1 layout;
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    uint32_t n_rows{0};
    uint32_t n_columns{0};
    uint32_t n_constraints{0};
    uint32_t max_alg_degree{0};
    uint32_t domain_bits{0};
    uint32_t violations{1};
    /** What the PROTOCOL function Fri3AlgAlgebraicQueryIndex returns. */
    uint32_t protocol_index{0};
    /** What this constraint system's output column actually carries. */
    uint32_t witness_index{0};
    bool booleanity_constrained{false};
    bool recomposition_constrained{false};
    bool canonicity_constrained{false};
    bool mask_constrained{false};
    /** The divergence check: protocol_index == witness_index. */
    bool matches_protocol{false};
    bool valid{false};
    std::string note;
};

/**
 * Chip half: replay the mask over an ARBITRARY lane value, with no protocol
 * derivation.  `use_aliased_witness` supplies B = lane0 + p instead of the
 * canonical decomposition -- the witness an attacker retargeting the index
 * would use; the canonicity constraints must reject it.  It only exists for
 * lane0 < 2^32 - 1, and the builder reports that rather than pretending.
 * `forced_index`, when not UINT32_MAX, overwrites the output column with an
 * attacker-chosen index so a test can observe the mask constraint rejecting
 * it rather than assuming it would.  protocol_index / matches_protocol are
 * NOT meaningful on this entry point.
 */
[[nodiscard]] AlgebraicQueryIndexAirV1 BuildAlgebraicQueryIndexAirFromLaneV1(
    gf::Fp lane0,
    uint32_t n_lde,
    bool use_aliased_witness = false,
    uint32_t forced_index = UINT32_MAX);

/**
 * Protocol half: derive the lane exactly as Fri3AlgAlgebraicQueryIndex does,
 * run the chip on it, and CROSS-CHECK the chip's output column against the
 * shipped protocol function.  `matches_protocol` is the divergence detector:
 * if either side is edited without the other, it goes false while both
 * halves still look internally consistent.
 */
[[nodiscard]] AlgebraicQueryIndexAirV1 BuildAlgebraicQueryIndexAirV1(
    const std::array<gf::Fp, 4>& sigma,
    uint32_t j,
    uint32_t n_lde,
    bool use_aliased_witness = false,
    uint32_t forced_index = UINT32_MAX);

/**
 * In-AIR replay cost of ONE challenge kind -- fra3_query -- under both rules.
 *
 * Algebraic side: MEASURED.  The permutation count comes from running the
 * real sponge padding rule, and the per-permutation AIR shape comes from
 * stage3_poseidon_air::Measure, which is the executable decomposed table
 * (one permutation per ROW).
 *
 * SHA side: COMPUTED from the shipped transcript layout -- preimage >= 52*W
 * bytes, compressions = ceil((52W + 9)/64) + 1, and the vertical SHA AIR's
 * n_rows = next_pow2(compressions) * 1024.  It is width-proportional; the
 * algebraic side is not.
 */
struct AlgebraicQueryIndexReplayCostV1 {
    uint32_t queries{0};
    uint32_t child_w{0};
    // --- algebraic (Poseidon2) route
    uint32_t alg_permutations_per_index{0};
    uint64_t alg_permutations{0};
    uint64_t alg_poseidon_rows{0};
    uint32_t alg_poseidon_columns{0};
    uint32_t alg_poseidon_max_degree{0};
    uint64_t alg_mask_rows{0};
    uint32_t alg_mask_columns{0};
    uint64_t alg_total_rows{0};
    bool alg_width_independent{false};
    // --- shipped SHA route, same query count, at child width W
    uint64_t sha_preimage_bytes{0};
    uint64_t sha_compressions_per_index{0};
    uint64_t sha_rows_per_index{0};
    uint64_t sha_total_rows{0};
    bool valid{false};
    std::string note;
};

[[nodiscard]] AlgebraicQueryIndexReplayCostV1
MeasureAlgebraicQueryIndexReplayCostV1(uint32_t queries, uint32_t child_w);

/** Built and measurable, but consumed by NOTHING on any protocol path. */
inline constexpr bool kAlgebraicQueryIndexAirExecutableV1 = true;
inline constexpr bool kAlgebraicQueryIndexActivatedV1 = false;
static_assert(!kAlgebraicQueryIndexActivatedV1,
              "Construction 2's index rule is not on any protocol path; see "
              "the activation analysis in the .cpp");

inline constexpr bool kUniformFp3SelectionAirExecutableV1 = true;
inline constexpr bool kPowerOfTwoQueryIndexAirExecutableV1 = true;
inline constexpr bool kUniformFp3SelectionRecursiveAuthorityV1 = false;
static_assert(kUniformFp3SelectionAirExecutableV1);
static_assert(kPowerOfTwoQueryIndexAirExecutableV1);
static_assert(!kUniformFp3SelectionRecursiveAuthorityV1);

// ===========================================================================
// PR-89 g4: the ROW-WISE child-challenge decoder table.
//
// The decoders that already exist here (BuildDirectChallengeWitnessV1,
// BuildQueryIndexWitnessV1, BuildAlgebraicQueryIndexAirFromLaneV1) each occupy
// a WHOLE constraint system for ONE challenge: their columns are constant down
// every row.  A recursion parent must decode every challenge of every child --
// for the shipped Q192 single-lane child that is 1 airq_lambda + 1 fra3_lambda
// + (>= 2) fra3_z + 2 fra3_w + n_folds fra3_fold + 192 fra3_query draws, times
// four slots.  One CS per draw does not fit any parent: at ~100 columns each,
// 4 x ~200 draws is ~80k columns against a 32768 column cap.
//
// This table transposes that.  ONE ROW PER CHALLENGE DRAW, uniform layout, all
// constraints kEverywhere -- the same structural move that makes the Poseidon2
// chip (1 row per permutation) affordable where the vertical SHA chip (1024
// rows per compression) is not.  Rows scale with the draw count; columns do
// not.
//
// WHAT ONE ROW CONSTRAINS
//   (a) word_j  - sum_i byte[8j+i]*256^i          = 0    (three lanes)
//   (b) chal    - (word0 + word1*X + word2*X^2)   = 0    (FromChallengeBytes3)
//   (c) chal    - consumed                        = 0    (the binding)
//   (d) 64 boolean bit columns, recomposed to word0, plus the Goldilocks
//       canonicity predicate NOT(high32 all ones AND low32 != 0)
//   (e) is_query * (index - sum_{b<domain_bits} bit_b * 2^b) = 0
//   (f) is_query * (index - consumed_index)       = 0
//       (1 - is_query) * index                    = 0
//
// (d)+(e) are the SHIPPED V3 query-index rule, not the Construction-2 one:
//   ProtocolChallengeIndex's non-uniform branch computes
//     out = ((Canonical(c1) << 64) | Canonical(c0)) % n_lde
//   and n_lde is a power of two dividing 2^64, so the c1 term vanishes and the
//   rule is exactly the low log2(n_lde) bits of Canonical(c0).  c0 IS a
//   Goldilocks field element, so the canonicity trap documented above for the
//   algebraic chip bites here for the same reason and is enforced the same way.
//   Fri3AlgV3QueryIndexFromChallengeV1 recomputes the 128-bit modulo form
//   independently so the two can be cross-checked rather than assumed equal.
//
// WHAT ONE ROW DOES *NOT* CONSTRAIN.  The 24 digest bytes are PREPROCESSED
// (public) cells.  Nothing here says they are SHA256d(child transcript); that
// is the companion-hash half, and for every kind except airq_lambda it is
// still open.  A table with zero violations therefore proves "the parent's
// decode of these pinned bytes is the value the in-parent verifier consumes",
// not "these bytes are the child's real transcript".  Do not read the two as
// the same claim.
// ===========================================================================

/** One decoded challenge draw = one table row. */
struct ChallengeTableRowV1 {
    std::array<unsigned char, 24> digest_bytes{};
    /** The value the in-parent verifier actually consumes for this draw. */
    gf::Fp3 consumed{};
    /** fra3_query rows only: the index the child's proof actually carries. */
    uint32_t consumed_index{0};
    bool is_query{false};
    /** Free-form kind tag, carried through for reporting only. */
    uint32_t kind{0};
};

inline constexpr uint32_t kChallengeTableBytes = 24;
inline constexpr uint32_t kChallengeTableLaneBits = kAlgebraicQueryLaneBits;
inline constexpr uint32_t kChallengeTableAndSteps = kAlgebraicQueryAndSteps;

struct ChallengeTableLayoutV1 {
    [[nodiscard]] constexpr uint32_t Byte(uint32_t i) const { return i; }
    [[nodiscard]] constexpr uint32_t Word(uint32_t j) const
    {
        return kChallengeTableBytes + j;
    }
    [[nodiscard]] constexpr uint32_t Challenge() const
    {
        return kChallengeTableBytes + 3;
    }
    [[nodiscard]] constexpr uint32_t Consumed() const
    {
        return kChallengeTableBytes + 4;
    }
    [[nodiscard]] constexpr uint32_t IsQuery() const
    {
        return kChallengeTableBytes + 5;
    }
    [[nodiscard]] constexpr uint32_t Bit(uint32_t b) const
    {
        return kChallengeTableBytes + 6 + b;
    }
    [[nodiscard]] constexpr uint32_t And(uint32_t step) const
    {
        return Bit(kChallengeTableLaneBits) + step;
    }
    [[nodiscard]] constexpr uint32_t Index() const
    {
        return And(kChallengeTableAndSteps);
    }
    [[nodiscard]] constexpr uint32_t ConsumedIndex() const
    {
        return Index() + 1;
    }
    [[nodiscard]] constexpr uint32_t End() const
    {
        return ConsumedIndex() + 1;
    }
};

struct ChallengeTableAirV1 {
    ChallengeTableLayoutV1 layout;
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    uint32_t n_draws{0};
    uint32_t n_rows{0};
    uint32_t n_columns{0};
    uint32_t n_constraints{0};
    uint32_t max_alg_degree{0};
    uint32_t n_lde{0};
    uint32_t domain_bits{0};
    uint32_t violations{1};
    /** Per-row: the decode reproduced the supplied `consumed` value. */
    uint32_t rows_bound_to_consumed{0};
    /** Per-row (query rows only): the mask reproduced `consumed_index`. */
    uint32_t query_rows_bound_to_consumed_index{0};
    uint32_t query_rows{0};
    bool recompose_constrained{false};
    bool basis_reconstruction_constrained{false};
    bool bound_to_consumed_constrained{false};
    bool booleanity_constrained{false};
    bool canonicity_constrained{false};
    bool mask_constrained{false};
    bool valid{false};
    std::string note;
};

/**
 * The SHIPPED V3 query-index rule, recomputed here INDEPENDENTLY of
 * fri_ext3_alg's ProtocolChallengeIndex so the in-AIR mask can be cross-checked
 * against it rather than against itself.  Returns
 *   ((Canonical(c1) << 64) | Canonical(c0)) % modulus
 * for any modulus > 0 (the 128-bit form, not the mask shortcut).
 */
[[nodiscard]] uint32_t Fri3AlgV3QueryIndexFromChallengeV1(
    const gf::Fp3& challenge, uint32_t modulus);

/**
 * Build the row-wise table over `draws`.  `n_lde` is the child's LDE domain
 * size and MUST be a power of two (the shipped rule's own precondition).
 * `forced_row` / `forced_challenge`, when forced_row != UINT32_MAX, overwrite
 * that row's challenge column with an attacker-chosen value so a test can
 * observe the constraints rejecting it rather than assume they would.
 */
[[nodiscard]] ChallengeTableAirV1 BuildChallengeTableAirV1(
    const std::vector<ChallengeTableRowV1>& draws,
    uint32_t n_lde,
    uint32_t forced_row = std::numeric_limits<uint32_t>::max(),
    const gf::Fp3& forced_challenge = gf::Fp3{});

/**
 * PR-89 g4, the obligation the SHORT-FS lane (proof version 7,
 * kRCFri3AlgShortFsActivatedV1 = false) hands to the parent.
 *
 * Committing the two OOD evaluation vectors removes the 48*W-byte absorb from
 * EVERY challenge preimage, but the commitment binds nothing in-circuit unless
 * the parent RECOMPUTES Fri3AlgOodEvalCommit in-AIR over all 2W cells.  That
 * recompute happens ONCE, not once per challenge -- which is the whole saving.
 *
 * COMPUTED here from the shipped preimage layout and the real sponge padding
 * rule rather than adopted from the transcript lane's figure, so the two are
 * cross-checked.  Preimage lanes (fri_ext3_alg.h Fri3AlgOodEvalCommit):
 *   |e1| | |e2| | z1.c0,c1,c2 | z2.c0,c1,c2 | e1[i].{c0,c1,c2} | e2[i].{c0,c1,c2}
 * = 8 + 6W lanes, absorbed at rate kAlgHashRate with injective 10* padding,
 * one Poseidon2 permutation per rate block and ONE ROW per permutation.
 */
struct OodEvalCommitReplayCostV1 {
    uint32_t child_w{0};
    uint64_t preimage_lanes{0};
    uint64_t permutations{0};
    uint64_t poseidon_rows{0};
    uint32_t poseidon_columns{0};
    uint32_t poseidon_max_degree{0};
    /** What the legacy 48*W-byte absorb cost in SHA compressions, PER
     *  CHALLENGE, for the same vectors: 48*W/64 = 0.75*W. */
    uint64_t legacy_sha_compressions_per_challenge{0};
    uint64_t legacy_sha_rows_per_challenge{0};
    bool valid{false};
    std::string note;
};

[[nodiscard]] OodEvalCommitReplayCostV1
MeasureOodEvalCommitReplayCostV1(uint32_t child_w);

/** Built and exercised; consumed by the g4 coverage assessor, not by consensus. */
inline constexpr bool kChallengeTableAirExecutableV1 = true;
inline constexpr bool kChallengeTableRecursiveAuthorityV1 = false;
static_assert(kChallengeTableAirExecutableV1);
static_assert(!kChallengeTableRecursiveAuthorityV1,
              "the decoder table binds pinned digest bytes to consumed "
              "challenges; it is not a transcript-provenance proof");

} // namespace matmul::v4::rc::stage3_fs_selection_air

#endif
