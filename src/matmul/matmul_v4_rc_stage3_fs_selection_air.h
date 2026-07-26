// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_FS_SELECTION_AIR_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_FS_SELECTION_AIR_H

#include <matmul/matmul_v4_rc_air_quotient.h>

#include <array>
#include <cstdint>
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

inline constexpr bool kUniformFp3SelectionAirExecutableV1 = true;
inline constexpr bool kPowerOfTwoQueryIndexAirExecutableV1 = true;
inline constexpr bool kUniformFp3SelectionRecursiveAuthorityV1 = false;
static_assert(kUniformFp3SelectionAirExecutableV1);
static_assert(kPowerOfTwoQueryIndexAirExecutableV1);
static_assert(!kUniformFp3SelectionRecursiveAuthorityV1);

} // namespace matmul::v4::rc::stage3_fs_selection_air

#endif
