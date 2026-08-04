// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_alg_hash_wide.h>

#include <matmul/matmul_v4_rc_fri_ext3.h>

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstring>
#include <utility>

namespace matmul::v4::rc::alg_hash_wide {
namespace {

namespace gf = gkr_field;

using gf::Add;
using gf::Canonical;
using gf::Inv;
using gf::kP;
using gf::Mul;
using gf::Sub;

constexpr uint32_t kHalfFull = kWideFullRounds / 2;

void AppendLE32(std::vector<unsigned char>& out, uint32_t value)
{
    for (uint32_t i = 0; i < 4; ++i) {
        out.push_back(static_cast<unsigned char>((value >> (8 * i)) & 0xff));
    }
}

void AppendLE64(std::vector<unsigned char>& out, uint64_t value)
{
    for (uint32_t i = 0; i < 8; ++i) {
        out.push_back(static_cast<unsigned char>((value >> (8 * i)) & 0xff));
    }
}

void AppendLabel(std::vector<unsigned char>& out, const char* label)
{
    const size_t size = std::strlen(label);
    out.insert(out.end(),
               reinterpret_cast<const unsigned char*>(label),
               reinterpret_cast<const unsigned char*>(label) + size);
}

[[nodiscard]] std::vector<unsigned char> Tagged(const char* label)
{
    std::vector<unsigned char> out;
    AppendLabel(out, kWideDomainTag);
    AppendLabel(out, label);
    return out;
}

template <typename Predicate>
[[nodiscard]] Fp SampleFpFiltered(
    const std::vector<unsigned char>& tag, Predicate accept)
{
    // Since p is the largest integer below 2^64 with the Goldilocks form,
    // rejection at w >= p is unbiased and occurs with probability about 2^-32.
    for (uint32_t counter = 0;; ++counter) {
        std::vector<unsigned char> input = tag;
        AppendLE32(input, counter);
        const uint256 hash =
            ::matmul::v4::rc::Sha256dBytes(
                input.data(), input.size());
        uint64_t word = 0;
        for (uint32_t i = 0; i < 8; ++i) {
            word |= static_cast<uint64_t>(hash.data()[i]) << (8 * i);
        }
        if (word < kP && accept(static_cast<Fp>(word))) {
            return static_cast<Fp>(word);
        }
    }
}

[[nodiscard]] Fp SampleFp(const std::vector<unsigned char>& tag)
{
    return SampleFpFiltered(tag, [](Fp) { return true; });
}

[[nodiscard]] Constants GenerateConstants()
{
    Constants constants;
    for (uint32_t round = 0; round < kWideFullRounds; ++round) {
        for (uint32_t lane = 0; lane < kWideT; ++lane) {
            std::vector<unsigned char> tag = Tagged("RCE");
            AppendLE32(tag, round);
            AppendLE32(tag, lane);
            constants.rc_ext[round][lane] = SampleFp(tag);
        }
    }
    for (uint32_t round = 0; round < kWidePartialRounds; ++round) {
        std::vector<unsigned char> tag = Tagged("RCI");
        AppendLE32(tag, round);
        constants.rc_int[round] = SampleFp(tag);
    }
    for (uint32_t lane = 0; lane < kWideT; ++lane) {
        std::vector<unsigned char> tag = Tagged("MU");
        AppendLE32(tag, lane);
        // J + diag(mu) has paper-diagonal 1+mu.  Excluding 0 and -1
        // therefore excludes paper-diagonal 1 and 0.
        constants.mu[lane] = SampleFpFiltered(
            tag, [](Fp value) {
                return value != 0 && value != kP - 1;
            });
    }
    constants.node_domain = SampleFp(Tagged("NODE"));
    constants.row_domain = SampleFp(Tagged("ROW"));
    constants.transcript_domain = SampleFp(Tagged("TRANSCRIPT"));
    assert(constants.node_domain != constants.row_domain);
    assert(constants.node_domain != constants.transcript_domain);
    assert(constants.row_domain != constants.transcript_domain);

    // Matrix determinant lemma:
    // det(J + diag(mu)) = product(mu_i) * (1 + sum(1/mu_i)).
    Fp determinant = 1;
    Fp correction = 1;
    for (const Fp mu : constants.mu) {
        determinant = Mul(determinant, mu);
        correction = Add(correction, Inv(mu));
    }
    assert(Mul(determinant, correction) != 0);
    return constants;
}

[[nodiscard]] Fp Pow7(Fp value)
{
    const Fp square = Mul(value, value);
    const Fp cube = Mul(square, value);
    const Fp fourth = Mul(square, square);
    return Mul(fourth, cube);
}

[[nodiscard]] Fp PowMod(Fp base, uint64_t exponent)
{
    Fp result = 1;
    Fp power = Canonical(base);
    while (exponent != 0) {
        if (exponent & 1u) result = Mul(result, power);
        power = Mul(power, power);
        exponent >>= 1;
    }
    return result;
}

[[nodiscard]] uint64_t InverseSboxExponent()
{
    const unsigned __int128 modulus = kP - 1;
    __int128 old_r = 7;
    __int128 r = static_cast<__int128>(modulus);
    __int128 old_s = 1;
    __int128 s = 0;
    while (r != 0) {
        const __int128 quotient = old_r / r;
        const __int128 next_r = old_r - quotient * r;
        old_r = r;
        r = next_r;
        const __int128 next_s = old_s - quotient * s;
        old_s = s;
        s = next_s;
    }
    assert(old_r == 1);
    if (old_s < 0) old_s += static_cast<__int128>(modulus);
    return static_cast<uint64_t>(old_s);
}

constexpr Fp kM4[4][4] = {
    {5, 7, 1, 3},
    {4, 6, 1, 1},
    {1, 3, 5, 7},
    {1, 1, 4, 6},
};

void ApplyM4(Fp* block)
{
    std::array<Fp, 4> result{};
    for (uint32_t row = 0; row < 4; ++row) {
        for (uint32_t column = 0; column < 4; ++column) {
            result[row] =
                Add(result[row], Mul(kM4[row][column], block[column]));
        }
    }
    for (uint32_t lane = 0; lane < 4; ++lane) block[lane] = result[lane];
}

using Matrix =
    std::array<std::array<Fp, kWideT>, kWideT>;

template <typename Layer>
[[nodiscard]] Matrix MatrixOfLayer(Layer layer)
{
    Matrix matrix{};
    for (uint32_t column = 0; column < kWideT; ++column) {
        State basis{};
        basis[column] = 1;
        layer(basis);
        for (uint32_t row = 0; row < kWideT; ++row) {
            matrix[row][column] = basis[row];
        }
    }
    return matrix;
}

[[nodiscard]] bool TryInvert(const Matrix& input, Matrix* inverse_out)
{
    Matrix matrix = input;
    Matrix inverse{};
    for (uint32_t i = 0; i < kWideT; ++i) inverse[i][i] = 1;
    for (uint32_t column = 0; column < kWideT; ++column) {
        uint32_t pivot = column;
        while (pivot < kWideT &&
               Canonical(matrix[pivot][column]) == 0) {
            ++pivot;
        }
        if (pivot == kWideT) return false;
        std::swap(matrix[pivot], matrix[column]);
        std::swap(inverse[pivot], inverse[column]);
        const Fp inverse_pivot = Inv(matrix[column][column]);
        for (uint32_t j = 0; j < kWideT; ++j) {
            matrix[column][j] =
                Mul(matrix[column][j], inverse_pivot);
            inverse[column][j] =
                Mul(inverse[column][j], inverse_pivot);
        }
        for (uint32_t row = 0; row < kWideT; ++row) {
            if (row == column ||
                Canonical(matrix[row][column]) == 0) {
                continue;
            }
            const Fp factor = matrix[row][column];
            for (uint32_t j = 0; j < kWideT; ++j) {
                matrix[row][j] =
                    Sub(matrix[row][j],
                        Mul(factor, matrix[column][j]));
                inverse[row][j] =
                    Sub(inverse[row][j],
                        Mul(factor, inverse[column][j]));
            }
        }
    }
    if (inverse_out != nullptr) *inverse_out = inverse;
    return true;
}

void ApplyMatrix(const Matrix& matrix, State& state)
{
    State result{};
    for (uint32_t row = 0; row < kWideT; ++row) {
        for (uint32_t column = 0; column < kWideT; ++column) {
            result[row] =
                Add(result[row],
                    Mul(matrix[row][column], state[column]));
        }
    }
    state = result;
}

struct InverseTables {
    Matrix external;
    Matrix internal;
    uint64_t sbox_exponent{0};
};

[[nodiscard]] const InverseTables& GetInverseTables()
{
    static const InverseTables tables = [] {
        InverseTables out;
        const bool external_ok = TryInvert(
            MatrixOfLayer([](State& state) {
                ApplyExternalMatrix(state);
            }),
            &out.external);
        const bool internal_ok = TryInvert(
            MatrixOfLayer([](State& state) {
                ApplyInternalMatrix(state);
            }),
            &out.internal);
        assert(external_ok);
        assert(internal_ok);
        out.sbox_exponent = InverseSboxExponent();
        return out;
    }();
    return tables;
}

[[nodiscard]] std::vector<Fp> EncodeMessage(
    const std::vector<Fp>& message, Fp domain)
{
    std::vector<Fp> encoded;
    encoded.reserve(message.size() + kWideRate + 1);
    encoded.push_back(Canonical(domain));
    for (const Fp value : message) {
        encoded.push_back(Canonical(value));
    }
    encoded.push_back(1);
    while (encoded.size() % kWideRate != 0) encoded.push_back(0);
    return encoded;
}

[[nodiscard]] Digest DigestOf(const State& state)
{
    Digest digest{};
    std::copy_n(state.begin(), kWideDigestLen, digest.begin());
    return digest;
}

[[nodiscard]] std::vector<Fp> FlattenChildren(
    const Digest& left, const Digest& right)
{
    std::vector<Fp> message;
    message.reserve(2 * kWideDigestLen);
    for (const Fp value : left) message.push_back(Canonical(value));
    for (const Fp value : right) message.push_back(Canonical(value));
    return message;
}

[[nodiscard]] bool EqualState(const State& left, const State& right)
{
    for (uint32_t lane = 0; lane < kWideT; ++lane) {
        if (Canonical(left[lane]) != Canonical(right[lane])) return false;
    }
    return true;
}

[[nodiscard]] bool EqualDigest(const Digest& left, const Digest& right)
{
    for (uint32_t lane = 0; lane < kWideDigestLen; ++lane) {
        if (Canonical(left[lane]) != Canonical(right[lane])) return false;
    }
    return true;
}

// -------------------------------------------------------------------------
// Reference internal-matrix parameter condition.
// -------------------------------------------------------------------------

using Polynomial = std::vector<Fp>; // ascending coefficient order

[[nodiscard]] Matrix MultiplyMatrix(
    const Matrix& left, const Matrix& right)
{
    Matrix product{};
    for (uint32_t row = 0; row < kWideT; ++row) {
        for (uint32_t inner = 0; inner < kWideT; ++inner) {
            if (Canonical(left[row][inner]) == 0) continue;
            for (uint32_t column = 0; column < kWideT; ++column) {
                product[row][column] = Add(
                    product[row][column],
                    Mul(left[row][inner], right[inner][column]));
            }
        }
    }
    return product;
}

[[nodiscard]] Matrix InternalMatrixOf(
    const std::array<Fp, kWideT>& mu)
{
    Matrix matrix{};
    for (uint32_t row = 0; row < kWideT; ++row) {
        for (uint32_t column = 0; column < kWideT; ++column) {
            matrix[row][column] = 1;
        }
        matrix[row][row] = Add(1, mu[row]);
    }
    return matrix;
}

/**
 * Faddeev-LeVerrier over Fp.  Since char(Fp) > 16, division by every
 * k=1..16 is defined.  Returns det(xI-A), ascending and monic.
 */
[[nodiscard]] Polynomial CharacteristicPolynomial(
    const Matrix& matrix)
{
    Matrix b{};
    for (uint32_t i = 0; i < kWideT; ++i) b[i][i] = 1;
    std::array<Fp, kWideT + 1> descending{};
    descending[0] = 1;
    for (uint32_t k = 1; k <= kWideT; ++k) {
        Matrix ab = MultiplyMatrix(matrix, b);
        Fp trace = 0;
        for (uint32_t i = 0; i < kWideT; ++i) {
            trace = Add(trace, ab[i][i]);
        }
        const Fp coefficient =
            Sub(0, Mul(trace, Inv(gf::FromU64(k))));
        descending[k] = coefficient;
        for (uint32_t i = 0; i < kWideT; ++i) {
            ab[i][i] = Add(ab[i][i], coefficient);
        }
        b = ab;
    }

    Polynomial out(kWideT + 1);
    for (uint32_t i = 0; i <= kWideT; ++i) {
        out[i] = descending[kWideT - i];
    }
    return out;
}

void TrimPolynomial(Polynomial& polynomial)
{
    while (polynomial.size() > 1 &&
           Canonical(polynomial.back()) == 0) {
        polynomial.pop_back();
    }
    if (polynomial.empty()) polynomial.push_back(0);
}

[[nodiscard]] bool IsZeroPolynomial(const Polynomial& polynomial)
{
    return polynomial.size() == 1 &&
           Canonical(polynomial[0]) == 0;
}

[[nodiscard]] Polynomial SubtractPolynomial(
    const Polynomial& left, const Polynomial& right)
{
    Polynomial out(std::max(left.size(), right.size()), 0);
    for (size_t i = 0; i < out.size(); ++i) {
        const Fp a = i < left.size() ? left[i] : 0;
        const Fp b = i < right.size() ? right[i] : 0;
        out[i] = Sub(a, b);
    }
    TrimPolynomial(out);
    return out;
}

[[nodiscard]] Polynomial PolynomialRemainder(
    Polynomial dividend, const Polynomial& divisor)
{
    TrimPolynomial(dividend);
    assert(!IsZeroPolynomial(divisor));
    const Fp inverse_lead = Inv(divisor.back());
    while (dividend.size() >= divisor.size() &&
           !IsZeroPolynomial(dividend)) {
        const size_t shift = dividend.size() - divisor.size();
        const Fp factor = Mul(dividend.back(), inverse_lead);
        for (size_t i = 0; i < divisor.size(); ++i) {
            dividend[shift + i] = Sub(
                dividend[shift + i], Mul(factor, divisor[i]));
        }
        TrimPolynomial(dividend);
    }
    return dividend;
}

[[nodiscard]] Polynomial MultiplyPolynomialMod(
    const Polynomial& left, const Polynomial& right,
    const Polynomial& modulus)
{
    Polynomial product(left.size() + right.size() - 1, 0);
    for (size_t i = 0; i < left.size(); ++i) {
        if (Canonical(left[i]) == 0) continue;
        for (size_t j = 0; j < right.size(); ++j) {
            product[i + j] = Add(
                product[i + j], Mul(left[i], right[j]));
        }
    }
    return PolynomialRemainder(std::move(product), modulus);
}

[[nodiscard]] Polynomial PowerPolynomialMod(
    Polynomial base, uint64_t exponent,
    const Polynomial& modulus)
{
    Polynomial result{1};
    base = PolynomialRemainder(std::move(base), modulus);
    while (exponent != 0) {
        if (exponent & 1u) {
            result = MultiplyPolynomialMod(
                result, base, modulus);
        }
        base = MultiplyPolynomialMod(base, base, modulus);
        exponent >>= 1;
    }
    return result;
}

[[nodiscard]] Polynomial GcdPolynomial(
    Polynomial left, Polynomial right)
{
    TrimPolynomial(left);
    TrimPolynomial(right);
    while (!IsZeroPolynomial(right)) {
        Polynomial remainder =
            PolynomialRemainder(left, right);
        left = std::move(right);
        right = std::move(remainder);
    }
    const Fp inverse_lead = Inv(left.back());
    for (Fp& coefficient : left) {
        coefficient = Mul(coefficient, inverse_lead);
    }
    TrimPolynomial(left);
    return left;
}

[[nodiscard]] bool EqualPolynomial(
    Polynomial left, Polynomial right)
{
    TrimPolynomial(left);
    TrimPolynomial(right);
    if (left.size() != right.size()) return false;
    for (size_t i = 0; i < left.size(); ++i) {
        if (Canonical(left[i]) != Canonical(right[i])) {
            return false;
        }
    }
    return true;
}

/**
 * Rabin irreducibility criterion specialized to degree 16.  The sole prime
 * divisor of 16 is 2, so require
 *   gcd(x^(p^8)-x, f)=1 and x^(p^16)-x=0 mod f.
 */
[[nodiscard]] bool IsIrreducibleDegree16(
    const Polynomial& polynomial)
{
    if (polynomial.size() != kWideT + 1 ||
        Canonical(polynomial.back()) != 1) {
        return false;
    }
    const Polynomial x{0, 1};
    Polynomial frobenius = x;
    for (uint32_t power = 1; power <= kWideT; ++power) {
        frobenius = PowerPolynomialMod(
            std::move(frobenius), kP, polynomial);
        if (power == kWideT / 2) {
            const Polynomial factor = GcdPolynomial(
                SubtractPolynomial(frobenius, x), polynomial);
            if (factor.size() != 1) return false;
        }
    }
    return EqualPolynomial(frobenius, x);
}

class ReferenceGrain
{
private:
    std::array<uint8_t, 80> m_state{};

    void AppendBits(
        size_t& position, uint32_t value, uint32_t width)
    {
        for (uint32_t bit = width; bit-- > 0;) {
            m_state[position++] =
                static_cast<uint8_t>((value >> bit) & 1u);
        }
    }

    [[nodiscard]] uint8_t Clock()
    {
        constexpr std::array<uint32_t, 6> taps{
            0, 13, 23, 38, 51, 62};
        uint8_t next = 0;
        for (const uint32_t tap : taps) next ^= m_state[tap];
        for (size_t i = 0; i + 1 < m_state.size(); ++i) {
            m_state[i] = m_state[i + 1];
        }
        m_state.back() = next;
        return next;
    }

    [[nodiscard]] uint8_t NextBit()
    {
        for (;;) {
            const uint8_t selector = Clock();
            const uint8_t value = Clock();
            if (selector == 1) return value;
        }
    }

public:
    ReferenceGrain()
    {
        size_t position = 0;
        AppendBits(position, 1, 2); // prime field
        AppendBits(position, 0, 4); // x^alpha S-box
        AppendBits(position, 64, 12);
        AppendBits(position, kWideT, 12);
        AppendBits(position, kWideFullRounds, 10);
        AppendBits(position, kWidePartialRounds, 10);
        while (position < m_state.size()) m_state[position++] = 1;
        for (uint32_t i = 0; i < 160; ++i) (void)Clock();
    }

    [[nodiscard]] Fp RandomFieldElement()
    {
        for (;;) {
            uint64_t value = 0;
            for (uint32_t bit = 0; bit < 64; ++bit) {
                value = (value << 1) | NextBit();
            }
            if (value < kP) return static_cast<Fp>(value);
        }
    }
};

[[nodiscard]] Constants GenerateReferenceRoundConstants()
{
    Constants constants;
    ReferenceGrain grain;
    for (uint32_t round = 0; round < kHalfFull; ++round) {
        for (uint32_t lane = 0; lane < kWideT; ++lane) {
            constants.rc_ext[round][lane] =
                grain.RandomFieldElement();
        }
    }
    for (uint32_t round = 0; round < kWidePartialRounds; ++round) {
        constants.rc_int[round] = grain.RandomFieldElement();
    }
    for (uint32_t round = 0; round < kHalfFull; ++round) {
        for (uint32_t lane = 0; lane < kWideT; ++lane) {
            constants.rc_ext[kHalfFull + round][lane] =
                grain.RandomFieldElement();
        }
    }
    return constants;
}

[[nodiscard]] const std::array<Fp, kWideT>&
Plonky3InternalMu()
{
    // Plonky3 MATRIX_DIAG_16_GOLDILOCKS: the diagonal added to the state
    // sum, i.e. mu in J+diag(mu), not the full diagonal 1+mu.
    static constexpr std::array<Fp, kWideT> mu{
        0xfffffffeffffffffULL,
        0x0000000000000001ULL,
        0x0000000000000002ULL,
        0x7fffffff80000001ULL,
        0x0000000000000003ULL,
        0x0000000000000004ULL,
        0x7fffffff80000000ULL,
        0xfffffffefffffffeULL,
        0xfffffffefffffffdULL,
        0xdfffffff20000001ULL,
        0xefffffff10000001ULL,
        0xf7ffffff08000001ULL,
        0x1fffffffe0000000ULL,
        0x0ffffffff0000000ULL,
        0x07fffffff8000000ULL,
        0xfffffffe00000002ULL,
    };
    return mu;
}

void ApplyInternalMatrixWithMu(
    State& state, const std::array<Fp, kWideT>& mu)
{
    Fp sum = 0;
    for (const Fp value : state) sum = Add(sum, value);
    for (uint32_t lane = 0; lane < kWideT; ++lane) {
        state[lane] = Add(sum, Mul(mu[lane], state[lane]));
    }
}

void ApplyPlonky3ExternalMatrix(State& state)
{
    // Plonky3's optimized MDSMat4, distinct from the paper/Horizen M4 used
    // by BTX above:
    // [2 3 1 1; 1 2 3 1; 1 1 2 3; 3 1 1 2].
    static constexpr Fp matrix[4][4] = {
        {2, 3, 1, 1},
        {1, 2, 3, 1},
        {1, 1, 2, 3},
        {3, 1, 1, 2},
    };
    for (uint32_t block = 0; block < 4; ++block) {
        std::array<Fp, 4> result{};
        for (uint32_t row = 0; row < 4; ++row) {
            for (uint32_t column = 0; column < 4; ++column) {
                result[row] = Add(
                    result[row],
                    Mul(
                        matrix[row][column],
                        state[4 * block + column]));
            }
        }
        for (uint32_t lane = 0; lane < 4; ++lane) {
            state[4 * block + lane] = result[lane];
        }
    }
    for (uint32_t lane = 0; lane < 4; ++lane) {
        Fp sum = 0;
        for (uint32_t block = 0; block < 4; ++block) {
            sum = Add(sum, state[4 * block + lane]);
        }
        for (uint32_t block = 0; block < 4; ++block) {
            state[4 * block + lane] =
                Add(state[4 * block + lane], sum);
        }
    }
}

void PermuteWithPlonky3Parameters(
    State& state, const Constants& constants,
    const std::array<Fp, kWideT>& mu)
{
    ApplyPlonky3ExternalMatrix(state);
    for (uint32_t round = 0; round < kHalfFull; ++round) {
        for (uint32_t lane = 0; lane < kWideT; ++lane) {
            state[lane] = Pow7(Add(
                state[lane], constants.rc_ext[round][lane]));
        }
        ApplyPlonky3ExternalMatrix(state);
    }
    for (uint32_t round = 0; round < kWidePartialRounds; ++round) {
        state[0] = Pow7(Add(state[0], constants.rc_int[round]));
        ApplyInternalMatrixWithMu(state, mu);
    }
    for (uint32_t round = 0; round < kHalfFull; ++round) {
        for (uint32_t lane = 0; lane < kWideT; ++lane) {
            state[lane] = Pow7(Add(
                state[lane],
                constants.rc_ext[kHalfFull + round][lane]));
        }
        ApplyPlonky3ExternalMatrix(state);
    }
}

[[nodiscard]] bool EqualRoundConstants(
    const Constants& left, const Constants& right)
{
    for (uint32_t round = 0; round < kWideFullRounds; ++round) {
        for (uint32_t lane = 0; lane < kWideT; ++lane) {
            if (Canonical(left.rc_ext[round][lane]) !=
                Canonical(right.rc_ext[round][lane])) {
                return false;
            }
        }
    }
    for (uint32_t round = 0; round < kWidePartialRounds; ++round) {
        if (Canonical(left.rc_int[round]) !=
            Canonical(right.rc_int[round])) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] uint256 RoundConstantsChecksum(
    const Constants& constants)
{
    std::vector<unsigned char> bytes;
    AppendLabel(
        bytes, "BTX_P2_T16_ROUND_CONSTANTS_AUDIT_V1");
    for (uint32_t round = 0; round < kHalfFull; ++round) {
        for (const Fp value : constants.rc_ext[round]) {
            AppendLE64(bytes, Canonical(value));
        }
    }
    for (const Fp value : constants.rc_int) {
        AppendLE64(bytes, Canonical(value));
    }
    for (uint32_t round = kHalfFull;
         round < kWideFullRounds; ++round) {
        for (const Fp value : constants.rc_ext[round]) {
            AppendLE64(bytes, Canonical(value));
        }
    }
    return ::matmul::v4::rc::Sha256dBytes(
        bytes.data(), bytes.size());
}

[[nodiscard]] bool ReferenceConstantPinsMatch(
    const Constants& constants)
{
    return
        constants.rc_ext[0][0] == 0x15ebea3fc73397c3ULL &&
        constants.rc_ext[3][15] == 0xed3fd595a3c0344aULL &&
        constants.rc_int[0] == 0x28eff4b01103d100ULL &&
        constants.rc_int[21] == 0xde884e9a17ced59eULL &&
        constants.rc_ext[4][0] == 0xdacf46dc1c31a045ULL &&
        constants.rc_ext[7][15] == 0x400d2bf56aa2a577ULL;
}

[[nodiscard]] bool ReferencePermutationKatMatches(
    const Constants& constants)
{
    State input{
        0x4d3f967fab9d4979ULL,
        0x57e1fba55677697eULL,
        0x57429a86e75a3774ULL,
        0x31d379f3a592b5ebULL,
        0x497232e1b648e3f1ULL,
        0x325a7db57173c39eULL,
        0xa802252d78bee916ULL,
        0x8920f55e154adef8ULL,
        0xa1225bc9c7913658ULL,
        0xd687be5097ffd038ULL,
        0x89f514ef0c913e48ULL,
        0x21fd4a9cf548cd84ULL,
        0x570a1586ada436ffULL,
        0x46bfbf38ccd740aeULL,
        0x23651b3f3ab26484ULL,
        0xe90f3b02127fa552ULL,
    };
    static constexpr State expected{
        0xf0f7717837c7032aULL,
        0xf12fbcc838feb15bULL,
        0xd8661f6fa4165ad8ULL,
        0x351cdc546760d1a9ULL,
        0x99474334bf02445fULL,
        0x46fc4e9ceb376d6aULL,
        0x4601808321fcd920ULL,
        0xc58bfd0342dc60dfULL,
        0xb7f3acd43f3c029cULL,
        0x5c7afa6a6997dfc5ULL,
        0xecbef8b82906c887ULL,
        0xd490e3b4e945d87cULL,
        0x31866766b83ebe0bULL,
        0xb32d52f6e7a5bea2ULL,
        0x9522431667b3c5f9ULL,
        0xeaf5638a69518f65ULL,
    };
    PermuteWithPlonky3Parameters(
        input, constants, Plonky3InternalMu());
    return EqualState(input, expected);
}

} // namespace

const Constants& GetConstants()
{
    static const Constants constants = GenerateConstants();
    return constants;
}

uint256 ConstantsChecksum()
{
    const Constants& constants = GetConstants();
    std::vector<unsigned char> bytes;
    AppendLabel(bytes, kWideDomainTag);
    for (const auto& round : constants.rc_ext) {
        for (const Fp value : round) {
            AppendLE64(bytes, Canonical(value));
        }
    }
    for (const Fp value : constants.rc_int) {
        AppendLE64(bytes, Canonical(value));
    }
    for (const Fp value : constants.mu) {
        AppendLE64(bytes, Canonical(value));
    }
    AppendLE64(bytes, Canonical(constants.node_domain));
    AppendLE64(bytes, Canonical(constants.row_domain));
    AppendLE64(bytes, Canonical(constants.transcript_domain));
    return ::matmul::v4::rc::Sha256dBytes(
        bytes.data(), bytes.size());
}

void ApplyExternalMatrix(State& state)
{
    // Poseidon2 t=16: circ(2*M4,M4,M4,M4).  If y_b=M4*x_b and
    // sigma=sum_b(y_b), output block b is y_b+sigma.
    for (uint32_t block = 0; block < 4; ++block) {
        ApplyM4(&state[4 * block]);
    }
    for (uint32_t lane = 0; lane < 4; ++lane) {
        Fp sum = 0;
        for (uint32_t block = 0; block < 4; ++block) {
            sum = Add(sum, state[4 * block + lane]);
        }
        for (uint32_t block = 0; block < 4; ++block) {
            state[4 * block + lane] =
                Add(state[4 * block + lane], sum);
        }
    }
}

void ApplyInternalMatrix(State& state)
{
    const Constants& constants = GetConstants();
    Fp sum = 0;
    for (const Fp value : state) sum = Add(sum, value);
    for (uint32_t lane = 0; lane < kWideT; ++lane) {
        state[lane] =
            Add(sum, Mul(constants.mu[lane], state[lane]));
    }
}

void Permute(State& state)
{
    const Constants& constants = GetConstants();
    ApplyExternalMatrix(state);
    for (uint32_t round = 0; round < kHalfFull; ++round) {
        for (uint32_t lane = 0; lane < kWideT; ++lane) {
            state[lane] =
                Pow7(Add(state[lane],
                         constants.rc_ext[round][lane]));
        }
        ApplyExternalMatrix(state);
    }
    for (uint32_t round = 0; round < kWidePartialRounds; ++round) {
        state[0] =
            Pow7(Add(state[0], constants.rc_int[round]));
        ApplyInternalMatrix(state);
    }
    for (uint32_t round = 0; round < kHalfFull; ++round) {
        for (uint32_t lane = 0; lane < kWideT; ++lane) {
            state[lane] =
                Pow7(Add(state[lane],
                         constants.rc_ext[kHalfFull + round][lane]));
        }
        ApplyExternalMatrix(state);
    }
}

void InversePermute(State& state)
{
    const Constants& constants = GetConstants();
    const InverseTables& inverse = GetInverseTables();
    for (uint32_t round = kHalfFull; round-- > 0;) {
        ApplyMatrix(inverse.external, state);
        for (uint32_t lane = 0; lane < kWideT; ++lane) {
            state[lane] = Sub(
                PowMod(state[lane], inverse.sbox_exponent),
                constants.rc_ext[kHalfFull + round][lane]);
        }
    }
    for (uint32_t round = kWidePartialRounds; round-- > 0;) {
        ApplyMatrix(inverse.internal, state);
        state[0] = Sub(
            PowMod(state[0], inverse.sbox_exponent),
            constants.rc_int[round]);
    }
    for (uint32_t round = kHalfFull; round-- > 0;) {
        ApplyMatrix(inverse.external, state);
        for (uint32_t lane = 0; lane < kWideT; ++lane) {
            state[lane] = Sub(
                PowMod(state[lane], inverse.sbox_exponent),
                constants.rc_ext[round][lane]);
        }
    }
    ApplyMatrix(inverse.external, state);
}

Digest SpongeHashFpDomain(const std::vector<Fp>& xs, Fp domain)
{
    const std::vector<Fp> encoded = EncodeMessage(xs, domain);
    State state{};
    for (size_t offset = 0; offset < encoded.size();
         offset += kWideRate) {
        for (uint32_t lane = 0; lane < kWideRate; ++lane) {
            state[lane] =
                Add(state[lane], encoded[offset + lane]);
        }
        Permute(state);
    }
    return DigestOf(state);
}

Digest Compress(const Digest& left, const Digest& right)
{
    return SpongeHashFpDomain(
        FlattenChildren(left, right), GetConstants().node_domain);
}

Digest LeafHashRow(const std::vector<Fp3>& row, uint32_t index)
{
    std::vector<Fp> message;
    message.reserve(3 * row.size() + 1);
    for (const Fp3& value : row) {
        message.push_back(Canonical(value.c0));
        message.push_back(Canonical(value.c1));
        message.push_back(Canonical(value.c2));
    }
    message.push_back(gf::FromU64(index));
    return SpongeHashFpDomain(message, GetConstants().row_domain);
}

PermWitness BuildPermWitness(const State& input)
{
    const Constants& constants = GetConstants();
    PermWitness witness;
    State state{};
    for (uint32_t lane = 0; lane < kWideT; ++lane) {
        state[lane] = Canonical(input[lane]);
        witness.cells[lane] = state[lane];
    }
    uint32_t sbox = 0;
    ApplyExternalMatrix(state);
    for (uint32_t round = 0; round < kHalfFull; ++round) {
        for (uint32_t lane = 0; lane < kWideT; ++lane) {
            state[lane] =
                Pow7(Add(state[lane],
                         constants.rc_ext[round][lane]));
            witness.cells[kWideT + sbox++] = state[lane];
        }
        ApplyExternalMatrix(state);
    }
    for (uint32_t round = 0; round < kWidePartialRounds; ++round) {
        state[0] =
            Pow7(Add(state[0], constants.rc_int[round]));
        witness.cells[kWideT + sbox++] = state[0];
        ApplyInternalMatrix(state);
    }
    for (uint32_t round = 0; round < kHalfFull; ++round) {
        for (uint32_t lane = 0; lane < kWideT; ++lane) {
            state[lane] =
                Pow7(Add(state[lane],
                         constants.rc_ext[kHalfFull + round][lane]));
            witness.cells[kWideT + sbox++] = state[lane];
        }
        ApplyExternalMatrix(state);
    }
    assert(sbox == kWideSboxCells);
    witness.output = state;
    return witness;
}

bool VerifyPermWitness(
    const PermWitness& witness, std::string* why)
{
    State input{};
    for (uint32_t lane = 0; lane < kWideT; ++lane) {
        input[lane] = Canonical(witness.cells[lane]);
    }
    const PermWitness expected = BuildPermWitness(input);
    for (uint32_t cell = 0; cell < kWidePermCells; ++cell) {
        if (Canonical(expected.cells[cell]) !=
            Canonical(witness.cells[cell])) {
            if (why) {
                *why = cell < kWideT
                    ? "wide permutation input canonicalization"
                    : "wide permutation sbox relation";
            }
            return false;
        }
    }
    if (!EqualState(expected.output, witness.output)) {
        if (why) *why = "wide permutation output relation";
        return false;
    }
    return true;
}

SpongeWitness BuildSpongeWitness(
    const std::vector<Fp>& xs, Fp domain)
{
    SpongeWitness witness;
    witness.domain = Canonical(domain);
    witness.message.reserve(xs.size());
    for (const Fp value : xs) {
        witness.message.push_back(Canonical(value));
    }
    const std::vector<Fp> encoded =
        EncodeMessage(witness.message, witness.domain);
    witness.permutations.reserve(encoded.size() / kWideRate);
    State state{};
    for (size_t offset = 0; offset < encoded.size();
         offset += kWideRate) {
        for (uint32_t lane = 0; lane < kWideRate; ++lane) {
            state[lane] =
                Add(state[lane], encoded[offset + lane]);
        }
        witness.permutations.push_back(BuildPermWitness(state));
        state = witness.permutations.back().output;
    }
    witness.digest = DigestOf(state);
    return witness;
}

bool VerifySpongeWitness(
    const SpongeWitness& witness, std::string* why)
{
    const std::vector<Fp> encoded =
        EncodeMessage(witness.message, witness.domain);
    if (witness.permutations.size() !=
        encoded.size() / kWideRate) {
        if (why) *why = "wide sponge permutation count";
        return false;
    }
    State state{};
    for (size_t block = 0; block < witness.permutations.size(); ++block) {
        for (uint32_t lane = 0; lane < kWideRate; ++lane) {
            state[lane] = Add(
                state[lane],
                encoded[block * kWideRate + lane]);
        }
        const PermWitness& permutation =
            witness.permutations[block];
        for (uint32_t lane = 0; lane < kWideT; ++lane) {
            if (Canonical(permutation.cells[lane]) !=
                Canonical(state[lane])) {
                if (why) *why = "wide sponge absorb/chaining relation";
                return false;
            }
        }
        if (!VerifyPermWitness(permutation, why)) return false;
        state = permutation.output;
    }
    if (!EqualDigest(DigestOf(state), witness.digest)) {
        if (why) *why = "wide sponge digest relation";
        return false;
    }
    return true;
}

SpongeWitness BuildCompressWitness(
    const Digest& left, const Digest& right)
{
    return BuildSpongeWitness(
        FlattenChildren(left, right), GetConstants().node_domain);
}

InternalMatrixConditionAudit AuditInternalMatrixCondition(
    const std::array<Fp, kWideT>& mu)
{
    InternalMatrixConditionAudit audit;
    audit.width = kWideT;
    audit.powers_required = 2 * kWideT;

    const Matrix base = InternalMatrixOf(mu);
    Matrix power = base;
    std::vector<unsigned char> transcript;
    AppendLabel(transcript, "BTX_P2_M_I_MINPOLY_AUDIT_V1");
    for (uint32_t exponent = 1;
         exponent <= audit.powers_required; ++exponent) {
        const Polynomial characteristic =
            CharacteristicPolynomial(power);
        AppendLE32(transcript, exponent);
        AppendLE32(
            transcript,
            static_cast<uint32_t>(characteristic.size()));
        for (const Fp coefficient : characteristic) {
            AppendLE64(transcript, Canonical(coefficient));
        }

        ++audit.powers_checked;
        if (!IsIrreducibleDegree16(characteristic)) {
            audit.first_failing_power = exponent;
            break;
        }
        ++audit.irreducible_powers;
        if (exponent != audit.powers_required) {
            power = MultiplyMatrix(base, power);
        }
    }
    audit.all_characteristic_polynomials_irreducible =
        audit.irreducible_powers == audit.powers_required;
    audit.characteristic_polynomials_checksum =
        ::matmul::v4::rc::Sha256dBytes(
            transcript.data(), transcript.size());
    return audit;
}

const ParameterConditionAudit& AssessParameterConditions()
{
    static const ParameterConditionAudit audit = [] {
        ParameterConditionAudit out;
        out.active_version = kWideVersion;
        out.btx_matrix =
            AuditInternalMatrixCondition(GetConstants().mu);
        out.plonky3_matrix =
            AuditInternalMatrixCondition(Plonky3InternalMu());

        const Constants reference =
            GenerateReferenceRoundConstants();
        out.btx_round_constants_checksum =
            RoundConstantsChecksum(GetConstants());
        out.plonky3_round_constants_checksum =
            RoundConstantsChecksum(reference);
        out.reference_round_constant_pins_match =
            ReferenceConstantPinsMatch(reference);
        out.reference_permutation_kat_matches =
            ReferencePermutationKatMatches(reference);
        out.reference_grain_replayed =
            out.reference_round_constant_pins_match &&
            out.reference_permutation_kat_matches;
        out.round_geometry_equal =
            kWideFullRounds == 8 &&
            kWidePartialRounds == 22;
        out.round_constants_equal =
            EqualRoundConstants(GetConstants(), reference);
        out.external_matrices_equal = false;
        out.internal_matrices_equal = true;
        for (uint32_t lane = 0; lane < kWideT; ++lane) {
            if (Canonical(GetConstants().mu[lane]) !=
                Canonical(Plonky3InternalMu()[lane])) {
                out.internal_matrices_equal = false;
                break;
            }
        }
        out.btx_parameter_condition_closed =
            out.reference_grain_replayed &&
            out.round_geometry_equal &&
            out.btx_matrix
                .all_characteristic_polynomials_irreducible;
        out.deterministic_regeneration_required =
            !out.btx_parameter_condition_closed;
        return out;
    }();
    return audit;
}

ResourceAudit AssessResources(uint32_t row_columns)
{
    ResourceAudit audit;
    audit.version = kWideVersion;
    audit.state_lanes = kWideT;
    audit.rate_lanes = kWideRate;
    audit.capacity_lanes = kWideCapacity;
    audit.digest_lanes = kWideDigestLen;
    audit.full_rounds = kWideFullRounds;
    audit.partial_rounds = kWidePartialRounds;
    audit.sboxes_per_permutation = kWideSboxCells;
    audit.perm_relation_columns = kWidePermCells;
    audit.perm_relation_constraints = kWideSboxCells;
    audit.max_algebraic_degree = kWideSboxPower;

    // [domain, 16 child lanes, 1 padding marker, 6 zeroes] = 24 fields.
    audit.node_permutations = 3;
    // Sixteen source lanes plus three independent flattened permutation
    // blocks.  Their 48 input cells are equality-pinned to absorb/chaining.
    audit.node_horizontal_columns =
        2 * kWideDigestLen +
        audit.node_permutations * kWidePermCells;
    audit.node_relation_constraints =
        audit.node_permutations *
        (kWideSboxCells + kWideT);
    audit.node_sbox_evaluations =
        static_cast<uint64_t>(audit.node_permutations) *
        kWideSboxCells;

    audit.row_columns = row_columns;
    audit.row_field_elements =
        static_cast<uint64_t>(3) * row_columns + 1; // plus row index
    // Prefix domain and mandatory 10* marker.
    const uint64_t encoded_fields =
        1 + audit.row_field_elements + 1;
    audit.row_permutations = static_cast<uint32_t>(
        (encoded_fields + kWideRate - 1) / kWideRate);
    audit.row_horizontal_columns =
        static_cast<uint64_t>(audit.row_permutations) *
        kWidePermCells;
    // One reusable flattened permutation block plus its eight-field source
    // bus. Chaining is expressed by 16 transition/equality constraints.
    audit.row_vertical_columns = kWidePermCells + kWideRate;
    audit.row_sbox_evaluations =
        static_cast<uint64_t>(audit.row_permutations) *
        kWideSboxCells;
    audit.declared_parent_column_cap = 16'384;
    audit.row_horizontal_fits_parent =
        audit.row_horizontal_columns <=
        audit.declared_parent_column_cap;
    audit.row_vertical_fits_parent =
        audit.row_vertical_columns <=
        audit.declared_parent_column_cap;

    audit.nominal_digest_bits = 64 * kWideDigestLen;
    audit.nominal_capacity_bits = 64 * kWideCapacity;
    // floor(4*log2(p)) = 255 for
    // p = 2^64 - 2^32 + 1.  Keep this exact instead of allowing a platform
    // floating-point conversion to round log2(p) up to 64.
    audit.strict_generic_collision_bits = 255;
    audit.strict_common_binding_cap_bits =
        audit.strict_generic_collision_bits;
    // A capacity calculation is not a construction-specific theorem.
    audit.production_security_claim_bits = 0;

    Matrix ignored{};
    audit.external_matrix_invertible = TryInvert(
        MatrixOfLayer([](State& state) {
            ApplyExternalMatrix(state);
        }),
        &ignored);
    audit.internal_matrix_invertible = TryInvert(
        MatrixOfLayer([](State& state) {
            ApplyInternalMatrix(state);
        }),
        &ignored);
    audit.bounded_relation_checker_executable = true;
    audit.round_geometry_matches_reference_search =
        kWideFullRounds == 8 && kWidePartialRounds == 22;
    // Deliberate fail-closed R&D status:
    audit.constants_match_reference_grain_instance = false;
    audit.internal_subspace_condition_verified =
        AssessParameterConditions()
            .btx_parameter_condition_closed;
    audit.sponge_mode_reduction_complete = false;
    audit.fri_air_integrated = false;
    audit.recursive_verifier_consumes_digest = false;
    audit.formal_security_reduction_complete = false;
    audit.production_selected = false;
    audit.consensus_enabled = false;
    return audit;
}

} // namespace matmul::v4::rc::alg_hash_wide
