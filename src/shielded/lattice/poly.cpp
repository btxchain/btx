// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/lattice/poly.h>

#include <crypto/common.h>
#include <shielded/lattice/ntt.h>

#include <cstdint>
#include <limits>
#include <stdexcept>

namespace shielded::lattice {
namespace {

[[nodiscard]] int32_t ModQ(int64_t value)
{
    int64_t out = value % POLY_Q;
    if (out < 0) out += POLY_Q;
    return static_cast<int32_t>(out);
}

} // namespace

void Poly256::NTT()
{
    lattice::NTT(coeffs);
}

void Poly256::InverseNTT()
{
    lattice::InverseNTT(coeffs);
}

void Poly256::Reduce()
{
    for (size_t i = 0; i < POLY_N; ++i) {
        coeffs[i] = lattice::Reduce32(coeffs[i]);
    }
}

void Poly256::CAddQ()
{
    for (size_t i = 0; i < POLY_N; ++i) {
        coeffs[i] = lattice::CAddQ(coeffs[i]);
    }
}

Poly256 Poly256::PointwiseMul(const Poly256& a, const Poly256& b)
{
    Poly256 out;
    for (size_t i = 0; i < POLY_N; ++i) {
        out.coeffs[i] = lattice::MontgomeryReduce(
            static_cast<int64_t>(a.coeffs[i]) * b.coeffs[i]);
    }
    return out;
}

// Ensure that MODULE_RANK chained additions of reduced coefficients cannot
// overflow int32_t. After reduction, |coeff| < POLY_Q. The worst case
// accumulation is MODULE_RANK * 2 * POLY_Q (from InnerProduct).
static_assert(static_cast<int64_t>(MODULE_RANK) * 2 * POLY_Q < std::numeric_limits<int32_t>::max(),
              "Polynomial arithmetic may overflow int32_t with current MODULE_RANK and POLY_Q");

Poly256 Poly256::operator+(const Poly256& other) const
{
    Poly256 out;
    for (size_t i = 0; i < POLY_N; ++i) {
        out.coeffs[i] = coeffs[i] + other.coeffs[i];
    }
    return out;
}

Poly256 Poly256::operator-(const Poly256& other) const
{
    Poly256 out;
    for (size_t i = 0; i < POLY_N; ++i) {
        out.coeffs[i] = coeffs[i] - other.coeffs[i];
    }
    return out;
}

int32_t Poly256::InfNorm() const
{
    int32_t max_abs{0};
    for (const int32_t coeff : coeffs) {
        // Constant-time absolute value via unsigned arithmetic to avoid
        // INT32_MIN overflow (which is UB with signed int32_t).
        const uint32_t u = static_cast<uint32_t>(coeff);
        const uint32_t mask = static_cast<uint32_t>(coeff >> 31);
        const uint32_t abs_v = (u ^ mask) - mask; // branchless abs, safe for INT32_MIN
        const int32_t abs_val = static_cast<int32_t>(abs_v & 0x7FFFFFFFU); // clamp to non-negative
        // Constant-time max
        const int32_t diff = max_abs - abs_val;
        const int32_t select = diff >> 31; // -1 if max_abs < abs_val, 0 otherwise
        max_abs = max_abs + (select & (abs_val - max_abs));
    }
    return max_abs;
}

std::vector<unsigned char> Poly256::Pack() const
{
    std::vector<unsigned char> out(POLY_N * sizeof(int32_t));
    for (size_t i = 0; i < POLY_N; ++i) {
        WriteLE32(out.data() + (i * sizeof(int32_t)), static_cast<uint32_t>(coeffs[i]));
    }
    return out;
}

Poly256 Poly256::Unpack(Span<const unsigned char> data)
{
    if (data.size() != POLY_N * sizeof(int32_t)) {
        throw std::runtime_error("Poly256::Unpack invalid length");
    }

    Poly256 out;
    for (size_t i = 0; i < POLY_N; ++i) {
        out.coeffs[i] = static_cast<int32_t>(ReadLE32(data.data() + (i * sizeof(int32_t))));
    }
    return out;
}

Poly256 PolyMul(const Poly256& a, const Poly256& b)
{
    Poly256 left{a};
    Poly256 right{b};

    left.NTT();
    right.NTT();

    Poly256 out = Poly256::PointwiseMul(left, right);
    out.InverseNTT();
    out.Reduce();
    out.CAddQ();
    return out;
}

Poly256 PolyScale(const Poly256& poly, int64_t scalar)
{
    const int32_t scalar_mod_q = ModQ(scalar);
    Poly256 out;
    for (size_t i = 0; i < POLY_N; ++i) {
        out.coeffs[i] = ModQ(static_cast<int64_t>(poly.coeffs[i]) * scalar_mod_q);
    }
    return out;
}

Poly256 PolyFromConstant(int64_t value)
{
    Poly256 out{};
    out.coeffs[0] = ModQ(value);
    return out;
}

} // namespace shielded::lattice
