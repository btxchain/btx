// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_COMPAT_WIDE128_H
#define BTX_COMPAT_WIDE128_H

#include <cstdint>
#include <type_traits>

// On GCC and Clang, btx::U128 and btx::I128 are the native 128-bit types, so
// existing arithmetic does not change. MSVC has no native 128-bit integer. The classes below
// are the substitute there, and the unit test compares them with the native
// type on compilers that have one.

namespace btx {
namespace wide_detail {

inline void Mul64(uint64_t a, uint64_t b, uint64_t& lo, uint64_t& hi)
{
    const uint64_t a0 = a & 0xffffffffu, a1 = a >> 32;
    const uint64_t b0 = b & 0xffffffffu, b1 = b >> 32;
    const uint64_t p0 = a0 * b0;
    const uint64_t p1 = a0 * b1;
    const uint64_t p2 = a1 * b0;
    const uint64_t p3 = a1 * b1;
    const uint64_t mid = (p0 >> 32) + (p1 & 0xffffffffu) + (p2 & 0xffffffffu);
    lo = (p0 & 0xffffffffu) | (mid << 32);
    hi = p3 + (p1 >> 32) + (p2 >> 32) + (mid >> 32);
}

class Unsigned128 {
public:
    uint64_t lo{0};
    uint64_t hi{0};
    constexpr Unsigned128() = default;
    constexpr Unsigned128(uint64_t v) : lo(v), hi(0) {}
    template <class T, typename std::enable_if<std::is_integral<T>::value && std::is_signed<T>::value, int>::type = 0>
    constexpr Unsigned128(T v) : lo(static_cast<uint64_t>(v)), hi(v < 0 ? ~uint64_t{0} : 0) {}
    template <class T, typename std::enable_if<std::is_integral<T>::value && std::is_unsigned<T>::value && !std::is_same<T, uint64_t>::value, int>::type = 0>
    constexpr Unsigned128(T v) : lo(static_cast<uint64_t>(v)), hi(0) {}

    explicit constexpr operator uint64_t() const { return lo; }
    explicit constexpr operator int64_t() const { return static_cast<int64_t>(lo); }
    explicit constexpr operator uint32_t() const { return static_cast<uint32_t>(lo); }
    explicit constexpr operator int32_t() const { return static_cast<int32_t>(lo); }

    friend constexpr bool operator==(Unsigned128 a, Unsigned128 b) { return a.lo == b.lo && a.hi == b.hi; }
    friend constexpr bool operator!=(Unsigned128 a, Unsigned128 b) { return !(a == b); }
    friend constexpr bool operator<(Unsigned128 a, Unsigned128 b) { return a.hi < b.hi || (a.hi == b.hi && a.lo < b.lo); }
    friend constexpr bool operator>(Unsigned128 a, Unsigned128 b) { return b < a; }
    friend constexpr bool operator<=(Unsigned128 a, Unsigned128 b) { return !(b < a); }
    friend constexpr bool operator>=(Unsigned128 a, Unsigned128 b) { return !(a < b); }

    friend constexpr Unsigned128 operator+(Unsigned128 a, Unsigned128 b)
    {
        Unsigned128 r;
        r.lo = a.lo + b.lo;
        r.hi = a.hi + b.hi + (r.lo < a.lo ? 1 : 0);
        return r;
    }
    friend constexpr Unsigned128 operator-(Unsigned128 a, Unsigned128 b)
    {
        Unsigned128 r;
        r.lo = a.lo - b.lo;
        r.hi = a.hi - b.hi - (a.lo < b.lo ? 1 : 0);
        return r;
    }
    Unsigned128& operator+=(Unsigned128 b) { return *this = *this + b; }
    Unsigned128& operator-=(Unsigned128 b) { return *this = *this - b; }

    friend Unsigned128 operator*(Unsigned128 a, Unsigned128 b)
    {
        uint64_t p00_lo, p00_hi, p01_lo, p01_hi, p10_lo, p10_hi;
        Mul64(a.lo, b.lo, p00_lo, p00_hi);
        Mul64(a.lo, b.hi, p01_lo, p01_hi);
        Mul64(a.hi, b.lo, p10_lo, p10_hi);
        Unsigned128 r;
        r.lo = p00_lo;
        r.hi = p00_hi + p01_lo + p10_lo;
        return r;
    }
    friend Unsigned128 operator&(Unsigned128 a, Unsigned128 b) { return Bit(a.lo & b.lo, a.hi & b.hi); }
    friend Unsigned128 operator|(Unsigned128 a, Unsigned128 b) { return Bit(a.lo | b.lo, a.hi | b.hi); }
    friend Unsigned128 operator^(Unsigned128 a, Unsigned128 b) { return Bit(a.lo ^ b.lo, a.hi ^ b.hi); }
    friend constexpr Unsigned128 operator<<(Unsigned128 a, int s)
    {
        if (s <= 0) return a;
        if (s >= 128) return {};
        if (s >= 64) return Bit(0, a.lo << (s - 64));
        return Bit(a.lo << s, (a.hi << s) | (a.lo >> (64 - s)));
    }
    friend constexpr Unsigned128 operator>>(Unsigned128 a, int s)
    {
        if (s <= 0) return a;
        if (s >= 128) return {};
        if (s >= 64) return Bit(a.hi >> (s - 64), 0);
        return Bit((a.lo >> s) | (a.hi << (64 - s)), a.hi >> s);
    }

    friend Unsigned128 operator/(Unsigned128 n, Unsigned128 d)
    {
        Unsigned128 q, r;
        if (d == Unsigned128(0)) return {};
        for (int i = BitLength(n) - 1; i >= 0; --i) {
            r = r << 1;
            if ((i >= 64 ? n.hi : n.lo) & (uint64_t{1} << (i & 63))) r.lo |= 1;
            if (!(r < d)) {
                r -= d;
                if (i >= 64) q.hi |= uint64_t{1} << (i - 64);
                else q.lo |= uint64_t{1} << i;
            }
        }
        return q;
    }
    friend Unsigned128 operator%(Unsigned128 n, Unsigned128 d)
    {
        if (d == Unsigned128(0)) return {};
        return n - (n / d) * d;
    }

private:
    static constexpr Unsigned128 Bit(uint64_t lo, uint64_t hi)
    {
        Unsigned128 r;
        r.lo = lo;
        r.hi = hi;
        return r;
    }
    static int BitLength(Unsigned128 n)
    {
        if (n.hi) {
            int s = 0;
            uint64_t v = n.hi;
            while (v) { ++s; v >>= 1; }
            return s + 64;
        }
        int s = 0;
        uint64_t v = n.lo;
        while (v) { ++s; v >>= 1; }
        return s;
    }
};

class Signed128 {
public:
    uint64_t lo{0};
    uint64_t hi{0};
    constexpr Signed128() = default;
    constexpr Signed128(Unsigned128 u) : lo(u.lo), hi(u.hi) {}
    template <class T, typename std::enable_if<std::is_integral<T>::value && std::is_unsigned<T>::value, int>::type = 0>
    constexpr Signed128(T v) : lo(static_cast<uint64_t>(v)), hi(0) {}
    template <class T, typename std::enable_if<std::is_integral<T>::value && std::is_signed<T>::value, int>::type = 0>
    constexpr Signed128(T v) : lo(static_cast<uint64_t>(v)), hi(v < 0 ? ~uint64_t{0} : 0) {}

    explicit constexpr operator uint64_t() const { return lo; }
    explicit constexpr operator int64_t() const { return static_cast<int64_t>(lo); }
    explicit constexpr operator uint32_t() const { return static_cast<uint32_t>(lo); }
    explicit constexpr operator int32_t() const { return static_cast<int32_t>(lo); }
    // GCC's native __int128 converts to double. MSVC has no native 128-bit
    // type, so the test printers need the same conversion here.
    explicit operator double() const
    {
        const bool neg = *this < 0;
        const Unsigned128 u = Magnitude(neg ? -*this : *this);
        const double d = static_cast<double>(u.hi) * 18446744073709551616.0 +
                         static_cast<double>(u.lo);
        return neg ? -d : d;
    }
    // Same bits as static_cast<unsigned __int128>(signed __int128). MSVC needs
    // this for the matmul accumulator reduction; GCC keeps the native type.
    explicit constexpr operator Unsigned128() const
    {
        Unsigned128 u;
        u.lo = lo;
        u.hi = hi;
        return u;
    }

    friend constexpr bool operator==(Signed128 a, Signed128 b) { return a.lo == b.lo && a.hi == b.hi; }
    friend constexpr bool operator!=(Signed128 a, Signed128 b) { return !(a == b); }
    friend constexpr bool operator<(Signed128 a, Signed128 b)
    {
        const int64_t ah = static_cast<int64_t>(a.hi), bh = static_cast<int64_t>(b.hi);
        return ah < bh || (ah == bh && a.lo < b.lo);
    }
    friend constexpr bool operator>(Signed128 a, Signed128 b) { return b < a; }
    friend constexpr bool operator<=(Signed128 a, Signed128 b) { return !(b < a); }
    friend constexpr bool operator>=(Signed128 a, Signed128 b) { return !(a < b); }

    friend constexpr Signed128 operator-(Signed128 a)
    {
        Unsigned128 u;
        u.lo = ~a.lo + 1;
        u.hi = ~a.hi + (u.lo == 0 ? 1 : 0);
        return Signed128(u);
    }
    friend constexpr Signed128 operator+(Signed128 a, Signed128 b)
    {
        return Signed128(Unsigned128Bits(a) + Unsigned128Bits(b));
    }
    friend constexpr Signed128 operator-(Signed128 a, Signed128 b) { return a + (-b); }
    Signed128& operator+=(Signed128 b) { return *this = *this + b; }
    Signed128& operator-=(Signed128 b) { return *this = *this - b; }
    friend Signed128 operator*(Signed128 a, Signed128 b)
    {
        return Signed128(Unsigned128Bits(a) * Unsigned128Bits(b));
    }
    friend constexpr Signed128 operator<<(Signed128 a, int s)
    {
        return Signed128(Unsigned128Bits(a) << s);
    }
    friend constexpr Signed128 operator>>(Signed128 a, int s)
    {
        if (s <= 0) return a;
        if (s >= 128) return a < 0 ? Signed128(-1) : Signed128(0);
        Unsigned128 u = Unsigned128Bits(a);
        if (s >= 64) {
            const uint64_t filled = static_cast<int64_t>(a.hi) < 0 ? ~uint64_t{0} : 0;
            return FromBits(static_cast<uint64_t>(static_cast<int64_t>(u.hi) >> (s - 64)), filled);
        }
        return FromBits((u.lo >> s) | (u.hi << (64 - s)), static_cast<uint64_t>(static_cast<int64_t>(u.hi) >> s));
    }
    friend Signed128 operator/(Signed128 a, Signed128 b)
    {
        if (b == 0) return {};
        const bool neg = (a < 0) != (b < 0);
        Unsigned128 q = Magnitude(a) / Magnitude(b);
        Signed128 s(q);
        return neg ? -s : s;
    }
    friend Signed128 operator%(Signed128 a, Signed128 b)
    {
        if (b == 0) return {};
        return a - (a / b) * b;
    }
    friend Signed128 operator&(Signed128 a, Signed128 b) { return Signed128(Unsigned128Bits(a) & Unsigned128Bits(b)); }
    friend Signed128 operator|(Signed128 a, Signed128 b) { return Signed128(Unsigned128Bits(a) | Unsigned128Bits(b)); }

private:
    static constexpr Unsigned128 Unsigned128Bits(Signed128 a)
    {
        Unsigned128 u;
        u.lo = a.lo;
        u.hi = a.hi;
        return u;
    }
    static constexpr Signed128 FromBits(uint64_t lo, uint64_t hi)
    {
        Signed128 r;
        r.lo = lo;
        r.hi = hi;
        return r;
    }
    static Unsigned128 Magnitude(Signed128 a)
    {
        return a < 0 ? Unsigned128Bits(-a) : Unsigned128Bits(a);
    }
};

} // namespace wide_detail

#if defined(__SIZEOF_INT128__)
using U128 = unsigned __int128;
using I128 = __int128;
#else
using U128 = wide_detail::Unsigned128;
using I128 = wide_detail::Signed128;
#endif

inline bool AddOverflow(uint64_t a, uint64_t b, uint64_t* out)
{
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_add_overflow(a, b, out);
#else
    *out = a + b;
    return *out < a;
#endif
}

inline bool SubOverflow(uint64_t a, uint64_t b, uint64_t* out)
{
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_sub_overflow(a, b, out);
#else
    *out = a - b;
    return a < b;
#endif
}

} // namespace btx

#endif
