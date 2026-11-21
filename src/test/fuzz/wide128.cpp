// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <compat/wide128.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>

#include <cassert>
#include <cstdint>

// MSVC has no 128-bit integer, so there btx::U128 and btx::I128 are the
// portable classes in compat/wide128.h, and consensus arithmetic (pow,
// matmul, smile2) runs on them. Where the native type exists, check the
// portable classes against it bit for bit.
#ifdef __SIZEOF_INT128__
namespace {
using Portable = btx::wide_detail::Unsigned128;
using PortableSigned = btx::wide_detail::Signed128;

Portable ToPortable(btx::U128 v)
{
    Portable p;
    p.lo = static_cast<uint64_t>(v);
    p.hi = static_cast<uint64_t>(v >> 64);
    return p;
}

btx::U128 Bits(Portable p)
{
    return (static_cast<btx::U128>(p.hi) << 64) | p.lo;
}

btx::U128 Bits(PortableSigned p)
{
    return (static_cast<btx::U128>(p.hi) << 64) | p.lo;
}
} // namespace

FUZZ_TARGET(wide128)
{
    FuzzedDataProvider fdp{buffer.data(), buffer.size()};
    const btx::U128 a{(static_cast<btx::U128>(fdp.ConsumeIntegral<uint64_t>()) << 64) | fdp.ConsumeIntegral<uint64_t>()};
    const btx::U128 b{(static_cast<btx::U128>(fdp.ConsumeIntegral<uint64_t>()) << 64) | fdp.ConsumeIntegral<uint64_t>()};
    const int shift{fdp.ConsumeIntegralInRange<int>(0, 127)};

    const Portable pa{ToPortable(a)};
    const Portable pb{ToPortable(b)};
    assert(Bits(pa + pb) == a + b);
    assert(Bits(pa - pb) == a - b);
    assert(Bits(pa * pb) == a * b);
    assert(Bits(pa & pb) == (a & b));
    assert(Bits(pa | pb) == (a | b));
    assert(Bits(pa ^ pb) == (a ^ b));
    assert(Bits(pa << shift) == (a << shift));
    assert(Bits(pa >> shift) == (a >> shift));
    assert((pa == pb) == (a == b));
    assert((pa < pb) == (a < b));
    assert((pa <= pb) == (a <= b));
    assert(static_cast<uint64_t>(pa) == static_cast<uint64_t>(a));
    if (b != 0) {
        assert(Bits(pa / pb) == a / b);
        assert(Bits(pa % pb) == a % b);
    }

    // Signed: wrapping results are compared through the unsigned bits,
    // since signed overflow is undefined for the native type.
    const btx::I128 sa{static_cast<btx::I128>(a)};
    const btx::I128 sb{static_cast<btx::I128>(b)};
    const PortableSigned qa{pa};
    const PortableSigned qb{pb};
    assert(Bits(qa + qb) == a + b);
    assert(Bits(qa - qb) == a - b);
    assert(Bits(qa * qb) == a * b);
    assert(Bits(-qa) == btx::U128{0} - a);
    assert(Bits(qa & qb) == (a & b));
    assert(Bits(qa | qb) == (a | b));
    assert(Bits(qa << shift) == (a << shift));
    assert(Bits(qa >> shift) == static_cast<btx::U128>(sa >> shift));
    assert((qa == qb) == (sa == sb));
    assert((qa < qb) == (sa < sb));
    assert((qa <= qb) == (sa <= sb));
    assert((qa >= qb) == (sa >= sb));
    assert(Bits(static_cast<Portable>(qa)) == a);
    assert(static_cast<int64_t>(qa) == static_cast<int64_t>(sa));
    const btx::I128 min{static_cast<btx::I128>(btx::U128{1} << 127)};
    if (sb != 0 && !(sa == min && sb == -1)) {
        assert(Bits(qa / qb) == static_cast<btx::U128>(sa / sb));
        assert(Bits(qa % qb) == static_cast<btx::U128>(sa % sb));
    }
}
#endif
