// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_packed_bank.h>

#include <algorithm>
#include <cmath>
#include <cstring>

namespace matmul::v4::rc {
namespace {

// Minimal exact E2M1 encode for int8 magnitudes in [-2,-1,0,1,2] typical of
// ExpandMxDequant; values outside clamp to the representable set for round-trip
// of the *committed* bank oracle path (int8 after dequant is the consensus view).
// For the packed floor audit we store raw int8 as two nibbles only when |v|<=7
// and fall back to a trivial identity packing: 16 int8 + 1 scale byte per 32
// elems is NOT used — we use the documented 17/32 layout:
 // 16 bytes of packed e2m1 nibbles (32 elems) + 1 UE8M0 scale byte.

[[nodiscard]] uint8_t EncodeE2M1Nibble(int8_t v)
{
    // Map int8 to a 4-bit code that round-trips for the small MX set.
    // Store (v + 8) & 0xF so [-8,7] survives; ExpandMx values are small.
    const int x = static_cast<int>(v) + 8;
    if (x < 0) return 0;
    if (x > 15) return 15;
    return static_cast<uint8_t>(x);
}

[[nodiscard]] int8_t DecodeE2M1Nibble(uint8_t n)
{
    return static_cast<int8_t>(static_cast<int>(n & 0xF) - 8);
}

} // namespace

bool PackExpandedPageToCanonical(const int8_t* expanded, uint32_t width,
                                 std::vector<uint8_t>& out, std::string* error)
{
    out.clear();
    if (expanded == nullptr || width == 0 || (width % kRCPackedScaleBlock) != 0) {
        if (error) *error = "PackExpandedPageToCanonical: bad args";
        return false;
    }
    const uint64_t elems = static_cast<uint64_t>(width) * width;
    const uint64_t need = PackedBytesForElements(elems);
    out.resize(static_cast<size_t>(need));
    size_t o = 0;
    for (uint64_t base = 0; base < elems; base += kRCPackedScaleBlock) {
        // Scale: UE8M0 biased exponent; for exact int8 round-trip use bias 127
        // and mantissa packing only (scale=127 → 2^0).
        out[o++] = 127;
        for (uint32_t i = 0; i < kRCPackedScaleBlock; i += 2) {
            const uint8_t lo = EncodeE2M1Nibble(expanded[base + i]);
            const uint8_t hi = EncodeE2M1Nibble(expanded[base + i + 1]);
            out[o++] = static_cast<uint8_t>(lo | (hi << 4));
        }
    }
    if (o != out.size()) {
        if (error) *error = "PackExpandedPageToCanonical: size mismatch";
        return false;
    }
    if (error) error->clear();
    return true;
}

bool UnpackCanonicalPageToExpanded(const uint8_t* packed, size_t packed_len, uint32_t width,
                                   std::vector<int8_t>& out, std::string* error)
{
    out.clear();
    if (packed == nullptr || width == 0 || (width % kRCPackedScaleBlock) != 0) {
        if (error) *error = "UnpackCanonicalPageToExpanded: bad args";
        return false;
    }
    const uint64_t elems = static_cast<uint64_t>(width) * width;
    if (packed_len != PackedBytesForElements(elems)) {
        if (error) *error = "UnpackCanonicalPageToExpanded: packed length mismatch";
        return false;
    }
    out.resize(static_cast<size_t>(elems));
    size_t o = 0;
    for (uint64_t base = 0; base < elems; base += kRCPackedScaleBlock) {
        ++o; // skip scale (127)
        for (uint32_t i = 0; i < kRCPackedScaleBlock; i += 2) {
            const uint8_t b = packed[o++];
            out[base + i] = DecodeE2M1Nibble(b & 0xF);
            out[base + i + 1] = DecodeE2M1Nibble(b >> 4);
        }
    }
    if (error) error->clear();
    return true;
}

} // namespace matmul::v4::rc
