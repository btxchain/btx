// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_packed_bank.h>

#include <algorithm>
#include <cmath>
#include <cstring>

namespace matmul::v4::rc {
namespace {

[[nodiscard]] bool IsM11(int32_t v)
{
    switch (v) {
    case 0:
    case 1:
    case -1:
    case 2:
    case -2:
    case 3:
    case -3:
    case 4:
    case -4:
    case 6:
    case -6:
        return true;
    default:
        return false;
    }
}

[[nodiscard]] bool FactorBlock(const int8_t* values, uint8_t& exponent, int8_t* mantissas)
{
    // The consensus bank is the expanded int8 view. Its generating MX stream
    // uses one exponent e∈{0,1,2,3} for each 32-value row block and M11
    // mantissas. Recover a deterministic exact representation by choosing the
    // largest admissible exponent. This is unique as a storage encoding even
    // when an all-even/all-zero block could have originated at a lower scale.
    for (int e = 3; e >= 0; --e) {
        const int32_t scale = int32_t{1} << e;
        bool ok = true;
        for (uint32_t i = 0; i < kRCPackedScaleBlock; ++i) {
            const int32_t v = static_cast<int32_t>(values[i]);
            if ((v % scale) != 0 || !IsM11(v / scale)) {
                ok = false;
                break;
            }
            mantissas[i] = static_cast<int8_t>(v / scale);
        }
        if (ok) {
            exponent = static_cast<uint8_t>(e);
            return true;
        }
    }
    return false;
}

[[nodiscard]] bool EncodeE2M1Nibble(int8_t v, uint8_t& out)
{
    // OCP E2M1 bit pattern used by SampleMantissaNibble. Rejected fractional
    // and negative-zero codes are intentionally absent.
    switch (v) {
    case 0: out = 0x0; return true;
    case 1: out = 0x2; return true;
    case 2: out = 0x4; return true;
    case 3: out = 0x5; return true;
    case 4: out = 0x6; return true;
    case 6: out = 0x7; return true;
    case -1: out = 0xa; return true;
    case -2: out = 0xc; return true;
    case -3: out = 0xd; return true;
    case -4: out = 0xe; return true;
    case -6: out = 0xf; return true;
    default: return false;
    }
}

[[nodiscard]] bool DecodeE2M1Nibble(uint8_t n, int8_t& out)
{
    switch (n & 0x0f) {
    case 0x0: out = 0; return true;
    case 0x2: out = 1; return true;
    case 0x4: out = 2; return true;
    case 0x5: out = 3; return true;
    case 0x6: out = 4; return true;
    case 0x7: out = 6; return true;
    case 0xa: out = -1; return true;
    case 0xc: out = -2; return true;
    case 0xd: out = -3; return true;
    case 0xe: out = -4; return true;
    case 0xf: out = -6; return true;
    default: return false;
    }
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
        int8_t mantissas[kRCPackedScaleBlock];
        uint8_t exponent = 0;
        if (!FactorBlock(expanded + base, exponent, mantissas)) {
            out.clear();
            if (error) {
                *error = "PackExpandedPageToCanonical: block is not exact MX E2M1/E8M0";
            }
            return false;
        }
        // VEC32 UE8M0 biased exponent code, matching the native CUDA packer.
        out[o++] = static_cast<uint8_t>(127u + exponent);
        for (uint32_t i = 0; i < kRCPackedScaleBlock; i += 2) {
            uint8_t lo = 0;
            uint8_t hi = 0;
            if (!EncodeE2M1Nibble(mantissas[i], lo) ||
                !EncodeE2M1Nibble(mantissas[i + 1], hi)) {
                out.clear();
                if (error) *error = "PackExpandedPageToCanonical: invalid M11 mantissa";
                return false;
            }
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
        const uint8_t scale_code = packed[o++];
        if (scale_code < 127u || scale_code > 130u) {
            out.clear();
            if (error) *error = "UnpackCanonicalPageToExpanded: invalid UE8M0 scale";
            return false;
        }
        const uint8_t exponent = static_cast<uint8_t>(scale_code - 127u);
        const int32_t scale = int32_t{1} << exponent;
        for (uint32_t i = 0; i < kRCPackedScaleBlock; i += 2) {
            const uint8_t b = packed[o++];
            int8_t lo = 0;
            int8_t hi = 0;
            if (!DecodeE2M1Nibble(b & 0x0f, lo) || !DecodeE2M1Nibble(b >> 4, hi)) {
                out.clear();
                if (error) *error = "UnpackCanonicalPageToExpanded: rejected E2M1 code";
                return false;
            }
            out[base + i] =
                static_cast<int8_t>(static_cast<int32_t>(lo) * scale);
            out[base + i + 1] =
                static_cast<int8_t>(static_cast<int32_t>(hi) * scale);
        }
    }
    if (error) error->clear();
    return true;
}

} // namespace matmul::v4::rc
