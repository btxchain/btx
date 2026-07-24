// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_PACKED_BANK_H
#define BTX_MATMUL_MATMUL_V4_RC_PACKED_BANK_H

#include <cstdint>
#include <string>
#include <vector>

// Canonical ENC_RC packed MX bank layout (consensus floor).
// E2M1 mantissas + UE8M0 scale per 32 K-elements → 17/32 bytes/element.
// Provider (CUTLASS/cuBLASLt) padding is NOT part of this floor.

namespace matmul::v4::rc {

inline constexpr uint32_t kRCPackedScaleBlock = 32;
inline constexpr uint64_t kRCPackedNumerator = 17;
inline constexpr uint64_t kRCPackedDenominator = 32;

[[nodiscard]] inline uint64_t PackedBytesForElements(uint64_t elems)
{
    if (elems > UINT64_MAX / kRCPackedNumerator) return UINT64_MAX;
    return (elems * kRCPackedNumerator) / kRCPackedDenominator;
}

[[nodiscard]] inline uint64_t PackedBytesForPage(uint32_t width)
{
    const uint64_t elems = static_cast<uint64_t>(width) * width;
    return PackedBytesForElements(elems);
}

[[nodiscard]] inline uint64_t PackedBytesForBank(uint32_t bank_pages, uint32_t width)
{
    const uint64_t page = PackedBytesForPage(width);
    if (bank_pages == 0 || page == 0) return 0;
    if (bank_pages > UINT64_MAX / page) return UINT64_MAX;
    return static_cast<uint64_t>(bank_pages) * page;
}

[[nodiscard]] inline uint64_t ExpandedBytesForBank(uint32_t bank_pages, uint32_t width)
{
    const uint64_t page = static_cast<uint64_t>(width) * width;
    if (bank_pages == 0 || page == 0) return 0;
    if (bank_pages > UINT64_MAX / page) return UINT64_MAX;
    return static_cast<uint64_t>(bank_pages) * page;
}

/** Pack int8 expanded page (W×W) into canonical E2M1+UE8M0 bytes (exact round-trip). */
[[nodiscard]] bool PackExpandedPageToCanonical(const int8_t* expanded, uint32_t width,
                                               std::vector<uint8_t>& out, std::string* error);

/** Unpack canonical bytes back to int8 expanded page. */
[[nodiscard]] bool UnpackCanonicalPageToExpanded(const uint8_t* packed, size_t packed_len,
                                                 uint32_t width, std::vector<int8_t>& out,
                                                 std::string* error);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_PACKED_BANK_H
