// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_PACKED_BANK_H
#define BTX_MATMUL_MATMUL_V4_RC_PACKED_BANK_H

#include <uint256.h>

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

/**
 * Pack the consensus expanded-int8 page (W×W) into a deterministic
 * E2M1+VEC32_UE8M0 storage representation. Every 32-value block must be exactly
 * factorable as M11·2^e for e∈{0,1,2,3}; otherwise this fails closed.
 */
[[nodiscard]] bool PackExpandedPageToCanonical(const int8_t* expanded, uint32_t width,
                                               std::vector<uint8_t>& out, std::string* error);

/** Unpack the storage representation back to the byte-identical int8 page. */
[[nodiscard]] bool UnpackCanonicalPageToExpanded(const uint8_t* packed, size_t packed_len,
                                                 uint32_t width, std::vector<int8_t>& out,
                                                 std::string* error);

/**
 * Expand the consensus MX mantissa/scale streams directly into their packed
 * E2M1+VEC32_UE8M0 storage form. If `expanded` is non-null, materialize the
 * byte-identical int8 page from the same streams without running the XOF twice.
 *
 * The source scale is retained. It can differ from PackExpandedPageToCanonical's
 * largest-factor encoding for ambiguous all-even blocks, but both unpack to the
 * same consensus page bytes.
 */
[[nodiscard]] bool ExpandMxPageToPackedStream(const uint256& seed, uint32_t width,
                                              uint32_t threads, std::vector<uint8_t>& packed,
                                              std::vector<int8_t>* expanded,
                                              std::string* error);

/** Parallel exact unpack for the generated or canonical packed representation. */
[[nodiscard]] bool UnpackPackedPageToExpandedParallel(const uint8_t* packed, size_t packed_len,
                                                      uint32_t width, uint32_t threads,
                                                      std::vector<int8_t>& out,
                                                      std::string* error);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_PACKED_BANK_H
