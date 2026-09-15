// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PIECE_RANGES_H
#define BITCOIN_MODELNET_PIECE_RANGES_H

#include <univalue.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** Compact run-length piece availability. Never a million-piece bitmap. */
constexpr size_t MAX_PIECE_RANGES = 1024;
constexpr size_t MAX_PIECE_INDEX_LIST = 1 << 20;

struct PieceRange {
    uint32_t first{0};
    uint32_t count{0};
};

bool RangeCovers(const PieceRange& r, uint32_t index);
bool RangesCover(const std::vector<PieceRange>& ranges, uint32_t file_index, uint32_t piece_index,
                 uint32_t offer_file_index);

/** Merge sorted unique piece indices into contiguous runs. Rejects huge sparse input. */
bool CompactPieceRanges(const std::vector<uint32_t>& sorted_unique, std::vector<PieceRange>& out, std::string& err);

bool ParsePieceRangesJson(const UniValue& arr, std::vector<PieceRange>& out, std::string& err);
UniValue PieceRangesToJson(const std::vector<PieceRange>& ranges);
UniValue PieceRangesToPairsJson(const std::vector<PieceRange>& ranges);
bool CanonicalizePieceRanges(std::vector<PieceRange>& ranges, uint32_t piece_count, std::string& err);

bool PieceComplete(uint64_t file_size, uint32_t have_count);

} // namespace modelnet

#endif // BITCOIN_MODELNET_PIECE_RANGES_H
