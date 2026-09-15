// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/piece_ranges.h>
#include <modelnet/types.h>

#include <algorithm>
#include <limits>

namespace modelnet {

bool RangeCovers(const PieceRange& r, uint32_t index)
{
    if (r.count == 0) return false;
    if (index < r.first) return false;
    return index < r.first + r.count;
}

bool RangesCover(const std::vector<PieceRange>& ranges, uint32_t file_index, uint32_t piece_index,
                 uint32_t offer_file_index)
{
    if (file_index != offer_file_index) return false;
    for (const auto& r : ranges) {
        if (RangeCovers(r, piece_index)) return true;
    }
    return false;
}

bool CompactPieceRanges(const std::vector<uint32_t>& sorted_unique, std::vector<PieceRange>& out, std::string& err)
{
    out.clear();
    if (sorted_unique.size() > MAX_PIECE_INDEX_LIST) {
        err = "huge sparse piece list";
        return false;
    }
    for (size_t i = 0; i < sorted_unique.size(); ++i) {
        if (i > 0 && sorted_unique[i] <= sorted_unique[i - 1]) {
            err = "piece indices must be strictly increasing";
            return false;
        }
        if (out.empty() || sorted_unique[i] != out.back().first + out.back().count) {
            if (out.size() >= MAX_PIECE_RANGES) {
                err = "too many piece ranges";
                return false;
            }
            PieceRange r;
            r.first = sorted_unique[i];
            r.count = 1;
            out.push_back(r);
        } else {
            if (out.back().count == std::numeric_limits<uint32_t>::max()) {
                err = "piece range overflow";
                return false;
            }
            ++out.back().count;
        }
    }
    return true;
}

bool ParsePieceRangesJson(const UniValue& arr, std::vector<PieceRange>& out, std::string& err)
{
    out.clear();
    if (!arr.isArray()) {
        err = "ranges must be an array";
        return false;
    }
    if (arr.size() > MAX_PIECE_RANGES) {
        err = "too many piece ranges";
        return false;
    }
    for (const auto& v : arr.getValues()) {
        PieceRange r;
        if (v.isArray()) {
            if (v.size() != 2) {
                err = "range pair must be [first, last]";
                return false;
            }
            const uint32_t lo = v[0].getInt<uint32_t>();
            const uint32_t hi = v[1].getInt<uint32_t>();
            if (hi < lo) {
                err = "inverted piece range";
                return false;
            }
            r.first = lo;
            r.count = hi - lo + 1;
        } else if (v.isObject()) {
            r.first = v.exists("first") ? v["first"].getInt<uint32_t>() :
                      (v.exists("first_piece") ? v["first_piece"].getInt<uint32_t>() : 0);
            r.count = v.exists("count") ? v["count"].getInt<uint32_t>() :
                       (v.exists("piece_count") ? v["piece_count"].getInt<uint32_t>() : 0);
        } else {
            err = "range object or [first, last] pair required";
            return false;
        }
        if (r.count == 0) {
            err = "empty piece range";
            return false;
        }
        if (r.first > std::numeric_limits<uint32_t>::max() - r.count) {
            err = "piece range overflow";
            return false;
        }
        out.push_back(r);
    }
    return true;
}

UniValue PieceRangesToPairsJson(const std::vector<PieceRange>& ranges)
{
    UniValue arr(UniValue::VARR);
    for (const auto& r : ranges) {
        if (r.count == 0) continue;
        UniValue pair(UniValue::VARR);
        pair.push_back(static_cast<int64_t>(r.first));
        pair.push_back(static_cast<int64_t>(r.first + r.count - 1));
        arr.push_back(pair);
    }
    return arr;
}

bool CanonicalizePieceRanges(std::vector<PieceRange>& ranges, uint32_t piece_count, std::string& err)
{
    std::sort(ranges.begin(), ranges.end(), [](const PieceRange& a, const PieceRange& b) {
        return a.first < b.first;
    });
    std::vector<PieceRange> merged;
    for (const auto& r : ranges) {
        if (r.count == 0) {
            err = "empty piece range";
            return false;
        }
        if (r.first > std::numeric_limits<uint32_t>::max() - r.count) {
            err = "piece range overflow";
            return false;
        }
        const uint32_t last = r.first + r.count - 1;
        if (piece_count > 0 && last >= piece_count) {
            err = "piece index beyond file";
            return false;
        }
        if (merged.empty() || r.first > merged.back().first + merged.back().count) {
            if (merged.size() >= MAX_PIECE_RANGES) {
                err = "too many piece ranges";
                return false;
            }
            merged.push_back(r);
        } else if (r.first < merged.back().first + merged.back().count) {
            // overlap: extend
            const uint32_t new_last = std::max(merged.back().first + merged.back().count - 1, last);
            merged.back().count = new_last - merged.back().first + 1;
        } else {
            merged.back().count += r.count;
        }
    }
    ranges = std::move(merged);
    return true;
}

UniValue PieceRangesToJson(const std::vector<PieceRange>& ranges)
{
    UniValue arr(UniValue::VARR);
    for (const auto& r : ranges) {
        UniValue o(UniValue::VOBJ);
        o.pushKV("first", static_cast<int64_t>(r.first));
        o.pushKV("count", static_cast<int64_t>(r.count));
        arr.push_back(o);
    }
    return arr;
}

bool PieceComplete(uint64_t file_size, uint32_t have_count)
{
    if (file_size == 0) return have_count == 0;
    const uint64_t n = (file_size + PIECE_SIZE - 1) / PIECE_SIZE;
    return have_count == n;
}

} // namespace modelnet
