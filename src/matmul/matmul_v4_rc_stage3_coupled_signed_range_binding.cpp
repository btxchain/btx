// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_coupled_signed_range_binding.h>

#include <cstring>

namespace matmul::v4::rc {

namespace {
namespace gf = gkr_field;
namespace ah = alg_hash;
using gf::Fp3;

[[nodiscard]] Fp3 F3(uint64_t x) { return gf::FromU64_3(x); }

[[nodiscard]] uint256 DigestToUint256(const ah::Digest& d)
{
    uint256 out;
    unsigned char* p = out.begin();
    for (uint32_t i = 0; i < ah::kAlgHashDigestLen; ++i) {
        const uint64_t lane = static_cast<uint64_t>(gf::Canonical(d[i]));
        std::memcpy(p + i * 8, &lane, 8);
    }
    return out;
}

// Four Goldilocks-reduced limb lanes of a 256-bit root (leaf binding only).
void PushRootLanes(std::vector<Fp3>& row, const uint256& root)
{
    const unsigned char* p = root.begin();
    for (uint32_t i = 0; i < 4; ++i) {
        uint64_t limb;
        std::memcpy(&limb, p + i * 8, 8);
        row.push_back(F3(limb));
    }
}

[[nodiscard]] uint256 RangeValueRoot(const RCStage3SignedRangePin& pin)
{
    if (pin.column_roots.size() != kRCStage3SignedRangeColumns) return uint256{};
    return pin.column_roots[kRCStage3RangeValue].root;
}

// Ordered fold leaf s.
[[nodiscard]] ah::Digest ShardLeaf(const RCStage3SignedRangeShardEntry& e,
                                   uint32_t s)
{
    std::vector<Fp3> row;
    row.push_back(F3(s));
    row.push_back(F3(e.pin.cell_begin));
    row.push_back(F3(e.pin.logical_rows));
    row.push_back(F3(e.pin.n_rows));
    row.push_back(F3(e.pin.max_abs));
    PushRootLanes(row, RangeValueRoot(e.pin));
    PushRootLanes(row, e.y_interval_root);
    return ah::LeafHashRow(row, s);
}
} // namespace

uint256 ComputeRCStage3SignedRangeLedgerFold(
    const std::vector<RCStage3SignedRangeShardEntry>& entries)
{
    if (entries.empty()) return uint256{};
    ah::Digest acc = ShardLeaf(entries[0], 0);
    for (uint32_t s = 1; s < entries.size(); ++s) {
        acc = ah::Compress(acc, ShardLeaf(entries[s], s));
    }
    return DigestToUint256(acc);
}

bool ComputeRCStage3SignedRangeAlgBinding(
    const std::vector<RCStage3SignedRangeShardEntry>& entries,
    RCStage3SignedRangeAlgBinding& out, std::string* why)
{
    out = RCStage3SignedRangeAlgBinding{};
    if (entries.empty()) {
        if (why != nullptr) *why = "signed_range:empty";
        return false;
    }
    for (const auto& e : entries) {
        if (RangeValueRoot(e.pin).IsNull()) {
            if (why != nullptr) *why = "signed_range:null_value_root";
            return false;
        }
    }
    out.value_roots_commitment = ComputeRCStage3SignedRangeLedgerFold(entries);
    out.shard_count = static_cast<uint32_t>(entries.size());
    return !out.value_roots_commitment.IsNull();
}

bool VerifyRCStage3SignedRangeAlgBinding(
    const std::vector<RCStage3SignedRangeShardEntry>& entries,
    const RCStage3SignedRangeAlgBinding& committed,
    RCStage3SignedRangeBindingResult& out, std::string* why)
{
    out = RCStage3SignedRangeBindingResult{};
    out.value_roots_commitment = committed.value_roots_commitment;
    out.shard_count = committed.shard_count;

    // (1) Contiguous 0-based shard indices; RANGE_VALUE roots present.
    out.shards_ordered = !entries.empty() &&
                         committed.shard_count == entries.size();
    if (out.shards_ordered) {
        for (uint32_t s = 0; s < entries.size(); ++s) {
            if (entries[s].pin.shard_index != s ||
                RangeValueRoot(entries[s].pin).IsNull()) {
                out.shards_ordered = false;
                break;
            }
        }
    }

    // (2) Ordered value-roots fold: recompute and require equality.
    const uint256 fold = ComputeRCStage3SignedRangeLedgerFold(entries);
    out.value_roots_pinned =
        !fold.IsNull() && fold == committed.value_roots_commitment;

    // (3) Per-shard RANGE_VALUE root == CoupledGemmOutputY interval root.
    out.y_interval_equal = !entries.empty();
    for (const auto& e : entries) {
        if (RangeValueRoot(e.pin) != e.y_interval_root ||
            e.y_interval_root.IsNull()) {
            out.y_interval_equal = false;
            break;
        }
    }

    out.binding_complete = out.shards_ordered && out.value_roots_pinned &&
                           out.y_interval_equal;
    if (out.binding_complete) {
        out.note = "binding_complete";
    } else if (!out.shards_ordered) {
        out.note = "shards_noncontiguous";
    } else if (!out.value_roots_pinned) {
        out.note = "value_roots_mismatch";
    } else {
        out.note = "y_interval_root_mismatch";
    }
    if (why != nullptr) *why = "signed_range:" + out.note;
    return out.binding_complete;
}

RCStage3SignedRangeSemanticPin RCStage3SignedRangeWireSemanticPin(
    const RCStage3SignedRangeBindingResult& result)
{
    RCStage3SignedRangeSemanticPin pin;
    pin.semantic_relation_complete = result.binding_complete;
    pin.value_roots_commitment = result.value_roots_commitment;
    pin.note = result.note;
    return pin;
}

} // namespace matmul::v4::rc
