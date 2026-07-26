// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_episode_builder_trace_binding.h>

#include <hash.h>

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

// Split a 256-bit root into four Goldilocks-reduced limb lanes (leaf binding
// only; the authority junction equality is the exact 32-byte compare).
void PushRootLanes(std::vector<Fp3>& row, const uint256& root)
{
    const unsigned char* p = root.begin();
    for (uint32_t i = 0; i < 4; ++i) {
        uint64_t limb;
        std::memcpy(&limb, p + i * 8, 8);
        row.push_back(F3(limb));
    }
}

[[nodiscard]] uint64_t XofIndexHash(const std::vector<uint32_t>& idx)
{
    HashWriter h;
    h << "BTX_RC_STAGE3_XOF_INDEX_HASH_V1";
    h << static_cast<uint64_t>(idx.size());
    for (const uint32_t v : idx) h << v;
    uint64_t out;
    std::memcpy(&out, h.GetHash().begin(), 8);
    return out;
}

// Expansion-ledger leaf j.
[[nodiscard]] ah::Digest ExpansionLeaf(
    const RCStage3EpisodeBuilderTraceExpansion& e, uint32_t j)
{
    std::vector<Fp3> row;
    row.push_back(F3(e.expansion_index));
    row.push_back(F3(static_cast<uint64_t>(e.kind)));
    row.push_back(F3(e.round_index));
    row.push_back(F3(e.layer_index));
    row.push_back(F3(e.rows));
    row.push_back(F3(e.cols));
    row.push_back(F3(XofIndexHash(e.operand_xof_indices)));
    PushRootLanes(row, e.source_link_root);
    // Shard output alg-roots in canonical shard order.
    for (const auto& sh : e.shards) PushRootLanes(row, sh.output_root);
    return ah::LeafHashRow(row, j);
}

// Trace-column ledger leaf i.
[[nodiscard]] ah::Digest TraceColumnLeaf(
    const RCStage3EpisodeBuilderTraceColumn& c, uint32_t i)
{
    std::vector<Fp3> row;
    row.push_back(F3(c.trace_index));
    row.push_back(F3(static_cast<uint64_t>(c.tensor)));
    row.push_back(F3(c.round_index));
    row.push_back(F3(c.layer_index));
    row.push_back(F3(c.rows));
    row.push_back(F3(c.cols));
    row.push_back(F3(c.first_column));
    row.push_back(F3(c.n_chunks));
    row.push_back(F3(c.expansion_index));
    PushRootLanes(row, c.wiring_vector_root);
    return ah::LeafHashRow(row, i);
}

[[nodiscard]] uint256 FoldExpansions(
    const RCStage3EpisodeBuilderTraceProduct& p)
{
    if (p.expansions.empty()) return uint256{};
    ah::Digest acc = ExpansionLeaf(p.expansions[0], 0);
    for (uint32_t j = 1; j < p.expansions.size(); ++j) {
        acc = ah::Compress(acc, ExpansionLeaf(p.expansions[j], j));
    }
    return DigestToUint256(acc);
}

[[nodiscard]] uint256 FoldTraceColumns(
    const RCStage3EpisodeBuilderTraceProduct& p)
{
    if (p.trace_columns.empty()) return uint256{};
    ah::Digest acc = TraceColumnLeaf(p.trace_columns[0], 0);
    for (uint32_t i = 1; i < p.trace_columns.size(); ++i) {
        acc = ah::Compress(acc, TraceColumnLeaf(p.trace_columns[i], i));
    }
    return DigestToUint256(acc);
}

} // namespace

RCStage3BuilderTraceAlgRoots ComputeRCStage3BuilderTraceAlgRoots(
    const RCStage3EpisodeBuilderTraceProduct& product)
{
    RCStage3BuilderTraceAlgRoots roots;
    roots.expansion_ledger_root = FoldExpansions(product);
    roots.builder_trace_root = FoldTraceColumns(product);
    roots.wiring_vector_roots.reserve(product.trace_columns.size());
    for (const auto& c : product.trace_columns) {
        roots.wiring_vector_roots.push_back(c.wiring_vector_root);
    }
    return roots;
}

bool VerifyRCStage3BuilderTraceAlgBinding(
    const RCStage3EpisodeBuilderTraceProduct& product,
    const uint256& committed_expansion_ledger_root,
    const uint256& committed_builder_trace_root,
    const std::vector<uint256>& ep3_stream_column_roots,
    RCStage3BuilderTraceAlgBindingResult& out, std::string* why)
{
    out = RCStage3BuilderTraceAlgBindingResult{};

    // (1) Canonical schedule re-derivation: contiguous 0-based indices and
    // every trace column referencing a live expansion.
    out.schedule_canonical_ordered = true;
    for (uint32_t j = 0; j < product.expansions.size(); ++j) {
        if (product.expansions[j].expansion_index != j) {
            out.schedule_canonical_ordered = false;
            break;
        }
    }
    if (out.schedule_canonical_ordered) {
        for (uint32_t i = 0; i < product.trace_columns.size(); ++i) {
            const auto& c = product.trace_columns[i];
            if (c.trace_index != i ||
                c.expansion_index >= product.expansions.size()) {
                out.schedule_canonical_ordered = false;
                break;
            }
        }
    }
    if (product.expansions.empty() || product.trace_columns.empty()) {
        out.schedule_canonical_ordered = false;
    }

    // (2) Two-layer alg fold, compared leaf-for-leaf against committed roots.
    out.expansion_ledger_root = FoldExpansions(product);
    out.builder_trace_root = FoldTraceColumns(product);
    out.expansion_ledger_matches =
        (out.expansion_ledger_root == committed_expansion_ledger_root);
    out.trace_ledger_matches =
        (out.builder_trace_root == committed_builder_trace_root);

    // (3) Cross-pin junction: each source_link_root == ep3 §4 stream root.
    out.cross_pin_ok = (ep3_stream_column_roots.size() ==
                        product.expansions.size());
    if (out.cross_pin_ok) {
        for (uint32_t j = 0; j < product.expansions.size(); ++j) {
            if (product.expansions[j].source_link_root !=
                ep3_stream_column_roots[j]) {
                out.cross_pin_ok = false;
                break;
            }
        }
    }

    // (4) root_memory belongs to this endpoint.
    out.root_memory_consistent =
        (product.root_memory.endpoint ==
         RCStage3RelationEndpoint::EpisodeBuilderTrace);

    // Export the operand roots endpoints 5/6 open.
    out.wiring_vector_roots.reserve(product.trace_columns.size());
    for (const auto& c : product.trace_columns) {
        out.wiring_vector_roots.push_back(c.wiring_vector_root);
    }

    out.binding_complete = out.schedule_canonical_ordered &&
                           out.expansion_ledger_matches &&
                           out.trace_ledger_matches && out.cross_pin_ok &&
                           out.root_memory_consistent;
    if (out.binding_complete) {
        out.note = "binding_complete";
    } else if (!out.schedule_canonical_ordered) {
        out.note = "schedule_noncanonical";
    } else if (!out.expansion_ledger_matches) {
        out.note = "expansion_ledger_mismatch";
    } else if (!out.trace_ledger_matches) {
        out.note = "trace_ledger_mismatch";
    } else if (!out.cross_pin_ok) {
        out.note = "cross_pin_mismatch";
    } else {
        out.note = "root_memory_wrong_endpoint";
    }
    if (why != nullptr) *why = "builder_trace:" + out.note;
    return out.binding_complete;
}

RCStage3BuilderTraceSemanticPin RCStage3BuilderTraceWireSemanticPin(
    const RCStage3BuilderTraceAlgBindingResult& result)
{
    RCStage3BuilderTraceSemanticPin pin;
    pin.semantic_relation_complete = result.binding_complete;
    pin.builder_trace_root = result.builder_trace_root;
    pin.wiring_vector_roots = result.wiring_vector_roots;
    pin.note = result.note;
    return pin;
}

} // namespace matmul::v4::rc
