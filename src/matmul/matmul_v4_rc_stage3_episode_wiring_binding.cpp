// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_episode_wiring_binding.h>

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

void PushRootLanes(std::vector<Fp3>& row, const uint256& root)
{
    const unsigned char* p = root.begin();
    for (uint32_t i = 0; i < 4; ++i) {
        uint64_t limb;
        std::memcpy(&limb, p + i * 8, 8);
        row.push_back(F3(limb));
    }
}

// --- Transpose leaf i ---
[[nodiscard]] ah::Digest TransposeLeaf(
    const RCStage3EpisodeWiringTransposeEdge& e, uint32_t i)
{
    std::vector<Fp3> row;
    const auto& s = e.schedule;
    row.push_back(F3(i));
    row.push_back(F3(s.schedule_index));
    row.push_back(F3(s.layer_ordinal));
    row.push_back(F3(static_cast<uint64_t>(s.slot)));
    row.push_back(F3(s.first_column));
    row.push_back(F3(s.n_chunks));
    row.push_back(F3(s.source_rows));
    row.push_back(F3(s.source_cols));
    row.push_back(F3(s.value_count));
    PushRootLanes(row, s.registered_source_root);
    PushRootLanes(row, e.pin.pin_commitment);
    PushRootLanes(row, e.transposed_vector_root);
    return ah::LeafHashRow(row, i);
}

// --- Residual leaf i ---
[[nodiscard]] ah::Digest ResidualLeaf(
    const RCStage3EpisodeWiringResidualEdge& e, uint32_t i)
{
    std::vector<Fp3> row;
    const auto& s = e.schedule;
    row.push_back(F3(i));
    row.push_back(F3(s.schedule_index));
    row.push_back(F3(s.layer_ordinal));
    row.push_back(F3(s.residual_first_column));
    row.push_back(F3(s.residual_n_chunks));
    row.push_back(F3(s.value_count));
    PushRootLanes(row, s.registered_y_root);
    PushRootLanes(row, s.registered_residual_root);
    PushRootLanes(row, e.pin.pin_commitment);
    return ah::LeafHashRow(row, i);
}

// --- Round-order leaf i ---
[[nodiscard]] ah::Digest RoundOrderLeaf(
    const RCStage3EpisodeWiringRoundOrderEdge& e, uint32_t i)
{
    std::vector<Fp3> row;
    const auto& s = e.schedule;
    row.push_back(F3(i));
    row.push_back(F3(s.schedule_index));
    row.push_back(F3(s.producer_layer_ordinal));
    row.push_back(F3(s.consumer_layer_ordinal));
    row.push_back(F3(s.round_index));
    row.push_back(F3(s.first_column));
    row.push_back(F3(s.n_chunks));
    row.push_back(F3(s.value_count));
    PushRootLanes(row, s.registered_consumer_root);
    PushRootLanes(row, e.pin.pin_commitment);
    return ah::LeafHashRow(row, i);
}

template <typename Edge, typename Leaf>
[[nodiscard]] uint256 FoldEdges(const std::vector<Edge>& edges, Leaf leaf)
{
    if (edges.empty()) return uint256{};
    ah::Digest acc = leaf(edges[0], 0);
    for (uint32_t i = 1; i < edges.size(); ++i) {
        acc = ah::Compress(acc, leaf(edges[i], i));
    }
    return DigestToUint256(acc);
}
} // namespace

RCStage3WiringLedgerRoots ComputeRCStage3WiringLedgerRoots(
    const RCStage3EpisodeWiringProduct& product)
{
    RCStage3WiringLedgerRoots roots;
    roots.transpose_proof_root =
        FoldEdges(product.transpose_edges, TransposeLeaf);
    roots.residual_proof_root =
        FoldEdges(product.residual_edges, ResidualLeaf);
    roots.round_order_proof_root =
        FoldEdges(product.round_order_edges, RoundOrderLeaf);
    return roots;
}

bool VerifyRCStage3WiringLedgerBinding(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeWiringProduct& product,
    const RCStage3WiringLedgerRoots& committed,
    RCStage3WiringBindingResult& out, std::string* why)
{
    out = RCStage3WiringBindingResult{};

    // Verifier re-derives every schedule from the manifest.
    const auto transpose = BuildRCStage3EpisodeWiringTransposeSchedule(manifest);
    const auto residual = BuildRCStage3EpisodeWiringResidualSchedule(manifest);
    const auto round_order =
        BuildRCStage3EpisodeWiringRoundOrderSchedule(manifest);

    // (1) leaf-for-leaf schedule equality, contiguous indices.
    out.transpose_schedule_matches =
        !transpose.empty() &&
        product.transpose_edges.size() == transpose.size();
    if (out.transpose_schedule_matches) {
        for (uint32_t i = 0; i < transpose.size(); ++i) {
            if (product.transpose_edges[i].schedule.schedule_index != i ||
                !(product.transpose_edges[i].schedule == transpose[i])) {
                out.transpose_schedule_matches = false;
                break;
            }
        }
    }
    out.residual_schedule_matches =
        !residual.empty() && product.residual_edges.size() == residual.size();
    if (out.residual_schedule_matches) {
        for (uint32_t i = 0; i < residual.size(); ++i) {
            if (product.residual_edges[i].schedule.schedule_index != i ||
                !(product.residual_edges[i].schedule == residual[i])) {
                out.residual_schedule_matches = false;
                break;
            }
        }
    }
    out.round_order_schedule_matches =
        !round_order.empty() &&
        product.round_order_edges.size() == round_order.size();
    if (out.round_order_schedule_matches) {
        for (uint32_t i = 0; i < round_order.size(); ++i) {
            if (product.round_order_edges[i].schedule.schedule_index != i ||
                !(product.round_order_edges[i].schedule == round_order[i])) {
                out.round_order_schedule_matches = false;
                break;
            }
        }
    }

    // (2) recomputed ordered proof_root == committed endpoint proof_root.
    out.roots = ComputeRCStage3WiringLedgerRoots(product);
    out.transpose_fold_matches =
        !out.roots.transpose_proof_root.IsNull() &&
        out.roots.transpose_proof_root == committed.transpose_proof_root;
    out.residual_fold_matches =
        !out.roots.residual_proof_root.IsNull() &&
        out.roots.residual_proof_root == committed.residual_proof_root;
    out.round_order_fold_matches =
        !out.roots.round_order_proof_root.IsNull() &&
        out.roots.round_order_proof_root == committed.round_order_proof_root;

    out.binding_complete =
        out.transpose_schedule_matches && out.transpose_fold_matches &&
        out.residual_schedule_matches && out.residual_fold_matches &&
        out.round_order_schedule_matches && out.round_order_fold_matches;
    if (out.binding_complete) {
        out.note = "binding_complete";
    } else if (!out.transpose_schedule_matches || !out.transpose_fold_matches) {
        out.note = "transpose_ledger_mismatch";
    } else if (!out.residual_schedule_matches || !out.residual_fold_matches) {
        out.note = "residual_ledger_mismatch";
    } else {
        out.note = "round_order_ledger_mismatch";
    }
    if (why != nullptr) *why = "wiring:" + out.note;
    return out.binding_complete;
}

RCStage3WiringSemanticPin RCStage3WiringWireSemanticPin(
    const RCStage3WiringBindingResult& result)
{
    RCStage3WiringSemanticPin pin;
    pin.transpose_complete =
        result.transpose_schedule_matches && result.transpose_fold_matches;
    pin.residual_complete =
        result.residual_schedule_matches && result.residual_fold_matches;
    pin.round_order_complete = result.round_order_schedule_matches &&
                               result.round_order_fold_matches;
    pin.roots = result.roots;
    pin.note = result.note;
    return pin;
}

} // namespace matmul::v4::rc
