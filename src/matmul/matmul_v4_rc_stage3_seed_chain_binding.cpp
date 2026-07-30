// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_seed_chain_binding.h>

namespace matmul::v4::rc {

namespace {
namespace ha = stage3_hash_air;

// Derive the ordered per-round SHA boundary stream (one single-block boundary
// per round) from the typed per-round SHA manifests.  Verifier-derived: no
// native SHA replay.
[[nodiscard]] bool DeriveSeedChainStream(
    const RCStage3EpisodeBuilderSeedChainProduct& product,
    std::vector<ha::FixedProgramBoundaryInstance>& stream, std::string* why)
{
    stream.clear();
    stream.reserve(product.steps.size());
    for (uint32_t r = 0; r < product.steps.size(); ++r) {
        const auto& step = product.steps[r];
        std::vector<ha::FixedProgramBoundaryInstance> per_round;
        if (!ha::BuildShaManifestBoundaryInstances(step.sha, per_round, why)) {
            return false;
        }
        if (per_round.size() != 1) {
            if (why != nullptr) *why = "seed_chain:round_not_single_block";
            return false;
        }
        stream.push_back(per_round.front());
    }
    return true;
}
} // namespace

bool ComputeRCStage3SeedChainAlgBinding(
    const RCStage3EpisodeBuilderSeedChainProduct& product,
    RCStage3SeedChainAlgBinding& out, std::string* why)
{
    out = RCStage3SeedChainAlgBinding{};
    const uint256 manifest_commitment =
        ComputeRCStage3EpisodeBuilderSeedChainProductCommitment(product);
    if (manifest_commitment.IsNull() ||
        manifest_commitment != product.product_commitment) {
        if (why != nullptr) *why = "seed_chain:product_commitment";
        return false;
    }
    std::vector<ha::FixedProgramBoundaryInstance> stream;
    if (!DeriveSeedChainStream(product, stream, why)) return false;
    if (!ha::BuildHashManifestRecursiveBinding(
            kRCStage3SeedChainFamilyDomain, manifest_commitment, stream,
            out.binding, why)) {
        return false;
    }
    out.manifest_commitment = manifest_commitment;
    out.round_count = stream.size();
    return true;
}

bool VerifyRCStage3SeedChainAlgBinding(
    const RCStage3SuccinctProof& statement,
    const RCStage3EpisodeBuilderSeedChainProduct& product,
    const RCStage3SeedChainAlgBinding& committed,
    RCStage3SeedChainBindingResult& out, std::string* why)
{
    out = RCStage3SeedChainBindingResult{};
    out.stream_column_root = committed.binding.stream_column_root;
    out.round_count = committed.binding.instance_count;

    // (1) Verifier re-derives the per-round boundary stream from typed SHA
    // manifests — never a native replay.
    std::vector<ha::FixedProgramBoundaryInstance> stream;
    out.boundary_stream_derived = DeriveSeedChainStream(product, stream, nullptr);

    // (2) Contiguous 0-based round indices (order-binding precondition).
    out.round_index_ordered = !product.steps.empty();
    for (uint32_t r = 0; r < product.steps.size(); ++r) {
        if (product.steps[r].round_index != r) {
            out.round_index_ordered = false;
            break;
        }
    }

    // (3) §4 recursive binding: recompute and require exact equality.
    const uint256 manifest_commitment =
        ComputeRCStage3EpisodeBuilderSeedChainProductCommitment(product);
    out.binding_verified =
        out.boundary_stream_derived && !manifest_commitment.IsNull() &&
        committed.binding.instance_count == stream.size() &&
        ha::VerifyHashManifestRecursiveBinding(
            kRCStage3SeedChainFamilyDomain, manifest_commitment, stream,
            committed.binding, nullptr);

    // (4) Seed chain edges: round 0 external source == σ; round r external
    // source == proof-owned round root r-1.
    out.chain_edges_ok = !product.steps.empty() &&
                         !statement.public_inputs.sigma.IsNull() &&
                         product.round_root_manifest.round_roots.size() + 1 >=
                             product.steps.size();
    if (out.chain_edges_ok) {
        for (uint32_t r = 0; r < product.steps.size(); ++r) {
            const uint256 expected_source =
                (r == 0) ? statement.public_inputs.sigma
                         : product.round_root_manifest.round_roots[r - 1];
            if (product.steps[r].source != expected_source) {
                out.chain_edges_ok = false;
                break;
            }
        }
    }

    out.binding_complete = out.boundary_stream_derived &&
                           out.round_index_ordered && out.binding_verified &&
                           out.chain_edges_ok;
    if (out.binding_complete) {
        out.note = "binding_complete";
    } else if (!out.boundary_stream_derived) {
        out.note = "boundary_stream_underived";
    } else if (!out.round_index_ordered) {
        out.note = "round_index_noncontiguous";
    } else if (!out.binding_verified) {
        out.note = "manifest_binding_mismatch";
    } else {
        out.note = "chain_edge_broken";
    }
    if (why != nullptr) *why = "seed_chain:" + out.note;
    return out.binding_complete;
}

RCStage3SeedChainSemanticPin RCStage3SeedChainWireSemanticPin(
    const RCStage3SeedChainBindingResult& result)
{
    RCStage3SeedChainSemanticPin pin;
    pin.semantic_relation_complete = result.binding_complete;
    pin.stream_column_root = result.stream_column_root;
    pin.note = result.note;
    return pin;
}

} // namespace matmul::v4::rc
