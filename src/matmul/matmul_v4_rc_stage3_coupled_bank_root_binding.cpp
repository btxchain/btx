// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_coupled_bank_root_binding.h>

namespace matmul::v4::rc {

namespace {
namespace ha = stage3_hash_air;
} // namespace

bool ComputeRCStage3CoupledBankRootAlgBinding(
    const RCStage3CoupledBankRootManifest& manifest,
    RCStage3CoupledBankRootAlgBinding& out, std::string* why)
{
    out = RCStage3CoupledBankRootAlgBinding{};
    if (manifest.commitment.IsNull() ||
        manifest.commitment !=
            CommitRCStage3CoupledBankRootManifest(manifest)) {
        if (why != nullptr) *why = "bank_root_binding:manifest_commitment";
        return false;
    }
    std::vector<ha::FixedProgramBoundaryInstance> stream;
    if (!ha::BuildShaManifestBoundaryInstances(
            manifest.sha256d, stream, why)) {
        return false;
    }
    if (!ha::BuildHashManifestRecursiveBinding(
            kRCStage3CoupledBankRootFamilyDomain, manifest.commitment,
            stream, out.binding, why)) {
        return false;
    }
    out.manifest_commitment = manifest.commitment;
    out.bank_root = manifest.bank_root;
    out.instance_count = stream.size();
    return true;
}

bool VerifyRCStage3CoupledBankRootAlgBinding(
    const RCStage3CoupledBankRootManifest& manifest,
    const RCStage3CoupledBankRootAlgBinding& committed,
    const uint256& committed_bank_root,
    RCStage3CoupledBankRootBindingResult& out, std::string* why)
{
    out = RCStage3CoupledBankRootBindingResult{};

    // (1) Verifier re-derives the boundary stream from the typed manifest —
    // never a native replay.
    std::vector<ha::FixedProgramBoundaryInstance> stream;
    out.boundary_stream_derived =
        ha::BuildShaManifestBoundaryInstances(manifest.sha256d, stream, nullptr);

    // The manifest commitment the §4 binding is taken under is the committed
    // bank manifest root (recomputed, so a tampered manifest is caught here).
    const uint256 manifest_commitment =
        CommitRCStage3CoupledBankRootManifest(manifest);
    out.stream_column_root = committed.binding.stream_column_root;
    out.bank_root = committed.bank_root;
    out.instance_count = committed.binding.instance_count;

    // (2) §4 recursive binding: recompute and require exact equality.
    out.binding_verified =
        out.boundary_stream_derived && !manifest_commitment.IsNull() &&
        ha::VerifyHashManifestRecursiveBinding(
            kRCStage3CoupledBankRootFamilyDomain, manifest_commitment, stream,
            committed.binding, nullptr);

    // (3) Instance count equals the derived compression/page count.
    out.instance_count_ok =
        out.boundary_stream_derived &&
        committed.binding.instance_count == stream.size();

    // (4) bank_root pin: the committed value and the manifest value agree.
    out.bank_root_pinned = !manifest.bank_root.IsNull() &&
                           committed_bank_root == manifest.bank_root &&
                           committed.bank_root == manifest.bank_root;

    out.binding_complete = out.boundary_stream_derived && out.binding_verified &&
                           out.instance_count_ok && out.bank_root_pinned;
    if (out.binding_complete) {
        out.note = "binding_complete";
    } else if (!out.boundary_stream_derived) {
        out.note = "boundary_stream_underived";
    } else if (!out.binding_verified) {
        out.note = "manifest_binding_mismatch";
    } else if (!out.instance_count_ok) {
        out.note = "instance_count_mismatch";
    } else {
        out.note = "bank_root_pin_mismatch";
    }
    if (why != nullptr) *why = "bank_root:" + out.note;
    return out.binding_complete;
}

RCStage3CoupledBankRootSemanticPin RCStage3CoupledBankRootWireSemanticPin(
    const RCStage3CoupledBankRootBindingResult& result)
{
    RCStage3CoupledBankRootSemanticPin pin;
    pin.semantic_relation_complete = result.binding_complete;
    pin.stream_column_root = result.stream_column_root;
    pin.bank_root = result.bank_root;
    pin.note = result.note;
    return pin;
}

} // namespace matmul::v4::rc
