// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_piecepipe/resume.h>

#include <modelnet/swarm_piecepipe/codes.h>

#include <string>
#include <vector>

namespace modelnet {

bool SwarmPiecePipeResume(SwarmPiecePipeManifestBook& manifests, const SwarmPiecePipeStore& store, const std::string& artifact, std::string& err)
{
    if (!manifests.contains(artifact)) {
        err = kSwarmPiecePipeManifest;
        return false;
    }
    const std::vector<std::string> ids = manifests.slice_ids(artifact);
    for (const std::string& id : ids) {
        if (store.contains(id)) {
            continue;
        }
        // Drop will not remove a required slice. A hole still refuses and
        // leaves the artifact unusable.
        manifests.clear_usable(artifact);
        err = kSwarmPiecePipeManifest;
        return false;
    }
    manifests.mark_usable(artifact);
    err.clear();
    return true;
}

bool SwarmPiecePipeUsable(const SwarmPiecePipeManifestBook& manifests, const SwarmPiecePipeStore& store, const std::string& artifact)
{
    if (!manifests.marked_usable(artifact)) {
        return false;
    }
    const std::vector<std::string> ids = manifests.slice_ids(artifact);
    for (const std::string& id : ids) {
        if (!store.contains(id)) {
            return false;
        }
    }
    return true;
}

} // namespace modelnet
