// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_meshpool.h>

#include <string>

namespace modelnet {
namespace {

SwarmMeshPoolsResult Refuse(const std::string& code, std::string& err)
{
    SwarmMeshPoolsResult result;
    result.merged = false;
    result.code = code;
    err = code;
    return result;
}

SwarmMeshPoolsResult Noted(std::string& err)
{
    SwarmMeshPoolsResult result;
    result.merged = false;
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace

SwarmMeshPoolsResult SwarmNoteMeshPools(const SwarmMeshPools& note, std::string& err)
{
    if (note.mesh_id.empty() || note.pool_a.empty() || note.pool_b.empty()) {
        return Refuse("MESH", err);
    }
    // The same pool named twice is not a pair, even when the caller asks
    // to merge the two names onto one balance.
    if (note.pool_a == note.pool_b) {
        return Refuse("SAME", err);
    }
    // One payment mesh may carry many pools. The pools stay separate.
    if (note.want_merge) {
        return Refuse("SEPARATE", err);
    }
    return Noted(err);
}

} // namespace modelnet
