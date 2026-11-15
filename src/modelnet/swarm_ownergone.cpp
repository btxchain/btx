// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ownergone.h>

namespace modelnet {
namespace {

SwarmCacheOwnerResult Deny(const std::string& code, std::string& err)
{
    SwarmCacheOwnerResult result;
    result.noted = false;
    result.bytes_moved = false;
    result.code = code;
    err = code;
    return result;
}

SwarmCacheOwnerResult Note(std::string& err)
{
    SwarmCacheOwnerResult result;
    result.noted = true;
    result.bytes_moved = false;
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace

SwarmCacheOwnerResult SwarmNoteCacheOwner(const SwarmCacheOwnerRequest& request, std::string& err)
{
    if (request.page_id.empty() || request.owner_id.empty()) {
        return Deny("CACHE", err);
    }
    if (!request.owner_present) {
        return Deny("OWNER_ABSENT", err);
    }
    if (request.transfer_requested) {
        return Deny("ENGINE_ABSENT", err);
    }
    return Note(err);
}

} // namespace modelnet
