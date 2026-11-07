// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_island.h>

namespace modelnet {

bool SwarmAcceptIslandUpdate(SwarmIslandUpdate& update, const std::string& expected_recipe, const std::string& expected_base, int64_t staleness_limit, std::string& err)
{
    if (update.island_id.empty() || update.recipe.empty() || update.base_checkpoint.empty() || update.update_digest.empty()) {
        update.bytes_averaged = false;
        err = "UPDATE";
        return false;
    }
    if (update.recipe != expected_recipe || update.base_checkpoint != expected_base) {
        update.bytes_averaged = false;
        err = "INCOMPATIBLE";
        return false;
    }
    if (staleness_limit < 0 || update.staleness < 0) {
        update.bytes_averaged = false;
        err = "STALE_UPDATE";
        return false;
    }
    if (update.staleness > staleness_limit) {
        update.bytes_averaged = false;
        err = "STALE_UPDATE";
        return false;
    }
    update.bytes_averaged = false;
    err.clear();
    return true;
}

} // namespace modelnet
