// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_routebook/sighash.h>

#include <modelnet/swarm_routebook/codes.h>

#include <string>

namespace modelnet {

bool SwarmRouteBookApplySighash(SwarmRouteBookPath& path, bool covers_outputs, std::string& err)
{
    if (!covers_outputs) {
        err = SWARM_ROUTEBOOK_NOT_SIGNED;
        return false;
    }
    // The description covered outputs. No key is attached.
    path.outputs_covered = true;
    err.clear();
    return true;
}

} // namespace modelnet
