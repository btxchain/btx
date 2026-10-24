// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoseedrole2.h>

#include <string>

namespace modelnet {

SwarmNotNoSeedRole2Result SwarmNoteNotNoSeedRole2(const SwarmNotNoSeedRole2& note, std::string& err)
{
    // Without a device file the node stays a seeder and does not train.
    SwarmNotNoSeedRole2Result result;
    result.training = false;
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.training = false;
        err = "NODE";
        return result;
    }
    // no_device is SEEDER even when want_train is false.
    if (note.no_device) {
        result.code = "SEEDER";
        result.training = false;
        err = "SEEDER";
        return result;
    }
    if (note.want_train) {
        result.code = "HELD";
        result.training = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.training = false;
    err.clear();
    return result;
}

} // namespace modelnet
