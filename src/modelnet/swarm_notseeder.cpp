// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notseeder.h>

#include <string>

namespace modelnet {

SwarmNotSeederResult SwarmNoteNotSeeder(const SwarmNotSeeder& note, std::string& err)
{
    SwarmNotSeederResult result;
    result.seeding = false;
    result.training = false;
    result.slots = 0;
    // An absent device note does not launch training.
    // A present device still trains nothing from this note.
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.seeding = false;
        result.training = false;
        result.slots = 0;
        err = "NODE";
        return result;
    }
    if (!note.device_present) {
        result.code = "PUBLIC_SEED";
        result.seeding = false;
        result.training = false;
        result.slots = 0;
        err = "PUBLIC_SEED";
        return result;
    }
    if (note.want_train) {
        result.code = "CPU_ONLY";
        result.seeding = false;
        result.training = false;
        result.slots = 0;
        err = "CPU_ONLY";
        return result;
    }
    result.code = "NOTED";
    result.seeding = false;
    result.training = false;
    result.slots = 0;
    err.clear();
    return result;
}

} // namespace modelnet
