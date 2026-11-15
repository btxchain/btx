// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoillus.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoIllusResult SwarmNoteNotNoIllus(const SwarmNotNoIllus& note, std::string& err)
{
    SwarmNotNoIllusResult result;
    result.paid = false;
    result.atoms = 0;
    // A revenue illustration of 700000, 200000, and 100000 ppm on a gross
    // of 10000 records 7000, 2000, and 1000 and pays nothing.
    if (note.split_id.empty()) {
        result.code = "SPLIT";
        result.paid = false;
        result.atoms = 0;
        err = "SPLIT";
        return result;
    }
    if (note.want_pay) {
        result.code = "NOT_PAID";
        result.paid = false;
        result.atoms = 0;
        err = "NOT_PAID";
        return result;
    }
    result.code = "NOTED";
    result.paid = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
