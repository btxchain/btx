// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnochurn.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoChurnResult SwarmNoteNotNoChurn(const SwarmNotNoChurn& note, std::string& err)
{
    SwarmNotNoChurnResult result;
    result.paid = false;
    result.atoms = 0;
    // A departed worker is not paid by this note.
    if (note.worker_id.empty()) {
        result.code = "WORKER";
        result.paid = false;
        result.atoms = 0;
        err = "WORKER";
        return result;
    }
    if (note.gone) {
        result.code = "HELD";
        result.paid = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    if (note.want_pay) {
        result.code = "HELD";
        result.paid = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.paid = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
