// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_onetemplate.h>

#include <cstdint>

namespace modelnet {

SwarmCloseTemplateResult SwarmNoteCloseTemplate(const SwarmCloseTemplateNote& note, std::string& err)
{
    SwarmCloseTemplateResult result;
    result.tx_count = 0;
    if (note.positive_pools < 0) {
        result.code = "CLOSE";
        result.tx_count = 0;
        err = "CLOSE";
        return result;
    }
    // One close template lists positive pool balances. It is not one
    // transaction per pool and does not broadcast.
    if (note.want_tx_per_pool) {
        result.code = "ONE_TEMPLATE";
        result.tx_count = 0;
        err = "ONE_TEMPLATE";
        return result;
    }
    if (note.positive_pools == 0) {
        result.code = "EMPTY";
        result.tx_count = 0;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.tx_count = 0;
    err.clear();
    return result;
}

} // namespace modelnet
