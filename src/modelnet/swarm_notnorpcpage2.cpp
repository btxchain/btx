// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnorpcpage2.h>

#include <string>

namespace modelnet {

SwarmNotNoRpcPage2Result SwarmNoteNotNoRpcPage2(const SwarmNotNoRpcPage2& note, std::string& err)
{
    SwarmNotNoRpcPage2Result result;
    result.added = false;
    // This note adds no operator page and no new RPC name.
    if (note.page_id.empty()) {
        result.code = "PAGE";
        result.added = false;
        err = "PAGE";
        return result;
    }
    if (note.want_add) {
        result.code = "HELD";
        result.added = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.added = false;
    err.clear();
    return result;
}

} // namespace modelnet
