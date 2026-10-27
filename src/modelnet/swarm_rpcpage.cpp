// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_rpcpage.h>

#include <string>

namespace modelnet {

SwarmRpcPageResult SwarmNoteRpcPage(const SwarmRpcPage& page, std::string& err)
{
    SwarmRpcPageResult result;
    result.added = false;
    // An operator-page add request is held and adds no RPC name.
    if (page.page_id.empty()) {
        result.code = "PAGE";
        result.added = false;
        err = "PAGE";
        return result;
    }
    if (page.want_add) {
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
