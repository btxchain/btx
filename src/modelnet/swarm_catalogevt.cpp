// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_catalogevt.h>

namespace modelnet {

SwarmCatalogEventResult SwarmNoteCatalogEvent(const SwarmCatalogEvent& event, std::string& err)
{
    SwarmCatalogEventResult result;
    result.noted = false;
    result.adopted = false;
    result.socket_opened = false;
    if (event.event_id.empty() || event.candidate_id.empty()) {
        result.code = "CATALOG";
        err = "CATALOG";
        return result;
    }
    if (event.want_socket) {
        result.code = "NO_SOCKET";
        err = "NO_SOCKET";
        return result;
    }
    if (event.want_adopt && !event.qualified) {
        result.code = "NOT_ADOPTED";
        err = "NOT_ADOPTED";
        return result;
    }
    result.noted = true;
    result.adopted = false;
    result.socket_opened = false;
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
