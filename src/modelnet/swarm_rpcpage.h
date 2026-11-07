// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_RPCPAGE_H
#define BTX_MODELNET_SWARM_RPCPAGE_H

#include <string>

namespace modelnet {

/**
 * An operator-page record. page_id names the page. want_add asks this note
 * to add.
 *
 * An operator-page add request is held and adds no RPC name.
 * added stays false on every path.
 */
struct SwarmRpcPage {
    std::string page_id;
    bool want_add{false};
};

/**
 * Outcome of noting a held operator-page add request. added stays false on
 * every path.
 */
struct SwarmRpcPageResult {
    std::string code;
    bool added{false};
};

/**
 * Note a held operator-page add request. It adds no RPC name.
 * Order, first match wins: an empty page_id is PAGE.
 * want_add true is HELD.
 * Otherwise the code is NOTED and err is cleared.
 * added stays false on every path.
 * An operator-page add request is held and adds no RPC name.
 */
SwarmRpcPageResult SwarmNoteRpcPage(const SwarmRpcPage& page, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_RPCPAGE_H
