// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNORPCPAGE2_H
#define BTX_MODELNET_SWARM_NOTNORPCPAGE2_H

#include <string>

namespace modelnet {

/**
 * A local note about one page. want_add asks this note to add an operator
 * page.
 *
 * This note adds no operator page and no new RPC name.
 * added stays false on every path.
 */
struct SwarmNotNoRpcPage2 {
    std::string page_id;
    bool want_add{false};
};

/**
 * Outcome of noting a page. added stays false on every path.
 * This note adds no operator page and no new RPC name.
 */
struct SwarmNotNoRpcPage2Result {
    std::string code;
    bool added{false};
};

/**
 * Note a page without adding an operator page or a new RPC name.
 * Order, first match wins: an empty page_id is PAGE. want_add is HELD.
 * Otherwise the note is NOTED and err is cleared. added stays false on
 * every path. This note adds no operator page and no new RPC name.
 */
SwarmNotNoRpcPage2Result SwarmNoteNotNoRpcPage2(const SwarmNotNoRpcPage2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNORPCPAGE2_H
