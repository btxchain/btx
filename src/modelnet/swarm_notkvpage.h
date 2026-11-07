// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTKVPAGE_H
#define BTX_MODELNET_SWARM_NOTKVPAGE_H

#include <string>

namespace modelnet {

/**
 * A local note about one KV page. compatible is false when the tensors
 * cannot share the page. want_share asks this note to share that page.
 *
 * Incompatible tensors do not share KV pages. shared and bytes_moved stay
 * false on every path.
 */
struct SwarmNotKvPage {
    std::string page_id;
    bool compatible{false};
    bool want_share{false};
};

/**
 * Outcome of noting a KV page. shared and bytes_moved stay false on every
 * path: incompatible tensors do not share KV pages.
 */
struct SwarmNotKvPageResult {
    std::string code;
    bool shared{false};
    bool bytes_moved{false};
};

/**
 * Note a KV page without sharing it.
 * Order, first match wins: an empty page_id is PAGE. compatible false
 * is SEPARATE even when want_share is false. want_share is HELD. Otherwise
 * the note is NOTED and err is clear.
 * shared and bytes_moved stay false on every path.
 */
SwarmNotKvPageResult SwarmNoteNotKvPage(const SwarmNotKvPage& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTKVPAGE_H
