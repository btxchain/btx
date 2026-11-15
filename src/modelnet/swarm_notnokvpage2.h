// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOKVPAGE2_H
#define BTX_MODELNET_SWARM_NOTNOKVPAGE2_H

#include <string>

namespace modelnet {

/**
 * A local note about one KV page. incompatible is true when the tensors
 * cannot share the page. want_share asks this note to share that page.
 *
 * Incompatible tensors do not share a KV page.
 * shared and bytes_moved stay false on every path.
 */
struct SwarmNotNoKvPage2 {
    std::string page_id;
    bool incompatible{false};
    bool want_share{false};
};

/**
 * Outcome of noting a KV page. shared and bytes_moved stay false on every
 * path. Incompatible tensors do not share a KV page.
 */
struct SwarmNotNoKvPage2Result {
    std::string code;
    bool shared{false};
    bool bytes_moved{false};
};

/**
 * Note a KV page without sharing it or moving bytes.
 * Order, first match wins: an empty page_id is PAGE. If incompatible is
 * true, the note is NOT_SHARED even when want_share is false.
 * want_share is HELD. Otherwise the note is NOTED and err is cleared.
 * shared and bytes_moved stay false on every path.
 * Incompatible tensors do not share a KV page.
 */
SwarmNotNoKvPage2Result SwarmNoteNotNoKvPage2(const SwarmNotNoKvPage2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOKVPAGE2_H
