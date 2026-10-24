// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOFALSEKV_H
#define BTX_MODELNET_SWARM_NOTNOFALSEKV_H

#include <string>

namespace modelnet {

/**
 * A local note about one KV page. false_claim is true when a compatibility
 * claim is false. want_share asks this note to share that page.
 *
 * A false compatibility claim shares no KV page. shared and bytes_moved stay
 * false on every path.
 */
struct SwarmNotNoFalseKv {
    std::string page_id;
    bool false_claim{false};
    bool want_share{false};
};

/**
 * Outcome of noting a KV page. shared and bytes_moved stay false on every
 * path: a false compatibility claim shares no KV page.
 */
struct SwarmNotNoFalseKvResult {
    std::string code;
    bool shared{false};
    bool bytes_moved{false};
};

/**
 * Note a KV page without sharing it on a false compatibility claim.
 * Order, first match wins: an empty page_id is PAGE. false_claim is
 * NOT_SHARED even when want_share is false. want_share is HELD. Otherwise
 * the note is NOTED and err is clear.
 * shared and bytes_moved stay false on every path.
 */
SwarmNotNoFalseKvResult SwarmNoteNotNoFalseKv(const SwarmNotNoFalseKv& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOFALSEKV_H
