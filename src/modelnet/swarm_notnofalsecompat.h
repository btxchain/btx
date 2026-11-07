// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOFALSECOMPAT_H
#define BTX_MODELNET_SWARM_NOTNOFALSECOMPAT_H

#include <string>

namespace modelnet {

/**
 * A local note about one KV page. false_compat records a false
 * compatibility claim. want_share asks this note to share that page.
 *
 * A false compatibility claim shares no KV page and moves no bytes.
 * shared and bytes_moved stay false on every path.
 */
struct SwarmNotNoFalseCompat {
    std::string page_id;
    bool false_compat{false};
    bool want_share{false};
};

/**
 * Outcome of noting a KV page. shared and bytes_moved stay false on every
 * path: a false compatibility claim shares no KV page and moves no bytes.
 */
struct SwarmNotNoFalseCompatResult {
    std::string code;
    bool shared{false};
    bool bytes_moved{false};
};

/**
 * Note a KV page without sharing it or moving bytes.
 * Order, first match wins: an empty page_id is PAGE. If false_compat is
 * true, the note is FAMILY_NOT_COMPAT even when want_share is false.
 * want_share is NOT_SHARED. Otherwise the note is NOTED and err is clear.
 * shared and bytes_moved stay false on every path.
 * A false compatibility claim shares no KV page and moves no bytes.
 */
SwarmNotNoFalseCompatResult SwarmNoteNotNoFalseCompat(const SwarmNotNoFalseCompat& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOFALSECOMPAT_H
