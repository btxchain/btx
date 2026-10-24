// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOINCLUDE2_H
#define BTX_MODELNET_SWARM_NOTNOINCLUDE2_H

#include <string>

namespace modelnet {

/**
 * A local note about one set boundary. set_id names the set.
 * inclusive marks the boundary as inclusive. want_exclude asks this
 * note to exclude a member.
 *
 * This note excludes no member. excluded stays false on every path.
 * An inclusive boundary excludes no member.
 */
struct SwarmNotNoInclude2 {
    std::string set_id;
    bool inclusive{false};
    bool want_exclude{false};
};

/**
 * Outcome of noting a set boundary. excluded stays false on every path.
 * An inclusive boundary excludes no member.
 */
struct SwarmNotNoInclude2Result {
    std::string code;
    bool excluded{false};
};

/**
 * Note a set boundary without excluding a member.
 * Order, first match wins: an empty set_id is SET. If inclusive is
 * true, the note is STAYS even when want_exclude is false. want_exclude
 * is HELD. Otherwise the note is NOTED and err is cleared. excluded
 * stays false on every path. An inclusive boundary excludes no member.
 */
SwarmNotNoInclude2Result SwarmNoteNotNoInclude2(const SwarmNotNoInclude2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOINCLUDE2_H
