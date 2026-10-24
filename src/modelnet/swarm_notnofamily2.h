// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOFAMILY2_H
#define BTX_MODELNET_SWARM_NOTNOFAMILY2_H

#include <string>

namespace modelnet {

/**
 * A local note about one family. family_id names the family.
 * private_family records that the family is private. want_publish asks
 * this note to publish.
 *
 * A private family is not published. published and bytes_moved stay
 * false on every path.
 */
struct SwarmNotNoFamily2 {
    std::string family_id;
    bool private_family{false};
    bool want_publish{false};
};

/**
 * Outcome of noting a family. published and bytes_moved stay false on
 * every path. A private family is not published.
 */
struct SwarmNotNoFamily2Result {
    std::string code;
    bool published{false};
    bool bytes_moved{false};
};

/**
 * Note a family without publishing it or moving bytes.
 * Order, first match wins: an empty family_id is FAMILY. private_family
 * true is NOT_PUBLISHED, even when want_publish is false. want_publish
 * is HELD. Otherwise the note is NOTED and err is cleared.
 * published and bytes_moved stay false on every path.
 * A private family is not published.
 */
SwarmNotNoFamily2Result SwarmNoteNotNoFamily2(const SwarmNotNoFamily2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOFAMILY2_H
