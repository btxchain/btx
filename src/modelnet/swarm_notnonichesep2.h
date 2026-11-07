// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNONICHESEP2_H
#define BTX_MODELNET_SWARM_NOTNONICHESEP2_H

#include <string>

namespace modelnet {

/**
 * A local note about one niche. niche_id names the niche. want_merge
 * asks this note to merge niches.
 *
 * Niches stay separate. merged stays false on every path.
 */
struct SwarmNotNoNicheSep2 {
    std::string niche_id;
    bool want_merge{false};
};

/**
 * Outcome of noting a niche. merged stays false on every path. Niches
 * stay separate.
 */
struct SwarmNotNoNicheSep2Result {
    std::string code;
    bool merged{false};
};

/**
 * Note a niche without merging it.
 * Order, first match wins: an empty niche_id is NICHE. want_merge is
 * HELD. Otherwise the note is NOTED and err is cleared.
 * merged stays false on every path. Niches stay separate.
 */
SwarmNotNoNicheSep2Result SwarmNoteNotNoNicheSep2(const SwarmNotNoNicheSep2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNONICHESEP2_H
