// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNONICHESEP_H
#define BTX_MODELNET_SWARM_NOTNONICHESEP_H

#include <string>

namespace modelnet {

/**
 * A local note about one niche. niche_id names the niche. same_niche
 * records niche membership. want_share asks this note to share.
 *
 * Niches stay separate. shared stays false and bytes_moved stays false
 * on every path.
 */
struct SwarmNotNoNicheSep {
    std::string niche_id;
    bool same_niche{false};
    bool want_share{false};
};

/**
 * Outcome of noting a niche. shared stays false and bytes_moved stays
 * false on every path. Niches stay separate.
 */
struct SwarmNotNoNicheSepResult {
    std::string code;
    bool shared{false};
    bool bytes_moved{false};
};

/**
 * Note a niche without sharing it or moving bytes.
 * Order, first match wins: an empty niche_id is NICHE.
 * If same_niche is false, the note is SEPARATE even when want_share
 * is false. want_share is NOT_SHARED.
 * Otherwise the note is NOTED and err is cleared.
 * shared stays false and bytes_moved stays false on every path.
 * Niches stay separate.
 */
SwarmNotNoNicheSepResult SwarmNoteNotNoNicheSep(const SwarmNotNoNicheSep& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNONICHESEP_H
