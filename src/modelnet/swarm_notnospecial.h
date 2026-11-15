// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSPECIAL_H
#define BTX_MODELNET_SWARM_NOTNOSPECIAL_H

#include <string>

namespace modelnet {

/**
 * A local note about one store. store_id names the store.
 * want_replace asks this note to replace general/stable.
 *
 * A specialist store leaves general/stable in place and moves no bytes.
 * replaced and bytes_moved stay false on every path.
 */
struct SwarmNotNoSpecial {
    std::string store_id;
    bool want_replace{false};
};

/**
 * Outcome of noting a specialist store. replaced and bytes_moved stay
 * false on every path. A specialist store leaves general/stable in place
 * and moves no bytes.
 */
struct SwarmNotNoSpecialResult {
    std::string code;
    bool replaced{false};
    bool bytes_moved{false};
};

/**
 * Note a specialist store without replacing general/stable or moving bytes.
 * Order, first match wins: an empty store_id is STORE. want_replace is
 * KEPT. Otherwise the note is NOTED and err is cleared.
 * replaced and bytes_moved stay false on every path. A specialist store
 * leaves general/stable in place and moves no bytes.
 */
SwarmNotNoSpecialResult SwarmNoteNotNoSpecial(const SwarmNotNoSpecial& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSPECIAL_H
