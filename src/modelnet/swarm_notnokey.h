// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOKEY_H
#define BTX_MODELNET_SWARM_NOTNOKEY_H

#include <string>

namespace modelnet {

/**
 * A local note about one role. research_or_scheduler marks a research
 * key or the scheduler. want_spend asks this note for a spend key.
 *
 * A research key and the scheduler receive no spend key. granted and
 * spent stay false on every path.
 */
struct SwarmNotNoKey {
    std::string role_id;
    bool research_or_scheduler{false};
    bool want_spend{false};
};

/**
 * Outcome of noting a role. granted and spent stay false on every
 * path. A research key and the scheduler receive no spend key.
 */
struct SwarmNotNoKeyResult {
    std::string code;
    bool granted{false};
    bool spent{false};
};

/**
 * Note a role without granting a spend key. Order, first match wins:
 * an empty role_id is ROLE. research_or_scheduler is NO_KEY even when
 * want_spend is false. want_spend is NO_KEY. Otherwise the note is
 * NOTED and err is clear. granted and spent stay false on every path.
 * A research key and the scheduler receive no spend key.
 */
SwarmNotNoKeyResult SwarmNoteNotNoKey(const SwarmNotNoKey& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOKEY_H
