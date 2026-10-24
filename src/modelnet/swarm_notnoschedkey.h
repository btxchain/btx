// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSCHEDKEY_H
#define BTX_MODELNET_SWARM_NOTNOSCHEDKEY_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one scheduler. scheduler records whether this
 * note names a scheduler. want_spend asks this note to spend.
 *
 * The scheduler never receives a spend key and spends nothing. spent
 * stays false and atoms stays 0 on every path.
 */
struct SwarmNotNoSchedKey {
    std::string scheduler_id;
    bool scheduler{false};
    bool want_spend{false};
};

/**
 * Outcome of noting a scheduler. spent stays false and atoms stays 0
 * on every path. The scheduler never receives a spend key and spends
 * nothing.
 */
struct SwarmNotNoSchedKeyResult {
    std::string code;
    bool spent{false};
    int64_t atoms{0};
};

/**
 * Note a scheduler without spending. Order, first match wins: an empty
 * scheduler_id is SCHEDULER. scheduler true is NO_SPEND even when
 * want_spend is false. want_spend is NO_SPEND. Otherwise the note is
 * NOTED and err is cleared. spent stays false and atoms stays 0 on
 * every path. The scheduler never receives a spend key and spends
 * nothing.
 */
SwarmNotNoSchedKeyResult SwarmNoteNotNoSchedKey(const SwarmNotNoSchedKey& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSCHEDKEY_H
