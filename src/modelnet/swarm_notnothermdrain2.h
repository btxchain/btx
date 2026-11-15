// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOTHERMDRAIN2_H
#define BTX_MODELNET_SWARM_NOTNOTHERMDRAIN2_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one governor. thermal records a thermal limit.
 * want_keep asks this note to keep workers running.
 *
 * On thermal limit the governor drains workers to zero. workers stays
 * 0 on every path. Nothing broadcasts, spends, launches, mines, or
 * moves bytes.
 */
struct SwarmNotNoThermDrain2 {
    std::string governor_id;
    bool thermal{false};
    bool want_keep{false};
};

/**
 * Outcome of noting a thermal drain. workers stays 0 on every path.
 * On thermal limit the governor drains workers to zero.
 */
struct SwarmNotNoThermDrain2Result {
    std::string code;
    int64_t workers{0};
};

/**
 * Note a thermal drain without keeping workers running.
 * Order, first match wins: an empty governor_id is GOVERNOR. If thermal
 * is true, the note is DRAINED even when want_keep is false. want_keep
 * is HELD. Otherwise the note is NOTED and err is cleared. workers
 * stays 0 on every path.
 * On thermal limit the governor drains workers to zero.
 */
SwarmNotNoThermDrain2Result SwarmNoteNotNoThermDrain2(const SwarmNotNoThermDrain2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOTHERMDRAIN2_H
