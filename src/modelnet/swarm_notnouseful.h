// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOUSEFUL_H
#define BTX_MODELNET_SWARM_NOTNOUSEFUL_H

#include <string>

namespace modelnet {

/**
 * A local note about one task. want_claim asks this note to mark that
 * work useful.
 *
 * A note does not mark work useful and pays nothing. useful and paid
 * stay false on every path.
 */
struct SwarmNotNoUseful {
    std::string task_id;
    bool want_claim{false};
};

/**
 * Outcome of noting one task. useful and paid stay false on every path:
 * a note does not mark work useful and pays nothing.
 */
struct SwarmNotNoUsefulResult {
    std::string code;
    bool useful{false};
    bool paid{false};
};

/**
 * Note one task without marking the work useful.
 * Order, first match wins: an empty task_id is TASK. want_claim is
 * NOT_USEFUL. Otherwise the note is NOTED and err is clear.
 * useful and paid stay false on every path. A note does not mark work
 * useful and pays nothing.
 */
SwarmNotNoUsefulResult SwarmNoteNotNoUseful(const SwarmNotNoUseful& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOUSEFUL_H
