// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOHOSTREFUSE2_H
#define BTX_MODELNET_SWARM_NOTNOHOSTREFUSE2_H

#include <string>

namespace modelnet {

/**
 * A local refusal note. names_host records whether the note names an
 * operator host. A note that names an operator host is refused.
 */
struct SwarmNotNoHostRefuse2 {
    std::string note_id;
    bool names_host{false};
};

/**
 * Outcome of a refusal note. accepted stays false on every path.
 */
struct SwarmNotNoHostRefuse2Result {
    std::string code;
    bool accepted{false};
};

/**
 * Note that no operator host is named. An empty note_id is NOTE.
 * names_host true is REFUSED. Otherwise the note is NOTED and err is
 * cleared. accepted stays false on every path. A note that names an
 * operator host is refused.
 */
SwarmNotNoHostRefuse2Result SwarmNoteNotNoHostRefuse2(const SwarmNotNoHostRefuse2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOHOSTREFUSE2_H
