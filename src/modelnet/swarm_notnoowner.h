// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOOWNER_H
#define BTX_MODELNET_SWARM_NOTNOOWNER_H

#include <string>

namespace modelnet {

/**
 * A local note about one owner. want_move asks this note to move the
 * owner key.
 *
 * This note moves no owner key. moved and broadcast stay false on every
 * path.
 */
struct SwarmNotNoOwner {
    std::string owner_id;
    bool want_move{false};
};

/**
 * Outcome of noting an owner. moved and broadcast stay false on every
 * path. This note moves no owner key.
 */
struct SwarmNotNoOwnerResult {
    std::string code;
    bool moved{false};
    bool broadcast{false};
};

/**
 * Note an owner without moving an owner key. Order, first match wins:
 * an empty owner_id is OWNER. want_move is REFUSED. Otherwise the note
 * is NOTED and err is clear. moved and broadcast stay false on every
 * path. This note moves no owner key.
 */
SwarmNotNoOwnerResult SwarmNoteNotNoOwner(const SwarmNotNoOwner& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOOWNER_H
