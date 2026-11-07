// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOHEADS_H
#define BTX_MODELNET_SWARM_NOTNOHEADS_H

#include <string>

namespace modelnet {

/**
 * A local note that several heads stay visible.
 * want_hide asks this note to hide them.
 *
 * Several heads stay visible. This note hides nothing and moves no bytes.
 * hidden and bytes_moved stay false on every path.
 */
struct SwarmNotNoHeads {
    std::string chain_id;
    bool several{false};
    bool want_hide{false};
};

/**
 * Outcome of noting that several heads stay visible.
 * hidden and bytes_moved stay false on every path. This note hides
 * nothing and moves no bytes.
 */
struct SwarmNotNoHeadsResult {
    std::string code;
    bool hidden{false};
    bool bytes_moved{false};
};

/**
 * Note that several heads stay visible. This note hides nothing and moves
 * no bytes. Order, first match wins: an empty chain_id is CHAIN.
 * several is VISIBLE, even when want_hide is false. want_hide is HELD.
 * Otherwise the note is NOTED and err is clear.
 * hidden and bytes_moved stay false on every path.
 */
SwarmNotNoHeadsResult SwarmNoteNotNoHeads(const SwarmNotNoHeads& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOHEADS_H
