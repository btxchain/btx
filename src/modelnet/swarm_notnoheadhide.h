// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOHEADHIDE_H
#define BTX_MODELNET_SWARM_NOTNOHEADHIDE_H

#include <string>

namespace modelnet {

/**
 * A local note about one head. want_hide asks this note to hide the head.
 *
 * Several heads stay visible. Hiding one does not train. hidden and trained
 * stay false on every path.
 */
struct SwarmNotNoHeadHide {
    std::string head_id;
    bool want_hide{false};
};

/**
 * Outcome of noting a head. hidden and trained stay false on every path:
 * several heads stay visible and hiding one does not train.
 */
struct SwarmNotNoHeadHideResult {
    std::string code;
    bool hidden{false};
    bool trained{false};
};

/**
 * Note a head without hiding it. Order, first match wins: an empty head_id
 * is HEAD. want_hide is VISIBLE. Otherwise the note is NOTED and err is
 * cleared. hidden and trained stay false on every path. Several heads stay
 * visible. Hiding one does not train.
 */
SwarmNotNoHeadHideResult SwarmNoteNotNoHeadHide(const SwarmNotNoHeadHide& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOHEADHIDE_H
