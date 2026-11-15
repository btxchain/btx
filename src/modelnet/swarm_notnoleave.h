// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOLEAVE_H
#define BTX_MODELNET_SWARM_NOTNOLEAVE_H

#include <string>

namespace modelnet {

/**
 * A local note about one candidate. candidate_id names the candidate.
 * unqualified is true when the candidate is unqualified.
 * want_keep asks this note to keep the candidate.
 *
 * An unqualified candidate leaves the parent. kept and admitted stay
 * false on every path.
 */
struct SwarmNotNoLeave {
    std::string candidate_id;
    bool unqualified{false};
    bool want_keep{false};
};

/**
 * Outcome of noting a candidate. kept and admitted stay false on every
 * path. An unqualified candidate leaves the parent.
 */
struct SwarmNotNoLeaveResult {
    std::string code;
    bool kept{false};
    bool admitted{false};
};

/**
 * Note a candidate without keeping it or admitting it. Order, first match
 * wins: an empty candidate_id is CANDIDATE. If unqualified is true, the
 * note is LEFT even when want_keep is false. want_keep is HELD. Otherwise
 * the note is NOTED and err is cleared.
 * kept and admitted stay false on every path. An unqualified candidate
 * leaves the parent.
 */
SwarmNotNoLeaveResult SwarmNoteNotNoLeave(const SwarmNotNoLeave& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOLEAVE_H
