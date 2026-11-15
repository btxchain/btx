// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPARENT_H
#define BTX_MODELNET_SWARM_NOTNOPARENT_H

#include <string>

namespace modelnet {

/**
 * A local note about one candidate. candidate_id names the candidate.
 * qualified marks the candidate as qualified to replace the parent.
 * want_replace asks this note to replace the parent.
 *
 * An unqualified candidate leaves the parent in place and does not train.
 * replaced and trained stay false on every path.
 */
struct SwarmNotNoParent {
    std::string candidate_id;
    bool qualified{false};
    bool want_replace{false};
};

/**
 * Outcome of noting a candidate. replaced and trained stay false on every
 * path. An unqualified candidate leaves the parent in place and does not
 * train.
 */
struct SwarmNotNoParentResult {
    std::string code;
    bool replaced{false};
    bool trained{false};
};

/**
 * Note a candidate without replacing the parent or training.
 * Order, first match wins: an empty candidate_id is CANDIDATE. If
 * qualified is false, the note is KEPT, even when want_replace is false.
 * want_replace is HELD. Otherwise the note is NOTED and err is clear.
 * An unqualified candidate leaves the parent in place and does not train.
 * replaced and trained stay false on every path.
 */
SwarmNotNoParentResult SwarmNoteNotNoParent(const SwarmNotNoParent& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPARENT_H
