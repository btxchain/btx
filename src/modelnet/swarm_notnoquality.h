// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOQUALITY_H
#define BTX_MODELNET_SWARM_NOTNOQUALITY_H

#include <string>

namespace modelnet {

/**
 * A local note about one candidate. want_promote asks this note to promote
 * a realm after a quality graduation.
 *
 * A quality graduation is not a realm promotion and admits nothing to
 * ExactReplay. promoted and admitted stay false on every path.
 */
struct SwarmNotNoQuality {
    std::string candidate_id;
    bool want_promote{false};
};

/**
 * Outcome of noting a quality graduation. promoted and admitted stay false
 * on every path. A quality graduation is not a realm promotion and admits
 * nothing to ExactReplay.
 */
struct SwarmNotNoQualityResult {
    std::string code;
    bool promoted{false};
    bool admitted{false};
};

/**
 * Note a quality graduation without promoting a realm or admitting
 * ExactReplay. Order, first match wins: an empty candidate_id is
 * CANDIDATE. want_promote is NOT_REALM. Otherwise the note is NOTED and
 * err is cleared. promoted and admitted stay false on every path. A
 * quality graduation is not a realm promotion and admits nothing to
 * ExactReplay.
 */
SwarmNotNoQualityResult SwarmNoteNotNoQuality(const SwarmNotNoQuality& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOQUALITY_H
