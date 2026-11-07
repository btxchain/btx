// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOREPLAYADM_H
#define BTX_MODELNET_SWARM_NOTNOREPLAYADM_H

#include <string>

namespace modelnet {

/**
 * A local note about one evaluation. quality_pass records a quality pass.
 * want_admit asks this note to admit ExactReplay.
 *
 * A quality pass is not ExactReplay admission and this note mines nothing.
 * admitted and mined stay false on every path.
 */
struct SwarmNotNoReplayAdm {
    std::string eval_id;
    bool quality_pass{false};
    bool want_admit{false};
};

/**
 * Outcome of noting an evaluation. admitted and mined stay false on every
 * path: a quality pass is not ExactReplay admission and this note mines
 * nothing.
 */
struct SwarmNotNoReplayAdmResult {
    std::string code;
    bool admitted{false};
    bool mined{false};
};

/**
 * Note an evaluation without admitting ExactReplay.
 * Order, first match wins: an empty eval_id is EVAL. quality_pass is
 * NOT_REPLAY even when want_admit is false. want_admit is NOT_REPLAY.
 * Otherwise the note is NOTED and err is cleared. admitted and mined
 * stay false on every path. A quality pass is not ExactReplay admission
 * and this note mines nothing.
 */
SwarmNotNoReplayAdmResult SwarmNoteNotNoReplayAdm(const SwarmNotNoReplayAdm& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOREPLAYADM_H
