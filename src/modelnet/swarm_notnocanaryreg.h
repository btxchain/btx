// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCANARYREG_H
#define BTX_MODELNET_SWARM_NOTNOCANARYREG_H

#include <string>

namespace modelnet {

/**
 * A local note about one canary regression. regression marks the run as a
 * regression. want_publish asks this note to publish it.
 *
 * A canary regression is not published and is not admitted.
 * published and admitted stay false on every path.
 */
struct SwarmNotNoCanaryReg {
    std::string run_id;
    bool regression{false};
    bool want_publish{false};
};

/**
 * Outcome of noting a canary regression. published and admitted stay false
 * on every path: a canary regression is not published and is not admitted.
 */
struct SwarmNotNoCanaryRegResult {
    std::string code;
    bool published{false};
    bool admitted{false};
};

/**
 * Note a canary regression without publishing or admitting it.
 * Order, first match wins: an empty run_id is RUN.
 * If regression is true, the note is CANARY even when want_publish is false.
 * want_publish is BLOCK. Otherwise the note is NOTED and err is cleared.
 * published and admitted stay false on every path. A canary regression
 * is not published and is not admitted.
 */
SwarmNotNoCanaryRegResult SwarmNoteNotNoCanaryReg(const SwarmNotNoCanaryReg& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCANARYREG_H
