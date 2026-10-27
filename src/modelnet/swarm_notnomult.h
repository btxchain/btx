// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOMULT_H
#define BTX_MODELNET_SWARM_NOTNOMULT_H

#include <string>

namespace modelnet {

struct SwarmNotNoMult {
    std::string run_id;
    bool want_publish{false};
};

struct SwarmNotNoMultResult {
    std::string code;
    bool published{false};
    int multiplier{0};
};

// A short generation is not a published performance multiplier.
// Order: empty run_id is RUN; want_publish is UNMEASURED; otherwise NOTED
// and err is cleared. published stays false and multiplier stays 0 on every path.
SwarmNotNoMultResult SwarmNoteNotNoMult(const SwarmNotNoMult& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOMULT_H
