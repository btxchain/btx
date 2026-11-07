// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNORESOURCECAP2_H
#define BTX_MODELNET_SWARM_NOTNORESOURCECAP2_H

#include <string>

namespace modelnet {

struct SwarmNotNoResourceCap2 {
    std::string sandbox_id;
    bool over_cap{false};
    bool want_raise{false};
};

struct SwarmNotNoResourceCap2Result {
    std::string code;
    bool raised{false};
};

// A sandbox raise stays capped.
SwarmNotNoResourceCap2Result SwarmNoteNotNoResourceCap2(const SwarmNotNoResourceCap2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNORESOURCECAP2_H
