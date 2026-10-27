// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FOURSCALE_GRADUATE_H
#define BITCOIN_MODELNET_SWARM_FOURSCALE_GRADUATE_H

#include <string>

namespace modelnet {

/**
 * Refuses to graduate any scale out of this plane.
 * This function takes no book and no realm flag, so it cannot move a
 * step and it cannot set graduated. The answer is always REALM.
 */
class SwarmFourScaleGraduate {
public:
    bool refuse(std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FOURSCALE_GRADUATE_H
