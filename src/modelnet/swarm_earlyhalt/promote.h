// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EARLYHALT_PROMOTE_H
#define BITCOIN_MODELNET_SWARM_EARLYHALT_PROMOTE_H

#include <modelnet/swarm_earlyhalt/mark.h>
#include <modelnet/swarm_earlyhalt/score.h>

#include <string>

namespace modelnet {

/**
 * Accepts a non-decreasing run.
 * An early-stop mark is STOPPED. The mark and the score are const, so
 * the row is not removed.
 * No stored score is STEP.
 * A stored score that did not fall is accepted, including when the
 * remainder is already zero. This does not graduate the run.
 */
class SwarmEarlyHaltPromote {
public:
    bool Apply(const SwarmEarlyHaltMark& mark, const SwarmEarlyHaltScore& score, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EARLYHALT_PROMOTE_H
