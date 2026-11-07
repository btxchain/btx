// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_HOLDROT_BLANK_H
#define BITCOIN_MODELNET_SWARM_HOLDROT_BLANK_H

#include <string>

namespace modelnet {

/**
 * Accepts a holdout that can be recorded.
 * A holdout is an opaque short label. An empty holdout is HOLDOUT.
 * The caller stores nothing on that result.
 */
class SwarmHoldoutRotateBlank {
public:
    bool accept(const std::string& holdout, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_HOLDROT_BLANK_H
