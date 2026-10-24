// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ADMINHOLD_KEY_H
#define BITCOIN_MODELNET_SWARM_ADMINHOLD_KEY_H

#include <string>
#include <vector>

namespace modelnet {

/**
 * Accepts a sponsor refund key that can be stored.
 * A size other than 1312 is KEY. Only the length is checked.
 * The caller stores nothing on that result.
 */
class SwarmAdminHoldKey {
public:
    bool accept(const std::vector<unsigned char>& sponsor_key, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ADMINHOLD_KEY_H
