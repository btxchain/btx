// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_LOGINHOLD_BLANK_H
#define BITCOIN_MODELNET_SWARM_LOGINHOLD_BLANK_H

#include <string>

namespace modelnet {

/**
 * Accepts a login name that can be recorded.
 * A login name is an opaque short label. An empty name is LOGIN.
 * The caller stores nothing on that result.
 */
class SwarmLoginHoldBlank {
public:
    bool accept(const std::string& name, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_LOGINHOLD_BLANK_H
