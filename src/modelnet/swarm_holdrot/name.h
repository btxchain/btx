// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_HOLDROT_NAME_H
#define BITCOIN_MODELNET_SWARM_HOLDROT_NAME_H

#include <string>

namespace modelnet {

/**
 * Copies a holdout as the recorded label.
 * The holdout is an opaque short label. The characters are kept as written.
 * No payload bytes are copied. An empty holdout copies nothing.
 */
class SwarmHoldoutRotateName {
public:
    std::string copy(const std::string& holdout) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_HOLDROT_NAME_H
