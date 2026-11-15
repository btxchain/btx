// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NODEDEFAULT_PRIVACY_H
#define BITCOIN_MODELNET_SWARM_NODEDEFAULT_PRIVACY_H

#include <modelnet/swarm_nodedefault/limits.h>

#include <string>

namespace modelnet {

/**
 * Private-prompt flag for the default node.
 * private_prompts() is false from construction. EnablePrivate is HELD
 * and leaves it false.
 */
class SwarmNodeDefaultPrivacy {
public:
    bool private_prompts() const;
    bool EnablePrivate(std::string& err);

private:
    bool m_private_prompts{kSwarmNodeDefaultPrivatePrompts};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NODEDEFAULT_PRIVACY_H
