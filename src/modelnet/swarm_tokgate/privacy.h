// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_TOKGATE_PRIVACY_H
#define BITCOIN_MODELNET_SWARM_TOKGATE_PRIVACY_H

namespace modelnet {

/**
 * True when the caller marked the prompt private.
 * A private prompt is not stored and is not generated text.
 */
bool SwarmTokenGatePrivatePrompt(bool is_private);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_TOKGATE_PRIVACY_H
