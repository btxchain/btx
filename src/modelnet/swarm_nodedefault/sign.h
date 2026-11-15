// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NODEDEFAULT_SIGN_H
#define BITCOIN_MODELNET_SWARM_NODEDEFAULT_SIGN_H

#include <string>

namespace modelnet {

/**
 * Signer check for an arm.
 * A research key or a scheduler is NOT_SIGNED. operator_signed false is
 * NOT_SIGNED. Otherwise the signer is accepted. This check does not arm
 * and does not spend.
 */
class SwarmNodeDefaultSign {
public:
    bool Accept(bool operator_signed, bool research_key, bool scheduler, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NODEDEFAULT_SIGN_H
