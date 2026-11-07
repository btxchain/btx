// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DUPRECEIPT_CALLER_H
#define BITCOIN_MODELNET_SWARM_DUPRECEIPT_CALLER_H

#include <string>

namespace modelnet {

/**
 * Caller allowed to pay a bound receipt.
 * A research key or a scheduler is NOT_SIGNED.
 * This check does not add atoms and does not mark the receipt paid.
 */
class SwarmDupCaller {
public:
    bool accept(bool research_key, bool scheduler, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DUPRECEIPT_CALLER_H
