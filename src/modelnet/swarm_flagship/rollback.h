// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FLAGSHIP_ROLLBACK_H
#define BITCOIN_MODELNET_SWARM_FLAGSHIP_ROLLBACK_H

#include <string>

namespace modelnet {

class SwarmFlagshipLedger;

/**
 * Clear one stage and every later stage.
 * A name outside the thirteen stages is STAGE and deletes nothing.
 * A listed stage clears that stage through repeat and leaves earlier
 * stages in place. Clearing evidence does not pass a stage.
 */
class SwarmFlagshipRollback {
public:
    bool apply(SwarmFlagshipLedger& ledger, const std::string& stage, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FLAGSHIP_ROLLBACK_H
