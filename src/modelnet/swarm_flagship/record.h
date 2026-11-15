// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FLAGSHIP_RECORD_H
#define BITCOIN_MODELNET_SWARM_FLAGSHIP_RECORD_H

#include <string>

namespace modelnet {

class SwarmFlagshipLedger;

/**
 * Apply one Record decision to the ledger.
 * Only a Store outcome writes, and it writes the evidence id alone.
 * A stored id does not pass the stage.
 */
class SwarmFlagshipRecord {
public:
    bool apply(SwarmFlagshipLedger& ledger,
               const std::string& stage,
               const std::string& evidence,
               std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FLAGSHIP_RECORD_H
