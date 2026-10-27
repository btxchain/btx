// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ONECHANNEL_QUOTE_H
#define BITCOIN_MODELNET_SWARM_ONECHANNEL_QUOTE_H

#include <modelnet/swarm_onechannel/record.h>

#include <string>

namespace modelnet {

/**
 * Decide whether usd may be stored on pool.
 * A null pool sets err to POOL and leaves store false.
 * An empty usd sets err to QUOTE and leaves store false.
 * A non-empty usd sets store and sets err to NOT_BALANCE. The function still returns false.
 * The quote is not an atom balance. holds_money is not decided here.
 */
bool SwarmOneChannelDecideQuote(const SwarmOneChannelPool* existing,
                                const std::string& usd,
                                bool& store,
                                std::string& err);

/**
 * Store a non-empty usd on row.
 * An empty usd stores nothing and leaves the row unchanged.
 * holds_money, funded, and atoms are written back to the values they already had.
 * Atoms stay at zero. This does not broadcast.
 */
void SwarmOneChannelApplyQuote(SwarmOneChannelPool& row, const std::string& usd);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ONECHANNEL_QUOTE_H
