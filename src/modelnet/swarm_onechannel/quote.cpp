// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_onechannel/quote.h>

#include <modelnet/swarm_onechannel/atoms.h>
#include <modelnet/swarm_onechannel/codes.h>
#include <modelnet/swarm_onechannel/record.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmOneChannelDecideQuote(const SwarmOneChannelPool* existing,
                                const std::string& usd,
                                bool& store,
                                std::string& err)
{
    store = false;
    if (existing == nullptr) {
        err = SWARM_ONECHANNEL_POOL;
        return false;
    }
    if (usd.empty()) {
        err = SWARM_ONECHANNEL_QUOTE;
        return false;
    }
    store = true;
    err = SWARM_ONECHANNEL_NOT_BALANCE;
    return false;
}

void SwarmOneChannelApplyQuote(SwarmOneChannelPool& row, const std::string& usd)
{
    if (usd.empty()) {
        return;
    }
    const bool funded = row.funded;
    const bool holds_money = row.holds_money;
    const int64_t atoms = SwarmOneChannelKeepAtoms(row.atoms);
    row.quote = usd;
    row.funded = funded;
    row.holds_money = holds_money;
    // A quote is not an atom balance and does not spend.
    static_cast<void>(SwarmOneChannelQuotingMovesAtoms());
    row.atoms = atoms;
}

} // namespace modelnet
