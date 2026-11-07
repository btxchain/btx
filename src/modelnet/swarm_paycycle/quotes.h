// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PAYCYCLE_QUOTES_H
#define BITCOIN_MODELNET_SWARM_PAYCYCLE_QUOTES_H

#include <map>
#include <string>

namespace modelnet {

/**
 * Fiat quotes. A quote is stored text. It is not a balance and it does not fund a pool.
 */
class SwarmPayQuotes {
public:
    bool Store(const std::string& pool, const std::string& usd, std::string& err);
    std::string get(const std::string& pool) const;

private:
    std::map<std::string, std::string> m_quotes;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PAYCYCLE_QUOTES_H
