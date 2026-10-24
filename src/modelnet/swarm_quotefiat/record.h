// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_QUOTEFIAT_RECORD_H
#define BITCOIN_MODELNET_SWARM_QUOTEFIAT_RECORD_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * One stored fiat quote.
 * usd is the quote text. atoms stay 0. usd_is_balance stays false.
 * Make is the only writer of those fields. There is no setter.
 */
class SwarmQuoteFiatRecord {
public:
    static SwarmQuoteFiatRecord Make(const std::string& usd);

    const std::string& usd() const { return m_usd; }
    int64_t atoms() const { return m_atoms; }
    bool usd_is_balance() const { return m_is_balance; }

private:
    std::string m_usd;
    int64_t m_atoms{0};
    bool m_is_balance{false};
};

/**
 * The quote text is non-empty, atoms are 0, and the quote is not a balance.
 */
bool SwarmQuoteFiatRecordUsable(const SwarmQuoteFiatRecord& record);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_QUOTEFIAT_RECORD_H
