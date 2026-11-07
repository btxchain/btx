// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_quotefiat/record.h>

#include <modelnet/swarm_quotefiat/limits.h>
#include <modelnet/swarm_quotefiat/text.h>

namespace modelnet {

SwarmQuoteFiatRecord SwarmQuoteFiatRecord::Make(const std::string& usd)
{
    SwarmQuoteFiatRecord record;
    record.m_usd = SwarmQuoteFiatText{}.copy(usd);
    record.m_atoms = kSwarmQuoteFiatAtoms;
    record.m_is_balance = kSwarmQuoteFiatUsdIsBalance;
    return record;
}

bool SwarmQuoteFiatRecordUsable(const SwarmQuoteFiatRecord& record)
{
    return !record.usd().empty() &&
           record.atoms() == kSwarmQuoteFiatAtoms &&
           record.usd_is_balance() == kSwarmQuoteFiatUsdIsBalance;
}

} // namespace modelnet
