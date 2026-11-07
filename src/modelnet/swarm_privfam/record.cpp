// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_privfam/record.h>

namespace modelnet {

SwarmPrivFamRecord SwarmPrivFamMakeRecord(const std::string& family, bool private_flag)
{
    SwarmPrivFamRecord record;
    record.family = family;
    record.private_flag = private_flag;
    return record;
}

bool SwarmPrivFamRecordUsable(const SwarmPrivFamRecord& record)
{
    return !record.family.empty() && record.private_flag;
}

} // namespace modelnet
