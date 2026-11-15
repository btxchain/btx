// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paylabel/record.h>

#include <modelnet/swarm_paylabel/vocabulary.h>

namespace modelnet {

SwarmPayLabelRecord SwarmPayLabelMakeRecord(const std::string& label)
{
    SwarmPayLabelRecord record;
    record.label = label;
    return record;
}

bool SwarmPayLabelRecordUsable(const SwarmPayLabelRecord& record)
{
    return SwarmPayLabelIsWork(record.label);
}

} // namespace modelnet
