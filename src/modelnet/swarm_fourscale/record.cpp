// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fourscale/record.h>

#include <modelnet/swarm_fourscale/limits.h>

#include <limits>

namespace modelnet {

SwarmFourScaleRecord SwarmFourScaleRecord::Make()
{
    SwarmFourScaleRecord record;
    record.m_steps = kSwarmFourScaleInitialStep;
    return record;
}

bool SwarmFourScaleRecord::advance()
{
    if (kSwarmFourScaleStepIncrement <= 0) return false;
    if (m_steps > std::numeric_limits<int64_t>::max() - kSwarmFourScaleStepIncrement) return false;
    m_steps += kSwarmFourScaleStepIncrement;
    return true;
}

} // namespace modelnet
