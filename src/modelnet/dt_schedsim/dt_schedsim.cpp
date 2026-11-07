// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_schedsim/dt_schedsim.h>

#include <limits>

namespace modelnet {
namespace {

bool SpanProduct(int64_t span, int64_t microbatches, int64_t& out)
{
    if (span == 0) {
        out = 0;
        return true;
    }
    if (microbatches > std::numeric_limits<int64_t>::max() / span) return false;
    out = span * microbatches;
    return true;
}

} // namespace

bool DtSchedSim::InPlan(int64_t microbatch, int64_t stage) const
{
    return m_planned && microbatch >= 0 && stage >= 0 && microbatch < m_microbatches && stage < m_stages;
}

bool DtSchedSim::Plan(int64_t microbatches, int64_t stages, std::string& err)
{
    if (microbatches < 1 || stages < 1) {
        err = DT_SCHEDSIM_SHAPE;
        return false;
    }
    const int64_t span = stages - 1;
    int64_t edges = 0;
    if (!SpanProduct(span, microbatches, edges)) {
        err = DT_SCHEDSIM_SHAPE;
        return false;
    }
    m_microbatches = microbatches;
    m_stages = stages;
    m_bubbles_gpipe = edges;
    m_bubbles_1f1b = span;
    m_dependencies = edges;
    m_planned = true;
    m_ready.clear();
    err.clear();
    return true;
}

bool DtSchedSim::Forward(int64_t microbatch, int64_t stage, std::string& err)
{
    if (!InPlan(microbatch, stage)) {
        err = DT_SCHEDSIM_SHAPE;
        return false;
    }
    if (stage > 0 && !slot_ready(microbatch, stage - 1)) {
        err = DT_SCHEDSIM_DEPENDENCY;
        return false;
    }
    m_ready.insert(Slot{microbatch, stage});
    err.clear();
    return true;
}

bool DtSchedSim::DualPipe(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool DtSchedSim::slot_ready(int64_t microbatch, int64_t stage) const
{
    return m_ready.count(Slot{microbatch, stage}) != 0;
}

bool DtSchedSim::dependency_to_next(int64_t microbatch, int64_t stage) const
{
    if (!InPlan(microbatch, stage)) return false;
    if (stage >= m_stages - 1) return false;
    return true;
}

} // namespace modelnet
