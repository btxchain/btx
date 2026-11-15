// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fourscale/swarm_fourscale.h>

#include <modelnet/swarm_fourscale/average.h>
#include <modelnet/swarm_fourscale/graduate.h>
#include <modelnet/swarm_fourscale/open.h>
#include <modelnet/swarm_fourscale/step.h>

namespace modelnet {

bool SwarmFourScale::Open(std::string& err)
{
    return SwarmFourScaleOpen{}.Apply(m_book, err);
}

bool SwarmFourScale::Step(const std::string& scale, std::string& err)
{
    return SwarmFourScaleStep{}.Apply(m_book, scale, err);
}

bool SwarmFourScale::Average(std::string& err) const
{
    return SwarmFourScaleAverage{}.refuse(err);
}

bool SwarmFourScale::Graduate(std::string& err) const
{
    return SwarmFourScaleGraduate{}.refuse(err);
}

bool SwarmFourScale::opened() const
{
    return m_book.opened();
}

bool SwarmFourScale::holds(const std::string& scale) const
{
    return m_book.holds(scale);
}

std::size_t SwarmFourScale::scale_count() const
{
    return m_book.size();
}

int64_t SwarmFourScale::steps(const std::string& scale) const
{
    return m_book.steps(scale);
}

bool SwarmFourScale::graduated() const
{
    return m_realm.graduated();
}

int64_t SwarmFourScale::bytes_moved() const
{
    return m_quiet.bytes_moved();
}

bool SwarmFourScale::gpu() const
{
    return m_quiet.gpu();
}

} // namespace modelnet
