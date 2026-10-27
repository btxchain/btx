// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fourscale/book.h>

#include <modelnet/swarm_fourscale/limits.h>
#include <modelnet/swarm_fourscale/names.h>

#include <utility>

namespace modelnet {

bool SwarmFourScaleBook::opened() const
{
    return m_opened;
}

std::size_t SwarmFourScaleBook::size() const
{
    if (!m_opened) return 0;
    return static_cast<std::size_t>(kSwarmFourScaleCount);
}

bool SwarmFourScaleBook::holds(const std::string& scale) const
{
    if (!m_opened) return false;
    const int index = SwarmFourScaleIndex(scale);
    return index >= 0 && index < kSwarmFourScaleCount;
}

int64_t SwarmFourScaleBook::steps(const std::string& scale) const
{
    if (!m_opened) return kSwarmFourScaleInitialStep;
    const int index = SwarmFourScaleIndex(scale);
    if (index < 0 || index >= kSwarmFourScaleCount) return kSwarmFourScaleInitialStep;
    return m_steps[static_cast<std::size_t>(index)].steps();
}

bool SwarmFourScaleBook::open()
{
    if (m_opened) return false;
    std::array<SwarmFourScaleRecord, kSwarmFourScaleCount> planted{};
    for (int i = 0; i < kSwarmFourScaleCount; ++i) {
        const char* name = SwarmFourScaleNameAt(i);
        if (name == nullptr || name[0] == '\0') return false;
        if (SwarmFourScaleIndex(name) != i) return false;
        SwarmFourScaleRecord record = SwarmFourScaleRecord::Make();
        if (record.steps() != kSwarmFourScaleInitialStep) return false;
        planted[static_cast<std::size_t>(i)] = std::move(record);
    }
    m_steps = std::move(planted);
    m_opened = true;
    return size() == static_cast<std::size_t>(kSwarmFourScaleCount);
}

bool SwarmFourScaleBook::advance(const std::string& scale)
{
    if (!m_opened) return false;
    const int index = SwarmFourScaleIndex(scale);
    if (index < 0 || index >= kSwarmFourScaleCount) return false;
    return m_steps[static_cast<std::size_t>(index)].advance();
}

} // namespace modelnet
