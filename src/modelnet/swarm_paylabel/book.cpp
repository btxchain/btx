// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paylabel/book.h>

#include <utility>

namespace modelnet {

bool SwarmPayLabelBook::accepted() const
{
    return m_stored && SwarmPayLabelRecordUsable(m_record);
}

bool SwarmPayLabelBook::contains(const std::string& label) const
{
    if (!accepted()) return false;
    return m_record.label == label;
}

std::string SwarmPayLabelBook::label() const
{
    if (!accepted()) return {};
    return m_record.label;
}

bool SwarmPayLabelBook::store(const std::string& label)
{
    // A second store is not written. The first label stays.
    if (m_stored) return false;
    SwarmPayLabelRecord record = SwarmPayLabelMakeRecord(label);
    if (!SwarmPayLabelRecordUsable(record)) return false;
    m_record = std::move(record);
    m_stored = true;
    return true;
}

} // namespace modelnet
