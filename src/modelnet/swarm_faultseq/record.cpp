// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_faultseq/record.h>

namespace modelnet {

void SwarmFaultSeqRecord::Clear()
{
    m_codes.clear();
    m_last.clear();
}

void SwarmFaultSeqRecord::Add(const std::string& code)
{
    m_codes.push_back(code);
    m_last = code;
}

const std::string& SwarmFaultSeqRecord::last() const
{
    return m_last;
}

} // namespace modelnet
