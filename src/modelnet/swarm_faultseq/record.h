// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FAULTSEQ_RECORD_H
#define BTX_MODELNET_SWARM_FAULTSEQ_RECORD_H

#include <cstddef>
#include <string>
#include <vector>

namespace modelnet {

/** Journal codes returned by Apply, in step order. DONE is not a journal code. */
class SwarmFaultSeqRecord {
public:
    void Clear();
    void Add(const std::string& code);
    const std::string& last() const;
    const std::vector<std::string>& codes() const { return m_codes; }
    std::size_t size() const { return m_codes.size(); }

private:
    std::vector<std::string> m_codes;
    std::string m_last;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FAULTSEQ_RECORD_H
