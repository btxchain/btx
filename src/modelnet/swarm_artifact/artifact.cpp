// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_artifact/artifact.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmArtifact::Capture(std::string& err)
{
    return m_capture.Capture(err);
}

bool SwarmArtifact::Split(std::string& err)
{
    return m_split.Split(m_capture.bytes(), err);
}

bool SwarmArtifact::Offer(int64_t index, const std::string& bytes, std::string& err)
{
    return m_offers.Offer(index, bytes, err);
}

bool SwarmArtifact::Join(std::string& err)
{
    return m_join.Join(m_capture.bytes(), m_split.pieces(), m_offers.table(), err);
}

} // namespace modelnet
