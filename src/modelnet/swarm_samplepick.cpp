// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_samplepick.h>

#include <algorithm>

namespace modelnet {

bool SwarmSamplePick::Select(const std::string& sample, const std::string& kind, std::string& err)
{
    if (sample.empty()) {
        err = "SAMPLE";
        return false;
    }
    if (kind != "public_trajectory" && kind != "synthetic_trajectory") {
        err = "PRIVATE_DATA";
        return false;
    }
    if (std::find(m_selected.begin(), m_selected.end(), sample) != m_selected.end()) {
        err = "REPLAY";
        return false;
    }
    m_selected.push_back(sample);
    err.clear();
    return true;
}

const std::vector<std::string>& SwarmSamplePick::Selected() const
{
    return m_selected;
}

} // namespace modelnet
