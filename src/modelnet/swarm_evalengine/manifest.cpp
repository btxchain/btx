// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evalengine/manifest.h>

namespace modelnet {

bool SwarmEvaluationManifestBook::contains(const std::string& experiment) const
{
    return m_rows.find(experiment) != m_rows.end();
}

std::size_t SwarmEvaluationManifestBook::size() const
{
    return m_rows.size();
}

bool SwarmEvaluationManifestBook::store(const std::string& experiment)
{
    if (experiment.empty() || contains(experiment)) {
        return false;
    }
    SwarmEvaluationManifest manifest;
    manifest.experiment = experiment;
    m_rows.emplace(experiment, manifest);
    return true;
}

} // namespace modelnet
