// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVALENGINE_MANIFEST_H
#define BITCOIN_MODELNET_SWARM_EVALENGINE_MANIFEST_H

#include <cstddef>
#include <map>
#include <string>

namespace modelnet {

/**
 * Experiment manifest for one opened experiment.
 * Opening stores the id. An empty id is not a manifest. A second open
 * of the same id does not replace the first.
 */
struct SwarmEvaluationManifest {
    std::string experiment;
};

/**
 * Manifests for the candidate population, keyed by experiment id.
 * store refuses an empty id and an id already present. There is no erase.
 */
class SwarmEvaluationManifestBook {
public:
    bool contains(const std::string& experiment) const;
    std::size_t size() const;
    bool store(const std::string& experiment);

private:
    std::map<std::string, SwarmEvaluationManifest> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVALENGINE_MANIFEST_H
