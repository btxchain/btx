// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_DATASETGRANT_H
#define BTX_MODELNET_SWARM_DATASETGRANT_H

#include <string>

namespace modelnet {

struct SwarmDatasetGrant {
    std::string grant_id;
    bool present{false};
    bool withdrawn{false};
    bool want_train{false};
};

struct SwarmDatasetGrantResult {
    std::string code;
    bool training{false};
};

/** Training stays off unless a dataset grant is present and not withdrawn. This check does not start it. */
SwarmDatasetGrantResult SwarmCheckDatasetGrant(const SwarmDatasetGrant& grant, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_DATASETGRANT_H
