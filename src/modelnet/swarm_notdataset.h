// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTDATASET_H
#define BTX_MODELNET_SWARM_NOTDATASET_H

#include <string>

namespace modelnet {

/**
 * A local note about one dataset. want_train asks this note to start a
 * GPU training job from a withdrawn dataset authorization.
 *
 * A withdrawn dataset authorization does not start a GPU job. training
 * stays false on every path.
 */
struct SwarmNotDataset {
    std::string dataset_id;
    bool want_train{false};
};

/**
 * Outcome of noting a dataset train request. training stays false on every
 * path: a withdrawn dataset authorization does not start a GPU job.
 */
struct SwarmNotDatasetResult {
    std::string code;
    bool training{false};
};

/**
 * Note a dataset train request without starting a GPU job.
 * Order, first match wins: an empty dataset_id is DATASET. want_train is
 * NOT_STARTED. Otherwise the note is NOTED and err is clear.
 * training stays false on every path.
 */
SwarmNotDatasetResult SwarmNoteNotDataset(const SwarmNotDataset& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTDATASET_H
