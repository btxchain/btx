// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notdataset.h>

#include <string>

namespace modelnet {

SwarmNotDatasetResult SwarmNoteNotDataset(const SwarmNotDataset& note, std::string& err)
{
    SwarmNotDatasetResult result;
    result.training = false;
    // A withdrawn dataset authorization does not start a GPU job.
    if (note.dataset_id.empty()) {
        result.code = "DATASET";
        result.training = false;
        err = "DATASET";
        return result;
    }
    if (note.want_train) {
        result.code = "NOT_STARTED";
        result.training = false;
        err = "NOT_STARTED";
        return result;
    }
    result.code = "NOTED";
    result.training = false;
    err.clear();
    return result;
}

} // namespace modelnet
