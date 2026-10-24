// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nottrainlicense.h>

#include <string>

namespace modelnet {

SwarmNotTrainLicenseResult SwarmNoteNotTrainLicense(const SwarmNotTrainLicense& note, std::string& err)
{
    SwarmNotTrainLicenseResult result;
    result.granted = false;
    result.trained = false;
    // A download license is not a training grant.
    if (note.license_id.empty()) {
        result.code = "LICENSE";
        result.granted = false;
        result.trained = false;
        err = "LICENSE";
        return result;
    }
    if (note.want_train) {
        result.code = "NOT_GRANT";
        result.granted = false;
        result.trained = false;
        err = "NOT_GRANT";
        return result;
    }
    result.code = "NOTED";
    result.granted = false;
    result.trained = false;
    err.clear();
    return result;
}

} // namespace modelnet
