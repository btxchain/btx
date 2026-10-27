// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_downloadlic.h>

#include <string>

namespace modelnet {

SwarmDownloadLicResult SwarmNoteDownloadLicense(const SwarmDownloadLic& license, std::string& err)
{
    SwarmDownloadLicResult result;
    result.training = false;
    result.granted = false;
    // A download license is not a training grant and not a redistribution grant.
    if (license.license_id.empty()) {
        result.code = "LICENSE";
        result.training = false;
        result.granted = false;
        err = "LICENSE";
        return result;
    }
    if (license.download) {
        result.code = "NOT_GRANT";
        result.training = false;
        result.granted = false;
        err = "NOT_GRANT";
        return result;
    }
    if (license.want_train || license.want_redist) {
        result.code = "HELD";
        result.training = false;
        result.granted = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.training = false;
    result.granted = false;
    err.clear();
    return result;
}

} // namespace modelnet
