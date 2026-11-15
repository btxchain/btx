// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_DOWNLOADLIC_H
#define BTX_MODELNET_SWARM_DOWNLOADLIC_H

#include <string>

namespace modelnet {

/**
 * A local note about one download license. download records that a
 * license was obtained. want_train asks this note to treat the license
 * as a training grant. want_redist asks this note to treat the license
 * as a redistribution grant.
 *
 * A download license is not a training grant and not a redistribution grant.
 * training and granted stay false on every path.
 */
struct SwarmDownloadLic {
    std::string license_id;
    bool download{false};
    bool want_train{false};
    bool want_redist{false};
};

/**
 * Outcome of noting a download license. training and granted stay false
 * on every path.
 * A download license is not a training grant and not a redistribution grant.
 */
struct SwarmDownloadLicResult {
    std::string code;
    bool training{false};
    bool granted{false};
};

/**
 * Note a download license without granting training or redistribution.
 * Order, first match wins: an empty license_id is LICENSE. download is
 * NOT_GRANT even when want_train and want_redist are false. want_train
 * or want_redist is HELD. Otherwise the note is NOTED and err is cleared.
 * training and granted stay false on every path.
 * A download license is not a training grant and not a redistribution grant.
 */
SwarmDownloadLicResult SwarmNoteDownloadLicense(const SwarmDownloadLic& license, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_DOWNLOADLIC_H
