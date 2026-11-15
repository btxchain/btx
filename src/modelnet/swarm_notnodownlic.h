// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNODOWNLIC_H
#define BTX_MODELNET_SWARM_NOTNODOWNLIC_H

#include <string>

namespace modelnet {

/**
 * A local note about one download license. download_only marks a license
 * that only permits download. want_train asks this note to treat a
 * download license as a training grant.
 *
 * A download license is not a training grant and moves no bytes, so
 * trained stays false and bytes_moved stays false on every path.
 */
struct SwarmNotNoDownLic {
    std::string license_id;
    bool download_only{false};
    bool want_train{false};
};

/**
 * Outcome of noting a download license. trained and bytes_moved stay false
 * on every path: a download license is not a training grant and moves no
 * bytes.
 */
struct SwarmNotNoDownLicResult {
    std::string code;
    bool trained{false};
    bool bytes_moved{false};
};

/**
 * Note a download license without granting training or moving bytes.
 * Order, first match wins: an empty license_id is LICENSE. download_only
 * is NOT_GRANT even when want_train is false. want_train is NOT_GRANT.
 * Otherwise the note is NOTED and err is cleared.
 * trained and bytes_moved stay false on every path. A download license is
 * not a training grant and moves no bytes.
 */
SwarmNotNoDownLicResult SwarmNoteNotNoDownLic(const SwarmNotNoDownLic& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNODOWNLIC_H
