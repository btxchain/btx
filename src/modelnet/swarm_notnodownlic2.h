// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNODOWNLIC2_H
#define BTX_MODELNET_SWARM_NOTNODOWNLIC2_H

#include <string>

namespace modelnet {

/**
 * A local note about one download license. download marks a license that
 * permits download. want_train asks this note to treat a download license
 * as a training grant. want_redistribute asks this note to treat a
 * download license as a redistribution grant.
 *
 * A download license is not a training grant and not a redistribution
 * grant, so trained stays false and redistributed stays false on every
 * path.
 */
struct SwarmNotNoDownLic2 {
    std::string license_id;
    bool download{false};
    bool want_train{false};
    bool want_redistribute{false};
};

/**
 * Outcome of noting a download license. trained and redistributed stay
 * false on every path: a download license is not a training grant and not
 * a redistribution grant.
 */
struct SwarmNotNoDownLic2Result {
    std::string code;
    bool trained{false};
    bool redistributed{false};
};

/**
 * Note a download license without granting training or redistribution.
 * Order, first match wins: an empty license_id is LICENSE. download is
 * NOT_GRANT even when want_train and want_redistribute are false.
 * want_train or want_redistribute is NOT_GRANT. Otherwise the note is
 * NOTED and err is cleared.
 * trained and redistributed stay false on every path. A download license
 * is not a training grant and not a redistribution grant.
 */
SwarmNotNoDownLic2Result SwarmNoteNotNoDownLic2(const SwarmNotNoDownLic2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNODOWNLIC2_H
