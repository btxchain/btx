// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOLEAKPAGE2_H
#define BTX_MODELNET_SWARM_NOTNOLEAKPAGE2_H

#include <string>

namespace modelnet {

/**
 * A local note about one member. revoked marks the member revoked.
 * gradient marks a gradient leak. want_read asks this note to read a
 * later page.
 *
 * A revoked member or a gradient leak reads no later page. read and
 * bytes_moved stay false on every path.
 */
struct SwarmNotNoLeakPage2 {
    std::string member_id;
    bool revoked{false};
    bool gradient{false};
    bool want_read{false};
};

/**
 * Outcome of noting a member. read and bytes_moved stay false on every
 * path. A revoked member or a gradient leak reads no later page.
 */
struct SwarmNotNoLeakPage2Result {
    std::string code;
    bool read{false};
    bool bytes_moved{false};
};

/**
 * Note a member without reading a later page. Order, first match wins:
 * an empty member_id is MEMBER. If revoked or gradient is true, the
 * note is NOT_READ even when want_read is false. want_read is HELD.
 * Otherwise the note is NOTED and err is cleared. read and bytes_moved
 * stay false on every path. A revoked member or a gradient leak reads
 * no later page.
 */
SwarmNotNoLeakPage2Result SwarmNoteNotNoLeakPage2(const SwarmNotNoLeakPage2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOLEAKPAGE2_H
