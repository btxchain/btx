// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOLEAK2_H
#define BTX_MODELNET_SWARM_NOTNOLEAK2_H

#include <string>

namespace modelnet {

/**
 * A local note about one member. revoked marks the member revoked.
 * want_read asks this note to read a later page.
 *
 * A revoked member reads no later page. read and bytes_moved stay
 * false on every path.
 */
struct SwarmNotNoLeak2 {
    std::string member_id;
    bool revoked{false};
    bool want_read{false};
};

/**
 * Outcome of noting a member. read and bytes_moved stay false on every
 * path. A revoked member reads no later page.
 */
struct SwarmNotNoLeak2Result {
    std::string code;
    bool read{false};
    bool bytes_moved{false};
};

/**
 * Note a member without reading a later page. Order, first match wins:
 * an empty member_id is MEMBER. revoked is NOT_READ even when want_read
 * is false. want_read is HELD. Otherwise the note is NOTED and err is
 * cleared. read and bytes_moved stay false on every path. A revoked
 * member reads no later page.
 */
SwarmNotNoLeak2Result SwarmNoteNotNoLeak2(const SwarmNotNoLeak2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOLEAK2_H
