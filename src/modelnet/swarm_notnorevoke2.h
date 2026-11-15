// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOREVOKE2_H
#define BTX_MODELNET_SWARM_NOTNOREVOKE2_H

#include <string>

namespace modelnet {

/**
 * A local note about one cache page. revoked marks the member revoked.
 * want_read asks this note to read a later cache page.
 *
 * A revoked member reads no later cache page. read and bytes_moved
 * stay false on every path.
 */
struct SwarmNotNoRevoke2 {
    std::string page_id;
    bool revoked{false};
    bool want_read{false};
};

/**
 * Outcome of noting a cache page. read and bytes_moved stay false on
 * every path. A revoked member reads no later cache page.
 */
struct SwarmNotNoRevoke2Result {
    std::string code;
    bool read{false};
    bool bytes_moved{false};
};

/**
 * Note a cache page without reading a later page. Order, first match
 * wins: an empty page_id is PAGE. revoked is NOT_READ even when
 * want_read is false. want_read is HELD. Otherwise the note is NOTED
 * and err is cleared. read and bytes_moved stay false on every path.
 * A revoked member reads no later cache page.
 */
SwarmNotNoRevoke2Result SwarmNoteNotNoRevoke2(const SwarmNotNoRevoke2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOREVOKE2_H
