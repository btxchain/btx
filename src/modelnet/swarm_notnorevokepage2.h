// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOREVOKEPAGE2_H
#define BTX_MODELNET_SWARM_NOTNOREVOKEPAGE2_H

#include <string>

namespace modelnet {

/**
 * A local note about one page. revoked marks the member revoked.
 * want_read asks this note to read a later page.
 *
 * A revoked member reads no later page. read stays false on every path.
 */
struct SwarmNotNoRevokePage2 {
    std::string page_id;
    bool revoked{false};
    bool want_read{false};
};

/**
 * Outcome of noting a page. read stays false on every path.
 * A revoked member reads no later page.
 */
struct SwarmNotNoRevokePage2Result {
    std::string code;
    bool read{false};
};

/**
 * Note a page without reading a later page. Order, first match wins:
 * an empty page_id is PAGE. revoked is NOT_READ even when want_read
 * is false. want_read is HELD. Otherwise the note is NOTED and err is
 * cleared. read stays false on every path. A revoked member reads no
 * later page.
 */
SwarmNotNoRevokePage2Result SwarmNoteNotNoRevokePage2(const SwarmNotNoRevokePage2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOREVOKEPAGE2_H
