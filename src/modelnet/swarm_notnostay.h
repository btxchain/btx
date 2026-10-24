// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSTAY_H
#define BTX_MODELNET_SWARM_NOTNOSTAY_H

#include <string>

namespace modelnet {

/**
 * A local note about one grant. revoked marks that the grant is
 * revoked. want_erase asks this note to erase previously delivered
 * plaintext.
 *
 * erased and bytes_moved stay false on every path. Previously delivered
 * plaintext stays after revoke.
 */
struct SwarmNotNoStay {
    std::string grant_id;
    bool revoked{false};
    bool want_erase{false};
};

/**
 * Outcome of noting a grant. erased and bytes_moved stay false on
 * every path. Previously delivered plaintext stays after revoke.
 */
struct SwarmNotNoStayResult {
    std::string code;
    bool erased{false};
    bool bytes_moved{false};
};

/**
 * Note a grant without erasing previously delivered plaintext.
 * Order, first match wins: an empty grant_id is GRANT. revoked is
 * STAYS even when want_erase is false. want_erase is HELD. Otherwise
 * the note is NOTED and err is cleared. erased and bytes_moved stay
 * false on every path. Previously delivered plaintext stays after
 * revoke.
 */
SwarmNotNoStayResult SwarmNoteNotNoStay(const SwarmNotNoStay& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSTAY_H
