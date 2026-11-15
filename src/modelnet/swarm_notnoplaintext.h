// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPLAINTEXT_H
#define BTX_MODELNET_SWARM_NOTNOPLAINTEXT_H

#include <string>

namespace modelnet {

/**
 * A local note about one member. revoked marks that the member is
 * revoked. want_erase asks this note to erase previously delivered
 * plaintext.
 *
 * erased and bytes_moved stay false on every path. Previously delivered
 * plaintext stays after revoke and is not erased.
 */
struct SwarmNotNoPlaintext {
    std::string member_id;
    bool revoked{false};
    bool want_erase{false};
};

/**
 * Outcome of noting a member. erased and bytes_moved stay false on
 * every path. Previously delivered plaintext stays after revoke and is
 * not erased.
 */
struct SwarmNotNoPlaintextResult {
    std::string code;
    bool erased{false};
    bool bytes_moved{false};
};

/**
 * Note a member without erasing previously delivered plaintext.
 * Order, first match wins: an empty member_id is MEMBER. revoked is
 * RETAINED even when want_erase is false. want_erase is RETAINED.
 * Otherwise the note is NOTED and err is cleared. erased and
 * bytes_moved stay false on every path. Previously delivered plaintext
 * stays after revoke and is not erased.
 */
SwarmNotNoPlaintextResult SwarmNoteNotNoPlaintext(const SwarmNotNoPlaintext& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPLAINTEXT_H
