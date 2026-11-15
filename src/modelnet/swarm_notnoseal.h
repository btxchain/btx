// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSEAL_H
#define BTX_MODELNET_SWARM_NOTNOSEAL_H

#include <string>

namespace modelnet {

/**
 * A local note about one realm. realm_id names the realm. want_seal asks
 * this note to seal a payload.
 *
 * This note does not seal with AES-GCM and moves no bytes. sealed and
 * bytes_moved stay false on every path.
 */
struct SwarmNotNoSeal {
    std::string realm_id;
    bool want_seal{false};
};

/**
 * Outcome of noting a realm without sealing. sealed and bytes_moved stay
 * false on every path: this note does not seal with AES-GCM and moves no
 * bytes.
 */
struct SwarmNotNoSealResult {
    std::string code;
    bool sealed{false};
    bool bytes_moved{false};
};

/**
 * Note a realm without sealing and without moving bytes. Order, first match
 * wins: an empty realm_id is REALM. want_seal is NOT_SEALED. Otherwise the
 * note is NOTED and err is clear. sealed and bytes_moved stay false on every
 * path. This note does not seal with AES-GCM and moves no bytes.
 */
SwarmNotNoSealResult SwarmNoteNotNoSeal(const SwarmNotNoSeal& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSEAL_H
