// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTAES_H
#define BTX_MODELNET_SWARM_NOTAES_H

#include <string>

namespace modelnet {

/**
 * A local note about one realm. realm_id names the realm. want_seal asks
 * this note to seal a payload with realm AES-GCM.
 *
 * Realm AES-GCM has not sealed a payload. sealed stays false on every
 * path. No hostnames or IPs are used.
 */
struct SwarmNotAes {
    std::string realm_id;
    bool want_seal{false};
};

/**
 * Outcome of noting a realm without AES-GCM. sealed stays false on every
 * path: realm AES-GCM has not sealed a payload.
 */
struct SwarmNotAesResult {
    std::string code;
    bool sealed{false};
};

/**
 * Note a realm without sealing a payload. Order, first match wins:
 * an empty realm_id is REALM. want_seal is NOT_SEALED. Otherwise the
 * note is NOTED and err is clear. sealed stays false on every path.
 * Realm AES-GCM has not sealed a payload.
 */
SwarmNotAesResult SwarmNoteNotAes(const SwarmNotAes& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTAES_H
