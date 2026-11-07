// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCRED_H
#define BTX_MODELNET_SWARM_NOTNOCRED_H

#include <string>

namespace modelnet {

/**
 * A local note about one credential id. want_use asks this note to use
 * that credential.
 *
 * This note uses no credential and opens no connection. used and
 * connected stay false on every path.
 */
struct SwarmNotNoCred {
    std::string cred_id;
    bool want_use{false};
};

/**
 * Outcome of noting a credential id. used and connected stay false
 * on every path. This note uses no credential and opens no connection.
 */
struct SwarmNotNoCredResult {
    std::string code;
    bool used{false};
    bool connected{false};
};

/**
 * Note a credential id without using a credential or opening a connection.
 * Order, first match wins: an empty cred_id is CRED.
 * want_use is REFUSED.
 * Otherwise the note is NOTED and err is clear.
 * used and connected stay false on every path. This note uses no
 * credential and opens no connection.
 */
SwarmNotNoCredResult SwarmNoteNotNoCred(const SwarmNotNoCred& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCRED_H
