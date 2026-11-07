// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTCREDENTIAL_H
#define BTX_MODELNET_SWARM_NOTCREDENTIAL_H

#include <string>

namespace modelnet {

/**
 * A local note about one item. is_credential marks the item as a
 * credential. want_admit asks this note to admit that credential.
 *
 * A credential is not admitted and is not stored. admitted and stored
 * stay false on every path.
 */
struct SwarmNotCredential {
    std::string item_id;
    bool is_credential{false};
    bool want_admit{false};
};

/**
 * Outcome of noting a credential. admitted and stored stay false on every
 * path. A credential is not admitted and is not stored.
 */
struct SwarmNotCredentialResult {
    std::string code;
    bool admitted{false};
    bool stored{false};
};

/**
 * Note an item without admitting or storing a credential. Order, first
 * match wins: an empty item_id is ITEM. is_credential or want_admit is
 * CREDENTIAL. Otherwise the note is NOTED and err is clear. admitted and
 * stored stay false on every path. A credential is not admitted and is
 * not stored.
 */
SwarmNotCredentialResult SwarmNoteNotCredential(const SwarmNotCredential& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTCREDENTIAL_H
