// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PIECEPIPE_SEALED_H
#define BITCOIN_MODELNET_SWARM_PIECEPIPE_SEALED_H

#include <modelnet/swarm_piecepipe/store.h>

#include <string>
#include <vector>

namespace modelnet {

/**
 * Private data is PRIVATE_DATA. Ciphertext is REALM_SEALED.
 * Neither path stores the body. A public plaintext piece follows Accept.
 * This does not decrypt and does not move bytes.
 */
bool SwarmPiecePipeAcceptSealed(SwarmPiecePipeStore& store, const std::string& id, const std::vector<unsigned char>& body, bool ciphertext, bool is_private, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PIECEPIPE_SEALED_H
