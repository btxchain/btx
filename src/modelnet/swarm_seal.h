// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_SEAL_H
#define BTX_MODELNET_SWARM_SEAL_H

#include <string>

namespace modelnet {

/**
 * A piece offered to the local store. ciphertext means the body is sealed.
 * This process does not apply AES-GCM and does not decrypt.
 */
struct SwarmSealedPiece {
    std::string piece_id;
    std::string realm_id;
    bool ciphertext{false};
    bool private_record{false};
};

struct SwarmSealResult {
    bool stored{false};
    bool decrypted{false};
    bool bytes_moved{false};
    std::string code;
};

/**
 * Empty ids are PIECE. Ciphertext is REALM_SEALED and is not decrypted.
 * A private plaintext record is PRIVATE_DATA and is not stored as a public
 * object. A public plaintext record is stored locally and is not decrypted
 * because it was not sealed. bytes_moved stays false.
 */
SwarmSealResult SwarmAcceptSealedPiece(const SwarmSealedPiece& piece, std::string& err);

/**
 * Public discovery refuses a private family id, a prompt, a work detail, or a
 * data grant. Any of those is PRIVATE_DATA.
 */
bool SwarmPublishDiscovery(bool private_family, bool contains_prompt, bool contains_work_detail, bool contains_data_grant, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_SEAL_H
