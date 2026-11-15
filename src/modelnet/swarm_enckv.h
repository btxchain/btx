// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_ENCKV_H
#define BTX_MODELNET_SWARM_ENCKV_H

#include <string>

namespace modelnet {

/**
 * Caller proof that an encrypted KV page may be admitted locally.
 * The flags are the proof. This request does not carry page bytes.
 */
struct SwarmEncryptedKvRequest {
    std::string page_id;
    bool plaintext{false};
    bool same_trust_domain{false};
    bool seal_present{false};
    bool engine_present{false};
};

/**
 * An admission answer. bytes_moved stays false: this function does not
 * encrypt, move bytes, or complete a transfer.
 */
struct SwarmEncryptedKvResult {
    bool admitted{false};
    bool bytes_moved{false};
    std::string code;
};

/**
 * Admits a sealed KV page only as a local label. bytes_moved stays false.
 * This flag compare does not encrypt, move bytes, or complete a transfer.
 *
 * Order: an empty page_id is KV, admitted false. plaintext is
 * REALM_SEALED and admitted false, even when same_trust_domain,
 * seal_present, and engine_present are true. same_trust_domain false is
 * REALM_SEALED and admitted false. seal_present false is REALM_SEALED
 * and admitted false. engine_present false is ENGINE_ABSENT and admitted
 * false. Otherwise the result is SEALED_LOCAL, admitted true, and err is
 * cleared. bytes_moved stays false on every path.
 */
SwarmEncryptedKvResult SwarmAdmitEncryptedKv(const SwarmEncryptedKvRequest& request, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_ENCKV_H
