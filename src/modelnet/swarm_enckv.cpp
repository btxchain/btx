// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_enckv.h>

namespace modelnet {

SwarmEncryptedKvResult SwarmAdmitEncryptedKv(const SwarmEncryptedKvRequest& request, std::string& err)
{
    SwarmEncryptedKvResult result;
    result.admitted = false;
    result.bytes_moved = false;
    if (request.page_id.empty()) {
        result.code = "KV";
        err = "KV";
        return result;
    }
    if (request.plaintext) {
        result.code = "REALM_SEALED";
        err = "REALM_SEALED";
        return result;
    }
    if (!request.same_trust_domain) {
        result.code = "REALM_SEALED";
        err = "REALM_SEALED";
        return result;
    }
    if (!request.seal_present) {
        result.code = "REALM_SEALED";
        err = "REALM_SEALED";
        return result;
    }
    if (!request.engine_present) {
        result.code = "ENGINE_ABSENT";
        err = "ENGINE_ABSENT";
        return result;
    }
    result.admitted = true;
    result.code = "SEALED_LOCAL";
    err.clear();
    return result;
}

} // namespace modelnet
