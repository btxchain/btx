// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NOTMTLS_H
#define BITCOIN_MODELNET_SWARM_NOTMTLS_H

#include <string>

namespace modelnet {

struct SwarmNotMtls {
    std::string peer_id;
    bool want_session{false};
};

struct SwarmNotMtlsResult {
    std::string code;
    bool session_opened{false};
};

SwarmNotMtlsResult SwarmNoteNotMtls(const SwarmNotMtls& note, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NOTMTLS_H
