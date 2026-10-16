// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SESSION_GATE_H
#define BITCOIN_MODELNET_SESSION_GATE_H

#include <span.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Strict PQ1 profile check. False, with err BTX035_PROFILE, for a classical
 * name or any suite other than TLS 1.3 / mlkem768 / AES-256-GCM-SHA384 / mldsa44.
 */
bool Pq1ProfileOrReject(const std::string& tls, const std::string& group, const std::string& cipher,
                        const std::string& sigalg, std::string& err);

/**
 * Accept one session proof for a research root bound to transport_pk.
 * Classical profiles fail BTX035_PROFILE. A root this store cannot bind fails
 * BTX035_UNBOUND. The same connection_id and nonce fails BTX035_REPLAY.
 */
bool AcceptBoundSession(const std::string& tls_version, const std::string& group, const std::string& ciphersuite,
                        const std::string& sigalg, const std::string& research_root_hex,
                        Span<const unsigned char> transport_pk, const std::string& connection_id,
                        const std::string& nonce, int64_t now_ms, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SESSION_GATE_H
