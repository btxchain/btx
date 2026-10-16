// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/session_gate.h>

#include <modelnet/pq_transport_binding.h>

namespace modelnet {

bool Pq1ProfileOrReject(const std::string& tls, const std::string& group, const std::string& cipher,
                        const std::string& sigalg, std::string& err)
{
    return SupportedPq1Profile(tls, group, cipher, sigalg, err);
}

bool AcceptBoundSession(const std::string& tls_version, const std::string& group, const std::string& ciphersuite,
                        const std::string& sigalg, const std::string& research_root_hex,
                        Span<const unsigned char> transport_pk, const std::string& connection_id,
                        const std::string& nonce, int64_t now_ms, std::string& err)
{
    if (!SupportedPq1Profile(tls_version, group, ciphersuite, sigalg, err)) return false;

    static SessionProofStore store;
    TransportBindingRecord record;
    std::string bind_err;
    if (BindTransportKey(research_root_hex, transport_pk, record, bind_err)) {
        if (!store.Bind(record, err)) return false;
    }
    return store.Accept(connection_id, nonce, research_root_hex, now_ms, err);
}

} // namespace modelnet
