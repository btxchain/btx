// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_TRANSPORT_PQ_H
#define BITCOIN_MODELNET_TRANSPORT_PQ_H

#include <modelnet/types.h>

#include <memory>
#include <string>
#include <vector>

namespace modelnet {

struct NegotiatedPq1 {
    std::string tls_version;
    std::string group;
    std::string ciphersuite;
    std::string sigalg;
    bool ok{false};
};

/** Isolated strict-PQ TLS 1.3 context. Fail closed; no hybrid/classical fallback. */
class Pq1Context {
    void* m_ctx{nullptr}; // SSL_CTX*
    std::string m_error;
    bool m_ready{false};

public:
    Pq1Context();
    ~Pq1Context();
    Pq1Context(const Pq1Context&) = delete;
    Pq1Context& operator=(const Pq1Context&) = delete;
    bool Ready() const { return m_ready; }
    const std::string& Error() const { return m_error; }
    void* SslCtx() const { return m_ctx; }
    bool LoadSelfSignedMlDsa(const std::string& cert_pem, const std::string& key_pem, std::string& err);
};

/** Pin TLS 1.3 / MLKEM768 / AES-256-GCM-SHA384 / mldsa44 on an SSL_CTX. */
bool PinPq1SslCtx(void* ssl_ctx, std::string& err);

bool InspectNegotiated(void* ssl, NegotiatedPq1& out);
bool IsStrictPq1(const NegotiatedPq1& n);
bool HandshakePair(Pq1Context& server, Pq1Context& client, NegotiatedPq1& negotiated, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_TRANSPORT_PQ_H
