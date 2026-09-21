// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/transport_pq.h>

#include <modelnet/pq1_runtime.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>

#include <array>
#include <cctype>
#include <cstring>
#include <vector>

namespace modelnet {
namespace {

std::string OpenSslErr()
{
    char buf[256];
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    return buf;
}

} // namespace

bool PinPq1SslCtx(void* ssl_ctx, std::string& err)
{
    auto* ctx = static_cast<SSL_CTX*>(ssl_ctx);
    if (!ctx) {
        err = "no ctx";
        return false;
    }
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1) {
        err = "TLS1.3 only";
        return false;
    }
    // Pure ML-KEM-768. Never X25519MLKEM768 / SecP256r1MLKEM768.
    if (SSL_CTX_set1_groups_list(ctx, "MLKEM768") != 1) {
        err = "MLKEM768 unavailable";
        return false;
    }
    if (SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384") != 1) {
        err = "AES-256-GCM-SHA384 unavailable";
        return false;
    }
    if (SSL_CTX_set1_sigalgs_list(ctx, "mldsa44") != 1) {
        err = "mldsa44 unavailable";
        return false;
    }
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET | SSL_OP_NO_COMPRESSION |
                                 SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_TLSv1 |
                                 SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_max_early_data(ctx, 0);
    // Stay under common WAN/NAT MTU. Default 16 KiB records stalled granite
    // retrieve (host Send-Q filled, client Recv-Q empty).
    if (SSL_CTX_set_max_send_fragment(ctx, 512) != 1) {
        err = "max_send_fragment";
        return false;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       [](int preverify_ok, X509_STORE_CTX*) -> int {
                           // Self-signed ML-DSA is expected; pin checks happen after handshake.
                           (void)preverify_ok;
                           return 1;
                       });
    return true;
}

Pq1Context::Pq1Context()
{
    Pq1InitOpenSsl();
    m_ctx = SSL_CTX_new(TLS_method());
    if (!m_ctx) {
        m_error = "SSL_CTX_new failed";
        return;
    }
    if (!PinPq1SslCtx(m_ctx, m_error)) {
        SSL_CTX_free(static_cast<SSL_CTX*>(m_ctx));
        m_ctx = nullptr;
        return;
    }
    m_ready = true;
}

Pq1Context::~Pq1Context()
{
    if (m_ctx) SSL_CTX_free(static_cast<SSL_CTX*>(m_ctx));
}

bool Pq1Context::LoadSelfSignedMlDsa(const std::string& cert_pem, const std::string& key_pem, std::string& err)
{
    if (!m_ctx) {
        err = "no ctx";
        return false;
    }
    BIO* cbio = BIO_new_mem_buf(cert_pem.data(), static_cast<int>(cert_pem.size()));
    X509* cert = PEM_read_bio_X509(cbio, nullptr, nullptr, nullptr);
    BIO_free(cbio);
    if (!cert) {
        err = "cert pem";
        return false;
    }
    BIO* kbio = BIO_new_mem_buf(key_pem.data(), static_cast<int>(key_pem.size()));
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(kbio, nullptr, nullptr, nullptr);
    BIO_free(kbio);
    if (!pkey) {
        X509_free(cert);
        err = "key pem";
        return false;
    }
    auto* ctx = static_cast<SSL_CTX*>(m_ctx);
    if (SSL_CTX_use_certificate(ctx, cert) != 1 || SSL_CTX_use_PrivateKey(ctx, pkey) != 1 ||
        SSL_CTX_check_private_key(ctx) != 1) {
        err = "use cert/key";
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return false;
    }
    EVP_PKEY_free(pkey);
    X509_free(cert);
    return true;
}

bool InspectNegotiated(void* ssl_void, NegotiatedPq1& out)
{
    auto* ssl = static_cast<SSL*>(ssl_void);
    if (!ssl) return false;
    out.tls_version = SSL_get_version(ssl) ? SSL_get_version(ssl) : "";
    const char* group = SSL_get0_group_name(ssl);
    out.group = group ? group : "";
    const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl);
    out.ciphersuite = cipher ? SSL_CIPHER_get_name(cipher) : "";
    const char* sig = nullptr;
#if OPENSSL_VERSION_NUMBER >= 0x30200000L
    SSL_get0_peer_signature_name(ssl, &sig);
#endif
    if (sig && *sig) {
        out.sigalg = sig;
    } else {
        int nid = 0;
        if (SSL_get_peer_signature_nid(ssl, &nid) == 1 && nid != 0) {
            const char* sn = OBJ_nid2sn(nid);
            out.sigalg = sn ? sn : "";
        } else {
            out.sigalg.clear();
        }
    }
    out.ok = IsStrictPq1(out);
    return true;
}

bool IsStrictPq1(const NegotiatedPq1& n)
{
    if (n.tls_version != "TLSv1.3") return false;
    if (n.group != "MLKEM768" && n.group != "mlkem768") return false;
    if (n.ciphersuite.find("AES_256_GCM_SHA384") == std::string::npos &&
        n.ciphersuite.find("AES256-GCM-SHA384") == std::string::npos) {
        return false;
    }
    // Hybrid groups must never pass even if a library reports them under another alias.
    if (n.group.find("X25519") != std::string::npos || n.group.find("SecP") != std::string::npos) return false;
    std::string sig = n.sigalg;
    for (char& c : sig) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (sig != "mldsa44" && sig != "ml-dsa-44" && sig != "mldsa_44") return false;
    return true;
}

bool HandshakePair(Pq1Context& server, Pq1Context& client, NegotiatedPq1& negotiated, std::string& err)
{
    if (!server.Ready() || !client.Ready()) {
        err = "PQ1 context not ready: " + (server.Ready() ? client.Error() : server.Error());
        return false;
    }
    SSL* ssl_s = SSL_new(static_cast<SSL_CTX*>(server.SslCtx()));
    SSL* ssl_c = SSL_new(static_cast<SSL_CTX*>(client.SslCtx()));
    if (!ssl_s || !ssl_c) {
        err = "SSL_new";
        SSL_free(ssl_s);
        SSL_free(ssl_c);
        return false;
    }
    BIO* b1 = nullptr;
    BIO* b2 = nullptr;
    if (BIO_new_bio_pair(&b1, 0, &b2, 0) != 1) {
        err = "BIO_new_bio_pair";
        SSL_free(ssl_s);
        SSL_free(ssl_c);
        return false;
    }
    SSL_set_bio(ssl_s, b1, b1);
    SSL_set_bio(ssl_c, b2, b2);
    SSL_set_accept_state(ssl_s);
    SSL_set_connect_state(ssl_c);
    int rc_c = 0, rc_s = 0;
    for (int i = 0; i < 64; ++i) {
        rc_c = SSL_do_handshake(ssl_c);
        rc_s = SSL_do_handshake(ssl_s);
        if (rc_c == 1 && rc_s == 1) break;
    }
    if (rc_c != 1 || rc_s != 1) {
        err = std::string("handshake failed: ") + OpenSslErr();
        SSL_free(ssl_c);
        SSL_free(ssl_s);
        return false;
    }
    InspectNegotiated(ssl_c, negotiated);
    if (!IsStrictPq1(negotiated)) {
        err = "negotiated parameters are not strict PQ1 group=" + negotiated.group +
              " cipher=" + negotiated.ciphersuite + " ver=" + negotiated.tls_version;
        SSL_free(ssl_c);
        SSL_free(ssl_s);
        return false;
    }
    SSL_free(ssl_c);
    SSL_free(ssl_s);
    return true;
}

} // namespace modelnet
