// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PQ1_RUNTIME_H
#define BITCOIN_MODELNET_PQ1_RUNTIME_H

#include <modelnet/types.h>
#include <util/fs.h>

#include <sys/socket.h>

#include <atomic>
#include <cstdint>
#include <string>

namespace modelnet {

/** Spec B0 §8.4 resource ceilings. */
constexpr int PQ1_HTTP_WORKERS = 8;
constexpr int PQ1_HTTP_QUEUE = 32;
constexpr int PQ1_MAX_INBOUND = 16;
constexpr int PQ1_MAX_OUTBOUND = 8;
/** One IPv4 buyer must be able to pipeline PQ1_INFLIGHT_PIECES. Still << MAX_INBOUND. */
constexpr int PQ1_MAX_INBOUND_PER_NETGROUP = 8;
constexpr int PQ1_INFLIGHT_PIECES = 8;
constexpr int PQ1_HANDSHAKE_MS = 10000;
constexpr int PQ1_IDLE_MS = 30000;
/** 4 MiB piece on a slow WAN; 120s fail-closed the granite fresh-buyer. */
constexpr int PQ1_TRANSFER_MS = 600000;
constexpr int PQ1_UNAUTH_HANDSHAKE_LIMIT = 4;
constexpr int PQ1_UNAUTH_WINDOW_S = 60;
constexpr int PQ1_PIECE_RETRIES = 8;
constexpr int PQ1_PEER_TRANSIENT_TRIES = 1024;
constexpr int PQ1_PEER_RETRY_MS = 1000;
constexpr uint64_t PQ1_RECONNECT_BYTES = 8ULL << 30;
/** Grant headers carry ML-DSA-44 hex; 16 KiB is too small for a typed FreeGrant GET. */
constexpr size_t PQ1_HTTP_HEADER_CAP = 64 * 1024;

void SetPq1SocketOpts(int fd, bool nonblock = true);

bool WaitFd(int fd, bool want_write, int timeout_ms, std::atomic<bool>* stop, std::string& err);

bool SslHandshake(void* ssl, int fd, bool accept, int timeout_ms, std::atomic<bool>* stop, std::string& err);
bool SslWriteAll(void* ssl, int fd, const std::string& data, int timeout_ms, std::atomic<bool>* stop, std::string& err);
std::string SslReadHttp(void* ssl, int fd, size_t cap, int timeout_ms, std::atomic<bool>* stop, std::string* err = nullptr);
/** WAN RST / timeout / truncated HTTP: retry the same seeder. Pin mismatch is not transient. */
bool IsTransientPq1Error(const std::string& err);

bool ExtractPeerTransportPin(void* ssl, Digest48& out, std::string& err);
bool CheckOrStorePin(const fs::path& pinfile, const std::string& endpoint, const Digest48& pin, std::string& err);

uint32_t Ipv4Netgroup(const sockaddr* sa, socklen_t len);
int CountUnauthAndBump(uint32_t netgroup);
int UnauthCount(uint32_t netgroup);
void ClearUnauth(uint32_t netgroup);

class ConnLimits {
    std::atomic<int> inbound{0};
    std::atomic<int> outbound{0};

public:
    bool TryInbound(uint32_t netgroup);
    void ReleaseInbound(uint32_t netgroup);
    bool TryOutbound();
    void ReleaseOutbound();
    int Inbound() const { return inbound.load(); }
    int Outbound() const { return outbound.load(); }
};

ConnLimits& GlobalConnLimits();

/** CLI used for ML-DSA-44 self-signed TLS files. Never Apple LibreSSL. */
std::string OpensslBin();

/** PQ-19: drop inherited OPENSSL_CONF / provider-module paths before SSL init. */
void Pq1SanitizeOpenSslEnv();
/** OPENSSL_INIT_NO_LOAD_CONFIG after sanitize. Safe to call more than once. */
void Pq1InitOpenSsl();
bool Pq1OpenSslEnvIsClean();
/**
 * PQ-19 test hook: apply OPENSSL_CONF-equivalent SSL_CONF (X25519, AES-128,
 * TLS 1.2) to a fresh SSL_CTX, then PinPq1SslCtx. True if the pin holds or
 * the context fail-closes. Injection must not leave a weaker live profile.
 */
bool Pq1HostileConfCannotWeaken(std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_PQ1_RUNTIME_H
