// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PQ1_RUNTIME_H
#define BITCOIN_MODELNET_PQ1_RUNTIME_H

#include <modelnet/types.h>
#include <util/fs.h>

#include <sys/socket.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace modelnet {

/** Spec B0 §8.4 resource ceilings. */
constexpr int PQ1_HTTP_WORKERS = 8;
constexpr int PQ1_UNIX_WORKERS = 2;
constexpr int PQ1_HTTP_QUEUE = 32;
constexpr int PQ1_UNIX_QUEUE = 16;
constexpr int PQ1_MAX_INBOUND = 16;
constexpr int PQ1_MAX_OUTBOUND = 8;
/** One IPv4 buyer must be able to pipeline PQ1_INFLIGHT_PIECES. Still << MAX_INBOUND. */
constexpr int PQ1_MAX_INBOUND_PER_NETGROUP = 8;
constexpr int PQ1_INFLIGHT_PIECES = 8;
/** Retrieve starts with this many pieces in flight per peer and adapts up to
 *  PQ1_INFLIGHT_PIECES from the measured rate (see PQ1_INFLIGHT_BUDGET_S). */
constexpr int PQ1_INFLIGHT_START = 2;
/** Size the in-flight window so it drains in about this long at the measured
 *  rate: half of PQ1_TRANSFER_MS, so a piece never races its own deadline. */
constexpr int PQ1_INFLIGHT_BUDGET_S = 300;
constexpr int PQ1_HANDSHAKE_MS = 10000;
constexpr int PQ1_IDLE_MS = 30000;
constexpr int PQ1_MAX_REQUESTS_PER_CONN = 32;
constexpr int PQ1_CONN_MAX_MS = 120000;
constexpr int PQ1_RELAY_CONNECT_MS = 5000;
constexpr int PQ1_RELAY_SPLICE_MS = 30000;
/** 4 MiB piece on a slow WAN; 120s fail-closed the granite fresh-buyer. */
constexpr int PQ1_TRANSFER_MS = 600000;
constexpr int PQ1_UNAUTH_HANDSHAKE_LIMIT = 4;
constexpr int PQ1_UNAUTH_WINDOW_S = 60;
constexpr int PQ1_PIECE_RETRIES = 8;
/** A peer's 429 + Retry-After asks us to slow down, not to give up: waits allowed per piece or grant. */
constexpr int PQ1_THROTTLE_WAITS = 120;
/** Longest a serving worker paces one piece under -modeluploadlimit; well inside a fetcher's PQ1_TRANSFER_MS. */
constexpr int64_t PQ1_SEED_PACE_MAX_MS = 120000;
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

// An inbound PQ1 connection holds its worker until it closes, idle time
// included, and one address may open PQ1_MAX_INBOUND_PER_NETGROUP of them:
// as many as there are workers. While another address waits, the workers are
// shared by address (R10-03). `held` counts the workers that each netgroup's
// connections hold now.

/** Index of the waiting connection (oldest first) to serve next: the oldest
 *  one whose netgroup holds the fewest workers. */
size_t Pq1NextWaiting(const std::vector<uint32_t>& waiting, const std::map<uint32_t, int>& held);
/** The netgroup that must close one connection so `waiting` gets a worker:
 *  the one holding the most, and only if that is at least two more than
 *  `waiting` holds. Each hand-over narrows the gap between the two, so over
 *  the same connections workers never pass back and forth. A buyer alone
 *  keeps every worker. */
std::optional<uint32_t> Pq1WorkerDonor(uint32_t waiting, const std::map<uint32_t, int>& held);

/** Milliseconds to wait so an upload of `nbytes` at `cap_bps` stays on the average
 *  rate. The bucket may go into debt. Returns -1 when that wait would exceed
 *  PQ1_SEED_PACE_MAX_MS; the caller then refuses without moving the bucket.
 *  A cap below the piece size must still make progress: tokens never exceed
 *  the cap, so requiring tokens >= nbytes refused every piece. */
inline int64_t SeedPaceWaitMs(int64_t tokens, int64_t nbytes, int64_t cap_bps)
{
    if (cap_bps <= 0 || nbytes < 0) return -1;
    const int64_t after = tokens - nbytes;
    if (after >= 0) return 0;
    const int64_t debt = -after;
    if (debt > (std::numeric_limits<int64_t>::max() / 1000)) return -1;
    const int64_t wait_ms = debt * 1000 / cap_bps;
    if (wait_ms > PQ1_SEED_PACE_MAX_MS) return -1;
    return wait_ms;
}

/** In-flight piece count that drains in about PQ1_INFLIGHT_BUDGET_S at `bytes_per_sec`. */
inline int InflightWindowForRate(double bytes_per_sec, int pool_n)
{
    if (pool_n < 1) return 0;
    if (bytes_per_sec < 0) bytes_per_sec = 0;
    const int want = static_cast<int>(bytes_per_sec * static_cast<double>(PQ1_INFLIGHT_BUDGET_S) /
                                       static_cast<double>(PIECE_SIZE));
    return std::clamp(want, 1, pool_n);
}

/** CLI used for ML-DSA-44 self-signed TLS files. Never Apple LibreSSL.
 *  Fetch-only start mints the certificate in-process and does not require this binary. */
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
