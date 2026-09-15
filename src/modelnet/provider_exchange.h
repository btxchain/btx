// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PROVIDER_EXCHANGE_H
#define BITCOIN_MODELNET_PROVIDER_EXCHANGE_H

#include <univalue.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

/** BTX-native provider gossip. Not BitTorrent PEX wire. Not AddrMan. */
constexpr size_t PEX_MAX_RECORDS_PER_MESSAGE = 16;
constexpr size_t PEX_MAX_BYTES_PER_MESSAGE = 4096;
constexpr int PEX_MAX_PER_PEER_PER_MINUTE = 8;
constexpr int64_t PEX_DEFAULT_TTL_MS = 15 * 60 * 1000;
constexpr size_t PEX_CACHE_CAP = 128;

struct ProviderHint {
    std::string endpoint;
    std::string service_id;
    std::string model_id;
    std::string availability_summary;
    int64_t expiry_ms{0};
    int64_t received_ms{0};
};

struct PexLimits {
    size_t max_records{PEX_MAX_RECORDS_PER_MESSAGE};
    size_t max_bytes{PEX_MAX_BYTES_PER_MESSAGE};
    int max_per_peer_per_minute{PEX_MAX_PER_PEER_PER_MINUTE};
    int64_t ttl_ms{PEX_DEFAULT_TTL_MS};
    size_t cache_cap{PEX_CACHE_CAP};
};

struct PexStats {
    uint64_t received{0};
    uint64_t accepted{0};
    uint64_t rejected{0};
    uint64_t expired{0};
    uint64_t duplicates{0};
};

class ProviderExchange {
    PexLimits m_limits;
    std::vector<ProviderHint> m_cache;
    std::vector<ProviderHint> m_local;
    std::map<std::string, std::vector<int64_t>> m_peer_times;
    PexStats m_stats;

public:
    explicit ProviderExchange(PexLimits limits = {});

    bool Ingest(const std::string& from_endpoint,
                const UniValue& body,
                int64_t now_ms,
                std::vector<ProviderHint>& accepted,
                std::string& err);

    void Expire(int64_t now_ms);
    std::vector<ProviderHint> Recent(int64_t now_ms) const;
    UniValue Advertise(int64_t now_ms, size_t max_records) const;
    const PexStats& Stats() const { return m_stats; }
    void NoteSelf(const std::string& endpoint) { m_self = endpoint; }
    /** Upsert a locally seeded catalog hint so Advertise can introduce this node. */
    void NoteLocal(const ProviderHint& hint);

private:
    std::string m_self;
};

bool ParseProviderHint(const UniValue& obj, int64_t now_ms, int64_t ttl_ms, ProviderHint& out, std::string& err);
bool IsForbiddenPexEndpoint(const std::string& endpoint, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_PROVIDER_EXCHANGE_H
