// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PROVIDER_ROUTE_H
#define BITCOIN_MODELNET_PROVIDER_ROUTE_H

#include <modelnet/identity.h>
#include <modelnet/piece_ranges.h>
#include <modelnet/types.h>
#include <span.h>
#include <univalue.h>

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace modelnet {

constexpr int64_t PROVIDER_TTL_MS = 60 * 60 * 1000;
constexpr size_t PROVIDER_MAX_ENDPOINTS = 8;
constexpr size_t PROVIDER_MAX_RANGES = 32;
constexpr size_t ROUTE_BUCKETS = Digest48::SIZE * 8; // 384 bit-prefix buckets, not 48 byte buckets
constexpr size_t ROUTE_K = 8;
constexpr int ROUTE_NETGROUP_CAP = 2;
constexpr int LOOKUP_MAX_QUERIES = 16;
constexpr int LOOKUP_PARALLEL = 3;
constexpr int64_t LOOKUP_MAX_MS = 8000;

struct ProviderRecord {
    Digest48 resource;
    Digest48 service_id;
    std::vector<std::string> endpoints;
    std::string reachability_kind; // direct / mapped / relay
    bool complete{false};
    std::vector<PieceRange> ranges;
    uint64_t seq{0};
    int64_t expiry_ms{0};
    std::vector<unsigned char> pubkey;
    std::vector<unsigned char> sig;
};

std::vector<unsigned char> ProviderRecordPreimage(const ProviderRecord& r);
bool SignProviderRecord(ProviderRecord& r, Span<const unsigned char> sk, std::string& err);
bool VerifyProviderRecord(const ProviderRecord& r, int64_t now_ms, std::string& err);
UniValue ProviderRecordToJson(const ProviderRecord& r);
bool ProviderRecordFromJson(const UniValue& o, ProviderRecord& r, std::string& err);

struct RouteContact {
    Digest48 id;
    std::string endpoint;
    std::string netgroup;
    int64_t last_ok_ms{0};
    bool bootstrap{false};
};

class RoutingTable {
    std::vector<std::vector<RouteContact>> m_buckets;
    Digest48 m_self;

public:
    RoutingTable();
    void SetSelf(const Digest48& id) { m_self = id; }
    bool Insert(const RouteContact& c, std::string& err);
    void Drop(const Digest48& id);
    std::vector<RouteContact> Closest(const Digest48& target, size_t n) const;
    std::vector<RouteContact> Healthy(int64_t now_ms, int64_t max_age_ms) const;
    size_t Size() const;
    UniValue StatusJson() const;
    std::vector<RouteContact> PersistSubset() const;
};

/** Leading XOR bit (0 = MSB of byte 0). Distinct from first differing byte. */
int RoutingBucketIndex(const Digest48& self, const Digest48& other);

class ProviderCache {
    std::map<std::string, std::vector<ProviderRecord>> m_by_resource;
    size_t m_cap{256};

public:
    bool Put(const ProviderRecord& r, int64_t now_ms, std::string& err);
    std::vector<ProviderRecord> Get(const Digest48& resource, int64_t now_ms) const;
    void Expire(int64_t now_ms);
    size_t Size() const;
    UniValue StatusJson() const;
};

struct LookupBudget {
    int queries{0};
    int max_queries{LOOKUP_MAX_QUERIES};
    int64_t start_ms{0};
    int64_t max_ms{LOOKUP_MAX_MS};
};

bool LookupStep(RoutingTable& table, ProviderCache& cache, const Digest48& resource,
                 LookupBudget& budget, int64_t now_ms, std::vector<ProviderRecord>& found,
                 std::string& err);

struct NetworkEpoch {
    uint64_t epoch{0};
    std::string last_ipv4;
    std::string last_ipv6;
    bool asleep{false};
    void NoticeAddressChange(const std::string& ipv4, const std::string& ipv6);
    void Sleep();
    void Wake();
};

bool BootstrapIndependent(bool bootstrap_down, size_t routing_size);
bool StaleCacheIsNotAuthority();
bool RoutingTouchesAddrMan();
bool AcceptProviderRecordType(const std::string& type);
bool LivePieceRangesRequireDirectQuery();
bool RoutingServerRole(bool public_direct_or_mapped);
void LoadPersistedContacts(RoutingTable& table, const std::vector<RouteContact>& rows, int64_t now_ms,
                           int64_t max_age_ms);

} // namespace modelnet

#endif // BITCOIN_MODELNET_PROVIDER_ROUTE_H
