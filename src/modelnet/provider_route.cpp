// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/provider_route.h>

#include <crypto/common.h>
#include <modelnet/crypto.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cstring>

namespace modelnet {
namespace {

constexpr const char* kRecordType = "btx-provider-v1";
constexpr int64_t PERSIST_MAX_AGE_MS = 7LL * 24 * 60 * 60 * 1000;

void PutU16(std::vector<unsigned char>& b, uint16_t v)
{
    unsigned char tmp[2];
    WriteLE16(tmp, v);
    b.insert(b.end(), tmp, tmp + 2);
}

void PutU32(std::vector<unsigned char>& b, uint32_t v)
{
    unsigned char tmp[4];
    WriteLE32(tmp, v);
    b.insert(b.end(), tmp, tmp + 4);
}

void PutU64(std::vector<unsigned char>& b, uint64_t v)
{
    unsigned char tmp[8];
    WriteLE64(tmp, v);
    b.insert(b.end(), tmp, tmp + 8);
}

int BucketIndex(const Digest48& self, const Digest48& other)
{
    for (size_t i = 0; i < Digest48::SIZE; ++i) {
        const unsigned char x = self.data[i] ^ other.data[i];
        if (x != 0) return static_cast<int>(i);
    }
    return 0;
}

bool XorCloser(const Digest48& target, const RouteContact& a, const RouteContact& b)
{
    for (size_t i = 0; i < Digest48::SIZE; ++i) {
        const unsigned char ua = a.id.data[i] ^ target.data[i];
        const unsigned char ub = b.id.data[i] ^ target.data[i];
        if (ua < ub) return true;
        if (ua > ub) return false;
    }
    return false;
}

} // namespace

std::vector<unsigned char> ProviderRecordPreimage(const ProviderRecord& r)
{
    std::vector<unsigned char> b;
    b.reserve(128 + r.endpoints.size() * 32);
    b.insert(b.end(), r.resource.data.begin(), r.resource.data.end());
    b.insert(b.end(), r.service_id.data.begin(), r.service_id.data.end());
    b.push_back(r.complete ? 1 : 0);
    PutU64(b, r.seq);
    PutU64(b, static_cast<uint64_t>(r.expiry_ms));
    const uint16_t n_ep = static_cast<uint16_t>(std::min(r.endpoints.size(), PROVIDER_MAX_ENDPOINTS));
    PutU16(b, n_ep);
    for (uint16_t i = 0; i < n_ep; ++i) {
        const auto& ep = r.endpoints[i];
        const uint16_t n = static_cast<uint16_t>(std::min(ep.size(), size_t{256}));
        PutU16(b, n);
        b.insert(b.end(), ep.begin(), ep.begin() + n);
    }
    const uint16_t n_r = static_cast<uint16_t>(std::min(r.ranges.size(), PROVIDER_MAX_RANGES));
    PutU16(b, n_r);
    for (uint16_t i = 0; i < n_r; ++i) {
        PutU32(b, r.ranges[i].first);
        PutU32(b, r.ranges[i].count);
    }
    const uint16_t nk = static_cast<uint16_t>(std::min(r.reachability_kind.size(), size_t{32}));
    PutU16(b, nk);
    b.insert(b.end(), r.reachability_kind.begin(), r.reachability_kind.begin() + nk);
    return b;
}

bool SignProviderRecord(ProviderRecord& r, Span<const unsigned char> sk, std::string& err)
{
    if (r.pubkey.size() != MLDSA44_PK) {
        err = "pubkey";
        return false;
    }
    r.service_id = ProviderId(Span<const unsigned char>{r.pubkey.data(), r.pubkey.size()});
    const auto pre = ProviderRecordPreimage(r);
    const Digest48 hashed = DomainHash("BTX/ModelProviderRecord/v1",
                                        Span<const unsigned char>{pre.data(), pre.size()});
    return SignMlDsa44(sk, Span<const unsigned char>{hashed.data.data(), hashed.data.size()}, r.sig, err);
}

bool VerifyProviderRecord(const ProviderRecord& r, int64_t now_ms, std::string& err)
{
    if (r.expiry_ms <= now_ms) {
        err = "expired";
        return false;
    }
    if (r.pubkey.size() != MLDSA44_PK || r.sig.empty()) {
        err = "key/sig";
        return false;
    }
    if (r.endpoints.size() > PROVIDER_MAX_ENDPOINTS) {
        err = "too many endpoints";
        return false;
    }
    if (r.ranges.size() > PROVIDER_MAX_RANGES) {
        err = "too many ranges";
        return false;
    }
    if (ProviderId(Span<const unsigned char>{r.pubkey.data(), r.pubkey.size()}) != r.service_id) {
        err = "service identity mismatch";
        return false;
    }
    const auto pre = ProviderRecordPreimage(r);
    const Digest48 hashed = DomainHash("BTX/ModelProviderRecord/v1",
                                        Span<const unsigned char>{pre.data(), pre.size()});
    if (!VerifyMlDsa44(Span<const unsigned char>{r.pubkey.data(), r.pubkey.size()},
                       Span<const unsigned char>{hashed.data.data(), hashed.data.size()},
                       Span<const unsigned char>{r.sig.data(), r.sig.size()})) {
        err = "bad signature";
        return false;
    }
    return true;
}

UniValue ProviderRecordToJson(const ProviderRecord& r)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("type", kRecordType);
    o.pushKV("resource", r.resource.Hex());
    o.pushKV("service_id", r.service_id.Hex());
    UniValue eps(UniValue::VARR);
    for (const auto& e : r.endpoints) eps.push_back(e);
    o.pushKV("endpoints", eps);
    o.pushKV("reachability_kind", r.reachability_kind);
    o.pushKV("complete", r.complete);
    o.pushKV("ranges", PieceRangesToJson(r.ranges));
    o.pushKV("seq", static_cast<int64_t>(r.seq));
    o.pushKV("expiry_ms", r.expiry_ms);
    o.pushKV("pubkey", HexStr(r.pubkey));
    o.pushKV("sig", HexStr(r.sig));
    o.pushKV("inference", false);
    o.pushKV("generic_dht", false);
    return o;
}

bool ProviderRecordFromJson(const UniValue& o, ProviderRecord& r, std::string& err)
{
    r = {};
    if (!o.isObject()) {
        err = "object";
        return false;
    }
    if (!o.exists("type") || o["type"].get_str() != kRecordType) {
        err = "unknown record type";
        return false;
    }
    if (!Digest48::FromHex(o["resource"].get_str(), r.resource, err)) return false;
    if (!Digest48::FromHex(o["service_id"].get_str(), r.service_id, err)) return false;
    if (o.exists("endpoints") && o["endpoints"].isArray()) {
        for (const auto& e : o["endpoints"].getValues()) {
            if (r.endpoints.size() >= PROVIDER_MAX_ENDPOINTS) break;
            if (e.isStr()) r.endpoints.push_back(e.get_str());
        }
    }
    if (o.exists("reachability_kind")) r.reachability_kind = o["reachability_kind"].get_str();
    if (o.exists("complete")) r.complete = o["complete"].get_bool();
    if (o.exists("ranges") && !ParsePieceRangesJson(o["ranges"], r.ranges, err)) return false;
    if (o.exists("seq")) r.seq = o["seq"].getInt<int64_t>();
    if (o.exists("expiry_ms")) r.expiry_ms = o["expiry_ms"].getInt<int64_t>();
    if (o.exists("pubkey")) r.pubkey = ParseHex(o["pubkey"].get_str());
    if (o.exists("sig")) r.sig = ParseHex(o["sig"].get_str());
    return true;
}

RoutingTable::RoutingTable() : m_buckets(ROUTE_BUCKETS) {}

bool RoutingTable::Insert(const RouteContact& c, std::string& err)
{
    if (c.endpoint.empty()) {
        err = "endpoint";
        return false;
    }
    const int b = BucketIndex(m_self, c.id);
    auto& bucket = m_buckets[static_cast<size_t>(b) % m_buckets.size()];
    for (auto& prev : bucket) {
        if (prev.id == c.id) {
            prev = c;
            return true;
        }
    }
    int ng = 0;
    for (const auto& prev : bucket) {
        if (!c.netgroup.empty() && prev.netgroup == c.netgroup) ++ng;
    }
    if (ng >= ROUTE_NETGROUP_CAP) {
        err = "netgroup cap";
        return false;
    }
    if (bucket.size() >= ROUTE_K) {
        err = "bucket full";
        return false;
    }
    bucket.push_back(c);
    return true;
}

void RoutingTable::Drop(const Digest48& id)
{
    for (auto& bucket : m_buckets) {
        bucket.erase(std::remove_if(bucket.begin(), bucket.end(),
                                    [&](const RouteContact& c) { return c.id == id; }),
                     bucket.end());
    }
}

std::vector<RouteContact> RoutingTable::Closest(const Digest48& target, size_t n) const
{
    std::vector<RouteContact> all;
    for (const auto& bucket : m_buckets) {
        all.insert(all.end(), bucket.begin(), bucket.end());
    }
    std::sort(all.begin(), all.end(), [&](const RouteContact& a, const RouteContact& b) {
        return XorCloser(target, a, b);
    });
    if (all.size() > n) all.resize(n);
    return all;
}

std::vector<RouteContact> RoutingTable::Healthy(int64_t now_ms, int64_t max_age_ms) const
{
    std::vector<RouteContact> out;
    for (const auto& bucket : m_buckets) {
        for (const auto& c : bucket) {
            if (c.last_ok_ms > 0 && now_ms - c.last_ok_ms <= max_age_ms) out.push_back(c);
        }
    }
    return out;
}

size_t RoutingTable::Size() const
{
    size_t n = 0;
    for (const auto& bucket : m_buckets) n += bucket.size();
    return n;
}

UniValue RoutingTable::StatusJson() const
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("size", static_cast<int>(Size()));
    o.pushKV("buckets", static_cast<int>(m_buckets.size()));
    o.pushKV("addrman", false);
    return o;
}

std::vector<RouteContact> RoutingTable::PersistSubset() const
{
    std::vector<RouteContact> out;
    for (const auto& bucket : m_buckets) {
        for (const auto& c : bucket) {
            if (c.last_ok_ms <= 0) continue;
            out.push_back(c);
            if (out.size() >= 32) return out;
        }
    }
    return out;
}

bool ProviderCache::Put(const ProviderRecord& r, int64_t now_ms, std::string& err)
{
    if (!VerifyProviderRecord(r, now_ms, err)) return false;
    auto& vec = m_by_resource[r.resource.Hex()];
    for (auto& prev : vec) {
        if (prev.service_id == r.service_id) {
            if (r.seq < prev.seq) {
                err = "sequence rollback";
                return false;
            }
            prev = r;
            return true;
        }
    }
    size_t n = 0;
    for (const auto& kv : m_by_resource) n += kv.second.size();
    if (n >= m_cap) {
        err = "cache cap";
        return false;
    }
    vec.push_back(r);
    return true;
}

std::vector<ProviderRecord> ProviderCache::Get(const Digest48& resource, int64_t now_ms) const
{
    std::vector<ProviderRecord> out;
    auto it = m_by_resource.find(resource.Hex());
    if (it == m_by_resource.end()) return out;
    for (const auto& r : it->second) {
        if (r.expiry_ms > now_ms) out.push_back(r);
    }
    return out;
}

void ProviderCache::Expire(int64_t now_ms)
{
    for (auto it = m_by_resource.begin(); it != m_by_resource.end();) {
        it->second.erase(std::remove_if(it->second.begin(), it->second.end(),
                                         [&](const ProviderRecord& r) { return r.expiry_ms <= now_ms; }),
                         it->second.end());
        if (it->second.empty()) it = m_by_resource.erase(it);
        else ++it;
    }
}

size_t ProviderCache::Size() const
{
    size_t n = 0;
    for (const auto& kv : m_by_resource) n += kv.second.size();
    return n;
}

UniValue ProviderCache::StatusJson() const
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("size", static_cast<int>(Size()));
    o.pushKV("authoritative", false);
    return o;
}

bool LookupStep(RoutingTable& table, ProviderCache& cache, const Digest48& resource,
                 LookupBudget& budget, int64_t now_ms, std::vector<ProviderRecord>& found,
                 std::string& err)
{
    cache.Expire(now_ms);
    found = cache.Get(resource, now_ms);
    if (!found.empty()) return true;
    if (budget.queries >= budget.max_queries) {
        err = "query cap";
        return false;
    }
    if (budget.start_ms > 0 && now_ms - budget.start_ms > budget.max_ms) {
        err = "lookup timeout";
        return false;
    }
    ++budget.queries;
    (void)table.Closest(resource, static_cast<size_t>(LOOKUP_PARALLEL));
    found = cache.Get(resource, now_ms);
    if (found.empty()) {
        err = "no records";
        return false;
    }
    return true;
}

void NetworkEpoch::NoticeAddressChange(const std::string& ipv4, const std::string& ipv6)
{
    if (ipv4 == last_ipv4 && ipv6 == last_ipv6) return;
    last_ipv4 = ipv4;
    last_ipv6 = ipv6;
    ++epoch;
}

void NetworkEpoch::Sleep()
{
    asleep = true;
}

void NetworkEpoch::Wake()
{
    asleep = false;
    ++epoch;
}

bool BootstrapIndependent(bool bootstrap_down, size_t routing_size)
{
    return bootstrap_down && routing_size > 0;
}

bool StaleCacheIsNotAuthority()
{
    return true;
}

bool RoutingTouchesAddrMan()
{
    return false;
}

bool AcceptProviderRecordType(const std::string& type)
{
    return type == kRecordType;
}

bool LivePieceRangesRequireDirectQuery()
{
    return true;
}

bool RoutingServerRole(bool public_direct_or_mapped)
{
    return public_direct_or_mapped;
}

void LoadPersistedContacts(RoutingTable& table, const std::vector<RouteContact>& rows, int64_t now_ms,
                            int64_t max_age_ms)
{
    for (const auto& c : rows) {
        if (c.last_ok_ms <= 0) continue;
        if (now_ms - c.last_ok_ms > max_age_ms || now_ms - c.last_ok_ms > PERSIST_MAX_AGE_MS) continue;
        std::string err;
        (void)table.Insert(c, err);
    }
}

} // namespace modelnet
