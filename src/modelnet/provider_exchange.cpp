// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/provider_exchange.h>
#include <modelnet/model_nat.h>

#include <algorithm>
#include <cctype>

namespace modelnet {
namespace {

bool ValidServiceHex(const std::string& s)
{
    if (s.empty()) return true;
    if (s.size() > 96) return false;
    for (char c : s) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    }
    return true;
}

} // namespace

ProviderExchange::ProviderExchange(PexLimits limits) : m_limits(limits) {}

bool ParseProviderHint(const UniValue& obj, int64_t now_ms, int64_t ttl_ms, ProviderHint& out, std::string& err)
{
    if (!obj.isObject()) {
        err = "provider object required";
        return false;
    }
    if (!obj.exists("endpoint") || !obj["endpoint"].isStr()) {
        err = "endpoint required";
        return false;
    }
    out = {};
    out.endpoint = obj["endpoint"].get_str();
    if (out.endpoint.size() > 128) {
        err = "endpoint too long";
        return false;
    }
    if (IsForbiddenPexEndpoint(out.endpoint, err)) return false;
    if (obj.exists("service_id") && obj["service_id"].isStr()) {
        out.service_id = obj["service_id"].get_str();
        if (!ValidServiceHex(out.service_id)) {
            err = "service_id";
            return false;
        }
    }
    if (obj.exists("model_id") && obj["model_id"].isStr()) {
        out.model_id = obj["model_id"].get_str();
        if (out.model_id.size() > 96) {
            err = "model_id";
            return false;
        }
    }
    if (obj.exists("availability") && obj["availability"].isStr()) {
        out.availability_summary = obj["availability"].get_str().substr(0, 64);
    }
    int64_t expiry = now_ms + ttl_ms;
    if (obj.exists("expiry") && obj["expiry"].isNum()) {
        expiry = obj["expiry"].getInt<int64_t>();
    } else if (obj.exists("ttl_ms") && obj["ttl_ms"].isNum()) {
        expiry = now_ms + obj["ttl_ms"].getInt<int64_t>();
    }
    if (expiry > now_ms + ttl_ms) expiry = now_ms + ttl_ms;
    if (expiry <= now_ms) {
        err = "expired";
        return false;
    }
    out.expiry_ms = expiry;
    out.received_ms = now_ms;
    return true;
}

bool IsForbiddenPexEndpoint(const std::string& endpoint, std::string& err)
{
    return IsForbiddenRelayEndpoint(endpoint, err);
}

bool ProviderExchange::Ingest(const std::string& from_endpoint,
                               const UniValue& body,
                               int64_t now_ms,
                               std::vector<ProviderHint>& accepted,
                               std::string& err)
{
    accepted.clear();
    if (!body.isObject()) {
        err = "pex object required";
        return false;
    }
    const std::string raw = body.write();
    m_stats.received += 1;
    if (raw.size() > m_limits.max_bytes) {
        err = "pex message too large";
        ++m_stats.rejected;
        return false;
    }
    auto tit = m_peer_times.find(from_endpoint);
    if (tit != m_peer_times.end()) {
        tit->second.erase(std::remove_if(tit->second.begin(), tit->second.end(),
                                         [&](int64_t t) { return now_ms - t > 60000; }),
                          tit->second.end());
        if (tit->second.empty()) {
            m_peer_times.erase(tit);
        } else if (static_cast<int>(tit->second.size()) >= m_limits.max_per_peer_per_minute) {
            err = "pex rate limited";
            ++m_stats.rejected;
            return false;
        }
    }
    m_peer_times[from_endpoint].push_back(now_ms);

    UniValue recs = UniValue(UniValue::VARR);
    if (body.exists("providers") && body["providers"].isArray()) recs = body["providers"];
    else if (body.exists("records") && body["records"].isArray()) recs = body["records"];
    if (recs.size() > m_limits.max_records) {
        err = "too many pex records";
        ++m_stats.rejected;
        return false;
    }
    Expire(now_ms);
    for (const auto& v : recs.getValues()) {
        ProviderHint h;
        std::string herr;
        if (!ParseProviderHint(v, now_ms, m_limits.ttl_ms, h, herr)) {
            ++m_stats.rejected;
            continue;
        }
        if (!m_self.empty() && h.endpoint == m_self) continue;
        bool dup = false;
        for (auto& c : m_cache) {
            if (c.endpoint == h.endpoint && c.service_id == h.service_id) {
                dup = true;
                if (h.expiry_ms > c.expiry_ms) c = h;
                break;
            }
        }
        if (dup) {
            ++m_stats.duplicates;
            continue;
        }
        if (m_cache.size() >= m_limits.cache_cap) {
            ++m_stats.rejected;
            continue;
        }
        m_cache.push_back(h);
        accepted.push_back(h);
        ++m_stats.accepted;
    }
    return true;
}

void ProviderExchange::Expire(int64_t now_ms)
{
    const auto before = m_cache.size();
    m_cache.erase(std::remove_if(m_cache.begin(), m_cache.end(),
                                 [&](const ProviderHint& h) { return h.expiry_ms <= now_ms; }),
                  m_cache.end());
    m_stats.expired += before - m_cache.size();
}

std::vector<ProviderHint> ProviderExchange::Recent(int64_t now_ms) const
{
    std::vector<ProviderHint> out;
    for (const auto& h : m_cache) {
        if (h.expiry_ms > now_ms) out.push_back(h);
    }
    return out;
}

UniValue ProviderExchange::Advertise(int64_t now_ms, size_t max_records) const
{
    UniValue arr(UniValue::VARR);
    std::vector<std::string> seen;
    auto emit = [&](const ProviderHint& h) {
        if (h.expiry_ms <= now_ms) return;
        if (arr.size() >= max_records) return;
        const std::string key = h.endpoint + "|" + h.model_id;
        if (std::find(seen.begin(), seen.end(), key) != seen.end()) return;
        seen.push_back(key);
        UniValue o(UniValue::VOBJ);
        o.pushKV("endpoint", h.endpoint);
        if (!h.service_id.empty()) o.pushKV("service_id", h.service_id);
        if (!h.model_id.empty()) o.pushKV("model_id", h.model_id);
        if (!h.availability_summary.empty()) o.pushKV("availability", h.availability_summary);
        o.pushKV("expiry", h.expiry_ms);
        arr.push_back(o);
    };
    for (const auto& h : m_local) emit(h);
    for (const auto& h : m_cache) emit(h);
    UniValue body(UniValue::VOBJ);
    body.pushKV("schema_version", 2);
    body.pushKV("providers", arr);
    return body;
}

void ProviderExchange::NoteLocal(const ProviderHint& hint)
{
    if (hint.endpoint.empty()) return;
    for (auto& c : m_local) {
        if (c.endpoint == hint.endpoint && c.model_id == hint.model_id) {
            c = hint;
            return;
        }
    }
    if (m_local.size() >= m_limits.max_records) m_local.erase(m_local.begin());
    m_local.push_back(hint);
}

} // namespace modelnet
