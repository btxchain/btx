// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/router.h>

#include <algorithm>
#include <set>

namespace modelnet {

bool PlanRouterQueries(const std::vector<std::string>& preferred,
                       const std::vector<std::string>& independent,
                       ResolveQueryPlan& out)
{
    out = {};
    out.max_concurrent = MAX_CONCURRENT_RESOLVE_QUERIES;
    std::set<std::string> seen;
    auto push = [&](const std::string& ep) {
        if (ep.empty() || out.contacts.size() >= static_cast<size_t>(MAX_ROUTER_CONTACTS)) return;
        if (!seen.insert(ep).second) return;
        out.contacts.push_back(ep);
    };
    for (const auto& p : preferred) push(p);
    out.reserved_independent = false;
    for (const auto& ind : independent) {
        if (ind.empty()) continue;
        const bool already = seen.count(ind) != 0;
        if (already) continue;
        if (out.contacts.size() >= static_cast<size_t>(MAX_ROUTER_CONTACTS)) {
            // Keep diversity: replace the last preferred slot with this independent contact.
            if (!out.contacts.empty()) {
                seen.erase(out.contacts.back());
                out.contacts.back() = ind;
                seen.insert(ind);
                out.reserved_independent = true;
            }
            break;
        }
        push(ind);
        out.reserved_independent = true;
        break;
    }
    if (out.max_concurrent > static_cast<int>(out.contacts.size())) {
        out.max_concurrent = static_cast<int>(out.contacts.size());
    }
    if (out.max_concurrent < 0) out.max_concurrent = 0;
    return true;
}

std::string NegativeResolveCache::Key(uint8_t kind, const Digest48& digest)
{
    return std::to_string(static_cast<int>(kind)) + "|" + digest.Hex();
}

void NegativeResolveCache::RememberIncomplete(uint8_t kind, const Digest48& digest, int64_t now)
{
    if (now < 0) now = 0;
    for (auto it = m_until.begin(); it != m_until.end();) {
        if (it->second <= now) it = m_until.erase(it);
        else ++it;
    }
    m_until[Key(kind, digest)] = now + NEGATIVE_RESOLVE_TTL_S;
}

bool NegativeResolveCache::HasIncomplete(uint8_t kind, const Digest48& digest, int64_t now) const
{
    const auto it = m_until.find(Key(kind, digest));
    if (it == m_until.end()) return false;
    return it->second > now;
}

namespace {
std::string HintKey(const Digest48& id, uint8_t kind)
{
    return std::to_string(static_cast<int>(kind)) + "|" + id.Hex();
}
size_t HintBytes(const SignedRecordHint& h)
{
    return h.payload.size() + h.signature.size() + h.pubkey.size();
}
} // namespace

bool RouterCache::Insert(const SignedRecordHint& rec, int64_t now, std::string& err)
{
    if (rec.expiry && rec.expiry < now) {
        err = "expired record";
        return false;
    }
    const std::string key = HintKey(rec.record_id, rec.kind);
    // Replacing the entry with the same key takes no new slot.
    const auto fits = [&] {
        const auto it = m_by_id.find(key);
        const bool held = it != m_by_id.end();
        return m_by_id.size() + (held ? 0 : 1) <= m_max &&
               m_bytes - (held ? HintBytes(it->second) : 0) + HintBytes(rec) <= m_max_bytes;
    };
    if (!fits()) {
        Expire(now);
        if (!fits()) {
            err = "router cache full";
            return false;
        }
    }
    const auto it = m_by_id.find(key);
    // The record id is the hash of the record body, so a live entry with the
    // same key already holds this record and refreshing it adds nothing new.
    if (it == m_by_id.end() || (it->second.expiry && it->second.expiry < now)) m_unsaved = true;
    if (it != m_by_id.end()) m_bytes -= HintBytes(it->second);
    m_bytes += HintBytes(rec);
    m_by_id[key] = rec;
    return true;
}

std::vector<SignedRecordHint> RouterCache::LookupExact(const Digest48& id, int64_t now) const
{
    std::vector<SignedRecordHint> out;
    for (const auto& kv : m_by_id) {
        if (kv.second.record_id != id) continue;
        if (kv.second.expiry && kv.second.expiry < now) continue;
        out.push_back(kv.second);
    }
    return out;
}

std::vector<SignedRecordHint> RouterCache::LookupExactKind(const Digest48& id, uint8_t kind, int64_t now) const
{
    std::vector<SignedRecordHint> out;
    const auto it = m_by_id.find(HintKey(id, kind));
    if (it == m_by_id.end()) return out;
    if (it->second.expiry && it->second.expiry < now) return out;
    out.push_back(it->second);
    return out;
}

std::vector<SignedRecordHint> RouterCache::All(int64_t now) const
{
    std::vector<SignedRecordHint> out;
    out.reserve(m_by_id.size());
    for (const auto& kv : m_by_id) {
        if (kv.second.expiry && kv.second.expiry < now) continue;
        out.push_back(kv.second);
    }
    return out;
}

void RouterCache::Expire(int64_t now)
{
    for (auto it = m_by_id.begin(); it != m_by_id.end();) {
        if (it->second.expiry && it->second.expiry < now) {
            m_bytes -= HintBytes(it->second);
            it = m_by_id.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace modelnet
