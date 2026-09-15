// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_ROUTER_H
#define BITCOIN_MODELNET_ROUTER_H

#include <modelnet/types.h>

#include <map>
#include <string>
#include <vector>

namespace modelnet {

/** B0 / 1.1 §4.3: at most eight consulted routers. */
constexpr int MAX_ROUTER_CONTACTS = 8;
/** At most four concurrent router queries. */
constexpr int MAX_CONCURRENT_RESOLVE_QUERIES = 4;
/** Negative lookup cache lifetime is at most 60 seconds. */
constexpr int64_t NEGATIVE_RESOLVE_TTL_S = 60;

struct SignedRecordHint {
    Digest48 record_id;
    uint8_t kind{0};
    int64_t expiry{0};
    std::string provider_id;
    std::vector<unsigned char> payload;
    std::vector<unsigned char> signature;
    std::vector<unsigned char> pubkey;
    bool signed_ok{false};
};

struct ResolveQueryPlan {
    std::vector<std::string> contacts;
    int max_concurrent{MAX_CONCURRENT_RESOLVE_QUERIES};
    bool reserved_independent{false};
};

/**
 * Preferred contacts first. When an independent contact is available, reserve
 * at least one slot outside the preferred community. No official-domain
 * allowlist. Caps at eight contacts and four concurrent queries.
 */
bool PlanRouterQueries(const std::vector<std::string>& preferred,
                       const std::vector<std::string>& independent,
                       ResolveQueryPlan& out);

/** Incomplete answers only. Never converts a miss into “the model does not exist.” */
class NegativeResolveCache {
    std::map<std::string, int64_t> m_until;

    static std::string Key(uint8_t kind, const Digest48& digest);

public:
    void RememberIncomplete(uint8_t kind, const Digest48& digest, int64_t now);
    bool HasIncomplete(uint8_t kind, const Digest48& digest, int64_t now) const;
};

/** CPU-only discovery cache. No GPU, no wallet, no consensus authority. */
class RouterCache {
    std::map<std::string, SignedRecordHint> m_by_id;
    size_t m_max{4096};

public:
    bool Insert(const SignedRecordHint& rec, int64_t now, std::string& err);
    std::vector<SignedRecordHint> LookupExact(const Digest48& id, int64_t now) const;
    std::vector<SignedRecordHint> LookupExactKind(const Digest48& id, uint8_t kind, int64_t now) const;
    std::vector<SignedRecordHint> All(int64_t now) const;
    void Expire(int64_t now);
    size_t Size() const { return m_by_id.size(); }
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_ROUTER_H
