// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_DIRECT_SEED_H
#define BITCOIN_MODELNET_DIRECT_SEED_H

#include <univalue.h>

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace modelnet {

struct DirectSeedLimits {
    int64_t ttl_ms{60 * 1000};
    int max_per_peer_per_minute{8};
    int max_per_netgroup_per_minute{16};
    int max_concurrent{4};
    uint64_t max_object_bytes{uint64_t{4} << 40};
    bool get_only{true};
};

struct DirectSeedOffer {
    std::string capability_id;
    std::string object_key;
    int64_t expires_at_ms{0};
    uint64_t size{0};
    uint64_t resume_offset{0};
    bool full_file{true};
    /** Bearer URL. Never persist in search/provider/event records. Redact in logs. */
    std::string presigned_get;
};

struct DirectSeedPolicy {
    DirectSeedLimits limits;
    std::string allowed_https_host;
    bool enabled{false};
};

bool DirectSeedUrlAllowed(const std::string& url, const DirectSeedPolicy& pol, std::string& err);
std::string RedactPresignedUrl(const std::string& url);
bool DirectSeedExpired(int64_t now_ms, const DirectSeedOffer& offer);
UniValue DirectSeedOfferPublicJson(const DirectSeedOffer& o);

/** Reject user-supplied arbitrary fetch targets (SSRF). Only operator origin host. */
bool LooksLikeMetadataServiceHost(const std::string& host);

/** IPv4 /24 or host string used as the netgroup rate-limit key. */
std::string DirectSeedNetgroup(const std::string& peer);

struct DirectSeedIssue {
    int64_t ms{0};
    std::string peer;
    std::string netgroup;
};

struct DirectSeedAdmissionState {
    std::mutex mu;
    std::vector<DirectSeedIssue> issued;
};

/** Record one presign issuance. Rate window is 60s; concurrent uses ttl_ms. */
bool DirectSeedAllowIssue(DirectSeedAdmissionState& st, const DirectSeedLimits& lim, const std::string& peer,
                          const std::string& netgroup, int64_t now_ms, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_DIRECT_SEED_H
