// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_ORIGIN_BROKER_H
#define BITCOIN_MODELNET_ORIGIN_BROKER_H

#include <modelnet/bootstrap_distributor.h>
#include <modelnet/types.h>
#include <univalue.h>

#include <cstdint>
#include <string>

namespace modelnet {

/** Spec §13.2 declared delivery modes. Default serving is PROXIED_NATIVE. */
enum class OriginDeliveryMode {
    PROXIED_NATIVE = 0,
    DIRECT_BEST_EFFORT = 1,
    DIRECT_GATEWAY_METERED = 2,
};

struct OriginBrokerPolicy {
    bool operator_allows_external{false};
    bool follow_redirects{false}; // must remain false; Issue fails if true
    uint64_t max_piece_bytes{PIECE_SIZE};
    uint64_t max_full_file_bytes{400ull * GIB};
    uint64_t grant_issuance_limit{1024}; // bounds grants issued, not URL reuse
    int64_t offer_ttl_ms{3600 * 1000};
};

struct OriginBrokerRequest {
    std::string artifact_id;
    int32_t file_index{0};
    uint64_t offset_bytes{0};
    uint64_t length_bytes{0};
    std::string object_generation;
    bool requester_allows_external{false};
    bool requester_accepts_full_ingest{false};
    OriginDeliveryMode requested_delivery{OriginDeliveryMode::PROXIED_NATIVE};
    std::string locator; // required for EXPLICIT_EXTERNAL / DIRECT_*
};

struct OriginBrokerOffer {
    int version{1};
    std::string offer_id;
    OriginMode mode{OriginMode::NATIVE_PROXY};
    OriginDeliveryMode delivery{OriginDeliveryMode::PROXIED_NATIVE};
    std::string artifact_id;
    int32_t file_index{0};
    uint64_t offset_bytes{0};
    uint64_t length_bytes{0};
    std::string object_generation;
    int64_t expires_at_ms{0};
    std::string external_url; // private bearer; omit from PublicJson
    std::string allowed_operation{"GET"};
    bool bearer_reusable{false};
    bool native_pq{true};
    bool requires_full_ingest{false};
    bool follow_redirects{false};
};

const char* OriginDeliveryModeName(OriginDeliveryMode m);
bool OriginDeliveryModeFromName(const std::string& name, OriginDeliveryMode& out);
OriginMode OriginModeFromDelivery(OriginDeliveryMode m);

/** Presigned GET is reusable bearer access, not a one-use / exact-byte meter. */
bool PresignedGetIsMeter();
/** Origin fetches never follow HTTP redirects. */
bool OriginFollowRedirectsAllowed();

bool LocatorEmbedsUserinfo(const std::string& locator);
/** True when a JSON object carries URL/credential/presign fields. */
bool OriginJsonHasCredential(const UniValue& json);

/**
 * Default: S3/R2 → provider broker → native PQ1 recipient (NATIVE_PROXY).
 * EXPLICIT_EXTERNAL / DIRECT_* only when operator + requester enable it and locator is set.
 * Never follows redirects. PublicJson never contains the cloud URL or secrets.
 */
class OriginBroker {
    OriginBrokerPolicy m_policy;
    uint64_t m_next_offer{1};
    uint64_t m_grants_issued{0};

public:
    explicit OriginBroker(OriginBrokerPolicy policy = {});

    bool Issue(const OriginBrokerRequest& req, int64_t now_ms, OriginBrokerOffer& out, std::string& err);

    /** Search / package / gossip: schema fields, no external_url or secrets. */
    UniValue PublicJson(const OriginBrokerOffer& offer) const;
    /** Authenticated-peer private delivery. Includes external_url bearer. */
    UniValue PrivateJson(const OriginBrokerOffer& offer) const;

    OriginOffer ToLegacyOffer(const OriginBrokerOffer& offer) const;
    uint64_t GrantsIssued() const { return m_grants_issued; }
    const OriginBrokerPolicy& Policy() const { return m_policy; }
    UniValue StatusJson() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_ORIGIN_BROKER_H
