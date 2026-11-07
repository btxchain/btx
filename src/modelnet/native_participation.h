// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying file COPYING.
#ifndef BITCOIN_MODELNET_NATIVE_PARTICIPATION_H
#define BITCOIN_MODELNET_NATIVE_PARTICIPATION_H

#include <modelnet/policy.h>

#include <cstddef>
#include <cstdint>
#include <set>
#include <string>

namespace modelnet {

inline constexpr size_t NATIVE_PEER_MODEL_LIMIT{128};
inline constexpr int64_t NATIVE_PEER_TTL_MS{90000};

/** Made locally after PQ1 authentication and an exact network response. */
struct NativePeerObservation {
    std::string endpoint;
    std::string network;
    std::string transport_pin;
    int64_t observed_at_ms{0};
    std::set<std::string> advertised_models;
};

/** The same gate applies at enqueue, continuation and live-policy cancellation. */
inline bool AutomaticAcquisitionAllowed(const PreservationPolicy& policy, bool preservation_permitted)
{
    return policy.storage_quota_bytes > 0 &&
        ((policy.follow_configured_peers && policy.seed_mode == SeedMode::AUTO) ||
         (policy.preserve_rare && preservation_permitted));
}

inline bool NativePeerObservationFresh(const NativePeerObservation& observation, int64_t now_ms)
{
    return observation.observed_at_ms >= 0 && now_ms >= observation.observed_at_ms &&
        now_ms - observation.observed_at_ms < NATIVE_PEER_TTL_MS;
}

inline bool NativeAvailabilityMatchesNetwork(const UniValue& response, const std::string& network)
{
    return !network.empty() && response.isObject() && response["network"].isStr() &&
        response["network"].get_str() == network;
}

/** Only a retained model may enter automatic candidate selection. */
inline bool RecordNativeAdvertisedModel(NativePeerObservation& observation, const std::string& model_id)
{
    if (observation.advertised_models.count(model_id)) return true;
    if (observation.advertised_models.size() >= NATIVE_PEER_MODEL_LIMIT) return false;
    return observation.advertised_models.insert(model_id).second;
}

/** Empty pin is the pre-dial check; a connected session must supply its actual pin. */
inline bool NativePeerObservationAllows(const NativePeerObservation& observation,
                                       const std::string& network, const std::string& model_id,
                                       int64_t now_ms, const std::string& connected_pin = {})
{
    return !network.empty() && observation.network == network && !observation.endpoint.empty() &&
        observation.transport_pin.size() == 96 && NativePeerObservationFresh(observation, now_ms) &&
        observation.advertised_models.count(model_id) &&
        (connected_pin.empty() || connected_pin == observation.transport_pin);
}

} // namespace modelnet
#endif // BITCOIN_MODELNET_NATIVE_PARTICIPATION_H
