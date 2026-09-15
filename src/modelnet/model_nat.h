// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_MODEL_NAT_H
#define BITCOIN_MODELNET_MODEL_NAT_H

#include <cstdint>
#include <string>

namespace modelnet {

constexpr uint16_t DEFAULT_MODEL_PORT = 29447;

enum class ModelNatStatus {
    UNKNOWN = 0,
    LOOPBACK = 1,
    UNMAPPED = 2,
    MAPPED = 3,
    DISABLED = 4,
};

struct ModelMapResult {
    ModelNatStatus status{ModelNatStatus::UNKNOWN};
    std::string external;
    uint16_t mapped_port{0};
    bool owned_mapping{false};
    std::string error;
};

/** Wallet / monetary RPC / attestor control — never mapped, never PEX'd. */
bool IsForbiddenControlPort(uint16_t port);
bool IsForbiddenControlEndpoint(const std::string& endpoint, std::string& err);
bool SplitListenBind(const std::string& bind, std::string& host, uint16_t& port);

bool MappingWouldExposeControlPlane(uint16_t port);
bool MayAdvertiseModelHost(bool operator_host, bool mapping_ok, bool loopback_only);
/** Renew before expiry. Failure to map never blocks helper startup. */
bool MappingRenewalDue(int64_t now_ms, int64_t created_ms, int64_t lifetime_ms);
constexpr int64_t MODEL_MAP_LIFETIME_MS = 3600 * 1000;
constexpr int64_t MODEL_MAP_RENEW_BEFORE_MS = 5 * 60 * 1000;

const char* ModelNatStatusName(ModelNatStatus s);

/**
 * Attempt PCP/NAT-PMP for the model-plane port only. Never GetListenPort().
 * Failure is fail-soft: helper stays unix+listen, advertised_host stays false.
 */
ModelMapResult AttemptModelPortMap(const std::string& bind, bool enable);
/** Lifetime 0 delete if we created the mapping. */
void ReleaseModelPortMap(ModelMapResult& mapping);

struct RelayConnectRequest {
    std::string endpoint;
    std::string expected_service_id;
    std::string presented_service_id;
};

bool ValidateRelayConnect(const RelayConnectRequest& req, bool relay_enabled, std::string& err);
bool ValidateRendezvous(const std::string& endpoint, const std::string& expected_id,
                        const std::string& presented_id, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_MODEL_NAT_H
