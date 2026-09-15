// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/model_nat.h>

#include <common/netif.h>
#include <common/pcp.h>
#include <netaddress.h>
#include <random.h>
#include <util/threadinterrupt.h>

#include <algorithm>
#include <arpa/inet.h>
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>
#include <optional>
#include <vector>

namespace modelnet {
namespace {

const uint16_t kForbidden[] = {
    8332, 18332, 18443, 18444, 28332, 28333, 8333, 18333, 38332, 38333,
    18766, 18445, 8334, 28334,
};

bool ParseHostPort(const std::string& in, std::string& host, uint16_t& port)
{
    const auto colon = in.rfind(':');
    if (colon == std::string::npos || colon == 0) return false;
    host = in.substr(0, colon);
    if (!host.empty() && host.front() == '[' && host.back() == ']') {
        host = host.substr(1, host.size() - 2);
    }
    try {
        const int p = std::stoi(in.substr(colon + 1));
        if (p <= 0 || p > 65535) return false;
        port = static_cast<uint16_t>(p);
    } catch (...) {
        return false;
    }
    return !host.empty();
}

} // namespace

bool IsForbiddenControlPort(uint16_t port)
{
    if (port == 0) return true;
    for (uint16_t p : kForbidden) {
        if (p == port) return true;
    }
    return false;
}

bool SplitListenBind(const std::string& bind, std::string& host, uint16_t& port)
{
    return ParseHostPort(bind, host, port);
}

bool IsForbiddenControlEndpoint(const std::string& endpoint, std::string& err)
{
    std::string host;
    uint16_t port = 0;
    if (!ParseHostPort(endpoint, host, port)) {
        err = "bad endpoint";
        return true;
    }
    if (IsForbiddenControlPort(port)) {
        err = "control-plane port";
        return true;
    }
    // Hidden/attestor/wallet cookie paths never belong here.
    if (endpoint.find("cookie") != std::string::npos ||
        endpoint.find("wallet") != std::string::npos ||
        endpoint.find(".cookie") != std::string::npos) {
        err = "wallet path";
        return true;
    }
    return false;
}

bool MappingWouldExposeControlPlane(uint16_t port)
{
    return IsForbiddenControlPort(port);
}

bool MayAdvertiseModelHost(bool operator_host, bool mapping_ok, bool loopback_only)
{
    if (!operator_host) return false;
    if (loopback_only) return false;
    return mapping_ok;
}

bool MappingRenewalDue(int64_t now_ms, int64_t created_ms, int64_t lifetime_ms)
{
    if (lifetime_ms <= 0) return true;
    const int64_t renew_at = created_ms + lifetime_ms - MODEL_MAP_RENEW_BEFORE_MS;
    return now_ms >= renew_at;
}

const char* ModelNatStatusName(ModelNatStatus s)
{
    switch (s) {
    case ModelNatStatus::LOOPBACK: return "loopback";
    case ModelNatStatus::UNMAPPED: return "unmapped";
    case ModelNatStatus::MAPPED: return "mapped";
    case ModelNatStatus::DISABLED: return "disabled";
    case ModelNatStatus::UNKNOWN:
    default: return "unknown";
    }
}

ModelMapResult AttemptModelPortMap(const std::string& bind, bool enable)
{
    ModelMapResult r;
    if (!enable || bind.empty()) {
        r.status = ModelNatStatus::DISABLED;
        return r;
    }
    std::string host;
    uint16_t port = 0;
    if (!SplitListenBind(bind, host, port)) {
        r.status = ModelNatStatus::UNMAPPED;
        r.error = "bad bind";
        return r;
    }
    if (MappingWouldExposeControlPlane(port)) {
        r.status = ModelNatStatus::UNMAPPED;
        r.error = "refusing to map control-plane port";
        return r;
    }
    const bool lab = std::getenv("BTX_MODEL_PCP_LAB") != nullptr;
    if (!lab && (host == "127.0.0.1" || host == "::1" || host == "localhost")) {
        r.status = ModelNatStatus::LOOPBACK;
        return r;
    }
    CThreadInterrupt interrupt;
    std::optional<CNetAddr> gw4;
    if (const char* lab_gw = std::getenv("BTX_MODEL_PCP_GATEWAY"); lab_gw && lab_gw[0] != '\0') {
        struct in_addr a{};
        if (inet_pton(AF_INET, lab_gw, &a) == 1) {
            gw4 = CNetAddr(a);
        }
    } else {
        gw4 = QueryDefaultGateway(NET_IPV4);
    }
    if (!gw4) {
        r.status = ModelNatStatus::UNMAPPED;
        r.error = "no default gateway";
        return r;
    }
    PCPMappingNonce nonce{};
    GetRandBytes(nonce);
    struct in_addr inaddr_any;
    inaddr_any.s_addr = htonl(INADDR_ANY);
    auto mapped = PCPRequestPortMap(nonce, *gw4, CNetAddr(inaddr_any), port, /*lifetime=*/3600, interrupt, /*num_tries=*/1,
                                    std::chrono::milliseconds(400));
    if (MappingResult* ok = std::get_if<MappingResult>(&mapped)) {
        r.status = ModelNatStatus::MAPPED;
        r.external = ok->external.ToStringAddrPort();
        r.mapped_port = ok->external.GetPort();
        r.owned_mapping = true;
        return r;
    }
    auto np = NATPMPRequestPortMap(*gw4, port, 3600, interrupt, 1, std::chrono::milliseconds(400));
    if (MappingResult* ok = std::get_if<MappingResult>(&np)) {
        r.status = ModelNatStatus::MAPPED;
        r.external = ok->external.ToStringAddrPort();
        r.mapped_port = ok->external.GetPort();
        r.owned_mapping = true;
        return r;
    }
    r.status = ModelNatStatus::UNMAPPED;
    r.error = "pcp/nat-pmp failed";
    return r;
}

void ReleaseModelPortMap(ModelMapResult& mapping)
{
    if (!mapping.owned_mapping || mapping.mapped_port == 0) {
        mapping = {};
        return;
    }
    CThreadInterrupt interrupt;
    std::optional<CNetAddr> gw4;
    if (const char* lab_gw = std::getenv("BTX_MODEL_PCP_GATEWAY"); lab_gw && lab_gw[0] != '\0') {
        struct in_addr a{};
        if (inet_pton(AF_INET, lab_gw, &a) == 1) {
            gw4 = CNetAddr(a);
        }
    } else {
        gw4 = QueryDefaultGateway(NET_IPV4);
    }
    if (gw4) {
        (void)NATPMPRequestPortMap(*gw4, mapping.mapped_port, /*lifetime=*/0, interrupt, 1,
                                    std::chrono::milliseconds(200));
    }
    mapping = {};
}

bool ValidateRelayConnect(const RelayConnectRequest& req, bool relay_enabled, std::string& err)
{
    if (!relay_enabled) {
        err = "relay disabled";
        return false;
    }
    if (IsForbiddenControlEndpoint(req.endpoint, err)) return false;
    if (!req.expected_service_id.empty() && !req.presented_service_id.empty() &&
        req.expected_service_id != req.presented_service_id) {
        err = "identity mismatch";
        return false;
    }
    return true;
}

bool ValidateRendezvous(const std::string& endpoint, const std::string& expected_id,
                         const std::string& presented_id, std::string& err)
{
    if (IsForbiddenControlEndpoint(endpoint, err)) return false;
    if (!expected_id.empty() && !presented_id.empty() && expected_id != presented_id) {
        err = "identity mismatch";
        return false;
    }
    return true;
}

} // namespace modelnet
