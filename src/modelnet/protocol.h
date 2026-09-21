// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PROTOCOL_H
#define BITCOIN_MODELNET_PROTOCOL_H

#include <modelnet/types.h>
#include <serialize.h>
#include <streams.h>

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace modelnet {

constexpr uint16_t MODEL_PROTOCOL_VERSION = 2;
constexpr uint32_t ROLE_RELAY = 1u << 0;
constexpr uint32_t ROLE_HOST = 1u << 1;
constexpr size_t MAX_MDPEERS_HINTS = 16;
constexpr size_t MAX_MDPEERS_BYTES = 4096;
constexpr size_t SENDMODELS_BYTES = 18;
constexpr size_t GETMDPEERS_BYTES = 17;
constexpr uint8_t HINT_ADDR_IPV4 = 1;
constexpr uint8_t HINT_ADDR_IPV6 = 2;
constexpr uint8_t HINT_ADDR_HOSTNAME = 3;

/** Wire admit for sendmodels / getmdpeers / mdpeers (#173). */
enum class HintWireDisposition : uint8_t {
    ACCEPT,    //!< same version (or unversioned current layout) and plausible size
    IGNORE,    //!< other MODEL_PROTOCOL_VERSION; must not Misbehave
    MISBEHAVE, //!< same-version garbage, or unreadable version prefix
};

struct SendModels {
    uint16_t version{MODEL_PROTOCOL_VERSION};
    uint32_t role_mask{0};
    uint32_t receive_cap{16};
    uint64_t features{0};
    SERIALIZE_METHODS(SendModels, obj)
    {
        READWRITE(obj.version, obj.role_mask, obj.receive_cap, obj.features);
    }
};

struct GetMdPeers {
    std::array<unsigned char, 16> request_id{};
    uint8_t requested_count{8};
    SERIALIZE_METHODS(GetMdPeers, obj)
    {
        READWRITE(obj.request_id, obj.requested_count);
    }
};

struct PublicEndpointHint {
    uint8_t addr_kind{0};
    std::vector<unsigned char> addr;
    uint16_t port{0};
    uint64_t expiry{0};
    std::optional<Digest48> service_key_digest;
    uint16_t suite_id{1};
};

bool ParseSendModels(Span<const unsigned char> payload, SendModels& out, std::string& err);
bool SerializeSendModels(const SendModels& msg, std::vector<unsigned char>& out, std::string& err);
bool ParseGetMdPeers(Span<const unsigned char> payload, GetMdPeers& out, std::string& err);
bool ParseMdPeers(Span<const unsigned char> payload, std::vector<PublicEndpointHint>& out, std::string& err);
bool SerializeMdPeers(const std::vector<PublicEndpointHint>& hints, std::vector<unsigned char>& out, std::string& err);

HintWireDisposition ClassifySendModelsWire(Span<const unsigned char> payload);
HintWireDisposition ClassifyGetMdPeersWire(Span<const unsigned char> payload);
HintWireDisposition ClassifyMdPeersWire(Span<const unsigned char> payload);

bool PublicEndpointHintWellFormed(const PublicEndpointHint& hint, std::string& err);
/** Introduction-only (empty endpoint + non-empty from_addr) is well-formed. */
bool PublicHintWellFormed(const PublicEndpointHint& hint, const std::string& from_addr, std::string& err);

/** HTTP path root for native model protocol. */
inline constexpr const char* MODEL_HTTP_ROOT = "/btx-model/2/";

} // namespace modelnet

#endif // BITCOIN_MODELNET_PROTOCOL_H
