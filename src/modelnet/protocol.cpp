// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/protocol.h>

#include <crypto/common.h>
#include <span.h>

#include <ios>

namespace modelnet {

namespace {

uint16_t PeekHintVersion(Span<const unsigned char> payload)
{
    return ReadLE16(payload.data());
}

} // namespace

bool PublicEndpointHintWellFormed(const PublicEndpointHint& hint, std::string& err)
{
    if (hint.port == 0) {
        err = "model hint port";
        return false;
    }
    if (hint.addr_kind == HINT_ADDR_IPV4) {
        if (hint.addr.size() != 4) {
            err = "model hint ipv4";
            return false;
        }
        return true;
    }
    if (hint.addr_kind == HINT_ADDR_IPV6) {
        if (hint.addr.size() != 16) {
            err = "model hint ipv6";
            return false;
        }
        return true;
    }
    if (hint.addr_kind == HINT_ADDR_HOSTNAME) {
        if (hint.addr.empty() || hint.addr.size() > 255) {
            err = "model hint hostname";
            return false;
        }
        return true;
    }
    err = "model hint addr_kind";
    return false;
}

bool PublicHintWellFormed(const PublicEndpointHint& hint, const std::string& from_addr, std::string& err)
{
    if (hint.addr.empty() && hint.addr_kind == 0) {
        if (from_addr.empty()) {
            err = "empty model hint";
            return false;
        }
        return true;
    }
    return PublicEndpointHintWellFormed(hint, err);
}

HintWireDisposition ClassifySendModelsWire(Span<const unsigned char> payload)
{
    // Fail-closed-but-not-eclipse (#173): a future MODEL_PROTOCOL_VERSION
    // that changes byte length must not accumulate Misbehaving against
    // upgraded peers. Only same-version garbage is penalized. A payload
    // too short to carry the version prefix cannot be an upgraded layout
    // (version stays little-endian uint16 at offset 0).
    if (payload.size() < 2) return HintWireDisposition::MISBEHAVE;
    if (PeekHintVersion(payload) != MODEL_PROTOCOL_VERSION) return HintWireDisposition::IGNORE;
    if (payload.size() != SENDMODELS_BYTES) return HintWireDisposition::MISBEHAVE;
    return HintWireDisposition::ACCEPT;
}

HintWireDisposition ClassifyGetMdPeersWire(Span<const unsigned char> payload)
{
    // GETMDPEERS v2 has no version field. A size change is the only way
    // the layout can evolve, so wrong size is IGNORE (not Misbehave).
    // Same 17-byte layout with an out-of-range count is same-version
    // garbage and is rejected by ParseGetMdPeers.
    if (payload.size() != GETMDPEERS_BYTES) return HintWireDisposition::IGNORE;
    return HintWireDisposition::ACCEPT;
}

HintWireDisposition ClassifyMdPeersWire(Span<const unsigned char> payload)
{
    if (payload.size() > MAX_MDPEERS_BYTES) return HintWireDisposition::MISBEHAVE;
    if (payload.empty()) return HintWireDisposition::ACCEPT; // introduction-only
    if (payload.size() < 2) return HintWireDisposition::MISBEHAVE;
    if (PeekHintVersion(payload) != MODEL_PROTOCOL_VERSION) return HintWireDisposition::IGNORE;
    return HintWireDisposition::ACCEPT;
}

bool ParseSendModels(Span<const unsigned char> payload, SendModels& out, std::string& err)
{
    if (payload.size() != SENDMODELS_BYTES) {
        err = "sendmodels size";
        return false;
    }
    DataStream s{payload};
    s >> out;
    if (out.version != MODEL_PROTOCOL_VERSION) {
        err = "sendmodels version";
        return false;
    }
    return true;
}

bool SerializeSendModels(const SendModels& msg, std::vector<unsigned char>& out, std::string& err)
{
    (void)err;
    DataStream s{};
    s << msg;
    out.assign(UCharCast(s.data()), UCharCast(s.data() + s.size()));
    return out.size() == SENDMODELS_BYTES;
}

bool ParseGetMdPeers(Span<const unsigned char> payload, GetMdPeers& out, std::string& err)
{
    if (payload.size() != GETMDPEERS_BYTES) {
        err = "getmdpeers size";
        return false;
    }
    DataStream s{payload};
    s >> out;
    if (out.requested_count < 1 || out.requested_count > MAX_MDPEERS_HINTS) {
        err = "getmdpeers count";
        return false;
    }
    return true;
}

bool ParseMdPeers(Span<const unsigned char> payload, std::vector<PublicEndpointHint>& out, std::string& err)
{
    out.clear();
    if (payload.empty()) return true;
    if (payload.size() > MAX_MDPEERS_BYTES) {
        err = "mdpeers oversized";
        return false;
    }
    try {
        DataStream s{payload};
        uint16_t version{0};
        uint8_t count{0};
        s >> version >> count;
        if (version != MODEL_PROTOCOL_VERSION) {
            err = "mdpeers version";
            return false;
        }
        if (count > MAX_MDPEERS_HINTS) {
            err = "mdpeers count";
            return false;
        }
        out.reserve(count);
        for (uint8_t i = 0; i < count; ++i) {
            PublicEndpointHint hint;
            uint8_t has_key{0};
            s >> hint.addr_kind >> hint.addr >> hint.port >> hint.expiry >> has_key;
            if (has_key > 1) {
                err = "mdpeers key flag";
                return false;
            }
            if (has_key) {
                Digest48 digest;
                s >> digest.data;
                hint.service_key_digest = digest;
            }
            s >> hint.suite_id;
            if (!PublicEndpointHintWellFormed(hint, err)) return false;
            out.push_back(std::move(hint));
        }
        if (!s.empty()) {
            err = "mdpeers trailing";
            return false;
        }
    } catch (const std::ios_base::failure&) {
        err = "mdpeers truncated";
        return false;
    }
    return true;
}

bool SerializeMdPeers(const std::vector<PublicEndpointHint>& hints, std::vector<unsigned char>& out, std::string& err)
{
    if (hints.size() > MAX_MDPEERS_HINTS) {
        err = "mdpeers count";
        return false;
    }
    DataStream s{};
    const uint16_t version{MODEL_PROTOCOL_VERSION};
    const uint8_t count{static_cast<uint8_t>(hints.size())};
    s << version << count;
    for (const auto& hint : hints) {
        if (!PublicEndpointHintWellFormed(hint, err)) return false;
        const uint8_t has_key{hint.service_key_digest ? uint8_t{1} : uint8_t{0}};
        s << hint.addr_kind << hint.addr << hint.port << hint.expiry << has_key;
        if (has_key) {
            s << hint.service_key_digest->data;
        }
        s << hint.suite_id;
    }
    out.assign(UCharCast(s.data()), UCharCast(s.data() + s.size()));
    if (out.size() > MAX_MDPEERS_BYTES) {
        err = "mdpeers oversized";
        return false;
    }
    return true;
}

} // namespace modelnet
