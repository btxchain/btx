// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/lab_peer.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <univalue.h>
#include <util/check.h>

#include <cstdint>
#include <string>
#include <vector>

namespace {

const std::vector<std::string> ROUTES{
    "hello",
    "auth",
    "records/get",
    "records/announce",
    "research/query",
    "subscriptions/poll",
    "git/tunnel",
    "artifacts/manifest",
    "artifacts/piece",
    "trust/state",
    "channels/get",
};

std::string Ascii(std::string s)
{
    for (char& c : s) c = static_cast<char>(0x20 + static_cast<unsigned char>(c) % 95);
    return s;
}

/**
 * Node-side state behind the `/btx-model/3/` routes. The dispatcher reads it
 * only through this interface, so the fuzzer picks each answer up front.
 */
class FuzzPeerView final : public modelnet::PeerView
{
public:
    bool record_found{false};
    modelnet::PeerRecord record;
    bool piece_found{false};
    std::string piece;
    bool channel_found{false};
    int64_t channel_sequence{0};
    std::string channel_update;
    bool realm_found{false};
    std::string realm_policy;
    int realm_threshold{0};
    std::vector<std::string> research;
    bool ticket_ok{false};
    bool session_ok{false};

    bool Record(const std::string&, modelnet::PeerRecord& out) const override
    {
        if (!record_found) return false;
        out = record;
        return true;
    }
    bool Piece(const std::string&, uint64_t, std::string& bytes) const override
    {
        if (!piece_found) return false;
        bytes = piece;
        return true;
    }
    bool Channel(const std::string&, const std::string&, int64_t& sequence, std::string& update_id) const override
    {
        if (!channel_found) return false;
        sequence = channel_sequence;
        update_id = channel_update;
        return true;
    }
    bool Realm(const std::string&, std::string& policy_id, int& threshold) const override
    {
        if (!realm_found) return false;
        policy_id = realm_policy;
        threshold = realm_threshold;
        return true;
    }
    void PublicResearch(std::vector<std::string>& ids) const override { ids = research; }
    bool Ticket(const std::string&) const override { return ticket_ok; }
    bool VerifySession(const std::string&, const std::string&) const override { return session_ok; }
};

} // namespace

// Routes served without RPC credentials to any local caller (httprpc.cpp).
FUZZ_TARGET(modelnet_lab_peer_route)
{
    FuzzedDataProvider fdp(buffer.data(), buffer.size());

    FuzzPeerView view;
    view.record_found = fdp.ConsumeBool();
    view.record.exists = fdp.ConsumeBool();
    view.record.is_private = fdp.ConsumeBool();
    view.piece_found = fdp.ConsumeBool();
    view.channel_found = fdp.ConsumeBool();
    view.channel_sequence = fdp.ConsumeIntegral<int64_t>();
    view.realm_found = fdp.ConsumeBool();
    view.realm_threshold = fdp.ConsumeIntegral<int>();
    view.ticket_ok = fdp.ConsumeBool();
    view.session_ok = fdp.ConsumeBool();
    const size_t research_count = fdp.ConsumeIntegralInRange<size_t>(0, 160);
    const bool prefixed = fdp.ConsumeBool();
    const bool known_route = fdp.ConsumeBool();
    const size_t route_index = fdp.ConsumeIntegralInRange<size_t>(0, ROUTES.size() - 1);

    std::string route = known_route ? ROUTES[route_index] : fdp.ConsumeRandomLengthString(64);
    if (prefixed) route = "/btx-model/3/" + route;
    // Stored strings come from the node's own JSON store, so keep them ASCII.
    view.record.body = Ascii(fdp.ConsumeRandomLengthString(4096));
    view.piece = fdp.ConsumeRandomLengthString(1 << 16);
    view.channel_update = Ascii(fdp.ConsumeRandomLengthString(128));
    view.realm_policy = Ascii(fdp.ConsumeRandomLengthString(128));
    for (size_t i = 0; i < research_count; ++i) view.research.emplace_back(96, 'a' + static_cast<char>(i % 6));
    const std::string request = fdp.ConsumeRemainingBytesAsString();

    std::string response;
    std::string err;
    const bool ok = modelnet::DispatchPeerRoute(route, request, view, response, err);
    if (ok) {
        Assert(err.empty());
        UniValue parsed;
        Assert(parsed.read(response));
        Assert(parsed.isObject());
    } else {
        Assert(response.empty());
        Assert(err.rfind("BTX035_", 0) == 0);
    }
}
