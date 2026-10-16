// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/lab_peer.h>
#include <crypto/sha384.h>
#include <univalue.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_035_peer_route_tests, BasicTestingSetup)

namespace {

std::string HexOf(const unsigned char* data, size_t n)
{
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out(n * 2, '\0');
    for (size_t i = 0; i < n; ++i) {
        out[i * 2] = kHex[data[i] >> 4];
        out[i * 2 + 1] = kHex[data[i] & 0x0f];
    }
    return out;
}

std::string HexOf(const std::string& bytes)
{
    return HexOf(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size());
}

std::string ExpectedNonce(const std::string& client_hex)
{
    unsigned char raw[32];
    for (size_t i = 0; i < 32; ++i) {
        const auto nibble = [](char c) -> unsigned char {
            return c <= '9' ? static_cast<unsigned char>(c - '0') : static_cast<unsigned char>(c - 'a' + 10);
        };
        raw[i] = static_cast<unsigned char>((nibble(client_hex[i * 2]) << 4) | nibble(client_hex[i * 2 + 1]));
    }
    unsigned char hash[CSHA384::OUTPUT_SIZE];
    CSHA384().Write(raw, sizeof(raw)).Finalize(hash);
    std::string nonce = HexOf(hash, 32);
    if (nonce == client_hex) {
        unsigned char again[CSHA384::OUTPUT_SIZE];
        CSHA384().Write(hash, sizeof(hash)).Finalize(again);
        nonce = HexOf(again, 32);
    }
    return nonce;
}

struct FakeView : modelnet::PeerView {
    std::map<std::string, modelnet::PeerRecord> records;
    std::map<std::pair<std::string, uint64_t>, std::string> pieces;
    std::map<std::pair<std::string, std::string>, std::pair<int64_t, std::string>> channels;
    std::map<std::string, std::pair<std::string, int>> realms;
    std::vector<std::string> research_ids;
    std::set<std::string> tickets;
    bool verify_ok{false};
    mutable std::string seen_message;
    mutable std::string seen_signature;

    bool Record(const std::string& id, modelnet::PeerRecord& out) const override
    {
        const auto it = records.find(id);
        if (it == records.end()) {
            out = modelnet::PeerRecord{};
            return false;
        }
        out = it->second;
        return true;
    }

    bool Piece(const std::string& model_digest, uint64_t index, std::string& bytes) const override
    {
        const auto it = pieces.find(std::make_pair(model_digest, index));
        if (it == pieces.end()) return false;
        bytes = it->second;
        return true;
    }

    bool Channel(const std::string& realm_id, const std::string& channel, int64_t& sequence, std::string& update_id) const override
    {
        const auto it = channels.find(std::make_pair(realm_id, channel));
        if (it == channels.end()) return false;
        sequence = it->second.first;
        update_id = it->second.second;
        return true;
    }

    bool Realm(const std::string& realm_id, std::string& policy_id, int& threshold) const override
    {
        const auto it = realms.find(realm_id);
        if (it == realms.end()) return false;
        policy_id = it->second.first;
        threshold = it->second.second;
        return true;
    }

    void PublicResearch(std::vector<std::string>& ids) const override { ids = research_ids; }

    bool Ticket(const std::string& ticket_id) const override { return tickets.count(ticket_id) != 0; }

    bool VerifySession(const std::string& message, const std::string& signature_hex) const override
    {
        seen_message = message;
        seen_signature = signature_hex;
        return verify_ok;
    }
};

const std::string kNonce(64, 'c');
const std::string kDigest(96, 'b');
const std::string kSignature(4840, 'a');

std::string HelloJson(const std::string& revision)
{
    UniValue versions(UniValue::VARR);
    versions.push_back(int64_t{3});
    UniValue roles(UniValue::VARR);
    roles.push_back("PUBLIC_READ");
    roles.push_back("GIT_READ");
    UniValue req(UniValue::VOBJ);
    req.pushKV("contract_revision", revision);
    req.pushKV("protocol_versions", versions);
    req.pushKV("mode", "ROOT_BOUND");
    req.pushKV("nonce", kNonce);
    req.pushKV("transport_binding_id", std::string(96, 'a'));
    req.pushKV("requested_roles", roles);
    req.pushKV("control_limit", int64_t{32768});
    req.pushKV("data_limit", int64_t{65536});
    req.pushKV("server_deadline_ms", "5000");
    req.pushKV("proof_window_ms", int64_t{1000});
    return req.write();
}

std::string AuthJson()
{
    UniValue req(UniValue::VOBJ);
    req.pushKV("mode", "PUBLIC_READER");
    req.pushKV("client_nonce", std::string(64, 'e'));
    req.pushKV("server_nonce", std::string(64, 'f'));
    req.pushKV("hello_digest", kDigest);
    req.pushKV("exporter_binding", std::string(96, 'c'));
    req.pushKV("certificate_key_id", std::string(96, 'd'));
    req.pushKV("deadline_ms", "1000");
    req.pushKV("signature_hex", kSignature);
    return req.write();
}

bool Call(const std::string& route, const std::string& request, const FakeView& view, std::string& response, std::string& err)
{
    return modelnet::DispatchPeerRoute("/btx-model/3/" + route, request, view, response, err);
}

} // namespace

BOOST_AUTO_TEST_CASE(peer_hello_ok)
{
    FakeView view;
    std::string response, err;
    BOOST_REQUIRE(Call("hello", HelloJson("1.1.0"), view, response, err));
    BOOST_CHECK(err.empty());
    UniValue resp;
    BOOST_REQUIRE(resp.read(response));
    BOOST_CHECK(resp.getKeys().size() == 10);
    BOOST_CHECK_EQUAL(resp["contract_revision"].get_str(), "1.1.0");
    BOOST_CHECK(resp["protocol_versions"].isArray());
    BOOST_CHECK(resp["protocol_versions"].size() == 1);
    BOOST_CHECK_EQUAL(resp["protocol_versions"][0].getInt<int64_t>(), int64_t{3});
    BOOST_CHECK_EQUAL(resp["mode"].get_str(), "PUBLIC_READER");
    const std::string nonce = resp["nonce"].get_str();
    BOOST_CHECK_EQUAL(nonce, ExpectedNonce(kNonce));
    BOOST_CHECK(nonce != kNonce);
    BOOST_CHECK(resp["transport_binding_id"].isNull());
    BOOST_CHECK(resp["requested_roles"].size() == 2);
    BOOST_CHECK_EQUAL(resp["requested_roles"][0].get_str(), "PUBLIC_READ");
    BOOST_CHECK_EQUAL(resp["requested_roles"][1].get_str(), "GIT_READ");
    BOOST_CHECK_EQUAL(resp["control_limit"].getInt<int64_t>(), int64_t{32768});
    BOOST_CHECK_EQUAL(resp["data_limit"].getInt<int64_t>(), int64_t{65536});
    BOOST_CHECK(resp["server_deadline_ms"].isNull());
    BOOST_CHECK_EQUAL(resp["proof_window_ms"].getInt<int64_t>(), int64_t{1000});
}

BOOST_AUTO_TEST_CASE(peer_hello_wrong_revision_upgrade_required)
{
    FakeView view;
    std::string response, err;
    BOOST_CHECK(!Call("hello", HelloJson("1.0.0"), view, response, err));
    BOOST_CHECK_EQUAL(err, "BTX035_UPGRADE_REQUIRED");
    BOOST_CHECK(response.empty());
}

BOOST_AUTO_TEST_CASE(peer_unknown_route_unsupported)
{
    FakeView view;
    std::string response, err;
    BOOST_CHECK(!modelnet::DispatchPeerRoute("/btx-model/3/nope", "{", view, response, err));
    BOOST_CHECK_EQUAL(err, "BTX035_UNSUPPORTED");
    BOOST_CHECK(response.empty());
}

BOOST_AUTO_TEST_CASE(peer_piece_over_maximum_bytes_limit_exceeded)
{
    const std::string manifest(96, 'a');
    const std::string digest(96, 'b');
    FakeView view;
    view.records[manifest] = modelnet::PeerRecord{true, false, "manifest"};
    view.pieces[std::make_pair(digest, uint64_t{0})] = std::string("\x01\x02\x03\x04", 4);
    UniValue resource(UniValue::VOBJ);
    resource.pushKV("kind", "MODEL");
    resource.pushKV("digest48", digest);
    UniValue req(UniValue::VOBJ);
    req.pushKV("resource", resource);
    req.pushKV("manifest_id", manifest);
    req.pushKV("piece_index", "0");
    req.pushKV("maximum_bytes", "3");
    std::string response, err;
    BOOST_CHECK(!Call("artifacts/piece", req.write(), view, response, err));
    BOOST_CHECK_EQUAL(err, "BTX035_LIMIT_EXCEEDED");
    BOOST_CHECK(response.empty());
}

BOOST_AUTO_TEST_CASE(peer_piece_hit_returns_hex)
{
    const std::string manifest(96, 'a');
    const std::string digest(96, 'b');
    const std::string bytes("\x0a\xff", 2);
    FakeView view;
    view.records[manifest] = modelnet::PeerRecord{true, false, "manifest"};
    view.pieces[std::make_pair(digest, uint64_t{0})] = bytes;
    UniValue resource(UniValue::VOBJ);
    resource.pushKV("kind", "MODEL");
    resource.pushKV("digest48", digest);
    UniValue req(UniValue::VOBJ);
    req.pushKV("resource", resource);
    req.pushKV("manifest_id", manifest);
    req.pushKV("piece_index", "0");
    req.pushKV("maximum_bytes", "2");
    std::string response, err;
    BOOST_REQUIRE(Call("artifacts/piece", req.write(), view, response, err));
    UniValue resp;
    BOOST_REQUIRE(resp.read(response));
    BOOST_CHECK_EQUAL(resp["piece_index"].get_str(), "0");
    BOOST_CHECK_EQUAL(resp["byte_size"].getInt<uint64_t>(), uint64_t{2});
    BOOST_CHECK_EQUAL(resp["content_hex"].get_str(), HexOf(bytes));
    BOOST_CHECK_EQUAL(resp["content_hex"].get_str(), "0aff");
}

BOOST_AUTO_TEST_CASE(peer_private_record_scope_denied)
{
    const std::string id(96, 'c');
    FakeView view;
    view.records[id] = modelnet::PeerRecord{true, true, "hidden-body"};
    UniValue req(UniValue::VOBJ);
    req.pushKV("record_id", id);
    std::string response, err;
    BOOST_CHECK(!Call("records/get", req.write(), view, response, err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCOPE_DENIED");
    BOOST_CHECK(response.empty());
    BOOST_CHECK(response.find("hidden-body") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(peer_announce_splits_accepted_and_rejected)
{
    const std::string pub(96, 'a');
    const std::string missing(96, 'b');
    const std::string priv(96, 'c');
    FakeView view;
    view.records[pub] = modelnet::PeerRecord{true, false, "public-body"};
    view.records[priv] = modelnet::PeerRecord{true, true, "private-body"};
    UniValue ids(UniValue::VARR);
    ids.push_back(pub);
    ids.push_back(missing);
    ids.push_back(priv);
    UniValue req(UniValue::VOBJ);
    req.pushKV("record_ids", ids);
    std::string response, err;
    BOOST_REQUIRE(Call("records/announce", req.write(), view, response, err));
    UniValue resp;
    BOOST_REQUIRE(resp.read(response));
    BOOST_REQUIRE(resp["accepted_ids"].isArray());
    BOOST_REQUIRE(resp["rejected"].isArray());
    BOOST_CHECK(resp["accepted_ids"].size() == 1);
    BOOST_CHECK_EQUAL(resp["accepted_ids"][0].get_str(), pub);
    BOOST_CHECK(resp["rejected"].size() == 2);
    BOOST_CHECK_EQUAL(resp["rejected"][0]["record_id"].get_str(), missing);
    BOOST_CHECK_EQUAL(resp["rejected"][0]["error_code"].get_str(), "BTX035_NOT_FOUND");
    BOOST_CHECK_EQUAL(resp["rejected"][1]["record_id"].get_str(), priv);
    BOOST_CHECK_EQUAL(resp["rejected"][1]["error_code"].get_str(), "BTX035_SCOPE_DENIED");
    BOOST_CHECK(response.find("private-body") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(peer_auth_verify_session_false_permit)
{
    FakeView view;
    view.verify_ok = false;
    std::string response, err;
    BOOST_CHECK(!Call("auth", AuthJson(), view, response, err));
    BOOST_CHECK_EQUAL(err, "BTX035_PERMIT");
    BOOST_CHECK(response.empty());
    BOOST_CHECK(response.find("\"authenticated\":true") == std::string::npos);
    BOOST_CHECK_EQUAL(view.seen_message, kDigest);
    BOOST_CHECK_EQUAL(view.seen_signature, kSignature);
}

BOOST_AUTO_TEST_CASE(peer_auth_verify_session_true_authenticated)
{
    FakeView view;
    view.verify_ok = true;
    std::string response, err;
    BOOST_REQUIRE(Call("auth", AuthJson(), view, response, err));
    BOOST_CHECK_EQUAL(view.seen_message, kDigest);
    BOOST_CHECK_EQUAL(view.seen_signature, kSignature);
    UniValue resp;
    BOOST_REQUIRE(resp.read(response));
    BOOST_CHECK(resp["authenticated"].isTrue());
    BOOST_CHECK_EQUAL(resp["mode"].get_str(), "PUBLIC_READER");
    BOOST_CHECK(resp.getKeys().size() == 2);
}

BOOST_AUTO_TEST_CASE(peer_git_tunnel_without_ticket_permit)
{
    UniValue req(UniValue::VOBJ);
    req.pushKV("repository_id", std::string(96, 'd'));
    req.pushKV("service", "git-upload-pack");
    req.pushKV("ticket_id", std::string(96, 'e'));
    req.pushKV("expected_ref_state", UniValue(UniValue::VNULL));
    FakeView view;
    std::string response, err;
    BOOST_CHECK(!Call("git/tunnel", req.write(), view, response, err));
    BOOST_CHECK_EQUAL(err, "BTX035_PERMIT");
    BOOST_CHECK(response.empty());
    BOOST_CHECK(response.find("opened") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(peer_channel_missing_unknown)
{
    UniValue req(UniValue::VOBJ);
    req.pushKV("realm_id", std::string(96, 'f'));
    req.pushKV("channel", "updates");
    FakeView view;
    std::string response, err;
    BOOST_REQUIRE(Call("channels/get", req.write(), view, response, err));
    BOOST_CHECK(err.empty());
    UniValue resp;
    BOOST_REQUIRE(resp.read(response));
    BOOST_CHECK(resp["update_id"].isNull());
    BOOST_CHECK_EQUAL(resp["sequence"].get_str(), "0");
    BOOST_CHECK_EQUAL(resp["state"].get_str(), "UNKNOWN");
}

BOOST_AUTO_TEST_CASE(peer_research_query_uses_the_lab_request)
{
    const std::string id(96, 'a');
    FakeView view;
    view.research_ids.push_back(id);
    UniValue topics(UniValue::VARR);
    UniValue kinds(UniValue::VARR);
    UniValue req(UniValue::VOBJ);
    req.pushKV("scope", "LOCAL");
    req.pushKV("topics", topics);
    req.pushKV("kinds", kinds);
    req.pushKV("after_cursor", UniValue(UniValue::VNULL));
    req.pushKV("limit", int64_t{10});
    std::string response, err;
    BOOST_REQUIRE(Call("research/query", req.write(), view, response, err));
    UniValue resp;
    BOOST_REQUIRE(resp.read(response));
    BOOST_CHECK(resp["complete"].isTrue());
    BOOST_CHECK_EQUAL(resp["record_ids"][0].get_str(), id);
    req.pushKV("scope", "PEERS");
    BOOST_CHECK(!Call("research/query", req.write(), view, response, err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCOPE_DENIED");
}

BOOST_AUTO_TEST_CASE(peer_git_tunnel_with_ticket_returns_end_frame)
{
    const std::string ticket(96, 'e');
    FakeView view;
    view.tickets.insert(ticket);
    UniValue req(UniValue::VOBJ);
    req.pushKV("repository_id", std::string(96, 'd'));
    req.pushKV("service", "git-upload-pack");
    req.pushKV("ticket_id", ticket);
    req.pushKV("expected_ref_state", UniValue(UniValue::VNULL));
    std::string response, err;
    BOOST_REQUIRE(Call("git/tunnel", req.write(), view, response, err));
    UniValue resp;
    BOOST_REQUIRE(resp.read(response));
    BOOST_CHECK(resp["pack"].isFalse());
    BOOST_REQUIRE(resp["frames"].size() == 2);
    BOOST_CHECK_EQUAL(resp["frames"][0]["type"].get_str(), "OPEN");
    BOOST_CHECK_EQUAL(resp["frames"][1]["type"].get_str(), "END");
    BOOST_CHECK_EQUAL(resp["frames"][1]["byte_count"].get_str(), "0");
    BOOST_CHECK(response.find("PACK") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(peer_piece_frames_end_after_the_bytes)
{
    const std::string manifest(96, 'a');
    const std::string digest(96, 'b');
    FakeView view;
    view.records[manifest] = modelnet::PeerRecord{true, false, "manifest"};
    view.pieces[std::make_pair(digest, uint64_t{0})] = std::string("\x0a\xff", 2);
    UniValue resource(UniValue::VOBJ);
    resource.pushKV("kind", "MODEL");
    resource.pushKV("digest48", digest);
    UniValue req(UniValue::VOBJ);
    req.pushKV("resource", resource);
    req.pushKV("manifest_id", manifest);
    req.pushKV("piece_index", "0");
    req.pushKV("maximum_bytes", "2");
    std::string response, err;
    BOOST_REQUIRE(Call("artifacts/piece", req.write(), view, response, err));
    UniValue resp;
    BOOST_REQUIRE(resp.read(response));
    BOOST_REQUIRE(resp["frames"].size() == 3);
    BOOST_CHECK_EQUAL(resp["frames"][0]["type"].get_str(), "OPEN");
    BOOST_CHECK_EQUAL(resp["frames"][1]["type"].get_str(), "DATA");
    BOOST_CHECK_EQUAL(resp["frames"][1]["content_hex"].get_str(), "0aff");
    BOOST_CHECK_EQUAL(resp["frames"][2]["type"].get_str(), "END");
    BOOST_CHECK_EQUAL(resp["frames"][2]["byte_count"].get_str(), "2");
}

BOOST_AUTO_TEST_CASE(peer_manifest_rejects_a_generic_record)
{
    const std::string id(96, 'a');
    FakeView view;
    view.records[id] = modelnet::PeerRecord{true, false, "notes"};
    UniValue req(UniValue::VOBJ);
    req.pushKV("record_id", id);
    std::string response, err;
    BOOST_CHECK(!Call("artifacts/manifest", req.write(), view, response, err));
    BOOST_CHECK_EQUAL(err, "BTX035_RECORD_TYPE");
    view.records[id].body = "v1|manifest|ok";
    BOOST_REQUIRE(Call("artifacts/manifest", req.write(), view, response, err));
}

BOOST_AUTO_TEST_CASE(peer_trust_state_reports_connectivity_disabled)
{
    const std::string realm(96, 'a');
    FakeView view;
    view.realms[realm] = std::make_pair(std::string(96, 'b'), 2);
    UniValue req(UniValue::VOBJ);
    req.pushKV("realm_id", realm);
    std::string response, err;
    BOOST_REQUIRE(Call("trust/state", req.write(), view, response, err));
    UniValue resp;
    BOOST_REQUIRE(resp.read(response));
    BOOST_CHECK_EQUAL(resp["threshold"].get_str(), "2");
    BOOST_CHECK_EQUAL(resp["public_connectivity"].get_str(), "DISABLED");
    BOOST_CHECK_EQUAL(resp["authority_state"].get_str(), "LOCAL");
}

BOOST_AUTO_TEST_SUITE_END()
