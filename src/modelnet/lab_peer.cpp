// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/lab_peer.h>

#include <crypto/sha384.h>
#include <univalue.h>

#include <cstddef>
#include <cstdint>
#include <exception>
#include <initializer_list>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace modelnet {
namespace {

bool Fail(std::string& response_json, std::string& err, const char* code)
{
    response_json.clear();
    err = code;
    return false;
}

bool Done(std::string& response_json, std::string& err, const UniValue& body)
{
    response_json = body.write();
    err.clear();
    return true;
}

bool ExactKeys(const UniValue& obj, std::initializer_list<const char*> keys)
{
    if (!obj.isObject() || obj.getKeys().size() != keys.size()) return false;
    for (const char* key : keys) {
        if (!obj.exists(key)) return false;
    }
    return true;
}

bool LowerHex(const std::string& text, size_t n)
{
    if (text.size() != n) return false;
    for (unsigned char c : text) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

bool DecimalString(const std::string& text)
{
    if (text.empty() || text.size() > 20) return false;
    if (text[0] == '0') return text.size() == 1;
    for (unsigned char c : text) {
        if (c < '0' || c > '9') return false;
    }
    return true;
}

bool ParseU64(const std::string& text, uint64_t& out)
{
    if (!DecimalString(text)) return false;
    uint64_t value = 0;
    for (unsigned char c : text) {
        const uint64_t digit = static_cast<uint64_t>(c - '0');
        if (value > (std::numeric_limits<uint64_t>::max() - digit) / 10) return false;
        value = value * 10 + digit;
    }
    out = value;
    return true;
}

bool ReadInt(const UniValue& value, int64_t& out)
{
    if (!value.isNum()) return false;
    const std::string& text = value.getValStr();
    if (text.empty()) return false;
    size_t i = 0;
    if (text[0] == '-') {
        if (text.size() == 1) return false;
        i = 1;
    }
    if (text[i] == '0' && text.size() != i + 1) return false;
    for (size_t j = i; j < text.size(); ++j) {
        if (text[j] < '0' || text[j] > '9') return false;
    }
    try {
        out = value.getInt<int64_t>();
    } catch (const std::exception&) {
        return false;
    }
    return true;
}

std::string ToHex(const unsigned char* data, size_t n)
{
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out(n * 2, '\0');
    for (size_t i = 0; i < n; ++i) {
        out[i * 2] = kHex[data[i] >> 4];
        out[i * 2 + 1] = kHex[data[i] & 0x0f];
    }
    return out;
}

std::string ToHex(const std::string& bytes)
{
    return ToHex(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size());
}

// Lowercase hex of the first 32 bytes of SHA-384 over the 32-byte client nonce.
std::string ServerNonce(const std::string& client_hex)
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
    std::string nonce = ToHex(hash, 32);
    if (nonce == client_hex) {
        unsigned char again[CSHA384::OUTPUT_SIZE];
        CSHA384().Write(hash, sizeof(hash)).Finalize(again);
        nonce = ToHex(again, 32);
    }
    return nonce;
}

bool KnownRole(const std::string& role)
{
    return role == "PUBLIC_READ" || role == "RESEARCH_PUBLISH" || role == "GIT_READ" || role == "GIT_WRITE" ||
           role == "PRIVATE_READ";
}

bool ChannelName(const std::string& name)
{
    if (name.empty() || name.size() > 64) return false;
    for (unsigned char c : name) {
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))) return false;
    }
    return true;
}

enum class RecordState { Missing, Private, Ok };

RecordState LoadRecord(const PeerView& view, const std::string& id, PeerRecord& out)
{
    out = PeerRecord{};
    if (!view.Record(id, out) || !out.exists) return RecordState::Missing;
    if (out.is_private) return RecordState::Private;
    return RecordState::Ok;
}

bool LargerThan(size_t size, const std::string& maximum_bytes)
{
    uint64_t cap = 0;
    if (!ParseU64(maximum_bytes, cap)) return false;
    return static_cast<uint64_t>(size) > cap;
}

std::string RouteName(const std::string& route)
{
    constexpr std::string_view kPrefix{"/btx-model/3/"};
    if (route.size() >= kPrefix.size() && std::string_view{route}.substr(0, kPrefix.size()) == kPrefix) {
        return route.substr(kPrefix.size());
    }
    return route;
}

bool KnownRoute(const std::string& name)
{
    return name == "hello" || name == "auth" || name == "records/get" || name == "records/announce" ||
           name == "research/query" || name == "subscriptions/poll" || name == "git/tunnel" ||
           name == "artifacts/manifest" || name == "artifacts/piece" || name == "trust/state" ||
           name == "channels/get";
}

bool ParseRoot(const std::string& request_json, UniValue& root, std::string& response_json, std::string& err)
{
    if (!root.read(request_json) || !root.isObject()) return Fail(response_json, err, "BTX035_SCHEMA");
    return true;
}

bool HandleHello(const UniValue& root, std::string& response_json, std::string& err)
{
    if (root.exists("contract_revision")) {
        const UniValue& revision = root["contract_revision"];
        if (!revision.isStr() || revision.get_str() != "1.1.0") return Fail(response_json, err, "BTX035_UPGRADE_REQUIRED");
    }
    if (!ExactKeys(root, {"contract_revision", "protocol_versions", "mode", "nonce", "transport_binding_id",
                          "requested_roles", "control_limit", "data_limit", "server_deadline_ms", "proof_window_ms"})) {
        return Fail(response_json, err, "BTX035_SCHEMA");
    }
    const UniValue& versions = root["protocol_versions"];
    int64_t version = 0;
    if (!versions.isArray() || versions.size() != 1 || !ReadInt(versions[0], version) || version != 3) {
        return Fail(response_json, err, "BTX035_SCHEMA");
    }
    const UniValue& mode = root["mode"];
    if (!mode.isStr() || (mode.get_str() != "PUBLIC_READER" && mode.get_str() != "ROOT_BOUND")) {
        return Fail(response_json, err, "BTX035_SCHEMA");
    }
    if (!root["nonce"].isStr() || !LowerHex(root["nonce"].get_str(), 64)) return Fail(response_json, err, "BTX035_SCHEMA");
    const UniValue& binding = root["transport_binding_id"];
    if (!(binding.isNull() || (binding.isStr() && LowerHex(binding.get_str(), 96)))) {
        return Fail(response_json, err, "BTX035_SCHEMA");
    }
    const UniValue& roles = root["requested_roles"];
    if (!roles.isArray() || roles.size() < 1 || roles.size() > 8) return Fail(response_json, err, "BTX035_SCHEMA");
    std::vector<std::string> copied;
    copied.reserve(roles.size());
    for (size_t i = 0; i < roles.size(); ++i) {
        if (!roles[i].isStr() || !KnownRole(roles[i].get_str())) return Fail(response_json, err, "BTX035_SCHEMA");
        for (const std::string& prior : copied) {
            if (prior == roles[i].get_str()) return Fail(response_json, err, "BTX035_SCHEMA");
        }
        copied.push_back(roles[i].get_str());
    }
    int64_t control = 0;
    int64_t data = 0;
    int64_t window = 0;
    if (!ReadInt(root["control_limit"], control) || control < 32768 || control > 262144) {
        return Fail(response_json, err, "BTX035_SCHEMA");
    }
    if (!ReadInt(root["data_limit"], data) || data < 65536 || data > 4194304) {
        return Fail(response_json, err, "BTX035_SCHEMA");
    }
    const UniValue& deadline = root["server_deadline_ms"];
    if (!(deadline.isNull() || (deadline.isStr() && DecimalString(deadline.get_str())))) {
        return Fail(response_json, err, "BTX035_SCHEMA");
    }
    if (!ReadInt(root["proof_window_ms"], window) || window < 1000 || window > 30000) {
        return Fail(response_json, err, "BTX035_SCHEMA");
    }

    UniValue out(UniValue::VOBJ);
    out.pushKV("contract_revision", "1.1.0");
    UniValue answered(UniValue::VARR);
    answered.push_back(int64_t{3});
    out.pushKV("protocol_versions", answered);
    out.pushKV("mode", "PUBLIC_READER");
    out.pushKV("nonce", ServerNonce(root["nonce"].get_str()));
    out.pushKV("transport_binding_id", UniValue(UniValue::VNULL));
    UniValue role_arr(UniValue::VARR);
    for (const std::string& role : copied) role_arr.push_back(role);
    out.pushKV("requested_roles", role_arr);
    out.pushKV("control_limit", control);
    out.pushKV("data_limit", data);
    out.pushKV("server_deadline_ms", UniValue(UniValue::VNULL));
    out.pushKV("proof_window_ms", window);
    return Done(response_json, err, out);
}

bool HandleAuth(const UniValue& root, const PeerView& view, std::string& response_json, std::string& err)
{
    if (!ExactKeys(root, {"mode", "client_nonce", "server_nonce", "hello_digest", "exporter_binding",
                          "certificate_key_id", "deadline_ms", "signature_hex"})) {
        return Fail(response_json, err, "BTX035_SCHEMA");
    }
    if (!root["mode"].isStr() || root["mode"].get_str() != "PUBLIC_READER") return Fail(response_json, err, "BTX035_SCHEMA");
    if (!root["client_nonce"].isStr() || !LowerHex(root["client_nonce"].get_str(), 64)) {
        return Fail(response_json, err, "BTX035_SCHEMA");
    }
    if (!root["server_nonce"].isStr() || !LowerHex(root["server_nonce"].get_str(), 64)) {
        return Fail(response_json, err, "BTX035_SCHEMA");
    }
    if (!root["hello_digest"].isStr() || !LowerHex(root["hello_digest"].get_str(), 96)) {
        return Fail(response_json, err, "BTX035_SCHEMA");
    }
    if (!root["exporter_binding"].isStr() || !LowerHex(root["exporter_binding"].get_str(), 96)) {
        return Fail(response_json, err, "BTX035_SCHEMA");
    }
    if (!root["certificate_key_id"].isStr() || !LowerHex(root["certificate_key_id"].get_str(), 96)) {
        return Fail(response_json, err, "BTX035_SCHEMA");
    }
    if (!root["deadline_ms"].isStr() || !DecimalString(root["deadline_ms"].get_str())) {
        return Fail(response_json, err, "BTX035_SCHEMA");
    }
    if (!root["signature_hex"].isStr() || !LowerHex(root["signature_hex"].get_str(), 4840)) {
        return Fail(response_json, err, "BTX035_SCHEMA");
    }
    const std::string digest = root["hello_digest"].get_str();
    const std::string signature = root["signature_hex"].get_str();
    if (!view.VerifySession(digest, signature)) return Fail(response_json, err, "BTX035_PERMIT");
    UniValue out(UniValue::VOBJ);
    out.pushKV("authenticated", true);
    out.pushKV("mode", "PUBLIC_READER");
    return Done(response_json, err, out);
}

bool HandleRecordGet(const UniValue& root, const PeerView& view, std::string& response_json, std::string& err, bool manifest)
{
    if (!ExactKeys(root, {"record_id"})) return Fail(response_json, err, "BTX035_SCHEMA");
    if (!root["record_id"].isStr() || !LowerHex(root["record_id"].get_str(), 96)) {
        return Fail(response_json, err, "BTX035_SCHEMA");
    }
    const std::string id = root["record_id"].get_str();
    PeerRecord rec;
    const RecordState state = LoadRecord(view, id, rec);
    if (state == RecordState::Missing) return Fail(response_json, err, "BTX035_NOT_FOUND");
    if (state == RecordState::Private) return Fail(response_json, err, "BTX035_SCOPE_DENIED");
    if (manifest && rec.body.find("manifest") == std::string::npos) return Fail(response_json, err, "BTX035_RECORD_TYPE");
    UniValue out(UniValue::VOBJ);
    out.pushKV("record_id", id);
    out.pushKV("body", rec.body);
    return Done(response_json, err, out);
}

bool HandleAnnounce(const UniValue& root, const PeerView& view, std::string& response_json, std::string& err)
{
    if (!ExactKeys(root, {"record_ids"})) return Fail(response_json, err, "BTX035_SCHEMA");
    const UniValue& ids = root["record_ids"];
    if (!ids.isArray() || ids.size() < 1 || ids.size() > 32) return Fail(response_json, err, "BTX035_SCHEMA");
    std::vector<std::string> requested;
    requested.reserve(ids.size());
    for (size_t i = 0; i < ids.size(); ++i) {
        if (!ids[i].isStr() || !LowerHex(ids[i].get_str(), 96)) return Fail(response_json, err, "BTX035_SCHEMA");
        requested.push_back(ids[i].get_str());
    }
    UniValue accepted(UniValue::VARR);
    UniValue rejected(UniValue::VARR);
    for (const std::string& id : requested) {
        PeerRecord rec;
        const RecordState state = LoadRecord(view, id, rec);
        if (state == RecordState::Ok) {
            accepted.push_back(id);
            continue;
        }
        UniValue row(UniValue::VOBJ);
        row.pushKV("record_id", id);
        row.pushKV("error_code", state == RecordState::Private ? "BTX035_SCOPE_DENIED" : "BTX035_NOT_FOUND");
        rejected.push_back(std::move(row));
    }
    UniValue out(UniValue::VOBJ);
    out.pushKV("accepted_ids", accepted);
    out.pushKV("rejected", rejected);
    return Done(response_json, err, out);
}

bool HandleResearch(const UniValue& root, const PeerView& view, std::string& response_json, std::string& err)
{
    if (!ExactKeys(root, {"scope", "topics", "kinds", "after_cursor", "limit"})) {
        return Fail(response_json, err, "BTX035_SCHEMA");
    }
    if (!root["scope"].isStr() || root["scope"].get_str() != "LOCAL") return Fail(response_json, err, "BTX035_SCOPE_DENIED");
    if (!root["topics"].isArray() || !root["kinds"].isArray()) return Fail(response_json, err, "BTX035_SCHEMA");
    const UniValue& cursor = root["after_cursor"];
    if (!(cursor.isNull() || cursor.isStr())) return Fail(response_json, err, "BTX035_SCHEMA");
    int64_t limit = 0;
    if (!ReadInt(root["limit"], limit) || limit < 1 || limit > 100) return Fail(response_json, err, "BTX035_SCHEMA");
    std::vector<std::string> ids;
    view.PublicResearch(ids);
    UniValue arr(UniValue::VARR);
    for (const std::string& id : ids) {
        if (static_cast<int64_t>(arr.size()) >= limit) break;
        arr.push_back(id);
    }
    UniValue out(UniValue::VOBJ);
    out.pushKV("record_ids", arr);
    out.pushKV("next_cursor", UniValue(UniValue::VNULL));
    out.pushKV("complete", static_cast<int64_t>(ids.size()) <= limit);
    return Done(response_json, err, out);
}

bool HandlePoll(const UniValue& root, const PeerView& view, std::string& response_json, std::string& err)
{
    if (!ExactKeys(root, {"subscription_id", "after_sequence", "wait_ms"})) return Fail(response_json, err, "BTX035_SCHEMA");
    if (!root["subscription_id"].isStr() || !LowerHex(root["subscription_id"].get_str(), 96)) {
        return Fail(response_json, err, "BTX035_SCHEMA");
    }
    if (!root["after_sequence"].isStr() || !DecimalString(root["after_sequence"].get_str())) {
        return Fail(response_json, err, "BTX035_SCHEMA");
    }
    uint64_t wait_ms = 0;
    if (!root["wait_ms"].isStr() || !ParseU64(root["wait_ms"].get_str(), wait_ms) || wait_ms > 5000) {
        return Fail(response_json, err, "BTX035_SCHEMA");
    }
    const std::string id = root["subscription_id"].get_str();
    PeerRecord rec;
    if (LoadRecord(view, id, rec) == RecordState::Missing) return Fail(response_json, err, "BTX035_NOT_FOUND");
    UniValue out(UniValue::VOBJ);
    out.pushKV("events", UniValue(UniValue::VARR));
    out.pushKV("next_sequence", root["after_sequence"].get_str());
    out.pushKV("gap", false);
    return Done(response_json, err, out);
}

bool HandleGit(const UniValue& root, const PeerView& view, std::string& response_json, std::string& err)
{
    if (!ExactKeys(root, {"repository_id", "service", "ticket_id", "expected_ref_state"})) {
        return Fail(response_json, err, "BTX035_SCHEMA");
    }
    if (!root["repository_id"].isStr() || !LowerHex(root["repository_id"].get_str(), 96)) {
        return Fail(response_json, err, "BTX035_SCHEMA");
    }
    if (!root["service"].isStr()) return Fail(response_json, err, "BTX035_SCHEMA");
    const std::string service = root["service"].get_str();
    if (service != "git-upload-pack" && service != "git-receive-pack") return Fail(response_json, err, "BTX035_SCHEMA");
    if (!root["ticket_id"].isStr() || !LowerHex(root["ticket_id"].get_str(), 96)) {
        return Fail(response_json, err, "BTX035_SCHEMA");
    }
    const UniValue& expected = root["expected_ref_state"];
    if (!(expected.isNull() || (expected.isStr() && LowerHex(expected.get_str(), 96)))) {
        return Fail(response_json, err, "BTX035_SCHEMA");
    }
    if (!view.Ticket(root["ticket_id"].get_str())) return Fail(response_json, err, "BTX035_PERMIT");
    UniValue frames(UniValue::VARR);
    UniValue open(UniValue::VOBJ);
    open.pushKV("type", "OPEN");
    open.pushKV("service", service);
    open.pushKV("resource_id", root["repository_id"].get_str());
    frames.push_back(std::move(open));
    UniValue end(UniValue::VOBJ);
    end.pushKV("type", "END");
    end.pushKV("byte_count", "0");
    end.pushKV("result", "OK");
    end.pushKV("physical_disposition", "STOPPED_QUIESCENT");
    frames.push_back(std::move(end));
    UniValue out(UniValue::VOBJ);
    out.pushKV("opened", true);
    out.pushKV("service", service);
    out.pushKV("frames", frames);
    out.pushKV("pack", false);
    return Done(response_json, err, out);
}

bool HandlePiece(const UniValue& root, const PeerView& view, std::string& response_json, std::string& err)
{
    if (!ExactKeys(root, {"resource", "manifest_id", "piece_index", "maximum_bytes"})) {
        return Fail(response_json, err, "BTX035_SCHEMA");
    }
    const UniValue& resource = root["resource"];
    if (!ExactKeys(resource, {"kind", "digest48"})) return Fail(response_json, err, "BTX035_SCHEMA");
    if (!resource["kind"].isStr() || resource["kind"].get_str() != "MODEL") return Fail(response_json, err, "BTX035_SCHEMA");
    if (!resource["digest48"].isStr() || !LowerHex(resource["digest48"].get_str(), 96)) {
        return Fail(response_json, err, "BTX035_SCHEMA");
    }
    if (!root["manifest_id"].isStr() || !LowerHex(root["manifest_id"].get_str(), 96)) {
        return Fail(response_json, err, "BTX035_SCHEMA");
    }
    if (!root["piece_index"].isStr() || !root["maximum_bytes"].isStr()) return Fail(response_json, err, "BTX035_SCHEMA");
    const std::string piece_index = root["piece_index"].get_str();
    const std::string maximum_bytes = root["maximum_bytes"].get_str();
    uint64_t index = 0;
    if (!ParseU64(piece_index, index) || !DecimalString(maximum_bytes)) return Fail(response_json, err, "BTX035_SCHEMA");
    const std::string manifest_id = root["manifest_id"].get_str();
    PeerRecord rec;
    const RecordState state = LoadRecord(view, manifest_id, rec);
    if (state == RecordState::Missing) return Fail(response_json, err, "BTX035_NOT_FOUND");
    if (state == RecordState::Private) return Fail(response_json, err, "BTX035_SCOPE_DENIED");
    std::string bytes;
    if (!view.Piece(resource["digest48"].get_str(), index, bytes)) return Fail(response_json, err, "BTX035_NOT_FOUND");
    if (LargerThan(bytes.size(), maximum_bytes)) return Fail(response_json, err, "BTX035_LIMIT_EXCEEDED");
    const std::string hex = ToHex(bytes);
    UniValue frames(UniValue::VARR);
    UniValue open(UniValue::VOBJ);
    open.pushKV("type", "OPEN");
    open.pushKV("piece_index", piece_index);
    frames.push_back(std::move(open));
    UniValue data(UniValue::VOBJ);
    data.pushKV("type", "DATA");
    data.pushKV("content_hex", hex);
    frames.push_back(std::move(data));
    UniValue end(UniValue::VOBJ);
    end.pushKV("type", "END");
    end.pushKV("byte_count", std::to_string(bytes.size()));
    end.pushKV("result", "OK");
    end.pushKV("physical_disposition", "STOPPED_QUIESCENT");
    frames.push_back(std::move(end));
    UniValue out(UniValue::VOBJ);
    out.pushKV("piece_index", piece_index);
    out.pushKV("byte_size", static_cast<uint64_t>(bytes.size()));
    out.pushKV("content_hex", hex);
    out.pushKV("frames", frames);
    return Done(response_json, err, out);
}

bool HandleTrust(const UniValue& root, const PeerView& view, std::string& response_json, std::string& err)
{
    if (!ExactKeys(root, {"realm_id"})) return Fail(response_json, err, "BTX035_SCHEMA");
    if (!root["realm_id"].isStr() || !LowerHex(root["realm_id"].get_str(), 96)) {
        return Fail(response_json, err, "BTX035_SCHEMA");
    }
    std::string policy_id;
    int threshold = 0;
    if (!view.Realm(root["realm_id"].get_str(), policy_id, threshold)) return Fail(response_json, err, "BTX035_NOT_FOUND");
    UniValue out(UniValue::VOBJ);
    out.pushKV("policy_id", policy_id);
    out.pushKV("epoch", "0");
    out.pushKV("threshold", std::to_string(threshold));
    out.pushKV("public_connectivity", "DISABLED");
    out.pushKV("revocation_age_ms", "0");
    out.pushKV("authority_state", "LOCAL");
    return Done(response_json, err, out);
}

bool HandleChannel(const UniValue& root, const PeerView& view, std::string& response_json, std::string& err)
{
    if (!ExactKeys(root, {"realm_id", "channel"})) return Fail(response_json, err, "BTX035_SCHEMA");
    if (!root["realm_id"].isStr() || !LowerHex(root["realm_id"].get_str(), 96)) {
        return Fail(response_json, err, "BTX035_SCHEMA");
    }
    if (!root["channel"].isStr() || !ChannelName(root["channel"].get_str())) return Fail(response_json, err, "BTX035_SCHEMA");
    int64_t sequence = 0;
    std::string update_id;
    UniValue out(UniValue::VOBJ);
    if (!view.Channel(root["realm_id"].get_str(), root["channel"].get_str(), sequence, update_id)) {
        out.pushKV("update_id", UniValue(UniValue::VNULL));
        out.pushKV("sequence", "0");
        out.pushKV("state", "UNKNOWN");
        return Done(response_json, err, out);
    }
    out.pushKV("update_id", update_id);
    out.pushKV("sequence", std::to_string(sequence));
    out.pushKV("state", "CURRENT");
    return Done(response_json, err, out);
}

} // namespace

bool DispatchPeerRoute(const std::string& route, const std::string& request_json, const PeerView& view,
                       std::string& response_json, std::string& err)
{
    response_json.clear();
    err.clear();
    const std::string name = RouteName(route);
    if (!KnownRoute(name)) return Fail(response_json, err, "BTX035_UNSUPPORTED");
    UniValue root;
    if (!ParseRoot(request_json, root, response_json, err)) return false;
    if (name == "hello") return HandleHello(root, response_json, err);
    if (name == "auth") return HandleAuth(root, view, response_json, err);
    if (name == "records/get") return HandleRecordGet(root, view, response_json, err, false);
    if (name == "records/announce") return HandleAnnounce(root, view, response_json, err);
    if (name == "research/query") return HandleResearch(root, view, response_json, err);
    if (name == "subscriptions/poll") return HandlePoll(root, view, response_json, err);
    if (name == "git/tunnel") return HandleGit(root, view, response_json, err);
    if (name == "artifacts/manifest") return HandleRecordGet(root, view, response_json, err, true);
    if (name == "artifacts/piece") return HandlePiece(root, view, response_json, err);
    if (name == "trust/state") return HandleTrust(root, view, response_json, err);
    if (name == "channels/get") return HandleChannel(root, view, response_json, err);
    return Fail(response_json, err, "BTX035_UNSUPPORTED");
}

} // namespace modelnet
