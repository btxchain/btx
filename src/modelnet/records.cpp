// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/records.h>

#include <modelnet/crypto.h>
#include <modelnet/identity.h>
#include <crypto/common.h>
#include <span.h>
#include <util/strencodings.h>

#include <algorithm>
#include <map>
#include <memory>
#include <regex>
#include <set>
#include <stdexcept>
#include <tuple>

namespace modelnet {
namespace {

struct FType {
    enum Kind { U, HEX, STR, BYTES, BOOL, VEC, STRUCT } kind{U};
    int n{0};
    std::vector<std::pair<std::string, FType>> members;
    std::shared_ptr<FType> elem;
};

FType T_U(int bits)
{
    FType t;
    t.kind = FType::U;
    t.n = bits;
    return t;
}
FType T_Hex(int n)
{
    FType t;
    t.kind = FType::HEX;
    t.n = n;
    return t;
}
FType T_Str(int n)
{
    FType t;
    t.kind = FType::STR;
    t.n = n;
    return t;
}
FType T_Bytes(int n)
{
    FType t;
    t.kind = FType::BYTES;
    t.n = n;
    return t;
}
FType T_Bool()
{
    FType t;
    t.kind = FType::BOOL;
    return t;
}
FType T_Vec(FType elem, int cap)
{
    FType t;
    t.kind = FType::VEC;
    t.n = cap;
    t.elem = std::make_shared<FType>(std::move(elem));
    return t;
}
FType T_Struct(std::vector<std::pair<std::string, FType>> members)
{
    FType t;
    t.kind = FType::STRUCT;
    t.members = std::move(members);
    return t;
}

using FieldList = std::vector<std::pair<std::string, FType>>;

const FieldList& CommonFields()
{
    static const FieldList f{
        {"ext_version", T_U(16)},
        {"network", T_Hex(32)},
        {"signer_role", T_U(8)},
        {"signer_id", T_Hex(48)},
        {"sequence", T_U(64)},
        {"issued_at", T_U(64)},
        {"expires_at", T_U(64)},
    };
    return f;
}

struct Layout {
    const char* name;
    FieldList extra;
};

const std::map<uint8_t, Layout>& Layouts()
{
    static const std::map<uint8_t, Layout> layouts{
        {16, {"IdentityCard", {{"display_name", T_Str(96)}, {"description", T_Str(1024)}}}},
        {17, {"ServiceDelegation", {{"delegate_pubkey", T_Bytes(1312)}, {"scopes", T_U(32)}, {"all_models", T_Bool()}, {"model_scope", T_Vec(T_Hex(48), 64)}}}},
        {18, {"Revocation", {{"target_kind", T_U(8)}, {"target_id", T_Hex(48)}, {"reason_code", T_U(16)}}}},
        {19, {"Collection", {{"title", T_Str(96)}, {"description", T_Str(1024)}, {"entries", T_Vec(T_Struct({{"model_id", T_Hex(48)}, {"priority", T_U(8)}, {"retention_days", T_U(16)}}), 512)}}}},
        {20, {"AliasRecord", {{"slug", T_Str(32)}, {"active", T_Bool()}, {"target_kind", T_U(8)}, {"target_id", T_Hex(48)}, {"previous_record_id", T_Hex(48)}}}},
        {21, {"PolicyBundle", {{"title", T_Str(96)}, {"recommendations", T_Vec(T_Struct({{"target_kind", T_U(8)}, {"target_id", T_Hex(48)}, {"action", T_U(8)}, {"ttl_seconds", T_U(32)}, {"reason", T_Str(192)}}), 128)}}}},
        {22, {"PreservationCircle", {{"title", T_Str(96)}, {"description", T_Str(1024)}, {"collection_id", T_Hex(48)}, {"target_observed_groups", T_U(8)}, {"suggested_storage_bytes", T_U(64)}, {"suggested_lease_seconds", T_U(32)}}}},
        {23, {"FreeGrant", {{"transfer_id", T_Hex(32)}, {"buyer_id", T_Hex(48)}, {"model_id", T_Hex(48)}, {"artifact_id", T_Hex(48)}, {"file_index", T_U(32)}, {"first_piece", T_U(32)}, {"piece_count", T_U(32)}, {"maximum_bytes", T_U(64)}, {"grant_nonce", T_Hex(32)}, {"queue_class", T_U(8)}}}},
        {24, {"ServiceReceipt", {{"receipt_kind", T_U(8)}, {"transfer_id", T_Hex(32)}, {"provider_id", T_Hex(48)}, {"buyer_id", T_Hex(48)}, {"model_id", T_Hex(48)}, {"artifact_id", T_Hex(48)}, {"file_index", T_U(32)}, {"first_piece", T_U(32)}, {"piece_count", T_U(32)}, {"verified_bytes", T_U(64)}, {"outcome", T_U(8)}, {"previous_receipt_id", T_Hex(48)}}}},
    };
    return layouts;
}

FieldList AllFields(uint8_t kind)
{
    FieldList f = CommonFields();
    const auto it = Layouts().find(kind);
    f.insert(f.end(), it->second.extra.begin(), it->second.extra.end());
    return f;
}

bool CompactSize(uint64_t n, std::vector<unsigned char>& out, std::string& err)
{
    (void)err;
    if (n < 253) {
        out.push_back(static_cast<unsigned char>(n));
        return true;
    }
    if (n <= 65535) {
        out.push_back(0xfd);
        unsigned char b[2];
        WriteLE16(b, static_cast<uint16_t>(n));
        out.insert(out.end(), b, b + 2);
        return true;
    }
    if (n <= 0xffffffffULL) {
        out.push_back(0xfe);
        unsigned char b[4];
        WriteLE32(b, static_cast<uint32_t>(n));
        out.insert(out.end(), b, b + 4);
        return true;
    }
    out.push_back(0xff);
    unsigned char b[8];
    WriteLE64(b, n);
    out.insert(out.end(), b, b + 8);
    return true;
}

class Reader {
    Span<const unsigned char> m_b;
    size_t m_i{0};
    size_t m_max;

public:
    Reader(Span<const unsigned char> b, size_t max_size) : m_b(b), m_max(max_size)
    {
        if (b.size() > max_size) throw std::runtime_error("object exceeds size limit");
    }
    std::vector<unsigned char> Take(size_t n)
    {
        if (m_i + n > m_b.size()) throw std::runtime_error("truncated object");
        std::vector<unsigned char> out(m_b.begin() + m_i, m_b.begin() + m_i + n);
        m_i += n;
        return out;
    }
    uint64_t Size(uint64_t max_n)
    {
        const unsigned char p = Take(1)[0];
        uint64_t n = p;
        if (p >= 253) {
            const int width = (p == 253) ? 2 : (p == 254) ? 4 : 8;
            auto raw = Take(width);
            if (width == 2) n = ReadLE16(raw.data());
            else if (width == 4) n = ReadLE32(raw.data());
            else n = ReadLE64(raw.data());
            const uint64_t minv = (p == 253) ? 253 : (p == 254) ? 65536ULL : 4294967296ULL;
            if (n < minv) throw std::runtime_error("nonminimal length");
        }
        if (n > max_n) throw std::runtime_error("length exceeds cap");
        return n;
    }
    bool Empty() const { return m_i == m_b.size(); }
};

bool EncodeValue(const FType& t, const UniValue& v, std::vector<unsigned char>& out, std::string& err);

bool EncodeFields(const FieldList& fields, const UniValue& v, std::vector<unsigned char>& out, std::string& err)
{
    if (!v.isObject()) {
        err = "expected object";
        return false;
    }
    std::set<std::string> expected;
    for (const auto& [name, _] : fields) expected.insert(name);
    std::set<std::string> got(v.getKeys().begin(), v.getKeys().end());
    if (expected != got) {
        err = "extra/missing field";
        return false;
    }
    for (const auto& [name, ty] : fields) {
        if (!EncodeValue(ty, v[name], out, err)) return false;
    }
    return true;
}

bool EncodeValue(const FType& t, const UniValue& v, std::vector<unsigned char>& out, std::string& err)
{
    if (t.kind == FType::VEC) {
        if (!v.isArray() || v.size() > static_cast<size_t>(t.n)) {
            err = "vector cap";
            return false;
        }
        if (!CompactSize(v.size(), out, err)) return false;
        for (const auto& item : v.getValues()) {
            if (!EncodeValue(*t.elem, item, out, err)) return false;
        }
        return true;
    }
    if (t.kind == FType::STRUCT) {
        return EncodeFields(t.members, v, out, err);
    }
    if (t.kind == FType::BOOL) {
        if (!v.isBool()) {
            err = "invalid bool";
            return false;
        }
        out.push_back(v.get_bool() ? 1 : 0);
        return true;
    }
    if (t.kind == FType::U) {
        if (!v.isNum()) {
            err = "integer out of range";
            return false;
        }
        // Reject non-integers / negatives via string form.
        const std::string& s = v.getValStr();
        if (s.empty() || s[0] == '-' || s.find('.') != std::string::npos) {
            err = "integer out of range";
            return false;
        }
        uint64_t n = 0;
        try {
            n = v.getInt<uint64_t>();
        } catch (...) {
            err = "integer out of range";
            return false;
        }
        const int bits = t.n;
        if (bits < 64 && n >= (uint64_t{1} << bits)) {
            err = "integer out of range";
            return false;
        }
        const int nbytes = bits / 8;
        unsigned char buf[8]{};
        WriteLE64(buf, n);
        out.insert(out.end(), buf, buf + nbytes);
        return true;
    }
    if (t.kind == FType::HEX) {
        if (!v.isStr()) {
            err = "invalid fixed hex";
            return false;
        }
        const std::string& hex = v.get_str();
        if (hex.size() != static_cast<size_t>(2 * t.n)) {
            err = "invalid fixed hex";
            return false;
        }
        for (char c : hex) {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                err = "invalid fixed hex";
                return false;
            }
        }
        const auto raw = TryParseHex<unsigned char>(hex);
        if (!raw || raw->size() != static_cast<size_t>(t.n)) {
            err = "invalid fixed hex";
            return false;
        }
        out.insert(out.end(), raw->begin(), raw->end());
        return true;
    }
    if (t.kind == FType::STR) {
        if (!v.isStr()) {
            err = "string cap or NUL";
            return false;
        }
        const std::string& s = v.get_str();
        if (s.find('\0') != std::string::npos || s.size() > static_cast<size_t>(t.n)) {
            err = "string cap or NUL";
            return false;
        }
        if (!CompactSize(s.size(), out, err)) return false;
        out.insert(out.end(), s.begin(), s.end());
        return true;
    }
    if (t.kind == FType::BYTES) {
        if (!v.isStr()) {
            err = "byte length";
            return false;
        }
        const std::string& hex = v.get_str();
        if (hex.size() != static_cast<size_t>(2 * t.n) || hex != ToLower(hex)) {
            err = "byte length";
            return false;
        }
        const auto raw = TryParseHex<unsigned char>(hex);
        if (!raw || raw->size() != static_cast<size_t>(t.n)) {
            err = "byte length";
            return false;
        }
        if (!CompactSize(static_cast<uint64_t>(t.n), out, err)) return false;
        out.insert(out.end(), raw->begin(), raw->end());
        return true;
    }
    err = "unknown type";
    return false;
}

UniValue DecodeValue(const FType& t, Reader& r);

UniValue DecodeFields(const FieldList& fields, Reader& r)
{
    UniValue obj(UniValue::VOBJ);
    for (const auto& [name, ty] : fields) {
        obj.pushKV(name, DecodeValue(ty, r));
    }
    return obj;
}

UniValue DecodeValue(const FType& t, Reader& r)
{
    if (t.kind == FType::VEC) {
        UniValue arr(UniValue::VARR);
        const uint64_t n = r.Size(t.n);
        for (uint64_t i = 0; i < n; ++i) arr.push_back(DecodeValue(*t.elem, r));
        return arr;
    }
    if (t.kind == FType::STRUCT) return DecodeFields(t.members, r);
    if (t.kind == FType::BOOL) {
        const auto b = r.Take(1)[0];
        if (b > 1) throw std::runtime_error("invalid bool");
        return UniValue(b == 1);
    }
    if (t.kind == FType::U) {
        const int nbytes = t.n / 8;
        auto raw = r.Take(nbytes);
        uint64_t n = 0;
        if (nbytes == 1) n = raw[0];
        else if (nbytes == 2) n = ReadLE16(raw.data());
        else if (nbytes == 4) n = ReadLE32(raw.data());
        else n = ReadLE64(raw.data());
        return UniValue(n);
    }
    if (t.kind == FType::HEX) {
        auto raw = r.Take(t.n);
        return HexStr(raw);
    }
    if (t.kind == FType::STR) {
        auto raw = r.Take(r.Size(t.n));
        std::string s(raw.begin(), raw.end());
        if (s.find('\0') != std::string::npos) throw std::runtime_error("NUL");
        // Validate UTF-8 by round-tripping through UniValue string.
        return s;
    }
    if (t.kind == FType::BYTES) {
        if (r.Size(t.n) != static_cast<uint64_t>(t.n)) throw std::runtime_error("fixed byte string wrong length");
        auto raw = r.Take(t.n);
        return HexStr(raw);
    }
    throw std::runtime_error("unknown type");
}

uint64_t U64(const UniValue& v, const char* k)
{
    return v[k].getInt<uint64_t>();
}
uint64_t U8(const UniValue& v, const char* k)
{
    return v[k].getInt<uint64_t>();
}

bool CheckRecord(uint8_t kind, const UniValue& v, std::string& err)
{
    if (!Layouts().count(kind) || U64(v, "ext_version") != EXT_VERSION_V11) {
        err = "version/type";
        return false;
    }
    const uint64_t expected_role = (kind == 23 || kind == 24) ? 0 : 1;
    if (U8(v, "signer_role") != expected_role) {
        err = "wrong signer role";
        return false;
    }
    if (U64(v, "sequence") < 1) {
        err = "sequence must be positive";
        return false;
    }
    const uint64_t expires = U64(v, "expires_at");
    const uint64_t issued = U64(v, "issued_at");
    if (kind != 18 && expires && expires <= issued) {
        err = "invalid expiry";
        return false;
    }
    if ((kind == 17 || kind == 20 || kind == 21 || kind == 23 || kind == 24) && !expires) {
        err = "expiry required";
        return false;
    }
    if (kind == 17) {
        const uint64_t scopes = U64(v, "scopes");
        if (!(scopes > 0 && scopes <= 31)) {
            err = "delegation scope";
            return false;
        }
        const bool all_models = v["all_models"].get_bool();
        const auto& ms = v["model_scope"].getValues();
        if (all_models != ms.empty()) {
            err = "ambiguous model scope";
            return false;
        }
        std::vector<std::string> ids;
        for (const auto& x : ms) ids.push_back(x.get_str());
        auto unique = ids;
        std::sort(unique.begin(), unique.end());
        unique.erase(std::unique(unique.begin(), unique.end()), unique.end());
        if (ids != unique) {
            err = "model scope order";
            return false;
        }
        if (expires - issued > 7 * static_cast<uint64_t>(DAY_SECONDS)) {
            err = "delegation too long";
            return false;
        }
    }
    if (kind == 18) {
        const uint64_t tk = U8(v, "target_kind");
        if ((tk != 1 && tk != 2) || expires != 0) {
            err = "revocation shape";
            return false;
        }
    }
    if (kind == 19) {
        std::vector<std::string> ids;
        for (const auto& e : v["entries"].getValues()) ids.push_back(e["model_id"].get_str());
        if (ids.empty()) {
            err = "collection order";
            return false;
        }
        auto unique = ids;
        std::sort(unique.begin(), unique.end());
        unique.erase(std::unique(unique.begin(), unique.end()), unique.end());
        if (ids != unique) {
            err = "collection order";
            return false;
        }
        for (const auto& e : v["entries"].getValues()) {
            const uint64_t p = e["priority"].getInt<uint64_t>();
            const uint64_t d = e["retention_days"].getInt<uint64_t>();
            if (!(p >= 1 && p <= 5) || d > 3650) {
                err = "entry policy";
                return false;
            }
        }
    }
    if (kind == 20) {
        static const std::regex slug_re{R"(^[a-z0-9][a-z0-9-]{0,31}$)"};
        if (!std::regex_match(v["slug"].get_str(), slug_re)) {
            err = "alias slug";
            return false;
        }
        const bool active = v["active"].get_bool();
        const uint64_t tk = U8(v, "target_kind");
        if (active) {
            if (tk != 0 && tk != 2 && tk != 4 && tk != 5 && tk != 6) {
                err = "alias target";
                return false;
            }
        } else {
            if (tk != 255 || v["target_id"].get_str() != std::string(96, '0')) {
                err = "alias tombstone";
                return false;
            }
        }
    }
    if (kind == 21) {
        const auto& recs = v["recommendations"].getValues();
        if (recs.empty()) {
            err = "empty policy";
            return false;
        }
        std::vector<std::tuple<uint64_t, std::string, uint64_t>> tuples;
        for (const auto& x : recs) {
            tuples.emplace_back(x["target_kind"].getInt<uint64_t>(), x["target_id"].get_str(), x["action"].getInt<uint64_t>());
        }
        auto unique = tuples;
        std::sort(unique.begin(), unique.end());
        unique.erase(std::unique(unique.begin(), unique.end()), unique.end());
        if (tuples != unique) {
            err = "policy order";
            return false;
        }
        for (const auto& x : recs) {
            const uint64_t tk = x["target_kind"].getInt<uint64_t>();
            const uint64_t action = x["action"].getInt<uint64_t>();
            const uint64_t ttl = x["ttl_seconds"].getInt<uint64_t>();
            if ((tk != 0 && tk != 1 && tk != 2 && tk != 3 && tk != 8) ||
                (action != 1 && action != 2 && action != 3 && action != 4) ||
                !(ttl >= 1 && ttl <= 30 * static_cast<uint64_t>(DAY_SECONDS))) {
                err = "policy entry";
                return false;
            }
            if ((action == 1 && tk != 3) || (action == 2 && tk != 8)) {
                err = "policy action target";
                return false;
            }
        }
    }
    if (kind == 22) {
        const uint64_t g = U8(v, "target_observed_groups");
        const uint64_t lease = U64(v, "suggested_lease_seconds");
        if (!(g >= 1 && g <= 16) || lease > 7 * static_cast<uint64_t>(DAY_SECONDS)) {
            err = "circle bound";
            return false;
        }
    }
    if (kind == 23) {
        const uint64_t pc = U64(v, "piece_count");
        const uint64_t mb = U64(v, "maximum_bytes");
        const uint64_t qc = U8(v, "queue_class");
        if (pc == 0 || mb == 0 || (qc != 0 && qc != 1 && qc != 2)) {
            err = "free range";
            return false;
        }
        if (expires - issued > 600) {
            err = "free grant too long";
            return false;
        }
    }
    if (kind == 24) {
        const uint64_t rk = U8(v, "receipt_kind");
        const uint64_t outcome = U8(v, "outcome");
        if ((rk != 0 && rk != 1) || (outcome != 0 && outcome != 1 && outcome != 2)) {
            err = "receipt enum";
            return false;
        }
        const std::string& signer = v["signer_id"].get_str();
        const std::string& expected = (rk == 0) ? v["buyer_id"].get_str() : v["provider_id"].get_str();
        if (signer != expected) {
            err = "receipt signer";
            return false;
        }
    }
    return true;
}

} // namespace

const char* RecordKindName(uint8_t kind)
{
    const auto it = Layouts().find(kind);
    if (it == Layouts().end()) return "UNKNOWN";
    return it->second.name;
}

bool EncodeRecord(uint8_t kind, const UniValue& body, std::vector<unsigned char>& out, std::string& err)
{
    if (!Layouts().count(kind)) {
        err = "unsupported record";
        return false;
    }
    if (!CheckRecord(kind, body, err)) return false;
    out.clear();
    if (!EncodeFields(AllFields(kind), body, out, err)) return false;
    const size_t cap = (kind == 19 || kind == 21) ? 65536 : 16384;
    if (out.size() > cap) {
        err = "record body cap";
        return false;
    }
    return true;
}

bool DecodeRecord(uint8_t kind, Span<const unsigned char> bytes, UniValue& body, std::string& err)
{
    if (!Layouts().count(kind)) {
        err = "unsupported record";
        return false;
    }
    try {
        Reader r(bytes, (kind == 19 || kind == 21) ? 65536 : 16384);
        body = DecodeFields(AllFields(kind), r);
        if (!r.Empty()) {
            err = "trailing bytes";
            return false;
        }
    } catch (const std::exception& e) {
        err = e.what();
        return false;
    }
    return CheckRecord(kind, body, err);
}

bool RecordId(uint8_t kind, const UniValue& body, Digest48& id, std::string& err)
{
    std::vector<unsigned char> encoded;
    if (!EncodeRecord(kind, body, encoded, err)) return false;
    const std::string domain = std::string("BTX/") + Layouts().at(kind).name + "/v1.1";
    id = DomainHash(domain, encoded);
    return true;
}

bool SigningMessage(uint8_t kind, const UniValue& body, Digest48& msg, std::string& err)
{
    Digest48 rid;
    if (!RecordId(kind, body, rid, err)) return false;
    std::vector<unsigned char> payload;
    payload.push_back(kind);
    const auto net = TryParseHex<unsigned char>(body["network"].get_str());
    if (!net || net->size() != 32) {
        err = "invalid network";
        return false;
    }
    payload.insert(payload.end(), net->begin(), net->end());
    payload.insert(payload.end(), rid.data.begin(), rid.data.end());
    msg = DomainHash("BTX/ModelExtensionSig/v1.1", payload);
    return true;
}

void FillRecordCommon(UniValue& body, uint8_t signer_role, const Digest48& signer_id, int64_t now, int64_t ttl_s)
{
    if (now < 0) now = 0;
    body.pushKV("ext_version", static_cast<int>(EXT_VERSION_V11));
    body.pushKV("network", std::string(64, '0'));
    body.pushKV("signer_role", signer_role);
    body.pushKV("signer_id", signer_id.Hex());
    body.pushKV("sequence", 1);
    body.pushKV("issued_at", now);
    body.pushKV("expires_at", ttl_s > 0 ? now + ttl_s : int64_t{0});
}

bool SignTypedRecord(uint8_t kind, const UniValue& body,
                      Span<const unsigned char> sk,
                      std::vector<unsigned char>& payload,
                      std::vector<unsigned char>& sig,
                      Digest48& record_id,
                      std::string& err)
{
    if (!EncodeRecord(kind, body, payload, err)) return false;
    if (!RecordId(kind, body, record_id, err)) return false;
    Digest48 msg;
    if (!SigningMessage(kind, body, msg, err)) return false;
    return SignMlDsa44(sk, Span<const unsigned char>{msg.data.data(), msg.data.size()}, sig, err);
}

bool VerifyTypedRecord(uint8_t kind,
                       Span<const unsigned char> payload,
                       Span<const unsigned char> sig,
                       Span<const unsigned char> pk,
                       int64_t now,
                       UniValue& body,
                       Digest48& record_id,
                       std::string& err)
{
    if (!DecodeRecord(kind, payload, body, err)) return false;
    if (!RecordId(kind, body, record_id, err)) return false;
    Digest48 msg;
    if (!SigningMessage(kind, body, msg, err)) return false;
    if (!VerifyMlDsa44(pk, Span<const unsigned char>{msg.data.data(), msg.data.size()}, sig)) {
        err = "bad signature";
        return false;
    }
    const int64_t exp = body.exists("expires_at") ? body["expires_at"].getInt<int64_t>() : 0;
    if (exp && now > 0 && exp < now) {
        err = "expired record";
        return false;
    }
    return true;
}

} // namespace modelnet
