// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/canonical_codec.h>

#include <crypto/sha384.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cctype>
#include <limits>
#include <map>
#include <regex>

namespace modelnet {
namespace {

void PutU32(std::vector<unsigned char>& b, uint32_t n)
{
    b.push_back(static_cast<unsigned char>(n));
    b.push_back(static_cast<unsigned char>(n >> 8));
    b.push_back(static_cast<unsigned char>(n >> 16));
    b.push_back(static_cast<unsigned char>(n >> 24));
}

void PutU64(std::vector<unsigned char>& b, uint64_t n)
{
    for (int i = 0; i < 8; ++i) b.push_back(static_cast<unsigned char>(n >> (8 * i)));
}

bool GetU32(Span<const unsigned char>& in, uint32_t& n)
{
    if (in.size() < 4) return false;
    n = static_cast<uint32_t>(in[0]) | (static_cast<uint32_t>(in[1]) << 8) |
        (static_cast<uint32_t>(in[2]) << 16) | (static_cast<uint32_t>(in[3]) << 24);
    in = in.subspan(4);
    return true;
}

bool GetU64(Span<const unsigned char>& in, uint64_t& n)
{
    if (in.size() < 8) return false;
    n = 0;
    for (int i = 0; i < 8; ++i) n |= static_cast<uint64_t>(in[i]) << (8 * i);
    in = in.subspan(8);
    return true;
}

bool ValidUtf8(std::string_view s)
{
    const auto* p = reinterpret_cast<const unsigned char*>(s.data());
    const auto* end = p + s.size();
    while (p < end) {
        if (*p <= 0x7f) {
            ++p;
            continue;
        }
        int need = 0;
        uint32_t cp = 0;
        if ((*p & 0xe0) == 0xc0) {
            need = 1;
            cp = *p & 0x1f;
            if (cp < 2) return false;
        } else if ((*p & 0xf0) == 0xe0) {
            need = 2;
            cp = *p & 0x0f;
        } else if ((*p & 0xf8) == 0xf0) {
            need = 3;
            cp = *p & 0x07;
        } else {
            return false;
        }
        ++p;
        for (int i = 0; i < need; ++i) {
            if (p >= end || (*p & 0xc0) != 0x80) return false;
            cp = (cp << 6) | (*p & 0x3f);
            ++p;
        }
        if (cp >= 0xd800 && cp <= 0xdfff) return false;
        if (need == 2 && cp < 0x800) return false;
        if (need == 3 && cp < 0x10000) return false;
        if (cp > 0x10ffff) return false;
    }
    return true;
}

bool ParseNumberToken(std::string_view tok, UniValue& out, std::string& err)
{
    if (tok.empty()) {
        err = "empty number";
        return false;
    }
    if (tok.find('.') != std::string_view::npos || tok.find('e') != std::string_view::npos ||
        tok.find('E') != std::string_view::npos) {
        err = "floating JSON number forbidden";
        return false;
    }
    if (tok[0] == '-') {
        err = "negative JSON integers forbidden";
        return false;
    }
    if (tok.size() > 1 && tok[0] == '0') {
        err = "noncanonical integer";
        return false;
    }
    if (!std::all_of(tok.begin(), tok.end(), [](unsigned char c) { return std::isdigit(c); })) {
        err = "invalid integer";
        return false;
    }
    uint64_t n = 0;
    for (char c : tok) {
        const uint64_t d = static_cast<uint64_t>(c - '0');
        if (n > (std::numeric_limits<uint64_t>::max() - d) / 10) {
            err = "uint64 overflow";
            return false;
        }
        n = n * 10 + d;
    }
    out.setInt(n);
    return true;
}

struct Parser {
    std::string_view s;
    size_t i{0};
    std::string* err;
    void Skip()
    {
        while (i < s.size() && (s[i] == ' ' || s[i] == '\n' || s[i] == '\r' || s[i] == '\t')) ++i;
    }
    bool Fail(const char* m)
    {
        if (err) *err = m;
        return false;
    }
    bool Hex4(uint32_t& cp)
    {
        cp = 0;
        if (i + 4 > s.size()) return false;
        for (int k = 0; k < 4; ++k, ++i) {
            const char h = s[i];
            int v;
            if (h >= '0' && h <= '9') v = h - '0';
            else if (h >= 'a' && h <= 'f') v = h - 'a' + 10;
            else if (h >= 'A' && h <= 'F') v = h - 'A' + 10;
            else return false;
            cp = (cp << 4) | static_cast<uint32_t>(v);
        }
        return true;
    }
    bool ParseStringInto(std::string& u)
    {
        Skip();
        if (i >= s.size() || s[i] != '"') return Fail("string");
        ++i;
        u.clear();
        while (i < s.size()) {
            const unsigned char c = static_cast<unsigned char>(s[i++]);
            if (c == '"') {
                if (!ValidUtf8(u)) return Fail("invalid UTF-8/surrogate");
                if (u.size() > CANONICAL_MAX_STRING) return Fail("string byte limit");
                return true;
            }
            if (c != '\\') {
                if (c < 0x20) return Fail("unescaped control");
                u.push_back(static_cast<char>(c));
                continue;
            }
            if (i >= s.size()) return Fail("unterminated string");
            const char e = s[i++];
            switch (e) {
            case '"':
            case '\\':
            case '/':
                u.push_back(e);
                break;
            case 'b':
                u.push_back('\b');
                break;
            case 'f':
                u.push_back('\f');
                break;
            case 'n':
                u.push_back('\n');
                break;
            case 'r':
                u.push_back('\r');
                break;
            case 't':
                u.push_back('\t');
                break;
            case 'u': {
                uint32_t cp = 0;
                if (!Hex4(cp)) return Fail("bad unicode escape");
                if (cp >= 0xd800 && cp <= 0xdbff) {
                    if (i + 6 > s.size() || s[i] != '\\' || s[i + 1] != 'u') return Fail("invalid UTF-8/surrogate");
                    i += 2;
                    uint32_t lo = 0;
                    if (!Hex4(lo) || lo < 0xdc00 || lo > 0xdfff) return Fail("invalid UTF-8/surrogate");
                    cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                } else if (cp >= 0xdc00 && cp <= 0xdfff) {
                    return Fail("invalid UTF-8/surrogate");
                }
                if (cp <= 0x7f) u.push_back(static_cast<char>(cp));
                else if (cp <= 0x7ff) {
                    u.push_back(static_cast<char>(0xc0 | (cp >> 6)));
                    u.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
                } else if (cp <= 0xffff) {
                    u.push_back(static_cast<char>(0xe0 | (cp >> 12)));
                    u.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
                    u.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
                } else {
                    u.push_back(static_cast<char>(0xf0 | (cp >> 18)));
                    u.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f)));
                    u.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
                    u.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
                }
                break;
            }
            default:
                return Fail("bad escape");
            }
        }
        return Fail("unterminated string");
    }
    bool Parse(UniValue& out, int depth)
    {
        if (depth > static_cast<int>(CANONICAL_MAX_DEPTH)) return Fail("depth limit");
        Skip();
        if (i >= s.size()) return Fail("unexpected end");
        const char c = s[i];
        if (c == 'n') {
            if (s.substr(i, 4) != "null") return Fail("invalid literal");
            i += 4;
            out.setNull();
            return true;
        }
        if (c == 't') {
            if (s.substr(i, 4) != "true") return Fail("invalid literal");
            i += 4;
            out.setBool(true);
            return true;
        }
        if (c == 'f') {
            if (s.substr(i, 5) != "false") return Fail("invalid literal");
            i += 5;
            out.setBool(false);
            return true;
        }
        if (c == '"') {
            std::string u;
            if (!ParseStringInto(u)) return false;
            out.setStr(std::move(u));
            return true;
        }
        if (c == '[') {
            ++i;
            out.setArray();
            Skip();
            if (i < s.size() && s[i] == ']') {
                ++i;
                return true;
            }
            for (;;) {
                if (out.size() >= CANONICAL_MAX_ARRAY) return Fail("array bound");
                UniValue elem;
                if (!Parse(elem, depth + 1)) return false;
                out.push_back(elem);
                Skip();
                if (i < s.size() && s[i] == ',') {
                    ++i;
                    continue;
                }
                if (i < s.size() && s[i] == ']') {
                    ++i;
                    return true;
                }
                return Fail("array");
            }
        }
        if (c == '{') {
            ++i;
            out.setObject();
            Skip();
            if (i < s.size() && s[i] == '}') {
                ++i;
                return true;
            }
            std::map<std::string, UniValue> seen;
            for (;;) {
                if (seen.size() >= CANONICAL_MAX_FIELDS) return Fail("object bound");
                std::string key;
                if (!ParseStringInto(key)) return false;
                if (!ValidCanonicalKey(key)) return Fail("ASCII field name required");
                Skip();
                if (i >= s.size() || s[i] != ':') return Fail("object colon");
                ++i;
                UniValue val;
                if (!Parse(val, depth + 1)) return false;
                if (seen.count(key)) return Fail("duplicate JSON key");
                seen.emplace(std::move(key), std::move(val));
                Skip();
                if (i < s.size() && s[i] == ',') {
                    ++i;
                    continue;
                }
                if (i < s.size() && s[i] == '}') {
                    ++i;
                    for (auto& kv : seen) out.pushKV(kv.first, kv.second);
                    return true;
                }
                return Fail("object");
            }
        }
        if (c == '-' || std::isdigit(static_cast<unsigned char>(c))) {
            const size_t start = i;
            if (s[i] == '-') ++i;
            if (i >= s.size() || !std::isdigit(static_cast<unsigned char>(s[i]))) return Fail("invalid integer");
            while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) ++i;
            if (i < s.size() && (s[i] == '.' || s[i] == 'e' || s[i] == 'E')) return Fail("floating JSON number forbidden");
            return ParseNumberToken(s.substr(start, i - start), out, *err);
        }
        return Fail("unsupported type; floats/bytes not accepted");
    }
};

} // namespace

bool ValidCanonicalKey(std::string_view key)
{
    static const std::regex re("^[a-z][a-z0-9_]{0,63}$");
    return std::regex_match(key.begin(), key.end(), re);
}

bool CanonicalAtoms(const std::string& s, int64_t& n, std::string& err)
{
    if (s.empty() || (s.size() > 1 && s[0] == '0') || s[0] == '-') {
        err = "noncanonical atoms";
        return false;
    }
    if (!std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isdigit(c); })) {
        err = "noncanonical atoms";
        return false;
    }
    n = 0;
    for (char c : s) {
        const int64_t d = c - '0';
        if (n > (MAX_MONEY_ATOMS - d) / 10) {
            err = "MoneyRange";
            return false;
        }
        n = n * 10 + d;
    }
    if (n > MAX_MONEY_ATOMS) {
        err = "MoneyRange";
        return false;
    }
    return true;
}

const char* KnownRecordType(std::string_view type)
{
    static const char* k[] = {
        "BountyTerms",
        "EvaluationSpec",
        "FundingRound",
        "Submission",
        "EvaluationReport",
        "AwardProposal",
        "ModelSearchRecordV2",
        "CouncilAppointment",
        "SubmissionCommitment",
        "AcceptanceCertificate",
        "Challenge",
        "AwardPolicyApproval",
        "AgentMandate",
        "FundingLot",
        "FeedEvent",
        "BountyEconomy",
        "RecoveryManifest",
        "ChainContext",
    };
    for (const char* t : k) {
        if (type == t) return t;
    }
    return nullptr;
}

bool CanonicalEncode(const UniValue& value, std::vector<unsigned char>& out, std::string& err, int depth)
{
    if (depth > static_cast<int>(CANONICAL_MAX_DEPTH)) {
        err = "depth limit";
        return false;
    }
    switch (value.getType()) {
    case UniValue::VNULL:
        out.push_back(0x00);
        return true;
    case UniValue::VBOOL:
        out.push_back(value.get_bool() ? 0x02 : 0x01);
        return true;
    case UniValue::VNUM: {
        const std::string& tok = value.getValStr();
        if (tok.find('.') != std::string::npos || tok.find('e') != std::string::npos ||
            tok.find('E') != std::string::npos) {
            err = "floating JSON number forbidden";
            return false;
        }
        if (!tok.empty() && tok[0] == '-') {
            err = "uint64 range";
            return false;
        }
        uint64_t n = 0;
        try {
            n = value.getInt<uint64_t>();
        } catch (...) {
            err = "uint64 range";
            return false;
        }
        out.push_back(0x03);
        PutU64(out, n);
        return true;
    }
    case UniValue::VSTR: {
        const std::string& u = value.get_str();
        if (!ValidUtf8(u)) {
            err = "invalid UTF-8/surrogate";
            return false;
        }
        if (u.size() > CANONICAL_MAX_STRING) {
            err = "string byte limit";
            return false;
        }
        out.push_back(0x04);
        PutU32(out, static_cast<uint32_t>(u.size()));
        out.insert(out.end(), u.begin(), u.end());
        return true;
    }
    case UniValue::VARR: {
        if (value.size() > CANONICAL_MAX_ARRAY) {
            err = "array bound";
            return false;
        }
        out.push_back(0x05);
        PutU32(out, static_cast<uint32_t>(value.size()));
        for (const auto& e : value.getValues()) {
            if (!CanonicalEncode(e, out, err, depth + 1)) return false;
        }
        return true;
    }
    case UniValue::VOBJ: {
        std::map<std::string, UniValue> kv;
        value.getObjMap(kv);
        if (kv.size() > CANONICAL_MAX_FIELDS) {
            err = "object bound";
            return false;
        }
        for (const auto& e : kv) {
            if (!ValidCanonicalKey(e.first)) {
                err = "ASCII field name required";
                return false;
            }
        }
        out.push_back(0x06);
        PutU32(out, static_cast<uint32_t>(kv.size()));
        for (const auto& e : kv) {
            UniValue k;
            k.setStr(e.first);
            if (!CanonicalEncode(k, out, err, depth + 1)) return false;
            if (!CanonicalEncode(e.second, out, err, depth + 1)) return false;
        }
        return true;
    }
    }
    err = "unsupported type; floats/bytes not accepted";
    return false;
}

bool CanonicalDecode(Span<const unsigned char> in, UniValue& out, std::string& err)
{
    auto rec = [&](auto&& self, Span<const unsigned char>& cur, UniValue& v, int depth) -> bool {
        if (depth > static_cast<int>(CANONICAL_MAX_DEPTH)) {
            err = "depth limit";
            return false;
        }
        if (cur.empty()) {
            err = "truncated";
            return false;
        }
        const unsigned char tag = cur[0];
        cur = cur.subspan(1);
        if (tag == 0x00) {
            v.setNull();
            return true;
        }
        if (tag == 0x01) {
            v.setBool(false);
            return true;
        }
        if (tag == 0x02) {
            v.setBool(true);
            return true;
        }
        if (tag == 0x03) {
            uint64_t n;
            if (!GetU64(cur, n)) {
                err = "truncated";
                return false;
            }
            v.setInt(n);
            return true;
        }
        if (tag == 0x04) {
            uint32_t n;
            if (!GetU32(cur, n) || cur.size() < n) {
                err = "string byte limit";
                return false;
            }
            if (n > CANONICAL_MAX_STRING) {
                err = "string byte limit";
                return false;
            }
            std::string u(reinterpret_cast<const char*>(cur.data()), n);
            cur = cur.subspan(n);
            if (!ValidUtf8(u)) {
                err = "invalid UTF-8/surrogate";
                return false;
            }
            v.setStr(std::move(u));
            return true;
        }
        if (tag == 0x05) {
            uint32_t n;
            if (!GetU32(cur, n) || n > CANONICAL_MAX_ARRAY) {
                err = "array bound";
                return false;
            }
            v.setArray();
            for (uint32_t i = 0; i < n; ++i) {
                UniValue e;
                if (!self(self, cur, e, depth + 1)) return false;
                v.push_back(e);
            }
            return true;
        }
        if (tag == 0x06) {
            uint32_t n;
            if (!GetU32(cur, n) || n > CANONICAL_MAX_FIELDS) {
                err = "object bound";
                return false;
            }
            v.setObject();
            for (uint32_t i = 0; i < n; ++i) {
                UniValue k, val;
                if (!self(self, cur, k, depth + 1) || k.getType() != UniValue::VSTR) {
                    err = "ASCII field name required";
                    return false;
                }
                if (!ValidCanonicalKey(k.get_str())) {
                    err = "ASCII field name required";
                    return false;
                }
                if (v.exists(k.get_str())) {
                    err = "duplicate JSON key";
                    return false;
                }
                if (!self(self, cur, val, depth + 1)) return false;
                v.pushKV(k.get_str(), val);
            }
            return true;
        }
        err = "unsupported type; floats/bytes not accepted";
        return false;
    };
    Span<const unsigned char> cur = in;
    if (!rec(rec, cur, out, 0)) return false;
    if (!cur.empty()) {
        err = "trailing canonical bytes";
        return false;
    }
    return true;
}

bool StrictParseJson(std::string_view raw, UniValue& out, std::string& err)
{
    Parser p{raw, 0, &err};
    if (!p.Parse(out, 0)) return false;
    p.Skip();
    if (p.i != raw.size()) {
        err = "trailing JSON";
        return false;
    }
    return true;
}

bool EnvelopeDomain(const std::string& record_type, std::vector<unsigned char>& domain, std::string& err)
{
    if (!KnownRecordType(record_type)) {
        err = "record type";
        return false;
    }
    const std::string name = (record_type == "ModelSearchRecordV2") ? "BTX/ModelSearchRecord/v2" : ("BTX/" + record_type + "/v1");
    domain.assign(name.begin(), name.end());
    domain.push_back(0);
    return true;
}

bool EnvelopeNetworkId(const UniValue& body, NetworkId& nid, std::string& err)
{
    if (!body.isObject() || !body.exists("network_id") || !body["network_id"].isStr()) {
        err = "network id";
        return false;
    }
    return NetworkId::FromHex(body["network_id"].get_str(), nid, err);
}

bool EnvelopePreimage(const UniValue& body, std::vector<unsigned char>& preimage, std::string& err)
{
    if (!body.isObject()) {
        err = "body fields mismatch";
        return false;
    }
    std::map<std::string, UniValue> kv;
    body.getObjMap(kv);
    static const char* need[] = {
        "envelope_version", "record_type", "network_id", "signer_id", "public_key_hex", "delegation_id", "payload"};
    if (kv.size() != 7) {
        err = "body fields mismatch";
        return false;
    }
    for (const char* k : need) {
        if (!kv.count(k)) {
            err = "body fields mismatch";
            return false;
        }
    }
    if (!body["envelope_version"].isNum() || body["envelope_version"].getInt<int>() != 1) {
        err = "envelope version";
        return false;
    }
    if (!body["record_type"].isStr() || !KnownRecordType(body["record_type"].get_str())) {
        err = "record type";
        return false;
    }
    NetworkId nid;
    if (!EnvelopeNetworkId(body, nid, err)) return false;
    std::vector<unsigned char> domain;
    if (!EnvelopeDomain(body["record_type"].get_str(), domain, err)) return false;
    std::vector<unsigned char> canon;
    if (!CanonicalEncode(body, canon, err)) return false;
    preimage = domain;
    preimage.insert(preimage.end(), nid.data.begin(), nid.data.end());
    preimage.insert(preimage.end(), canon.begin(), canon.end());
    if (preimage.size() > CANONICAL_MAX_ENVELOPE) {
        err = "envelope bound";
        return false;
    }
    return true;
}

bool EnvelopeDigest(const UniValue& body, Digest48& id, std::string& err)
{
    std::vector<unsigned char> pre;
    if (!EnvelopePreimage(body, pre, err)) return false;
    CSHA384 hasher;
    hasher.Write(pre.data(), pre.size());
    hasher.Finalize(id.data.data());
    return true;
}

} // namespace modelnet
