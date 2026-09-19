// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/package_pjson.h>

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace modelnet {
namespace {

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

bool SafeAsciiKey(std::string_view k)
{
    if (k.empty()) return false;
    for (unsigned char c : k) {
        if (c < 0x20 || c > 0x7e) return false;
    }
    return true;
}

bool CanonicalIntToken(std::string_view n, std::string& err)
{
    if (n == "-0") {
        err = "negative numeric zero";
        return false;
    }
    if (n.empty() || n.size() > 17) {
        err = "integer token too long";
        return false;
    }
    size_t i = 0;
    if (n[0] == '-') {
        i = 1;
        if (i >= n.size()) {
            err = "invalid integer";
            return false;
        }
    }
    if (n[i] == '0' && n.size() != i + 1) {
        err = "noncanonical integer";
        return false;
    }
    for (size_t j = i; j < n.size(); ++j) {
        if (n[j] < '0' || n[j] > '9') {
            err = "invalid integer";
            return false;
        }
    }
    int64_t v = 0;
    const auto r = std::from_chars(n.data(), n.data() + n.size(), v);
    if (r.ec != std::errc{} || r.ptr != n.data() + n.size()) {
        err = "JSON integer outside exact range";
        return false;
    }
    const int64_t lim = static_cast<int64_t>(PJSON_MAX_SAFE_INT);
    if (v > lim || v < -lim) {
        err = "JSON integer outside exact range";
        return false;
    }
    return true;
}

void AppendEscaped(std::string& out, const std::string& s)
{
    out.push_back('"');
    for (unsigned char c : s) {
        switch (c) {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\b':
            out += "\\b";
            break;
        case '\f':
            out += "\\f";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            if (c < 0x20) {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                out += buf;
            } else {
                out.push_back(static_cast<char>(c));
            }
            break;
        }
    }
    out.push_back('"');
}

bool AppendValue(const UniValue& v, std::string& out, std::string& err, int depth, size_t& nodes);

bool AppendValue(const UniValue& v, std::string& out, std::string& err, int depth, size_t& nodes)
{
    if (depth > static_cast<int>(PJSON_MAX_DEPTH) || ++nodes > PJSON_MAX_NODES) {
        err = "JSON structural limit";
        return false;
    }
    switch (v.type()) {
    case UniValue::VNULL:
        out += "null";
        return true;
    case UniValue::VBOOL:
        out += v.get_bool() ? "true" : "false";
        return true;
    case UniValue::VNUM: {
        const std::string n = v.getValStr();
        if (n.find('.') != std::string::npos || n.find('e') != std::string::npos ||
            n.find('E') != std::string::npos) {
            err = "floats prohibited";
            return false;
        }
        if (!CanonicalIntToken(n, err)) return false;
        out += n;
        return true;
    }
    case UniValue::VSTR:
        if (!ValidUtf8(v.get_str())) {
            err = "invalid UTF-8/JSON/depth";
            return false;
        }
        AppendEscaped(out, v.get_str());
        return true;
    case UniValue::VARR: {
        out.push_back('[');
        const auto& vals = v.getValues();
        for (size_t i = 0; i < vals.size(); ++i) {
            if (i) out.push_back(',');
            if (!AppendValue(vals[i], out, err, depth + 1, nodes)) return false;
        }
        out.push_back(']');
        return true;
    }
    case UniValue::VOBJ: {
        std::map<std::string, UniValue> kv;
        v.getObjMap(kv);
        out.push_back('{');
        bool first = true;
        for (const auto& e : kv) {
            if (!SafeAsciiKey(e.first)) {
                err = "JSON keys must be nonempty ASCII";
                return false;
            }
            if (!first) out.push_back(',');
            first = false;
            AppendEscaped(out, e.first);
            out.push_back(':');
            if (!AppendValue(e.second, out, err, depth + 1, nodes)) return false;
        }
        out.push_back('}');
        return true;
    }
    }
    err = "unsupported JSON type";
    return false;
}

void AppendUtf8(std::string& u, uint32_t cp)
{
    if (cp <= 0x7f) {
        u.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7ff) {
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
}

struct Parser {
    std::string_view s;
    size_t i{0};
    std::string* err;
    size_t nodes{0};

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
                if (!ValidUtf8(u)) return Fail("invalid UTF-8/JSON/depth");
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
                    if (i + 6 > s.size() || s[i] != '\\' || s[i + 1] != 'u') {
                        return Fail("invalid UTF-8/JSON/depth");
                    }
                    i += 2;
                    uint32_t lo = 0;
                    if (!Hex4(lo) || lo < 0xdc00 || lo > 0xdfff) return Fail("invalid UTF-8/JSON/depth");
                    cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                } else if (cp >= 0xdc00 && cp <= 0xdfff) {
                    return Fail("invalid UTF-8/JSON/depth");
                }
                if (cp > 0x10ffff) return Fail("invalid UTF-8/JSON/depth");
                AppendUtf8(u, cp);
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
        if (depth > static_cast<int>(PJSON_MAX_DEPTH) || ++nodes > PJSON_MAX_NODES) {
            return Fail("JSON structural limit");
        }
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
                UniValue elem;
                if (!Parse(elem, depth + 1)) return false;
                out.push_back(std::move(elem));
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
            for (;;) {
                std::string key;
                if (!ParseStringInto(key)) return false;
                if (!SafeAsciiKey(key)) return Fail("JSON keys must be nonempty ASCII");
                if (out.exists(key)) return Fail("duplicate JSON key");
                Skip();
                if (i >= s.size() || s[i] != ':') return Fail("object colon");
                ++i;
                UniValue val;
                if (!Parse(val, depth + 1)) return false;
                out.pushKVEnd(std::move(key), std::move(val));
                Skip();
                if (i < s.size() && s[i] == ',') {
                    ++i;
                    continue;
                }
                if (i < s.size() && s[i] == '}') {
                    ++i;
                    return true;
                }
                return Fail("object");
            }
        }
        if (c == 'N' || c == 'I') {
            return Fail("float/exponent/nonfinite token rejected");
        }
        if (c == '-' || (c >= '0' && c <= '9')) {
            const size_t start = i;
            if (s[i] == '-') ++i;
            if (i >= s.size() || s[i] < '0' || s[i] > '9') return Fail("invalid integer");
            while (i < s.size() && s[i] >= '0' && s[i] <= '9') ++i;
            if (i < s.size() && (s[i] == '.' || s[i] == 'e' || s[i] == 'E')) {
                return Fail("float/exponent/nonfinite token rejected");
            }
            const std::string_view tok = s.substr(start, i - start);
            if (!CanonicalIntToken(tok, *err)) return false;
            try {
                out.setNumStr(std::string{tok});
            } catch (const std::exception&) {
                return Fail("invalid integer");
            }
            return true;
        }
        return Fail("unsupported JSON type (no floating point)");
    }
};

} // namespace

bool EncodePjson1(const UniValue& value, std::vector<unsigned char>& out, std::string& err)
{
    out.clear();
    std::string s;
    size_t nodes = 0;
    if (!AppendValue(value, s, err, 0, nodes)) return false;
    out.assign(s.begin(), s.end());
    return true;
}

bool DecodePjson1(Span<const unsigned char> raw, UniValue& out, std::string& err)
{
    out = UniValue();
    const std::string_view sv{reinterpret_cast<const char*>(raw.data()), raw.size()};
    if (!ValidUtf8(sv)) {
        err = "invalid UTF-8/JSON/depth";
        return false;
    }
    Parser p{sv, 0, &err, 0};
    if (!p.Parse(out, 0)) return false;
    p.Skip();
    if (p.i != sv.size()) {
        err = "trailing JSON";
        return false;
    }
    std::vector<unsigned char> again;
    if (!EncodePjson1(out, again, err)) return false;
    if (again.size() != raw.size() || !std::equal(again.begin(), again.end(), raw.begin())) {
        err = "noncanonical JSON bytes";
        return false;
    }
    return true;
}

bool Pjson1Equals(Span<const unsigned char> a, Span<const unsigned char> b)
{
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin());
}

} // namespace modelnet
