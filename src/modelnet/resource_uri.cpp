// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/resource_uri.h>

#include <bech32.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cctype>
#include <regex>

namespace modelnet {
namespace {

bool IsAscii(std::string_view s)
{
    for (unsigned char c : s) {
        if (c > 127) return false;
    }
    return true;
}

bool AllLower(std::string_view s)
{
    for (unsigned char c : s) {
        if (std::isupper(c)) return false;
    }
    return true;
}

bool AllUpper(std::string_view s)
{
    for (unsigned char c : s) {
        if (std::islower(c)) return false;
    }
    return true;
}

bool IsBech32Charset(std::string_view s)
{
    static const std::string alphabet{"qpzry9x8gf2tvdw0s3jn54khce6mua7l"};
    for (char c : s) {
        if (alphabet.find(c) == std::string::npos) return false;
    }
    return true;
}

bool IEquals(std::string_view a, std::string_view b)
{
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

} // namespace

std::string Resource::Uri() const
{
    std::string uri;
    std::string err;
    if (!EncodeResource(kind, digest, uri, err)) return {};
    return uri;
}

bool RawToken(uint8_t version, uint8_t kind, const Digest48& digest, std::string& token, std::string& err)
{
    std::vector<uint8_t> values;
    values.reserve(2 + 77);
    values.push_back(version);
    values.push_back(kind);
    if (!ConvertBits<8, 5, true>([&](unsigned char c) { values.push_back(c); }, digest.data.begin(), digest.data.end())) {
        err = "convertbits failed";
        return false;
    }
    const std::string full = bech32::Encode(bech32::Encoding::BECH32M, "btx", values);
    if (full.size() < 5 || full.compare(0, 4, "btx1") != 0) {
        err = "bech32m encode failed";
        return false;
    }
    token = full.substr(4);
    return true;
}

bool EncodeResource(ResourceKind kind, const Digest48& digest, std::string& uri, std::string& err)
{
    ResourceKind tmp;
    if (!ResourceKindFromInt(static_cast<int>(kind), tmp)) {
        err = "unsupported resource type";
        return false;
    }
    std::string token;
    if (!RawToken(RESOURCE_VERSION, static_cast<uint8_t>(kind), digest, token, err)) return false;
    uri = "btx://" + token;
    return true;
}

bool DecodeResource(std::string_view text, Resource& out, std::string& err)
{
    if (text.size() > MAX_URI_INPUT || !IsAscii(text)) {
        err = "invalid URI input";
        return false;
    }
    std::string_view token = text;
    if (text.size() >= 6 && IEquals(text.substr(0, 6), "btx://")) {
        token = text.substr(6);
    } else if (text.size() >= 4 && IEquals(text.substr(0, 4), "btx:")) {
        token = text.substr(4);
    }
    if (!token.empty() && token.back() == '/') {
        token = token.substr(0, token.size() - 1);
    }
    if (token.size() != 85 || (!AllLower(token) && !AllUpper(token))) {
        err = "invalid token length or mixed case";
        return false;
    }
    std::string lower(token);
    for (char& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (!IsBech32Charset(lower)) {
        err = "invalid token character";
        return false;
    }
    const std::string internal = "btx1" + lower;
    const auto decoded = bech32::Decode(internal, bech32::CharLimit::BECH32);
    if (decoded.encoding != bech32::Encoding::BECH32M || decoded.hrp != "btx") {
        err = "checksum mismatch";
        return false;
    }
    if (decoded.data.size() < 2) {
        err = "truncated token";
        return false;
    }
    if (decoded.data[0] != RESOURCE_VERSION) {
        err = "unsupported resource version";
        return false;
    }
    ResourceKind kind;
    if (!ResourceKindFromInt(decoded.data[1], kind)) {
        err = "unsupported resource type";
        return false;
    }
    std::vector<unsigned char> digest_bytes;
    if (!ConvertBits<5, 8, false>([&](unsigned char c) { digest_bytes.push_back(c); },
                                  decoded.data.begin() + 2, decoded.data.end())) {
        err = "noncanonical residual bits";
        return false;
    }
    if (digest_bytes.size() != Digest48::SIZE) {
        err = "invalid digest length";
        return false;
    }
    out.kind = kind;
    std::copy(digest_bytes.begin(), digest_bytes.end(), out.digest.data.begin());
    return true;
}

bool BridgePath(const std::string& uri, const std::string& origin, std::string& out, std::string& err)
{
    Resource r;
    if (!DecodeResource(uri, r, err)) return false;
    static const std::regex origin_re{R"(^https://[a-z0-9.-]+(?::[0-9]+)?$)"};
    if (!std::regex_match(origin, origin_re)) {
        err = "bridge origin must be configured HTTPS origin";
        return false;
    }
    out = origin + "/" + r.Uri().substr(6);
    return true;
}

bool SplitBridgeHost(const std::string& uri, const std::string& suffix, std::string& out, std::string& err)
{
    static const std::regex suffix_re{R"(^[a-z0-9.-]+$)"};
    if (!std::regex_match(suffix, suffix_re)) {
        err = "invalid bridge suffix";
        return false;
    }
    Resource r;
    if (!DecodeResource(uri, r, err)) return false;
    const std::string token = r.Uri().substr(6);
    out = token.substr(0, 42) + "." + token.substr(42) + "." + suffix;
    return true;
}

std::string ShortDisplayUri(std::string_view text)
{
    Resource r;
    std::string err;
    if (!DecodeResource(text, r, err)) return {};
    const std::string full = r.Uri();
    if (full.size() < 22) return {};
    const std::string token = full.substr(6);
    return "btx://" + token.substr(0, 8) + "..." + token.substr(token.size() - 8);
}

std::string CopyUri(std::string_view text)
{
    Resource r;
    std::string err;
    if (!DecodeResource(text, r, err)) return {};
    return r.Uri();
}

} // namespace modelnet
