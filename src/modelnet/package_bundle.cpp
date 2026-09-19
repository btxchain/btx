// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/package_bundle.h>

#include <crypto/common.h>
#include <crypto/sha384.h>
#include <modelnet/package_core.h>
#include <span.h>
#include <univalue.h>

#include <cstring>
#include <limits>

namespace modelnet {
namespace {

constexpr size_t MAX_BUNDLE_PAYLOAD = 4 * 1024 * 1024;

bool RejectFloats(const UniValue& v, std::string& err, int depth = 0)
{
    if (depth > 32) {
        err = "nesting";
        return false;
    }
    if (v.isNum()) {
        const std::string s = v.getValStr();
        if (s.find('.') != std::string::npos || s.find('e') != std::string::npos ||
            s.find('E') != std::string::npos) {
            err = "floats prohibited";
            return false;
        }
    }
    if (v.isArray()) {
        for (const auto& e : v.getValues()) {
            if (!RejectFloats(e, err, depth + 1)) return false;
        }
    } else if (v.isObject()) {
        for (const auto& k : v.getKeys()) {
            if (!RejectFloats(v[k], err, depth + 1)) return false;
        }
    }
    return true;
}

/** Header length is trusted only after this check; never 68+n or memcpy(n) first. */
bool ParseBundleHeader(Span<const unsigned char> data, uint32_t& flags, uint64_t& n, std::string& err)
{
    flags = 0;
    n = 0;
    if (data.size() < 68) {
        err = "invalid header";
        return false;
    }
    if (std::memcmp(data.data(), BTXPKG_MAGIC, 8) != 0) {
        err = "invalid header";
        return false;
    }
    flags = ReadLE32(data.data() + 8);
    n = ReadLE64(data.data() + 12);
    if (n == std::numeric_limits<uint64_t>::max() || n > MAX_BUNDLE_PAYLOAD) {
        err = "flags/size/trailing";
        return false;
    }
    if (static_cast<uint64_t>(data.size()) < 68 || static_cast<uint64_t>(data.size()) - 68 != n) {
        err = "flags/size/trailing";
        return false;
    }
    return true;
}

} // namespace

bool EncodeBtxBundle(const UniValue& value, std::vector<unsigned char>& out, std::string& err)
{
    out.clear();
    if (!value.isObject()) {
        err = "package must be object";
        return false;
    }
    if (!RejectFloats(value, err)) return false;
    const std::string payload = value.write();
    if (payload.size() > MAX_BUNDLE_PAYLOAD) {
        err = "oversize";
        return false;
    }
    CSHA384 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(payload.data()), payload.size());
    unsigned char digest[48];
    hasher.Finalize(digest);
    out.resize(8 + 4 + 8 + 48 + payload.size());
    std::memcpy(out.data(), BTXPKG_MAGIC, 8);
    WriteLE32(out.data() + 8, BTXPKG_BUNDLE_FLAGS);
    WriteLE64(out.data() + 12, payload.size());
    std::memcpy(out.data() + 20, digest, 48);
    std::memcpy(out.data() + 68, payload.data(), payload.size());
    return true;
}

bool DecodeBtxBundle(Span<const unsigned char> data, UniValue& out, std::string& err)
{
    out = UniValue(UniValue::VOBJ);
    uint32_t flags = 0;
    uint64_t n = 0;
    if (!ParseBundleHeader(data, flags, n, err)) return false;
    if (flags != BTXPKG_BUNDLE_FLAGS && flags != BTXPKG_CORE_FLAGS) {
        err = "flags/size/trailing";
        return false;
    }
    const size_t payload_n = static_cast<size_t>(n);
    CSHA384 hasher;
    hasher.Write(data.data() + 68, payload_n);
    unsigned char digest[48];
    hasher.Finalize(digest);
    if (std::memcmp(digest, data.data() + 20, 48) != 0) {
        err = "payload digest";
        return false;
    }
    // flags=0 is the PJSON1 package discriminator. It is not a valid bundle
    // discriminator when that package body is also present.
    if (flags == BTXPKG_CORE_FLAGS) {
        DecodedBtxPackage pkg;
        std::string pkg_err;
        if (DecodeBtxPackage(data, pkg, pkg_err)) {
            err = "conflicting dual body";
            return false;
        }
    }
    const std::string payload(reinterpret_cast<const char*>(data.data() + 68), payload_n);
    if (!out.read(payload) || !out.isObject()) {
        err = "package must be object";
        return false;
    }
    if (!RejectFloats(out, err)) return false;
    return true;
}

} // namespace modelnet
