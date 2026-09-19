// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/hello_caps.h>

#include <modelnet/file_stream.h>
#include <modelnet/subpiece.h>

#include <algorithm>
#include <map>
#include <utility>

namespace modelnet {
namespace {

int VersionSuffix(const char* name)
{
    const std::string s(name);
    const auto pos = s.rfind("_V");
    if (pos == std::string::npos || pos + 2 >= s.size()) return 1;
    int v = 0;
    for (size_t i = pos + 2; i < s.size(); ++i) {
        if (s[i] < '0' || s[i] > '9') return 1;
        v = v * 10 + (s[i] - '0');
    }
    return v > 0 ? v : 1;
}

} // namespace

bool HelloCapabilityEntryName(const UniValue& entry, std::string& name)
{
    name.clear();
    if (entry.isStr()) {
        name = entry.get_str();
        return !name.empty();
    }
    if (entry.isObject() && entry.exists("name") && entry["name"].isStr()) {
        name = entry["name"].get_str();
        return !name.empty();
    }
    return false;
}

UniValue HelloCapabilityArray()
{
    UniValue a(UniValue::VARR);
    for (const char* c : {
             FULL_FILE_STREAM_V1,
             SUBPIECE_V1,
             "SELECTIVE_FILES_V1",
             "ORIGIN_OFFER_V1",
             "FULL_ORIGIN_INGEST_V1",
             "ERASURE_PRESERVATION_V1",
             "QUERY_SUMMARY_V1",
             "INDEX_RECONCILE_V1",
             "METADATA_GOSSIP_V1",
             "PACKAGE_V1",
             "BTXPKG_CORE_V2",
             "AGENT_HANDOFF_V1",
             "BTXPKG_CORE_V3",
             "CAPABILITY_HANDOFF_V1",
             "LAN_DISCOVERY_V1",
         }) {
        const int v = VersionSuffix(c);
        UniValue o(UniValue::VOBJ);
        o.pushKV("name", c);
        o.pushKV("min", v);
        o.pushKV("max", v);
        a.push_back(o);
    }
    return a;
}

bool HelloHasCapability(const UniValue& hello, const std::string& name)
{
    if (!hello.isObject()) return false;
    if (name == FULL_FILE_STREAM_V1 && hello.exists("full_file_stream_v1") && hello["full_file_stream_v1"].isTrue()) {
        return true;
    }
    if (hello.exists("capability") && hello["capability"].isStr() && hello["capability"].get_str() == name) {
        return true;
    }
    if (hello.exists("capabilities") && hello["capabilities"].isArray()) {
        for (const auto& c : hello["capabilities"].getValues()) {
            std::string n;
            if (HelloCapabilityEntryName(c, n) && n == name) return true;
        }
    }
    return false;
}

bool HelloCapabilityRange(const UniValue& entry, std::string& name, int& min_v, int& max_v)
{
    if (!HelloCapabilityEntryName(entry, name)) return false;
    min_v = VersionSuffix(name.c_str());
    max_v = min_v;
    if (entry.isObject()) {
        if (entry.exists("min") && entry["min"].isNum()) min_v = entry["min"].getInt<int>();
        if (entry.exists("max") && entry["max"].isNum()) max_v = entry["max"].getInt<int>();
    }
    if (min_v > max_v) std::swap(min_v, max_v);
    return true;
}

UniValue HelloCapsArray(const UniValue& hello)
{
    if (hello.isArray()) return hello;
    if (hello.isObject() && hello.exists("capabilities") && hello["capabilities"].isArray()) {
        return hello["capabilities"];
    }
    return UniValue(UniValue::VARR);
}

UniValue IntersectHelloCapabilities(const UniValue& local, const UniValue& remote)
{
    std::map<std::string, std::pair<int, int>> remote_ranges;
    const UniValue remote_arr = HelloCapsArray(remote);
    for (const auto& c : remote_arr.getValues()) {
        std::string n;
        int min_v = 1, max_v = 1;
        if (!HelloCapabilityRange(c, n, min_v, max_v)) continue;
        remote_ranges[n] = {min_v, max_v};
    }

    UniValue local_arr = HelloCapsArray(local);
    if (local_arr.empty()) local_arr = HelloCapabilityArray();

    UniValue out(UniValue::VARR);
    for (const auto& c : local_arr.getValues()) {
        std::string n;
        int min_v = 1, max_v = 1;
        if (!HelloCapabilityRange(c, n, min_v, max_v)) continue;
        auto it = remote_ranges.find(n);
        if (it == remote_ranges.end()) continue;
        const int lo = std::max(min_v, it->second.first);
        const int hi = std::min(max_v, it->second.second);
        if (lo > hi) continue;
        UniValue o(UniValue::VOBJ);
        o.pushKV("name", n);
        o.pushKV("min", lo);
        o.pushKV("max", hi);
        out.push_back(o);
    }
    return out;
}

UniValue HelloCapabilityArrayMaybeIntersect(const UniValue& peer)
{
    if (HelloCapsArray(peer).empty()) return HelloCapabilityArray();
    return IntersectHelloCapabilities(HelloCapabilityArray(), peer);
}

} // namespace modelnet
