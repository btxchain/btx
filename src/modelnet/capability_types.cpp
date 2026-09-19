// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/capability_types.h>

#include <modelnet/package_pjson.h>
#include <crypto/common.h>
#include <crypto/sha384.h>
#include <random.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cstring>

namespace modelnet {

const char* RecipeKindName(RecipeKind k)
{
    switch (k) {
    case RecipeKind::FULL_MODEL: return "FULL_MODEL";
    case RecipeKind::BASE_WITH_ADAPTERS: return "BASE_WITH_ADAPTERS";
    case RecipeKind::PIPELINE: return "PIPELINE";
    case RecipeKind::EXPERT_RESIDENT_MODEL: return "EXPERT_RESIDENT_MODEL";
    }
    return "UNKNOWN";
}

bool RecipeKindFromName(const std::string& s, RecipeKind& out)
{
    if (s == "FULL_MODEL") {
        out = RecipeKind::FULL_MODEL;
        return true;
    }
    if (s == "BASE_WITH_ADAPTERS") {
        out = RecipeKind::BASE_WITH_ADAPTERS;
        return true;
    }
    if (s == "PIPELINE") {
        out = RecipeKind::PIPELINE;
        return true;
    }
    if (s == "EXPERT_RESIDENT_MODEL") {
        out = RecipeKind::EXPERT_RESIDENT_MODEL;
        return true;
    }
    return false;
}

const char* ReadinessTargetName(ReadinessTarget t)
{
    switch (t) {
    case ReadinessTarget::VERIFIED_FILES: return "VERIFIED_FILES";
    case ReadinessTarget::RUNTIME_LOADED: return "RUNTIME_LOADED";
    case ReadinessTarget::RUNTIME_READY: return "RUNTIME_READY";
    case ReadinessTarget::FIRST_USEFUL_RESULT: return "FIRST_USEFUL_RESULT";
    }
    return "UNKNOWN";
}

bool ReadinessTargetFromName(const std::string& s, ReadinessTarget& out)
{
    if (s == "VERIFIED_FILES") {
        out = ReadinessTarget::VERIFIED_FILES;
        return true;
    }
    if (s == "RUNTIME_LOADED") {
        out = ReadinessTarget::RUNTIME_LOADED;
        return true;
    }
    if (s == "RUNTIME_READY") {
        out = ReadinessTarget::RUNTIME_READY;
        return true;
    }
    if (s == "FIRST_USEFUL_RESULT") {
        out = ReadinessTarget::FIRST_USEFUL_RESULT;
        return true;
    }
    return false;
}

const char* LeaseLifeName(LeaseLife s)
{
    switch (s) {
    case LeaseLife::RESERVED: return "RESERVED";
    case LeaseLife::ALLOCATED: return "ALLOCATED";
    case LeaseLife::POPULATING: return "POPULATING";
    case LeaseLife::VERIFIED: return "VERIFIED";
    case LeaseLife::ACTIVE: return "ACTIVE";
    case LeaseLife::RETIRING: return "RETIRING";
    case LeaseLife::QUIESCENT: return "QUIESCENT";
    case LeaseLife::RELEASED: return "RELEASED";
    case LeaseLife::QUARANTINED: return "QUARANTINED";
    }
    return "UNKNOWN";
}

const char* PhysicalDispositionName(PhysicalDisposition d)
{
    switch (d) {
    case PhysicalDisposition::NOT_DISPATCHED: return "NOT_DISPATCHED";
    case PhysicalDisposition::STOPPED_QUIESCENT: return "STOPPED_QUIESCENT";
    case PhysicalDisposition::STILL_IN_FLIGHT: return "STILL_IN_FLIGHT";
    case PhysicalDisposition::UNKNOWN: return "UNKNOWN";
    }
    return "UNKNOWN";
}

const char* LoadStrategyResultName(LoadStrategyResult r)
{
    switch (r) {
    case LoadStrategyResult::CLEAN_MISS: return "CLEAN_MISS";
    case LoadStrategyResult::FAILED_UNMUTATED: return "FAILED_UNMUTATED";
    case LoadStrategyResult::FAILED_MUTATED: return "FAILED_MUTATED";
    case LoadStrategyResult::READY: return "READY";
    }
    return "UNKNOWN";
}

const char* TransportAssuranceName(TransportAssurance t)
{
    switch (t) {
    case TransportAssurance::NATIVE_PQ1: return "NATIVE_PQ1";
    case TransportAssurance::TRUSTED_FABRIC: return "TRUSTED_FABRIC";
    case TransportAssurance::VERIFIED_EXTERNAL: return "VERIFIED_EXTERNAL";
    case TransportAssurance::HOST_BUFFER: return "HOST_BUFFER";
    }
    return "UNKNOWN";
}

const char* PlacementTierName(PlacementTier t)
{
    switch (t) {
    case PlacementTier::LOCAL_FILE: return "LOCAL_FILE";
    case PlacementTier::PAGE_CACHE: return "PAGE_CACHE";
    case PlacementTier::HOST_PAGEABLE: return "HOST_PAGEABLE";
    case PlacementTier::HOST_PINNED: return "HOST_PINNED";
    case PlacementTier::DEVICE: return "DEVICE";
    case PlacementTier::CXL_NUMA: return "CXL_NUMA";
    case PlacementTier::PEER_HOST: return "PEER_HOST";
    case PlacementTier::PEER_DEVICE: return "PEER_DEVICE";
    case PlacementTier::UNKNOWN_TIER: return "UNKNOWN";
    }
    return "UNKNOWN";
}

std::string GenerationHex(const Generation16& g)
{
    return HexStr(Span<const unsigned char>{g.data(), g.size()});
}

bool GenerationFromHex(const std::string& hex, Generation16& out, std::string& err)
{
    if (hex.size() != 32 || !IsHex(hex)) {
        err = "generation";
        return false;
    }
    const auto raw = ParseHex(hex);
    if (raw.size() != 16) {
        err = "generation";
        return false;
    }
    std::copy(raw.begin(), raw.end(), out.begin());
    return true;
}

Generation16 NewGeneration()
{
    Generation16 g{};
    GetRandBytes(Span<unsigned char>{g.data(), g.size()});
    return g;
}

bool CapabilityObjectId(const std::string& domain, Span<const unsigned char> body, Digest48& out, std::string& err)
{
    out = {};
    if (domain.empty() || domain.size() > 255) {
        err = "domain";
        return false;
    }
    std::vector<unsigned char> pre;
    pre.insert(pre.end(), domain.begin(), domain.end());
    pre.push_back(0x00);
    unsigned char lenle[8];
    WriteLE64(lenle, static_cast<uint64_t>(body.size()));
    pre.insert(pre.end(), lenle, lenle + 8);
    pre.insert(pre.end(), body.begin(), body.end());
    CSHA384 hasher;
    hasher.Write(pre.data(), pre.size());
    hasher.Finalize(out.data.data());
    return true;
}

bool CapabilityObjectIdJson(const std::string& domain, const UniValue& obj, Digest48& out, std::string& err)
{
    UniValue body(UniValue::VOBJ);
    if (obj.isObject()) {
        static const char* skip[] = {"recipe_id", "lock_id", "plan_digest48", "map_id", "representation_id"};
        for (const auto& k : obj.getKeys()) {
            bool drop = false;
            for (const char* s : skip) {
                if (k == s) {
                    drop = true;
                    break;
                }
            }
            if (!drop) body.pushKV(k, obj[k]);
        }
    } else {
        body = obj;
    }
    std::vector<unsigned char> c;
    if (!EncodePjson1(body, c, err)) return false;
    return CapabilityObjectId(domain, Span<const unsigned char>{c.data(), c.size()}, out, err);
}

} // namespace modelnet
