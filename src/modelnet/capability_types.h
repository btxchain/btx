// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_CAPABILITY_TYPES_H
#define BITCOIN_MODELNET_CAPABILITY_TYPES_H

#include <modelnet/types.h>
#include <span.h>
#include <univalue.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

inline constexpr const char* PACKAGE_CORE_V3_DOMAIN = "BTX/PackageCore/v3";
inline constexpr const char* CAPABILITY_HANDOFF_V1 = "CAPABILITY_HANDOFF_V1";
inline constexpr const char* BTXPKG_CORE_V3 = "BTXPKG_CORE_V3";
inline constexpr const char* RECIPE_DOMAIN = "BTX/CapabilityRecipe/v1";
inline constexpr const char* LOCK_DOMAIN = "BTX/CapabilityLock/v1";
inline constexpr const char* PLAN_DOMAIN = "BTX/CapabilityPlan/v1";
inline constexpr const char* TENSOR_MAP_DOMAIN = "BTX/TensorRangeMap/v1";
inline constexpr const char* REPRESENTATION_DOMAIN = "BTX/RuntimeRepresentation/v1";
inline constexpr const char* RUNTIME_ADAPTER_ABI = "btx-runtime/1";

inline constexpr size_t CAPABILITY_RESOURCE_MAX = 256;
inline constexpr int CAPABILITY_DEPTH_MAX = 16;
inline constexpr size_t CAPABILITY_CANDIDATE_MAX = 64;
inline constexpr size_t TENSOR_MAP_ENTRY_MAX = 1000000;
inline constexpr uint64_t TENSOR_MAP_BYTES_MAX = 256ull << 20;
inline constexpr int PREFETCH_JOB_MAX = 2;
inline constexpr int PREFETCH_BUDGET_PERCENT = 10;

using Generation16 = std::array<unsigned char, 16>;

enum class RecipeKind : uint8_t {
    FULL_MODEL = 0,
    BASE_WITH_ADAPTERS = 1,
    PIPELINE = 2,
    EXPERT_RESIDENT_MODEL = 3,
};

enum class ReadinessTarget : uint8_t {
    VERIFIED_FILES = 0,
    RUNTIME_LOADED = 1,
    RUNTIME_READY = 2,
    FIRST_USEFUL_RESULT = 3,
};

enum class ReadinessContract : uint8_t {
    FULL_REQUIRED_SET = 0,
    VERIFIED_DEMAND_PAGING = 1,
    PARTITIONED_VALIDATED = 2,
};

enum class LeaseClass : uint8_t {
    LOAD = 0,
    EXECUTE = 1,
    TRANSFER = 2,
    PREFETCH = 3,
    COMPILE = 4,
    PRIVATE_STATE = 5,
};

enum class LeaseLife : uint8_t {
    RESERVED = 0,
    ALLOCATED = 1,
    POPULATING = 2,
    VERIFIED = 3,
    ACTIVE = 4,
    RETIRING = 5,
    QUIESCENT = 6,
    RELEASED = 7,
    QUARANTINED = 8,
};

enum class PhysicalDisposition : uint8_t {
    NOT_DISPATCHED = 0,
    STOPPED_QUIESCENT = 1,
    STILL_IN_FLIGHT = 2,
    UNKNOWN = 3,
};

enum class LoadStrategyResult : uint8_t {
    CLEAN_MISS = 0,
    FAILED_UNMUTATED = 1,
    FAILED_MUTATED = 2,
    READY = 3,
};

enum class TransportAssurance : uint8_t {
    NATIVE_PQ1 = 0,
    TRUSTED_FABRIC = 1,
    VERIFIED_EXTERNAL = 2,
    HOST_BUFFER = 3,
};

enum class PlacementTier : uint8_t {
    LOCAL_FILE = 0,
    PAGE_CACHE = 1,
    HOST_PAGEABLE = 2,
    HOST_PINNED = 3,
    DEVICE = 4,
    CXL_NUMA = 5,
    PEER_HOST = 6,
    PEER_DEVICE = 7,
    UNKNOWN_TIER = 8,
};

enum class TrustDomain : uint8_t {
    PUBLIC_MODEL = 0,
    LOCAL_USER = 1,
    ORGANIZATION = 2,
    RUNTIME_PROCESS = 3,
};

const char* RecipeKindName(RecipeKind k);
bool RecipeKindFromName(const std::string& s, RecipeKind& out);
const char* ReadinessTargetName(ReadinessTarget t);
bool ReadinessTargetFromName(const std::string& s, ReadinessTarget& out);
const char* LeaseLifeName(LeaseLife s);
const char* PhysicalDispositionName(PhysicalDisposition d);
const char* LoadStrategyResultName(LoadStrategyResult r);
const char* TransportAssuranceName(TransportAssurance t);
const char* PlacementTierName(PlacementTier t);

std::string GenerationHex(const Generation16& g);
bool GenerationFromHex(const std::string& hex, Generation16& out, std::string& err);
Generation16 NewGeneration();

/** Spec B.1: SHA384(UTF8(domain) || 0x00 || LE64(len) || body). */
bool CapabilityObjectId(const std::string& domain, Span<const unsigned char> body, Digest48& out, std::string& err);
bool CapabilityObjectIdJson(const std::string& domain, const UniValue& obj, Digest48& out, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_CAPABILITY_TYPES_H
