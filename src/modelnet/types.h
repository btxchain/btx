// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_TYPES_H
#define BITCOIN_MODELNET_TYPES_H

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** SHA-384 content identity. Distinct from uint256 / txid. */
struct Digest48 {
    std::array<unsigned char, 48> data{};

    static constexpr size_t SIZE = 48;

    bool IsNull() const;
    std::string Hex() const;
    static bool FromHex(const std::string& hex, Digest48& out, std::string& err);
};

bool operator==(const Digest48& a, const Digest48& b);
bool operator!=(const Digest48& a, const Digest48& b);
bool operator<(const Digest48& a, const Digest48& b);

/** SHA-256 release hashlock. Distinct from Digest48. */
struct Hash32 {
    std::array<unsigned char, 32> data{};
    static constexpr size_t SIZE = 32;
    bool IsNull() const;
    std::string Hex() const;
    static bool FromHex(const std::string& hex, Hash32& out, std::string& err);
};

bool operator==(const Hash32& a, const Hash32& b);

/** Consensus / chain genesis binding for model records (32-byte network id). */
struct NetworkId {
    std::array<unsigned char, 32> data{};
    std::string Hex() const;
    static bool FromHex(const std::string& hex, NetworkId& out, std::string& err);
};

bool operator==(const NetworkId& a, const NetworkId& b);

enum class ResourceKind : uint8_t {
    MODEL = 0,
    ARTIFACT = 1,
    COLLECTION = 2,
    IDENTITY = 3,
    RELEASE = 4,
    POLICY_BUNDLE = 5,
    CIRCLE = 6,
    ALIAS = 7,
    PROVIDER = 8,
    BOUNTY = 9,
    BOUNTY_TERMS = 10,
    FUNDING_ROUND = 11,
    SUBMISSION = 12,
    EVALUATION = 13,
    AWARD = 14,
};

constexpr uint8_t RESOURCE_VERSION = 1;
constexpr uint16_t EXT_VERSION_V11 = 257; // 0x0101
constexpr int64_t MAX_MONEY_ATOMS = 21000000LL * 100000000LL;
constexpr int64_t DAY_SECONDS = 86400;
constexpr uint64_t MIB = uint64_t{1} << 20;
constexpr uint64_t GIB = uint64_t{1} << 30;
constexpr size_t PIECE_SIZE = 4U << 20;
constexpr size_t MAX_URI_INPUT = 512;

const char* ResourceKindName(ResourceKind kind);
bool ResourceKindFromInt(int kind, ResourceKind& out);

enum class AdmissionLevel : uint8_t {
    DISCOVERED = 0,
    MANIFEST_CHECKED = 1,
    OPERATOR_APPROVED = 2,
    FETCHING = 3,
    BYTES_VERIFIED = 4,
    STRUCTURE_VERIFIED = 5,
    PROFILE_VERIFIED = 6,
    RUNTIME_OBSERVED = 7,
    PINNED = 8,
    SEEDING = 9,
    EVICTABLE = 10,
    ENCRYPTED_UNQUALIFIED = 11,
    FAILED = 12,
    NOT_RUN_RESOURCE_LIMIT = 13,
};

const char* AdmissionLevelName(AdmissionLevel level);

enum class RetrievalMode : uint8_t {
    FREE_ONLY = 0,
    FREE_FIRST_APPROVAL = 1,
    FREE_FIRST_BUDGET = 2,
    EXPLICIT_PAID = 3,
};

const char* RetrievalModeName(RetrievalMode mode);
bool RetrievalModeFromName(const std::string& name, RetrievalMode& out);

enum class PlanChoice : uint8_t {
    FREE = 0,
    WAIT_FREE = 1,
    PAID = 2,
    APPROVAL_REQUIRED = 3,
};

const char* PlanChoiceName(PlanChoice choice);

enum class AclDecision : uint8_t {
    REJECT_CRYPTO = 0,
    RETRY_RESOURCE = 1,
    DENY_LOCAL = 2,
    QUARANTINE = 3,
    DENY_SUBSCRIBED = 4,
    REQUIRE_SPEND_APPROVAL = 5,
    ALLOW = 6,
};

const char* AclDecisionName(AclDecision d);

enum class PolicyAction : uint8_t {
    CONNECT = 1,
    DISCOVER = 2,
    RETRIEVE = 3,
    SERVE = 4,
    TRUST_METADATA = 5,
    AUTO_SEED = 6,
    AUTO_PAY = 7,
};

enum class TrustLabel : uint8_t {
    NEW = 0,
    OBSERVED = 1,
    RECIPROCAL = 2,
    RELIABLE = 3,
    PREFERRED = 4,
    TRUSTED = 5,
    BLOCKED = 6,
};

const char* TrustLabelName(TrustLabel label);

enum class FileRole : uint8_t {
    WEIGHTS = 1,
    CONFIG = 2,
    TOKENIZER = 3,
    LICENSE = 4,
    MODEL_CARD = 5,
};

bool FileRoleFromName(const std::string& name, FileRole& out);
const char* FileRoleName(FileRole role);

} // namespace modelnet

#endif // BITCOIN_MODELNET_TYPES_H
