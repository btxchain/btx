// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/types.h>

#include <util/strencodings.h>

#include <algorithm>
#include <cstring>

namespace modelnet {

bool Digest48::IsNull() const
{
    return std::all_of(data.begin(), data.end(), [](unsigned char c) { return c == 0; });
}

std::string Digest48::Hex() const
{
    return HexStr(data);
}

bool Digest48::FromHex(const std::string& hex, Digest48& out, std::string& err)
{
    if (hex.size() != 96) {
        err = "digest48 must be 96 lowercase hex characters";
        return false;
    }
    for (char c : hex) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            err = "digest48 must be lowercase hex";
            return false;
        }
    }
    const auto raw = TryParseHex<unsigned char>(hex);
    if (!raw || raw->size() != SIZE) {
        err = "digest48 hex parse failed";
        return false;
    }
    std::copy(raw->begin(), raw->end(), out.data.begin());
    return true;
}

bool operator==(const Digest48& a, const Digest48& b)
{
    return a.data == b.data;
}
bool operator!=(const Digest48& a, const Digest48& b)
{
    return !(a == b);
}
bool operator<(const Digest48& a, const Digest48& b)
{
    return a.data < b.data;
}

bool Hash32::IsNull() const
{
    return std::all_of(data.begin(), data.end(), [](unsigned char c) { return c == 0; });
}

std::string Hash32::Hex() const
{
    return HexStr(data);
}

bool Hash32::FromHex(const std::string& hex, Hash32& out, std::string& err)
{
    if (hex.size() != 64) {
        err = "hash32 must be 64 lowercase hex characters";
        return false;
    }
    for (char c : hex) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            err = "hash32 must be lowercase hex";
            return false;
        }
    }
    const auto raw = TryParseHex<unsigned char>(hex);
    if (!raw || raw->size() != SIZE) {
        err = "hash32 hex parse failed";
        return false;
    }
    std::copy(raw->begin(), raw->end(), out.data.begin());
    return true;
}

bool operator==(const Hash32& a, const Hash32& b)
{
    return a.data == b.data;
}

std::string NetworkId::Hex() const
{
    return HexStr(data);
}

bool NetworkId::FromHex(const std::string& hex, NetworkId& out, std::string& err)
{
    if (hex.size() != 64) {
        err = "network id must be 64 lowercase hex characters";
        return false;
    }
    for (char c : hex) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            err = "network id must be lowercase hex";
            return false;
        }
    }
    const auto raw = TryParseHex<unsigned char>(hex);
    if (!raw || raw->size() != 32) {
        err = "network id hex parse failed";
        return false;
    }
    std::copy(raw->begin(), raw->end(), out.data.begin());
    return true;
}

bool operator==(const NetworkId& a, const NetworkId& b)
{
    return a.data == b.data;
}

const char* ResourceKindName(ResourceKind kind)
{
    switch (kind) {
    case ResourceKind::MODEL: return "MODEL";
    case ResourceKind::ARTIFACT: return "ARTIFACT";
    case ResourceKind::COLLECTION: return "COLLECTION";
    case ResourceKind::IDENTITY: return "IDENTITY";
    case ResourceKind::RELEASE: return "RELEASE";
    case ResourceKind::POLICY_BUNDLE: return "POLICY_BUNDLE";
    case ResourceKind::CIRCLE: return "CIRCLE";
    case ResourceKind::ALIAS: return "ALIAS";
    case ResourceKind::PROVIDER: return "PROVIDER";
    case ResourceKind::BOUNTY: return "BOUNTY";
    case ResourceKind::BOUNTY_TERMS: return "BOUNTY_TERMS";
    case ResourceKind::FUNDING_ROUND: return "FUNDING_ROUND";
    case ResourceKind::SUBMISSION: return "SUBMISSION";
    case ResourceKind::EVALUATION: return "EVALUATION";
    case ResourceKind::AWARD: return "AWARD";
    }
    return "UNKNOWN";
}

bool ResourceKindFromInt(int kind, ResourceKind& out)
{
    if (kind < 0 || kind > 14) return false;
    out = static_cast<ResourceKind>(kind);
    return true;
}

const char* AdmissionLevelName(AdmissionLevel level)
{
    switch (level) {
    case AdmissionLevel::DISCOVERED: return "DISCOVERED";
    case AdmissionLevel::MANIFEST_CHECKED: return "MANIFEST_CHECKED";
    case AdmissionLevel::OPERATOR_APPROVED: return "OPERATOR_APPROVED";
    case AdmissionLevel::FETCHING: return "FETCHING";
    case AdmissionLevel::BYTES_VERIFIED: return "BYTES_VERIFIED";
    case AdmissionLevel::STRUCTURE_VERIFIED: return "STRUCTURE_VERIFIED";
    case AdmissionLevel::PROFILE_VERIFIED: return "PROFILE_VERIFIED";
    case AdmissionLevel::RUNTIME_OBSERVED: return "RUNTIME_OBSERVED";
    case AdmissionLevel::PINNED: return "PINNED";
    case AdmissionLevel::SEEDING: return "SEEDING";
    case AdmissionLevel::EVICTABLE: return "EVICTABLE";
    case AdmissionLevel::ENCRYPTED_UNQUALIFIED: return "ENCRYPTED_UNQUALIFIED";
    case AdmissionLevel::FAILED: return "FAILED";
    case AdmissionLevel::NOT_RUN_RESOURCE_LIMIT: return "NOT_RUN_RESOURCE_LIMIT";
    }
    return "UNKNOWN";
}

const char* RetrievalModeName(RetrievalMode mode)
{
    switch (mode) {
    case RetrievalMode::FREE_ONLY: return "FREE_ONLY";
    case RetrievalMode::FREE_FIRST_APPROVAL: return "FREE_FIRST_APPROVAL";
    case RetrievalMode::FREE_FIRST_BUDGET: return "FREE_FIRST_BUDGET";
    case RetrievalMode::EXPLICIT_PAID: return "EXPLICIT_PAID";
    }
    return "UNKNOWN";
}

bool RetrievalModeFromName(const std::string& name, RetrievalMode& out)
{
    if (name == "FREE_ONLY") { out = RetrievalMode::FREE_ONLY; return true; }
    if (name == "FREE_FIRST_APPROVAL") { out = RetrievalMode::FREE_FIRST_APPROVAL; return true; }
    if (name == "FREE_FIRST_BUDGET") { out = RetrievalMode::FREE_FIRST_BUDGET; return true; }
    if (name == "EXPLICIT_PAID") { out = RetrievalMode::EXPLICIT_PAID; return true; }
    return false;
}

const char* PlanChoiceName(PlanChoice choice)
{
    switch (choice) {
    case PlanChoice::FREE: return "FREE";
    case PlanChoice::WAIT_FREE: return "WAIT_FREE";
    case PlanChoice::PAID: return "PAID";
    case PlanChoice::APPROVAL_REQUIRED: return "APPROVAL_REQUIRED";
    }
    return "UNKNOWN";
}

const char* AclDecisionName(AclDecision d)
{
    switch (d) {
    case AclDecision::REJECT_CRYPTO: return "REJECT_CRYPTO";
    case AclDecision::RETRY_RESOURCE: return "RETRY_RESOURCE";
    case AclDecision::DENY_LOCAL: return "DENY_LOCAL";
    case AclDecision::QUARANTINE: return "QUARANTINE";
    case AclDecision::DENY_SUBSCRIBED: return "DENY_SUBSCRIBED";
    case AclDecision::REQUIRE_SPEND_APPROVAL: return "REQUIRE_SPEND_APPROVAL";
    case AclDecision::ALLOW: return "ALLOW";
    }
    return "UNKNOWN";
}

const char* TrustLabelName(TrustLabel label)
{
    switch (label) {
    case TrustLabel::NEW: return "New";
    case TrustLabel::OBSERVED: return "Observed";
    case TrustLabel::RECIPROCAL: return "Reciprocal";
    case TrustLabel::RELIABLE: return "Reliable";
    case TrustLabel::PREFERRED: return "Preferred";
    case TrustLabel::TRUSTED: return "Trusted";
    case TrustLabel::BLOCKED: return "Blocked";
    }
    return "Unknown";
}

const char* FileRoleName(FileRole role)
{
    switch (role) {
    case FileRole::WEIGHTS: return "WEIGHTS";
    case FileRole::CONFIG: return "CONFIG";
    case FileRole::TOKENIZER: return "TOKENIZER";
    case FileRole::LICENSE: return "LICENSE";
    case FileRole::MODEL_CARD: return "MODEL_CARD";
    }
    return "UNKNOWN";
}

bool FileRoleFromName(const std::string& name, FileRole& out)
{
    if (name == "WEIGHTS") { out = FileRole::WEIGHTS; return true; }
    if (name == "CONFIG") { out = FileRole::CONFIG; return true; }
    if (name == "TOKENIZER") { out = FileRole::TOKENIZER; return true; }
    if (name == "LICENSE") { out = FileRole::LICENSE; return true; }
    if (name == "MODEL_CARD") { out = FileRole::MODEL_CARD; return true; }
    return false;
}

} // namespace modelnet
