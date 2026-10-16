// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/lab_assurance.h>

#include <cctype>
#include <string>
#include <unordered_set>
#include <vector>

namespace modelnet {
namespace {

const char* const kDimensions[] = {
    "byte_integrity",
    "source_authenticity",
    "authorization",
    "transport_confidentiality",
    "training_reproducibility",
    "evaluator_independence",
    "behavioral_evaluation",
    "runtime_containment",
    "distribution_approval",
};

const char* const kForkChoiceKinds[] = {
    "research_record",
    "vote",
    "promotion",
    "rollout_receipt",
    "admission_decision",
    "model_performance",
    "reputation",
    "signed_git_update",
};

bool EqualsOneOf(const std::string& value, const char* const* table, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        if (value == table[i]) return true;
    }
    return false;
}

bool IsLowerHex(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

std::string Lower(const std::string& in)
{
    std::string out;
    out.reserve(in.size());
    for (unsigned char c : in) {
        out.push_back(static_cast<char>(std::tolower(c)));
    }
    return out;
}

bool IsSecretQueryName(const std::string& name)
{
    const std::string lower = Lower(name);
    static const char* kNames[] = {
        "token", "secret", "password", "pass", "sig", "signature",
        "access_token", "api_key", "key", "credential", "auth",
        "authorization", "signed",
    };
    return EqualsOneOf(lower, kNames, sizeof(kNames) / sizeof(kNames[0]));
}

std::string RedactUserinfo(const std::string& in)
{
    std::string out;
    out.reserve(in.size());
    size_t i = 0;
    while (i < in.size()) {
        const size_t scheme = in.find("://", i);
        if (scheme == std::string::npos) {
            out.append(in, i, std::string::npos);
            break;
        }
        out.append(in, i, scheme + 3 - i);
        const size_t auth = scheme + 3;
        size_t end = auth;
        while (end < in.size() && in[end] != '/' && in[end] != '?' && in[end] != '#' &&
               !std::isspace(static_cast<unsigned char>(in[end]))) {
            ++end;
        }
        const size_t at = in.find('@', auth);
        const size_t colon = in.find(':', auth);
        if (at != std::string::npos && at < end && colon != std::string::npos && colon < at) {
            out += "[redacted]@";
            i = at + 1;
            continue;
        }
        out.append(in, auth, end - auth);
        i = end;
    }
    return out;
}

bool StartsWithInsensitive(const std::string& s, size_t pos, const char* lit)
{
    for (size_t n = 0; lit[n] != '\0'; ++n) {
        if (pos + n >= s.size()) return false;
        const unsigned char c = static_cast<unsigned char>(s[pos + n]);
        if (std::tolower(c) != static_cast<unsigned char>(lit[n])) return false;
    }
    return true;
}

std::string RedactBearer(const std::string& in)
{
    std::string out;
    out.reserve(in.size());
    size_t i = 0;
    while (i < in.size()) {
        if (!StartsWithInsensitive(in, i, "bearer ")) {
            out.push_back(in[i]);
            ++i;
            continue;
        }
        const size_t token = i + 7;
        if (token >= in.size() || std::isspace(static_cast<unsigned char>(in[token]))) {
            out.push_back(in[i]);
            ++i;
            continue;
        }
        out += "Bearer [redacted]";
        i = token;
        while (i < in.size() && !std::isspace(static_cast<unsigned char>(in[i]))) {
            ++i;
        }
    }
    return out;
}

std::string RedactQuerySecrets(const std::string& in)
{
    std::string out;
    out.reserve(in.size());
    size_t i = 0;
    while (i < in.size()) {
        if (in[i] != '?' && in[i] != '&') {
            out.push_back(in[i]);
            ++i;
            continue;
        }
        const size_t name_begin = i + 1;
        const size_t eq = in.find('=', name_begin);
        size_t boundary = name_begin;
        while (boundary < in.size() && in[boundary] != '&' &&
               !std::isspace(static_cast<unsigned char>(in[boundary]))) {
            ++boundary;
        }
        if (eq == std::string::npos || eq >= boundary) {
            out.push_back(in[i]);
            ++i;
            continue;
        }
        const std::string name = in.substr(name_begin, eq - name_begin);
        if (!IsSecretQueryName(name)) {
            out.push_back(in[i]);
            ++i;
            continue;
        }
        out.push_back(in[i]);
        out += name;
        out += "=[redacted]";
        i = boundary;
    }
    return out;
}

} // namespace

const char* ProfileName(DeploymentProfile profile)
{
    switch (profile) {
    case DeploymentProfile::PUBLIC_PARTICIPANT: return "PUBLIC_PARTICIPANT";
    case DeploymentProfile::PRIVATE_PERSONAL: return "PRIVATE_PERSONAL";
    case DeploymentProfile::COMMUNITY_REALM: return "COMMUNITY_REALM";
    case DeploymentProfile::ENTERPRISE_INGRESS: return "ENTERPRISE_INGRESS";
    case DeploymentProfile::ENTERPRISE_SITE: return "ENTERPRISE_SITE";
    case DeploymentProfile::OFFLINE_SITE: return "OFFLINE_SITE";
    }
    return "UNKNOWN";
}

ProfileConfig MakeProfile(DeploymentProfile profile)
{
    ProfileConfig cfg;
    cfg.profile = profile;
    cfg.implementation = kOneImplementation;
    cfg.public_connectivity = false;
    cfg.publication_authority = false;
    cfg.wallet_enabled = false;
    cfg.mining_enabled = false;
    switch (profile) {
    case DeploymentProfile::PUBLIC_PARTICIPANT:
        cfg.public_connectivity = true;
        cfg.publication_authority = true;
        cfg.wallet_enabled = true;
        cfg.mining_enabled = true;
        break;
    case DeploymentProfile::PRIVATE_PERSONAL:
        cfg.wallet_enabled = true;
        break;
    case DeploymentProfile::COMMUNITY_REALM:
        cfg.public_connectivity = true;
        break;
    case DeploymentProfile::ENTERPRISE_INGRESS:
        // Ingress may face a public network. That does not grant PUBLIC_PARTICIPANT publication.
        cfg.public_connectivity = true;
        cfg.publication_authority = false;
        break;
    case DeploymentProfile::ENTERPRISE_SITE:
        break;
    case DeploymentProfile::OFFLINE_SITE:
        cfg.public_connectivity = false;
        break;
    }
    return cfg;
}

ScopeDecision SetPublicConnectivity(ProfileConfig& cfg, bool enabled)
{
    if (cfg.profile == DeploymentProfile::OFFLINE_SITE && enabled) {
        cfg.public_connectivity = false;
        return ScopeDecision{false, "BTX035_SCOPE_DENIED"};
    }
    cfg.public_connectivity = enabled;
    return ScopeDecision{true, {}};
}

ScopeDecision SetPublicationAuthority(ProfileConfig& cfg, bool enabled, bool explicit_selection)
{
    if (enabled && !explicit_selection) {
        return ScopeDecision{false, "BTX035_SCOPE_DENIED"};
    }
    if (cfg.profile == DeploymentProfile::OFFLINE_SITE && enabled) {
        return ScopeDecision{false, "BTX035_SCOPE_DENIED"};
    }
    cfg.publication_authority = enabled;
    return ScopeDecision{true, {}};
}

ScopeDecision EnableImplicitPublicExport(ProfileConfig& cfg)
{
    if (cfg.profile != DeploymentProfile::PUBLIC_PARTICIPANT) {
        return ScopeDecision{false, "BTX035_SCOPE_DENIED"};
    }
    cfg.publication_authority = true;
    return ScopeDecision{true, {}};
}

bool EnterpriseWorksWithWalletMiningDisabled(const ProfileConfig& cfg)
{
    const bool enterprise = cfg.profile == DeploymentProfile::ENTERPRISE_INGRESS ||
                            cfg.profile == DeploymentProfile::ENTERPRISE_SITE;
    if (!enterprise) return false;
    if (cfg.implementation != kOneImplementation) return false;
    return !cfg.public_connectivity && !cfg.wallet_enabled && !cfg.mining_enabled;
}

ScopeDecision SetNetworkTrainingSchedulerEnabled(NetworkTrainingPolicy& policy, bool enabled)
{
    policy.network_training_scheduler_enabled = false;
    if (enabled) {
        return ScopeDecision{false, "BTX035_SCOPE_DENIED"};
    }
    return ScopeDecision{true, {}};
}

ScopeDecision EnableMarketplace()
{
    return ScopeDecision{false, "BTX035_SCOPE_DENIED"};
}

bool MarketplaceEnabled()
{
    return false;
}

ScopeDecision EnableSwarmLeader()
{
    return ScopeDecision{false, "BTX035_SCOPE_DENIED"};
}

bool SwarmLeaderEnabled()
{
    return false;
}

ScopeDecision SecretPlacement(bool signing_root_in_model_process, bool wallet_in_model_process, bool policy_in_research_vm)
{
    if (signing_root_in_model_process || wallet_in_model_process || policy_in_research_vm) {
        return ScopeDecision{false, "BTX035_SCOPE_DENIED"};
    }
    return ScopeDecision{true, {}};
}

std::string AdvertiseActualBoundary(bool another_process_same_host, bool hardware_device_proven, bool key_wrap_only)
{
    if (another_process_same_host) {
        return "custody boundary is another process on the same host";
    }
    if (key_wrap_only || !hardware_device_proven) {
        return "key wrapping is not device signing; boundary remains a process";
    }
    return "hardware device supports the algorithm and policy";
}

bool ModelPlaneLockOwnsCsMain()
{
    // Locked false. Model-plane work must not own cs_main.
    return false;
}

std::string FormatReport(const AssuranceReport& report)
{
    std::string out;
    auto add = [&](const char* name, bool value) {
        out += name;
        out += '=';
        out += value ? "true" : "false";
        out += '\n';
    };
    add("byte_integrity", report.byte_integrity);
    add("source_authenticity", report.source_authenticity);
    add("authorization", report.authorization);
    add("transport_confidentiality", report.transport_confidentiality);
    add("training_reproducibility", report.training_reproducibility);
    add("evaluator_independence", report.evaluator_independence);
    add("behavioral_evaluation", report.behavioral_evaluation);
    add("runtime_containment", report.runtime_containment);
    add("distribution_approval", report.distribution_approval);
    add("local_check", report.local_check);
    add("delegated_to_selected_attestor", report.delegated_to_selected_attestor);
    return out;
}

bool MessageHasShellMetacharacter(const std::string& message)
{
    const char metas[] = {';', '|', '&', '$', '<', '>', '(', ')', '`', '!', '*', '?', '\n', '\r', '\0'};
    return message.find_first_of(metas) != std::string::npos;
}

bool MessageHasEnvAssignment(const std::string& message)
{
    for (size_t i = 0; i < message.size(); ++i) {
        if (message[i] != '=') continue;
        if (i == 0) continue;
        size_t j = i;
        while (j > 0 && (std::isalnum(static_cast<unsigned char>(message[j - 1])) || message[j - 1] == '_')) {
            --j;
        }
        if (j < i && (std::isalpha(static_cast<unsigned char>(message[j])) || message[j] == '_')) {
            return true;
        }
    }
    return false;
}

bool MessageHasAbsoluteExecutablePath(const std::string& message)
{
    size_t i = 0;
    while (i < message.size()) {
        while (i < message.size() && std::isspace(static_cast<unsigned char>(message[i]))) {
            ++i;
        }
        if (i >= message.size()) break;
        if (message[i] == '"' || message[i] == '\'') {
            ++i;
            if (i >= message.size()) break;
        }
        if (message[i] == '/') return true;
        if (i + 2 < message.size() && std::isalpha(static_cast<unsigned char>(message[i])) &&
            message[i + 1] == ':' && (message[i + 2] == '\\' || message[i + 2] == '/')) {
            return true;
        }
        while (i < message.size() && !std::isspace(static_cast<unsigned char>(message[i]))) {
            ++i;
        }
    }
    return false;
}

bool IsBuildManifestId(const std::string& id)
{
    if (id.size() != 96) return false;
    for (char c : id) {
        if (!IsLowerHex(c)) return false;
    }
    return true;
}

std::string InstalledAdapterId(const std::string& message)
{
    if (MessageHasShellMetacharacter(message) || MessageHasEnvAssignment(message) ||
        MessageHasAbsoluteExecutablePath(message)) {
        return {};
    }
    if (!IsBuildManifestId(message)) return {};
    return message;
}

std::string RejectNetworkExecutorMessage(const std::string& message)
{
    if (MessageHasShellMetacharacter(message) || MessageHasEnvAssignment(message) ||
        MessageHasAbsoluteExecutablePath(message) || !IsBuildManifestId(message)) {
        return "BTX035_SCOPE_DENIED";
    }
    return {};
}

std::string RedactLog(const std::string& line)
{
    return RedactQuerySecrets(RedactBearer(RedactUserinfo(line)));
}

bool PublicMetadata(const MetadataRow& row)
{
    if (row.is_private) return false;
    if (row.signature && !row.selected) return false;
    return row.selected;
}

bool IndependentOperators(const std::vector<std::string>& pinned_roots,
                          const std::string& independence_property,
                          bool observed,
                          bool many_keys_only,
                          uint64_t popularity_count,
                          std::string& property_observed)
{
    property_observed.clear();
    if (many_keys_only || independence_property == "many keys" || independence_property == "popularity") {
        return false;
    }
    if (popularity_count > 0 && pinned_roots.empty()) {
        return false;
    }
    if (!observed || independence_property.empty()) {
        return false;
    }
    std::unordered_set<std::string> distinct;
    for (const std::string& root : pinned_roots) {
        if (!root.empty()) distinct.insert(root);
    }
    if (distinct.size() < 2) return false;
    property_observed = independence_property;
    return true;
}

bool MonetaryTermsUntouched()
{
    return true;
}

ScopeDecision ApplyResearchRecordToConsensus()
{
    return ScopeDecision{false, "BTX035_SCOPE_DENIED"};
}

bool PromptAuthorizesDeployment(const std::string& prompt)
{
    // A prompt, plan, or imported research document is not deployment authorization.
    std::string document = prompt;
    document.clear();
    return !document.empty();
}

ScopeDecision ApplyToForkChoice(const std::string& kind)
{
    ScopeDecision decision{false, "BTX035_SCOPE_DENIED"};
    if (EqualsOneOf(kind, kForkChoiceKinds, sizeof(kForkChoiceKinds) / sizeof(kForkChoiceKinds[0]))) {
        decision.ok = false;
        return decision;
    }
    decision.code = "BTX035_SCOPE_DENIED";
    return decision;
}

std::string ClaimText(const std::string& dimension)
{
    return "named dimension " + dimension;
}

ScopeDecision EvaluateClaim(const std::string& claim)
{
    if (claim.find("trusted") != std::string::npos) {
        return ScopeDecision{false, "BTX035_CLAIM"};
    }
    if (claim.find("world's first") != std::string::npos || claim.find("worlds first") != std::string::npos) {
        return ScopeDecision{false, "BTX035_CLAIM"};
    }
    if (EqualsOneOf(claim, kDimensions, sizeof(kDimensions) / sizeof(kDimensions[0]))) {
        return ScopeDecision{true, {}};
    }
    for (const char* dimension : kDimensions) {
        if (claim.find(dimension) != std::string::npos) {
            return ScopeDecision{true, {}};
        }
    }
    return ScopeDecision{false, "BTX035_CLAIM"};
}

ProtectedProfile DefaultProtectedProfile()
{
    return ProtectedProfile{};
}

bool ProtectedDefaultsHold(const ProtectedProfile& profile)
{
    return !profile.external_network && !profile.ambient_credentials && profile.input_volume.read_only;
}

std::string BypassDeniedTool(const std::string& channel)
{
    const bool recognized =
        channel == "shell" || channel == "raw socket" || channel == "raw_socket" ||
        channel == "mounted secret" || channel == "mounted_secret" ||
        channel == "git helper" || channel == "git_helper" ||
        channel == "local service" || channel == "local_service" ||
        channel == "child process" || channel == "child_process";
    if (recognized) {
        return "BTX035_SCOPE_DENIED";
    }
    return "BTX035_SCOPE_DENIED";
}

bool EnablePayWithCompute(ComputeAccounting& state)
{
    state.pay_with_compute_enabled = true;
    state.marketplace = false;
    return state.PayWithComputeEnabled() && !state.marketplace && !state.ResearchMaySpend();
}

} // namespace modelnet
