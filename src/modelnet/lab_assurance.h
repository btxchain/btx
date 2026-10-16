// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_LAB_ASSURANCE_H
#define BITCOIN_MODELNET_LAB_ASSURANCE_H

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** Denial or acceptance. This is not a collapsed trust bit. */
struct ScopeDecision {
    bool ok{false};
    std::string code;
};

inline constexpr char kOneImplementation[] = "btx-035";

// ARCH-004. One implementation; profile is data. Connectivity and publication are separate fields.
enum class DeploymentProfile {
    PUBLIC_PARTICIPANT,
    PRIVATE_PERSONAL,
    COMMUNITY_REALM,
    ENTERPRISE_INGRESS,
    ENTERPRISE_SITE,
    OFFLINE_SITE,
};

struct ProfileConfig {
    DeploymentProfile profile{DeploymentProfile::PRIVATE_PERSONAL};
    bool public_connectivity{false};
    bool publication_authority{false};
    bool wallet_enabled{false};
    bool mining_enabled{false};
    std::string implementation{kOneImplementation};
};

const char* ProfileName(DeploymentProfile profile);
ProfileConfig MakeProfile(DeploymentProfile profile);
ScopeDecision SetPublicConnectivity(ProfileConfig& cfg, bool enabled);
/** Publication changes only when explicit_selection is true. Profiles do not imply it. */
ScopeDecision SetPublicationAuthority(ProfileConfig& cfg, bool enabled, bool explicit_selection);
/** Private and enterprise profiles cannot gain publication by implication. */
ScopeDecision EnableImplicitPublicExport(ProfileConfig& cfg);
/** Enterprise profiles remain valid with public networking, wallet, and mining disabled. */
bool EnterpriseWorksWithWalletMiningDisabled(const ProfileConfig& cfg);

// ARCH-002. The scheduler flag defaults false and cannot be turned on.
struct NetworkTrainingPolicy {
    bool network_training_scheduler_enabled{false};
};

ScopeDecision SetNetworkTrainingSchedulerEnabled(NetworkTrainingPolicy& policy, bool enabled);
ScopeDecision EnableMarketplace();
bool MarketplaceEnabled();
ScopeDecision EnableSwarmLeader();
bool SwarmLeaderEnabled();

// ARCH-001. Secrets stay out of the model process and the untrusted research VM.
ScopeDecision SecretPlacement(bool signing_root_in_model_process, bool wallet_in_model_process, bool policy_in_research_vm);
/**
 * Advertise the boundary the inputs actually describe.
 * Same-host process separation yields text that contains "process" and does not claim hardware isolation.
 * key_wrap_only is not hardware ML-DSA signing.
 */
std::string AdvertiseActualBoundary(bool another_process_same_host, bool hardware_device_proven, bool key_wrap_only);

/**
 * ARCH-003 lock: model-plane work does not own cs_main.
 * Hashing, fetch, Git parse, model checks, large writes, and child-process waits stay off this lock.
 * This function is required to stay false.
 */
bool ModelPlaneLockOwnsCsMain();

// SEC-001. Dimensions stay separate. CollapseToTrusted is intentionally not declared.
struct AssuranceReport {
    bool byte_integrity{false};
    bool source_authenticity{false};
    bool authorization{false};
    bool transport_confidentiality{false};
    bool training_reproducibility{false};
    bool evaluator_independence{false};
    bool behavioral_evaluation{false};
    bool runtime_containment{false};
    bool distribution_approval{false};
    /** Local check and a selected attestor are different facts. */
    bool local_check{false};
    bool delegated_to_selected_attestor{false};
};

std::string FormatReport(const AssuranceReport& report);

// SEC-002. A network message cannot choose the executor.
bool MessageHasShellMetacharacter(const std::string& message);
bool MessageHasEnvAssignment(const std::string& message);
bool MessageHasAbsoluteExecutablePath(const std::string& message);
bool IsBuildManifestId(const std::string& id);
/** Returns the id only when message is exactly that 96-hex manifest. Never a path. */
std::string InstalledAdapterId(const std::string& message);
/** Empty when message is only a 96-hex build manifest id. Otherwise BTX035_SCOPE_DENIED. */
std::string RejectNetworkExecutorMessage(const std::string& message);

// SEC-003. A signature is not disclosure. Public metadata requires selected=true.
struct MetadataRow {
    bool is_private{true};
    bool signature{false};
    bool selected{false};
};

std::string RedactLog(const std::string& line);
bool PublicMetadata(const MetadataRow& row);

// SEC-004. Many keys and popularity are not independence.
bool IndependentOperators(const std::vector<std::string>& pinned_roots,
                          const std::string& independence_property,
                          bool observed,
                          bool many_keys_only,
                          uint64_t popularity_count,
                          std::string& property_observed);

// CORE-002. Monetary terms stay in place. A research record is not consensus.
bool MonetaryTermsUntouched();
ScopeDecision ApplyResearchRecordToConsensus();
bool PromptAuthorizesDeployment(const std::string& prompt);

// CORE-003. One gate for every model-plane kind that must not move fork choice.
ScopeDecision ApplyToForkChoice(const std::string& kind);

// CORE-005. Claim text names the dimension. The bare word trusted is BTX035_CLAIM.
std::string ClaimText(const std::string& dimension);
ScopeDecision EvaluateClaim(const std::string& claim);

// RUN-002. Protected VM defaults, and denied tools cannot be bypassed.
struct InputVolume {
    bool read_only{true};
};

struct ProtectedProfile {
    bool external_network{false};
    bool ambient_credentials{false};
    InputVolume input_volume{};
};

ProtectedProfile DefaultProtectedProfile();
bool ProtectedDefaultsHold(const ProtectedProfile& profile);
std::string BypassDeniedTool(const std::string& channel);

// ECON-002. Pay With Compute is optional accounting. It is not a marketplace and it does not spend.
struct ComputeAccounting {
    bool pay_with_compute_enabled{false};
    bool marketplace{false};

    bool PayWithComputeEnabled() const { return pay_with_compute_enabled; }
    /** ResearchMaySpend equivalent. Research records do not spend. */
    bool ResearchMaySpend() const { return false; }
};

bool EnablePayWithCompute(ComputeAccounting& state);

} // namespace modelnet

#endif // BITCOIN_MODELNET_LAB_ASSURANCE_H
