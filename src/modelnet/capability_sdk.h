// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Owner-local typed SDK for BTX-SPEC-0348-CAPABILITY-01 (spec 21.1–21.3).
// Wraps DispatchCapabilityRpc. Never public HTTP. automatic_spend_atoms stays 0.
// A readiness handle is lease_id + generation, never a naked filesystem path.

#ifndef BITCOIN_MODELNET_CAPABILITY_SDK_H
#define BITCOIN_MODELNET_CAPABILITY_SDK_H

#include <modelnet/capability.h>
#include <univalue.h>

#include <string>
#include <vector>

namespace modelnet {

struct CapabilityError {
    std::string code;
    std::string stage;
    std::string message;
    bool retryable{false};
};

/** Leased capability reference. Never a garbage-collectable filesystem path. */
struct ReadinessHandle {
    std::string lease_id;
    std::string generation;
    bool IsReadyReference() const { return !lease_id.empty() && !generation.empty(); }
};

inline constexpr const char* kErrNoEligibleRecipe = "NO_ELIGIBLE_RECIPE";
inline constexpr const char* kErrUnsupportedRuntimeProfile = "UNSUPPORTED_RUNTIME_PROFILE";
inline constexpr const char* kErrMemoryReservationFailed = "MEMORY_RESERVATION_FAILED";
inline constexpr const char* kErrUnverifiedRange = "UNVERIFIED_RANGE";
inline constexpr const char* kErrStaleGeneration = "STALE_GENERATION";
inline constexpr const char* kErrDeadlineUnachievable = "DEADLINE_UNACHIEVABLE";
inline constexpr const char* kErrRepresentationMismatch = "REPRESENTATION_MISMATCH";
inline constexpr const char* kErrSoftwareTrustRequired = "SOFTWARE_TRUST_REQUIRED";
inline constexpr const char* kErrFabricPolicyRequired = "FABRIC_POLICY_REQUIRED";
inline constexpr const char* kErrTransferStillInFlight = "TRANSFER_STILL_IN_FLIGHT";
inline constexpr const char* kErrExpertUnavailable = "EXPERT_UNAVAILABLE";
inline constexpr const char* kErrPrefixIncompatible = "PREFIX_INCOMPATIBLE";
inline constexpr const char* kErrHelperDown = "HELPER_DOWN";

bool CapabilityErrorRetryable(const std::string& code);
CapabilityError MakeCapabilityError(const std::string& code, const std::string& message, const std::string& method);
void ForceZeroSpend(UniValue& o);
bool RejectNonzeroSpend(const UniValue& o, CapabilityError& err);
bool JsonContainsWalletPath(const UniValue& v);
ReadinessHandle ReadinessFromResult(const UniValue& result);

/** Spec 21.2 primary verbs. Help is generated from IsCapabilityHelperMethod, not invented names. */
std::vector<std::string> CapabilityCliPrimaryCommands();
std::vector<std::string> RegisteredCapabilityMethods();
std::string MapCapabilityCliVerb(const std::string& verb);
std::string CapabilityCliUsage();

class CapabilityClient {
    ModelCatalog* m_cat{nullptr};
    std::string m_socket;

    CapabilityClient() = default;

public:
    explicit CapabilityClient(ModelCatalog& cat);
    static CapabilityClient UnixSocket(std::string socket_path);

    bool Call(const std::string& method, const UniValue& params, UniValue& result, CapabilityError& err);

    bool Plan(const UniValue& recipe, const UniValue& grant, UniValue& result, CapabilityError& err);
    bool Ensure(const std::string& plan_id, const UniValue& grant, ReadinessHandle& handle, UniValue& result,
                CapabilityError& err);
    bool Get(const std::string& job_or_lease, UniValue& result, CapabilityError& err);
    bool Cancel(const std::string& job_id, UniValue& result, CapabilityError& err);
    bool Release(const std::string& lease_id, UniValue& result, CapabilityError& err);
    bool Prefetch(const UniValue& hint, UniValue& result, CapabilityError& err);
    bool Sleep(const std::string& lease_id, UniValue& result, CapabilityError& err);
    bool Wake(const std::string& lease_id, UniValue& result, CapabilityError& err);
    bool Events(UniValue& result, CapabilityError& err);
    bool Ttc(const std::string& job_id, UniValue& result, CapabilityError& err);
    bool Capabilities(UniValue& result, CapabilityError& err);
};

/** Owner-local unix JSON-RPC 1.0 newline (same framing as capabilityd). Never HTTP. */
bool CallCapabilityUnix(const std::string& socket_path, const std::string& method, const UniValue& params,
                        UniValue& result, CapabilityError& err);

int RunCapabilityCli(const std::vector<std::string>& args, std::string& out, std::string& err_out);

} // namespace modelnet

#endif // BITCOIN_MODELNET_CAPABILITY_SDK_H
