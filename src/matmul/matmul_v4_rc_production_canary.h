// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_PRODUCTION_CANARY_H
#define BTX_MATMUL_MATMUL_V4_RC_PRODUCTION_CANARY_H

#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_rc.h>
#include <primitives/block.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace Consensus {
struct Params;
}

namespace matmul::v4::rc {

/** Public, non-secret runtime identity used to bind production qualification.
 *
 * Device serial numbers, PCI addresses, host names, and other operator-specific
 * identifiers are deliberately excluded. Architecture plus driver/runtime ABI
 * versions are sufficient to invalidate a canary when the executable device
 * stack changes without leaking private deployment information.
 */
struct RCProductionProviderIdentity {
    std::string provider_family;
    std::string device_architecture;
    std::string driver_identity;
    std::string runtime_identity;
    bool complete{false};
    std::string reason;
};

/** Consensus epoch identity covered by one production-shape golden. */
struct RCProductionEpochIdentity {
    int32_t activation_height{-1};
    uint32_t profile{0};
    uint32_t transcript_version{0};
    uint32_t matmul_dimension{0};
    RCEpisodeParams params{};
};

/** One independently reproduced, reviewable production-shape golden.
 *
 * Entries are exact: provider family, device architecture, runtime/driver,
 * activation height, transcript version, consensus MatMul dimension, and every
 * episode dimension must all match. A pending/null/unreviewed entry can never
 * authorize a provider.
 */
struct RCProductionGoldenManifestEntry {
    std::string id;
    RCProductionProviderIdentity provider{};
    RCProductionEpochIdentity epoch{};
    uint64_t header_nonce{0};
    uint256 expected_digest{};
    bool independently_reproduced{false};
    std::string public_provenance;
};

enum class RCProductionCanaryOutcome : uint8_t {
    NotRun = 0,
    Passed = 1,
    MissingGolden = 2,
    ProviderIdentityUnavailable = 3,
    ProviderNotPolicyEligible = 4,
    LocalAcceleratorFailure = 5,
    DigestMismatch = 6,
    UnsupportedEpoch = 7,
};

struct RCProductionCanaryStatus {
    RCProductionCanaryOutcome outcome{RCProductionCanaryOutcome::NotRun};
    bool manifest_has_reviewed_goldens{false};
    bool exact_manifest_match{false};
    bool attempted{false};
    bool passed{false};
    bool activation_ready{false};
    size_t manifest_entries{0};
    std::string manifest_entry_id;
    std::string provider;
    RCProductionProviderIdentity provider_identity{};
    RCProductionEpochIdentity epoch{};
    uint256 expected_digest{};
    uint256 observed_digest{};
    RCExactReplayAccelerationStats acceleration{};
    double wall_s{0.0};
    std::string reason;
};

/** Opaque proof that one exact provider/backend/epoch tuple completed the
 * reviewed production canary in this daemon process.
 *
 * A default-constructed value is deliberately unusable. The nonce and
 * generation are private and are checked against process-local canary state;
 * provider labels, configuration files, and callers cannot manufacture an
 * authorization claim. A fresh canary or Reset invalidates the old token. */
class RCProductionProviderCapability {
public:
    RCProductionProviderCapability() = default;
    [[nodiscard]] bool IsNull() const;

private:
    uint64_t m_process_nonce{0};
    uint64_t m_generation{0};

    friend struct RCProductionProviderCapabilityAccess;
};

/** Reviewed production goldens compiled into this source revision.
 *
 * The launch-candidate branch intentionally returns an empty manifest until
 * independent full-production CPU-oracle evidence has been reviewed and
 * committed. Keeping the registry empty is a fail-closed readiness state, not
 * a skipped test or an implied qualification claim.
 */
[[nodiscard]] const std::vector<RCProductionGoldenManifestEntry>&
CommittedRCProductionGoldenManifest();

[[nodiscard]] RCProductionProviderIdentity
ProbeRCProductionProviderIdentity(const std::string& resolved_provider);

[[nodiscard]] bool RCProductionProviderIdentityMatches(
    const RCProductionProviderIdentity& a,
    const RCProductionProviderIdentity& b);

[[nodiscard]] RCProductionEpochIdentity MakeRCProductionEpochIdentity(
    const Consensus::Params& consensus, int32_t activation_height);

[[nodiscard]] const RCProductionGoldenManifestEntry* FindRCProductionGolden(
    const RCProductionProviderIdentity& provider,
    const RCProductionEpochIdentity& epoch,
    const std::vector<RCProductionGoldenManifestEntry>& manifest);

/** Fixed, domain-separated, epoch-bound input header for production canaries. */
[[nodiscard]] CBlockHeader MakeRCProductionCanaryHeader(
    const RCProductionEpochIdentity& epoch, uint64_t nonce);

/** Pure final gate used by production and focused unit tests. */
[[nodiscard]] RCProductionCanaryOutcome EvaluateRCProductionCanaryResult(
    const RCProductionGoldenManifestEntry& golden,
    const RCStrictDeviceEpisodeResult& replay);

/** Run the strict, no-CPU-fallback startup canary for a configured RC epoch. */
[[nodiscard]] RCProductionCanaryStatus RunRCProductionStartupCanary(
    const std::string& resolved_provider,
    const matmul::v4::lt::ExactGemmBackend& backend,
    const Consensus::Params& consensus,
    int32_t activation_height);

/** Restricted negative-path seam for tests that need to prove the pre-fork or
 * epoch guards without running a real resolver. Only `test:` providers are
 * accepted and this path never issues a production capability. */
[[nodiscard]] RCProductionCanaryStatus RunRCProductionStartupCanaryForTest(
    const std::string& test_provider,
    const matmul::v4::lt::ExactGemmBackend& backend,
    const Consensus::Params& consensus,
    int32_t activation_height);

/** Return the current canary-issued capability for an exact tuple. */
[[nodiscard]] std::optional<RCProductionProviderCapability>
GetRCProductionProviderCapability(
    const std::string& provider,
    const matmul::v4::lt::ExactGemmBackend& backend,
    const Consensus::Params& consensus,
    int32_t height,
    std::string* reason = nullptr);

/** Revalidate a capability against current process canary state. Passing a
 * null backend validates the provider/epoch identity only, for consumers that
 * do not retain backend callbacks. */
[[nodiscard]] bool RCProductionProviderCapabilityAuthorizes(
    const RCProductionProviderCapability& capability,
    const std::string& provider,
    const matmul::v4::lt::ExactGemmBackend* backend,
    const Consensus::Params& consensus,
    int32_t height,
    std::string* reason = nullptr);

/** Replay-path authorization when the caller already has the exact consensus
 * episode tuple but not the full Consensus::Params object. */
[[nodiscard]] bool RCProductionProviderCapabilityAuthorizesReplay(
    const RCProductionProviderCapability& capability,
    const std::string& provider,
    const matmul::v4::lt::ExactGemmBackend* backend,
    uint32_t matmul_dimension,
    const RCEpisodeParams& params,
    int32_t height,
    std::string* reason = nullptr);

/** Current provider/backend authorization without an epoch lookup. This is
 * used only to admit bounded registry entries; replay use rechecks the epoch. */
[[nodiscard]] bool RCProductionProviderCapabilityAuthorizesIdentity(
    const RCProductionProviderCapability& capability,
    const std::string& provider,
    const matmul::v4::lt::ExactGemmBackend* backend,
    std::string* reason = nullptr);

/** Two tokens are independent only when both are current capabilities for the
 * same epoch and bind distinct proven physical-device execution identities.
 * The launch-candidate production resolver does not yet expose that binding,
 * so production capabilities deliberately return false. The restricted test
 * issuer may exercise adjudication with distinct callbacks. Free-form labels
 * are never evidence of independence. */
[[nodiscard]] bool RCProductionProviderCapabilitiesIndependent(
    const RCProductionProviderCapability& first,
    const RCProductionProviderCapability& second,
    std::string* reason = nullptr);

[[nodiscard]] std::string RCProductionProviderCapabilityId(
    const RCProductionProviderCapability& capability);

/** Narrow unit-test issuer. It accepts only `test:` provider ids and remains
 * process-local/resettable. Production provider ids can only receive a token
 * from RunRCProductionStartupCanary after an exact reviewed golden passes. */
[[nodiscard]] RCProductionProviderCapability
IssueRCProductionProviderCapabilityForTest(
    const std::string& provider,
    const matmul::v4::lt::ExactGemmBackend& backend,
    const RCProductionEpochIdentity& epoch);

/** Non-triggering telemetry snapshot. */
[[nodiscard]] RCProductionCanaryStatus GetLastRCProductionCanaryStatus();
[[nodiscard]] const char* RCProductionCanaryOutcomeName(
    RCProductionCanaryOutcome outcome);
void ResetRCProductionCanaryForTest();

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_PRODUCTION_CANARY_H
