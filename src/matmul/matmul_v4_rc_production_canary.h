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
#include <string_view>
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

/** Stable public provider class covered by a cross-backend golden.
 *
 * Driver/runtime versions deliberately do not live here: a golden proves the
 * deterministic workload for an implementation family and architecture,
 * while each startup canary and its process capability bind the exact live
 * driver/runtime identity and must be rerun after that identity changes.
 */
struct RCProductionGoldenProviderClass {
    std::string provider_family;
    std::string device_architecture;
};

/** Consensus epoch identity covered by one production-shape golden. */
struct RCProductionEpochIdentity {
    /** A reviewed golden may use this value because the frozen canary header
     * and current Profile-1 transcript do not depend on the eventual public
     * activation height. Runtime capabilities still bind the real height. */
    static constexpr int32_t ANY_ACTIVATION_HEIGHT{-1};
    int32_t activation_height{-1};
    uint32_t profile{0};
    uint32_t transcript_version{0};
    uint32_t matmul_dimension{0};
    RCEpisodeParams params{};
};

/** One independently reproduced, reviewable production-shape golden.
 *
 * Entries exactly bind provider family and architecture, transcript version,
 * consensus MatMul dimension, every episode dimension, header nonce/digest,
 * source fingerprint, and harness binary. The epoch height may use the
 * explicitly documented ANY_ACTIVATION_HEIGHT sentinel because it is not a
 * canary-header input; the live capability separately binds the configured
 * height. Runtime/driver identity is probed and reported at qualification time,
 * not stored as a manifest-field wildcard. A pending/null/unreviewed entry can
 * never authorize a provider. Absence of a matching row is not a mining
 * refusal: byte-exact ExactGemmS8S8 self-qualification admits the device.
 * A digest mismatch against a unique matching row remains fail-closed.
 */
struct RCProductionGoldenManifestEntry {
    std::string id;
    RCProductionGoldenProviderClass provider_class{};
    RCProductionEpochIdentity epoch{};
    uint64_t header_nonce{0};
    uint256 expected_digest{};
    bool independently_reproduced{false};
    std::string public_provenance;
    /** Exact reviewed code-freeze commit (40 hexadecimal characters). */
    std::string source_revision;
    /** SHA-256 over root CMakeLists.txt, cmake/, and src/ at the code freeze. */
    std::string source_tree_fingerprint;
    /** SHA-256 of the provider-specific harness binary used for this record. */
    std::string harness_sha256;
};

enum class RCProductionCanaryOutcome : uint8_t {
    NotRun = 0,
    Passed = 1,
    /** No unique reviewed row for this device class. Reporting only when
     *  byte-exact self-qualification passed; not a mining refusal. */
    MissingGolden = 2,
    ProviderIdentityUnavailable = 3,
    ProviderNotPolicyEligible = 4,
    LocalAcceleratorFailure = 5,
    DigestMismatch = 6,
    UnsupportedEpoch = 7,
    BuildProvenanceMismatch = 8,
};

/** How this process admitted (or refused) mining for the live provider. */
enum class RCProductionAdmissionPath : uint8_t {
    None = 0,
    ReviewedGolden = 1,
    SelfQualification = 2,
};

enum class RCProductionGoldenLookupStatus : uint8_t {
    None = 0,
    Unique = 1,
    Duplicate = 2,
};

struct RCProductionGoldenLookup {
    RCProductionGoldenLookupStatus status{
        RCProductionGoldenLookupStatus::None};
    const RCProductionGoldenManifestEntry* entry{nullptr};
};

/** Pure mining-admission decision. Does not run devices. */
struct RCProductionAdmissionDecision {
    bool admissible{false};
    RCProductionAdmissionPath path{RCProductionAdmissionPath::None};
    RCProductionCanaryOutcome outcome{RCProductionCanaryOutcome::NotRun};
    std::string reason;
    bool exact_manifest_match{false};
    bool passed{false};
    bool activation_ready{false};
};

struct RCProductionCanaryStatus {
    RCProductionCanaryOutcome outcome{RCProductionCanaryOutcome::NotRun};
    RCProductionAdmissionPath admission_path{
        RCProductionAdmissionPath::None};
    bool manifest_has_reviewed_goldens{false};
    bool build_provenance_matches{false};
    bool build_source_dirty{true};
    bool exact_manifest_match{false};
    bool attempted{false};
    bool passed{false};
    bool activation_ready{false};
    size_t manifest_entries{0};
    std::string manifest_entry_id;
    std::string build_source_revision;
    std::string build_source_tree_fingerprint;
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
 * This tree ships the classes it measured. Additional provider rows
 * are added by the builder that measured them, in that builder's
 * manifest. Portable CPU is not an accepted independent reproduction
 * path. Extra families present in a cohort must byte-match each other.
 */
[[nodiscard]] const std::vector<RCProductionGoldenManifestEntry>&
CommittedRCProductionGoldenManifest();

/** Parse the strictly data-only production seal. This is public for fail-closed
 * parser tests; production callers use CommittedRCProductionGoldenManifest(). */
[[nodiscard]] std::vector<RCProductionGoldenManifestEntry>
ParseRCProductionGoldenManifestData(std::string_view encoded);

/** Require one coherent independently reproduced cohort. Any single
 *  admitted family (CUDA, Metal, HIP, …) is enough; CUDA is not required. */
[[nodiscard]] bool RCProductionGoldenManifestCohortValid(
    const std::vector<RCProductionGoldenManifestEntry>& manifest);

/** Bind a structurally valid cohort to the implementation fingerprint embedded
 * in the running binary. The data-only manifest seal is excluded from that
 * fingerprint, so the reviewed code-freeze and its later seal can agree
 * without a circular hash. Dirty builds never match. */
[[nodiscard]] bool RCProductionGoldenManifestMatchesBuild(
    const std::vector<RCProductionGoldenManifestEntry>& manifest,
    const std::string& build_source_tree_fingerprint,
    bool build_source_dirty);

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

/** Locate a reviewed row for this provider class and epoch.
 *
 * Unlike FindRCProductionGolden, this does not require the whole cohort to
 * be coherent: a unique matching row is still compared. Duplicate matching
 * rows fail closed. Zero matches is absence, not a digest failure. */
[[nodiscard]] RCProductionGoldenLookup LookupRCProductionGolden(
    const RCProductionProviderIdentity& provider,
    const RCProductionEpochIdentity& epoch,
    const std::vector<RCProductionGoldenManifestEntry>& manifest);

/** Mining admission: unique matching row compares digest; absence of a row
 *  admits when self-qualification passed; self-qual failure and digest
 *  mismatch remain fail-closed. */
[[nodiscard]] RCProductionAdmissionDecision DecideRCProductionMiningAdmission(
    bool self_qualified,
    const RCProductionGoldenLookup& lookup,
    const RCStrictDeviceEpisodeResult* replay);

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
 * from RunRCProductionStartupCanary after admission (reviewed golden match
 * or byte-exact self-qualification with no matching row). */
[[nodiscard]] RCProductionProviderCapability
IssueRCProductionProviderCapabilityForTest(
    const std::string& provider,
    const matmul::v4::lt::ExactGemmBackend& backend,
    const RCProductionEpochIdentity& epoch);

/** Non-triggering telemetry snapshot. */
[[nodiscard]] RCProductionCanaryStatus GetLastRCProductionCanaryStatus();
[[nodiscard]] const char* RCProductionCanaryOutcomeName(
    RCProductionCanaryOutcome outcome);
[[nodiscard]] const char* RCProductionAdmissionPathName(
    RCProductionAdmissionPath path);
/** Test-only identity probe override. ResetRCProductionCanaryForTest clears it. */
void SetRCProductionProviderIdentityOverrideForTest(
    std::optional<RCProductionProviderIdentity> identity);
void ResetRCProductionCanaryForTest();

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_PRODUCTION_CANARY_H
