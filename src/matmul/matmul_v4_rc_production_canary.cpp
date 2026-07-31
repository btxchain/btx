// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_production_canary.h>

#include <consensus/params.h>
#include <cuda/cuda_context.h>
#include <logging.h>
#include <matmul/matmul_v4_rc_scale.h>

#include <chrono>
#include <limits>
#include <mutex>
#include <utility>

namespace matmul::v4::rc {
namespace {

std::mutex g_production_canary_mutex;
RCProductionCanaryStatus g_last_production_canary;

bool ParamsEqual(const RCEpisodeParams& a, const RCEpisodeParams& b)
{
    return a.rounds == b.rounds && a.d_head == b.d_head &&
        a.n_q == b.n_q && a.n_ctx == b.n_ctx && a.L_lyr == b.L_lyr &&
        a.d_model == b.d_model && a.d_ff == b.d_ff &&
        a.b_seq == b.b_seq && a.T_leaf == b.T_leaf;
}

bool ProviderEqual(const RCProductionProviderIdentity& a,
                   const RCProductionProviderIdentity& b)
{
    return a.complete && b.complete &&
        a.provider_family == b.provider_family &&
        a.device_architecture == b.device_architecture &&
        a.driver_api_version == b.driver_api_version &&
        a.runtime_version == b.runtime_version;
}

bool EpochEqual(const RCProductionEpochIdentity& a,
                const RCProductionEpochIdentity& b)
{
    return a.activation_height == b.activation_height &&
        a.profile == b.profile &&
        a.transcript_version == b.transcript_version &&
        ParamsEqual(a.params, b.params);
}

bool PublicProvenanceValid(const std::string& value)
{
    if (value.empty() || value.front() == '/' ||
        value.find("../") != std::string::npos ||
        value.find("file:") == 0) {
        return false;
    }
    // Accept a repository-relative evidence path or a public HTTPS reference;
    // reject host-local absolute/file paths at the authorization boundary.
    return value.find("doc/") == 0 || value.find("https://") == 0;
}

void StoreStatus(const RCProductionCanaryStatus& status)
{
    std::lock_guard<std::mutex> lock{g_production_canary_mutex};
    g_last_production_canary = status;
}

std::string ProviderFamily(const std::string& provider)
{
    if (provider.find("cuda") != std::string::npos ||
        provider.find("nvidia") != std::string::npos ||
        provider.find("ozaki_mxfp4") != std::string::npos) {
        return "cuda";
    }
    if (provider.find("metal") != std::string::npos ||
        provider.find("apple") != std::string::npos) {
        return "metal";
    }
    if (provider.find("hip") != std::string::npos ||
        provider.find("rocm") != std::string::npos) {
        return "hip";
    }
    if (provider.find("ascend") != std::string::npos ||
        provider.find("cann") != std::string::npos) {
        return "ascend";
    }
    if (provider.find("tpu") != std::string::npos) return "tpu";
    if (provider.find("trainium") != std::string::npos) return "trainium";
    return provider;
}

} // namespace

const std::vector<RCProductionGoldenManifestEntry>&
CommittedRCProductionGoldenManifest()
{
    // Intentionally empty. Do not add an entry until its complete production
    // oracle output and public provenance have been independently reproduced
    // and reviewed. In particular, toy/scaled-medium self-qualification data
    // is not a production golden.
    static const std::vector<RCProductionGoldenManifestEntry> manifest{};
    return manifest;
}

RCProductionProviderIdentity
ProbeRCProductionProviderIdentity(const std::string& resolved_provider)
{
    RCProductionProviderIdentity out;
    out.provider_family = ProviderFamily(resolved_provider);
    if (out.provider_family == "cuda") {
        const auto probe{btx::cuda::ProbeCudaRuntime()};
        if (!probe.available) {
            out.reason = probe.reason.empty() ? "cuda_runtime_unavailable"
                                              : probe.reason;
            return out;
        }
        out.device_architecture = "sm_" +
            std::to_string(probe.compute_capability_major) +
            std::to_string(probe.compute_capability_minor);
        out.driver_api_version = probe.driver_api_version;
        out.runtime_version = probe.runtime_version;
        out.complete = !out.device_architecture.empty() &&
            out.driver_api_version != 0 && out.runtime_version != 0;
        out.reason = out.complete ? "complete"
                                  : "cuda_driver_or_runtime_version_missing";
        return out;
    }

    // These provider boundaries do not yet expose a stable driver/runtime ABI
    // fingerprint to this common resolver. They remain usable for experiments
    // and ordinary self-qualification, but cannot become automatic production
    // providers until that public probe is implemented and a matching manifest
    // entry is committed.
    out.reason = out.provider_family.empty() || out.provider_family == "cpu"
        ? "no_device_provider"
        : "provider_runtime_identity_unavailable";
    return out;
}

bool RCProductionProviderIdentityMatches(
    const RCProductionProviderIdentity& a,
    const RCProductionProviderIdentity& b)
{
    return ProviderEqual(a, b);
}

RCProductionEpochIdentity MakeRCProductionEpochIdentity(
    const Consensus::Params& consensus, int32_t activation_height)
{
    RCProductionEpochIdentity out;
    out.activation_height = activation_height;
    out.profile = consensus.nMatMulRCProfile;
    out.transcript_version = kRCTranscriptVersion;
    if (activation_height >= 0 &&
        activation_height != std::numeric_limits<int32_t>::max()) {
        out.params = ConsensusRCEpisodeParamsForHeight(
            activation_height, consensus);
    }
    return out;
}

const RCProductionGoldenManifestEntry* FindRCProductionGolden(
    const RCProductionProviderIdentity& provider,
    const RCProductionEpochIdentity& epoch,
    const std::vector<RCProductionGoldenManifestEntry>& manifest)
{
    const RCProductionGoldenManifestEntry* match{nullptr};
    for (const auto& entry : manifest) {
        if (!entry.independently_reproduced || entry.expected_digest.IsNull() ||
            entry.id.empty() || !PublicProvenanceValid(entry.public_provenance)) {
            continue;
        }
        if (ProviderEqual(provider, entry.provider) &&
            EpochEqual(epoch, entry.epoch)) {
            // Duplicate authority records are ambiguous even if their digest
            // happens to agree. Require one exact reviewed entry per identity.
            if (match != nullptr) return nullptr;
            match = &entry;
        }
    }
    return match;
}

CBlockHeader MakeRCProductionCanaryHeader(uint64_t nonce)
{
    // This input is public and deterministic. It is deliberately unrelated to
    // any live block, wallet, operator host, or deployment identifier.
    CBlockHeader header;
    header.nVersion = 0x20000004;
    header.nTime = 1'780'000'000;
    header.nBits = 0x207fffff;
    header.nNonce64 = nonce;
    header.nNonce = static_cast<uint32_t>(nonce);
    for (int i = 0; i < 32; ++i) {
        header.hashPrevBlock.data()[i] = static_cast<unsigned char>(0x91);
        header.hashMerkleRoot.data()[i] = static_cast<unsigned char>(0x2d);
        header.seed_a.data()[i] = static_cast<unsigned char>(0x46);
        header.seed_b.data()[i] = static_cast<unsigned char>(0xb8);
    }
    return header;
}

RCProductionCanaryOutcome EvaluateRCProductionCanaryResult(
    const RCProductionGoldenManifestEntry& golden,
    const RCStrictDeviceEpisodeResult& replay)
{
    if (!golden.independently_reproduced || golden.expected_digest.IsNull() ||
        golden.id.empty() || !PublicProvenanceValid(golden.public_provenance)) {
        return RCProductionCanaryOutcome::MissingGolden;
    }
    if (replay.outcome != RCStrictDeviceEpisodeOutcome::Complete ||
        replay.digest.IsNull() || !replay.acceleration.require_device ||
        !replay.acceleration.fully_accelerated ||
        replay.acceleration.cpu_calls != 0 ||
        replay.acceleration.cpu_fallbacks != 0 ||
        replay.acceleration.device_macs != TotalRCEpisodeMacs(golden.epoch.params)) {
        return RCProductionCanaryOutcome::LocalAcceleratorFailure;
    }
    return replay.digest == golden.expected_digest
        ? RCProductionCanaryOutcome::Passed
        : RCProductionCanaryOutcome::DigestMismatch;
}

RCProductionCanaryStatus RunRCProductionStartupCanary(
    const std::string& resolved_provider,
    const matmul::v4::lt::ExactGemmBackend& backend,
    bool automatic_policy_eligible,
    const Consensus::Params& consensus,
    int32_t activation_height)
{
    RCProductionCanaryStatus out;
    out.provider = resolved_provider;
    out.provider_identity = ProbeRCProductionProviderIdentity(resolved_provider);
    out.epoch = MakeRCProductionEpochIdentity(consensus, activation_height);
    const auto& manifest{CommittedRCProductionGoldenManifest()};
    out.manifest_entries = manifest.size();
    for (const auto& entry : manifest) {
        if (entry.independently_reproduced && !entry.expected_digest.IsNull() &&
            !entry.id.empty() && PublicProvenanceValid(entry.public_provenance)) {
            out.manifest_has_reviewed_goldens = true;
            break;
        }
    }

    if (activation_height < 0 ||
        activation_height == std::numeric_limits<int32_t>::max() ||
        consensus.nMatMulRCProfile != 1 ||
        consensus.fMatMulRCUseToyDims) {
        out.outcome = RCProductionCanaryOutcome::UnsupportedEpoch;
        out.reason = "production_profile1_epoch_not_configured";
        StoreStatus(out);
        return out;
    }

    if (!automatic_policy_eligible) {
        out.outcome = RCProductionCanaryOutcome::ProviderNotPolicyEligible;
        out.reason = "provider_not_automatic_policy_eligible";
        StoreStatus(out);
        return out;
    }
    if (!out.provider_identity.complete) {
        out.outcome = RCProductionCanaryOutcome::ProviderIdentityUnavailable;
        out.reason = out.provider_identity.reason;
        StoreStatus(out);
        return out;
    }
    const auto* golden{FindRCProductionGolden(
        out.provider_identity, out.epoch, manifest)};
    if (golden == nullptr) {
        out.outcome = RCProductionCanaryOutcome::MissingGolden;
        out.reason = "no_exact_reviewed_production_golden";
        StoreStatus(out);
        return out;
    }
    out.exact_manifest_match = true;
    out.manifest_entry_id = golden->id;
    out.expected_digest = golden->expected_digest;
    out.attempted = true;

    const auto started{std::chrono::steady_clock::now()};
    const RCStrictDeviceEpisodeResult replay{MineRCEpisodeStrictDevice(
        MakeRCProductionCanaryHeader(golden->header_nonce),
        golden->epoch.params, golden->epoch.activation_height, backend,
        resolved_provider)};
    out.wall_s = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - started).count();
    out.observed_digest = replay.digest;
    out.acceleration = replay.acceleration;
    out.outcome = EvaluateRCProductionCanaryResult(*golden, replay);
    out.passed = out.outcome == RCProductionCanaryOutcome::Passed;
    out.activation_ready = out.passed;
    out.reason = RCProductionCanaryOutcomeName(out.outcome);
    StoreStatus(out);

    LogPrintf(
        "MatMul RC production canary: outcome=%s provider=%s family=%s "
        "arch=%s driver=%u runtime=%u epoch_height=%d profile=%u "
        "transcript=%u manifest=%s wall=%.3fs device_macs=%llu "
        "cpu_fallbacks=%llu\n",
        RCProductionCanaryOutcomeName(out.outcome), out.provider,
        out.provider_identity.provider_family,
        out.provider_identity.device_architecture,
        out.provider_identity.driver_api_version,
        out.provider_identity.runtime_version,
        out.epoch.activation_height, out.epoch.profile,
        out.epoch.transcript_version, out.manifest_entry_id, out.wall_s,
        static_cast<unsigned long long>(out.acceleration.device_macs),
        static_cast<unsigned long long>(out.acceleration.cpu_fallbacks));
    return out;
}

RCProductionCanaryStatus GetLastRCProductionCanaryStatus()
{
    std::lock_guard<std::mutex> lock{g_production_canary_mutex};
    return g_last_production_canary;
}

const char* RCProductionCanaryOutcomeName(RCProductionCanaryOutcome outcome)
{
    switch (outcome) {
    case RCProductionCanaryOutcome::NotRun: return "not_run";
    case RCProductionCanaryOutcome::Passed: return "passed";
    case RCProductionCanaryOutcome::MissingGolden: return "missing_golden";
    case RCProductionCanaryOutcome::ProviderIdentityUnavailable:
        return "provider_identity_unavailable";
    case RCProductionCanaryOutcome::ProviderNotPolicyEligible:
        return "provider_not_policy_eligible";
    case RCProductionCanaryOutcome::LocalAcceleratorFailure:
        return "local_accelerator_failure";
    case RCProductionCanaryOutcome::DigestMismatch: return "digest_mismatch";
    case RCProductionCanaryOutcome::UnsupportedEpoch: return "unsupported_epoch";
    }
    return "unknown";
}

void ResetRCProductionCanaryForTest()
{
    StoreStatus({});
}

} // namespace matmul::v4::rc
