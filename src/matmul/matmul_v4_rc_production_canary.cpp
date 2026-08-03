// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_production_canary.h>

#include <consensus/params.h>
#include <cuda/cuda_context.h>
#include <cuda/matmul_v4_lt_tensor_gemm.h>
#include <logging.h>
#include <matmul/exact_gemm_resolve.h>
#include <matmul/matmul_v4_rc_scale.h>
#include <random.h>

#include <array>
#include <chrono>
#include <cctype>
#include <limits>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <utility>

#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif

namespace matmul::v4::rc {

struct RCProductionProviderCapabilityAccess {
    static RCProductionProviderCapability Make(uint64_t nonce,
                                               uint64_t generation)
    {
        RCProductionProviderCapability out;
        out.m_process_nonce = nonce;
        out.m_generation = generation;
        return out;
    }

    static uint64_t Nonce(const RCProductionProviderCapability& capability)
    {
        return capability.m_process_nonce;
    }

    static uint64_t Generation(
        const RCProductionProviderCapability& capability)
    {
        return capability.m_generation;
    }
};

namespace {

std::mutex g_production_canary_mutex;
RCProductionCanaryStatus g_last_production_canary;

struct BackendIdentity {
    std::array<uintptr_t, 8> callbacks{};

    friend bool operator==(const BackendIdentity&, const BackendIdentity&) =
        default;
};

struct CapabilityRecord {
    RCProductionProviderCapability capability{};
    std::string provider;
    RCProductionProviderIdentity provider_identity{};
    RCProductionEpochIdentity epoch{};
    BackendIdentity backend{};
    bool test_only{false};
};

std::map<std::string, CapabilityRecord> g_provider_capabilities;
uint64_t g_capability_process_nonce{0};
uint64_t g_next_capability_generation{1};
constexpr size_t MAX_PROVIDER_CAPABILITIES{8};

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
        a.driver_identity == b.driver_identity &&
        a.runtime_identity == b.runtime_identity;
}

bool CapabilityEpochEqual(const RCProductionEpochIdentity& a,
                          const RCProductionEpochIdentity& b)
{
    return a.activation_height == b.activation_height &&
        a.profile == b.profile &&
        a.transcript_version == b.transcript_version &&
        a.matmul_dimension == b.matmul_dimension &&
        ParamsEqual(a.params, b.params);
}

bool GoldenEpochMatches(const RCProductionEpochIdentity& runtime,
                        const RCProductionEpochIdentity& golden)
{
    const bool activation_height_matches =
        runtime.activation_height == golden.activation_height ||
        golden.activation_height ==
            RCProductionEpochIdentity::ANY_ACTIVATION_HEIGHT;
    return activation_height_matches &&
        runtime.profile == golden.profile &&
        runtime.transcript_version == golden.transcript_version &&
        runtime.matmul_dimension == golden.matmul_dimension &&
        ParamsEqual(runtime.params, golden.params);
}

bool GoldenProviderClassMatches(
    const RCProductionProviderIdentity& runtime,
    const RCProductionGoldenProviderClass& golden)
{
    return runtime.complete && !golden.provider_family.empty() &&
        !golden.device_architecture.empty() &&
        runtime.provider_family == golden.provider_family &&
        runtime.device_architecture == golden.device_architecture;
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

bool IsHexIdentity(const std::string& value, size_t expected_size)
{
    if (value.size() != expected_size) return false;
    for (const unsigned char ch : value) {
        if (!std::isxdigit(ch)) return false;
    }
    return true;
}

bool GoldenEvidenceIdentityValid(
    const RCProductionGoldenManifestEntry& entry)
{
    // NOTE: these are shape checks only. This process has no repository to
    // resolve a revision against and no way to hash the harness that produced
    // the corpus, so a well-formed string that names nothing passes here. That
    // is not hypothetical: the first final-freeze corpus recorded in this tree
    // carried a 40-hex source_revision that resolved to no commit. The
    // out-of-process guards in contrib/matmul-v4/multi-gpu-golden-corpus.sh and
    // contrib/matmul-v4/verify-evidence-provenance.py are what actually bind
    // these fields to real objects, and per
    // doc/btx-matmul-v4.7-production-golden-policy.md they MUST pass before
    // this manifest is populated.
    return IsHexIdentity(entry.source_revision, 40) &&
        IsHexIdentity(entry.source_tree_fingerprint, 64) &&
        IsHexIdentity(entry.harness_sha256, 64);
}

// A provider family and a device architecture that cannot describe the same
// hardware are a data-entry error at best. Reject the combination outright so a
// hand-written manifest entry cannot claim, say, {family:"metal", arch:"sm_120"}
// and thereby satisfy the two-provider cohort requirement with one vendor's
// silicon named twice.
bool GoldenArchitectureMatchesFamily(const std::string& family,
                                     const std::string& architecture)
{
    if (family.empty() || architecture.empty()) return false;
    if (family == "cuda") return architecture.rfind("sm_", 0) == 0;
    if (family == "hip") return architecture.rfind("gfx", 0) == 0;
    if (family == "metal") {
        // Apple silicon is recorded as a generation class, e.g. "m4_class".
        // "other" is also legitimate: LtMetalArchNameClass emits it for any
        // device it does not recognise, which is every future Apple generation
        // until someone teaches it the name. Rejecting it would silently make
        // the next generation's golden un-committable. Only "unknown" (probe
        // failed) is refused, and the identity probe already rejects that.
        if (architecture == "other") return true;
        return architecture.size() > 6 &&
            architecture.compare(architecture.size() - 6, 6, "_class") == 0 &&
            architecture.front() == 'm';
    }
    // Unknown families are not eligible for the production cohort. Requiring
    // CUDA plus Metal is not enough by itself: otherwise an arbitrary third
    // entry can acquire manifest authority without a defined architecture
    // binding or a production identity probe.
    return false;
}

BackendIdentity IdentifyBackend(
    const matmul::v4::lt::ExactGemmBackend& backend)
{
    return {{
        reinterpret_cast<uintptr_t>(backend.gemm_s8s8),
        reinterpret_cast<uintptr_t>(backend.gemm_s32s8),
        reinterpret_cast<uintptr_t>(backend.rc_fused_ffn),
        reinterpret_cast<uintptr_t>(backend.rc_fused_ffn_chain),
        reinterpret_cast<uintptr_t>(backend.rc_expand_mx),
        reinterpret_cast<uintptr_t>(backend.rc_merkle_leaves),
        reinterpret_cast<uintptr_t>(backend.rc_merkle_root),
        reinterpret_cast<uintptr_t>(backend.rc_phase1),
    }};
}

uint64_t CapabilityProcessNonceLocked()
{
    if (g_capability_process_nonce == 0) {
        do {
            g_capability_process_nonce = FastRandomContext{}.rand64();
        } while (g_capability_process_nonce == 0);
    }
    return g_capability_process_nonce;
}

RCProductionProviderCapability IssueCapabilityLocked(
    const std::string& provider,
    const RCProductionProviderIdentity& provider_identity,
    const RCProductionEpochIdentity& epoch,
    const matmul::v4::lt::ExactGemmBackend& backend,
    bool test_only)
{
    if (provider.empty() || backend.gemm_s8s8 == nullptr) return {};
    const bool replacing{g_provider_capabilities.count(provider) != 0};
    if (!replacing &&
        g_provider_capabilities.size() >= MAX_PROVIDER_CAPABILITIES) {
        return {};
    }
    if (g_next_capability_generation == 0) ++g_next_capability_generation;
    const auto capability{RCProductionProviderCapabilityAccess::Make(
        CapabilityProcessNonceLocked(), g_next_capability_generation++)};
    g_provider_capabilities[provider] = {
        .capability = capability,
        .provider = provider,
        .provider_identity = provider_identity,
        .epoch = epoch,
        .backend = IdentifyBackend(backend),
        .test_only = test_only,
    };
    return capability;
}

const CapabilityRecord* FindCapabilityLocked(
    const RCProductionProviderCapability& capability)
{
    if (capability.IsNull() ||
        RCProductionProviderCapabilityAccess::Nonce(capability) !=
            g_capability_process_nonce) {
        return nullptr;
    }
    for (const auto& [_, record] : g_provider_capabilities) {
        if (RCProductionProviderCapabilityAccess::Generation(
                record.capability) ==
            RCProductionProviderCapabilityAccess::Generation(capability) &&
            RCProductionProviderCapabilityAccess::Nonce(record.capability) ==
            RCProductionProviderCapabilityAccess::Nonce(capability)) {
            return &record;
        }
    }
    return nullptr;
}

const CapabilityRecord* AuthorizeIdentityLocked(
    const RCProductionProviderCapability& capability,
    const std::string& provider,
    const matmul::v4::lt::ExactGemmBackend* backend,
    std::string* reason)
{
    const auto fail = [&](const char* why) -> const CapabilityRecord* {
        if (reason != nullptr) *reason = why;
        return nullptr;
    };
    const auto* record{FindCapabilityLocked(capability)};
    if (record == nullptr) return fail("invalid_or_stale_capability");
    if (record->provider != provider) {
        return fail("capability_provider_mismatch");
    }
    if (backend != nullptr && record->backend != IdentifyBackend(*backend)) {
        return fail("capability_backend_mismatch");
    }
    if (!record->test_only) {
        const auto current{ProbeRCProductionProviderIdentity(provider)};
        if (!ProviderEqual(current, record->provider_identity)) {
            return fail("capability_runtime_identity_changed");
        }
    }
    if (reason != nullptr) reason->clear();
    return record;
}

bool EpochAuthorizes(const CapabilityRecord& record,
                     uint32_t profile,
                     uint32_t transcript_version,
                     uint32_t matmul_dimension,
                     const RCEpisodeParams& params,
                     int32_t height,
                     std::string* reason)
{
    const auto fail = [&](const char* why) {
        if (reason != nullptr) *reason = why;
        return false;
    };
    if (height < record.epoch.activation_height) {
        return fail("capability_before_qualified_epoch");
    }
    if (profile != record.epoch.profile ||
        transcript_version != record.epoch.transcript_version ||
        matmul_dimension != record.epoch.matmul_dimension ||
        !ParamsEqual(params, record.epoch.params)) {
        return fail("capability_epoch_mismatch");
    }
    if (reason != nullptr) reason->clear();
    return true;
}

bool StoreStatus(
    const RCProductionCanaryStatus& status,
    const matmul::v4::lt::ExactGemmBackend* passed_backend = nullptr)
{
    std::lock_guard<std::mutex> lock{g_production_canary_mutex};
    g_last_production_canary = status;
    if (status.provider.empty()) {
        g_provider_capabilities.clear();
        return true;
    }

    // Every new canary outcome supersedes the prior authorization for this
    // provider, including a failed or unsupported rerun.
    g_provider_capabilities.erase(status.provider);
    if (!status.passed || !status.activation_ready ||
        passed_backend == nullptr) {
        return true;
    }
    return !IssueCapabilityLocked(
        status.provider, status.provider_identity, status.epoch,
        *passed_backend, /*test_only=*/false).IsNull();
}

std::string ProviderFamily(const std::string& provider)
{
    if (provider.find("cuda") != std::string::npos ||
        provider.find("nvidia") != std::string::npos) {
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
    // The Ozaki MXFP4 lane has CUDA, HIP and Metal natives. This check must stay
    // BELOW the explicit family
    // markers above: when it sat at the top, `metal_ozaki_mxfp4` and
    // `hip_ozaki_mxfp4` were both classified "cuda", and because
    // ProbeRCProductionProviderIdentity derives architecture/driver/runtime
    // from the family string alone, work executed on one vendor's device would
    // have been identity-bound to another's. An unqualified
    // `rc_ozaki_mxfp4` remains ambiguous: do not guess CUDA from the shared
    // implementation label. It can become production eligible only after the
    // family is derived from the resolver's typed Kind.
    if (provider.find("ozaki_mxfp4") != std::string::npos) {
        return {};
    }
    if (provider.find("ascend") != std::string::npos ||
        provider.find("cann") != std::string::npos) {
        return "ascend";
    }
    if (provider.find("tpu") != std::string::npos) return "tpu";
    if (provider.find("trainium") != std::string::npos) return "trainium";
    return provider;
}

#if defined(__APPLE__)
std::string ReadPublicSysctlString(const char* name)
{
    size_t size{0};
    if (sysctlbyname(name, nullptr, &size, nullptr, 0) != 0 || size <= 1) {
        return {};
    }
    std::string out(size, '\0');
    if (sysctlbyname(name, out.data(), &size, nullptr, 0) != 0) return {};
    out.resize(size);
    while (!out.empty() && out.back() == '\0') out.pop_back();
    return out;
}
#endif

} // namespace

const std::vector<RCProductionGoldenManifestEntry>&
CommittedRCProductionGoldenManifest()
{
    // POPULATED for the Epoch-A activation at mainnet height 182'600.
    //
    // Precondition satisfied: contrib/matmul-v4/multi-gpu-golden-corpus.sh
    // reported complete_multi_gpu_match=true for CUDA and Metal reproduced from
    // ONE code freeze -- the same source_revision AND the same build-relevant
    // source_tree_fingerprint, which is what RCProductionGoldenManifestCohortValid
    // requires and what every earlier corpus in this branch failed. Digest
    // equality alone was never the gate.
    //
    // Evidence: doc/evidence/multi-gpu-profile1-goldens-cuda-metal-2026-08-03-final,
    // regenerated on both providers at the FINAL pre-merge freeze 807cd19b.
    // The digests are bit-identical to the earlier 78a88af5 cohort, so the six
    // commits in between are demonstrably predicate-neutral rather than merely
    // asserted to be.
    // Both providers independently reported 1'088 device calls and
    // 1'129'198'441'725'952 device MACs with zero CPU GEMM calls, zero CPU MACs
    // and zero fallbacks, and ExtractMX self-qualification PASS. All eight
    // digests and all eight frozen header byte strings are byte-identical
    // across providers, verified independently of the comparator script.
    //
    // The two entries deliberately share header_nonce, expected_digest, epoch,
    // source_revision and source_tree_fingerprint, and differ only in
    // provider_class and harness_sha256: that is exactly the cohort shape the
    // validator enforces (one cuda entry, one metal entry, distinct provider
    // classes, identical workload and provenance).
    //
    // ANY_ACTIVATION_HEIGHT is correct here: the frozen canary header and the
    // Profile-1 transcript do not depend on the activation height, and runtime
    // capabilities still bind the real height separately.
    static const std::vector<RCProductionGoldenManifestEntry> manifest{
        RCProductionGoldenManifestEntry{
            .id = "epoch-a-profile1-cuda-sm120-nonce1",
            .provider_class = {.provider_family = "cuda",
                               .device_architecture = "sm_120"},
            .epoch = {.activation_height =
                          RCProductionEpochIdentity::ANY_ACTIVATION_HEIGHT,
                      .profile = 1,
                      .transcript_version = kRCTranscriptVersion,
                      .matmul_dimension = 4096,
                      .params = DefaultConsensusRCEpisodeParams()},
            .header_nonce = 1,
            .expected_digest = uint256{
                "b4777985d4f2621d0b9c119f4188ac7d80158fc92560ade96cc7a3fd8cfae953"},
            .independently_reproduced = true,
            .public_provenance =
                "doc/evidence/multi-gpu-profile1-goldens-cuda-metal-2026-08-03-final",
            .source_revision = "807cd19bd1ee78a415e5e23aa8c049780dce2616",
            .source_tree_fingerprint =
                "f12b05195d2a9f1a9a1ce8f575e0cb102d339b31e02144167b9105c01ae51256",
            .harness_sha256 =
                "497e4b7fc1ad0f3b9c43ea1123fcec6386b211784cf9e740784b2b0897563502",
        },
        RCProductionGoldenManifestEntry{
            .id = "epoch-a-profile1-metal-m4-nonce1",
            .provider_class = {.provider_family = "metal",
                               .device_architecture = "m4_class"},
            .epoch = {.activation_height =
                          RCProductionEpochIdentity::ANY_ACTIVATION_HEIGHT,
                      .profile = 1,
                      .transcript_version = kRCTranscriptVersion,
                      .matmul_dimension = 4096,
                      .params = DefaultConsensusRCEpisodeParams()},
            .header_nonce = 1,
            .expected_digest = uint256{
                "b4777985d4f2621d0b9c119f4188ac7d80158fc92560ade96cc7a3fd8cfae953"},
            .independently_reproduced = true,
            .public_provenance =
                "doc/evidence/multi-gpu-profile1-goldens-cuda-metal-2026-08-03-final",
            .source_revision = "807cd19bd1ee78a415e5e23aa8c049780dce2616",
            .source_tree_fingerprint =
                "f12b05195d2a9f1a9a1ce8f575e0cb102d339b31e02144167b9105c01ae51256",
            .harness_sha256 =
                "b301d2cd65727554f1d12e2b43aa309726c88eac48368dc635b37cee1c78cf0a",
        },
    };
    return manifest;
}

bool RCProductionGoldenManifestCohortValid(
    const std::vector<RCProductionGoldenManifestEntry>& manifest)
{
    if (manifest.size() < 2) return false;
    const auto& reference{manifest.front()};
    bool has_cuda{false};
    bool has_metal{false};
    std::set<std::pair<std::string, std::string>> provider_classes;
    for (const auto& entry : manifest) {
        if (!entry.independently_reproduced || entry.expected_digest.IsNull() ||
            entry.id.empty() || !PublicProvenanceValid(entry.public_provenance) ||
            !GoldenEvidenceIdentityValid(entry) ||
            entry.provider_class.provider_family.empty() ||
            entry.provider_class.device_architecture.empty() ||
            !GoldenArchitectureMatchesFamily(
                entry.provider_class.provider_family,
                entry.provider_class.device_architecture) ||
            entry.header_nonce != reference.header_nonce ||
            entry.expected_digest != reference.expected_digest ||
            // Symmetric, not GoldenEpochMatches(). That helper treats its first
            // argument as "runtime" and its second as "golden", so the
            // ANY_ACTIVATION_HEIGHT wildcard absorbs in one direction only and
            // the cohort verdict flipped when the manifest literal was
            // reordered. Within a cohort every entry must describe the same
            // epoch, so require exact equality.
            !CapabilityEpochEqual(reference.epoch, entry.epoch)) {
            return false;
        }
        if (entry.source_revision != reference.source_revision ||
            entry.source_tree_fingerprint != reference.source_tree_fingerprint) {
            return false;
        }
        const auto provider_class{std::make_pair(
            entry.provider_class.provider_family,
            entry.provider_class.device_architecture)};
        if (!provider_classes.insert(provider_class).second) return false;
        has_cuda = has_cuda || entry.provider_class.provider_family == "cuda";
        has_metal = has_metal || entry.provider_class.provider_family == "metal";
    }
    return has_cuda && has_metal;
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
        out.driver_identity = std::to_string(probe.driver_api_version);
        out.runtime_identity = std::to_string(probe.runtime_version);
        out.complete = !out.device_architecture.empty() &&
            probe.driver_api_version != 0 && probe.runtime_version != 0;
        out.reason = out.complete ? "complete"
                                  : "cuda_driver_or_runtime_version_missing";
        return out;
    }

#if defined(__APPLE__)
    if (out.provider_family == "metal") {
        const auto arch{matmul_v4::metal::ProbeLtMetalArch()};
        if (!arch.available || arch.name_class_string.empty() ||
            arch.name_class_string == "unknown") {
            out.reason = "metal_architecture_class_unavailable";
            return out;
        }
        out.device_architecture = arch.name_class_string;
        // Apple distributes the Metal user runtime and GPU driver with the OS.
        // These public build/release identifiers change across driver/runtime
        // updates without exposing the device name, serial, host or account.
        out.driver_identity = ReadPublicSysctlString("kern.osversion");
        out.runtime_identity = ReadPublicSysctlString("kern.osrelease");
        out.complete = !out.driver_identity.empty() &&
            !out.runtime_identity.empty();
        out.reason = out.complete ? "complete"
                                  : "metal_driver_or_runtime_build_missing";
        return out;
    }
#endif

    // These remaining provider boundaries do not yet expose a stable
    // architecture plus driver/runtime ABI
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
    out.matmul_dimension = consensus.nMatMulV4Dimension;
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
    if (!RCProductionGoldenManifestCohortValid(manifest)) return nullptr;
    const RCProductionGoldenManifestEntry* match{nullptr};
    for (const auto& entry : manifest) {
        if (!entry.independently_reproduced || entry.expected_digest.IsNull() ||
            entry.id.empty() || !PublicProvenanceValid(entry.public_provenance) ||
            !GoldenEvidenceIdentityValid(entry)) {
            continue;
        }
        if (GoldenProviderClassMatches(provider, entry.provider_class) &&
            GoldenEpochMatches(epoch, entry.epoch)) {
            // Duplicate authority records are ambiguous even if their digest
            // happens to agree. Require one exact reviewed entry per identity.
            if (match != nullptr) return nullptr;
            match = &entry;
        }
    }
    return match;
}

CBlockHeader MakeRCProductionCanaryHeader(
    const RCProductionEpochIdentity& epoch, uint64_t nonce)
{
    // This input is public and deterministic. It is deliberately unrelated to
    // any live block, wallet, operator host, or deployment identifier.
    CBlockHeader header;
    header.nVersion = 0x20000004;
    header.nTime = 1'780'000'000;
    header.nBits = 0x207fffff;
    header.nNonce64 = nonce;
    header.nNonce = static_cast<uint32_t>(nonce);
    // The caller rejects unsupported epoch identities before reaching the
    // canary. Keep this helper defensive as well so an out-of-range manifest
    // dimension can never be silently truncated into the 16-bit header field.
    if (epoch.matmul_dimension == 0 ||
        epoch.matmul_dimension > std::numeric_limits<uint16_t>::max()) {
        return header;
    }
    header.matmul_dim = static_cast<uint16_t>(epoch.matmul_dimension);
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
        golden.id.empty() || !PublicProvenanceValid(golden.public_provenance) ||
        !GoldenEvidenceIdentityValid(golden)) {
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

static RCProductionCanaryStatus RunRCProductionStartupCanaryImpl(
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
    out.manifest_has_reviewed_goldens =
        RCProductionGoldenManifestCohortValid(manifest);

    if (out.epoch.matmul_dimension == 0 ||
        out.epoch.matmul_dimension > std::numeric_limits<uint16_t>::max()) {
        out.outcome = RCProductionCanaryOutcome::UnsupportedEpoch;
        out.reason = "production_matmul_dimension_out_of_header_range";
        StoreStatus(out);
        return out;
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
        MakeRCProductionCanaryHeader(out.epoch, golden->header_nonce),
        out.epoch.params, activation_height, backend,
        resolved_provider)};
    out.wall_s = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - started).count();
    out.observed_digest = replay.digest;
    out.acceleration = replay.acceleration;
    out.outcome = EvaluateRCProductionCanaryResult(*golden, replay);
    out.passed = out.outcome == RCProductionCanaryOutcome::Passed;
    out.activation_ready = out.passed;
    out.reason = RCProductionCanaryOutcomeName(out.outcome);
    if (!StoreStatus(out, &backend)) {
        out.outcome = RCProductionCanaryOutcome::LocalAcceleratorFailure;
        out.passed = false;
        out.activation_ready = false;
        out.reason = "production_capability_registry_full";
        StoreStatus(out);
    }

    LogPrintf(
        "MatMul RC production canary: outcome=%s provider=%s family=%s "
        "arch=%s driver=%s runtime=%s epoch_height=%d profile=%u "
        "transcript=%u matmul_dim=%u manifest=%s wall=%.3fs device_macs=%llu "
        "cpu_fallbacks=%llu\n",
        RCProductionCanaryOutcomeName(out.outcome), out.provider,
        out.provider_identity.provider_family,
        out.provider_identity.device_architecture,
        out.provider_identity.driver_identity,
        out.provider_identity.runtime_identity,
        out.epoch.activation_height, out.epoch.profile,
        out.epoch.transcript_version, out.epoch.matmul_dimension,
        out.manifest_entry_id, out.wall_s,
        static_cast<unsigned long long>(out.acceleration.device_macs),
        static_cast<unsigned long long>(out.acceleration.cpu_fallbacks));
    return out;
}

RCProductionCanaryStatus RunRCProductionStartupCanary(
    const std::string& resolved_provider,
    const matmul::v4::lt::ExactGemmBackend& backend,
    const Consensus::Params& consensus,
    int32_t activation_height)
{
    const auto resolved{
        matmul_v4::accel::ProbeLastRCExactGemmResolution()};
    const bool resolver_authorized{
        resolved.resolved && resolved.self_qualified &&
        resolved.automatic_policy_eligible &&
        resolved.provider == resolved_provider &&
        IdentifyBackend(resolved.backend) == IdentifyBackend(backend)};
    return RunRCProductionStartupCanaryImpl(
        resolved_provider, backend, resolver_authorized,
        consensus, activation_height);
}

RCProductionCanaryStatus RunRCProductionStartupCanaryForTest(
    const std::string& test_provider,
    const matmul::v4::lt::ExactGemmBackend& backend,
    const Consensus::Params& consensus,
    int32_t activation_height)
{
    if (test_provider.rfind("test:", 0) != 0) {
        RCProductionCanaryStatus out;
        out.provider = test_provider;
        out.outcome = RCProductionCanaryOutcome::ProviderNotPolicyEligible;
        out.reason = "test_canary_provider_prefix_required";
        StoreStatus(out);
        return out;
    }
    // The claim that this seam "can never mint a production capability" held
    // only because CommittedRCProductionGoldenManifest() is empty. ProviderFamily
    // classifies by substring, so "test:cuda_shim" resolves to family "cuda" and
    // would match a real cuda manifest entry the moment one is committed --
    // and Impl reaches StoreStatus -> IssueCapabilityLocked(test_only=false),
    // minting a genuine production capability for a caller-supplied backend
    // while bypassing the resolver binding that the production entry point
    // applies. Refuse any test provider that resolves to a real accelerator
    // family so the guarantee is structural rather than incidental.
    const std::string family{ProviderFamily(test_provider)};
    if (family == "cuda" || family == "metal" || family == "hip" ||
        family == "ascend" || family == "tpu" || family == "trainium") {
        RCProductionCanaryStatus out;
        out.provider = test_provider;
        out.outcome = RCProductionCanaryOutcome::ProviderNotPolicyEligible;
        out.reason = "test_canary_provider_resolves_to_real_family";
        StoreStatus(out);
        return out;
    }
    return RunRCProductionStartupCanaryImpl(
        test_provider, backend, /*automatic_policy_eligible=*/true,
        consensus, activation_height);
}

bool RCProductionProviderCapability::IsNull() const
{
    return m_process_nonce == 0 || m_generation == 0;
}

std::optional<RCProductionProviderCapability>
GetRCProductionProviderCapability(
    const std::string& provider,
    const matmul::v4::lt::ExactGemmBackend& backend,
    const Consensus::Params& consensus,
    int32_t height,
    std::string* reason)
{
    std::lock_guard<std::mutex> lock{g_production_canary_mutex};
    const auto it{g_provider_capabilities.find(provider)};
    if (it == g_provider_capabilities.end()) {
        if (reason != nullptr) *reason = "provider_has_no_current_capability";
        return std::nullopt;
    }
    const auto* record{AuthorizeIdentityLocked(
        it->second.capability, provider, &backend, reason)};
    if (record == nullptr) return std::nullopt;
    const auto expected{MakeRCProductionEpochIdentity(consensus, height)};
    if (!EpochAuthorizes(
            *record, expected.profile, expected.transcript_version,
            expected.matmul_dimension, expected.params, height, reason)) {
        return std::nullopt;
    }
    return record->capability;
}

bool RCProductionProviderCapabilityAuthorizes(
    const RCProductionProviderCapability& capability,
    const std::string& provider,
    const matmul::v4::lt::ExactGemmBackend* backend,
    const Consensus::Params& consensus,
    int32_t height,
    std::string* reason)
{
    std::lock_guard<std::mutex> lock{g_production_canary_mutex};
    const auto* record{
        AuthorizeIdentityLocked(capability, provider, backend, reason)};
    if (record == nullptr) return false;
    const auto expected{MakeRCProductionEpochIdentity(consensus, height)};
    return EpochAuthorizes(
        *record, expected.profile, expected.transcript_version,
        expected.matmul_dimension, expected.params, height, reason);
}

bool RCProductionProviderCapabilityAuthorizesReplay(
    const RCProductionProviderCapability& capability,
    const std::string& provider,
    const matmul::v4::lt::ExactGemmBackend* backend,
    uint32_t matmul_dimension,
    const RCEpisodeParams& params,
    int32_t height,
    std::string* reason)
{
    std::lock_guard<std::mutex> lock{g_production_canary_mutex};
    const auto* record{
        AuthorizeIdentityLocked(capability, provider, backend, reason)};
    if (record == nullptr) return false;
    return EpochAuthorizes(
        *record, /*profile=*/1, kRCTranscriptVersion, matmul_dimension,
        params, height, reason);
}

bool RCProductionProviderCapabilityAuthorizesIdentity(
    const RCProductionProviderCapability& capability,
    const std::string& provider,
    const matmul::v4::lt::ExactGemmBackend* backend,
    std::string* reason)
{
    std::lock_guard<std::mutex> lock{g_production_canary_mutex};
    return AuthorizeIdentityLocked(
               capability, provider, backend, reason) != nullptr;
}

bool RCProductionProviderCapabilitiesIndependent(
    const RCProductionProviderCapability& first,
    const RCProductionProviderCapability& second,
    std::string* reason)
{
    const auto fail = [&](const char* why) {
        if (reason != nullptr) *reason = why;
        return false;
    };
    std::lock_guard<std::mutex> lock{g_production_canary_mutex};
    const auto* a{FindCapabilityLocked(first)};
    const auto* b{FindCapabilityLocked(second)};
    if (a == nullptr || b == nullptr) {
        return fail("invalid_or_stale_capability");
    }
    if (!CapabilityEpochEqual(a->epoch, b->epoch)) {
        return fail("capability_epoch_mismatch");
    }
    if ((!a->test_only &&
         !ProviderEqual(ProbeRCProductionProviderIdentity(a->provider),
                        a->provider_identity)) ||
        (!b->test_only &&
         !ProviderEqual(ProbeRCProductionProviderIdentity(b->provider),
                        b->provider_identity))) {
        return fail("capability_runtime_identity_changed");
    }
    // The current production resolver binds one selected device per process,
    // but does not yet issue a canary-bound physical-device execution identity
    // for multiple devices. Different wrapper functions over that same device
    // are correlated and must never turn a shared device fault into a permanent
    // peer-invalid verdict. Keep production adjudication fail-closed until the
    // resolver proves distinct device identities. The restricted test issuer
    // below may still exercise the state machine with distinct callbacks.
    if (!a->test_only || !b->test_only) {
        return fail("independent_device_execution_identity_unavailable");
    }
    // Provider names and caller-supplied failure-domain labels are not
    // execution identities. Even in tests, require a distinct exact GEMM
    // entry point so two labels around the same callback remain correlated.
    if (a->backend.callbacks[0] == 0 ||
        a->backend.callbacks[0] == b->backend.callbacks[0]) {
        return fail("correlated_backend_entry_point");
    }
    if (reason != nullptr) reason->clear();
    return true;
}

std::string RCProductionProviderCapabilityId(
    const RCProductionProviderCapability& capability)
{
    if (capability.IsNull()) return "none";
    std::ostringstream out;
    out << "rcpc-" << std::hex
        << RCProductionProviderCapabilityAccess::Nonce(capability) << '-'
        << RCProductionProviderCapabilityAccess::Generation(capability);
    return out.str();
}

RCProductionProviderCapability
IssueRCProductionProviderCapabilityForTest(
    const std::string& provider,
    const matmul::v4::lt::ExactGemmBackend& backend,
    const RCProductionEpochIdentity& epoch)
{
    if (provider.rfind("test:", 0) != 0 || provider.size() > 128 ||
        backend.gemm_s8s8 == nullptr || epoch.profile != 1 ||
        epoch.transcript_version != kRCTranscriptVersion ||
        epoch.matmul_dimension == 0 || epoch.activation_height < 0 ||
        TotalRCEpisodeMacs(epoch.params) == 0) {
        return {};
    }
    RCProductionProviderIdentity identity;
    identity.provider_family = "test";
    identity.device_architecture = "unit-test-backend";
    identity.driver_identity = "unit-test";
    identity.runtime_identity = "unit-test";
    identity.complete = true;
    identity.reason = "test-only";
    std::lock_guard<std::mutex> lock{g_production_canary_mutex};
    return IssueCapabilityLocked(
        provider, identity, epoch, backend, /*test_only=*/true);
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
