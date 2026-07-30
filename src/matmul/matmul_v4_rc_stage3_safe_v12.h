// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_SAFE_V12_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_SAFE_V12_H

#include <matmul/matmul_v4_rc_alg_hash.h>
#include <matmul/matmul_v4_rc_alg_hash_typed.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

/**
 * Native V12 SAFE/SAFECore foundation.
 *
 * This module implements the algorithms in:
 *
 *   Aumasson et al., "SAFE: Sponge API for Field Elements",
 *   IACR ePrint 2023/522, Algorithms 1 and 2; and
 *
 *   Khovratovich et al., "Generic Security of the SAFE API and Its
 *   Applications", IACR ePrint 2023/520, Algorithms 2 and 3.
 *
 * The online object is the stateful START/ABSORB/SQUEEZE/FINISH API.  The
 * stateless evaluator is the exact SAFECore construction used by the security
 * reduction.  The latter is also a low-delta candidate for V11's existing hash
 * DAG: each old stateless digest can become
 *
 *   SAFECore(IO=(message_length, 4), typed_domain, message).
 *
 * Consequently, seed/digest feedback is ordinary message data and need not be
 * removed merely to use SAFECore.  A single continuous online transcript is a
 * separate, higher-change option.
 *
 * SECURITY STATUS: this file supplies a native construction, not an activated
 * consensus theorem.  Concrete H/P reductions, a globally exact query
 * manifest, a pinned domain registry, active native migration, and recursive
 * AIR parity remain fail-closed below.
 */
namespace matmul::v4::rc::safe_v12 {

namespace gf = gkr_field;
namespace ah = alg_hash;
namespace aht = alg_hash_typed;

inline constexpr uint32_t kSafeProtocolVersionV12 = 12;
inline constexpr uint32_t kSafeEncodingVersionV1 = 1;
inline constexpr uint32_t kSafeRateV12 = ah::kAlgHashRate;
inline constexpr uint32_t kSafeCapacityV12 = ah::kAlgHashCapacity;
inline constexpr uint32_t kSafeWidthV12 = ah::kAlgHashT;
inline constexpr uint32_t kSafeMaxIoElementsPerPhase =
    UINT32_C(0x7fffffff);
inline constexpr uint32_t kSafeMaxPatternSegments = 4096;
inline constexpr uint64_t kSafeMaxDomainBytes = UINT64_C(1) << 20;
inline constexpr uint64_t kSafeMaxTagVectorAttempts =
    UINT64_C(1) << 20;
inline constexpr uint32_t kPoseidonAirColumnsPerPermutationV12 = 484;
inline constexpr uint32_t kPoseidonAirRowsPerPermutationV12 = 1;

static_assert(kSafeRateV12 + kSafeCapacityV12 == kSafeWidthV12);
static_assert(kSafeCapacityV12 == 4,
              "SAFECore H(IO,D) must fill every capacity lane");

enum class IoKindV12 : uint8_t {
    Squeeze = 0,
    Absorb = 1,
};

struct IoSegmentV12 {
    IoKindV12 kind{IoKindV12::Absorb};
    uint32_t elements{0};

    friend bool operator==(const IoSegmentV12&,
                           const IoSegmentV12&) = default;
};

/**
 * Canonical SAFE IO pattern.  Adjacent operations of one kind are aggregated,
 * the first segment is ABSORB, kinds alternate, and the last is SQUEEZE.
 */
struct IoPatternV12 {
    /**
     * Canonical tag pattern after aggregating adjacent calls of one kind.
     * SAFECore consumes this alternating (I_1,O_1,...,I_k,O_k) form.
     */
    std::vector<IoSegmentV12> segments;
    /**
     * Exact online SAFE call schedule checked by Algorithms 1/2.  An empty
     * vector means that `segments` itself is the exact schedule; builders
     * populate this field so split calls remain distinguishable at runtime
     * even though their H(IO,D) tag is canonically identical.
     */
    std::vector<IoSegmentV12> exact_calls;

    friend bool operator==(const IoPatternV12&,
                           const IoPatternV12&) = default;
};

/** Build the canonical equivalence class from arbitrary call chunking. */
class IoPatternBuilderV12
{
private:
    std::vector<IoSegmentV12> m_segments;
    std::vector<IoSegmentV12> m_exact_calls;
    std::string m_error;

    [[nodiscard]] bool Add(
        IoKindV12 kind, uint32_t elements, std::string* why);

public:
    [[nodiscard]] bool Absorb(uint32_t elements, std::string* why = nullptr);
    [[nodiscard]] bool Squeeze(uint32_t elements, std::string* why = nullptr);
    [[nodiscard]] bool Build(
        IoPatternV12& pattern, std::string* why = nullptr) const;
};

[[nodiscard]] bool ValidateIoPatternV12(
    const IoPatternV12& pattern, std::string* why = nullptr);

/**
 * SAFE's canonical word encoding (2023/522 section 3.3):
 *
 *   ABSORB(L)  -> BE32(0x80000000 | L)
 *   SQUEEZE(L) -> BE32(L)
 *
 * after contiguous calls of one kind have been aggregated.
 */
[[nodiscard]] bool CanonicalIoWordsV12(
    const IoPatternV12& pattern, std::vector<uint32_t>& words,
    std::string* why = nullptr);
[[nodiscard]] bool CanonicalIoBytesV12(
    const IoPatternV12& pattern, std::vector<uint8_t>& bytes,
    std::string* why = nullptr);

struct TagHashStatsV12 {
    uint64_t canonical_io_bytes{0};
    uint64_t framed_base_bytes{0};
    uint64_t candidate_preimage_bytes{0};
    uint64_t first_sha256_blocks_per_attempt{0};
    uint64_t logical_h_queries{0};
    uint64_t vector_attempts{0};
    uint64_t rejected_vectors{0};
    uint64_t sha256d_calls{0};
    uint64_t sha256_compression_blocks{0};
};

/**
 * Parse one 32-byte digest as four big-endian u64 candidates. Acceptance is
 * joint: every candidate must be less than p, otherwise the entire vector is
 * rejected.
 * No modular reduction is used.
 */
[[nodiscard]] bool AcceptTagVectorCandidateV12(
    const std::array<uint8_t, 32>& digest,
    std::array<gf::Fp, kSafeCapacityV12>& tag);

/**
 * Full-capacity H(IO,D)->Fp^4.
 *
 * Concrete H is a SHA256d counter-XOF.  Its canonical preimage is
 *
 *   "BTX_SAFECORE_H_IO_D_V12" ||
 *   BE32(protocol=12) || BE32(encoding=1) ||
 *   BE32(rate=8) || BE32(capacity=4) || BE32(width=12) ||
 *   BE32(full_rounds=8) || BE32(partial_rounds=22) ||
 *   BE32(sbox_power=7) || BE32(digest_lanes=4) ||
 *   BE32(Poseidon parameter id length) || parameter id ||
 *   BE32(io_word_count) || canonical_io_words ||
 *   BE64(domain_length) || domain ||
 *   BE64(rejection_counter).
 *
 * One SHA256d result is parsed jointly into Fp^4. Thus one construction call
 * is one vector-valued H query, exactly matching SAFECore's H:(IO,D)->Fp^c
 * interface; a noncanonical limb retries the whole vector with one counter.
 * The fixed Poseidon parameter id is kAlgHashDomainTag and binds the SAFE tag
 * to the frozen P,r,c parameter set. The retry cap is fail-closed (joint
 * Goldilocks-vector rejection probability is about 4*2^-32 per attempt).
 */
[[nodiscard]] bool DeriveTagV12(
    const IoPatternV12& pattern, const std::vector<uint8_t>& domain,
    std::array<gf::Fp, kSafeCapacityV12>& tag,
    TagHashStatsV12* stats = nullptr, std::string* why = nullptr);

/**
 * Typed domain bytes for one canonical V12 role plus application suffix.
 * The role is encoded explicitly; it is not folded into one Fp lane.
 */
[[nodiscard]] bool TypedDomainV12(
    aht::RoleV12 role, const std::vector<uint8_t>& application_domain,
    std::vector<uint8_t>& domain, std::string* why = nullptr);

enum class LifecycleV12 : uint8_t {
    Created = 0,
    Active = 1,
    Failed = 2,
    Finished = 3,
};

struct SafeStateSnapshotV12 {
    ah::State state{};
    LifecycleV12 lifecycle{LifecycleV12::Created};
    /** Index of the next exact online SAFE call. */
    uint32_t segment_index{0};
    /** Retained for wire/debug compatibility; exact calls are atomic. */
    uint32_t segment_used{0};
    uint32_t absorb_pos{0};
    uint32_t squeeze_pos{0};
    uint64_t permutation_calls{0};
};

/**
 * Stateful SAFE API. H(IO,D) uses the canonically aggregated pattern, while
 * each online ABSORB/SQUEEZE call must exactly match the schedule supplied to
 * START. Any misuse erases the state and makes the object permanently Failed.
 */
class SafeTranscriptV12
{
private:
    IoPatternV12 m_pattern;
    ah::State m_state{};
    LifecycleV12 m_lifecycle{LifecycleV12::Created};
    uint32_t m_call_index{0};
    uint32_t m_absorb_pos{0};
    uint32_t m_squeeze_pos{0};
    uint64_t m_permutation_calls{0};

    void Permute();
    void Erase(LifecycleV12 terminal);
    [[nodiscard]] bool Fail(std::string* why, const char* text);
    [[nodiscard]] bool CheckCall(
        IoKindV12 kind, uint32_t elements, std::string* why);
    void ConsumeCall(uint32_t elements);

public:
    [[nodiscard]] bool Start(
        const IoPatternV12& pattern, const std::vector<uint8_t>& domain,
        TagHashStatsV12* tag_stats = nullptr, std::string* why = nullptr);
    [[nodiscard]] bool Absorb(
        const std::vector<gf::Fp>& lanes, std::string* why = nullptr);
    [[nodiscard]] bool Squeeze(
        uint32_t elements, std::vector<gf::Fp>& lanes,
        std::string* why = nullptr);
    [[nodiscard]] bool Finish(std::string* why = nullptr);

    [[nodiscard]] SafeStateSnapshotV12 Snapshot() const;
};

struct SafeCoreCostV12 {
    uint64_t tag_sha256d_calls{0};
    uint64_t tag_sha256_compression_blocks{0};
    uint64_t absorb_poseidon_calls{0};
    uint64_t output_required_poseidon_calls{0};
    uint64_t published_algorithm_poseidon_calls{0};
    uint64_t output_required_poseidon_air_rows{0};
    uint64_t published_algorithm_poseidon_air_rows{0};
    uint64_t poseidon_air_columns{0};
};

struct SafeCoreResultV12 {
    std::vector<gf::Fp> output;
    /** State after the published Algorithm 3 post-output permutation(s). */
    ah::State final_state{};
    std::array<gf::Fp, kSafeCapacityV12> tag{};
    TagHashStatsV12 tag_stats{};
    SafeCoreCostV12 cost{};
};

/**
 * Exact stateless SAFECore Algorithm 3 for one absorb-prefix ending at
 * `squeeze_phase` (zero based). Message length must equal the sum of absorb
 * phase sizes through that phase. SAFECorePad uses ZERO padding to rate
 * boundaries and blank blocks for earlier squeeze phases; it never uses 10*.
 *
 * The implementation performs Algorithm 3's post-output P call even after the
 * final output block, so `published_algorithm_poseidon_calls` is exact.
 */
[[nodiscard]] bool EvaluateSafeCoreV12(
    const IoPatternV12& pattern, const std::vector<uint8_t>& domain,
    const std::vector<gf::Fp>& message, uint32_t squeeze_phase,
    SafeCoreResultV12& result, std::string* why = nullptr);

/**
 * Low-delta stateless digest candidate for the existing V11 hash DAG:
 * IO=(ABSORB(message.size), SQUEEZE(4)), with a typed role/domain.
 */
[[nodiscard]] bool SafeCoreDigestV12(
    aht::RoleV12 role, const std::vector<uint8_t>& application_domain,
    const std::vector<gf::Fp>& message, ah::Digest& digest,
    SafeCoreResultV12* audit = nullptr, std::string* why = nullptr);

struct SafeCorePrefixV12 {
    uint32_t squeeze_phase{0};
    std::vector<gf::Fp> output;
    /**
     * Published SAFECore state immediately after the last output lane and
     * before Algorithm 3's unobservable final post-output permutation.
     */
    ah::State state_before_final_output_permutation{};
    uint64_t output_required_poseidon_calls{0};
};

/**
 * Exact published SAFECore evaluator for an absorb prefix.  Unlike
 * EvaluateSafeCoreV12, this stops before Algorithm 3's unobservable final
 * post-output P.
 *
 * Do not treat this state as the online SAFE duplex state after an earlier
 * squeeze.  SAFECorePad Algorithm 2 inserts ceil(O_i/r) blank blocks between
 * phases, whereas online SAFE needs only the ceil(O_i/r)-1 permutations that
 * advance between visible output blocks.  The single-phase fixed-length hash
 * used by SafeCoreDigestV12 has no such intermediate phase.
 */
[[nodiscard]] bool EvaluateSafeCorePrefixV12(
    const IoPatternV12& pattern, const std::vector<uint8_t>& domain,
    const std::vector<gf::Fp>& message, uint32_t squeeze_phase,
    SafeCorePrefixV12& prefix, std::string* why = nullptr);

struct ManifestCallV12 {
    IoKindV12 kind{IoKindV12::Absorb};
    uint32_t elements{0};
    std::string label;
};

struct TranscriptPatternManifestV12 {
    uint32_t protocol_version{kSafeProtocolVersionV12};
    uint32_t encoding_version{kSafeEncodingVersionV1};
    std::vector<uint8_t> domain;
    std::vector<ManifestCallV12> exact_calls;
    IoPatternV12 canonical_pattern;
    std::vector<uint32_t> canonical_io_words;
    std::vector<uint8_t> canonical_io_bytes;
    std::array<gf::Fp, kSafeCapacityV12> tag{};
    TagHashStatsV12 tag_stats{};
    uint64_t absorb_elements{0};
    uint64_t squeeze_elements{0};
    uint64_t online_poseidon_calls{0};
    uint64_t online_poseidon_air_rows{0};
    uint64_t poseidon_air_columns{kPoseidonAirColumnsPerPermutationV12};
};

/**
 * Exact labelled transcript manifest. Labels preserve protocol call
 * boundaries for audit; H(IO,D) uses the canonical aggregation required by
 * SAFE. Duplicate or empty labels and zero-width declarations are rejected.
 */
class TranscriptPatternManifestBuilderV12
{
private:
    std::vector<ManifestCallV12> m_calls;
    std::string m_error;

    [[nodiscard]] bool Add(
        IoKindV12 kind, const std::string& label, uint32_t elements,
        std::string* why);

public:
    [[nodiscard]] bool Absorb(
        const std::string& label, uint32_t elements,
        std::string* why = nullptr);
    [[nodiscard]] bool Squeeze(
        const std::string& label, uint32_t elements,
        std::string* why = nullptr);
    [[nodiscard]] bool Build(
        const std::vector<uint8_t>& domain,
        TranscriptPatternManifestV12& manifest,
        std::string* why = nullptr) const;
};

// The native foundation is real; authority remains deliberately fail-closed.
inline constexpr bool kFullCapacityTagHashImplementedV12 = true;
inline constexpr bool kCanonicalAggregatedIoImplementedV12 = true;
inline constexpr bool kExactOnlineIoCallScheduleImplementedV12 = true;
inline constexpr bool kStatefulSafeApiImplementedV12 = true;
inline constexpr bool kPublishedSafeCoreInterphasePadExactV12 = true;
inline constexpr bool kOnlineAndSafeCoreInterphaseSemanticsSeparatedV12 = true;
inline constexpr bool kStatelessSafeCoreImplementedV12 = true;
inline constexpr bool kStatelessSafeCoreSupportsSeedFeedbackV12 = true;

inline constexpr bool kConcreteTagHashReductionCertifiedV12 = false;
inline constexpr bool kConcretePoseidonReductionCertifiedV12 = false;
inline constexpr bool kExactGlobalSafeQueryManifestEnforcedV12 = false;
inline constexpr bool kSafeDomainRegistryRootPinnedV12 = false;
inline constexpr bool kActiveNativeSafeMigrationV12 = false;
inline constexpr bool kRecursiveSafeAirExecutableV12 = false;
inline constexpr bool kNativeRecursiveSafeParityCertifiedV12 = false;

inline constexpr bool kStatelessSafeCoreAuthorityReadyV12 =
    kFullCapacityTagHashImplementedV12 &&
    kCanonicalAggregatedIoImplementedV12 &&
    kPublishedSafeCoreInterphasePadExactV12 &&
    kOnlineAndSafeCoreInterphaseSemanticsSeparatedV12 &&
    kStatelessSafeCoreImplementedV12 &&
    kStatelessSafeCoreSupportsSeedFeedbackV12 &&
    kConcreteTagHashReductionCertifiedV12 &&
    kConcretePoseidonReductionCertifiedV12 &&
    kExactGlobalSafeQueryManifestEnforcedV12 &&
    kSafeDomainRegistryRootPinnedV12 &&
    kActiveNativeSafeMigrationV12 &&
    kRecursiveSafeAirExecutableV12 &&
    kNativeRecursiveSafeParityCertifiedV12;

inline constexpr bool kSafeV12ProductionAuthorityReady =
    kStatelessSafeCoreAuthorityReadyV12;

} // namespace matmul::v4::rc::safe_v12

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_SAFE_V12_H
