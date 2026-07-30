// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_safe_v12.h>

#include <crypto/sha256.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <set>

namespace matmul::v4::rc::safe_v12 {
namespace {

constexpr char kTagHashDomain[] = "BTX_SAFECORE_H_IO_D_V12";
constexpr char kTypedDomainPrefix[] = "BTX_SAFECORE_ROLE_V12";

void SetError(std::string* why, const std::string& text)
{
    if (why != nullptr) *why = text;
}

bool KnownKind(IoKindV12 kind)
{
    return kind == IoKindV12::Absorb ||
           kind == IoKindV12::Squeeze;
}

void AppendBE32(std::vector<uint8_t>& out, uint32_t value)
{
    out.push_back(static_cast<uint8_t>(value >> 24));
    out.push_back(static_cast<uint8_t>(value >> 16));
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value));
}

void AppendBE64(std::vector<uint8_t>& out, uint64_t value)
{
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<uint8_t>(value >> shift));
    }
}

uint64_t ReadBE64(const uint8_t* bytes)
{
    uint64_t value = 0;
    for (uint32_t i = 0; i < 8; ++i) {
        value = (value << 8) | bytes[i];
    }
    return value;
}

std::array<uint8_t, 32> DoubleSha256(
    const std::vector<uint8_t>& bytes)
{
    std::array<uint8_t, 32> first{};
    std::array<uint8_t, 32> second{};
    CSHA256()
        .Write(bytes.data(), bytes.size())
        .Finalize(first.data());
    CSHA256()
        .Write(first.data(), first.size())
        .Finalize(second.data());
    return second;
}

uint64_t Sha256Blocks(uint64_t message_bytes)
{
    // SHA-256 appends one 0x80 byte and one BE64 bit length.
    return (message_bytes + 1 + 8 + 63) / 64;
}

uint64_t CeilDivRate(uint64_t elements)
{
    return (elements + kSafeRateV12 - 1) / kSafeRateV12;
}

bool CanonicalMessage(
    const std::vector<gf::Fp>& message, std::string* why)
{
    for (const gf::Fp value : message) {
        if (value >= gf::kP) {
            SetError(why, "SAFE message contains non-canonical field lane");
            return false;
        }
    }
    return true;
}

bool ExpectedPrefixLength(
    const IoPatternV12& pattern, uint32_t squeeze_phase,
    uint64_t& expected, std::string* why)
{
    if (!ValidateIoPatternV12(pattern, why)) return false;
    const uint32_t phases =
        static_cast<uint32_t>(pattern.segments.size() / 2);
    if (squeeze_phase >= phases) {
        SetError(why, "SAFECore squeeze phase out of range");
        return false;
    }
    expected = 0;
    for (uint32_t phase = 0; phase <= squeeze_phase; ++phase) {
        const uint32_t width = pattern.segments[2 * phase].elements;
        if (expected >
            std::numeric_limits<uint64_t>::max() - width) {
            SetError(why, "SAFECore prefix length overflow");
            return false;
        }
        expected += width;
    }
    return true;
}

void InitializeSafeState(
    const std::array<gf::Fp, kSafeCapacityV12>& tag,
    ah::State& state)
{
    state = {};
    std::copy(tag.begin(), tag.end(),
              state.begin() + kSafeRateV12);
}

void AbsorbPaddedPhase(
    ah::State& state, const std::vector<gf::Fp>& message,
    size_t offset, uint32_t elements, uint64_t& permutation_calls)
{
    const uint64_t blocks = CeilDivRate(elements);
    for (uint64_t block = 0; block < blocks; ++block) {
        for (uint32_t lane = 0; lane < kSafeRateV12; ++lane) {
            const uint64_t local = block * kSafeRateV12 + lane;
            const gf::Fp value =
                local < elements ? message[offset + local] : 0;
            state[lane] = gf::Add(state[lane], value);
        }
        ah::Permute(state);
        ++permutation_calls;
    }
}

void ApplySafeCoreBlankBlocks(
    ah::State& state, uint32_t squeeze_elements,
    uint64_t& permutation_calls)
{
    // ePrint 2023/520 SAFECorePad Algorithm 2 line 5 appends exactly
    // 0^(r*ceil(O_i/r)) for every completed earlier phase.  These are
    // full zero absorb blocks and each causes one Algorithm-3 permutation.
    //
    // This is deliberately NOT the online SAFE duplex transition count:
    // online output block one is already the state after the absorb->squeeze
    // permutation and therefore only ceil(O_i/r)-1 further permutations are
    // required to expose the remaining blocks.
    const uint64_t blocks = CeilDivRate(squeeze_elements);
    for (uint64_t block = 0; block < blocks; ++block) {
        ah::Permute(state);
        ++permutation_calls;
    }
}

bool BuildSafeCoreAbsorbState(
    const IoPatternV12& pattern, const std::vector<uint8_t>& domain,
    const std::vector<gf::Fp>& message, uint32_t squeeze_phase,
    ah::State& state,
    std::array<gf::Fp, kSafeCapacityV12>& tag,
    TagHashStatsV12& tag_stats, uint64_t& absorb_calls,
    std::string* why)
{
    uint64_t expected = 0;
    if (!ExpectedPrefixLength(
            pattern, squeeze_phase, expected, why)) {
        return false;
    }
    if (expected != message.size()) {
        SetError(why, "SAFECore message length does not match IO prefix");
        return false;
    }
    if (!CanonicalMessage(message, why)) return false;
    if (!DeriveTagV12(pattern, domain, tag, &tag_stats, why)) {
        return false;
    }

    InitializeSafeState(tag, state);
    absorb_calls = 0;
    size_t offset = 0;
    for (uint32_t phase = 0; phase <= squeeze_phase; ++phase) {
        const uint32_t input_elements =
            pattern.segments[2 * phase].elements;
        AbsorbPaddedPhase(
            state, message, offset, input_elements, absorb_calls);
        offset += input_elements;
        if (phase < squeeze_phase) {
            ApplySafeCoreBlankBlocks(
                state, pattern.segments[2 * phase + 1].elements,
                absorb_calls);
        }
    }
    return true;
}

} // namespace

bool IoPatternBuilderV12::Add(
    IoKindV12 kind, uint32_t elements, std::string* why)
{
    if (!m_error.empty()) {
        SetError(why, m_error);
        return false;
    }
    if (!KnownKind(kind)) {
        m_error = "SAFE IO pattern unknown operation";
        SetError(why, m_error);
        return false;
    }
    if (elements == 0 || elements > kSafeMaxIoElementsPerPhase) {
        m_error = "SAFE IO pattern operation length";
        SetError(why, m_error);
        return false;
    }
    if (m_exact_calls.size() >= kSafeMaxPatternSegments) {
        m_error = "SAFE IO pattern exact-call cap";
        SetError(why, m_error);
        return false;
    }
    if (!m_segments.empty() &&
        m_segments.back().kind == kind) {
        const uint64_t combined =
            static_cast<uint64_t>(m_segments.back().elements) +
            elements;
        if (combined > kSafeMaxIoElementsPerPhase) {
            m_error = "SAFE IO pattern aggregate overflow";
            SetError(why, m_error);
            return false;
        }
        m_segments.back().elements =
            static_cast<uint32_t>(combined);
        m_exact_calls.push_back({kind, elements});
        return true;
    }
    if (m_segments.size() >= kSafeMaxPatternSegments) {
        m_error = "SAFE IO pattern segment cap";
        SetError(why, m_error);
        return false;
    }
    m_segments.push_back({kind, elements});
    m_exact_calls.push_back({kind, elements});
    return true;
}

bool IoPatternBuilderV12::Absorb(
    uint32_t elements, std::string* why)
{
    return Add(IoKindV12::Absorb, elements, why);
}

bool IoPatternBuilderV12::Squeeze(
    uint32_t elements, std::string* why)
{
    return Add(IoKindV12::Squeeze, elements, why);
}

bool IoPatternBuilderV12::Build(
    IoPatternV12& pattern, std::string* why) const
{
    pattern = {};
    if (!m_error.empty()) {
        SetError(why, m_error);
        return false;
    }
    pattern.segments = m_segments;
    pattern.exact_calls = m_exact_calls;
    if (!ValidateIoPatternV12(pattern, why)) {
        pattern = {};
        return false;
    }
    return true;
}

bool ValidateIoPatternV12(
    const IoPatternV12& pattern, std::string* why)
{
    if (pattern.segments.empty() ||
        pattern.segments.size() > kSafeMaxPatternSegments ||
        (pattern.segments.size() & 1u) != 0) {
        SetError(why, "SAFE IO pattern must contain absorb/squeeze pairs");
        return false;
    }
    for (size_t i = 0; i < pattern.segments.size(); ++i) {
        const IoSegmentV12& segment = pattern.segments[i];
        const IoKindV12 expected =
            (i & 1u) == 0 ? IoKindV12::Absorb
                          : IoKindV12::Squeeze;
        if (!KnownKind(segment.kind) ||
            segment.kind != expected) {
            SetError(why, "SAFE IO pattern must alternate absorb/squeeze");
            return false;
        }
        if (segment.elements == 0 ||
            segment.elements > kSafeMaxIoElementsPerPhase) {
            SetError(why, "SAFE IO pattern non-canonical length");
            return false;
        }
    }
    if (!pattern.exact_calls.empty()) {
        if (pattern.exact_calls.size() > kSafeMaxPatternSegments) {
            SetError(why, "SAFE IO pattern exact-call cap");
            return false;
        }
        std::vector<IoSegmentV12> normalized;
        normalized.reserve(pattern.exact_calls.size());
        for (const IoSegmentV12& call : pattern.exact_calls) {
            if (!KnownKind(call.kind) || call.elements == 0 ||
                call.elements > kSafeMaxIoElementsPerPhase) {
                SetError(why, "SAFE IO pattern exact call invalid");
                return false;
            }
            if (!normalized.empty() &&
                normalized.back().kind == call.kind) {
                const uint64_t combined =
                    static_cast<uint64_t>(
                        normalized.back().elements) +
                    call.elements;
                if (combined > kSafeMaxIoElementsPerPhase) {
                    SetError(
                        why,
                        "SAFE IO pattern exact-call aggregate overflow");
                    return false;
                }
                normalized.back().elements =
                    static_cast<uint32_t>(combined);
            } else {
                normalized.push_back(call);
            }
        }
        if (normalized != pattern.segments) {
            SetError(
                why,
                "SAFE exact calls do not normalize to canonical IO");
            return false;
        }
    }
    return true;
}

bool CanonicalIoWordsV12(
    const IoPatternV12& pattern, std::vector<uint32_t>& words,
    std::string* why)
{
    words.clear();
    if (!ValidateIoPatternV12(pattern, why)) return false;
    words.reserve(pattern.segments.size());
    for (const IoSegmentV12& segment : pattern.segments) {
        const uint32_t kind =
            segment.kind == IoKindV12::Absorb
            ? UINT32_C(0x80000000) : 0;
        words.push_back(kind | segment.elements);
    }
    return true;
}

bool CanonicalIoBytesV12(
    const IoPatternV12& pattern, std::vector<uint8_t>& bytes,
    std::string* why)
{
    bytes.clear();
    std::vector<uint32_t> words;
    if (!CanonicalIoWordsV12(pattern, words, why)) return false;
    bytes.reserve(4 * words.size());
    for (const uint32_t word : words) AppendBE32(bytes, word);
    return true;
}

bool AcceptTagVectorCandidateV12(
    const std::array<uint8_t, 32>& digest,
    std::array<gf::Fp, kSafeCapacityV12>& tag)
{
    tag = {};
    std::array<gf::Fp, kSafeCapacityV12> candidate{};
    for (uint32_t lane = 0; lane < kSafeCapacityV12; ++lane) {
        candidate[lane] = ReadBE64(digest.data() + 8 * lane);
        if (candidate[lane] >= gf::kP) return false;
    }
    tag = candidate;
    return true;
}

bool DeriveTagV12(
    const IoPatternV12& pattern, const std::vector<uint8_t>& domain,
    std::array<gf::Fp, kSafeCapacityV12>& tag,
    TagHashStatsV12* stats, std::string* why)
{
    tag = {};
    TagHashStatsV12 local{};
    if (domain.size() > kSafeMaxDomainBytes) {
        SetError(why, "SAFE domain exceeds cap");
        if (stats != nullptr) *stats = local;
        return false;
    }

    std::vector<uint8_t> io_bytes;
    std::vector<uint32_t> io_words;
    if (!CanonicalIoBytesV12(pattern, io_bytes, why) ||
        !CanonicalIoWordsV12(pattern, io_words, why)) {
        if (stats != nullptr) *stats = local;
        return false;
    }

    std::vector<uint8_t> base;
    constexpr uint32_t parameter_id_bytes =
        sizeof(ah::kAlgHashDomainTag) - 1;
    base.reserve(
        sizeof(kTagHashDomain) - 1 +
        4 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 4 +
        4 + parameter_id_bytes + 4 +
        io_bytes.size() + 8 + domain.size());
    base.insert(
        base.end(),
        reinterpret_cast<const uint8_t*>(kTagHashDomain),
        reinterpret_cast<const uint8_t*>(kTagHashDomain) +
            sizeof(kTagHashDomain) - 1);
    AppendBE32(base, kSafeProtocolVersionV12);
    AppendBE32(base, kSafeEncodingVersionV1);
    AppendBE32(base, kSafeRateV12);
    AppendBE32(base, kSafeCapacityV12);
    AppendBE32(base, kSafeWidthV12);
    AppendBE32(base, ah::kAlgHashFullRounds);
    AppendBE32(base, ah::kAlgHashPartialRounds);
    AppendBE32(base, ah::kAlgHashSboxPower);
    AppendBE32(base, ah::kAlgHashDigestLen);
    AppendBE32(base, parameter_id_bytes);
    base.insert(
        base.end(),
        reinterpret_cast<const uint8_t*>(ah::kAlgHashDomainTag),
        reinterpret_cast<const uint8_t*>(ah::kAlgHashDomainTag) +
            parameter_id_bytes);
    AppendBE32(base, static_cast<uint32_t>(io_words.size()));
    base.insert(base.end(), io_bytes.begin(), io_bytes.end());
    AppendBE64(base, domain.size());
    base.insert(base.end(), domain.begin(), domain.end());

    local.canonical_io_bytes = io_bytes.size();
    local.framed_base_bytes = base.size();
    local.candidate_preimage_bytes = base.size() + 8;
    local.first_sha256_blocks_per_attempt =
        Sha256Blocks(local.candidate_preimage_bytes);
    local.logical_h_queries = 1;

    for (uint64_t counter = 0;
         counter < kSafeMaxTagVectorAttempts;
         ++counter) {
        std::vector<uint8_t> candidate = base;
        AppendBE64(candidate, counter);
        const std::array<uint8_t, 32> digest =
            DoubleSha256(candidate);
        ++local.vector_attempts;
        ++local.sha256d_calls;
        local.sha256_compression_blocks +=
            local.first_sha256_blocks_per_attempt + 1;
        if (AcceptTagVectorCandidateV12(digest, tag)) {
            if (stats != nullptr) *stats = local;
            return true;
        }
        ++local.rejected_vectors;
    }
    tag = {};
    if (stats != nullptr) *stats = local;
    SetError(why, "SAFE tag rejection sampler exhausted");
    return false;
}

bool TypedDomainV12(
    aht::RoleV12 role, const std::vector<uint8_t>& application_domain,
    std::vector<uint8_t>& domain, std::string* why)
{
    domain.clear();
    if (!aht::IsKnownRoleV12(role)) {
        SetError(why, "SAFE typed domain unknown role");
        return false;
    }
    if (application_domain.size() > kSafeMaxDomainBytes) {
        SetError(why, "SAFE typed application domain exceeds cap");
        return false;
    }
    domain.insert(
        domain.end(),
        reinterpret_cast<const uint8_t*>(kTypedDomainPrefix),
        reinterpret_cast<const uint8_t*>(kTypedDomainPrefix) +
            sizeof(kTypedDomainPrefix) - 1);
    AppendBE32(domain, kSafeProtocolVersionV12);
    AppendBE32(domain, static_cast<uint32_t>(role));
    AppendBE64(domain, application_domain.size());
    domain.insert(
        domain.end(), application_domain.begin(),
        application_domain.end());
    if (domain.size() > kSafeMaxDomainBytes) {
        domain.clear();
        SetError(why, "SAFE typed domain framing exceeds cap");
        return false;
    }
    return true;
}

void SafeTranscriptV12::Permute()
{
    ah::Permute(m_state);
    ++m_permutation_calls;
}

void SafeTranscriptV12::Erase(LifecycleV12 terminal)
{
    m_state = {};
    m_pattern = {};
    m_call_index = 0;
    m_absorb_pos = 0;
    m_squeeze_pos = 0;
    m_permutation_calls = 0;
    m_lifecycle = terminal;
}

bool SafeTranscriptV12::Fail(
    std::string* why, const char* text)
{
    SetError(why, text);
    Erase(LifecycleV12::Failed);
    return false;
}

bool SafeTranscriptV12::CheckCall(
    IoKindV12 kind, uint32_t elements, std::string* why)
{
    if (m_lifecycle != LifecycleV12::Active) {
        return Fail(why, "SAFE transcript is not active");
    }
    if (elements == 0) return true; // SAFE Algorithm 2 no-op.
    const std::vector<IoSegmentV12>& calls =
        m_pattern.exact_calls.empty()
        ? m_pattern.segments : m_pattern.exact_calls;
    if (m_call_index >= calls.size()) {
        return Fail(why, "SAFE transcript has no remaining operation");
    }
    const IoSegmentV12& call = calls[m_call_index];
    if (call.kind != kind) {
        return Fail(why, "SAFE transcript operation order mismatch");
    }
    if (call.elements != elements) {
        return Fail(why, "SAFE transcript exact call length mismatch");
    }
    return true;
}

void SafeTranscriptV12::ConsumeCall(uint32_t elements)
{
    if (elements == 0) return;
    ++m_call_index;
}

bool SafeTranscriptV12::Start(
    const IoPatternV12& pattern, const std::vector<uint8_t>& domain,
    TagHashStatsV12* tag_stats, std::string* why)
{
    if (m_lifecycle != LifecycleV12::Created) {
        return Fail(why, "SAFE START may be called exactly once");
    }
    if (!ValidateIoPatternV12(pattern, why)) {
        Erase(LifecycleV12::Failed);
        return false;
    }
    std::array<gf::Fp, kSafeCapacityV12> tag{};
    if (!DeriveTagV12(pattern, domain, tag, tag_stats, why)) {
        Erase(LifecycleV12::Failed);
        return false;
    }
    m_pattern = pattern;
    InitializeSafeState(tag, m_state);
    m_call_index = 0;
    m_absorb_pos = 0;
    m_squeeze_pos = 0;
    m_permutation_calls = 0;
    m_lifecycle = LifecycleV12::Active;
    return true;
}

bool SafeTranscriptV12::Absorb(
    const std::vector<gf::Fp>& lanes, std::string* why)
{
    if (lanes.size() >
        std::numeric_limits<uint32_t>::max()) {
        return Fail(why, "SAFE absorb call length overflow");
    }
    const uint32_t elements =
        static_cast<uint32_t>(lanes.size());
    if (!CheckCall(IoKindV12::Absorb, elements, why)) {
        return false;
    }
    if (!CanonicalMessage(lanes, why)) {
        Erase(LifecycleV12::Failed);
        return false;
    }
    for (const gf::Fp lane : lanes) {
        if (m_absorb_pos == kSafeRateV12) {
            Permute();
            m_absorb_pos = 0;
        }
        m_state[m_absorb_pos] =
            gf::Add(m_state[m_absorb_pos], lane);
        ++m_absorb_pos;
    }
    if (elements != 0) {
        // Force P before the next squeeze, as SAFE Algorithm 2 specifies.
        m_squeeze_pos = kSafeRateV12;
    }
    ConsumeCall(elements);
    return true;
}

bool SafeTranscriptV12::Squeeze(
    uint32_t elements, std::vector<gf::Fp>& lanes,
    std::string* why)
{
    lanes.clear();
    if (!CheckCall(IoKindV12::Squeeze, elements, why)) {
        return false;
    }
    lanes.reserve(elements);
    for (uint32_t i = 0; i < elements; ++i) {
        if (m_squeeze_pos == kSafeRateV12) {
            Permute();
            m_squeeze_pos = 0;
            m_absorb_pos = 0;
        }
        lanes.push_back(m_state[m_squeeze_pos]);
        ++m_squeeze_pos;
    }
    ConsumeCall(elements);
    return true;
}

bool SafeTranscriptV12::Finish(std::string* why)
{
    if (m_lifecycle != LifecycleV12::Active) {
        return Fail(why, "SAFE FINISH requires active transcript");
    }
    const size_t expected_calls =
        m_pattern.exact_calls.empty()
        ? m_pattern.segments.size()
        : m_pattern.exact_calls.size();
    if (m_call_index != expected_calls) {
        return Fail(why, "SAFE FINISH before IO pattern completion");
    }
    Erase(LifecycleV12::Finished);
    return true;
}

SafeStateSnapshotV12 SafeTranscriptV12::Snapshot() const
{
    return {
        m_state,
        m_lifecycle,
        m_call_index,
        0,
        m_absorb_pos,
        m_squeeze_pos,
        m_permutation_calls,
    };
}

bool EvaluateSafeCoreV12(
    const IoPatternV12& pattern, const std::vector<uint8_t>& domain,
    const std::vector<gf::Fp>& message, uint32_t squeeze_phase,
    SafeCoreResultV12& result, std::string* why)
{
    result = {};
    uint64_t absorb_calls = 0;
    if (!BuildSafeCoreAbsorbState(
            pattern, domain, message, squeeze_phase,
            result.final_state, result.tag, result.tag_stats,
            absorb_calls, why)) {
        return false;
    }

    const uint32_t output_elements =
        pattern.segments[2 * squeeze_phase + 1].elements;
    const uint64_t output_blocks =
        CeilDivRate(output_elements);
    result.output.reserve(output_elements);
    for (uint64_t block = 0; block < output_blocks; ++block) {
        const uint32_t take = static_cast<uint32_t>(
            std::min<uint64_t>(
                kSafeRateV12,
                output_elements - result.output.size()));
        result.output.insert(
            result.output.end(), result.final_state.begin(),
            result.final_state.begin() + take);
        // Algorithm 3 line 10 calls P after EVERY output block, including the
        // final block. The output is already fixed, but the call is retained
        // so cost and final state are specification-exact.
        ah::Permute(result.final_state);
    }

    result.cost.tag_sha256d_calls =
        result.tag_stats.sha256d_calls;
    result.cost.tag_sha256_compression_blocks =
        result.tag_stats.sha256_compression_blocks;
    result.cost.absorb_poseidon_calls = absorb_calls;
    result.cost.output_required_poseidon_calls =
        absorb_calls + output_blocks - 1;
    result.cost.published_algorithm_poseidon_calls =
        absorb_calls + output_blocks;
    result.cost.output_required_poseidon_air_rows =
        result.cost.output_required_poseidon_calls *
        kPoseidonAirRowsPerPermutationV12;
    result.cost.published_algorithm_poseidon_air_rows =
        result.cost.published_algorithm_poseidon_calls *
        kPoseidonAirRowsPerPermutationV12;
    result.cost.poseidon_air_columns =
        kPoseidonAirColumnsPerPermutationV12;
    return true;
}

bool SafeCoreDigestV12(
    aht::RoleV12 role, const std::vector<uint8_t>& application_domain,
    const std::vector<gf::Fp>& message, ah::Digest& digest,
    SafeCoreResultV12* audit, std::string* why)
{
    digest = {};
    if (message.empty() ||
        message.size() > kSafeMaxIoElementsPerPhase) {
        SetError(why, "SAFECore digest message length");
        if (audit != nullptr) *audit = {};
        return false;
    }
    std::vector<uint8_t> domain;
    if (!TypedDomainV12(
            role, application_domain, domain, why)) {
        if (audit != nullptr) *audit = {};
        return false;
    }
    IoPatternBuilderV12 builder;
    IoPatternV12 pattern;
    if (!builder.Absorb(
            static_cast<uint32_t>(message.size()), why) ||
        !builder.Squeeze(ah::kAlgHashDigestLen, why) ||
        !builder.Build(pattern, why)) {
        if (audit != nullptr) *audit = {};
        return false;
    }
    SafeCoreResultV12 result;
    if (!EvaluateSafeCoreV12(
            pattern, domain, message, 0, result, why)) {
        if (audit != nullptr) *audit = {};
        return false;
    }
    if (result.output.size() != ah::kAlgHashDigestLen) {
        SetError(why, "SAFECore digest output width");
        if (audit != nullptr) *audit = {};
        return false;
    }
    std::copy(result.output.begin(), result.output.end(),
              digest.begin());
    if (audit != nullptr) *audit = std::move(result);
    return true;
}

bool EvaluateSafeCorePrefixV12(
    const IoPatternV12& pattern, const std::vector<uint8_t>& domain,
    const std::vector<gf::Fp>& message, uint32_t squeeze_phase,
    SafeCorePrefixV12& prefix, std::string* why)
{
    prefix = {};
    ah::State state{};
    std::array<gf::Fp, kSafeCapacityV12> tag{};
    TagHashStatsV12 tag_stats{};
    uint64_t absorb_calls = 0;
    if (!BuildSafeCoreAbsorbState(
            pattern, domain, message, squeeze_phase, state,
            tag, tag_stats, absorb_calls, why)) {
        return false;
    }

    const uint32_t output_elements =
        pattern.segments[2 * squeeze_phase + 1].elements;
    const uint64_t output_blocks =
        CeilDivRate(output_elements);
    prefix.squeeze_phase = squeeze_phase;
    prefix.output.reserve(output_elements);
    for (uint64_t block = 0; block < output_blocks; ++block) {
        const uint32_t take = static_cast<uint32_t>(
            std::min<uint64_t>(
                kSafeRateV12,
                output_elements - prefix.output.size()));
        prefix.output.insert(
            prefix.output.end(), state.begin(), state.begin() + take);
        // Stop before the unobservable final post-output permutation. For a
        // single phase this is also the online SAFE state at that boundary;
        // for later phases SAFECorePad's full blank-block convention makes
        // the published SAFECore state intentionally different.
        if (block + 1 < output_blocks) ah::Permute(state);
    }
    prefix.state_before_final_output_permutation = state;
    prefix.output_required_poseidon_calls =
        absorb_calls + output_blocks - 1;
    return true;
}

bool TranscriptPatternManifestBuilderV12::Add(
    IoKindV12 kind, const std::string& label, uint32_t elements,
    std::string* why)
{
    if (!m_error.empty()) {
        SetError(why, m_error);
        return false;
    }
    if (!KnownKind(kind)) {
        m_error = "SAFE manifest unknown operation";
        SetError(why, m_error);
        return false;
    }
    if (label.empty()) {
        m_error = "SAFE manifest empty label";
        SetError(why, m_error);
        return false;
    }
    if (elements == 0 ||
        elements > kSafeMaxIoElementsPerPhase) {
        m_error = "SAFE manifest operation length";
        SetError(why, m_error);
        return false;
    }
    if (m_calls.size() >= kSafeMaxPatternSegments) {
        m_error = "SAFE manifest exact-call cap";
        SetError(why, m_error);
        return false;
    }
    for (const ManifestCallV12& call : m_calls) {
        if (call.label == label) {
            m_error = "SAFE manifest duplicate label";
            SetError(why, m_error);
            return false;
        }
    }
    m_calls.push_back({kind, elements, label});
    return true;
}

bool TranscriptPatternManifestBuilderV12::Absorb(
    const std::string& label, uint32_t elements, std::string* why)
{
    return Add(IoKindV12::Absorb, label, elements, why);
}

bool TranscriptPatternManifestBuilderV12::Squeeze(
    const std::string& label, uint32_t elements, std::string* why)
{
    return Add(IoKindV12::Squeeze, label, elements, why);
}

bool TranscriptPatternManifestBuilderV12::Build(
    const std::vector<uint8_t>& domain,
    TranscriptPatternManifestV12& manifest,
    std::string* why) const
{
    manifest = {};
    if (!m_error.empty()) {
        SetError(why, m_error);
        return false;
    }
    IoPatternBuilderV12 pattern_builder;
    for (const ManifestCallV12& call : m_calls) {
        const bool ok =
            call.kind == IoKindV12::Absorb
            ? pattern_builder.Absorb(call.elements, why)
            : pattern_builder.Squeeze(call.elements, why);
        if (!ok) return false;
    }
    if (!pattern_builder.Build(
            manifest.canonical_pattern, why) ||
        !CanonicalIoWordsV12(
            manifest.canonical_pattern,
            manifest.canonical_io_words, why) ||
        !CanonicalIoBytesV12(
            manifest.canonical_pattern,
            manifest.canonical_io_bytes, why) ||
        !DeriveTagV12(
            manifest.canonical_pattern, domain, manifest.tag,
            &manifest.tag_stats, why)) {
        manifest = {};
        return false;
    }
    manifest.protocol_version = kSafeProtocolVersionV12;
    manifest.encoding_version = kSafeEncodingVersionV1;
    manifest.domain = domain;
    manifest.exact_calls = m_calls;
    for (const IoSegmentV12& segment :
         manifest.canonical_pattern.segments) {
        if (segment.kind == IoKindV12::Absorb) {
            manifest.absorb_elements += segment.elements;
            manifest.online_poseidon_calls +=
                CeilDivRate(segment.elements);
        } else {
            manifest.squeeze_elements += segment.elements;
            manifest.online_poseidon_calls +=
                CeilDivRate(segment.elements) - 1;
        }
    }
    manifest.online_poseidon_air_rows =
        manifest.online_poseidon_calls *
        kPoseidonAirRowsPerPermutationV12;
    manifest.poseidon_air_columns =
        kPoseidonAirColumnsPerPermutationV12;
    return true;
}

} // namespace matmul::v4::rc::safe_v12
