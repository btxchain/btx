// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_ctl.h>

#include <crypto/sha256.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>

namespace matmul::v4::rc {
namespace {

namespace aq = air_quotient;
namespace gf = gkr_field;
using gf::Fp3;
using CS = aq::AirConstraintSystem<Fp3>;

constexpr size_t PIN_BYTES = 212;

bool Fail(std::string* why, const std::string& message)
{
    if (why != nullptr) *why = "stage3:ctl:" + message;
    return false;
}

template <typename T>
std::optional<T> FailOptional(std::string* why, const std::string& message)
{
    Fail(why, message);
    return std::nullopt;
}

void WriteU16(std::vector<unsigned char>& out, uint16_t value)
{
    out.push_back(static_cast<unsigned char>(value));
    out.push_back(static_cast<unsigned char>(value >> 8));
}

void WriteU32(std::vector<unsigned char>& out, uint32_t value)
{
    for (uint32_t i = 0; i < 4; ++i) {
        out.push_back(static_cast<unsigned char>(value >> (8U * i)));
    }
}

void WriteU64(std::vector<unsigned char>& out, uint64_t value)
{
    for (uint32_t i = 0; i < 8; ++i) {
        out.push_back(static_cast<unsigned char>(value >> (8U * i)));
    }
}

void WriteHash(std::vector<unsigned char>& out, const uint256& value)
{
    out.insert(out.end(), value.begin(), value.end());
}

void WriteFp3(std::vector<unsigned char>& out, const Fp3& value)
{
    WriteU64(out, value.c0);
    WriteU64(out, value.c1);
    WriteU64(out, value.c2);
}

void WriteDomain(std::vector<unsigned char>& out, const char* domain)
{
    const auto* begin = reinterpret_cast<const unsigned char*>(domain);
    out.insert(out.end(), begin, begin + std::strlen(domain));
}

uint256 Sha256d(const std::vector<unsigned char>& bytes)
{
    uint8_t first[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(bytes.data(), bytes.size()).Finalize(first);
    uint8_t second[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(first, sizeof(first)).Finalize(second);
    uint256 result;
    std::memcpy(result.data(), second, result.size());
    return result;
}

class Reader {
public:
    explicit Reader(const std::vector<unsigned char>& bytes) : m_bytes(bytes) {}

    bool U16(uint16_t& out)
    {
        if (Remaining() < 2) return false;
        out = static_cast<uint16_t>(m_bytes[m_pos]) |
              (static_cast<uint16_t>(m_bytes[m_pos + 1]) << 8);
        m_pos += 2;
        return true;
    }

    bool U32(uint32_t& out)
    {
        if (Remaining() < 4) return false;
        out = 0;
        for (uint32_t i = 0; i < 4; ++i) {
            out |= static_cast<uint32_t>(m_bytes[m_pos + i]) << (8U * i);
        }
        m_pos += 4;
        return true;
    }

    bool U64(uint64_t& out)
    {
        if (Remaining() < 8) return false;
        out = 0;
        for (uint32_t i = 0; i < 8; ++i) {
            out |= static_cast<uint64_t>(m_bytes[m_pos + i]) << (8U * i);
        }
        m_pos += 8;
        return true;
    }

    bool Hash(uint256& out)
    {
        if (Remaining() < out.size()) return false;
        std::copy_n(m_bytes.data() + m_pos, out.size(), out.data());
        m_pos += out.size();
        return true;
    }

    bool Field(Fp3& out)
    {
        return U64(out.c0) && U64(out.c1) && U64(out.c2);
    }

    [[nodiscard]] size_t Remaining() const { return m_bytes.size() - m_pos; }

private:
    const std::vector<unsigned char>& m_bytes;
    size_t m_pos{0};
};

bool Canonical(const Fp3& value)
{
    return value.c0 < gf::kP && value.c1 < gf::kP && value.c2 < gf::kP;
}

bool KnownRole(RCStage3RelationRole role)
{
    return std::strcmp(RCStage3RelationRoleName(role), "unknown") != 0;
}

bool CheckedAdd(uint64_t a, uint64_t b, uint64_t& out)
{
    if (a > std::numeric_limits<uint64_t>::max() - b) return false;
    out = a + b;
    return true;
}

bool CountScheduleEvents(const RCStage3CtlSchedule& schedule,
                         uint64_t& event_count,
                         uint64_t& send_count,
                         uint64_t& receive_count)
{
    event_count = 0;
    send_count = 0;
    receive_count = 0;
    for (const auto& event : schedule.events) {
        uint64_t next{0};
        if (!CheckedAdd(event_count, 1, next)) return false;
        event_count = next;
        if (event.multiplicity == 1) {
            if (!CheckedAdd(send_count, 1, next)) return false;
            send_count = next;
        } else if (event.multiplicity == -1) {
            if (!CheckedAdd(receive_count, 1, next)) return false;
            receive_count = next;
        } else {
            return false;
        }
    }
    return true;
}

uint32_t NextPow2(size_t count)
{
    uint32_t result = 2;
    while (result < count) result <<= 1;
    return result;
}

bool ValidateManifest(const RCStage3CtlManifest& manifest, std::string* why)
{
    if (manifest.bus_id == 0) return Fail(why, "manifest:zero_bus");
    if (manifest.transcript_seed.IsNull()) {
        return Fail(why, "manifest:null_transcript_seed");
    }
    if (manifest.participants.empty() ||
        manifest.participants.size() > kRCStage3MaxRelationSections) {
        return Fail(why, "manifest:participant_count");
    }
    uint16_t previous = 0;
    for (const auto& participant : manifest.participants) {
        const uint16_t role = static_cast<uint16_t>(participant.role);
        if (!KnownRole(participant.role) || role <= previous) {
            return Fail(why, "manifest:role_order");
        }
        previous = role;
        uint64_t total{0};
        if (!CheckedAdd(participant.send_count, participant.receive_count, total) ||
            participant.event_count != total || participant.event_count == 0 ||
            participant.event_count > kRCStage3CtlMaxEvents) {
            return Fail(why, "manifest:event_counts");
        }
        if (participant.schedule_commitment.IsNull()) {
            return Fail(why, "manifest:null_schedule");
        }
    }
    return true;
}

bool ValidatePin(const RCStage3CtlChildPin& pin, std::string* why,
                 bool require_postchallenge)
{
    if (pin.magic != kRCStage3CtlPinMagic) return Fail(why, "pin:bad_magic");
    if (pin.version != kRCStage3CtlVersion) return Fail(why, "pin:bad_version");
    if (!KnownRole(pin.role)) return Fail(why, "pin:bad_role");
    if (pin.bus_id == 0) return Fail(why, "pin:zero_bus");
    uint64_t total{0};
    if (!CheckedAdd(pin.send_count, pin.receive_count, total) ||
        pin.event_count != total || pin.event_count == 0 ||
        pin.event_count > kRCStage3CtlMaxEvents) {
        return Fail(why, "pin:event_counts");
    }
    if (pin.schedule_commitment.IsNull() || pin.trace_commitment.IsNull()) {
        return Fail(why, "pin:null_prechallenge_commitment");
    }
    if (require_postchallenge &&
        (pin.auxiliary_commitment.IsNull() || pin.challenge_commitment.IsNull())) {
        return Fail(why, "pin:null_postchallenge_commitment");
    }
    if (!Canonical(pin.terminal.alpha1_sum) ||
        !Canonical(pin.terminal.alpha2_sum)) {
        return Fail(why, "pin:noncanonical_terminal");
    }
    return true;
}

bool ValidateRelationExportPin(
    const RCStage3CtlRelationExportPin& pin,
    std::string* why)
{
    if (pin.magic != kRCStage3CtlRelationExportMagic) {
        return Fail(why, "relation_export:bad_magic");
    }
    if (pin.version != kRCStage3CtlRelationExportVersion) {
        return Fail(why, "relation_export:bad_version");
    }
    if (!KnownRole(pin.role) || pin.bus_id == 0 ||
        pin.event_count == 0 ||
        pin.event_count > kRCStage3CtlMaxEvents ||
        pin.relation_commitment.IsNull() ||
        pin.schedule_commitment.IsNull() ||
        pin.n_rows < 2 || pin.n_coeffs < pin.n_rows) {
        return Fail(why, "relation_export:shape");
    }
    for (const auto& root : pin.prechallenge_column_roots) {
        if (root.IsNull()) return Fail(why, "relation_export:null_root");
    }
    return true;
}

void WriteParticipant(std::vector<unsigned char>& out,
                      const RCStage3CtlParticipantSpec& participant)
{
    WriteU16(out, static_cast<uint16_t>(participant.role));
    WriteU64(out, participant.event_count);
    WriteU64(out, participant.send_count);
    WriteU64(out, participant.receive_count);
    WriteHash(out, participant.schedule_commitment);
}

uint256 CommitManifest(const RCStage3CtlManifest& manifest)
{
    std::string ignored;
    if (!ValidateManifest(manifest, &ignored)) return {};
    std::vector<unsigned char> bytes;
    WriteDomain(bytes, "BTX_RC_STAGE3_CTL_MANIFEST_V1");
    WriteU32(bytes, manifest.bus_id);
    WriteHash(bytes, manifest.transcript_seed);
    WriteU16(bytes, static_cast<uint16_t>(manifest.participants.size()));
    for (const auto& participant : manifest.participants) {
        WriteParticipant(bytes, participant);
    }
    return Sha256d(bytes);
}

bool Challenge(const uint256& seed, const char* label, uint32_t counter,
               Fp3& out)
{
    std::array<gf::Fp, 3> limbs{};
    uint32_t accepted = 0;
    for (uint32_t block = 0;
         block < kRCStage3CtlChallengeBlockCount;
         ++block) {
        std::vector<unsigned char> bytes;
        WriteDomain(bytes, "BTX_RC_STAGE3_CTL_CHALLENGE_BLOCK_V3");
        WriteHash(bytes, seed);
        WriteDomain(bytes, label);
        WriteU32(bytes, counter);
        WriteU32(bytes, block);
        const uint256 digest = Sha256d(bytes);
        for (uint32_t offset = 0;
             offset < kRCStage3CtlChallengeWordsPerBlock;
             ++offset) {
            uint64_t word{0};
            for (uint32_t byte = 0; byte < 8; ++byte) {
                word |= static_cast<uint64_t>(
                            digest.data()[8 * offset + byte])
                        << (8U * byte);
            }
            if (RCStage3CtlChallengeWordIsAccepted(word) &&
                accepted < limbs.size()) {
                limbs[accepted++] = static_cast<gf::Fp>(word);
            }
        }
    }
    // Fewer than three accepted words requires at least six of eight words
    // to fall in [p,2^64), an event below 28*2^-192 < 2^-187.
    if (accepted != limbs.size()) return false;
    out = {limbs[0], limbs[1], limbs[2]};
    return true;
}

bool ValidChallenges(const RCStage3CtlChallenges& challenges)
{
    return Canonical(challenges.gamma1) &&
           Canonical(challenges.gamma2) &&
           Canonical(challenges.alpha1) &&
           Canonical(challenges.alpha2) &&
           !gf::IsZero(challenges.gamma1) &&
           !gf::IsZero(challenges.gamma2) &&
           !gf::Eq(challenges.gamma1, challenges.gamma2) &&
           !gf::Eq(challenges.alpha1, challenges.alpha2);
}

void Add(CS& cs, const char* name, aq::AirKind kind, uint32_t degree,
         std::function<Fp3(const std::vector<Fp3>&, const std::vector<Fp3>&)> eval)
{
    cs.constraints.push_back({name, kind, degree, std::move(eval)});
}

Fp3 CompressRow(const std::vector<Fp3>& row, const Fp3& gamma)
{
    using namespace stage3_ctl_col;
    const Fp3 gamma2 = gf::Mul(gamma, gamma);
    const Fp3 gamma3 = gf::Mul(gamma2, gamma);
    return gf::Add(
        row[NAMESPACE],
        gf::Add(gf::Mul(gamma, row[STAGE]),
                gf::Add(gf::Mul(gamma2, row[ADDRESS]),
                        gf::Mul(gamma3, row[VALUE]))));
}

void HashLimbs(const uint256& hash, std::vector<Fp3>& out)
{
    for (uint32_t limb = 0; limb < 8; ++limb) {
        uint32_t value = 0;
        for (uint32_t byte = 0; byte < 4; ++byte) {
            value |= static_cast<uint32_t>(hash.data()[limb * 4 + byte])
                     << (8U * byte);
        }
        out.push_back(gf::FromU64_3(value));
    }
}

uint32_t CeilLog2U64(uint64_t value)
{
    if (value <= 1) return 0;
    uint32_t bits = 0;
    --value;
    while (value != 0) {
        value >>= 1;
        ++bits;
    }
    return bits;
}

uint32_t ConservativeBits(uint32_t field_bits, uint64_t numerator,
                          uint32_t grinding_bits,
                          uint64_t invocation_union_bound)
{
    if (numerator == 0 || invocation_union_bound == 0) return 0;
    const uint64_t loss =
        static_cast<uint64_t>(CeilLog2U64(numerator)) +
        CeilLog2U64(invocation_union_bound) + grinding_bits;
    return loss >= field_bits
        ? 0
        : field_bits - static_cast<uint32_t>(loss);
}

uint256 CommitPrechallengeRoots(
    const RCStage3CtlSchedule& schedule,
    uint32_t n_rows,
    uint32_t n_coeffs,
    const std::array<uint256, 5>& roots)
{
    const uint256 schedule_commitment =
        CommitRCStage3CtlSchedule(schedule);
    if (schedule_commitment.IsNull()) return {};
    for (const auto& root : roots) {
        if (root.IsNull()) return {};
    }
    std::vector<unsigned char> bytes;
    WriteDomain(bytes, "BTX_RC_STAGE3_CTL_TRACE_EPOCH1_V3");
    WriteHash(bytes, schedule_commitment);
    WriteU32(bytes, n_rows);
    WriteU32(bytes, n_coeffs);
    for (const auto& root : roots) WriteHash(bytes, root);
    return Sha256d(bytes);
}

uint256 CommitPrechallengeProofRoots(
    const RCStage3CtlSchedule& schedule,
    const RCStage3CtlAirProof& proof)
{
    using namespace stage3_ctl_col;
    if (proof.batch.columns.size() != NUM_COLUMNS + 1 ||
        proof.batch.column_len.size() != NUM_COLUMNS + 1) {
        return {};
    }
    std::array<uint256, 5> roots{};
    for (uint32_t column = NAMESPACE; column <= MULTIPLICITY; ++column) {
        roots[column] = proof.batch.columns[column].root;
    }
    return CommitPrechallengeRoots(
        schedule, proof.batch.column_len[NAMESPACE],
        proof.batch.n_coeffs, roots);
}

} // namespace

RCStage3CtlSoundnessLedger AssessRCStage3CtlSoundness(
    const std::vector<RCStage3CtlManifest>& manifests,
    uint32_t grinding_bits,
    uint64_t invocation_union_bound)
{
    RCStage3CtlSoundnessLedger out;
    if (manifests.empty() || invocation_union_bound == 0) return out;

    std::vector<uint32_t> bus_ids;
    bus_ids.reserve(manifests.size());
    uint64_t dual_numerator{0};
    uint64_t pole_numerator{0};
    for (const auto& manifest : manifests) {
        if (!ValidateManifest(manifest, nullptr) ||
            std::find(bus_ids.begin(), bus_ids.end(), manifest.bus_id) !=
                bus_ids.end()) {
            return {};
        }
        bus_ids.push_back(manifest.bus_id);

        uint64_t events{0};
        uint64_t sends{0};
        uint64_t receives{0};
        for (const auto& participant : manifest.participants) {
            if (!CheckedAdd(events, participant.event_count, events) ||
                !CheckedAdd(sends, participant.send_count, sends) ||
                !CheckedAdd(receives, participant.receive_count, receives)) {
                return {};
            }
        }
        if (events < 2 || sends != receives) return {};
        if (!CheckedAdd(out.total_events, events, out.total_events)) return {};

        // Per lane: at most 3(E-1) tuple-compression roots plus E-1
        // rational-numerator roots.  The two independently sampled lanes
        // both have to accept.
        const uint64_t one_lane = 4 * (events - 1);
        if (one_lane >
            std::numeric_limits<uint64_t>::max() / one_lane) {
            return {};
        }
        const uint64_t bus_dual = one_lane * one_lane;
        if (!CheckedAdd(dual_numerator, bus_dual, dual_numerator)) return {};

        // Two alpha lanes.  A pole makes an inverse constraint impossible,
        // so this is an honest-prover failure probability only.
        if (events > std::numeric_limits<uint64_t>::max() / 2 ||
            !CheckedAdd(pole_numerator, 2 * events, pole_numerator)) {
            return {};
        }
    }

    out.bus_count = manifests.size();
    out.dual_lane_false_accept_numerator = dual_numerator;
    out.pole_completeness_numerator = pole_numerator;
    out.algebraic_bits_before_losses =
        ConservativeBits(378, dual_numerator, 0, 1);
    out.false_accept_bits_after_losses =
        ConservativeBits(378, dual_numerator, grinding_bits,
                         invocation_union_bound);
    out.pole_completeness_bits_after_losses =
        ConservativeBits(189, pole_numerator, grinding_bits,
                         invocation_union_bound);
    // At most 25 Fp3 candidate draws per bus: eight each for gamma1,
    // gamma2 and alpha2, plus alpha1.  Each two-block sampler exhausts with
    // probability < 2^-187.  This is liveness only.
    constexpr uint64_t CANDIDATES_PER_BUS =
        3 * kRCStage3CtlChallengeMaxCandidates + 1;
    if (manifests.size() >
        std::numeric_limits<uint64_t>::max() / CANDIDATES_PER_BUS) {
        return {};
    }
    const uint64_t max_candidate_draws =
        static_cast<uint64_t>(manifests.size()) * CANDIDATES_PER_BUS;
    const uint64_t sampler_loss =
        static_cast<uint64_t>(CeilLog2U64(
            std::max<uint64_t>(1, max_candidate_draws))) +
        CeilLog2U64(invocation_union_bound) + grinding_bits;
    out.sampler_exhaustion_bits_after_losses =
        sampler_loss >= 187
            ? 0
            : 187 - static_cast<uint32_t>(sampler_loss);
    out.manifests_exact = true;
    // These are structural properties of DeriveRCStage3CtlChallenges:
    // epoch-1 trace roots are absorbed before the labelled challenges, and
    // gamma1/gamma2/alpha1/alpha2 use separate labels with distinctness
    // rejection.  The external FS/BCS theorem is deliberately not inferred.
    out.commit_then_challenge = true;
    out.independent_domain_separated_lanes = true;
    out.uniform_challenge_sampling = kRCStage3CtlUniformChallengeSampling;
    out.bounded_challenge_sampling =
        kRCStage3CtlChallengeBlockCount == 2 &&
        kRCStage3CtlChallengeWordsPerBlock == 4 &&
        kRCStage3CtlChallengeMaxCandidates != 0;
    out.reduction_complete = false;
    return out;
}

bool ValidateRCStage3CtlSchedule(const RCStage3CtlSchedule& schedule,
                                 std::string* why)
{
    if (schedule.events.empty() ||
        schedule.events.size() > kRCStage3CtlMaxEvents) {
        return Fail(why, "schedule:event_count");
    }
    for (const auto& event : schedule.events) {
        if (event.namespace_id == 0) return Fail(why, "schedule:zero_namespace");
        if (event.multiplicity != 1 && event.multiplicity != -1) {
            return Fail(why, "schedule:multiplicity");
        }
    }
    if (why != nullptr) *why = "stage3:ctl:ok";
    return true;
}

uint256 CommitRCStage3CtlSchedule(const RCStage3CtlSchedule& schedule)
{
    std::string ignored;
    if (!ValidateRCStage3CtlSchedule(schedule, &ignored)) return {};
    std::vector<unsigned char> bytes;
    WriteDomain(bytes, "BTX_RC_STAGE3_CTL_SCHEDULE_V1");
    WriteU32(bytes, static_cast<uint32_t>(schedule.events.size()));
    for (const auto& event : schedule.events) {
        WriteU32(bytes, event.namespace_id);
        WriteU32(bytes, event.stage);
        WriteU32(bytes, event.address);
        bytes.push_back(static_cast<unsigned char>(event.multiplicity));
    }
    return Sha256d(bytes);
}

Fp3 CompressRCStage3CtlTuple(const RCStage3CtlEvent& event,
                             const Fp3& value,
                             const Fp3& gamma)
{
    const Fp3 gamma2 = gf::Mul(gamma, gamma);
    const Fp3 gamma3 = gf::Mul(gamma2, gamma);
    return gf::Add(
        gf::FromU64_3(event.namespace_id),
        gf::Add(gf::Mul(gamma, gf::FromU64_3(event.stage)),
                gf::Add(gf::Mul(gamma2, gf::FromU64_3(event.address)),
                        gf::Mul(gamma3, value))));
}

bool DeriveRCStage3CtlChallenges(
    const RCStage3CtlManifest& manifest,
    const std::vector<RCStage3CtlChildPin>& prechallenge_pins,
    RCStage3CtlChallenges& out,
    std::string* why)
{
    out = {};
    if (!ValidateManifest(manifest, why)) return false;
    if (prechallenge_pins.size() != manifest.participants.size()) {
        return Fail(why, "challenge:pin_count");
    }

    std::vector<unsigned char> bytes;
    WriteDomain(bytes, "BTX_RC_STAGE3_CTL_TRACE_EPOCH_V3");
    WriteHash(bytes, CommitManifest(manifest));
    for (size_t i = 0; i < prechallenge_pins.size(); ++i) {
        const auto& pin = prechallenge_pins[i];
        const auto& participant = manifest.participants[i];
        if (!ValidatePin(pin, why, false)) return false;
        if (pin.role != participant.role || pin.bus_id != manifest.bus_id ||
            pin.event_count != participant.event_count ||
            pin.send_count != participant.send_count ||
            pin.receive_count != participant.receive_count ||
            pin.schedule_commitment != participant.schedule_commitment) {
            return Fail(why, "challenge:participant_binding");
        }
        WriteU16(bytes, static_cast<uint16_t>(pin.role));
        WriteHash(bytes, pin.trace_commitment);
    }
    const uint256 seed = Sha256d(bytes);

    const auto sample_filtered =
        [&](const char* label, const auto& accept, Fp3& value) {
            for (uint32_t counter = 0;
                 counter < kRCStage3CtlChallengeMaxCandidates;
                 ++counter) {
                Fp3 candidate;
                if (!Challenge(seed, label, counter, candidate)) return false;
                if (accept(candidate)) {
                    value = candidate;
                    return true;
                }
            }
            return false;
        };
    if (!sample_filtered(
            "gamma1",
            [](const Fp3& value) { return !gf::IsZero(value); },
            out.gamma1) ||
        !sample_filtered(
            "gamma2",
            [&](const Fp3& value) {
                return !gf::IsZero(value) &&
                       !gf::Eq(out.gamma1, value);
            },
            out.gamma2) ||
        !Challenge(seed, "alpha1", 0, out.alpha1) ||
        !sample_filtered(
            "alpha2",
            [&](const Fp3& value) {
                return !gf::Eq(out.alpha1, value);
            },
            out.alpha2)) {
        out = {};
        return Fail(why, "challenge:sampler_exhausted");
    }

    if (!ValidChallenges(out)) return Fail(why, "challenge:invalid");
    if (why != nullptr) *why = "stage3:ctl:ok";
    return true;
}

uint256 CommitRCStage3CtlChallenges(const RCStage3CtlChallenges& challenges)
{
    if (!ValidChallenges(challenges)) return {};
    std::vector<unsigned char> bytes;
    WriteDomain(bytes, "BTX_RC_STAGE3_CTL_CHALLENGES_V3");
    WriteFp3(bytes, challenges.gamma1);
    WriteFp3(bytes, challenges.gamma2);
    WriteFp3(bytes, challenges.alpha1);
    WriteFp3(bytes, challenges.alpha2);
    return Sha256d(bytes);
}

CS BuildRCStage3CtlConstraintSystem(const RCStage3CtlAirSpec& spec)
{
    using namespace stage3_ctl_col;
    CS cs;
    std::string ignored;
    if (!ValidateRCStage3CtlSchedule(spec.schedule, &ignored) ||
        !ValidChallenges(spec.challenges) ||
        !Canonical(spec.expected_terminal.alpha1_sum) ||
        !Canonical(spec.expected_terminal.alpha2_sum)) {
        return cs;
    }

    cs.n_rows = NextPow2(spec.schedule.events.size());
    cs.n_columns = NUM_COLUMNS;
    cs.preprocessed_pin_ood = true;
    std::vector<Fp3> namespace_col(cs.n_rows, Fp3::Zero());
    std::vector<Fp3> stage_col(cs.n_rows, Fp3::Zero());
    std::vector<Fp3> address_col(cs.n_rows, Fp3::Zero());
    std::vector<Fp3> multiplicity_col(cs.n_rows, Fp3::Zero());
    for (size_t i = 0; i < spec.schedule.events.size(); ++i) {
        const auto& event = spec.schedule.events[i];
        namespace_col[i] = gf::FromU64_3(event.namespace_id);
        stage_col[i] = gf::FromU64_3(event.stage);
        address_col[i] = gf::FromU64_3(event.address);
        multiplicity_col[i] = gf::FromSigned3(event.multiplicity);
    }
    cs.preprocessed.push_back({NAMESPACE, std::move(namespace_col)});
    cs.preprocessed.push_back({STAGE, std::move(stage_col)});
    cs.preprocessed.push_back({ADDRESS, std::move(address_col)});
    cs.preprocessed.push_back({MULTIPLICITY, std::move(multiplicity_col)});

    Add(cs, "ctl.multiplicity", aq::AirKind::kEverywhere, 3,
        [](const std::vector<Fp3>& row, const std::vector<Fp3>&) {
            const Fp3 m = row[MULTIPLICITY];
            return gf::Mul(m, gf::Mul(gf::Sub(m, Fp3::One()),
                                      gf::Add(m, Fp3::One())));
        });
    Add(cs, "ctl.inverse1", aq::AirKind::kEverywhere, 4,
        [ch = spec.challenges](const std::vector<Fp3>& row,
                               const std::vector<Fp3>&) {
            const Fp3 active = gf::Mul(row[MULTIPLICITY], row[MULTIPLICITY]);
            return gf::Sub(
                gf::Mul(row[INVERSE1],
                        gf::Sub(ch.alpha1, CompressRow(row, ch.gamma1))),
                active);
        });
    Add(cs, "ctl.inverse2", aq::AirKind::kEverywhere, 4,
        [ch = spec.challenges](const std::vector<Fp3>& row,
                               const std::vector<Fp3>&) {
            const Fp3 active = gf::Mul(row[MULTIPLICITY], row[MULTIPLICITY]);
            return gf::Sub(
                gf::Mul(row[INVERSE2],
                        gf::Sub(ch.alpha2, CompressRow(row, ch.gamma2))),
                active);
        });
    Add(cs, "ctl.padding_value", aq::AirKind::kEverywhere, 3,
        [](const std::vector<Fp3>& row, const std::vector<Fp3>&) {
            const Fp3 active = gf::Mul(row[MULTIPLICITY], row[MULTIPLICITY]);
            return gf::Mul(gf::Sub(Fp3::One(), active), row[VALUE]);
        });
    Add(cs, "ctl.padding_inverse1", aq::AirKind::kEverywhere, 3,
        [](const std::vector<Fp3>& row, const std::vector<Fp3>&) {
            const Fp3 active = gf::Mul(row[MULTIPLICITY], row[MULTIPLICITY]);
            return gf::Mul(gf::Sub(Fp3::One(), active), row[INVERSE1]);
        });
    Add(cs, "ctl.padding_inverse2", aq::AirKind::kEverywhere, 3,
        [](const std::vector<Fp3>& row, const std::vector<Fp3>&) {
            const Fp3 active = gf::Mul(row[MULTIPLICITY], row[MULTIPLICITY]);
            return gf::Mul(gf::Sub(Fp3::One(), active), row[INVERSE2]);
        });
    Add(cs, "ctl.running1.first", aq::AirKind::kFirstRow, 1,
        [](const std::vector<Fp3>& row, const std::vector<Fp3>&) {
            return row[RUNNING1];
        });
    Add(cs, "ctl.running2.first", aq::AirKind::kFirstRow, 1,
        [](const std::vector<Fp3>& row, const std::vector<Fp3>&) {
            return row[RUNNING2];
        });
    Add(cs, "ctl.running1.transition", aq::AirKind::kTransition, 2,
        [](const std::vector<Fp3>& row, const std::vector<Fp3>& next) {
            const Fp3 term = gf::Mul(row[MULTIPLICITY], row[INVERSE1]);
            return gf::Sub(next[RUNNING1], gf::Add(row[RUNNING1], term));
        });
    Add(cs, "ctl.running2.transition", aq::AirKind::kTransition, 2,
        [](const std::vector<Fp3>& row, const std::vector<Fp3>& next) {
            const Fp3 term = gf::Mul(row[MULTIPLICITY], row[INVERSE2]);
            return gf::Sub(next[RUNNING2], gf::Add(row[RUNNING2], term));
        });
    Add(cs, "ctl.running1.last", aq::AirKind::kLastRow, 2,
        [terminal = spec.expected_terminal.alpha1_sum](
            const std::vector<Fp3>& row, const std::vector<Fp3>&) {
            const Fp3 term = gf::Mul(row[MULTIPLICITY], row[INVERSE1]);
            return gf::Sub(gf::Add(row[RUNNING1], term), terminal);
        });
    Add(cs, "ctl.running2.last", aq::AirKind::kLastRow, 2,
        [terminal = spec.expected_terminal.alpha2_sum](
            const std::vector<Fp3>& row, const std::vector<Fp3>&) {
            const Fp3 term = gf::Mul(row[MULTIPLICITY], row[INVERSE2]);
            return gf::Sub(gf::Add(row[RUNNING2], term), terminal);
        });
    return cs;
}

RCStage3CtlWitness BuildRCStage3CtlWitness(
    const RCStage3CtlSchedule& schedule,
    const std::vector<Fp3>& values,
    const RCStage3CtlChallenges& challenges)
{
    using namespace stage3_ctl_col;
    RCStage3CtlWitness out;
    if (!ValidateRCStage3CtlSchedule(schedule, &out.note) ||
        !ValidChallenges(challenges)) {
        if (out.note.empty()) out.note = "stage3:ctl:witness:invalid_challenges";
        return out;
    }
    if (values.size() != schedule.events.size()) {
        out.note = "stage3:ctl:witness:value_count";
        return out;
    }
    for (const Fp3& value : values) {
        if (!Canonical(value)) {
            out.note = "stage3:ctl:witness:noncanonical_value";
            return out;
        }
    }

    const uint32_t n_rows = NextPow2(schedule.events.size());
    out.columns.assign(NUM_COLUMNS, std::vector<Fp3>(n_rows, Fp3::Zero()));
    Fp3 running1 = Fp3::Zero();
    Fp3 running2 = Fp3::Zero();
    for (uint32_t row = 0; row < n_rows; ++row) {
        out.columns[RUNNING1][row] = running1;
        out.columns[RUNNING2][row] = running2;
        if (row >= schedule.events.size()) continue;
        const auto& event = schedule.events[row];
        const Fp3 compressed1 =
            CompressRCStage3CtlTuple(event, values[row],
                                     challenges.gamma1);
        const Fp3 compressed2 =
            CompressRCStage3CtlTuple(event, values[row],
                                     challenges.gamma2);
        const Fp3 denominator1 =
            gf::Sub(challenges.alpha1, compressed1);
        const Fp3 denominator2 =
            gf::Sub(challenges.alpha2, compressed2);
        if (gf::IsZero(denominator1) || gf::IsZero(denominator2)) {
            out.note = "stage3:ctl:witness:challenge_collision";
            out.columns.clear();
            return out;
        }
        const Fp3 multiplicity = gf::FromSigned3(event.multiplicity);
        const Fp3 inverse1 = gf::Inv(denominator1);
        const Fp3 inverse2 = gf::Inv(denominator2);
        out.columns[NAMESPACE][row] = gf::FromU64_3(event.namespace_id);
        out.columns[STAGE][row] = gf::FromU64_3(event.stage);
        out.columns[ADDRESS][row] = gf::FromU64_3(event.address);
        out.columns[VALUE][row] = values[row];
        out.columns[MULTIPLICITY][row] = multiplicity;
        out.columns[INVERSE1][row] = inverse1;
        out.columns[INVERSE2][row] = inverse2;
        running1 = gf::Add(running1, gf::Mul(multiplicity, inverse1));
        running2 = gf::Add(running2, gf::Mul(multiplicity, inverse2));
    }
    out.terminal = {running1, running2};
    out.ok = true;
    out.note = "stage3:ctl:witness:ok";
    return out;
}

CS BuildRCStage3CtlDegree2ConstraintSystem(
    const RCStage3CtlDegree2AirSpec& spec)
{
    using namespace stage3_ctl_degree2_col;
    CS cs;
    std::string ignored;
    const size_t event_count =
        spec.schedule.events.size();
    if (spec.version !=
            kRCStage3CtlDegree2Version ||
        !ValidateRCStage3CtlSchedule(
            spec.schedule, &ignored) ||
        event_count < 2 ||
        (event_count &
         (event_count - 1)) != 0 ||
        !ValidChallenges(spec.challenges) ||
        !Canonical(
            spec.expected_terminal.alpha1_sum) ||
        !Canonical(
            spec.expected_terminal.alpha2_sum)) {
        return cs;
    }

    cs.n_rows =
        static_cast<uint32_t>(event_count);
    cs.n_columns = NUM_COLUMNS;
    cs.preprocessed_pin_ood = true;
    std::vector<Fp3> namespace_col(
        cs.n_rows, Fp3::Zero());
    std::vector<Fp3> stage_col(
        cs.n_rows, Fp3::Zero());
    std::vector<Fp3> address_col(
        cs.n_rows, Fp3::Zero());
    std::vector<Fp3> multiplicity_col(
        cs.n_rows, Fp3::Zero());
    for (uint32_t row = 0;
         row < cs.n_rows;
         ++row) {
        const auto& event =
            spec.schedule.events[row];
        namespace_col[row] =
            gf::FromU64_3(event.namespace_id);
        stage_col[row] =
            gf::FromU64_3(event.stage);
        address_col[row] =
            gf::FromU64_3(event.address);
        multiplicity_col[row] =
            gf::FromSigned3(event.multiplicity);
    }
    cs.preprocessed.push_back(
        {NAMESPACE, std::move(namespace_col)});
    cs.preprocessed.push_back(
        {STAGE, std::move(stage_col)});
    cs.preprocessed.push_back(
        {ADDRESS, std::move(address_col)});
    cs.preprocessed.push_back(
        {MULTIPLICITY,
         std::move(multiplicity_col)});

    const auto compress =
        [](const std::vector<Fp3>& row,
           const Fp3& gamma) {
            const Fp3 gamma2 =
                gf::Mul(gamma, gamma);
            const Fp3 gamma3 =
                gf::Mul(gamma2, gamma);
            return gf::Add(
                row[NAMESPACE],
                gf::Add(
                    gf::Mul(
                        gamma, row[STAGE]),
                    gf::Add(
                        gf::Mul(
                            gamma2,
                            row[ADDRESS]),
                        gf::Mul(
                            gamma3,
                            row[VALUE]))));
        };

    Add(cs, "ctl.degree2.inverse1",
        aq::AirKind::kEverywhere, 2,
        [ch = spec.challenges,
         compress](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            return gf::Sub(
                gf::Mul(
                    row[INVERSE1],
                    gf::Sub(
                        ch.alpha1,
                        compress(
                            row, ch.gamma1))),
                Fp3::One());
        });
    Add(cs, "ctl.degree2.inverse2",
        aq::AirKind::kEverywhere, 2,
        [ch = spec.challenges,
         compress](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            return gf::Sub(
                gf::Mul(
                    row[INVERSE2],
                    gf::Sub(
                        ch.alpha2,
                        compress(
                            row, ch.gamma2))),
                Fp3::One());
        });
    Add(cs, "ctl.degree2.term1",
        aq::AirKind::kEverywhere, 2,
        [](const std::vector<Fp3>& row,
           const std::vector<Fp3>&) {
            return gf::Sub(
                row[TERM1],
                gf::Mul(
                    row[MULTIPLICITY],
                    row[INVERSE1]));
        });
    Add(cs, "ctl.degree2.term2",
        aq::AirKind::kEverywhere, 2,
        [](const std::vector<Fp3>& row,
           const std::vector<Fp3>&) {
            return gf::Sub(
                row[TERM2],
                gf::Mul(
                    row[MULTIPLICITY],
                    row[INVERSE2]));
        });
    Add(cs, "ctl.degree2.running1.first",
        aq::AirKind::kFirstRow, 1,
        [](const std::vector<Fp3>& row,
           const std::vector<Fp3>&) {
            return row[RUNNING1];
        });
    Add(cs, "ctl.degree2.running2.first",
        aq::AirKind::kFirstRow, 1,
        [](const std::vector<Fp3>& row,
           const std::vector<Fp3>&) {
            return row[RUNNING2];
        });
    Add(cs, "ctl.degree2.running1.transition",
        aq::AirKind::kTransition, 1,
        [](const std::vector<Fp3>& row,
           const std::vector<Fp3>& next) {
            return gf::Sub(
                next[RUNNING1],
                gf::Add(
                    row[RUNNING1],
                    row[TERM1]));
        });
    Add(cs, "ctl.degree2.running2.transition",
        aq::AirKind::kTransition, 1,
        [](const std::vector<Fp3>& row,
           const std::vector<Fp3>& next) {
            return gf::Sub(
                next[RUNNING2],
                gf::Add(
                    row[RUNNING2],
                    row[TERM2]));
        });
    Add(cs, "ctl.degree2.running1.last",
        aq::AirKind::kLastRow, 1,
        [terminal =
             spec.expected_terminal.alpha1_sum](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            return gf::Sub(
                gf::Add(
                    row[RUNNING1],
                    row[TERM1]),
                terminal);
        });
    Add(cs, "ctl.degree2.running2.last",
        aq::AirKind::kLastRow, 1,
        [terminal =
             spec.expected_terminal.alpha2_sum](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            return gf::Sub(
                gf::Add(
                    row[RUNNING2],
                    row[TERM2]),
                terminal);
        });

    // This is the defining invariant of the versioned layout.  Refuse to
    // produce a constraint system if a future edit silently raises the
    // common commitment size above the exact trace size.
    if (cs.QuotientLen() > cs.n_rows) {
        return {};
    }
    return cs;
}

RCStage3CtlDegree2Witness
BuildRCStage3CtlDegree2Witness(
    const RCStage3CtlSchedule& schedule,
    const std::vector<Fp3>& values,
    const RCStage3CtlChallenges& challenges)
{
    using namespace stage3_ctl_degree2_col;
    RCStage3CtlDegree2Witness out;
    std::string schedule_why;
    const size_t event_count =
        schedule.events.size();
    if (!ValidateRCStage3CtlSchedule(
            schedule, &schedule_why) ||
        event_count < 2 ||
        (event_count &
         (event_count - 1)) != 0) {
        out.note =
            "stage3:ctl:degree2:"
            "schedule_must_be_exact_power_of_two";
        return out;
    }
    if (!ValidChallenges(challenges)) {
        out.note =
            "stage3:ctl:degree2:"
            "invalid_challenges";
        return out;
    }
    if (values.size() != event_count) {
        out.note =
            "stage3:ctl:degree2:"
            "value_count";
        return out;
    }
    for (const Fp3& value : values) {
        if (!Canonical(value)) {
            out.note =
                "stage3:ctl:degree2:"
                "noncanonical_value";
            return out;
        }
    }

    const uint32_t n_rows =
        static_cast<uint32_t>(event_count);
    out.columns.assign(
        NUM_COLUMNS,
        std::vector<Fp3>(
            n_rows, Fp3::Zero()));
    Fp3 running1 = Fp3::Zero();
    Fp3 running2 = Fp3::Zero();
    for (uint32_t row = 0;
         row < n_rows;
         ++row) {
        const auto& event =
            schedule.events[row];
        const Fp3 denominator1 =
            gf::Sub(
                challenges.alpha1,
                CompressRCStage3CtlTuple(
                    event, values[row],
                    challenges.gamma1));
        const Fp3 denominator2 =
            gf::Sub(
                challenges.alpha2,
                CompressRCStage3CtlTuple(
                    event, values[row],
                    challenges.gamma2));
        if (gf::IsZero(denominator1) ||
            gf::IsZero(denominator2)) {
            out.columns.clear();
            out.note =
                "stage3:ctl:degree2:"
                "challenge_collision";
            return out;
        }
        const Fp3 multiplicity =
            gf::FromSigned3(
                event.multiplicity);
        const Fp3 inverse1 =
            gf::Inv(denominator1);
        const Fp3 inverse2 =
            gf::Inv(denominator2);
        const Fp3 term1 =
            gf::Mul(
                multiplicity, inverse1);
        const Fp3 term2 =
            gf::Mul(
                multiplicity, inverse2);

        out.columns[NAMESPACE][row] =
            gf::FromU64_3(
                event.namespace_id);
        out.columns[STAGE][row] =
            gf::FromU64_3(event.stage);
        out.columns[ADDRESS][row] =
            gf::FromU64_3(event.address);
        out.columns[VALUE][row] =
            values[row];
        out.columns[MULTIPLICITY][row] =
            multiplicity;
        out.columns[INVERSE1][row] =
            inverse1;
        out.columns[INVERSE2][row] =
            inverse2;
        out.columns[TERM1][row] =
            term1;
        out.columns[TERM2][row] =
            term2;
        out.columns[RUNNING1][row] =
            running1;
        out.columns[RUNNING2][row] =
            running2;
        running1 =
            gf::Add(running1, term1);
        running2 =
            gf::Add(running2, term2);
    }
    out.terminal = {running1, running2};
    out.ok = true;
    out.note =
        "stage3:ctl:degree2:ok";
    return out;
}

uint256 ComputeRCStage3CtlDegree2PrechallengeTraceCommitment(
    const RCStage3CtlSchedule& schedule,
    const std::vector<Fp3>& values)
{
    using namespace stage3_ctl_degree2_col;
    std::string ignored;
    if (!ValidateRCStage3CtlSchedule(schedule, &ignored) ||
        schedule.events.size() < 2 ||
        (schedule.events.size() & (schedule.events.size() - 1)) != 0 ||
        values.size() != schedule.events.size()) {
        return {};
    }
    for (const auto& value : values) {
        if (!Canonical(value)) return {};
    }

    const uint32_t n_rows =
        static_cast<uint32_t>(schedule.events.size());
    std::array<std::vector<Fp3>, 5> columns;
    for (auto& column : columns) {
        column.assign(n_rows, Fp3::Zero());
    }
    for (uint32_t row = 0; row < n_rows; ++row) {
        const auto& event = schedule.events[row];
        columns[NAMESPACE][row] =
            gf::FromU64_3(event.namespace_id);
        columns[STAGE][row] =
            gf::FromU64_3(event.stage);
        columns[ADDRESS][row] =
            gf::FromU64_3(event.address);
        columns[VALUE][row] = values[row];
        columns[MULTIPLICITY][row] =
            gf::FromSigned3(event.multiplicity);
    }
    std::array<uint256, 5> roots{};
    for (uint32_t column = NAMESPACE;
         column <= MULTIPLICITY; ++column) {
        roots[column] =
            aq::AirCommittedValuesRoot<Fp3>(
                columns[column], n_rows);
    }
    return CommitPrechallengeRoots(
        schedule, n_rows, n_rows, roots);
}

uint256
ComputeRCStage3CtlDegree2PrechallengeTraceCommitmentFromRoots(
    const RCStage3CtlSchedule& schedule,
    uint32_t n_rows,
    uint32_t n_coeffs,
    const std::array<uint256, 5>& roots)
{
    std::string ignored;
    if (!ValidateRCStage3CtlSchedule(schedule, &ignored) ||
        schedule.events.size() < 2 ||
        (schedule.events.size() & (schedule.events.size() - 1)) != 0 ||
        n_rows != schedule.events.size() ||
        n_coeffs != n_rows) {
        return {};
    }
    return CommitPrechallengeRoots(
        schedule, n_rows, n_coeffs, roots);
}

uint256 ComputeRCStage3CtlPrechallengeTraceCommitment(
    const RCStage3CtlSchedule& schedule,
    const std::vector<Fp3>& values)
{
    using namespace stage3_ctl_col;
    std::string ignored;
    if (!ValidateRCStage3CtlSchedule(schedule, &ignored) ||
        values.size() != schedule.events.size()) {
        return {};
    }
    for (const auto& value : values) {
        if (!Canonical(value)) return {};
    }

    const uint32_t n_rows = NextPow2(schedule.events.size());
    // CTL's highest composed degree is 4(N-1), hence the quotient length is
    // 3N-3.  The backend pads every trace and quotient to this common power
    // of two before computing the per-column roots.
    const uint32_t quotient_len = 3 * n_rows - 3;
    const uint32_t n_coeffs =
        FriNextPow2(std::max(n_rows, quotient_len));
    std::array<std::vector<Fp3>, 5> columns;
    for (auto& column : columns) {
        column.assign(n_rows, Fp3::Zero());
    }
    for (size_t row = 0; row < schedule.events.size(); ++row) {
        const auto& event = schedule.events[row];
        columns[NAMESPACE][row] = gf::FromU64_3(event.namespace_id);
        columns[STAGE][row] = gf::FromU64_3(event.stage);
        columns[ADDRESS][row] = gf::FromU64_3(event.address);
        columns[VALUE][row] = values[row];
        columns[MULTIPLICITY][row] =
            gf::FromSigned3(event.multiplicity);
    }
    std::array<uint256, 5> roots{};
    for (uint32_t column = NAMESPACE; column <= MULTIPLICITY; ++column) {
        roots[column] = aq::AirCommittedValuesRoot<Fp3>(
            columns[column], n_coeffs);
    }
    return CommitPrechallengeRoots(schedule, n_rows, n_coeffs, roots);
}

uint256 ComputeRCStage3CtlPrechallengeTraceCommitmentFromRoots(
    const RCStage3CtlSchedule& schedule,
    uint32_t n_rows,
    uint32_t n_coeffs,
    const std::array<uint256, 5>& roots)
{
    std::string ignored;
    if (!ValidateRCStage3CtlSchedule(schedule, &ignored) ||
        n_rows != NextPow2(schedule.events.size())) {
        return {};
    }
    const uint32_t quotient_len = 3 * n_rows - 3;
    if (n_coeffs != FriNextPow2(std::max(n_rows, quotient_len))) {
        return {};
    }
    return CommitPrechallengeRoots(schedule, n_rows, n_coeffs, roots);
}

uint256 ComputeRCStage3CtlAuxiliaryCommitment(
    const RCStage3CtlAirProof& proof)
{
    using namespace stage3_ctl_col;
    if (proof.batch.columns.size() != NUM_COLUMNS + 1 ||
        proof.batch.column_len.size() != NUM_COLUMNS + 1 ||
        proof.batch.n_coeffs == 0) {
        return {};
    }
    for (const auto& column : proof.batch.columns) {
        if (column.root.IsNull()) return {};
    }
    std::vector<unsigned char> bytes;
    WriteDomain(bytes, "BTX_RC_STAGE3_CTL_TRACE_EPOCH2_V3");
    WriteU32(bytes, proof.batch.version);
    WriteU32(bytes, proof.batch.blowup);
    WriteU32(bytes, proof.batch.n_coeffs);
    WriteU32(bytes, static_cast<uint32_t>(proof.batch.column_len.size()));
    for (const uint32_t length : proof.batch.column_len) {
        WriteU32(bytes, length);
    }
    for (uint32_t column = INVERSE1; column <= RUNNING2 + 1; ++column) {
        WriteHash(bytes, proof.batch.columns[column].root);
    }
    return Sha256d(bytes);
}

uint256 ComputeRCStage3CtlAirSeed(
    const RCStage3CtlManifest& manifest,
    const RCStage3CtlChildPin& pin)
{
    if (!ValidateManifest(manifest, nullptr) ||
        !ValidatePin(pin, nullptr, false) ||
        pin.bus_id != manifest.bus_id ||
        pin.challenge_commitment.IsNull()) {
        return {};
    }
    const auto participant = std::find_if(
        manifest.participants.begin(), manifest.participants.end(),
        [&](const RCStage3CtlParticipantSpec& candidate) {
            return candidate.role == pin.role;
        });
    if (participant == manifest.participants.end() ||
        participant->event_count != pin.event_count ||
        participant->send_count != pin.send_count ||
        participant->receive_count != pin.receive_count ||
        participant->schedule_commitment != pin.schedule_commitment) {
        return {};
    }

    std::vector<unsigned char> bytes;
    WriteDomain(bytes, "BTX_RC_STAGE3_CTL_AIR_SEED_V3");
    WriteHash(bytes, CommitManifest(manifest));
    WriteU16(bytes, static_cast<uint16_t>(pin.role));
    WriteU32(bytes, pin.bus_id);
    WriteHash(bytes, pin.schedule_commitment);
    WriteHash(bytes, pin.trace_commitment);
    WriteHash(bytes, pin.challenge_commitment);
    return Sha256d(bytes);
}

bool VerifyRCStage3CtlChildAirProof(
    const RCStage3CtlManifest& manifest,
    const std::vector<RCStage3CtlChildPin>& pins,
    size_t child_index,
    const RCStage3CtlSchedule& schedule,
    const RCStage3CtlAirProof& proof,
    std::string* why)
{
    if (child_index >= pins.size() ||
        pins.size() != manifest.participants.size()) {
        return Fail(why, "air:child_index");
    }
    const auto& pin = pins[child_index];
    const auto& participant = manifest.participants[child_index];
    uint64_t schedule_events{0};
    uint64_t schedule_sends{0};
    uint64_t schedule_receives{0};
    if (!ValidatePin(pin, why, true) ||
        pin.role != participant.role ||
        pin.bus_id != manifest.bus_id ||
        pin.event_count != participant.event_count ||
        pin.send_count != participant.send_count ||
        pin.receive_count != participant.receive_count ||
        pin.schedule_commitment != participant.schedule_commitment ||
        CommitRCStage3CtlSchedule(schedule) != pin.schedule_commitment) {
        return Fail(why, "air:participant_binding");
    }
    if (!CountScheduleEvents(schedule, schedule_events, schedule_sends,
                             schedule_receives) ||
        schedule_events != pin.event_count ||
        schedule_sends != pin.send_count ||
        schedule_receives != pin.receive_count) {
        return Fail(why, "air:schedule_counts");
    }

    RCStage3CtlChallenges challenges;
    if (!DeriveRCStage3CtlChallenges(
            manifest, pins, challenges, why)) {
        return false;
    }
    if (pin.challenge_commitment !=
        CommitRCStage3CtlChallenges(challenges)) {
        return Fail(why, "air:challenge_binding");
    }
    if (pin.trace_commitment !=
        CommitPrechallengeProofRoots(schedule, proof)) {
        return Fail(why, "air:trace_epoch_binding");
    }
    if (pin.auxiliary_commitment !=
        ComputeRCStage3CtlAuxiliaryCommitment(proof)) {
        return Fail(why, "air:auxiliary_epoch_binding");
    }

    const RCStage3CtlAirSpec spec{
        schedule, challenges, pin.terminal};
    const CS cs = BuildRCStage3CtlConstraintSystem(spec);
    const uint256 seed = ComputeRCStage3CtlAirSeed(manifest, pin);
    if (cs.n_columns != stage3_ctl_col::NUM_COLUMNS || seed.IsNull()) {
        return Fail(why, "air:constraint_system");
    }
    std::string air_why;
    if (!aq::AirQuotientVerify<Fp3>(
            cs, proof, seed, &air_why)) {
        return Fail(why, "air:proof:" + air_why);
    }
    if (why != nullptr) {
        *why = "stage3:ctl:air_child_ok_recursive_consumption_pending";
    }
    return true;
}

bool VerifyRCStage3CtlBusAirProofs(
    const RCStage3CtlManifest& manifest,
    const std::vector<RCStage3CtlChildPin>& pins,
    const std::vector<RCStage3CtlSchedule>& schedules,
    const std::vector<RCStage3CtlAirProof>& proofs,
    std::string* why)
{
    if (pins.size() != manifest.participants.size() ||
        schedules.size() != pins.size() ||
        proofs.size() != pins.size()) {
        return Fail(why, "air_bus:shape");
    }
    for (size_t i = 0; i < pins.size(); ++i) {
        if (!VerifyRCStage3CtlChildAirProof(
                manifest, pins, i, schedules[i], proofs[i], why)) {
            return false;
        }
    }
    if (!VerifyRCStage3CtlPublicPinComposition(
            manifest, pins, why)) {
        return Fail(why, "air_bus:terminal_composition");
    }
    if (why != nullptr) {
        *why = "stage3:ctl:air_bus_ok_recursive_consumption_pending";
    }
    return true;
}

bool SerializeRCStage3CtlChildPin(const RCStage3CtlChildPin& pin,
                                  std::vector<unsigned char>& out,
                                  std::string* why)
{
    out.clear();
    if (!ValidatePin(pin, why, true)) return false;
    WriteU32(out, pin.magic);
    WriteU16(out, pin.version);
    WriteU16(out, static_cast<uint16_t>(pin.role));
    WriteU32(out, pin.bus_id);
    WriteU64(out, pin.event_count);
    WriteU64(out, pin.send_count);
    WriteU64(out, pin.receive_count);
    WriteHash(out, pin.schedule_commitment);
    WriteHash(out, pin.trace_commitment);
    WriteHash(out, pin.auxiliary_commitment);
    WriteHash(out, pin.challenge_commitment);
    WriteFp3(out, pin.terminal.alpha1_sum);
    WriteFp3(out, pin.terminal.alpha2_sum);
    if (out.size() != PIN_BYTES) return Fail(why, "pin:internal_size");
    if (why != nullptr) *why = "stage3:ctl:ok";
    return true;
}

std::optional<RCStage3CtlChildPin>
DeserializeRCStage3CtlChildPin(const std::vector<unsigned char>& bytes,
                               std::string* why)
{
    if (bytes.size() != PIN_BYTES) {
        return FailOptional<RCStage3CtlChildPin>(why, "pin:encoded_size");
    }
    Reader reader(bytes);
    RCStage3CtlChildPin pin;
    uint16_t role{0};
    if (!reader.U32(pin.magic) || !reader.U16(pin.version) ||
        !reader.U16(role) || !reader.U32(pin.bus_id) ||
        !reader.U64(pin.event_count) || !reader.U64(pin.send_count) ||
        !reader.U64(pin.receive_count) ||
        !reader.Hash(pin.schedule_commitment) ||
        !reader.Hash(pin.trace_commitment) ||
        !reader.Hash(pin.auxiliary_commitment) ||
        !reader.Hash(pin.challenge_commitment) ||
        !reader.Field(pin.terminal.alpha1_sum) ||
        !reader.Field(pin.terminal.alpha2_sum) || reader.Remaining() != 0) {
        return FailOptional<RCStage3CtlChildPin>(why, "pin:truncated");
    }
    pin.role = static_cast<RCStage3RelationRole>(role);
    if (!ValidatePin(pin, why, true)) return std::nullopt;
    if (why != nullptr) *why = "stage3:ctl:ok";
    return pin;
}

uint256 CommitRCStage3CtlChildPin(const RCStage3CtlChildPin& pin)
{
    std::vector<unsigned char> encoded;
    if (!SerializeRCStage3CtlChildPin(pin, encoded)) return {};
    std::vector<unsigned char> bytes;
    WriteDomain(bytes, "BTX_RC_STAGE3_CTL_CHILD_PIN_V3");
    bytes.insert(bytes.end(), encoded.begin(), encoded.end());
    return Sha256d(bytes);
}

bool SerializeRCStage3CtlRelationExportPin(
    const RCStage3CtlRelationExportPin& pin,
    std::vector<unsigned char>& out,
    std::string* why)
{
    out.clear();
    if (!ValidateRelationExportPin(pin, why)) return false;
    WriteU32(out, pin.magic);
    WriteU16(out, pin.version);
    WriteU16(out, static_cast<uint16_t>(pin.role));
    WriteU32(out, pin.bus_id);
    WriteU64(out, pin.event_count);
    WriteHash(out, pin.relation_commitment);
    WriteHash(out, pin.schedule_commitment);
    WriteU32(out, pin.n_rows);
    WriteU32(out, pin.n_coeffs);
    for (const auto& root : pin.prechallenge_column_roots) {
        WriteHash(out, root);
    }
    if (out.size() != kRCStage3CtlRelationExportBytes) {
        return Fail(why, "relation_export:internal_size");
    }
    if (why != nullptr) *why = "stage3:ctl:relation_export_ok";
    return true;
}

std::optional<RCStage3CtlRelationExportPin>
DeserializeRCStage3CtlRelationExportPin(
    const std::vector<unsigned char>& bytes,
    std::string* why)
{
    if (bytes.size() != kRCStage3CtlRelationExportBytes) {
        return FailOptional<RCStage3CtlRelationExportPin>(
            why, "relation_export:encoded_size");
    }
    Reader reader(bytes);
    RCStage3CtlRelationExportPin pin;
    uint16_t role{0};
    if (!reader.U32(pin.magic) || !reader.U16(pin.version) ||
        !reader.U16(role) || !reader.U32(pin.bus_id) ||
        !reader.U64(pin.event_count) ||
        !reader.Hash(pin.relation_commitment) ||
        !reader.Hash(pin.schedule_commitment) ||
        !reader.U32(pin.n_rows) || !reader.U32(pin.n_coeffs)) {
        return FailOptional<RCStage3CtlRelationExportPin>(
            why, "relation_export:truncated");
    }
    for (auto& root : pin.prechallenge_column_roots) {
        if (!reader.Hash(root)) {
            return FailOptional<RCStage3CtlRelationExportPin>(
                why, "relation_export:truncated");
        }
    }
    if (reader.Remaining() != 0) {
        return FailOptional<RCStage3CtlRelationExportPin>(
            why, "relation_export:trailing");
    }
    pin.role = static_cast<RCStage3RelationRole>(role);
    if (!ValidateRelationExportPin(pin, why)) return std::nullopt;
    if (why != nullptr) *why = "stage3:ctl:relation_export_ok";
    return pin;
}

uint256 CommitRCStage3CtlRelationExportPin(
    const RCStage3CtlRelationExportPin& pin)
{
    std::vector<unsigned char> encoded;
    if (!SerializeRCStage3CtlRelationExportPin(pin, encoded)) return {};
    std::vector<unsigned char> bytes;
    WriteDomain(bytes, "BTX_RC_STAGE3_CTL_RELATION_EXPORT_V1");
    bytes.insert(bytes.end(), encoded.begin(), encoded.end());
    return Sha256d(bytes);
}

bool VerifyRCStage3CtlRelationExportBinding(
    const RCStage3CtlRelationExportPin& relation_export,
    const RCStage3CtlChildPin& child,
    const RCStage3CtlSchedule& schedule,
    const RCStage3CtlAirProof& proof,
    const uint256& expected_relation_commitment,
    std::string* why)
{
    using namespace stage3_ctl_col;
    if (!ValidateRelationExportPin(relation_export, why) ||
        !ValidatePin(child, why, true) ||
        expected_relation_commitment.IsNull()) {
        return false;
    }
    const uint256 schedule_commitment =
        CommitRCStage3CtlSchedule(schedule);
    if (relation_export.role != child.role ||
        relation_export.bus_id != child.bus_id ||
        relation_export.event_count != child.event_count ||
        relation_export.relation_commitment !=
            expected_relation_commitment ||
        relation_export.schedule_commitment !=
            child.schedule_commitment ||
        relation_export.schedule_commitment != schedule_commitment) {
        return Fail(why, "relation_export:public_binding");
    }
    if (proof.batch.columns.size() != NUM_COLUMNS + 1 ||
        proof.batch.column_len.size() != NUM_COLUMNS + 1 ||
        proof.batch.n_coeffs != relation_export.n_coeffs) {
        return Fail(why, "relation_export:proof_shape");
    }
    for (uint32_t column = NAMESPACE;
         column <= MULTIPLICITY; ++column) {
        if (proof.batch.column_len[column] != relation_export.n_rows ||
            proof.batch.columns[column].root !=
                relation_export.prechallenge_column_roots[column]) {
            return Fail(why, "relation_export:column_root");
        }
    }
    const uint256 trace =
        ComputeRCStage3CtlPrechallengeTraceCommitmentFromRoots(
            schedule, relation_export.n_rows,
            relation_export.n_coeffs,
            relation_export.prechallenge_column_roots);
    if (trace.IsNull() || trace != child.trace_commitment ||
        trace != CommitPrechallengeProofRoots(schedule, proof)) {
        return Fail(why, "relation_export:trace_commitment");
    }
    if (why != nullptr) {
        *why =
            "stage3:ctl:relation_export_to_ctl_columns_ok_"
            "relation_witness_equality_pending";
    }
    return true;
}

bool EncodeRCStage3CtlChildPinForRecursion(
    const RCStage3CtlChildPin& pin,
    std::vector<Fp3>& out,
    std::string* why)
{
    out.clear();
    if (!ValidatePin(pin, why, true)) return false;
    out.reserve(kRCStage3CtlRecursivePinElements);
    out.push_back(gf::FromU64_3(pin.magic));
    out.push_back(gf::FromU64_3(pin.version));
    out.push_back(gf::FromU64_3(static_cast<uint16_t>(pin.role)));
    out.push_back(gf::FromU64_3(pin.bus_id));
    for (uint64_t count :
         {pin.event_count, pin.send_count, pin.receive_count}) {
        out.push_back(gf::FromU64_3(static_cast<uint32_t>(count)));
        out.push_back(gf::FromU64_3(static_cast<uint32_t>(count >> 32)));
    }
    HashLimbs(pin.schedule_commitment, out);
    HashLimbs(pin.trace_commitment, out);
    HashLimbs(pin.auxiliary_commitment, out);
    HashLimbs(pin.challenge_commitment, out);
    out.push_back(pin.terminal.alpha1_sum);
    out.push_back(pin.terminal.alpha2_sum);
    if (out.size() != kRCStage3CtlRecursivePinElements) {
        out.clear();
        return Fail(why, "recursive_pin:internal_size");
    }
    if (why != nullptr) *why = "stage3:ctl:ok";
    return true;
}

bool VerifyRCStage3CtlPublicPinComposition(
    const RCStage3CtlManifest& manifest,
    const std::vector<RCStage3CtlChildPin>& pins,
    std::string* why)
{
    if (!ValidateManifest(manifest, why)) return false;
    if (pins.size() != manifest.participants.size()) {
        return Fail(why, "composition:pin_count");
    }
    RCStage3CtlChallenges challenges;
    if (!DeriveRCStage3CtlChallenges(manifest, pins, challenges, why)) {
        return false;
    }
    const uint256 challenge_commitment =
        CommitRCStage3CtlChallenges(challenges);

    uint64_t sends{0};
    uint64_t receives{0};
    Fp3 total1 = Fp3::Zero();
    Fp3 total2 = Fp3::Zero();
    for (size_t i = 0; i < pins.size(); ++i) {
        const auto& pin = pins[i];
        const auto& participant = manifest.participants[i];
        if (!ValidatePin(pin, why, true)) return false;
        if (pin.role != participant.role || pin.bus_id != manifest.bus_id ||
            pin.event_count != participant.event_count ||
            pin.send_count != participant.send_count ||
            pin.receive_count != participant.receive_count ||
            pin.schedule_commitment != participant.schedule_commitment) {
            return Fail(why, "composition:participant_binding");
        }
        if (pin.challenge_commitment != challenge_commitment) {
            return Fail(why, "composition:challenge_binding");
        }
        if (!CheckedAdd(sends, pin.send_count, sends) ||
            !CheckedAdd(receives, pin.receive_count, receives)) {
            return Fail(why, "composition:count_overflow");
        }
        total1 = gf::Add(total1, pin.terminal.alpha1_sum);
        total2 = gf::Add(total2, pin.terminal.alpha2_sum);
    }
    if (sends != receives) return Fail(why, "composition:unbalanced_counts");
    if (!gf::IsZero(total1) || !gf::IsZero(total2)) {
        return Fail(why, "composition:nonzero_terminal");
    }
    if (why != nullptr) *why = "stage3:ctl:ok";
    return true;
}

uint256 CommitRCStage3CtlComposition(
    const RCStage3CtlManifest& manifest,
    const std::vector<RCStage3CtlChildPin>& pins)
{
    if (!VerifyRCStage3CtlPublicPinComposition(manifest, pins)) return {};
    std::vector<unsigned char> bytes;
    WriteDomain(bytes, "BTX_RC_STAGE3_CTL_COMPOSITION_V3");
    WriteHash(bytes, CommitManifest(manifest));
    WriteU16(bytes, static_cast<uint16_t>(pins.size()));
    for (const auto& pin : pins) {
        WriteHash(bytes, CommitRCStage3CtlChildPin(pin));
    }
    return Sha256d(bytes);
}

} // namespace matmul::v4::rc
