// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <shielded/matrict_plus_backend.h>

#include <consensus/amount.h>
#include <hash.h>
#include <random.h>
#include <shielded/lattice/params.h>
#include <streams.h>

#include <cstddef>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>

namespace shielded::matrictplus {
namespace {

constexpr std::string_view TAG_BACKEND_ID{"BTX_MatRiCTPlus_Backend_V1"};
constexpr std::string_view TAG_TEST_VECTOR{"BTX_MATRICT_TEST_VECTOR_V1"};
constexpr std::string_view TAG_SEEDED_FIXTURE{"BTX_MATRICT_PLUS_SEEDED_FIXTURE_V1"};

[[nodiscard]] uint256 DeterministicVectorHash(std::string_view tag, uint32_t index)
{
    HashWriter hw;
    hw << std::string{TAG_TEST_VECTOR};
    hw << std::string{tag};
    hw << index;
    return hw.GetSHA256();
}

[[nodiscard]] uint256 SeededVectorHash(const uint256& seed, std::string_view tag, uint32_t index)
{
    HashWriter hw;
    hw << std::string{TAG_SEEDED_FIXTURE};
    hw << seed;
    hw << std::string{tag};
    hw << index;
    return hw.GetSHA256();
}

[[nodiscard]] uint256 EnsureNonNullHash(const uint256& seed, std::string_view tag, uint32_t index)
{
    uint256 value = SeededVectorHash(seed, tag, index);
    if (!value.IsNull()) return value;
    value = SeededVectorHash(seed, tag, index + 0x80000000U);
    if (!value.IsNull()) return value;
    return uint256::ONE;
}

[[nodiscard]] ShieldedNote MakeDeterministicNote(CAmount value, uint32_t index)
{
    ShieldedNote note;
    note.value = value;
    note.recipient_pk_hash = DeterministicVectorHash("pkh", index);
    note.rho = DeterministicVectorHash("rho", index);
    note.rcm = DeterministicVectorHash("rcm", index);
    return note;
}

[[nodiscard]] ShieldedNote MakeSeededNote(const uint256& seed, CAmount value, uint32_t index)
{
    ShieldedNote note;
    note.value = value;
    note.recipient_pk_hash = EnsureNonNullHash(seed, "pkh", index);
    note.rho = EnsureNonNullHash(seed, "rho", index);
    note.rcm = EnsureNonNullHash(seed, "rcm", index);
    return note;
}

[[nodiscard]] std::vector<Nullifier> BuildInputNullifiers(const PortableFixture& fixture)
{
    if (fixture.input_notes.size() != fixture.ring_members.size() ||
        fixture.input_notes.size() != fixture.real_indices.size()) {
        return {};
    }

    std::vector<Nullifier> nullifiers;
    nullifiers.reserve(fixture.input_notes.size());
    for (size_t i = 0; i < fixture.input_notes.size(); ++i) {
        if (fixture.real_indices[i] >= fixture.ring_members[i].size()) return {};

        Nullifier nullifier;
        if (!ringct::DeriveInputNullifierForNote(nullifier,
                                                 fixture.spending_key,
                                                 fixture.input_notes[i],
                                                 fixture.ring_members[i][fixture.real_indices[i]])) {
            return {};
        }
        nullifiers.push_back(nullifier);
    }
    return nullifiers;
}

[[nodiscard]] const uint256& BackendId()
{
    static const uint256 backend_id = [] {
        HashWriter hw;
        hw << std::string{TAG_BACKEND_ID};
        return hw.GetSHA256();
    }();
    return backend_id;
}

[[nodiscard]] CAmount SelectBoundedAmount(const uint256& seed,
                                          std::string_view tag,
                                          uint32_t index,
                                          CAmount minimum,
                                          CAmount span)
{
    const uint256 digest = SeededVectorHash(seed, tag, index);
    const uint64_t offset = ReadLE64(digest.begin()) % static_cast<uint64_t>(span);
    const CAmount amount = minimum + static_cast<CAmount>(offset);
    if (!MoneyRange(amount)) {
        throw std::runtime_error("seeded MatRiCT+ amount fell outside MoneyRange");
    }
    return amount;
}

void FillSpendingKey(const uint256& seed, std::vector<unsigned char>& out)
{
    out.clear();
    out.reserve(32);
    uint32_t block = 0;
    while (out.size() < 32) {
        const uint256 chunk = SeededVectorHash(seed, "spending-key", block++);
        const size_t remaining = 32 - out.size();
        const size_t take = std::min<size_t>(remaining, uint256::size());
        out.insert(out.end(), chunk.begin(), chunk.begin() + take);
    }
}

} // namespace

bool PortableFixture::IsValid() const
{
    if (input_notes.empty() || output_notes.empty()) return false;
    if (input_notes.size() != input_nullifiers.size() ||
        input_notes.size() != ring_members.size() ||
        input_notes.size() != real_indices.size()) {
        return false;
    }
    if (output_notes.size() != output_note_commitments.size()) return false;
    if (input_notes.size() > ringct::MAX_MATRICT_INPUTS || output_notes.size() > ringct::MAX_MATRICT_OUTPUTS) {
        return false;
    }
    if (spending_key.size() != 32 || !MoneyRange(fee)) return false;
    if (ring_members.empty()) return false;

    const size_t ring_size = ring_members.front().size();
    if (!lattice::IsSupportedRingSize(ring_size)) return false;

    for (size_t i = 0; i < input_notes.size(); ++i) {
        if (ring_members[i].size() != ring_size) return false;
        if (real_indices[i] >= ring_members[i].size()) return false;
        if (ring_members[i][real_indices[i]] != input_notes[i].GetCommitment()) return false;
    }

    for (size_t i = 0; i < output_notes.size(); ++i) {
        if (output_note_commitments[i] != output_notes[i].GetCommitment()) return false;
    }

    return true;
}

uint256 GetBackendId()
{
    return BackendId();
}

PortableFixture BuildDeterministicFixture()
{
    PortableFixture fixture;
    fixture.input_notes = {
        MakeDeterministicNote(700, 0),
        MakeDeterministicNote(500, 1),
    };
    fixture.output_notes = {
        MakeDeterministicNote(600, 10),
        MakeDeterministicNote(450, 11),
    };
    fixture.ring_members.assign(fixture.input_notes.size(), std::vector<uint256>(lattice::RING_SIZE));
    for (size_t i = 0; i < fixture.ring_members.size(); ++i) {
        for (size_t j = 0; j < fixture.ring_members[i].size(); ++j) {
            fixture.ring_members[i][j] =
                DeterministicVectorHash("member", static_cast<uint32_t>(i * 100 + j));
        }
    }
    fixture.real_indices = {2, 3};
    fixture.ring_members[0][fixture.real_indices[0]] = fixture.input_notes[0].GetCommitment();
    fixture.ring_members[1][fixture.real_indices[1]] = fixture.input_notes[1].GetCommitment();
    fixture.spending_key.resize(32);
    for (size_t i = 0; i < fixture.spending_key.size(); ++i) {
        fixture.spending_key[i] = static_cast<unsigned char>(0x70 + i);
    }
    fixture.fee = 150;
    fixture.output_note_commitments.reserve(fixture.output_notes.size());
    for (const auto& note : fixture.output_notes) {
        fixture.output_note_commitments.push_back(note.GetCommitment());
    }
    fixture.input_nullifiers = BuildInputNullifiers(fixture);
    return fixture;
}

PortableFixture BuildFixtureFromSeed(const uint256& seed, size_t input_count, size_t output_count)
{
    if (input_count == 0 || output_count == 0) {
        throw std::runtime_error("MatRiCT+ fixture must include at least one input and one output");
    }
    if (input_count > ringct::MAX_MATRICT_INPUTS || output_count > ringct::MAX_MATRICT_OUTPUTS) {
        throw std::runtime_error("MatRiCT+ fixture exceeds proof family limits");
    }
    if (input_count > static_cast<size_t>(std::numeric_limits<uint32_t>::max()) ||
        output_count > static_cast<size_t>(std::numeric_limits<uint32_t>::max())) {
        throw std::runtime_error("MatRiCT+ fixture size exceeds uint32_t indexing");
    }

    PortableFixture fixture;
    fixture.input_notes.reserve(input_count);
    fixture.output_notes.reserve(output_count);
    fixture.ring_members.assign(input_count, std::vector<uint256>(lattice::RING_SIZE));
    fixture.real_indices.reserve(input_count);

    CAmount total_in{0};
    for (size_t i = 0; i < input_count; ++i) {
        const CAmount value = SelectBoundedAmount(seed, "input-value", static_cast<uint32_t>(i),
                                                  /*minimum=*/400, /*span=*/250);
        const auto next_total = total_in + value;
        if (!MoneyRange(next_total)) {
            throw std::runtime_error("MatRiCT+ seeded fixture input sum overflow");
        }
        total_in = next_total;
        fixture.input_notes.push_back(MakeSeededNote(seed, value, static_cast<uint32_t>(i)));
    }

    const CAmount max_fee = std::min<CAmount>(total_in - static_cast<CAmount>(output_count), 125);
    if (max_fee <= 0) {
        throw std::runtime_error("MatRiCT+ seeded fixture cannot reserve a positive fee");
    }
    fixture.fee = SelectBoundedAmount(seed, "fee", 0, /*minimum=*/25, /*span=*/max_fee - 24);
    CAmount remaining_out = total_in - fixture.fee;
    if (!MoneyRange(remaining_out) || remaining_out < static_cast<CAmount>(output_count)) {
        throw std::runtime_error("MatRiCT+ seeded fixture output budget underflow");
    }

    for (size_t i = 0; i < output_count; ++i) {
        const size_t outputs_left = output_count - i;
        const CAmount minimum_tail = static_cast<CAmount>(outputs_left - 1);
        CAmount value;
        if (i + 1 == output_count) {
            value = remaining_out;
        } else {
            const CAmount max_for_this = remaining_out - minimum_tail;
            value = SelectBoundedAmount(seed, "output-value", static_cast<uint32_t>(i),
                                        /*minimum=*/1, /*span=*/max_for_this);
        }
        if (!MoneyRange(value) || value <= 0) {
            throw std::runtime_error("MatRiCT+ seeded fixture produced invalid output amount");
        }
        fixture.output_notes.push_back(MakeSeededNote(seed, value, static_cast<uint32_t>(0x100 + i)));
        remaining_out -= value;
    }
    if (remaining_out != 0) {
        throw std::runtime_error("MatRiCT+ seeded fixture output partition did not exhaust budget");
    }

    for (size_t i = 0; i < input_count; ++i) {
        fixture.real_indices.push_back(ReadLE64(SeededVectorHash(seed, "real-index", static_cast<uint32_t>(i)).begin()) %
                                       lattice::RING_SIZE);
        for (size_t j = 0; j < lattice::RING_SIZE; ++j) {
            fixture.ring_members[i][j] =
                EnsureNonNullHash(seed, "member", static_cast<uint32_t>(i * 256 + j));
        }
        fixture.ring_members[i][fixture.real_indices[i]] = fixture.input_notes[i].GetCommitment();
    }

    FillSpendingKey(seed, fixture.spending_key);
    fixture.tx_binding_hash = EnsureNonNullHash(seed, "tx-binding", 0);
    fixture.output_note_commitments.reserve(output_count);
    for (const auto& note : fixture.output_notes) {
        fixture.output_note_commitments.push_back(note.GetCommitment());
    }
    fixture.input_nullifiers = BuildInputNullifiers(fixture);
    return fixture;
}

uint256 SerializeProofHash(const ringct::MatRiCTProof& proof)
{
    DataStream ds;
    ds << proof;

    HashWriter hw;
    if (!ds.empty()) {
        hw.write(Span<const std::byte>{reinterpret_cast<const std::byte*>(ds.data()), ds.size()});
    }
    return hw.GetSHA256();
}

bool CreateProof(ringct::MatRiCTProof& proof,
                 const PortableFixture& fixture,
                 Span<const unsigned char> rng_entropy)
{
    if (!fixture.IsValid()) return false;

    return ringct::CreateMatRiCTProof(proof,
                                      fixture.input_notes,
                                      fixture.output_notes,
                                      Span<const uint256>{fixture.output_note_commitments.data(),
                                                          fixture.output_note_commitments.size()},
                                      fixture.input_nullifiers,
                                      fixture.ring_members,
                                      fixture.real_indices,
                                      fixture.spending_key,
                                      fixture.fee,
                                      fixture.tx_binding_hash,
                                      rng_entropy);
}

bool VerifyProof(const ringct::MatRiCTProof& proof, const PortableFixture& fixture)
{
    if (!fixture.IsValid()) return false;

    return ringct::VerifyMatRiCTProof(proof,
                                      fixture.ring_members,
                                      fixture.input_nullifiers,
                                      fixture.output_note_commitments,
                                      fixture.fee,
                                      fixture.tx_binding_hash);
}

} // namespace shielded::matrictplus
