// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_SHIELDED_MATRICT_PLUS_BACKEND_H
#define BTX_SHIELDED_MATRICT_PLUS_BACKEND_H

#include <consensus/amount.h>
#include <shielded/note.h>
#include <shielded/ringct/matrict.h>

#include <span.h>
#include <uint256.h>

#include <cstddef>
#include <vector>

namespace shielded::matrictplus {

struct PortableFixture
{
    std::vector<ShieldedNote> input_notes;
    std::vector<ShieldedNote> output_notes;
    std::vector<Nullifier> input_nullifiers;
    std::vector<std::vector<uint256>> ring_members;
    std::vector<uint256> output_note_commitments;
    std::vector<size_t> real_indices;
    std::vector<unsigned char> spending_key;
    CAmount fee{0};
    uint256 tx_binding_hash{};

    [[nodiscard]] bool IsValid() const;
};

[[nodiscard]] uint256 GetBackendId();
[[nodiscard]] PortableFixture BuildDeterministicFixture();
[[nodiscard]] PortableFixture BuildFixtureFromSeed(const uint256& seed,
                                                   size_t input_count = 2,
                                                   size_t output_count = 2);
[[nodiscard]] uint256 SerializeProofHash(const ringct::MatRiCTProof& proof);
[[nodiscard]] bool CreateProof(ringct::MatRiCTProof& proof,
                               const PortableFixture& fixture,
                               Span<const unsigned char> rng_entropy = {});
[[nodiscard]] bool VerifyProof(const ringct::MatRiCTProof& proof, const PortableFixture& fixture);

} // namespace shielded::matrictplus

#endif // BTX_SHIELDED_MATRICT_PLUS_BACKEND_H
