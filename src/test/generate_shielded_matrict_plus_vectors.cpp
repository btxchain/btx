// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <consensus/amount.h>
#include <shielded/matrict_plus_backend.h>
#include <shielded/note.h>
#include <shielded/ringct/matrict.h>
#include <streams.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <cstddef>
#include <cstdint>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace matrictplus = shielded::matrictplus;
using shielded::ringct::MatRiCTProof;

namespace {

UniValue ToHexArray(const std::vector<uint256>& values)
{
    UniValue out(UniValue::VARR);
    for (const uint256& value : values) {
        out.push_back(value.GetHex());
    }
    return out;
}

UniValue ToNestedHexArray(const std::vector<std::vector<uint256>>& values)
{
    UniValue out(UniValue::VARR);
    for (const auto& row : values) {
        out.push_back(ToHexArray(row));
    }
    return out;
}

UniValue ToSizeArray(const std::vector<size_t>& values)
{
    UniValue out(UniValue::VARR);
    for (const size_t value : values) {
        out.push_back(static_cast<uint64_t>(value));
    }
    return out;
}

UniValue NoteToJson(const ShieldedNote& note)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("value", static_cast<int64_t>(note.value));
    out.pushKV("recipient_pk_hash_hex", note.recipient_pk_hash.GetHex());
    out.pushKV("rho_hex", note.rho.GetHex());
    out.pushKV("rcm_hex", note.rcm.GetHex());
    out.pushKV("memo_hex", HexStr(note.memo));
    out.pushKV("commitment_hex", note.GetCommitment().GetHex());
    return out;
}

UniValue NotesToJson(const std::vector<ShieldedNote>& notes)
{
    UniValue out(UniValue::VARR);
    for (const auto& note : notes) {
        out.push_back(NoteToJson(note));
    }
    return out;
}

UniValue BuildFixtureJson(const matrictplus::PortableFixture& fixture)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("input_notes", NotesToJson(fixture.input_notes));
    out.pushKV("output_notes", NotesToJson(fixture.output_notes));
    out.pushKV("input_nullifiers_hex", ToHexArray(fixture.input_nullifiers));
    out.pushKV("ring_members_hex", ToNestedHexArray(fixture.ring_members));
    out.pushKV("output_note_commitments_hex", ToHexArray(fixture.output_note_commitments));
    out.pushKV("real_indices", ToSizeArray(fixture.real_indices));
    out.pushKV("spending_key_hex", HexStr(fixture.spending_key));
    out.pushKV("fee_sat", static_cast<int64_t>(fixture.fee));
    out.pushKV("tx_binding_hash_hex", fixture.tx_binding_hash.GetHex());
    return out;
}

UniValue BuildProofJson(const MatRiCTProof& proof)
{
    DataStream ds;
    ds << proof;
    std::vector<unsigned char> serialized;
    serialized.reserve(ds.size());
    for (const std::byte byte : ds) {
        serialized.push_back(std::to_integer<unsigned char>(byte));
    }

    UniValue out(UniValue::VOBJ);
    out.pushKV("serialized_size", static_cast<uint64_t>(serialized.size()));
    out.pushKV("serialized_proof_hash_hex", matrictplus::SerializeProofHash(proof).GetHex());
    out.pushKV("serialized_proof_hex", HexStr(serialized));
    out.pushKV("verification_expected", true);
    return out;
}

UniValue BuildVectorJson()
{
    const auto fixture = matrictplus::BuildDeterministicFixture();
    if (!fixture.IsValid()) throw std::runtime_error("deterministic MatRiCT+ fixture is invalid");

    MatRiCTProof proof;
    if (!matrictplus::CreateProof(proof, fixture)) {
        throw std::runtime_error("failed to create deterministic MatRiCT+ proof");
    }
    if (!matrictplus::VerifyProof(proof, fixture)) {
        throw std::runtime_error("deterministic MatRiCT+ proof failed verification");
    }

    UniValue out(UniValue::VOBJ);
    out.pushKV("format_version", 1);
    out.pushKV("backend_id_hex", matrictplus::GetBackendId().GetHex());
    out.pushKV("fixture", BuildFixtureJson(fixture));
    out.pushKV("proof", BuildProofJson(proof));
    return out;
}

} // namespace

int main()
{
    try {
        std::cout << BuildVectorJson().write(2) << '\n';
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "gen_shielded_matrict_plus_vectors: " << e.what() << '\n';
        return 1;
    }
}
