// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_normalized_block_transport.h>

#include <matmul/matmul_v4_rc_stage3.h>
#include <primitives/block.h>

#include <limits>

namespace matmul::v4::rc::normalized_block_transport {
namespace {

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:normalized_block_transport_v3:" + detail;
    }
    return false;
}

} // namespace

bool PackReceiptWordsV3(
    const std::vector<unsigned char>& receipt_bytes,
    std::vector<uint32_t>& out,
    std::string* why)
{
    out.clear();
    if (receipt_bytes.empty() ||
        receipt_bytes.size() > kRCStage3MaxProofBytes ||
        receipt_bytes.size() >
            std::numeric_limits<uint32_t>::max()) {
        return Fail(why, "receipt_size");
    }
    std::string decode_why;
    if (!nav3::DeserializeNormalizedAuthorityReceiptV3(
            receipt_bytes, &decode_why).has_value()) {
        return Fail(why, "receipt:" + decode_why);
    }

    const size_t payload_words =
        (receipt_bytes.size() + sizeof(uint32_t) - 1) /
        sizeof(uint32_t);
    std::vector<uint32_t> packed(2 + payload_words, 0);
    packed[0] = kNormalizedBlockPayloadMagicV3;
    packed[1] =
        static_cast<uint32_t>(receipt_bytes.size());
    for (size_t index = 0;
         index < receipt_bytes.size();
         ++index) {
        packed[2 + index / sizeof(uint32_t)] |=
            static_cast<uint32_t>(receipt_bytes[index])
            << (8U * (index % sizeof(uint32_t)));
    }
    out = std::move(packed);
    if (why != nullptr) {
        *why =
            "stage3:normalized_block_transport_v3:"
            "packed_canonical";
    }
    return true;
}

std::optional<std::vector<unsigned char>>
UnpackReceiptWordsV3(
    const std::vector<uint32_t>& words,
    std::string* why)
{
    const auto fail =
        [&](const std::string& detail)
            -> std::optional<std::vector<unsigned char>> {
        Fail(why, detail);
        return std::nullopt;
    };
    if (words.size() < 3 ||
        words[0] != kNormalizedBlockPayloadMagicV3) {
        return fail("payload_magic");
    }
    const size_t byte_count = words[1];
    if (byte_count == 0 ||
        byte_count > kRCStage3MaxProofBytes) {
        return fail("payload_size");
    }
    const size_t payload_words =
        (byte_count + sizeof(uint32_t) - 1) /
        sizeof(uint32_t);
    if (words.size() != 2 + payload_words) {
        return fail("payload_word_count");
    }

    std::vector<unsigned char> bytes(byte_count);
    for (size_t index = 0; index < byte_count; ++index) {
        bytes[index] =
            static_cast<unsigned char>(
                words[2 + index / sizeof(uint32_t)] >>
                (8U * (index % sizeof(uint32_t))));
    }
    const size_t padded_bytes =
        payload_words * sizeof(uint32_t);
    for (size_t index = byte_count;
         index < padded_bytes;
         ++index) {
        const unsigned char pad =
            static_cast<unsigned char>(
                words[2 + index / sizeof(uint32_t)] >>
                (8U * (index % sizeof(uint32_t))));
        if (pad != 0) return fail("nonzero_padding");
    }

    std::string decode_why;
    if (!nav3::DeserializeNormalizedAuthorityReceiptV3(
            bytes, &decode_why).has_value()) {
        return fail("receipt:" + decode_why);
    }
    if (why != nullptr) {
        *why =
            "stage3:normalized_block_transport_v3:"
            "unpacked_canonical";
    }
    return bytes;
}

bool IsReceiptWordsV3(
    const std::vector<uint32_t>& words)
{
    return words.size() >= 3 &&
        words[0] == kNormalizedBlockPayloadMagicV3;
}

bool AttachReceiptV3(
    CBlock& block,
    const std::vector<unsigned char>& receipt_bytes,
    std::string* why)
{
    std::vector<uint32_t> packed;
    if (!PackReceiptWordsV3(
            receipt_bytes, packed, why)) {
        return false;
    }
    block.matrix_c_data = std::move(packed);
    return true;
}

bool VerifyAttachedReceiptV3(
    const CBlock& block,
    const aq::AirConstraintSystem<gf::Fp3>& rebuilt_parent_cs,
    const nav3::RebuiltVerifierInputsV3& rebuilt_inputs,
    aq::AirQuotientSplitRapRowsProof* decoded_parent_proof,
    std::string* why)
{
    if (decoded_parent_proof != nullptr) {
        *decoded_parent_proof = {};
    }
    std::string unpack_why;
    const auto receipt_bytes =
        UnpackReceiptWordsV3(
            block.matrix_c_data, &unpack_why);
    if (!receipt_bytes.has_value()) {
        return Fail(why, "unpack:" + unpack_why);
    }
    std::string verify_why;
    if (!normalized_relation_receipt_consumer::
            VerifyReceiptV1(
                rebuilt_parent_cs,
                rebuilt_inputs,
                *receipt_bytes,
                decoded_parent_proof,
                &verify_why)) {
        return Fail(
            why, "parent_verify:" + verify_why);
    }
    if (why != nullptr) {
        *why =
            "stage3:normalized_block_transport_v3:"
            "fresh_parent_verified";
    }
    return true;
}

} // namespace matmul::v4::rc::normalized_block_transport
