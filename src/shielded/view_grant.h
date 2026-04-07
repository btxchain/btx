// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_SHIELDED_VIEW_GRANT_H
#define BTX_SHIELDED_VIEW_GRANT_H

#include <consensus/amount.h>
#include <serialize.h>
#include <shielded/note.h>
#include <span.h>
#include <support/allocators/secure.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace shielded::viewgrants {

static constexpr uint8_t STRUCTURED_DISCLOSURE_VERSION{1};
static constexpr uint8_t DISCLOSE_AMOUNT{1U << 0};
static constexpr uint8_t DISCLOSE_RECIPIENT{1U << 1};
static constexpr uint8_t DISCLOSE_MEMO{1U << 2};
static constexpr uint8_t DISCLOSE_SENDER{1U << 3};
static constexpr uint8_t DISCLOSE_ALL{DISCLOSE_AMOUNT | DISCLOSE_RECIPIENT | DISCLOSE_MEMO | DISCLOSE_SENDER};

using SecureBytes = std::vector<uint8_t, secure_allocator<uint8_t>>;

[[nodiscard]] constexpr bool HasDisclosureField(uint8_t disclosure_flags, uint8_t field)
{
    return (disclosure_flags & field) != 0;
}

[[nodiscard]] bool IsValidDisclosureFlags(uint8_t disclosure_flags);
[[nodiscard]] std::optional<uint8_t> ParseDisclosureField(std::string_view field_name);
[[nodiscard]] std::vector<std::string> GetDisclosureFieldNames(uint8_t disclosure_flags);

struct SenderContext
{
    uint256 bridge_id;
    uint256 operation_id;

    [[nodiscard]] bool IsValid() const;

    SERIALIZE_METHODS(SenderContext, obj)
    {
        READWRITE(obj.bridge_id, obj.operation_id);
    }
};

struct StructuredDisclosurePayload
{
    uint8_t version{STRUCTURED_DISCLOSURE_VERSION};
    uint8_t disclosure_flags{0};
    CAmount amount{0};
    uint256 recipient_pk_hash;
    std::vector<unsigned char> memo;
    SenderContext sender;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        if (!IsValid()) {
            throw std::ios_base::failure("StructuredDisclosurePayload::Serialize invalid payload");
        }
        ::Serialize(s, version);
        ::Serialize(s, disclosure_flags);
        if (HasDisclosureField(disclosure_flags, DISCLOSE_AMOUNT)) {
            ::Serialize(s, amount);
        }
        if (HasDisclosureField(disclosure_flags, DISCLOSE_RECIPIENT)) {
            ::Serialize(s, recipient_pk_hash);
        }
        if (HasDisclosureField(disclosure_flags, DISCLOSE_MEMO)) {
            const uint64_t memo_size = memo.size();
            ::Serialize(s, COMPACTSIZE(memo_size));
            if (memo_size > 0) {
                s.write(AsBytes(Span<const unsigned char>{memo.data(), memo.size()}));
            }
        }
        if (HasDisclosureField(disclosure_flags, DISCLOSE_SENDER)) {
            ::Serialize(s, sender);
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        version = STRUCTURED_DISCLOSURE_VERSION;
        disclosure_flags = 0;
        amount = 0;
        recipient_pk_hash.SetNull();
        memo.clear();
        sender = {};

        ::Unserialize(s, version);
        ::Unserialize(s, disclosure_flags);
        if (HasDisclosureField(disclosure_flags, DISCLOSE_AMOUNT)) {
            ::Unserialize(s, amount);
        }
        if (HasDisclosureField(disclosure_flags, DISCLOSE_RECIPIENT)) {
            ::Unserialize(s, recipient_pk_hash);
        }
        if (HasDisclosureField(disclosure_flags, DISCLOSE_MEMO)) {
            uint64_t memo_size{0};
            ::Unserialize(s, COMPACTSIZE(memo_size));
            if (memo_size > MAX_SHIELDED_MEMO_SIZE) {
                throw std::ios_base::failure("StructuredDisclosurePayload::Unserialize oversized memo");
            }
            memo.resize(memo_size);
            if (memo_size > 0) {
                s.read(AsWritableBytes(Span<unsigned char>{memo.data(), memo.size()}));
            }
        }
        if (HasDisclosureField(disclosure_flags, DISCLOSE_SENDER)) {
            ::Unserialize(s, sender);
        }
        if (!IsValid()) {
            throw std::ios_base::failure("StructuredDisclosurePayload::Unserialize invalid payload");
        }
    }
};

[[nodiscard]] std::optional<StructuredDisclosurePayload> DecodeStructuredDisclosurePayload(Span<const uint8_t> bytes);
[[nodiscard]] std::vector<uint8_t> SerializeStructuredDisclosurePayload(const StructuredDisclosurePayload& payload);
[[nodiscard]] SecureBytes SerializeStructuredDisclosurePayloadSecure(const StructuredDisclosurePayload& payload);

} // namespace shielded::viewgrants

#endif // BTX_SHIELDED_VIEW_GRANT_H
