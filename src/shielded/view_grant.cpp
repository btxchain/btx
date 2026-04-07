// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <shielded/view_grant.h>

#include <streams.h>

#include <algorithm>
#include <array>
#include <cstring>

namespace shielded::viewgrants {
namespace {

template <typename ByteVector>
class ByteVectorWriter
{
public:
    ByteVectorWriter(ByteVector& data, size_t pos) : m_data{data}, m_pos{pos}
    {
        if (m_pos > m_data.size()) m_data.resize(m_pos);
    }

    void write(Span<const std::byte> src)
    {
        const size_t overwrite = std::min(src.size(), m_data.size() - m_pos);
        if (overwrite > 0) {
            std::memcpy(m_data.data() + m_pos, src.data(), overwrite);
        }
        if (overwrite < src.size()) {
            const size_t append = src.size() - overwrite;
            const size_t old_size = m_data.size();
            m_data.resize(old_size + append);
            std::memcpy(m_data.data() + old_size, src.data() + overwrite, append);
        }
        m_pos += src.size();
    }

    template <typename T>
    ByteVectorWriter& operator<<(const T& obj)
    {
        ::Serialize(*this, obj);
        return *this;
    }

private:
    ByteVector& m_data;
    size_t m_pos;
};

constexpr std::array<std::pair<std::string_view, uint8_t>, 4> DISCLOSURE_FIELD_MAP{{
    {"amount", DISCLOSE_AMOUNT},
    {"recipient", DISCLOSE_RECIPIENT},
    {"memo", DISCLOSE_MEMO},
    {"sender", DISCLOSE_SENDER},
}};

} // namespace

bool IsValidDisclosureFlags(uint8_t disclosure_flags)
{
    return disclosure_flags != 0 && (disclosure_flags & ~DISCLOSE_ALL) == 0;
}

std::optional<uint8_t> ParseDisclosureField(std::string_view field_name)
{
    const auto it = std::find_if(DISCLOSURE_FIELD_MAP.begin(),
                                 DISCLOSURE_FIELD_MAP.end(),
                                 [&](const auto& entry) { return entry.first == field_name; });
    if (it == DISCLOSURE_FIELD_MAP.end()) return std::nullopt;
    return it->second;
}

std::vector<std::string> GetDisclosureFieldNames(uint8_t disclosure_flags)
{
    std::vector<std::string> names;
    for (const auto& [field_name, flag] : DISCLOSURE_FIELD_MAP) {
        if (HasDisclosureField(disclosure_flags, flag)) {
            names.emplace_back(field_name);
        }
    }
    return names;
}

bool SenderContext::IsValid() const
{
    return !bridge_id.IsNull() && !operation_id.IsNull();
}

bool StructuredDisclosurePayload::IsValid() const
{
    if (version != STRUCTURED_DISCLOSURE_VERSION) return false;
    if (!IsValidDisclosureFlags(disclosure_flags)) return false;

    if (HasDisclosureField(disclosure_flags, DISCLOSE_AMOUNT)) {
        if (!MoneyRange(amount) || amount <= 0) return false;
    } else if (amount != 0) {
        return false;
    }

    if (HasDisclosureField(disclosure_flags, DISCLOSE_RECIPIENT)) {
        if (recipient_pk_hash.IsNull()) return false;
    } else if (!recipient_pk_hash.IsNull()) {
        return false;
    }

    if (HasDisclosureField(disclosure_flags, DISCLOSE_MEMO)) {
        if (memo.size() > MAX_SHIELDED_MEMO_SIZE) return false;
    } else if (!memo.empty()) {
        return false;
    }

    if (HasDisclosureField(disclosure_flags, DISCLOSE_SENDER)) {
        if (!sender.IsValid()) return false;
    } else if (sender.IsValid()) {
        return false;
    }

    return true;
}

std::optional<StructuredDisclosurePayload> DecodeStructuredDisclosurePayload(Span<const uint8_t> bytes)
{
    if (bytes.empty()) return std::nullopt;
    DataStream ds{bytes};
    StructuredDisclosurePayload payload;
    try {
        ds >> payload;
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (!ds.empty() || !payload.IsValid()) return std::nullopt;
    return payload;
}

std::vector<uint8_t> SerializeStructuredDisclosurePayload(const StructuredDisclosurePayload& payload)
{
    if (!payload.IsValid()) return {};
    DataStream ds{};
    ds << payload;
    const auto bytes = MakeUCharSpan(ds);
    return std::vector<uint8_t>(bytes.begin(), bytes.end());
}

SecureBytes SerializeStructuredDisclosurePayloadSecure(const StructuredDisclosurePayload& payload)
{
    if (!payload.IsValid()) return {};
    SecureBytes bytes;
    ByteVectorWriter writer{bytes, 0};
    writer << payload;
    return bytes;
}

} // namespace shielded::viewgrants
