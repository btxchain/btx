// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_bounded_semantic_codec.h>

#include <hash.h>
#include <matmul/matmul_v4_rc_gkr_field_ext3.h>
#include <primitives/block.h>
#include <tinyformat.h>

#include <algorithm>
#include <array>
#include <concepts>
#include <limits>
#include <type_traits>
#include <utility>

namespace matmul::v4::rc::bounded_semantic_codec {
namespace {

constexpr uint32_t kBlockMagicV1 =
    0x31425342U; // "BSB1"
constexpr uint32_t kMaxVectorItemsV1 =
    1U << 28;
constexpr size_t kEnvelopeHeaderBytesV1 =
    4 + 2 + 2 + 4 + 4 + 4;

bool Fail(
    std::string* why,
    const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:bounded_semantic_codec_v1:" +
            detail;
    }
    return false;
}

template <typename T>
struct IsVector : std::false_type {};
template <typename T, typename A>
struct IsVector<std::vector<T, A>> : std::true_type {
    using Value = T;
};

template <typename T>
struct IsArray : std::false_type {};
template <typename T, size_t N>
struct IsArray<std::array<T, N>> : std::true_type {
    using Value = T;
    static constexpr size_t kSize = N;
};

template <typename T>
struct IsOptional : std::false_type {};
template <typename T>
struct IsOptional<std::optional<T>> : std::true_type {
    using Value = T;
};

template <typename T>
struct IsPair : std::false_type {};
template <typename A, typename B>
struct IsPair<std::pair<A, B>> : std::true_type {};

struct AggregateAny {
    template <typename T>
    constexpr operator T() const noexcept;
};

template <typename T, size_t... I>
consteval bool AggregateInitializable(
    std::index_sequence<I...>)
{
    return requires {
        T{(static_cast<void>(I),
           AggregateAny{})...};
    };
}

template <typename T, size_t N = 0>
consteval size_t AggregateFieldCount()
{
    if constexpr (
        N == 32 ||
        !AggregateInitializable<T>(
            std::make_index_sequence<N + 1>{})) {
        return N;
    } else {
        return AggregateFieldCount<T, N + 1>();
    }
}

// Wire-order tripwires for the two complete inventories. Adding, removing or
// reordering a top-level family requires an explicit codec-version review.
static_assert(
    AggregateFieldCount<
        RCStage3BoundedEpisodeSemanticComposition>() ==
        17);
static_assert(
    AggregateFieldCount<
        RCStage3BoundedCoupledSemanticComposition>() ==
        9);

template <typename T, typename F>
bool VisitAggregate(T& value, F&& field)
{
    constexpr size_t n =
        AggregateFieldCount<
            std::remove_cvref_t<T>>();
    static_assert(
        n != 32 ||
            !AggregateInitializable<
                std::remove_cvref_t<T>>(
                std::make_index_sequence<33>{}),
        "bounded semantic codec aggregate exceeds 32 fields");
    bool ok = true;
    const auto visit =
        [&](auto& item) {
            if (ok) ok = field(item);
        };
    if constexpr (n == 0) {
        return true;
    } else if constexpr (n == 1) {
        auto& [a0] = value;
        visit(a0);
    } else if constexpr (n == 2) {
        auto& [a0, a1] = value;
        visit(a0); visit(a1);
    } else if constexpr (n == 3) {
        auto& [a0, a1, a2] = value;
        visit(a0); visit(a1); visit(a2);
    } else if constexpr (n == 4) {
        auto& [a0, a1, a2, a3] = value;
        visit(a0); visit(a1); visit(a2); visit(a3);
    } else if constexpr (n == 5) {
        auto& [a0, a1, a2, a3, a4] = value;
        visit(a0); visit(a1); visit(a2); visit(a3); visit(a4);
    } else if constexpr (n == 6) {
        auto& [a0, a1, a2, a3, a4, a5] = value;
        visit(a0); visit(a1); visit(a2); visit(a3); visit(a4); visit(a5);
    } else if constexpr (n == 7) {
        auto& [a0, a1, a2, a3, a4, a5, a6] = value;
        visit(a0); visit(a1); visit(a2); visit(a3); visit(a4); visit(a5);
        visit(a6);
    } else if constexpr (n == 8) {
        auto& [a0, a1, a2, a3, a4, a5, a6, a7] = value;
        visit(a0); visit(a1); visit(a2); visit(a3); visit(a4); visit(a5);
        visit(a6); visit(a7);
    } else if constexpr (n == 9) {
        auto& [a0, a1, a2, a3, a4, a5, a6, a7, a8] = value;
        visit(a0); visit(a1); visit(a2); visit(a3); visit(a4); visit(a5);
        visit(a6); visit(a7); visit(a8);
    } else if constexpr (n == 10) {
        auto& [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9] = value;
        visit(a0); visit(a1); visit(a2); visit(a3); visit(a4); visit(a5);
        visit(a6); visit(a7); visit(a8); visit(a9);
    } else if constexpr (n == 11) {
        auto& [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10] = value;
        visit(a0); visit(a1); visit(a2); visit(a3); visit(a4); visit(a5);
        visit(a6); visit(a7); visit(a8); visit(a9); visit(a10);
    } else if constexpr (n == 12) {
        auto& [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11] = value;
        visit(a0); visit(a1); visit(a2); visit(a3); visit(a4); visit(a5);
        visit(a6); visit(a7); visit(a8); visit(a9); visit(a10); visit(a11);
    } else if constexpr (n == 13) {
        auto& [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12] = value;
        visit(a0); visit(a1); visit(a2); visit(a3); visit(a4); visit(a5);
        visit(a6); visit(a7); visit(a8); visit(a9); visit(a10); visit(a11);
        visit(a12);
    } else if constexpr (n == 14) {
        auto& [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13] = value;
        visit(a0); visit(a1); visit(a2); visit(a3); visit(a4); visit(a5);
        visit(a6); visit(a7); visit(a8); visit(a9); visit(a10); visit(a11);
        visit(a12); visit(a13);
    } else if constexpr (n == 15) {
        auto& [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14] = value;
        visit(a0); visit(a1); visit(a2); visit(a3); visit(a4); visit(a5);
        visit(a6); visit(a7); visit(a8); visit(a9); visit(a10); visit(a11);
        visit(a12); visit(a13); visit(a14);
    } else if constexpr (n == 16) {
        auto& [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15] = value;
        visit(a0); visit(a1); visit(a2); visit(a3); visit(a4); visit(a5);
        visit(a6); visit(a7); visit(a8); visit(a9); visit(a10); visit(a11);
        visit(a12); visit(a13); visit(a14); visit(a15);
    } else if constexpr (n == 17) {
        auto& [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16] = value;
        visit(a0); visit(a1); visit(a2); visit(a3); visit(a4); visit(a5);
        visit(a6); visit(a7); visit(a8); visit(a9); visit(a10); visit(a11);
        visit(a12); visit(a13); visit(a14); visit(a15); visit(a16);
    } else if constexpr (n == 18) {
        auto& [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17] = value;
        visit(a0); visit(a1); visit(a2); visit(a3); visit(a4); visit(a5);
        visit(a6); visit(a7); visit(a8); visit(a9); visit(a10); visit(a11);
        visit(a12); visit(a13); visit(a14); visit(a15); visit(a16); visit(a17);
    } else if constexpr (n == 19) {
        auto& [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18] = value;
        visit(a0); visit(a1); visit(a2); visit(a3); visit(a4); visit(a5);
        visit(a6); visit(a7); visit(a8); visit(a9); visit(a10); visit(a11);
        visit(a12); visit(a13); visit(a14); visit(a15); visit(a16); visit(a17);
        visit(a18);
    } else if constexpr (n == 20) {
        auto& [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19] = value;
        visit(a0); visit(a1); visit(a2); visit(a3); visit(a4); visit(a5);
        visit(a6); visit(a7); visit(a8); visit(a9); visit(a10); visit(a11);
        visit(a12); visit(a13); visit(a14); visit(a15); visit(a16); visit(a17);
        visit(a18); visit(a19);
    } else if constexpr (n == 21) {
        auto& [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20] = value;
        visit(a0); visit(a1); visit(a2); visit(a3); visit(a4); visit(a5);
        visit(a6); visit(a7); visit(a8); visit(a9); visit(a10); visit(a11);
        visit(a12); visit(a13); visit(a14); visit(a15); visit(a16); visit(a17);
        visit(a18); visit(a19); visit(a20);
    } else if constexpr (n == 22) {
        auto& [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21] = value;
        visit(a0); visit(a1); visit(a2); visit(a3); visit(a4); visit(a5);
        visit(a6); visit(a7); visit(a8); visit(a9); visit(a10); visit(a11);
        visit(a12); visit(a13); visit(a14); visit(a15); visit(a16); visit(a17);
        visit(a18); visit(a19); visit(a20); visit(a21);
    } else if constexpr (n == 23) {
        auto& [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22] = value;
        visit(a0); visit(a1); visit(a2); visit(a3); visit(a4); visit(a5);
        visit(a6); visit(a7); visit(a8); visit(a9); visit(a10); visit(a11);
        visit(a12); visit(a13); visit(a14); visit(a15); visit(a16); visit(a17);
        visit(a18); visit(a19); visit(a20); visit(a21); visit(a22);
    } else if constexpr (n == 24) {
        auto& [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23] = value;
        visit(a0); visit(a1); visit(a2); visit(a3); visit(a4); visit(a5);
        visit(a6); visit(a7); visit(a8); visit(a9); visit(a10); visit(a11);
        visit(a12); visit(a13); visit(a14); visit(a15); visit(a16); visit(a17);
        visit(a18); visit(a19); visit(a20); visit(a21); visit(a22); visit(a23);
    } else if constexpr (n == 25) {
        auto& [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24] = value;
        visit(a0); visit(a1); visit(a2); visit(a3); visit(a4); visit(a5);
        visit(a6); visit(a7); visit(a8); visit(a9); visit(a10); visit(a11);
        visit(a12); visit(a13); visit(a14); visit(a15); visit(a16); visit(a17);
        visit(a18); visit(a19); visit(a20); visit(a21); visit(a22); visit(a23);
        visit(a24);
    } else if constexpr (n == 26) {
        auto& [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24, a25] = value;
        visit(a0); visit(a1); visit(a2); visit(a3); visit(a4); visit(a5);
        visit(a6); visit(a7); visit(a8); visit(a9); visit(a10); visit(a11);
        visit(a12); visit(a13); visit(a14); visit(a15); visit(a16); visit(a17);
        visit(a18); visit(a19); visit(a20); visit(a21); visit(a22); visit(a23);
        visit(a24); visit(a25);
    } else if constexpr (n == 27) {
        auto& [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24, a25, a26] = value;
        visit(a0); visit(a1); visit(a2); visit(a3); visit(a4); visit(a5);
        visit(a6); visit(a7); visit(a8); visit(a9); visit(a10); visit(a11);
        visit(a12); visit(a13); visit(a14); visit(a15); visit(a16); visit(a17);
        visit(a18); visit(a19); visit(a20); visit(a21); visit(a22); visit(a23);
        visit(a24); visit(a25); visit(a26);
    } else if constexpr (n == 28) {
        auto& [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24, a25, a26, a27] = value;
        visit(a0); visit(a1); visit(a2); visit(a3); visit(a4); visit(a5);
        visit(a6); visit(a7); visit(a8); visit(a9); visit(a10); visit(a11);
        visit(a12); visit(a13); visit(a14); visit(a15); visit(a16); visit(a17);
        visit(a18); visit(a19); visit(a20); visit(a21); visit(a22); visit(a23);
        visit(a24); visit(a25); visit(a26); visit(a27);
    } else if constexpr (n == 29) {
        auto& [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24, a25, a26, a27, a28] = value;
        visit(a0); visit(a1); visit(a2); visit(a3); visit(a4); visit(a5);
        visit(a6); visit(a7); visit(a8); visit(a9); visit(a10); visit(a11);
        visit(a12); visit(a13); visit(a14); visit(a15); visit(a16); visit(a17);
        visit(a18); visit(a19); visit(a20); visit(a21); visit(a22); visit(a23);
        visit(a24); visit(a25); visit(a26); visit(a27); visit(a28);
    } else if constexpr (n == 30) {
        auto& [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24, a25, a26, a27, a28, a29] = value;
        visit(a0); visit(a1); visit(a2); visit(a3); visit(a4); visit(a5);
        visit(a6); visit(a7); visit(a8); visit(a9); visit(a10); visit(a11);
        visit(a12); visit(a13); visit(a14); visit(a15); visit(a16); visit(a17);
        visit(a18); visit(a19); visit(a20); visit(a21); visit(a22); visit(a23);
        visit(a24); visit(a25); visit(a26); visit(a27); visit(a28); visit(a29);
    } else if constexpr (n == 31) {
        auto& [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24, a25, a26, a27, a28, a29, a30] = value;
        visit(a0); visit(a1); visit(a2); visit(a3); visit(a4); visit(a5);
        visit(a6); visit(a7); visit(a8); visit(a9); visit(a10); visit(a11);
        visit(a12); visit(a13); visit(a14); visit(a15); visit(a16); visit(a17);
        visit(a18); visit(a19); visit(a20); visit(a21); visit(a22); visit(a23);
        visit(a24); visit(a25); visit(a26); visit(a27); visit(a28); visit(a29);
        visit(a30);
    } else if constexpr (n == 32) {
        auto& [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24, a25, a26, a27, a28, a29, a30, a31] = value;
        visit(a0); visit(a1); visit(a2); visit(a3); visit(a4); visit(a5);
        visit(a6); visit(a7); visit(a8); visit(a9); visit(a10); visit(a11);
        visit(a12); visit(a13); visit(a14); visit(a15); visit(a16); visit(a17);
        visit(a18); visit(a19); visit(a20); visit(a21); visit(a22); visit(a23);
        visit(a24); visit(a25); visit(a26); visit(a27); visit(a28); visit(a29);
        visit(a30); visit(a31);
    }
    return ok;
}

class Writer {
public:
    explicit Writer(size_t max_bytes)
        : m_max_bytes(max_bytes)
    {
    }

    template <typename T>
    bool Value(const T& value)
    {
        using U = std::remove_cvref_t<T>;
        if constexpr (std::same_as<U, uint256>) {
            return Raw(value.begin(), value.size());
        } else if constexpr (
            std::same_as<U, gkr_field::Fp3>) {
            return Integer(
                       gkr_field::Canonical(value.c0)) &&
                Integer(
                       gkr_field::Canonical(value.c1)) &&
                Integer(
                       gkr_field::Canonical(value.c2));
        } else if constexpr (std::same_as<U, bool>) {
            return Byte(value ? 1 : 0);
        } else if constexpr (std::is_enum_v<U>) {
            return Integer(
                static_cast<
                    std::underlying_type_t<U>>(
                    value));
        } else if constexpr (std::is_integral_v<U>) {
            return Integer(value);
        } else if constexpr (
            std::same_as<U, std::string>) {
            return SizedBytes(
                reinterpret_cast<
                    const unsigned char*>(
                    value.data()),
                value.size());
        } else if constexpr (IsVector<U>::value) {
            if (value.size() >
                kMaxVectorItemsV1) {
                return false;
            }
            if (!Integer(
                    static_cast<uint32_t>(
                        value.size()))) {
                return false;
            }
            if constexpr (
                std::same_as<
                    typename IsVector<U>::Value,
                    bool>) {
                for (bool item : value) {
                    if (!Value(item)) return false;
                }
            } else {
                for (const auto& item : value) {
                    if (!Value(item)) return false;
                }
            }
            return true;
        } else if constexpr (IsArray<U>::value) {
            for (const auto& item : value) {
                if (!Value(item)) return false;
            }
            return true;
        } else if constexpr (IsOptional<U>::value) {
            return Value(value.has_value()) &&
                (!value.has_value() ||
                 Value(*value));
        } else if constexpr (IsPair<U>::value) {
            return Value(value.first) &&
                Value(value.second);
        } else if constexpr (std::is_aggregate_v<U>) {
            U& mutable_value =
                const_cast<U&>(value);
            return VisitAggregate(
                mutable_value,
                [&](const auto& field) {
                    return Value(field);
                });
        } else {
            static_assert(
                std::is_aggregate_v<U>,
                "unsupported bounded semantic codec field");
            return false;
        }
    }

    const std::vector<unsigned char>& Bytes() const
    {
        return m_bytes;
    }

private:
    bool Byte(unsigned char value)
    {
        return Raw(&value, 1);
    }

    template <typename T>
    bool Integer(T value)
    {
        using U = std::make_unsigned_t<T>;
        const U encoded =
            static_cast<U>(value);
        std::array<unsigned char, sizeof(U)>
            bytes{};
        for (size_t i = 0; i < bytes.size(); ++i) {
            bytes[i] =
                static_cast<unsigned char>(
                    encoded >> (8U * i));
        }
        return Raw(bytes.data(), bytes.size());
    }

    bool SizedBytes(
        const unsigned char* data,
        size_t size)
    {
        return size <= kMaxVectorItemsV1 &&
            Integer(
                static_cast<uint32_t>(size)) &&
            Raw(data, size);
    }

    bool Raw(
        const unsigned char* data,
        size_t size)
    {
        if (size >
                m_max_bytes -
                    std::min(
                        m_max_bytes,
                        m_bytes.size()) ||
            m_bytes.size() + size >
                m_max_bytes) {
            return false;
        }
        m_bytes.insert(
            m_bytes.end(), data, data + size);
        return true;
    }

    size_t m_max_bytes;
    std::vector<unsigned char> m_bytes;
};

class Reader {
public:
    explicit Reader(
        const std::vector<unsigned char>& bytes)
        : m_cursor(bytes.data()),
          m_end(bytes.data() + bytes.size())
    {
    }

    template <typename T>
    bool Value(T& value)
    {
        using U = std::remove_cvref_t<T>;
        if constexpr (std::same_as<U, uint256>) {
            if (Remaining() < value.size()) {
                return false;
            }
            value = uint256{
                Span<const unsigned char>{
                    m_cursor, value.size()}};
            m_cursor += value.size();
            return true;
        } else if constexpr (
            std::same_as<U, gkr_field::Fp3>) {
            return Integer(value.c0) &&
                Integer(value.c1) &&
                Integer(value.c2) &&
                value.c0 < gkr_field::kP &&
                value.c1 < gkr_field::kP &&
                value.c2 < gkr_field::kP;
        } else if constexpr (std::same_as<U, bool>) {
            uint8_t encoded = 0;
            if (!Integer(encoded) ||
                encoded > 1) {
                return false;
            }
            value = encoded != 0;
            return true;
        } else if constexpr (std::is_enum_v<U>) {
            std::underlying_type_t<U> encoded{};
            if (!Integer(encoded)) return false;
            value = static_cast<U>(encoded);
            return true;
        } else if constexpr (std::is_integral_v<U>) {
            return Integer(value);
        } else if constexpr (
            std::same_as<U, std::string>) {
            uint32_t size = 0;
            if (!Integer(size) ||
                size > Remaining()) {
                return false;
            }
            value.assign(
                reinterpret_cast<
                    const char*>(m_cursor),
                size);
            m_cursor += size;
            return true;
        } else if constexpr (IsVector<U>::value) {
            uint32_t count = 0;
            using Item =
                typename IsVector<U>::Value;
            constexpr size_t kItemStorage =
                std::same_as<Item, bool>
                ? 1
                : std::max<size_t>(
                      sizeof(Item), 1);
            if (!Integer(count) ||
                count > kMaxVectorItemsV1 ||
                count > Remaining() + 1 ||
                count >
                    kDirectCodecMaxBytesV1 /
                        kItemStorage) {
                return false;
            }
            value.clear();
            value.resize(count);
            if constexpr (
                std::same_as<
                    typename IsVector<U>::Value,
                    bool>) {
                for (uint32_t i = 0;
                     i < count; ++i) {
                    bool item = false;
                    if (!Value(item)) return false;
                    value[i] = item;
                }
            } else {
                for (auto& item : value) {
                    if (!Value(item)) return false;
                }
            }
            return true;
        } else if constexpr (IsArray<U>::value) {
            for (auto& item : value) {
                if (!Value(item)) return false;
            }
            return true;
        } else if constexpr (IsOptional<U>::value) {
            bool present = false;
            if (!Value(present)) return false;
            if (!present) {
                value.reset();
                return true;
            }
            typename IsOptional<U>::Value item{};
            if (!Value(item)) return false;
            value = std::move(item);
            return true;
        } else if constexpr (IsPair<U>::value) {
            return Value(value.first) &&
                Value(value.second);
        } else if constexpr (std::is_aggregate_v<U>) {
            return VisitAggregate(
                value,
                [&](auto& field) {
                    return Value(field);
                });
        } else {
            static_assert(
                std::is_aggregate_v<U>,
                "unsupported bounded semantic codec field");
            return false;
        }
    }

    size_t Remaining() const
    {
        return static_cast<size_t>(
            m_end - m_cursor);
    }

private:
    template <typename T>
    bool Integer(T& value)
    {
        using U = std::make_unsigned_t<T>;
        if (Remaining() < sizeof(U)) {
            return false;
        }
        U encoded = 0;
        for (size_t i = 0; i < sizeof(U); ++i) {
            encoded |=
                static_cast<U>(m_cursor[i])
                << (8U * i);
        }
        m_cursor += sizeof(U);
        value = static_cast<T>(encoded);
        return true;
    }

    const unsigned char* m_cursor;
    const unsigned char* m_end;
};

void AppendU16(
    std::vector<unsigned char>& out,
    uint16_t value)
{
    out.push_back(
        static_cast<unsigned char>(value));
    out.push_back(
        static_cast<unsigned char>(value >> 8));
}

void AppendU32(
    std::vector<unsigned char>& out,
    uint32_t value)
{
    for (uint32_t i = 0; i < 4; ++i) {
        out.push_back(
            static_cast<unsigned char>(
                value >> (8U * i)));
    }
}

bool ReadU16(
    const unsigned char*& cursor,
    const unsigned char* end,
    uint16_t& value)
{
    if (end - cursor < 2) return false;
    value =
        static_cast<uint16_t>(cursor[0]) |
        (static_cast<uint16_t>(cursor[1]) << 8);
    cursor += 2;
    return true;
}

bool ReadU32(
    const unsigned char*& cursor,
    const unsigned char* end,
    uint32_t& value)
{
    if (end - cursor < 4) return false;
    value =
        static_cast<uint32_t>(cursor[0]) |
        (static_cast<uint32_t>(cursor[1]) << 8) |
        (static_cast<uint32_t>(cursor[2]) << 16) |
        (static_cast<uint32_t>(cursor[3]) << 24);
    cursor += 4;
    return true;
}

template <typename T>
bool EncodeTyped(
    const T& value,
    std::vector<unsigned char>& out)
{
    Writer writer(kDirectCodecMaxBytesV1);
    if (!writer.Value(value)) {
        out.clear();
        return false;
    }
    out = writer.Bytes();
    return true;
}

template <typename T>
bool DecodeTyped(
    const std::vector<unsigned char>& bytes,
    T& out)
{
    if (bytes.empty() ||
        bytes.size() >
            kDirectCodecMaxBytesV1) {
        return false;
    }
    Reader reader(bytes);
    T decoded{};
    if (!reader.Value(decoded) ||
        reader.Remaining() != 0) {
        return false;
    }
    std::vector<unsigned char> canonical;
    if (!EncodeTyped(decoded, canonical) ||
        canonical != bytes) {
        return false;
    }
    out = std::move(decoded);
    return true;
}

} // namespace

std::string SizeReportV1::ToString() const
{
    return strprintf(
        "direct-semantic-inventory:"
        " statement=%u episode=%u coupled=%u"
        " envelope=%u direct_cap=%u(%s)"
        " consensus_cap=%u(%s)",
        statement_bytes, episode_bytes,
        coupled_bytes, envelope_bytes,
        kDirectCodecMaxBytesV1,
        direct_codec_fit ? "ok" : "OVER",
        kRCStage3MaxProofBytes,
        consensus_payload_fit ? "ok" : "OVER");
}

bool SerializeEnvelopeV1(
    const EnvelopeV1& envelope,
    std::vector<unsigned char>& out,
    SizeReportV1* size,
    std::string* why)
{
    out.clear();
    if (size != nullptr) *size = {};
    std::vector<unsigned char> statement;
    std::vector<unsigned char> episode;
    std::vector<unsigned char> coupled;
    std::string statement_why;
    const bool statement_ok =
        SerializeRCStage3Proof(
            envelope.statement, statement,
            &statement_why);
    const bool episode_ok =
        EncodeTyped(
            envelope.composition.episode,
            episode);
    const bool coupled_ok =
        EncodeTyped(
            envelope.composition.coupled,
            coupled);
    SizeReportV1 report;
    report.statement_bytes = statement.size();
    report.episode_bytes = episode.size();
    report.coupled_bytes = coupled.size();
    report.envelope_bytes =
        kEnvelopeHeaderBytesV1 +
        report.statement_bytes +
        report.episode_bytes +
        report.coupled_bytes;
    report.direct_codec_fit =
        statement_ok && episode_ok &&
        coupled_ok &&
        report.envelope_bytes <=
            kDirectCodecMaxBytesV1;
    report.consensus_payload_fit =
        report.direct_codec_fit &&
        report.envelope_bytes <=
            kRCStage3MaxProofBytes;
    if (size != nullptr) *size = report;
    if (!statement_ok) {
        return Fail(
            why,
            "statement:" + statement_why);
    }
    if (!episode_ok) {
        return Fail(
            why, "episode_direct_codec_cap");
    }
    if (!coupled_ok) {
        return Fail(
            why, "coupled_direct_codec_cap");
    }
    if (!report.direct_codec_fit ||
        statement.size() >
            std::numeric_limits<uint32_t>::max() ||
        episode.size() >
            std::numeric_limits<uint32_t>::max() ||
        coupled.size() >
            std::numeric_limits<uint32_t>::max()) {
        return Fail(
            why, "direct_codec_cap:" +
                report.ToString());
    }
    out.reserve(report.envelope_bytes);
    AppendU32(out, kEnvelopeMagicV1);
    AppendU16(out, kEnvelopeVersionV1);
    AppendU16(out, 0);
    AppendU32(
        out,
        static_cast<uint32_t>(
            statement.size()));
    AppendU32(
        out,
        static_cast<uint32_t>(
            episode.size()));
    AppendU32(
        out,
        static_cast<uint32_t>(
            coupled.size()));
    out.insert(
        out.end(), statement.begin(),
        statement.end());
    out.insert(
        out.end(), episode.begin(),
        episode.end());
    out.insert(
        out.end(), coupled.begin(),
        coupled.end());
    if (out.size() !=
        report.envelope_bytes) {
        out.clear();
        return Fail(why, "encoded_size");
    }
    if (why != nullptr) {
        *why =
            "stage3:bounded_semantic_codec_v1:"
            "complete_typed_inventory_encoded;" +
            report.ToString();
    }
    return true;
}

std::optional<EnvelopeV1>
DeserializeEnvelopeV1(
    const std::vector<unsigned char>& bytes,
    std::string* why)
{
    const auto fail =
        [&](const std::string& detail)
            -> std::optional<EnvelopeV1> {
        Fail(why, "decode_" + detail);
        return std::nullopt;
    };
    if (bytes.size() <=
            kEnvelopeHeaderBytesV1 ||
        bytes.size() >
            kDirectCodecMaxBytesV1) {
        return fail("size");
    }
    const unsigned char* cursor =
        bytes.data();
    const unsigned char* end =
        bytes.data() + bytes.size();
    uint32_t magic = 0;
    uint16_t version = 0;
    uint16_t reserved = 0;
    uint32_t statement_size = 0;
    uint32_t episode_size = 0;
    uint32_t coupled_size = 0;
    if (!ReadU32(cursor, end, magic) ||
        !ReadU16(cursor, end, version) ||
        !ReadU16(cursor, end, reserved) ||
        !ReadU32(
            cursor, end, statement_size) ||
        !ReadU32(
            cursor, end, episode_size) ||
        !ReadU32(
            cursor, end, coupled_size) ||
        magic != kEnvelopeMagicV1 ||
        version != kEnvelopeVersionV1 ||
        reserved != 0 ||
        statement_size == 0 ||
        episode_size == 0 ||
        coupled_size == 0) {
        return fail("header");
    }
    const uint64_t payload =
        uint64_t{statement_size} +
        episode_size + coupled_size;
    if (payload !=
        static_cast<uint64_t>(end - cursor)) {
        return fail("lengths");
    }
    std::vector<unsigned char> statement_bytes(
        cursor, cursor + statement_size);
    cursor += statement_size;
    std::vector<unsigned char> episode_bytes(
        cursor, cursor + episode_size);
    cursor += episode_size;
    std::vector<unsigned char> coupled_bytes(
        cursor, cursor + coupled_size);
    cursor += coupled_size;
    if (cursor != end) return fail("trailing");

    const auto statement =
        DeserializeRCStage3Proof(
            statement_bytes, why);
    if (!statement.has_value()) {
        return fail("statement");
    }
    EnvelopeV1 out;
    out.statement = *statement;
    if (!DecodeTyped(
            episode_bytes,
            out.composition.episode)) {
        return fail("episode");
    }
    if (!DecodeTyped(
            coupled_bytes,
            out.composition.coupled)) {
        return fail("coupled");
    }
    std::vector<unsigned char> canonical;
    if (!SerializeEnvelopeV1(
            out, canonical, nullptr,
            nullptr) ||
        canonical != bytes) {
        return fail("noncanonical");
    }
    if (why != nullptr) {
        *why =
            "stage3:bounded_semantic_codec_v1:"
            "complete_typed_inventory_decoded";
    }
    return out;
}

bool VerifyEnvelopeV1(
    const std::vector<unsigned char>& bytes,
    const CBlockHeader& header,
    const RCEpisodeParams& episode_params,
    const RCStage3CoupledShape& coupled_shape,
    EnvelopeV1* decoded,
    std::string* why)
{
    if (decoded != nullptr) *decoded = {};
    std::string decode_why;
    auto envelope =
        DeserializeEnvelopeV1(
            bytes, &decode_why);
    if (!envelope.has_value()) {
        return Fail(
            why, "decode:" + decode_why);
    }
    std::string verify_why;
    if (!VerifyRCStage3BoundedSemanticComposition(
            envelope->statement, header,
            episode_params, coupled_shape,
            envelope->composition,
            &verify_why)) {
        return Fail(
            why, "fresh_verify:" +
                verify_why);
    }
    if (decoded != nullptr) {
        *decoded = std::move(*envelope);
    }
    if (why != nullptr) {
        *why =
            "stage3:bounded_semantic_codec_v1:"
            "fresh_complete_typed_inventory_verified";
    }
    return true;
}

bool AttachEnvelopeV1(
    CBlock& block,
    const EnvelopeV1& envelope,
    SizeReportV1* size,
    std::string* why)
{
    std::vector<unsigned char> bytes;
    SizeReportV1 report;
    if (!SerializeEnvelopeV1(
            envelope, bytes, &report, why)) {
        if (size != nullptr) *size = report;
        return false;
    }
    if (size != nullptr) *size = report;
    if (!report.consensus_payload_fit) {
        return Fail(
            why, "consensus_payload_cap:" +
                report.ToString());
    }
    const size_t payload_words =
        (bytes.size() + 3) / 4;
    std::vector<uint32_t> words(
        2 + payload_words, 0);
    words[0] = kBlockMagicV1;
    words[1] =
        static_cast<uint32_t>(
            bytes.size());
    for (size_t i = 0;
         i < bytes.size(); ++i) {
        words[2 + i / 4] |=
            static_cast<uint32_t>(bytes[i])
            << (8U * (i % 4));
    }
    block.matrix_c_data =
        std::move(words);
    if (why != nullptr) {
        *why =
            "stage3:bounded_semantic_codec_v1:"
            "complete_typed_inventory_attached;" +
            report.ToString();
    }
    return true;
}

std::optional<std::vector<unsigned char>>
UnpackEnvelopeWordsV1(
    const std::vector<uint32_t>& words,
    std::string* why)
{
    const auto fail =
        [&](const std::string& detail)
            -> std::optional<
                std::vector<unsigned char>> {
        Fail(why, "unpack_" + detail);
        return std::nullopt;
    };
    if (words.size() < 3 ||
        words[0] != kBlockMagicV1) {
        return fail("magic");
    }
    const size_t byte_count = words[1];
    if (byte_count == 0 ||
        byte_count >
            kRCStage3MaxProofBytes) {
        return fail("size");
    }
    const size_t payload_words =
        (byte_count + 3) / 4;
    if (words.size() !=
        2 + payload_words) {
        return fail("word_count");
    }
    std::vector<unsigned char> bytes(
        byte_count);
    for (size_t i = 0;
         i < byte_count; ++i) {
        bytes[i] =
            static_cast<unsigned char>(
                words[2 + i / 4] >>
                (8U * (i % 4)));
    }
    for (size_t i = byte_count;
         i < payload_words * 4; ++i) {
        const auto pad =
            static_cast<unsigned char>(
                words[2 + i / 4] >>
                (8U * (i % 4)));
        if (pad != 0) {
            return fail("padding");
        }
    }
    if (!DeserializeEnvelopeV1(
            bytes, why).has_value()) {
        return fail("envelope");
    }
    return bytes;
}

bool VerifyAttachedEnvelopeV1(
    const CBlock& block,
    const RCEpisodeParams& episode_params,
    const RCStage3CoupledShape& coupled_shape,
    EnvelopeV1* decoded,
    std::string* why)
{
    const auto bytes =
        UnpackEnvelopeWordsV1(
            block.matrix_c_data, why);
    if (!bytes.has_value()) return false;
    return VerifyEnvelopeV1(
        *bytes, block, episode_params,
        coupled_shape, decoded, why);
}

} // namespace matmul::v4::rc::bounded_semantic_codec
