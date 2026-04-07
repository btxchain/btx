// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_SHIELDED_ACCOUNT_REGISTRY_PROOF_H
#define BTX_SHIELDED_ACCOUNT_REGISTRY_PROOF_H

#include <consensus/consensus.h>
#include <serialize.h>
#include <span.h>
#include <uint256.h>

#include <cstdint>
#include <ios>
#include <vector>

namespace shielded::registry {

static constexpr uint8_t REGISTRY_WIRE_VERSION{1};
static constexpr uint64_t MAX_REGISTRY_PROOF_SIBLINGS{64};
static constexpr uint64_t MAX_REGISTRY_ENTRIES{1'000'000};

namespace detail {

template <typename Stream>
void SerializeBoundedCompactSize(Stream& s,
                                 uint64_t size,
                                 uint64_t max_size,
                                 const char* error)
{
    if (size > max_size) {
        throw std::ios_base::failure(error);
    }
    ::WriteCompactSize(s, size);
}

template <typename Stream>
uint64_t UnserializeBoundedCompactSize(Stream& s,
                                       uint64_t max_size,
                                       const char* error)
{
    const uint64_t size = ::ReadCompactSize(s);
    if (size > max_size) {
        throw std::ios_base::failure(error);
    }
    return size;
}

} // namespace detail

struct ShieldedAccountRegistryEntry
{
    uint8_t version{REGISTRY_WIRE_VERSION};
    uint64_t leaf_index{0};
    uint256 account_leaf_commitment;
    std::vector<uint8_t> account_leaf_payload;
    bool spent{false};

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        if (!IsValid()) {
            throw std::ios_base::failure("ShieldedAccountRegistryEntry::Serialize invalid entry");
        }
        ::Serialize(s, version);
        ::Serialize(s, leaf_index);
        ::Serialize(s, account_leaf_commitment);
        detail::SerializeBoundedCompactSize(
            s,
            account_leaf_payload.size(),
            MAX_BLOCK_SERIALIZED_SIZE,
            "ShieldedAccountRegistryEntry::Serialize oversized account_leaf_payload");
        if (!account_leaf_payload.empty()) {
            s.write(AsBytes(Span<const uint8_t>{account_leaf_payload.data(), account_leaf_payload.size()}));
        }
        ::Serialize(s, spent);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, version);
        if (version != REGISTRY_WIRE_VERSION) {
            throw std::ios_base::failure("ShieldedAccountRegistryEntry::Unserialize invalid version");
        }
        ::Unserialize(s, leaf_index);
        ::Unserialize(s, account_leaf_commitment);
        const uint64_t payload_size = detail::UnserializeBoundedCompactSize(
            s,
            MAX_BLOCK_SERIALIZED_SIZE,
            "ShieldedAccountRegistryEntry::Unserialize oversized account_leaf_payload");
        account_leaf_payload.assign(payload_size, 0);
        if (payload_size > 0) {
            s.read(AsWritableBytes(Span<uint8_t>{account_leaf_payload.data(), account_leaf_payload.size()}));
        }
        ::Unserialize(s, spent);
        if (!IsValid()) {
            throw std::ios_base::failure("ShieldedAccountRegistryEntry::Unserialize invalid entry");
        }
    }
};

struct ShieldedAccountRegistryProof
{
    uint8_t version{REGISTRY_WIRE_VERSION};
    ShieldedAccountRegistryEntry entry;
    std::vector<uint256> sibling_path;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        if (!IsValid()) {
            throw std::ios_base::failure("ShieldedAccountRegistryProof::Serialize invalid proof");
        }
        ::Serialize(s, version);
        ::Serialize(s, entry);
        detail::SerializeBoundedCompactSize(
            s,
            sibling_path.size(),
            MAX_REGISTRY_PROOF_SIBLINGS,
            "ShieldedAccountRegistryProof::Serialize oversized sibling_path");
        for (const uint256& sibling : sibling_path) {
            ::Serialize(s, sibling);
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, version);
        if (version != REGISTRY_WIRE_VERSION) {
            throw std::ios_base::failure("ShieldedAccountRegistryProof::Unserialize invalid version");
        }
        ::Unserialize(s, entry);
        const uint64_t sibling_count = detail::UnserializeBoundedCompactSize(
            s,
            MAX_REGISTRY_PROOF_SIBLINGS,
            "ShieldedAccountRegistryProof::Unserialize oversized sibling_path");
        sibling_path.assign(sibling_count, {});
        for (uint256& sibling : sibling_path) {
            ::Unserialize(s, sibling);
        }
        if (!IsValid()) {
            throw std::ios_base::failure("ShieldedAccountRegistryProof::Unserialize invalid proof");
        }
    }
};

struct ShieldedAccountRegistrySpendWitness
{
    uint8_t version{REGISTRY_WIRE_VERSION};
    uint64_t leaf_index{0};
    uint256 account_leaf_commitment;
    std::vector<uint256> sibling_path;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        if (!IsValid()) {
            throw std::ios_base::failure(
                "ShieldedAccountRegistrySpendWitness::Serialize invalid witness");
        }
        ::Serialize(s, version);
        ::Serialize(s, leaf_index);
        ::Serialize(s, account_leaf_commitment);
        detail::SerializeBoundedCompactSize(
            s,
            sibling_path.size(),
            MAX_REGISTRY_PROOF_SIBLINGS,
            "ShieldedAccountRegistrySpendWitness::Serialize oversized sibling_path");
        for (const uint256& sibling : sibling_path) {
            ::Serialize(s, sibling);
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, version);
        if (version != REGISTRY_WIRE_VERSION) {
            throw std::ios_base::failure(
                "ShieldedAccountRegistrySpendWitness::Unserialize invalid version");
        }
        ::Unserialize(s, leaf_index);
        ::Unserialize(s, account_leaf_commitment);
        const uint64_t sibling_count = detail::UnserializeBoundedCompactSize(
            s,
            MAX_REGISTRY_PROOF_SIBLINGS,
            "ShieldedAccountRegistrySpendWitness::Unserialize oversized sibling_path");
        sibling_path.assign(sibling_count, {});
        for (uint256& sibling : sibling_path) {
            ::Unserialize(s, sibling);
        }
        if (!IsValid()) {
            throw std::ios_base::failure(
                "ShieldedAccountRegistrySpendWitness::Unserialize invalid witness");
        }
    }
};

[[nodiscard]] uint256 ComputeShieldedAccountRegistryEntryCommitment(
    const ShieldedAccountRegistryEntry& entry);
[[nodiscard]] bool VerifyShieldedAccountRegistryProof(const ShieldedAccountRegistryProof& proof,
                                                      const uint256& expected_root);
[[nodiscard]] std::optional<ShieldedAccountRegistrySpendWitness>
BuildShieldedAccountRegistrySpendWitness(const ShieldedAccountRegistryProof& proof);

} // namespace shielded::registry

#endif // BTX_SHIELDED_ACCOUNT_REGISTRY_PROOF_H
