// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_SHIELDED_RINGCT_PROOF_ENCODING_H
#define BTX_SHIELDED_RINGCT_PROOF_ENCODING_H

#include <serialize.h>
#include <shielded/lattice/polyvec.h>

#include <ios>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace shielded::ringct {

static constexpr size_t POLYVEC_SIGNED24_PACKED_SIZE{
    lattice::MODULE_RANK * lattice::POLY_N * 3U};
static constexpr size_t POLYVEC_SIGNED16_PACKED_SIZE{
    lattice::MODULE_RANK * lattice::POLY_N * sizeof(int16_t)};
static constexpr size_t POLYVEC_SIGNED8_PACKED_SIZE{
    lattice::MODULE_RANK * lattice::POLY_N * sizeof(int8_t)};
static constexpr size_t POLYVEC_MODQ24_PACKED_SIZE{
    lattice::MODULE_RANK * lattice::POLY_N * 3U};
static constexpr size_t POLYVEC_MODQ23_PACKED_SIZE{
    (lattice::MODULE_RANK * lattice::POLY_N * 23U) / 8U};

template <typename Stream>
void SerializePolyVecSigned8(Stream& s, const lattice::PolyVec& vec, std::string_view context)
{
    if (vec.size() != lattice::MODULE_RANK) {
        throw std::ios_base::failure(std::string(context) + ": invalid vector rank");
    }

    std::vector<int8_t> packed;
    packed.reserve(lattice::MODULE_RANK * lattice::POLY_N);
    for (const auto& poly : vec) {
        for (size_t i = 0; i < lattice::POLY_N; ++i) {
            const int32_t coeff = poly.coeffs[i];
            if (coeff < std::numeric_limits<int8_t>::min() ||
                coeff > std::numeric_limits<int8_t>::max()) {
                throw std::ios_base::failure(std::string(context) + ": signed8 coefficient overflow");
            }
            packed.push_back(static_cast<int8_t>(coeff));
        }
    }
    ::Serialize(s, packed);
}

template <typename Stream>
void UnserializePolyVecSigned8(Stream& s, lattice::PolyVec& vec, std::string_view context)
{
    static constexpr size_t EXPECTED_PACKED_COEFFS = lattice::MODULE_RANK * lattice::POLY_N;
    uint64_t packed_coeff_count{0};
    ::Unserialize(s, COMPACTSIZE(packed_coeff_count));
    if (packed_coeff_count != EXPECTED_PACKED_COEFFS) {
        throw std::ios_base::failure(std::string(context) + ": invalid packed signed8 length");
    }
    std::array<int8_t, EXPECTED_PACKED_COEFFS> packed{};
    for (size_t i = 0; i < EXPECTED_PACKED_COEFFS; ++i) {
        ::Unserialize(s, packed[i]);
    }

    vec.assign(lattice::MODULE_RANK, lattice::Poly256{});
    size_t offset{0};
    for (size_t rank = 0; rank < lattice::MODULE_RANK; ++rank) {
        for (size_t i = 0; i < lattice::POLY_N; ++i) {
            vec[rank].coeffs[i] = packed[offset++];
        }
    }
}

template <typename Stream>
void SerializePolyVecSigned24(Stream& s, const lattice::PolyVec& vec, std::string_view context)
{
    if (vec.size() != lattice::MODULE_RANK) {
        throw std::ios_base::failure(std::string(context) + ": invalid vector rank");
    }

    std::vector<unsigned char> packed;
    packed.reserve(POLYVEC_SIGNED24_PACKED_SIZE);
    for (const auto& poly : vec) {
        for (size_t i = 0; i < lattice::POLY_N; ++i) {
            const int32_t coeff = poly.coeffs[i];
            if (coeff < -(1 << 23) || coeff >= (1 << 23)) {
                throw std::ios_base::failure(std::string(context) + ": signed24 coefficient overflow");
            }
            // Two's complement encoding in 24 bits.
            const uint32_t encoded = static_cast<uint32_t>(coeff) & 0xFFFFFFU;
            packed.push_back(static_cast<unsigned char>(encoded & 0xFFU));
            packed.push_back(static_cast<unsigned char>((encoded >> 8) & 0xFFU));
            packed.push_back(static_cast<unsigned char>((encoded >> 16) & 0xFFU));
        }
    }
    ::Serialize(s, packed);
}

template <typename Stream>
void UnserializePolyVecSigned24(Stream& s, lattice::PolyVec& vec, std::string_view context)
{
    std::vector<unsigned char> packed;
    ::Unserialize(s, packed);
    if (packed.size() != POLYVEC_SIGNED24_PACKED_SIZE) {
        throw std::ios_base::failure(std::string(context) + ": invalid packed signed24 length");
    }

    vec.assign(lattice::MODULE_RANK, lattice::Poly256{});
    size_t offset{0};
    for (size_t rank = 0; rank < lattice::MODULE_RANK; ++rank) {
        for (size_t i = 0; i < lattice::POLY_N; ++i) {
            const uint32_t raw = static_cast<uint32_t>(packed[offset]) |
                                 (static_cast<uint32_t>(packed[offset + 1]) << 8) |
                                 (static_cast<uint32_t>(packed[offset + 2]) << 16);
            offset += 3;
            // Sign-extend from 24-bit two's complement.
            const int32_t value = (raw & 0x800000U)
                                      ? static_cast<int32_t>(raw | 0xFF000000U)
                                      : static_cast<int32_t>(raw);
            vec[rank].coeffs[i] = value;
        }
    }
}

template <typename Stream>
void SerializePolyVecSigned16(Stream& s, const lattice::PolyVec& vec, std::string_view context)
{
    if (vec.size() != lattice::MODULE_RANK) {
        throw std::ios_base::failure(std::string(context) + ": invalid vector rank");
    }

    std::vector<int16_t> packed;
    packed.reserve(lattice::MODULE_RANK * lattice::POLY_N);
    for (const auto& poly : vec) {
        for (size_t i = 0; i < lattice::POLY_N; ++i) {
            const int32_t coeff = poly.coeffs[i];
            if (coeff < std::numeric_limits<int16_t>::min() ||
                coeff > std::numeric_limits<int16_t>::max()) {
                throw std::ios_base::failure(std::string(context) + ": signed16 coefficient overflow");
            }
            packed.push_back(static_cast<int16_t>(coeff));
        }
    }
    ::Serialize(s, packed);
}

template <typename Stream>
void UnserializePolyVecSigned16(Stream& s, lattice::PolyVec& vec, std::string_view context)
{
    static constexpr size_t EXPECTED_PACKED_COEFFS = lattice::MODULE_RANK * lattice::POLY_N;
    uint64_t packed_coeff_count{0};
    ::Unserialize(s, COMPACTSIZE(packed_coeff_count));
    if (packed_coeff_count != EXPECTED_PACKED_COEFFS) {
        throw std::ios_base::failure(std::string(context) + ": invalid packed signed16 length");
    }
    std::array<int16_t, EXPECTED_PACKED_COEFFS> packed{};
    for (size_t i = 0; i < EXPECTED_PACKED_COEFFS; ++i) {
        ::Unserialize(s, packed[i]);
    }

    vec.assign(lattice::MODULE_RANK, lattice::Poly256{});
    size_t offset{0};
    for (size_t rank = 0; rank < lattice::MODULE_RANK; ++rank) {
        for (size_t i = 0; i < lattice::POLY_N; ++i) {
            vec[rank].coeffs[i] = packed[offset++];
        }
    }
}

template <typename Stream>
void SerializePolyVecModQ24(Stream& s, const lattice::PolyVec& vec, std::string_view context)
{
    if (vec.size() != lattice::MODULE_RANK) {
        throw std::ios_base::failure(std::string(context) + ": invalid vector rank");
    }

    std::vector<unsigned char> packed;
    packed.reserve(POLYVEC_MODQ24_PACKED_SIZE);
    for (const auto& poly : vec) {
        for (size_t i = 0; i < lattice::POLY_N; ++i) {
            const int32_t coeff = poly.coeffs[i];
            if (coeff < 0 || coeff >= lattice::POLY_Q) {
                throw std::ios_base::failure(std::string(context) + ": coefficient out of mod-q range");
            }
            const uint32_t value = static_cast<uint32_t>(coeff);
            packed.push_back(static_cast<unsigned char>(value & 0xFFU));
            packed.push_back(static_cast<unsigned char>((value >> 8) & 0xFFU));
            packed.push_back(static_cast<unsigned char>((value >> 16) & 0xFFU));
        }
    }
    ::Serialize(s, packed);
}

template <typename Stream>
void UnserializePolyVecModQ24(Stream& s, lattice::PolyVec& vec, std::string_view context)
{
    uint64_t packed_byte_count{0};
    ::Unserialize(s, COMPACTSIZE(packed_byte_count));
    if (packed_byte_count != POLYVEC_MODQ24_PACKED_SIZE) {
        throw std::ios_base::failure(std::string(context) + ": invalid packed mod-q length");
    }
    std::array<unsigned char, POLYVEC_MODQ24_PACKED_SIZE> packed{};
    s.read(MakeWritableByteSpan(packed));

    vec.assign(lattice::MODULE_RANK, lattice::Poly256{});
    size_t offset{0};
    for (size_t rank = 0; rank < lattice::MODULE_RANK; ++rank) {
        for (size_t i = 0; i < lattice::POLY_N; ++i) {
            const uint32_t value = static_cast<uint32_t>(packed[offset]) |
                                   (static_cast<uint32_t>(packed[offset + 1]) << 8) |
                                   (static_cast<uint32_t>(packed[offset + 2]) << 16);
            offset += 3;
            if (value >= static_cast<uint32_t>(lattice::POLY_Q)) {
                throw std::ios_base::failure(std::string(context) + ": decoded mod-q coefficient out of range");
            }
            vec[rank].coeffs[i] = static_cast<int32_t>(value);
        }
    }
}

template <typename Stream>
void SerializePolyVecModQ23(Stream& s, const lattice::PolyVec& vec, std::string_view context)
{
    if (vec.size() != lattice::MODULE_RANK) {
        throw std::ios_base::failure(std::string(context) + ": invalid vector rank");
    }

    std::array<unsigned char, POLYVEC_MODQ23_PACKED_SIZE> packed{};
    size_t out_pos{0};
    uint64_t accumulator{0};
    int accumulator_bits{0};

    for (const auto& poly : vec) {
        for (size_t i = 0; i < lattice::POLY_N; ++i) {
            const int32_t coeff = poly.coeffs[i];
            if (coeff < 0 || coeff >= lattice::POLY_Q) {
                throw std::ios_base::failure(std::string(context) + ": coefficient out of mod-q range");
            }
            accumulator |= static_cast<uint64_t>(static_cast<uint32_t>(coeff)) << accumulator_bits;
            accumulator_bits += 23;

            while (accumulator_bits >= 8) {
                if (out_pos >= packed.size()) {
                    throw std::ios_base::failure(std::string(context) + ": packed buffer overflow");
                }
                packed[out_pos++] = static_cast<unsigned char>(accumulator & 0xFFU);
                accumulator >>= 8;
                accumulator_bits -= 8;
            }
        }
    }

    if (accumulator_bits != 0 || out_pos != packed.size()) {
        throw std::ios_base::failure(std::string(context) + ": invalid packed size");
    }
    s.write(MakeByteSpan(packed));
}

template <typename Stream>
void UnserializePolyVecModQ23(Stream& s, lattice::PolyVec& vec, std::string_view context)
{
    std::array<unsigned char, POLYVEC_MODQ23_PACKED_SIZE> packed{};
    s.read(MakeWritableByteSpan(packed));

    vec.assign(lattice::MODULE_RANK, lattice::Poly256{});
    size_t in_pos{0};
    uint64_t accumulator{0};
    int accumulator_bits{0};

    for (size_t rank = 0; rank < lattice::MODULE_RANK; ++rank) {
        for (size_t i = 0; i < lattice::POLY_N; ++i) {
            while (accumulator_bits < 23) {
                if (in_pos >= packed.size()) {
                    throw std::ios_base::failure(std::string(context) + ": invalid packed length");
                }
                accumulator |= static_cast<uint64_t>(packed[in_pos++]) << accumulator_bits;
                accumulator_bits += 8;
            }

            const uint32_t value = static_cast<uint32_t>(accumulator & 0x7FFFFFU);
            accumulator >>= 23;
            accumulator_bits -= 23;

            if (value >= static_cast<uint32_t>(lattice::POLY_Q)) {
                throw std::ios_base::failure(std::string(context) + ": decoded mod-q coefficient out of range");
            }
            vec[rank].coeffs[i] = static_cast<int32_t>(value);
        }
    }

    if (in_pos != packed.size() || accumulator_bits != 0) {
        throw std::ios_base::failure(std::string(context) + ": trailing packed data");
    }
}

} // namespace shielded::ringct

#endif // BTX_SHIELDED_RINGCT_PROOF_ENCODING_H
