// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_SHIELDED_SMILE2_SERIALIZE_H
#define BTX_SHIELDED_SMILE2_SERIALIZE_H

#include <shielded/smile2/ct_proof.h>
#include <shielded/smile2/poly.h>
#include <span.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <ios>
#include <vector>

namespace smile2 {

enum class SmileProofCodecPolicy : uint8_t {
    CANONICAL_NO_RICE = 0,
    SMALLEST = 1,
    FORCE_RICE = 2,
};

enum class SmileCTDecodeStatus : uint8_t {
    OK = 0,
    MALFORMED = 1,
    DISALLOWED_RICE_CODEC = 2,
};

[[nodiscard]] constexpr uint32_t SmileCtHardenedWireMagic()
{
    // Legacy proofs start with the centered max-abs header for aux t0. That
    // value is always < Q/2, so 0xFFFFFFFF is an impossible legacy prefix.
    return 0xFFFFFFFFu;
}

// Serialize a SmileCTProof to bytes
std::vector<uint8_t> SerializeCTProof(
    const SmileCTProof& proof,
    SmileProofCodecPolicy codec_policy = SmileProofCodecPolicy::CANONICAL_NO_RICE);

// Deserialize a SmileCTProof from bytes for the reset-chain launch surface.
// The hard-fork codec is fixed-layout and derives most counts from the
// statement dimensions instead of serializing them redundantly.
SmileCTDecodeStatus DecodeCTProof(const std::vector<uint8_t>& data,
                                  SmileCTProof& proof,
                                  size_t num_inputs,
                                  size_t num_outputs,
                                  bool reject_rice_codec = false);
bool DeserializeCTProof(const std::vector<uint8_t>& data,
                        SmileCTProof& proof,
                        size_t num_inputs,
                        size_t num_outputs);

// Serialize a single polynomial (32 bits per coefficient)
void SerializePoly(const SmilePoly& p, std::vector<uint8_t>& out);

// Deserialize a single polynomial
bool DeserializePoly(const uint8_t*& ptr, const uint8_t* end, SmilePoly& p);

// Stream-based polynomial serialization for use in V2SendWitness.
// Writes POLY_DEGREE 32-bit little-endian coefficients to the stream.
template <typename Stream>
void SerializePoly(const SmilePoly& p, Stream& s)
{
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        uint32_t val = static_cast<uint32_t>(mod_q(p.coeffs[i]));
        s.write(AsBytes(Span<const uint32_t>{&val, 1}));
    }
}

// Stream-based polynomial deserialization for use in V2SendWitness.
template <typename Stream>
void DeserializePoly(Stream& s, SmilePoly& p)
{
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        uint32_t val;
        s.read(AsWritableBytes(Span<uint32_t>{&val, 1}));
        if (val >= static_cast<uint32_t>(Q)) {
            throw std::ios_base::failure("DeserializePoly non-canonical coefficient");
        }
        p.coeffs[i] = static_cast<int64_t>(val);
    }
}

// Serialize polynomial with compression (drop low-order D bits)
void SerializePolyCompressed(const SmilePoly& p, std::vector<uint8_t>& out, size_t drop_bits);

// Deserialize compressed polynomial
bool DeserializePolyCompressed(const uint8_t*& ptr, const uint8_t* end, SmilePoly& p, size_t drop_bits);

// Stream-based compressed polynomial serialization (Dilithium-style).
// Drops the low-order `drop_bits` bits from each 32-bit coefficient and
// bitpacks the remaining (32-drop_bits) bits.  With COMPRESS_D=12 this
// yields 20 bits per coefficient = 320 bytes per 128-coeff polynomial
// (vs 512 bytes uncompressed), a 37.5% saving.
template <typename Stream>
void SerializePolyCompressed(const SmilePoly& p, Stream& s, size_t drop_bits)
{
    const size_t keep_bits = 32 - drop_bits;
    // Bitpack into a temporary buffer, then write all at once.
    const size_t total_bytes = (POLY_DEGREE * keep_bits + 7) / 8;
    std::vector<uint8_t> buf(total_bytes, 0);
    size_t bit_pos = 0;
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        uint32_t compressed = static_cast<uint32_t>(mod_q(p.coeffs[i])) >> drop_bits;
        for (size_t b = 0; b < keep_bits; ++b) {
            if (compressed & (1u << b)) {
                buf[bit_pos / 8] |= static_cast<uint8_t>(1u << (bit_pos % 8));
            }
            ++bit_pos;
        }
    }
    s.write(MakeByteSpan(buf));
}

// Stream-based compressed polynomial deserialization.
template <typename Stream>
void DeserializePolyCompressed(Stream& s, SmilePoly& p, size_t drop_bits)
{
    const size_t keep_bits = 32 - drop_bits;
    const size_t total_bytes = (POLY_DEGREE * keep_bits + 7) / 8;
    std::vector<uint8_t> buf(total_bytes);
    s.read(MakeWritableByteSpan(buf));
    size_t bit_pos = 0;
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        uint32_t val = 0;
        for (size_t b = 0; b < keep_bits; ++b) {
            if (buf[bit_pos / 8] & (1u << (bit_pos % 8))) {
                val |= (1u << b);
            }
            ++bit_pos;
        }
        p.coeffs[i] = static_cast<int64_t>(val << drop_bits);
    }
}

// Serialize a polynomial vector
void SerializePolyVec(const SmilePolyVec& v, std::vector<uint8_t>& out);

// Deserialize a polynomial vector
bool DeserializePolyVec(const uint8_t*& ptr, const uint8_t* end, size_t count, SmilePolyVec& v);

// Exact centered bitpacked serialization for proof polynomials whose length is
// implied by the statement surface. This preserves the exact coefficients
// modulo q while avoiding the generic 32-bit-per-coefficient wire format.
void SerializeCenteredPolyExact(const SmilePoly& p, std::vector<uint8_t>& out);
bool DeserializeCenteredPolyExact(const uint8_t*& ptr, const uint8_t* end, SmilePoly& p);

template <typename Stream>
void SerializeCenteredPolyExact(const SmilePoly& p, Stream& s)
{
    std::vector<uint8_t> buf;
    SerializeCenteredPolyExact(p, buf);
    s.write(MakeByteSpan(buf));
}

template <typename Stream>
void DeserializeCenteredPolyExact(Stream& s, SmilePoly& p)
{
    std::array<uint8_t, 5> header{};
    s.read(AsWritableBytes(Span<uint8_t>{header.data(), header.size()}));

    const uint32_t max_abs =
        static_cast<uint32_t>(header[0]) |
        (static_cast<uint32_t>(header[1]) << 8) |
        (static_cast<uint32_t>(header[2]) << 16) |
        (static_cast<uint32_t>(header[3]) << 24);
    const uint8_t bits_needed = header[4];
    if (bits_needed == 0 || bits_needed > 32) {
        throw std::ios_base::failure("DeserializeCenteredPolyExact invalid bits_needed");
    }

    const size_t packed_bytes = (POLY_DEGREE * bits_needed + 7) / 8;
    std::vector<uint8_t> buf(header.size() + packed_bytes);
    std::memcpy(buf.data(), header.data(), header.size());
    if (packed_bytes > 0) {
        s.read(AsWritableBytes(Span<uint8_t>{buf.data() + header.size(), packed_bytes}));
    }

    const uint8_t* ptr = buf.data();
    const uint8_t* end = buf.data() + buf.size();
    if (!DeserializeCenteredPolyExact(ptr, end, p) || ptr != end) {
        throw std::ios_base::failure("DeserializeCenteredPolyExact malformed polynomial");
    }

    (void)max_abs;
}

void SerializeCenteredPolyVecFixed(const SmilePolyVec& v, std::vector<uint8_t>& out);
bool DeserializeCenteredPolyVecFixed(const uint8_t*& ptr,
                                     const uint8_t* end,
                                     size_t count,
                                     SmilePolyVec& v);

// Entropy-coded serialization for Gaussian-distributed z vectors
// Uses variable-length encoding (~12 bits per coefficient instead of 32)
void SerializeGaussianVec(const SmilePolyVec& z, std::vector<uint8_t>& out);
bool DeserializeGaussianVec(const uint8_t*& ptr, const uint8_t* end, size_t count, SmilePolyVec& z);

// Fixed-layout exact encoding for hard-fork Gaussian witness vectors where the
// vector length is implied by statement dimensions. The canonical serializer
// avoids the legacy Rice form; verifiers keep Rice decoding for pre-activation
// compatibility and explicit test coverage.
void SerializeGaussianVecFixed(
    const SmilePolyVec& z,
    std::vector<uint8_t>& out,
    SmileProofCodecPolicy codec_policy = SmileProofCodecPolicy::CANONICAL_NO_RICE);
bool DeserializeGaussianVecFixed(const uint8_t*& ptr, const uint8_t* end, size_t count, SmilePolyVec& z);

// Exact witness-vector encoding that chooses between the existing fixed
// Gaussian vector codec and a per-polynomial adaptive exact encoding. This is
// useful for small proof families whose members have mixed distributions, such
// as amount-side CT responses.
void SerializeAdaptiveWitnessPolyVec(
    const SmilePolyVec& z,
    std::vector<uint8_t>& out,
    SmileProofCodecPolicy codec_policy = SmileProofCodecPolicy::CANONICAL_NO_RICE);
bool DeserializeAdaptiveWitnessPolyVec(const uint8_t*& ptr,
                                       const uint8_t* end,
                                       size_t count,
                                       SmilePolyVec& z);

} // namespace smile2

#endif // BTX_SHIELDED_SMILE2_SERIALIZE_H
