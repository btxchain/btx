// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/smile2/serialize.h>

#include <crypto/common.h>

#include <bit>
#include <cstring>
#include <limits>

namespace smile2 {

namespace {

constexpr uint8_t kExactPolyCodecCentered = 0;
constexpr uint8_t kExactPolyCodecGaussian = 1;
constexpr uint8_t kWitnessVecCodecGaussian = 0;
constexpr uint8_t kWitnessVecCodecPolywiseExact = 1;

void WriteU32(std::vector<uint8_t>& out, uint32_t val) {
    uint8_t buf[4];
    WriteLE32(buf, val);
    out.insert(out.end(), buf, buf + sizeof(buf));
}

bool ReadU32(const uint8_t*& ptr, const uint8_t* end, uint32_t& val) {
    if (ptr + 4 > end) return false;
    val = ReadLE32(ptr);
    ptr += 4;
    return true;
}

void WriteBytes(std::vector<uint8_t>& out, const uint8_t* data, size_t len) {
    out.insert(out.end(), data, data + len);
}

bool ReadBytes(const uint8_t*& ptr, const uint8_t* end, uint8_t* data, size_t len) {
    if (ptr + len > end) return false;
    std::memcpy(data, ptr, len);
    ptr += len;
    return true;
}

// Center a mod-q coefficient to [-q/2, q/2]
int64_t CenterCoeff(int64_t c) {
    c = mod_q(c);
    return c > Q / 2 ? c - Q : c;
}

constexpr size_t kCtPublicRowCount = KEY_ROWS + 2;

size_t ComputeLiveCtAuxMsgCount(size_t num_inputs, size_t num_outputs)
{
    const size_t selectors = num_inputs;
    const size_t amounts = num_inputs + num_outputs;
    const size_t w_rows = num_inputs * kCtPublicRowCount;
    const size_t x_slots = num_inputs;
    const size_t tail = 2; // g, psi
    return selectors + amounts + w_rows + x_slots + tail;
}

size_t ComputeLiveCtRetainedAuxMsgCount(size_t num_inputs, size_t num_outputs)
{
    (void)num_inputs;
    (void)num_outputs;
    return 0;
}

size_t ComputeLiveCtW0Offset(size_t num_inputs, size_t num_outputs)
{
    return num_inputs + num_inputs + num_outputs;
}

size_t InferLiveCtOutputCount(const SmileCTProof& proof)
{
    const size_t num_inputs = proof.z0.size();
    const size_t fixed_slots =
        num_inputs +                    // selectors
        num_inputs +                    // input amounts
        num_inputs * kCtPublicRowCount +// W0 tuple-account rows
        num_inputs +                    // X slots
        2;                              // G and Psi
    if (proof.aux_commitment.t_msg.size() < fixed_slots) {
        return 0;
    }
    return proof.aux_commitment.t_msg.size() - fixed_slots;
}

bool IsLiveCtW0Slot(size_t num_inputs, size_t num_outputs, size_t slot)
{
    const size_t w0_offset = ComputeLiveCtW0Offset(num_inputs, num_outputs);
    const size_t w0_count = num_inputs * kCtPublicRowCount;
    return slot >= w0_offset && slot < w0_offset + w0_count;
}

SmilePolyVec CollectSerializedOmittedAuxSelectorAmountResidues(const SmileCTProof& proof,
                                                               size_t num_inputs,
                                                               size_t num_outputs)
{
    SmilePolyVec serialized;
    const size_t retained_count = ComputeLiveCtRetainedAuxMsgCount(num_inputs, num_outputs);
    const size_t split_slot = ComputeLiveCtW0Offset(num_inputs, num_outputs);
    for (size_t slot = retained_count;
         slot < proof.aux_residues.size() && slot < split_slot;
         ++slot) {
        serialized.push_back(proof.aux_residues[slot]);
    }
    return serialized;
}

SmilePolyVec CollectSerializedOmittedAuxTailResidues(const SmileCTProof& proof,
                                                     size_t num_inputs,
                                                     size_t num_outputs)
{
    SmilePolyVec serialized;
    const size_t tail_offset =
        ComputeLiveCtW0Offset(num_inputs, num_outputs) + num_inputs * kCtPublicRowCount;
    for (size_t slot = tail_offset; slot < proof.aux_residues.size(); ++slot) {
        serialized.push_back(proof.aux_residues[slot]);
    }
    return serialized;
}

BDLOPCommitmentKey GetCtPublicCoinCommitmentKey()
{
    std::array<uint8_t, 32> out_ck_seed{};
    out_ck_seed[0] = 0xCC;
    return BDLOPCommitmentKey::Generate(out_ck_seed, 1);
}

// Bitstream writer for bitpacked encoding
class BitWriter {
    std::vector<uint8_t>& out;
    uint8_t current = 0;
    int bits_used = 0;
public:
    explicit BitWriter(std::vector<uint8_t>& o) : out(o) {}

    void WriteBit(bool bit) {
        if (bit) current |= (1u << bits_used);
        bits_used++;
        if (bits_used == 8) {
            out.push_back(current);
            current = 0;
            bits_used = 0;
        }
    }

    void Write(uint32_t val, int bits) {
        for (int i = 0; i < bits; ++i) {
            WriteBit((val & (1u << i)) != 0);
        }
    }

    void Flush() {
        if (bits_used > 0) {
            out.push_back(current);
            current = 0;
            bits_used = 0;
        }
    }
};

// Bitstream reader
class BitReader {
    const uint8_t* data;
    size_t total_bits;
    size_t pos = 0;

    static uint8_t LowBitMask(size_t bits)
    {
        if (bits >= 8) {
            return 0xFF;
        }
        return static_cast<uint8_t>((uint16_t{1} << bits) - 1);
    }
public:
    BitReader(const uint8_t* d, size_t byte_len) : data(d), total_bits(byte_len * 8) {}

    bool Read(int bits, uint32_t& val) {
        if (pos + static_cast<size_t>(bits) > total_bits) return false;
        val = 0;
        for (int i = 0; i < bits; ++i) {
            size_t byte_idx = (pos + i) / 8;
            size_t bit_idx = (pos + i) % 8;
            if (data[byte_idx] & (1u << bit_idx)) val |= (1u << i);
        }
        pos += bits;
        return true;
    }

    bool ReadUnary(uint32_t& run_len)
    {
        run_len = 0;
        while (pos < total_bits) {
            const size_t byte_idx = pos / 8;
            const size_t bit_idx = pos % 8;
            const size_t bits_available = std::min<size_t>(8 - bit_idx, total_bits - pos);
            const uint8_t valid_mask = LowBitMask(bits_available);
            const uint8_t chunk = static_cast<uint8_t>((data[byte_idx] >> bit_idx) & valid_mask);
            const uint8_t zero_mask = static_cast<uint8_t>((~chunk) & valid_mask);
            if (zero_mask != 0) {
                const unsigned run = std::countr_zero(static_cast<unsigned>(zero_mask));
                if (run_len > std::numeric_limits<uint32_t>::max() - run) {
                    return false;
                }
                run_len += run;
                pos += static_cast<size_t>(run) + 1;
                return true;
            }
            if (run_len > std::numeric_limits<uint32_t>::max() - bits_available) {
                return false;
            }
            run_len += static_cast<uint32_t>(bits_available);
            pos += bits_available;
        }
        return false;
    }

    [[nodiscard]] size_t BitsRead() const { return pos; }
};

uint8_t ComputeBitsNeededForCenteredRange(int64_t max_abs)
{
    uint64_t range = static_cast<uint64_t>(2 * max_abs + 1);
    uint8_t bits_needed = 1;
    while ((1ULL << bits_needed) < range) bits_needed++;
    return bits_needed;
}

int64_t ComputeCenteredMaxAbs(const SmilePoly& p)
{
    int64_t max_abs = 0;
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        const int64_t centered = CenterCoeff(p.coeffs[i]);
        const int64_t abs_val = centered < 0 ? -centered : centered;
        if (abs_val > max_abs) max_abs = abs_val;
    }
    return max_abs;
}

int64_t ComputeCenteredMaxAbs(const SmilePolyVec& v)
{
    int64_t max_abs = 0;
    for (const auto& p : v) {
        const int64_t poly_max_abs = ComputeCenteredMaxAbs(p);
        if (poly_max_abs > max_abs) max_abs = poly_max_abs;
    }
    return max_abs;
}

constexpr uint8_t kGaussianCodecCentered = 0;
constexpr uint8_t kGaussianCodecRice = 1;
constexpr uint8_t kGaussianCodecPolywiseCentered = 2;

void WriteWireHeader(std::vector<uint8_t>& out, uint8_t version)
{
    WriteU32(out, SmileCtHardenedWireMagic());
    out.push_back(version);
}

[[nodiscard]] bool ReadWireHeader(const std::vector<uint8_t>& data,
                                  size_t& body_offset,
                                  uint8_t& version)
{
    body_offset = 0;
    version = SmileCTProof::WIRE_VERSION_LEGACY;
    if (data.size() < 5) {
        return false;
    }
    const uint32_t maybe_magic = ReadLE32(data.data());
    if (maybe_magic != SmileCtHardenedWireMagic()) {
        return false;
    }
    body_offset = 5;
    version = data[4];
    return true;
}

uint32_t ZigZagEncodeCentered(int64_t centered)
{
    if (centered >= 0) {
        return static_cast<uint32_t>(centered) << 1;
    }
    return (static_cast<uint32_t>(-centered) << 1) - 1;
}

int64_t ZigZagDecodeCentered(uint32_t encoded)
{
    if ((encoded & 1U) == 0) {
        return static_cast<int64_t>(encoded >> 1);
    }
    return -static_cast<int64_t>((encoded + 1) >> 1);
}

uint64_t ComputeGaussianRiceBitCost(const SmilePolyVec& z, uint8_t k)
{
    uint64_t total_bits = 0;
    for (const auto& poly : z) {
        for (size_t i = 0; i < POLY_DEGREE; ++i) {
            const uint32_t encoded = ZigZagEncodeCentered(CenterCoeff(poly.coeffs[i]));
            total_bits += static_cast<uint64_t>(encoded >> k) + 1 + k;
        }
    }
    return total_bits;
}

uint8_t ChooseGaussianRiceParameter(const SmilePolyVec& z)
{
    uint8_t best_k = 0;
    uint64_t best_bits = ComputeGaussianRiceBitCost(z, 0);
    for (uint8_t k = 1; k <= 15; ++k) {
        const uint64_t bits = ComputeGaussianRiceBitCost(z, k);
        if (bits < best_bits) {
            best_bits = bits;
            best_k = k;
        }
    }
    return best_k;
}

void SerializeGaussianVecFixedRice(const SmilePolyVec& z, std::vector<uint8_t>& out, uint8_t k)
{
    out.push_back(k);
    BitWriter bw(out);
    for (const auto& poly : z) {
        for (size_t i = 0; i < POLY_DEGREE; ++i) {
            const uint32_t encoded = ZigZagEncodeCentered(CenterCoeff(poly.coeffs[i]));
            uint32_t q = encoded >> k;
            while (q-- > 0) {
                bw.WriteBit(true);
            }
            bw.WriteBit(false);
            if (k > 0) {
                bw.Write(encoded & ((1u << k) - 1), static_cast<int>(k));
            }
        }
    }
    bw.Flush();
}

bool DeserializeGaussianVecFixedRice(const uint8_t*& ptr,
                                     const uint8_t* end,
                                     size_t count,
                                     SmilePolyVec& z)
{
    if (ptr >= end) return false;
    const uint8_t k = *ptr++;
    if (k > 15) return false;

    z.resize(count);
    BitReader br(ptr, end - ptr);
    for (size_t poly = 0; poly < count; ++poly) {
        for (size_t coeff = 0; coeff < POLY_DEGREE; ++coeff) {
            uint32_t q = 0;
            if (!br.ReadUnary(q)) return false;
            uint32_t remainder = 0;
            if (k > 0 && !br.Read(static_cast<int>(k), remainder)) return false;
            const uint32_t encoded = (q << k) | remainder;
            z[poly].coeffs[coeff] = mod_q(ZigZagDecodeCentered(encoded));
        }
    }
    ptr += (br.BitsRead() + 7) / 8;
    return true;
}

SmileCTDecodeStatus DecodeGaussianVecFixed(const uint8_t*& ptr,
                                           const uint8_t* end,
                                           size_t count,
                                           SmilePolyVec& z,
                                           bool reject_rice_codec);

void SerializeGaussianVecFixedPolywiseCentered(const SmilePolyVec& z, std::vector<uint8_t>& out)
{
    for (const auto& poly : z) {
        SerializeCenteredPolyExact(poly, out);
    }
}

bool DeserializeGaussianVecFixedPolywiseCentered(const uint8_t*& ptr,
                                                 const uint8_t* end,
                                                 size_t count,
                                                 SmilePolyVec& z)
{
    z.resize(count);
    for (size_t poly = 0; poly < count; ++poly) {
        if (!DeserializeCenteredPolyExact(ptr, end, z[poly])) return false;
    }
    return true;
}

void SerializeExactPolyAdaptive(const SmilePoly& p, std::vector<uint8_t>& out)
{
    std::vector<uint8_t> centered_buf;
    SerializeCenteredPolyExact(p, centered_buf);

    SmilePolyVec singleton{p};
    std::vector<uint8_t> gaussian_buf;
    SerializeGaussianVecFixed(singleton, gaussian_buf, SmileProofCodecPolicy::CANONICAL_NO_RICE);

    if (gaussian_buf.size() < centered_buf.size()) {
        out.push_back(kExactPolyCodecGaussian);
        out.insert(out.end(), gaussian_buf.begin(), gaussian_buf.end());
        return;
    }

    out.push_back(kExactPolyCodecCentered);
    out.insert(out.end(), centered_buf.begin(), centered_buf.end());
}

SmileCTDecodeStatus DecodeExactPolyAdaptive(const uint8_t*& ptr,
                                            const uint8_t* end,
                                            SmilePoly& p,
                                            bool reject_rice_codec)
{
    if (ptr >= end) return SmileCTDecodeStatus::MALFORMED;

    const uint8_t codec = *ptr++;
    switch (codec) {
    case kExactPolyCodecCentered:
        return DeserializeCenteredPolyExact(ptr, end, p)
            ? SmileCTDecodeStatus::OK
            : SmileCTDecodeStatus::MALFORMED;
    case kExactPolyCodecGaussian: {
        SmilePolyVec singleton;
        const auto status = DecodeGaussianVecFixed(ptr, end, 1, singleton, reject_rice_codec);
        if (status != SmileCTDecodeStatus::OK) {
            return status;
        }
        if (singleton.size() != 1) {
            return SmileCTDecodeStatus::MALFORMED;
        }
        p = singleton[0];
        return SmileCTDecodeStatus::OK;
    }
    default:
        return SmileCTDecodeStatus::MALFORMED;
    }
}

} // anonymous namespace

void SerializePoly(const SmilePoly& p, std::vector<uint8_t>& out) {
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        uint32_t val = static_cast<uint32_t>(mod_q(p.coeffs[i]));
        WriteU32(out, val);
    }
}

bool DeserializePoly(const uint8_t*& ptr, const uint8_t* end, SmilePoly& p) {
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        uint32_t val;
        if (!ReadU32(ptr, end, val)) return false;
        if (val >= static_cast<uint32_t>(Q)) return false;
        p.coeffs[i] = static_cast<int64_t>(val);
    }
    return true;
}

void SerializePolyCompressed(const SmilePoly& p, std::vector<uint8_t>& out, size_t drop_bits) {
    // Bitpack (32-drop_bits) bits per coefficient
    size_t keep_bits = 32 - drop_bits;
    BitWriter bw(out);
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        uint32_t val = static_cast<uint32_t>(mod_q(p.coeffs[i]));
        uint32_t compressed = val >> drop_bits;
        bw.Write(compressed, static_cast<int>(keep_bits));
    }
    bw.Flush();
}

bool DeserializePolyCompressed(const uint8_t*& ptr, const uint8_t* end, SmilePoly& p, size_t drop_bits) {
    size_t keep_bits = 32 - drop_bits;
    size_t total_bytes = (POLY_DEGREE * keep_bits + 7) / 8;
    if (ptr + total_bytes > end) return false;
    BitReader br(ptr, total_bytes);
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        uint32_t val;
        if (!br.Read(static_cast<int>(keep_bits), val)) return false;
        const uint64_t expanded = static_cast<uint64_t>(val) << drop_bits;
        if (expanded >= static_cast<uint64_t>(Q)) return false;
        p.coeffs[i] = static_cast<int64_t>(expanded);
    }
    ptr += total_bytes;
    return true;
}

void SerializePolyVec(const SmilePolyVec& v, std::vector<uint8_t>& out) {
    WriteU32(out, static_cast<uint32_t>(v.size()));
    for (const auto& p : v) {
        SerializePoly(p, out);
    }
}

bool DeserializePolyVec(const uint8_t*& ptr, const uint8_t* end, size_t count, SmilePolyVec& v) {
    v.resize(count);
    for (size_t i = 0; i < count; ++i) {
        if (!DeserializePoly(ptr, end, v[i])) return false;
    }
    return true;
}

void SerializeCenteredPolyExact(const SmilePoly& p, std::vector<uint8_t>& out)
{
    const int64_t max_abs = ComputeCenteredMaxAbs(p);
    WriteU32(out, static_cast<uint32_t>(max_abs));

    const uint8_t bits_needed = ComputeBitsNeededForCenteredRange(max_abs);
    out.push_back(bits_needed);

    BitWriter bw(out);
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        const int64_t centered = CenterCoeff(p.coeffs[i]);
        const uint32_t encoded = static_cast<uint32_t>(centered + max_abs);
        bw.Write(encoded, bits_needed);
    }
    bw.Flush();
}

bool DeserializeCenteredPolyExact(const uint8_t*& ptr, const uint8_t* end, SmilePoly& p)
{
    uint32_t max_abs_u32;
    if (!ReadU32(ptr, end, max_abs_u32)) return false;
    const int64_t offset = static_cast<int64_t>(max_abs_u32);

    if (ptr >= end) return false;
    const uint8_t bits_needed = *ptr++;
    if (bits_needed == 0 || bits_needed > 32) return false;

    const size_t total_bits = POLY_DEGREE * bits_needed;
    const size_t total_bytes = (total_bits + 7) / 8;
    if (ptr + total_bytes > end) return false;

    BitReader br(ptr, total_bytes);
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        uint32_t encoded;
        if (!br.Read(bits_needed, encoded)) return false;
        const int64_t centered = static_cast<int64_t>(encoded) - offset;
        p.coeffs[i] = mod_q(centered);
    }
    ptr += total_bytes;
    return true;
}

void SerializeCenteredPolyVecFixed(const SmilePolyVec& v, std::vector<uint8_t>& out)
{
    if (v.empty()) return;

    const int64_t max_abs = ComputeCenteredMaxAbs(v);
    WriteU32(out, static_cast<uint32_t>(max_abs));

    const uint8_t bits_needed = ComputeBitsNeededForCenteredRange(max_abs);
    out.push_back(bits_needed);

    BitWriter bw(out);
    for (const auto& p : v) {
        for (size_t i = 0; i < POLY_DEGREE; ++i) {
            const int64_t centered = CenterCoeff(p.coeffs[i]);
            const uint32_t encoded = static_cast<uint32_t>(centered + max_abs);
            bw.Write(encoded, bits_needed);
        }
    }
    bw.Flush();
}

bool DeserializeCenteredPolyVecFixed(const uint8_t*& ptr,
                                     const uint8_t* end,
                                     size_t count,
                                     SmilePolyVec& v)
{
    v.resize(count);
    if (count == 0) return true;

    uint32_t max_abs_u32;
    if (!ReadU32(ptr, end, max_abs_u32)) return false;
    const int64_t offset = static_cast<int64_t>(max_abs_u32);

    if (ptr >= end) return false;
    const uint8_t bits_needed = *ptr++;
    if (bits_needed == 0 || bits_needed > 32) return false;

    const size_t total_bits = count * POLY_DEGREE * bits_needed;
    const size_t total_bytes = (total_bits + 7) / 8;
    if (ptr + total_bytes > end) return false;

    BitReader br(ptr, total_bytes);
    for (size_t poly = 0; poly < count; ++poly) {
        for (size_t coeff = 0; coeff < POLY_DEGREE; ++coeff) {
            uint32_t encoded;
            if (!br.Read(bits_needed, encoded)) return false;
            const int64_t centered = static_cast<int64_t>(encoded) - offset;
            v[poly].coeffs[coeff] = mod_q(centered);
        }
    }
    ptr += total_bytes;
    return true;
}

// Bitpacked Gaussian encoding: center coefficients and pack at fixed bit width
void SerializeGaussianVec(const SmilePolyVec& z, std::vector<uint8_t>& out) {
    WriteU32(out, static_cast<uint32_t>(z.size()));
    // Determine bit width from the actual maximum centered coefficient
    int64_t max_abs = 0;
    for (const auto& p : z) {
        for (size_t i = 0; i < POLY_DEGREE; ++i) {
            int64_t centered = CenterCoeff(p.coeffs[i]);
            int64_t a = centered < 0 ? -centered : centered;
            if (a > max_abs) max_abs = a;
        }
    }
    // Store max_abs as offset (16 bits suffices for σ ≤ 65535)
    WriteU32(out, static_cast<uint32_t>(max_abs));

    // Compute bits needed for range [0, 2*max_abs]
    uint64_t range = static_cast<uint64_t>(2 * max_abs + 1);
    uint8_t bits_needed = 1;
    while ((1ULL << bits_needed) < range) bits_needed++;
    out.push_back(bits_needed);

    // Encode: offset each centered value by max_abs to make unsigned
    BitWriter bw(out);
    for (const auto& p : z) {
        for (size_t i = 0; i < POLY_DEGREE; ++i) {
            int64_t centered = CenterCoeff(p.coeffs[i]);
            uint32_t encoded = static_cast<uint32_t>(centered + max_abs);
            bw.Write(encoded, bits_needed);
        }
    }
    bw.Flush();
}

bool DeserializeGaussianVec(const uint8_t*& ptr, const uint8_t* end, size_t count, SmilePolyVec& z) {
    z.resize(count);
    if (count == 0) return true;

    uint32_t max_abs_u32;
    if (!ReadU32(ptr, end, max_abs_u32)) return false;
    int64_t offset = static_cast<int64_t>(max_abs_u32);

    if (ptr >= end) return false;
    uint8_t bits_needed = *ptr++;
    if (bits_needed > 32 || bits_needed == 0) return false;

    size_t total_bits = count * POLY_DEGREE * bits_needed;
    size_t total_bytes = (total_bits + 7) / 8;
    if (ptr + total_bytes > end) return false;

    BitReader br(ptr, total_bytes);
    for (size_t p = 0; p < count; ++p) {
        for (size_t i = 0; i < POLY_DEGREE; ++i) {
            uint32_t encoded;
            if (!br.Read(bits_needed, encoded)) return false;
            int64_t centered = static_cast<int64_t>(encoded) - offset;
            z[p].coeffs[i] = mod_q(centered);
        }
    }
    ptr += total_bytes;
    return true;
}

void SerializeGaussianVecFixed(const SmilePolyVec& z,
                               std::vector<uint8_t>& out,
                               SmileProofCodecPolicy codec_policy) {
    if (z.empty()) {
        return;
    }

    std::vector<uint8_t> centered_buf;
    SerializeCenteredPolyVecFixed(z, centered_buf);

    std::vector<uint8_t> polywise_buf;
    SerializeGaussianVecFixedPolywiseCentered(z, polywise_buf);

    const uint8_t rice_k = ChooseGaussianRiceParameter(z);
    std::vector<uint8_t> rice_buf;
    SerializeGaussianVecFixedRice(z, rice_buf, rice_k);

    const size_t centered_size = 1 + centered_buf.size();
    const size_t rice_size = 1 + rice_buf.size();
    const size_t polywise_size = 1 + polywise_buf.size();

    if (codec_policy == SmileProofCodecPolicy::FORCE_RICE) {
        out.push_back(kGaussianCodecRice);
        out.insert(out.end(), rice_buf.begin(), rice_buf.end());
        return;
    }

    if (codec_policy == SmileProofCodecPolicy::CANONICAL_NO_RICE) {
        out.push_back(kGaussianCodecCentered);
        out.insert(out.end(), centered_buf.begin(), centered_buf.end());
        return;
    }

    if (codec_policy == SmileProofCodecPolicy::SMALLEST &&
        rice_size <= centered_size &&
        rice_size <= polywise_size) {
        out.push_back(kGaussianCodecRice);
        out.insert(out.end(), rice_buf.begin(), rice_buf.end());
        return;
    }

    if (polywise_size < centered_size) {
        out.push_back(kGaussianCodecPolywiseCentered);
        out.insert(out.end(), polywise_buf.begin(), polywise_buf.end());
        return;
    }

    out.push_back(kGaussianCodecCentered);
    out.insert(out.end(), centered_buf.begin(), centered_buf.end());
}

namespace {

SmileCTDecodeStatus DecodeGaussianVecFixed(const uint8_t*& ptr,
                                           const uint8_t* end,
                                           size_t count,
                                           SmilePolyVec& z,
                                           bool reject_rice_codec)
{
    if (count == 0) {
        z.clear();
        return SmileCTDecodeStatus::OK;
    }
    if (ptr >= end) return SmileCTDecodeStatus::MALFORMED;

    const uint8_t codec = *ptr++;
    switch (codec) {
    case kGaussianCodecCentered:
        return DeserializeCenteredPolyVecFixed(ptr, end, count, z)
            ? SmileCTDecodeStatus::OK
            : SmileCTDecodeStatus::MALFORMED;
    case kGaussianCodecRice:
        if (reject_rice_codec) {
            return SmileCTDecodeStatus::DISALLOWED_RICE_CODEC;
        }
        return DeserializeGaussianVecFixedRice(ptr, end, count, z)
            ? SmileCTDecodeStatus::OK
            : SmileCTDecodeStatus::MALFORMED;
    case kGaussianCodecPolywiseCentered:
        return DeserializeGaussianVecFixedPolywiseCentered(ptr, end, count, z)
            ? SmileCTDecodeStatus::OK
            : SmileCTDecodeStatus::MALFORMED;
    default:
        return SmileCTDecodeStatus::MALFORMED;
    }
}

} // namespace

bool DeserializeGaussianVecFixed(const uint8_t*& ptr,
                                 const uint8_t* end,
                                 size_t count,
                                 SmilePolyVec& z)
{
    return DecodeGaussianVecFixed(ptr, end, count, z, /*reject_rice_codec=*/false) ==
        SmileCTDecodeStatus::OK;
}

void SerializeAdaptiveWitnessPolyVec(const SmilePolyVec& z,
                                     std::vector<uint8_t>& out,
                                     SmileProofCodecPolicy codec_policy)
{
    if (z.empty()) {
        return;
    }

    std::vector<uint8_t> gaussian_buf;
    SerializeGaussianVecFixed(z, gaussian_buf, codec_policy);

    if (codec_policy == SmileProofCodecPolicy::CANONICAL_NO_RICE) {
        out.push_back(kWitnessVecCodecGaussian);
        out.insert(out.end(), gaussian_buf.begin(), gaussian_buf.end());
        return;
    }

    std::vector<uint8_t> polywise_buf;
    polywise_buf.reserve(z.size() * 16);
    for (const auto& poly : z) {
        SerializeExactPolyAdaptive(poly, polywise_buf);
    }

    if (gaussian_buf.size() <= polywise_buf.size()) {
        out.push_back(kWitnessVecCodecGaussian);
        out.insert(out.end(), gaussian_buf.begin(), gaussian_buf.end());
        return;
    }

    out.push_back(kWitnessVecCodecPolywiseExact);
    out.insert(out.end(), polywise_buf.begin(), polywise_buf.end());
}

namespace {

SmileCTDecodeStatus DecodeAdaptiveWitnessPolyVec(const uint8_t*& ptr,
                                                 const uint8_t* end,
                                                 size_t count,
                                                 SmilePolyVec& z,
                                                 bool reject_rice_codec)
{
    if (count == 0) {
        z.clear();
        return SmileCTDecodeStatus::OK;
    }
    if (ptr >= end) return SmileCTDecodeStatus::MALFORMED;

    const uint8_t codec = *ptr++;
    switch (codec) {
    case kWitnessVecCodecGaussian:
        return DecodeGaussianVecFixed(ptr, end, count, z, reject_rice_codec);
    case kWitnessVecCodecPolywiseExact:
        z.resize(count);
        for (size_t poly = 0; poly < count; ++poly) {
            const auto status = DecodeExactPolyAdaptive(ptr, end, z[poly], reject_rice_codec);
            if (status != SmileCTDecodeStatus::OK) {
                return status;
            }
        }
        return SmileCTDecodeStatus::OK;
    default:
        return SmileCTDecodeStatus::MALFORMED;
    }
}

} // namespace

bool DeserializeAdaptiveWitnessPolyVec(const uint8_t*& ptr,
                                       const uint8_t* end,
                                       size_t count,
                                       SmilePolyVec& z)
{
    return DecodeAdaptiveWitnessPolyVec(ptr, end, count, z, /*reject_rice_codec=*/false) ==
        SmileCTDecodeStatus::OK;
}

std::vector<uint8_t> SerializeCTProof(const SmileCTProof& proof, SmileProofCodecPolicy codec_policy) {
    std::vector<uint8_t> out;
    out.reserve(32 * 1024);

    if (proof.wire_version >= SmileCTProof::WIRE_VERSION_M4_HARDENED) {
        WriteWireHeader(out, proof.wire_version);
    }

    // Output coins are NOT serialized — they are separate transaction data.
    // The reset-chain hard-fork proof codec is fixed-layout: counts derive from
    // the statement dimensions instead of being serialized redundantly.

    // Auxiliary commitment t'_0: exact centered bitpacking over the fixed
    // full B0 row surface.
    SerializeCenteredPolyVecFixed(proof.aux_commitment.t0, out);

    // Auxiliary commitment t'_msg prefix. The reset-chain live codec keeps the
    // selector + amount slots exact on-wire and carries the W0/X/G/Psi tail as
    // post-challenge residues instead.
    const size_t retained_aux_msg = ComputeLiveCtRetainedAuxMsgCount(
        proof.z0.size(),
        InferLiveCtOutputCount(proof));
    SmilePolyVec retained_tmsg;
    retained_tmsg.reserve(retained_aux_msg);
    for (size_t slot = 0; slot < retained_aux_msg && slot < proof.aux_commitment.t_msg.size(); ++slot) {
        retained_tmsg.push_back(proof.aux_commitment.t_msg[slot]);
    }
    SerializeCenteredPolyVecFixed(retained_tmsg, out);

    const size_t num_inputs = proof.z0.size();
    const size_t num_outputs = InferLiveCtOutputCount(proof);
    const SmilePolyVec omitted_selector_amount_residues =
        CollectSerializedOmittedAuxSelectorAmountResidues(proof, num_inputs, num_outputs);
    const SmilePolyVec omitted_tail_residues =
        CollectSerializedOmittedAuxTailResidues(proof, num_inputs, num_outputs);
    SerializeAdaptiveWitnessPolyVec(omitted_selector_amount_residues, out, codec_policy);
    SerializeGaussianVecFixed(omitted_tail_residues, out, codec_policy);
    SerializeGaussianVecFixed(proof.w0_residue_accs, out, codec_policy);
    WriteBytes(out,
               proof.round1_aux_binding_digest.data(),
               proof.round1_aux_binding_digest.size());
    WriteBytes(out, proof.pre_h2_binding_digest.data(), proof.pre_h2_binding_digest.size());

    // z vector (Gaussian-coded, adaptive bit width)
    SerializeGaussianVecFixed(proof.z, out, codec_policy);

    // z0 vectors (per-input, Gaussian-coded)
    for (const auto& z0i : proof.z0) {
        SerializeGaussianVecFixed(z0i, out, codec_policy);
    }

    // First-round tuple-opening proofs for selected input public accounts.
    for (const auto& tuple : proof.input_tuples) {
        SerializeGaussianVecFixed(tuple.z_coin, out, codec_policy);
    }
    if (!proof.input_tuples.empty()) {
        SmilePolyVec z_amounts;
        SmilePolyVec z_leafs;
        z_amounts.reserve(proof.input_tuples.size());
        z_leafs.reserve(proof.input_tuples.size());
        for (const auto& tuple : proof.input_tuples) {
            z_amounts.push_back(tuple.z_amount);
            z_leafs.push_back(tuple.z_leaf);
        }
        SerializeAdaptiveWitnessPolyVec(z_amounts, out, codec_policy);
        SerializeAdaptiveWitnessPolyVec(z_leafs, out, codec_policy);
    }
    SerializeExactPolyAdaptive(proof.tuple_opening_acc, out);

    // Combined input/output coin opening proof
    SerializeGaussianVecFixed(proof.coin_opening.z, out, codec_policy);
    WriteBytes(out, proof.coin_opening.binding_digest.data(), proof.coin_opening.binding_digest.size());

    // Serial numbers
    SerializeCenteredPolyVecFixed(proof.serial_numbers, out);

    // weak-opening omega and exact framework omega are reconstructed by the
    // verifier on the reset-chain hard-fork surface. Only the transcript-bound
    // post-h2 digest remains on-wire.
    WriteBytes(out, proof.post_h2_binding_digest.data(), proof.post_h2_binding_digest.size());

    // h2 (skip first 4 zero coefficients)
    for (size_t c = SLOT_DEGREE; c < POLY_DEGREE; ++c) {
        WriteU32(out, static_cast<uint32_t>(mod_q(proof.h2.coeffs[c])));
    }

    // seed_c must stay on-wire on the launch surface because the live verifier
    // still uses it to recover the exact round-1 B0*y rows before seed_c0 is
    // recomputed.
    WriteBytes(out, proof.seed_c.data(), 32);

    // Output coins and prover public keys are NO LONGER serialized inside the
    // proof bytes.  They are transmitted alongside the proof in the
    // V2SendWitness structure, reducing the proof wire size from ~70 KB to ~25 KB.

    return out;
}

SmileCTDecodeStatus DecodeCTProof(const std::vector<uint8_t>& data,
                                  SmileCTProof& proof,
                                  size_t num_inputs,
                                  size_t num_outputs,
                                  bool reject_rice_codec) {
    size_t body_offset{0};
    uint8_t wire_version{SmileCTProof::WIRE_VERSION_LEGACY};
    if (ReadWireHeader(data, body_offset, wire_version)) {
        if (wire_version != SmileCTProof::WIRE_VERSION_M4_HARDENED) {
            return SmileCTDecodeStatus::MALFORMED;
        }
    }

    proof.wire_version = wire_version;

    const uint8_t* ptr = data.data() + body_offset;
    const uint8_t* end = data.data() + data.size();

    if (num_inputs == 0 || num_inputs > MAX_CT_INPUTS) return SmileCTDecodeStatus::MALFORMED;
    if (num_outputs == 0 || num_outputs > MAX_CT_OUTPUTS) return SmileCTDecodeStatus::MALFORMED;

    const size_t n_aux_msg = ComputeLiveCtAuxMsgCount(num_inputs, num_outputs);
    const size_t z_size = BDLOP_RAND_DIM_BASE + n_aux_msg;
    const auto coin_ck = GetCtPublicCoinCommitmentKey();
    const size_t coin_z_count = coin_ck.rand_dim();

    if (z_size > 256) return SmileCTDecodeStatus::MALFORMED;

    // Auxiliary commitment t0
    if (!DeserializeCenteredPolyVecFixed(ptr, end, BDLOP_RAND_DIM_BASE, proof.aux_commitment.t0)) {
        return SmileCTDecodeStatus::MALFORMED;
    }

    const size_t retained_aux_msg = ComputeLiveCtRetainedAuxMsgCount(num_inputs, num_outputs);
    const size_t omitted_w0_msg = num_inputs * kCtPublicRowCount;
    const size_t omitted_aux_msg = n_aux_msg - retained_aux_msg - omitted_w0_msg;

    proof.aux_commitment.t_msg.assign(n_aux_msg, {});
    SmilePolyVec retained_tmsg;
    if (!DeserializeCenteredPolyVecFixed(ptr, end, retained_aux_msg, retained_tmsg)) {
        return SmileCTDecodeStatus::MALFORMED;
    }
    for (size_t slot = 0; slot < retained_tmsg.size(); ++slot) {
        proof.aux_commitment.t_msg[slot] = retained_tmsg[slot];
    }

    proof.aux_residues.assign(n_aux_msg, {});
    const size_t omitted_selector_amount_count =
        ComputeLiveCtW0Offset(num_inputs, num_outputs) - retained_aux_msg;
    const size_t omitted_tail_count = omitted_aux_msg - omitted_selector_amount_count;

    SmilePolyVec omitted_selector_amount_residues;
    if (const auto status = DecodeAdaptiveWitnessPolyVec(ptr,
                                                         end,
                                                         omitted_selector_amount_count,
                                                         omitted_selector_amount_residues,
                                                         reject_rice_codec);
        status != SmileCTDecodeStatus::OK) {
        return status;
    }
    SmilePolyVec omitted_tail_residues;
    if (const auto status = DecodeGaussianVecFixed(ptr,
                                                   end,
                                                   omitted_tail_count,
                                                   omitted_tail_residues,
                                                   reject_rice_codec);
        status != SmileCTDecodeStatus::OK) {
        return status;
    }
    size_t omitted_selector_amount_index = 0;
    size_t omitted_tail_index = 0;
    for (size_t slot = retained_aux_msg; slot < n_aux_msg; ++slot) {
        if (IsLiveCtW0Slot(num_inputs, num_outputs, slot)) {
            proof.aux_residues[slot] = SmilePoly{};
            continue;
        }
        if (slot < ComputeLiveCtW0Offset(num_inputs, num_outputs)) {
            if (omitted_selector_amount_index >= omitted_selector_amount_residues.size()) {
                return SmileCTDecodeStatus::MALFORMED;
            }
            proof.aux_residues[slot] =
                omitted_selector_amount_residues[omitted_selector_amount_index++];
            continue;
        }
        if (omitted_tail_index >= omitted_tail_residues.size()) {
            return SmileCTDecodeStatus::MALFORMED;
        }
        proof.aux_residues[slot] = omitted_tail_residues[omitted_tail_index++];
    }
    proof.w0_commitment_accs.clear();
    proof.w0_residue_accs.clear();
    if (const auto status = DecodeGaussianVecFixed(ptr,
                                                   end,
                                                   num_inputs,
                                                   proof.w0_residue_accs,
                                                   reject_rice_codec);
        status != SmileCTDecodeStatus::OK) {
        return status;
    }
    if (!ReadBytes(ptr,
                   end,
                   proof.round1_aux_binding_digest.data(),
                   proof.round1_aux_binding_digest.size())) return SmileCTDecodeStatus::MALFORMED;
    if (!ReadBytes(ptr, end, proof.pre_h2_binding_digest.data(), proof.pre_h2_binding_digest.size())) {
        return SmileCTDecodeStatus::MALFORMED;
    }

    // z vector (Gaussian-coded)
    if (const auto status = DecodeGaussianVecFixed(ptr, end, z_size, proof.z, reject_rice_codec);
        status != SmileCTDecodeStatus::OK) {
        return status;
    }

    // z0 vectors
    proof.z0.resize(num_inputs);
    for (size_t i = 0; i < num_inputs; ++i) {
        if (const auto status = DecodeGaussianVecFixed(ptr,
                                                       end,
                                                       KEY_COLS,
                                                       proof.z0[i],
                                                       reject_rice_codec);
            status != SmileCTDecodeStatus::OK) {
            return status;
        }
    }

    // First-round tuple-opening proofs for selected input public accounts.
    proof.input_tuples.resize(num_inputs);
    for (size_t i = 0; i < num_inputs; ++i) {
        if (const auto status = DecodeGaussianVecFixed(ptr,
                                                       end,
                                                       coin_z_count,
                                                       proof.input_tuples[i].z_coin,
                                                       reject_rice_codec);
            status != SmileCTDecodeStatus::OK) {
            return status;
        }
    }
    if (num_inputs > 0) {
        SmilePolyVec z_amounts;
        if (const auto status = DecodeAdaptiveWitnessPolyVec(ptr,
                                                             end,
                                                             num_inputs,
                                                             z_amounts,
                                                             reject_rice_codec);
            status != SmileCTDecodeStatus::OK) {
            return status;
        }
        SmilePolyVec z_leafs;
        if (const auto status = DecodeAdaptiveWitnessPolyVec(ptr,
                                                             end,
                                                             num_inputs,
                                                             z_leafs,
                                                             reject_rice_codec);
            status != SmileCTDecodeStatus::OK) {
            return status;
        }
        for (size_t i = 0; i < num_inputs; ++i) {
            proof.input_tuples[i].z_amount = z_amounts[i];
            proof.input_tuples[i].z_leaf = z_leafs[i];
        }
    }
    if (const auto status = DecodeExactPolyAdaptive(ptr,
                                                    end,
                                                    proof.tuple_opening_acc,
                                                    reject_rice_codec);
        status != SmileCTDecodeStatus::OK) {
        return status;
    }

    // Combined input/output coin opening proof
    if (const auto status = DecodeGaussianVecFixed(ptr,
                                                   end,
                                                   coin_z_count,
                                                   proof.coin_opening.z,
                                                   reject_rice_codec);
        status != SmileCTDecodeStatus::OK) {
        return status;
    }
    proof.coin_opening.w0.clear();
    proof.coin_opening.f = SmilePoly{};
    if (!ReadBytes(ptr, end, proof.coin_opening.binding_digest.data(), proof.coin_opening.binding_digest.size())) {
        return SmileCTDecodeStatus::MALFORMED;
    }

    // Serial numbers
    if (!DeserializeCenteredPolyVecFixed(ptr, end, num_inputs, proof.serial_numbers)) {
        return SmileCTDecodeStatus::MALFORMED;
    }

    proof.omega = SmilePoly{};
    proof.framework_omega = SmilePoly{};
    if (!ReadBytes(ptr, end, proof.post_h2_binding_digest.data(), proof.post_h2_binding_digest.size())) {
        return SmileCTDecodeStatus::MALFORMED;
    }

    proof.g0 = SmilePoly{};

    // h2
    // C1 audit fix: validate each coefficient is in [0, Q) to prevent
    // non-canonical encodings that could cause consensus splits.
    proof.h2.coeffs.fill(0);
    for (size_t c = SLOT_DEGREE; c < POLY_DEGREE; ++c) {
        uint32_t val;
        if (!ReadU32(ptr, end, val)) return SmileCTDecodeStatus::MALFORMED;
        if (val >= static_cast<uint32_t>(Q)) return SmileCTDecodeStatus::MALFORMED;
        proof.h2.coeffs[c] = static_cast<int64_t>(val);
    }

    proof.fs_seed.fill(0);
    proof.seed_c0.fill(0);
    proof.seed_z.fill(0);
    if (!ReadBytes(ptr, end, proof.seed_c.data(), 32)) return SmileCTDecodeStatus::MALFORMED;

    // Output coins and prover public keys are NO LONGER deserialized from the
    // proof bytes. They are read from the V2SendWitness structure instead.
    return ptr == end ? SmileCTDecodeStatus::OK : SmileCTDecodeStatus::MALFORMED;
}

bool DeserializeCTProof(const std::vector<uint8_t>& data,
                        SmileCTProof& proof,
                        size_t num_inputs,
                        size_t num_outputs) {
    return DecodeCTProof(data,
                         proof,
                         num_inputs,
                         num_outputs,
                         /*reject_rice_codec=*/false) == SmileCTDecodeStatus::OK;
}

} // namespace smile2
