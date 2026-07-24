// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_packed_bank.h>

#include <matmul/matmul_v4_bmx4.h>

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstring>
#include <limits>
#include <thread>

namespace matmul::v4::rc {
namespace {

[[nodiscard]] bool IsM11(int32_t v)
{
    switch (v) {
    case 0:
    case 1:
    case -1:
    case 2:
    case -2:
    case 3:
    case -3:
    case 4:
    case -4:
    case 6:
    case -6:
        return true;
    default:
        return false;
    }
}

[[nodiscard]] bool FactorBlock(const int8_t* values, uint8_t& exponent, int8_t* mantissas)
{
    // The consensus bank is the expanded int8 view. Its generating MX stream
    // uses one exponent e∈{0,1,2,3} for each 32-value row block and M11
    // mantissas. Recover a deterministic exact representation by choosing the
    // largest admissible exponent. This is unique as a storage encoding even
    // when an all-even/all-zero block could have originated at a lower scale.
    for (int e = 3; e >= 0; --e) {
        const int32_t scale = int32_t{1} << e;
        bool ok = true;
        for (uint32_t i = 0; i < kRCPackedScaleBlock; ++i) {
            const int32_t v = static_cast<int32_t>(values[i]);
            if ((v % scale) != 0 || !IsM11(v / scale)) {
                ok = false;
                break;
            }
            mantissas[i] = static_cast<int8_t>(v / scale);
        }
        if (ok) {
            exponent = static_cast<uint8_t>(e);
            return true;
        }
    }
    return false;
}

[[nodiscard]] bool EncodeE2M1Nibble(int8_t v, uint8_t& out)
{
    // OCP E2M1 bit pattern used by SampleMantissaNibble. Rejected fractional
    // and negative-zero codes are intentionally absent.
    switch (v) {
    case 0: out = 0x0; return true;
    case 1: out = 0x2; return true;
    case 2: out = 0x4; return true;
    case 3: out = 0x5; return true;
    case 4: out = 0x6; return true;
    case 6: out = 0x7; return true;
    case -1: out = 0xa; return true;
    case -2: out = 0xc; return true;
    case -3: out = 0xd; return true;
    case -4: out = 0xe; return true;
    case -6: out = 0xf; return true;
    default: return false;
    }
}

[[nodiscard]] bool DecodeE2M1Nibble(uint8_t n, int8_t& out)
{
    switch (n & 0x0f) {
    case 0x0: out = 0; return true;
    case 0x2: out = 1; return true;
    case 0x4: out = 2; return true;
    case 0x5: out = 3; return true;
    case 0x6: out = 4; return true;
    case 0x7: out = 6; return true;
    case 0xa: out = -1; return true;
    case 0xc: out = -2; return true;
    case 0xd: out = -3; return true;
    case 0xe: out = -4; return true;
    case 0xf: out = -6; return true;
    default: return false;
    }
}

template <typename Fn>
void ParallelRanges(uint64_t jobs, uint32_t threads, const Fn& fn)
{
    if (jobs == 0) return;
    threads = std::max(1u, std::min<uint32_t>(threads, 64u));
    threads = std::min<uint32_t>(threads, static_cast<uint32_t>(jobs));
    if (threads <= 1) {
        fn(0, jobs);
        return;
    }
    std::vector<std::thread> workers;
    workers.reserve(threads);
    for (uint32_t t = 0; t < threads; ++t) {
        const uint64_t begin = (jobs * t) / threads;
        const uint64_t end = (jobs * (t + 1)) / threads;
        workers.emplace_back([&, begin, end] { fn(begin, end); });
    }
    for (auto& worker : workers) worker.join();
}

} // namespace

bool PackExpandedPageToCanonical(const int8_t* expanded, uint32_t width,
                                 std::vector<uint8_t>& out, std::string* error)
{
    out.clear();
    if (expanded == nullptr || width == 0 || (width % kRCPackedScaleBlock) != 0) {
        if (error) *error = "PackExpandedPageToCanonical: bad args";
        return false;
    }
    const uint64_t elems = static_cast<uint64_t>(width) * width;
    const uint64_t need = PackedBytesForElements(elems);
    out.resize(static_cast<size_t>(need));
    size_t o = 0;
    for (uint64_t base = 0; base < elems; base += kRCPackedScaleBlock) {
        int8_t mantissas[kRCPackedScaleBlock];
        uint8_t exponent = 0;
        if (!FactorBlock(expanded + base, exponent, mantissas)) {
            out.clear();
            if (error) {
                *error = "PackExpandedPageToCanonical: block is not exact MX E2M1/E8M0";
            }
            return false;
        }
        // VEC32 UE8M0 biased exponent code, matching the native CUDA packer.
        out[o++] = static_cast<uint8_t>(127u + exponent);
        for (uint32_t i = 0; i < kRCPackedScaleBlock; i += 2) {
            uint8_t lo = 0;
            uint8_t hi = 0;
            if (!EncodeE2M1Nibble(mantissas[i], lo) ||
                !EncodeE2M1Nibble(mantissas[i + 1], hi)) {
                out.clear();
                if (error) *error = "PackExpandedPageToCanonical: invalid M11 mantissa";
                return false;
            }
            out[o++] = static_cast<uint8_t>(lo | (hi << 4));
        }
    }
    if (o != out.size()) {
        if (error) *error = "PackExpandedPageToCanonical: size mismatch";
        return false;
    }
    if (error) error->clear();
    return true;
}

bool UnpackCanonicalPageToExpanded(const uint8_t* packed, size_t packed_len, uint32_t width,
                                   std::vector<int8_t>& out, std::string* error)
{
    out.clear();
    if (packed == nullptr || width == 0 || (width % kRCPackedScaleBlock) != 0) {
        if (error) *error = "UnpackCanonicalPageToExpanded: bad args";
        return false;
    }
    const uint64_t elems = static_cast<uint64_t>(width) * width;
    if (packed_len != PackedBytesForElements(elems)) {
        if (error) *error = "UnpackCanonicalPageToExpanded: packed length mismatch";
        return false;
    }
    out.resize(static_cast<size_t>(elems));
    size_t o = 0;
    for (uint64_t base = 0; base < elems; base += kRCPackedScaleBlock) {
        const uint8_t scale_code = packed[o++];
        if (scale_code < 127u || scale_code > 130u) {
            out.clear();
            if (error) *error = "UnpackCanonicalPageToExpanded: invalid UE8M0 scale";
            return false;
        }
        const uint8_t exponent = static_cast<uint8_t>(scale_code - 127u);
        const int32_t scale = int32_t{1} << exponent;
        for (uint32_t i = 0; i < kRCPackedScaleBlock; i += 2) {
            const uint8_t b = packed[o++];
            int8_t lo = 0;
            int8_t hi = 0;
            if (!DecodeE2M1Nibble(b & 0x0f, lo) || !DecodeE2M1Nibble(b >> 4, hi)) {
                out.clear();
                if (error) *error = "UnpackCanonicalPageToExpanded: rejected E2M1 code";
                return false;
            }
            out[base + i] =
                static_cast<int8_t>(static_cast<int32_t>(lo) * scale);
            out[base + i + 1] =
                static_cast<int8_t>(static_cast<int32_t>(hi) * scale);
        }
    }
    if (error) error->clear();
    return true;
}

bool ExpandMxPageToPackedStream(const uint256& seed, uint32_t width, uint32_t threads,
                                std::vector<uint8_t>& packed, std::vector<int8_t>* expanded,
                                std::string* error)
{
    packed.clear();
    if (expanded != nullptr) expanded->clear();
    if (width == 0 || (width % kRCPackedScaleBlock) != 0 || threads == 0) {
        if (error) *error = "ExpandMxPageToPackedStream: bad args";
        return false;
    }
    const uint64_t elems = static_cast<uint64_t>(width) * width;
    if (elems > std::numeric_limits<size_t>::max()) {
        if (error) *error = "ExpandMxPageToPackedStream: page too large";
        return false;
    }
    const uint64_t blocks = elems / kRCPackedScaleBlock;
    const uint64_t packed_bytes = PackedBytesForElements(elems);
    if (packed_bytes > std::numeric_limits<size_t>::max()) {
        if (error) *error = "ExpandMxPageToPackedStream: packed page too large";
        return false;
    }

    std::vector<int8_t> mantissas(static_cast<size_t>(elems));
    std::vector<uint8_t> scales(static_cast<size_t>(blocks));
    matmul::v4::bmx4::ExpandMantissaStreamParallel(
        seed, mantissas.size(), mantissas.data(), threads);
    matmul::v4::bmx4::ExpandScaleStreamParallel(seed, scales.size(), scales.data(), threads);

    packed.resize(static_cast<size_t>(packed_bytes));
    if (expanded != nullptr) expanded->resize(static_cast<size_t>(elems));
    std::atomic_bool valid{true};
    ParallelRanges(blocks, threads, [&](uint64_t begin, uint64_t end) {
        for (uint64_t block = begin; block < end; ++block) {
            const uint8_t exponent = scales[static_cast<size_t>(block)];
            if (exponent > 3u) {
                valid.store(false, std::memory_order_relaxed);
                continue;
            }
            const size_t packed_base = static_cast<size_t>(block * 17u);
            const size_t elem_base = static_cast<size_t>(block * kRCPackedScaleBlock);
            packed[packed_base] = static_cast<uint8_t>(127u + exponent);
            const int32_t scale = int32_t{1} << exponent;
            for (uint32_t i = 0; i < kRCPackedScaleBlock; i += 2) {
                uint8_t lo = 0;
                uint8_t hi = 0;
                if (!EncodeE2M1Nibble(mantissas[elem_base + i], lo) ||
                    !EncodeE2M1Nibble(mantissas[elem_base + i + 1], hi)) {
                    valid.store(false, std::memory_order_relaxed);
                    break;
                }
                packed[packed_base + 1 + i / 2] = static_cast<uint8_t>(lo | (hi << 4));
                if (expanded != nullptr) {
                    (*expanded)[elem_base + i] = static_cast<int8_t>(
                        static_cast<int32_t>(mantissas[elem_base + i]) * scale);
                    (*expanded)[elem_base + i + 1] = static_cast<int8_t>(
                        static_cast<int32_t>(mantissas[elem_base + i + 1]) * scale);
                }
            }
        }
    });
    if (!valid.load(std::memory_order_relaxed)) {
        packed.clear();
        if (expanded != nullptr) expanded->clear();
        if (error) *error = "ExpandMxPageToPackedStream: invalid generated MX stream";
        return false;
    }
    if (error) error->clear();
    return true;
}

bool UnpackPackedPageToExpandedParallel(const uint8_t* packed, size_t packed_len,
                                        uint32_t width, uint32_t threads,
                                        std::vector<int8_t>& out, std::string* error)
{
    out.clear();
    if (packed == nullptr || width == 0 || (width % kRCPackedScaleBlock) != 0 ||
        threads == 0) {
        if (error) *error = "UnpackPackedPageToExpandedParallel: bad args";
        return false;
    }
    const uint64_t elems = static_cast<uint64_t>(width) * width;
    if (elems > std::numeric_limits<size_t>::max() ||
        packed_len != PackedBytesForElements(elems)) {
        if (error) *error = "UnpackPackedPageToExpandedParallel: packed length mismatch";
        return false;
    }
    const uint64_t blocks = elems / kRCPackedScaleBlock;
    out.resize(static_cast<size_t>(elems));
    std::atomic_bool valid{true};
    ParallelRanges(blocks, threads, [&](uint64_t begin, uint64_t end) {
        for (uint64_t block = begin; block < end; ++block) {
            const size_t packed_base = static_cast<size_t>(block * 17u);
            const size_t elem_base = static_cast<size_t>(block * kRCPackedScaleBlock);
            const uint8_t scale_code = packed[packed_base];
            if (scale_code < 127u || scale_code > 130u) {
                valid.store(false, std::memory_order_relaxed);
                continue;
            }
            const int32_t scale = int32_t{1} << (scale_code - 127u);
            for (uint32_t i = 0; i < kRCPackedScaleBlock; i += 2) {
                const uint8_t byte = packed[packed_base + 1 + i / 2];
                int8_t lo = 0;
                int8_t hi = 0;
                if (!DecodeE2M1Nibble(byte & 0x0f, lo) ||
                    !DecodeE2M1Nibble(byte >> 4, hi)) {
                    valid.store(false, std::memory_order_relaxed);
                    break;
                }
                out[elem_base + i] =
                    static_cast<int8_t>(static_cast<int32_t>(lo) * scale);
                out[elem_base + i + 1] =
                    static_cast<int8_t>(static_cast<int32_t>(hi) * scale);
            }
        }
    });
    if (!valid.load(std::memory_order_relaxed)) {
        out.clear();
        if (error) *error = "UnpackPackedPageToExpandedParallel: invalid packed MX page";
        return false;
    }
    if (error) error->clear();
    return true;
}

} // namespace matmul::v4::rc
