// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cuda/oracle_accel.h>

#include <crypto/sha256.h>
#include <cuda/cuda_context.h>
#include <cuda_runtime.h>
#include <matmul/noise.h>
#include <matmul/transcript.h>
#include <span.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <limits>
#include <new>
#include <mutex>
#include <string>
#include <vector>

namespace btx::cuda {
namespace {

using Element = matmul::field::Element;
constexpr uint32_t MODULUS = matmul::field::MODULUS;
constexpr uint32_t ORACLE_THREADS = 256;

struct OracleSeedBytes {
    uint8_t data[32];
};

struct OracleProfileState {
    std::atomic<bool> pool_initialized{false};
    std::atomic<uint64_t> samples{0};
    std::atomic<uint64_t> allocation_events{0};
    std::atomic<uint64_t> reuse_events{0};
    std::mutex mutex;
    double last_encode_noise_us{0.0};
    double last_encode_compress_us{0.0};
    double last_submit_wait_us{0.0};
    double last_gpu_generation_ms{0.0};
    std::string reason{"cuda_oracle_ready"};
};

struct OracleWorkspace {
    struct HostStageBuffer {
        Element* pinned{nullptr};
        size_t capacity{0};
        bool pinned_disabled{false};
        std::vector<Element> fallback;

        ~HostStageBuffer() { cudaFreeHost(pinned); }

        bool Ensure(size_t required, std::string& error)
        {
            if (required == 0) {
                fallback.clear();
                return true;
            }

            if (!pinned_disabled && pinned != nullptr && capacity >= required) {
                return true;
            }

            if (!pinned_disabled) {
                cudaFreeHost(pinned);
                pinned = nullptr;
                capacity = 0;

                Element* candidate{nullptr};
                const cudaError_t alloc_error = cudaMallocHost(&candidate, required * sizeof(Element));
                if (alloc_error == cudaSuccess) {
                    pinned = candidate;
                    capacity = required;
                    fallback.clear();
                    return true;
                }

                pinned_disabled = true;
                error = "cudaMallocHost failed:" + std::string(cudaGetErrorString(alloc_error)) +
                    "; falling back to pageable host memory";
            }

            try {
                fallback.resize(required);
            } catch (const std::bad_alloc&) {
                error = "host staging allocation failed";
                return false;
            }
            return true;
        }

        Element* data()
        {
            return pinned != nullptr ? pinned : fallback.data();
        }
    };

    int device_index{-1};
    cudaStream_t stream{nullptr};
    Element* out_e_l{nullptr};
    Element* out_e_r{nullptr};
    Element* out_f_l{nullptr};
    Element* out_f_r{nullptr};
    Element* out_cv{nullptr};
    size_t noise_capacity{0};
    size_t compress_capacity{0};
    HostStageBuffer host_e_l;
    HostStageBuffer host_e_r;
    HostStageBuffer host_f_l;
    HostStageBuffer host_f_r;
    HostStageBuffer host_cv;

    ~OracleWorkspace()
    {
        if (device_index >= 0) {
            cudaSetDevice(device_index);
        }
        if (stream != nullptr) {
            cudaStreamDestroy(stream);
        }
        cudaFree(out_cv);
        cudaFree(out_f_r);
        cudaFree(out_f_l);
        cudaFree(out_e_r);
        cudaFree(out_e_l);
    }
};

thread_local OracleWorkspace g_workspace;
OracleProfileState g_profile;

struct DeviceInputPoolSlot {
    MatMulGeneratedInputsDevice inputs;
    size_t storage_capacity_words{0};
    bool in_use{false};
};

struct DeviceInputPoolContext {
    std::mutex mutex;
    std::vector<std::unique_ptr<DeviceInputPoolSlot>> slots;
    uint32_t next_slot{0};
};

DeviceInputPoolContext& GetDeviceInputPoolContext()
{
    static DeviceInputPoolContext context;
    return context;
}

std::array<uint8_t, 32> ToCanonicalBytes(const uint256& value)
{
    std::array<uint8_t, 32> out;
    for (size_t i = 0; i < out.size(); ++i) {
        out[i] = value.data()[out.size() - 1 - i];
    }
    return out;
}

uint256 CanonicalBytesToUint256(const uint8_t* bytes)
{
    std::array<unsigned char, 32> internal;
    for (size_t i = 0; i < internal.size(); ++i) {
        internal[i] = bytes[internal.size() - 1 - i];
    }
    return uint256{Span<const unsigned char>{internal.data(), internal.size()}};
}

uint256 DeriveCompressionSeed(const uint256& sigma)
{
    const auto sigma_bytes = ToCanonicalBytes(sigma);
    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const uint8_t*>(matmul::transcript::COMPRESS_TAG.data()),
                 matmul::transcript::COMPRESS_TAG.size());
    hasher.Write(sigma_bytes.data(), sigma_bytes.size());

    uint8_t digest[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(digest);
    return CanonicalBytesToUint256(digest);
}

OracleSeedBytes ToInternalSeedBytes(const uint256& seed)
{
    OracleSeedBytes out{};
    std::memcpy(out.data, seed.data(), sizeof(out.data));
    return out;
}

void ResetWorkspaceForDevice(OracleWorkspace& workspace, int device_index)
{
    if (workspace.device_index == device_index) {
        return;
    }

    if (workspace.device_index >= 0) {
        cudaSetDevice(workspace.device_index);
    }
    cudaFree(workspace.out_cv);
    cudaFree(workspace.out_f_r);
    cudaFree(workspace.out_f_l);
    cudaFree(workspace.out_e_r);
    cudaFree(workspace.out_e_l);
    workspace.out_e_l = nullptr;
    workspace.out_e_r = nullptr;
    workspace.out_f_l = nullptr;
    workspace.out_f_r = nullptr;
    workspace.out_cv = nullptr;
    workspace.noise_capacity = 0;
    workspace.compress_capacity = 0;
    if (workspace.stream != nullptr) {
        cudaStreamDestroy(workspace.stream);
        workspace.stream = nullptr;
    }
    workspace.device_index = device_index;
}

bool EnsureWorkspaceStream(OracleWorkspace& workspace, std::string& error)
{
    if (workspace.stream != nullptr) {
        return true;
    }

    const cudaError_t stream_error = cudaStreamCreateWithFlags(&workspace.stream, cudaStreamNonBlocking);
    if (stream_error != cudaSuccess) {
        error = "cudaStreamCreateWithFlags failed:" + std::string(cudaGetErrorString(stream_error));
        workspace.stream = nullptr;
        return false;
    }
    return true;
}

bool EnsureDeviceBuffer(Element*& buffer, size_t& capacity, size_t required, std::string& error)
{
    if (capacity >= required && buffer != nullptr) {
        return true;
    }

    cudaFree(buffer);
    buffer = nullptr;
    capacity = 0;

    if (required == 0) {
        return true;
    }

    const cudaError_t alloc_error = cudaMalloc(&buffer, required * sizeof(Element));
    if (alloc_error != cudaSuccess) {
        error = "cudaMalloc failed:" + std::string(cudaGetErrorString(alloc_error));
        return false;
    }

    capacity = required;
    return true;
}

bool EnsureOutputBuffers(OracleWorkspace& workspace,
                         size_t noise_words,
                         size_t compress_words,
                         std::string& error)
{
    const bool reused = workspace.out_e_l != nullptr &&
        workspace.out_e_r != nullptr &&
        workspace.out_f_l != nullptr &&
        workspace.out_f_r != nullptr &&
        workspace.out_cv != nullptr &&
        workspace.noise_capacity >= noise_words &&
        workspace.compress_capacity >= compress_words;

    if (reused) {
        g_profile.pool_initialized.store(true, std::memory_order_relaxed);
        g_profile.reuse_events.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    cudaFree(workspace.out_e_l);
    cudaFree(workspace.out_e_r);
    cudaFree(workspace.out_f_l);
    cudaFree(workspace.out_f_r);
    workspace.out_e_l = nullptr;
    workspace.out_e_r = nullptr;
    workspace.out_f_l = nullptr;
    workspace.out_f_r = nullptr;
    workspace.noise_capacity = 0;

    if (noise_words != 0) {
        cudaError_t alloc_error = cudaMalloc(&workspace.out_e_l, noise_words * sizeof(Element));
        if (alloc_error == cudaSuccess) {
            alloc_error = cudaMalloc(&workspace.out_e_r, noise_words * sizeof(Element));
        }
        if (alloc_error == cudaSuccess) {
            alloc_error = cudaMalloc(&workspace.out_f_l, noise_words * sizeof(Element));
        }
        if (alloc_error == cudaSuccess) {
            alloc_error = cudaMalloc(&workspace.out_f_r, noise_words * sizeof(Element));
        }
        if (alloc_error != cudaSuccess) {
            cudaFree(workspace.out_e_l);
            cudaFree(workspace.out_e_r);
            cudaFree(workspace.out_f_l);
            cudaFree(workspace.out_f_r);
            workspace.out_e_l = nullptr;
            workspace.out_e_r = nullptr;
            workspace.out_f_l = nullptr;
            workspace.out_f_r = nullptr;
            error = "cudaMalloc failed:" + std::string(cudaGetErrorString(alloc_error));
            return false;
        }
        workspace.noise_capacity = noise_words;
    }

    if (!EnsureDeviceBuffer(workspace.out_cv, workspace.compress_capacity, compress_words, error)) {
        cudaFree(workspace.out_e_l);
        cudaFree(workspace.out_e_r);
        cudaFree(workspace.out_f_l);
        cudaFree(workspace.out_f_r);
        workspace.out_e_l = nullptr;
        workspace.out_e_r = nullptr;
        workspace.out_f_l = nullptr;
        workspace.out_f_r = nullptr;
        workspace.noise_capacity = 0;
        return false;
    }

    g_profile.pool_initialized.store(true, std::memory_order_relaxed);
    g_profile.allocation_events.fetch_add(1, std::memory_order_relaxed);
    return true;
}

bool ValidateInputGenerationRequest(const MatMulInputGenerationRequest& request,
                                    std::string& error,
                                    uint32_t& noise_words,
                                    uint32_t& compress_words)
{
    if (request.n == 0 || request.b == 0 || request.r == 0) {
        error = "invalid dimensions for GPU input generation";
        return false;
    }
    if (request.r > request.n) {
        error = "noise rank exceeds matrix dimension";
        return false;
    }
    if ((request.n % request.b) != 0) {
        error = "matrix dimension must be divisible by transcript block size";
        return false;
    }

    const uint64_t noise_words64 = static_cast<uint64_t>(request.n) * request.r;
    const uint64_t compress_words64 = static_cast<uint64_t>(request.b) * request.b;
    if (noise_words64 > std::numeric_limits<uint32_t>::max() ||
        compress_words64 > std::numeric_limits<uint32_t>::max()) {
        error = "input generation dimensions exceed supported bounds";
        return false;
    }

    noise_words = static_cast<uint32_t>(noise_words64);
    compress_words = static_cast<uint32_t>(compress_words64);
    return true;
}

void UpdateProfile(double encode_noise_us,
                   double encode_compress_us,
                   double submit_wait_us,
                   const char* reason)
{
    {
        std::lock_guard<std::mutex> lock(g_profile.mutex);
        g_profile.last_encode_noise_us = encode_noise_us;
        g_profile.last_encode_compress_us = encode_compress_us;
        g_profile.last_submit_wait_us = submit_wait_us;
        g_profile.last_gpu_generation_ms = submit_wait_us / 1000.0;
        g_profile.reason = reason;
    }
    g_profile.samples.fetch_add(1, std::memory_order_relaxed);
}

bool EnsureGeneratedInputsDeviceBuffers(DeviceInputPoolSlot& slot,
                                        int device_index,
                                        uint32_t n,
                                        uint32_t b,
                                        uint32_t r,
                                        uint32_t noise_words,
                                        uint32_t compress_words,
                                        std::string& error,
                                        bool& allocated)
{
    auto& inputs = slot.inputs;
    if (inputs.device_index != device_index && inputs.device_index >= 0) {
        cudaSetDevice(inputs.device_index);
        if (inputs.ready_event != nullptr) {
            cudaEventDestroy(reinterpret_cast<cudaEvent_t>(inputs.ready_event));
            inputs.ready_event = nullptr;
        }
        cudaFree(inputs.storage);
        inputs.storage = nullptr;
        inputs.noise_e_l = nullptr;
        inputs.noise_e_r = nullptr;
        inputs.noise_f_l = nullptr;
        inputs.noise_f_r = nullptr;
        inputs.compress_vec = nullptr;
        slot.storage_capacity_words = 0;
    }

    if (inputs.device_index != device_index) {
        cudaSetDevice(device_index);
    }

    inputs.device_index = device_index;
    inputs.n = n;
    inputs.b = b;
    inputs.r = r;
    inputs.noise_words = noise_words;
    inputs.compress_words = compress_words;

    const size_t total_words =
        static_cast<size_t>(noise_words) * 4U + compress_words;
    if (total_words == 0) {
        return true;
    }

    if (inputs.storage == nullptr || slot.storage_capacity_words < total_words) {
        cudaFree(inputs.storage);
        inputs.storage = nullptr;
        inputs.noise_e_l = nullptr;
        inputs.noise_e_r = nullptr;
        inputs.noise_f_l = nullptr;
        inputs.noise_f_r = nullptr;
        inputs.compress_vec = nullptr;

        const cudaError_t alloc_error = cudaMalloc(&inputs.storage, total_words * sizeof(Element));
        if (alloc_error != cudaSuccess) {
            error = "cudaMalloc failed:" + std::string(cudaGetErrorString(alloc_error));
            return false;
        }
        allocated = true;
        slot.storage_capacity_words = total_words;
    }

    inputs.noise_e_l = inputs.storage;
    inputs.noise_e_r = inputs.noise_e_l + noise_words;
    inputs.noise_f_l = inputs.noise_e_r + noise_words;
    inputs.noise_f_r = inputs.noise_f_l + noise_words;
    inputs.compress_vec = inputs.noise_f_r + noise_words;
    return true;
}

bool EnsureGeneratedInputsReadyEvent(MatMulGeneratedInputsDevice& inputs, std::string& error)
{
    if (inputs.ready_event != nullptr) {
        return true;
    }

    cudaEvent_t event_handle{nullptr};
    const cudaError_t event_error = cudaEventCreateWithFlags(&event_handle, cudaEventDisableTiming);
    if (event_error != cudaSuccess) {
        error = "cudaEventCreateWithFlags failed:" + std::string(cudaGetErrorString(event_error));
        return false;
    }

    inputs.ready_event = reinterpret_cast<void*>(event_handle);
    return true;
}

std::shared_ptr<const MatMulGeneratedInputsDevice> AcquireGeneratedInputsDevice(int device_index,
                                                                                uint32_t n,
                                                                                uint32_t b,
                                                                                uint32_t r,
                                                                                uint32_t noise_words,
                                                                                uint32_t compress_words,
                                                                                std::string& error)
{
    auto& context = GetDeviceInputPoolContext();
    std::unique_lock<std::mutex> lock(context.mutex);

    DeviceInputPoolSlot* slot_ptr{nullptr};
    bool reused_existing_slot{false};
    for (size_t offset = 0; offset < context.slots.size(); ++offset) {
        const size_t slot_index = (context.next_slot + offset) % context.slots.size();
        auto& slot = context.slots[slot_index];
        if (slot->in_use) {
            continue;
        }
        slot->in_use = true;
        context.next_slot = static_cast<uint32_t>((slot_index + 1) % std::max<size_t>(context.slots.size(), 1));
        slot_ptr = slot.get();
        reused_existing_slot = true;
        break;
    }

    if (slot_ptr == nullptr) {
        auto slot = std::make_unique<DeviceInputPoolSlot>();
        slot->in_use = true;
        slot_ptr = slot.get();
        context.slots.push_back(std::move(slot));
        context.next_slot = static_cast<uint32_t>(context.slots.size() % std::max<size_t>(context.slots.size(), 1));
    }

    lock.unlock();

    bool allocated_buffers{false};
    if (!EnsureGeneratedInputsDeviceBuffers(
            *slot_ptr,
            device_index,
            n,
            b,
            r,
            noise_words,
            compress_words,
            error,
            allocated_buffers)) {
        std::lock_guard<std::mutex> relock(context.mutex);
        slot_ptr->in_use = false;
        return {};
    }

    g_profile.pool_initialized.store(true, std::memory_order_relaxed);
    if (allocated_buffers || !reused_existing_slot) {
        g_profile.allocation_events.fetch_add(1, std::memory_order_relaxed);
    } else {
        g_profile.reuse_events.fetch_add(1, std::memory_order_relaxed);
    }

    auto holder = std::shared_ptr<DeviceInputPoolSlot>(
        slot_ptr,
        [&context](DeviceInputPoolSlot* slot) {
            std::lock_guard<std::mutex> lock(context.mutex);
            slot->in_use = false;
        });
    return std::shared_ptr<const MatMulGeneratedInputsDevice>(holder, &slot_ptr->inputs);
}

__device__ inline uint32_t RotR(uint32_t x, uint32_t n)
{
    return (x >> n) | (x << (32U - n));
}

__device__ inline uint32_t ShaCh(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ ((~x) & z);
}

__device__ inline uint32_t ShaMaj(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

__device__ inline uint32_t ShaBSig0(uint32_t x)
{
    return RotR(x, 2U) ^ RotR(x, 13U) ^ RotR(x, 22U);
}

__device__ inline uint32_t ShaBSig1(uint32_t x)
{
    return RotR(x, 6U) ^ RotR(x, 11U) ^ RotR(x, 25U);
}

__device__ inline uint32_t ShaSSig0(uint32_t x)
{
    return RotR(x, 7U) ^ RotR(x, 18U) ^ (x >> 3U);
}

__device__ inline uint32_t ShaSSig1(uint32_t x)
{
    return RotR(x, 17U) ^ RotR(x, 19U) ^ (x >> 10U);
}

__device__ __constant__ uint32_t SHA256_K[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

__device__ inline void Sha256Init(uint32_t state[8])
{
    state[0] = 0x6a09e667U;
    state[1] = 0xbb67ae85U;
    state[2] = 0x3c6ef372U;
    state[3] = 0xa54ff53aU;
    state[4] = 0x510e527fU;
    state[5] = 0x9b05688cU;
    state[6] = 0x1f83d9abU;
    state[7] = 0x5be0cd19U;
}

__device__ inline void SetByte(uint32_t w[64], uint32_t offset, uint32_t byte)
{
    const uint32_t word_index = offset >> 2U;
    const uint32_t shift = (3U - (offset & 3U)) * 8U;
    w[word_index] |= (byte & 0xffU) << shift;
}

__device__ inline uint32_t Bswap32(uint32_t x)
{
    return ((x & 0x000000ffU) << 24U) |
        ((x & 0x0000ff00U) << 8U) |
        ((x & 0x00ff0000U) >> 8U) |
        ((x & 0xff000000U) >> 24U);
}

__device__ inline void Sha256Compress(uint32_t state[8], uint32_t w[64])
{
    for (uint32_t t = 16; t < 64; ++t) {
        w[t] = ShaSSig1(w[t - 2]) + w[t - 7] + ShaSSig0(w[t - 15]) + w[t - 16];
    }

    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

    for (uint32_t t = 0; t < 64; ++t) {
        const uint32_t t1 = h + ShaBSig1(e) + ShaCh(e, f, g) + SHA256_K[t] + w[t];
        const uint32_t t2 = ShaBSig0(a) + ShaMaj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

__device__ inline uint32_t CandidateFromSeedAndIndex(const OracleSeedBytes& seed,
                                                     uint32_t index,
                                                     bool with_retry,
                                                     uint32_t retry)
{
    uint32_t w[64] = {};
    for (uint32_t i = 0; i < 32; ++i) {
        SetByte(w, i, seed.data[31U - i]);
    }

    SetByte(w, 32U, index & 0xffU);
    SetByte(w, 33U, (index >> 8U) & 0xffU);
    SetByte(w, 34U, (index >> 16U) & 0xffU);
    SetByte(w, 35U, (index >> 24U) & 0xffU);

    uint32_t message_len = 36U;
    if (with_retry) {
        SetByte(w, 36U, retry & 0xffU);
        SetByte(w, 37U, (retry >> 8U) & 0xffU);
        SetByte(w, 38U, (retry >> 16U) & 0xffU);
        SetByte(w, 39U, (retry >> 24U) & 0xffU);
        message_len = 40U;
    }

    SetByte(w, message_len, 0x80U);
    w[15] = message_len * 8U;

    uint32_t state[8];
    Sha256Init(state);
    Sha256Compress(state, w);
    return Bswap32(state[0]) & MODULUS;
}

__device__ inline uint32_t FallbackCandidate(const OracleSeedBytes& seed, uint32_t index)
{
    uint32_t w[64] = {};
    for (uint32_t i = 0; i < 32; ++i) {
        SetByte(w, i, seed.data[31U - i]);
    }

    SetByte(w, 32U, index & 0xffU);
    SetByte(w, 33U, (index >> 8U) & 0xffU);
    SetByte(w, 34U, (index >> 16U) & 0xffU);
    SetByte(w, 35U, (index >> 24U) & 0xffU);

    constexpr uint8_t fallback_tag[15] = {
        'o', 'r', 'a', 'c', 'l', 'e', '-', 'f', 'a', 'l', 'l', 'b', 'a', 'c', 'k'
    };
    for (uint32_t i = 0; i < 15; ++i) {
        SetByte(w, 36U + i, fallback_tag[i]);
    }

    SetByte(w, 51U, 0x80U);
    w[15] = 51U * 8U;

    uint32_t state[8];
    Sha256Init(state);
    Sha256Compress(state, w);
    return Bswap32(state[0]) % MODULUS;
}

__device__ inline uint32_t FromOracle(const OracleSeedBytes& seed, uint32_t index)
{
    for (uint32_t retry = 0; retry < 256; ++retry) {
        const uint32_t candidate = retry == 0
            ? CandidateFromSeedAndIndex(seed, index, false, 0U)
            : CandidateFromSeedAndIndex(seed, index, true, retry);
        if (candidate < MODULUS) {
            return candidate;
        }
    }
    return FallbackCandidate(seed, index);
}

__global__ void GenerateOracleNoiseKernel(OracleSeedBytes seed_el,
                                          OracleSeedBytes seed_er,
                                          OracleSeedBytes seed_fl,
                                          OracleSeedBytes seed_fr,
                                          Element* out_e_l,
                                          Element* out_e_r,
                                          Element* out_f_l,
                                          Element* out_f_r,
                                          uint32_t count)
{
    const uint32_t gid = blockIdx.x * blockDim.x + threadIdx.x;
    if (gid >= count) {
        return;
    }

    out_e_l[gid] = FromOracle(seed_el, gid);
    out_e_r[gid] = FromOracle(seed_er, gid);
    out_f_l[gid] = FromOracle(seed_fl, gid);
    out_f_r[gid] = FromOracle(seed_fr, gid);
}

__global__ void GenerateOracleVectorKernel(OracleSeedBytes seed_cv,
                                           Element* out,
                                           uint32_t count)
{
    const uint32_t gid = blockIdx.x * blockDim.x + threadIdx.x;
    if (gid >= count) {
        return;
    }

    out[gid] = FromOracle(seed_cv, gid);
}

} // namespace

MatMulGeneratedInputsDevice::~MatMulGeneratedInputsDevice()
{
    if (device_index >= 0) {
        cudaSetDevice(device_index);
    }
    if (ready_event != nullptr) {
        cudaEventDestroy(reinterpret_cast<cudaEvent_t>(ready_event));
    }
    cudaFree(storage);
}

MatMulInputGenerationProfile ProbeMatMulInputGenerationProfile()
{
    MatMulInputGenerationProfile profile;

    const auto runtime = ProbeCudaRuntime();
    if (!runtime.available) {
        profile.available = false;
        profile.pool_initialized = false;
        profile.library_source = "unavailable";
        profile.reason = runtime.reason;
        return profile;
    }

    profile.available = true;
    profile.pool_initialized = g_profile.pool_initialized.load(std::memory_order_relaxed);
    profile.samples = g_profile.samples.load(std::memory_order_relaxed);
    profile.allocation_events = g_profile.allocation_events.load(std::memory_order_relaxed);
    profile.reuse_events = g_profile.reuse_events.load(std::memory_order_relaxed);
    profile.library_source = "cuda_compiled";
    {
        std::lock_guard<std::mutex> lock(g_profile.mutex);
        profile.last_encode_noise_us = g_profile.last_encode_noise_us;
        profile.last_encode_compress_us = g_profile.last_encode_compress_us;
        profile.last_submit_wait_us = g_profile.last_submit_wait_us;
        profile.last_gpu_generation_ms = g_profile.last_gpu_generation_ms;
        profile.reason = g_profile.reason;
    }
    if (profile.reason.empty()) {
        profile.reason = profile.pool_initialized ? "cuda_oracle_ready" : "cuda_oracle_pool_uninitialized";
    }
    return profile;
}

MatMulInputGenerationResult GenerateMatMulInputsGPU(const MatMulInputGenerationRequest& request)
{
    MatMulInputGenerationResult result;
    const auto runtime = ProbeCudaRuntime();
    result.available = runtime.available;
    if (!runtime.available) {
        result.error = runtime.reason;
        return result;
    }

    uint32_t noise_words{0};
    uint32_t compress_words{0};
    if (!ValidateInputGenerationRequest(request, result.error, noise_words, compress_words)) {
        return result;
    }
    const auto seed_el = ToInternalSeedBytes(matmul::noise::DeriveNoiseSeed(matmul::noise::TAG_EL, request.sigma));
    const auto seed_er = ToInternalSeedBytes(matmul::noise::DeriveNoiseSeed(matmul::noise::TAG_ER, request.sigma));
    const auto seed_fl = ToInternalSeedBytes(matmul::noise::DeriveNoiseSeed(matmul::noise::TAG_FL, request.sigma));
    const auto seed_fr = ToInternalSeedBytes(matmul::noise::DeriveNoiseSeed(matmul::noise::TAG_FR, request.sigma));
    const auto seed_cv = ToInternalSeedBytes(DeriveCompressionSeed(request.sigma));

    auto& workspace = g_workspace;
    ResetWorkspaceForDevice(workspace, runtime.device_index);

    cudaError_t error = cudaSetDevice(runtime.device_index);
    if (error != cudaSuccess) {
        result.error = "cudaSetDevice failed:" + std::string(cudaGetErrorString(error));
        return result;
    }
    if (!EnsureWorkspaceStream(workspace, result.error)) {
        return result;
    }

    if (!EnsureOutputBuffers(workspace, noise_words, compress_words, result.error)) {
        return result;
    }

    const uint32_t noise_blocks = (noise_words + ORACLE_THREADS - 1) / ORACLE_THREADS;
    const uint32_t compress_blocks = (compress_words + ORACLE_THREADS - 1) / ORACLE_THREADS;
    const auto encode_noise_start = std::chrono::steady_clock::now();
    GenerateOracleNoiseKernel<<<noise_blocks, ORACLE_THREADS, 0, workspace.stream>>>(
        seed_el,
        seed_er,
        seed_fl,
        seed_fr,
        workspace.out_e_l,
        workspace.out_e_r,
        workspace.out_f_l,
        workspace.out_f_r,
        noise_words);
    double encode_noise_us = std::chrono::duration<double, std::micro>(
                                 std::chrono::steady_clock::now() - encode_noise_start)
                                 .count();

    error = cudaGetLastError();
    if (error != cudaSuccess) {
        result.error = "CUDA oracle noise kernel failed:" + std::string(cudaGetErrorString(error));
        return result;
    }

    const auto encode_compress_start = std::chrono::steady_clock::now();
    GenerateOracleVectorKernel<<<compress_blocks, ORACLE_THREADS, 0, workspace.stream>>>(
        seed_cv,
        workspace.out_cv,
        compress_words);
    double encode_compress_us = std::chrono::duration<double, std::micro>(
                                    std::chrono::steady_clock::now() - encode_compress_start)
                                    .count();

    error = cudaGetLastError();
    if (error != cudaSuccess) {
        result.error = "CUDA oracle compress kernel failed:" + std::string(cudaGetErrorString(error));
        return result;
    }

    const auto submit_wait_start = std::chrono::steady_clock::now();
    std::string staging_warning;
    if (!workspace.host_e_l.Ensure(noise_words, staging_warning) ||
        !workspace.host_e_r.Ensure(noise_words, staging_warning) ||
        !workspace.host_f_l.Ensure(noise_words, staging_warning) ||
        !workspace.host_f_r.Ensure(noise_words, staging_warning) ||
        !workspace.host_cv.Ensure(compress_words, staging_warning)) {
        result.error = staging_warning;
        return result;
    }
    error = cudaMemcpyAsync(workspace.host_e_l.data(), workspace.out_e_l, noise_words * sizeof(Element), cudaMemcpyDeviceToHost, workspace.stream);
    if (error == cudaSuccess) error = cudaMemcpyAsync(workspace.host_e_r.data(), workspace.out_e_r, noise_words * sizeof(Element), cudaMemcpyDeviceToHost, workspace.stream);
    if (error == cudaSuccess) error = cudaMemcpyAsync(workspace.host_f_l.data(), workspace.out_f_l, noise_words * sizeof(Element), cudaMemcpyDeviceToHost, workspace.stream);
    if (error == cudaSuccess) error = cudaMemcpyAsync(workspace.host_f_r.data(), workspace.out_f_r, noise_words * sizeof(Element), cudaMemcpyDeviceToHost, workspace.stream);
    if (error == cudaSuccess) error = cudaMemcpyAsync(workspace.host_cv.data(), workspace.out_cv, compress_words * sizeof(Element), cudaMemcpyDeviceToHost, workspace.stream);
    if (error == cudaSuccess) error = cudaStreamSynchronize(workspace.stream);
    const double submit_wait_us = std::chrono::duration<double, std::micro>(
                                      std::chrono::steady_clock::now() - submit_wait_start)
                                      .count();
    if (error != cudaSuccess) {
        result.error = "CUDA oracle stream completion failed:" + std::string(cudaGetErrorString(error));
        return result;
    }

    result.noise_e_l.assign(workspace.host_e_l.data(), workspace.host_e_l.data() + noise_words);
    result.noise_e_r.assign(workspace.host_e_r.data(), workspace.host_e_r.data() + noise_words);
    result.noise_f_l.assign(workspace.host_f_l.data(), workspace.host_f_l.data() + noise_words);
    result.noise_f_r.assign(workspace.host_f_r.data(), workspace.host_f_r.data() + noise_words);
    result.compress_vec.assign(workspace.host_cv.data(), workspace.host_cv.data() + compress_words);
    result.success = true;
    UpdateProfile(encode_noise_us, encode_compress_us, submit_wait_us, "cuda_noise4_plus_compress");
    return result;
}

MatMulInputGenerationDeviceResult GenerateMatMulInputsGPUDevice(const MatMulInputGenerationRequest& request)
{
    MatMulInputGenerationDeviceResult result;
    const auto runtime = ProbeCudaRuntime();
    result.available = runtime.available;
    if (!runtime.available) {
        result.error = runtime.reason;
        return result;
    }

    uint32_t noise_words{0};
    uint32_t compress_words{0};
    if (!ValidateInputGenerationRequest(request, result.error, noise_words, compress_words)) {
        return result;
    }

    const auto seed_el = ToInternalSeedBytes(matmul::noise::DeriveNoiseSeed(matmul::noise::TAG_EL, request.sigma));
    const auto seed_er = ToInternalSeedBytes(matmul::noise::DeriveNoiseSeed(matmul::noise::TAG_ER, request.sigma));
    const auto seed_fl = ToInternalSeedBytes(matmul::noise::DeriveNoiseSeed(matmul::noise::TAG_FL, request.sigma));
    const auto seed_fr = ToInternalSeedBytes(matmul::noise::DeriveNoiseSeed(matmul::noise::TAG_FR, request.sigma));
    const auto seed_cv = ToInternalSeedBytes(DeriveCompressionSeed(request.sigma));

    auto& workspace = g_workspace;
    ResetWorkspaceForDevice(workspace, runtime.device_index);

    cudaError_t error = cudaSetDevice(runtime.device_index);
    if (error != cudaSuccess) {
        result.error = "cudaSetDevice failed:" + std::string(cudaGetErrorString(error));
        return result;
    }
    if (!EnsureWorkspaceStream(workspace, result.error)) {
        return result;
    }

    auto generated = AcquireGeneratedInputsDevice(
        runtime.device_index,
        request.n,
        request.b,
        request.r,
        noise_words,
        compress_words,
        result.error);
    if (!generated) {
        return result;
    }

    const uint32_t noise_blocks = (noise_words + ORACLE_THREADS - 1) / ORACLE_THREADS;
    const uint32_t compress_blocks = (compress_words + ORACLE_THREADS - 1) / ORACLE_THREADS;
    const auto encode_noise_start = std::chrono::steady_clock::now();
    GenerateOracleNoiseKernel<<<noise_blocks, ORACLE_THREADS, 0, workspace.stream>>>(
        seed_el,
        seed_er,
        seed_fl,
        seed_fr,
        generated->noise_e_l,
        generated->noise_e_r,
        generated->noise_f_l,
        generated->noise_f_r,
        noise_words);
    const double encode_noise_us = std::chrono::duration<double, std::micro>(
                                       std::chrono::steady_clock::now() - encode_noise_start)
                                       .count();

    error = cudaGetLastError();
    if (error != cudaSuccess) {
        result.error = "CUDA oracle noise kernel failed:" + std::string(cudaGetErrorString(error));
        return result;
    }

    const auto encode_compress_start = std::chrono::steady_clock::now();
    GenerateOracleVectorKernel<<<compress_blocks, ORACLE_THREADS, 0, workspace.stream>>>(
        seed_cv,
        generated->compress_vec,
        compress_words);
    const double encode_compress_us = std::chrono::duration<double, std::micro>(
                                          std::chrono::steady_clock::now() - encode_compress_start)
                                          .count();

    error = cudaGetLastError();
    if (error != cudaSuccess) {
        result.error = "CUDA oracle compress kernel failed:" + std::string(cudaGetErrorString(error));
        return result;
    }

    auto* generated_inputs = const_cast<MatMulGeneratedInputsDevice*>(generated.get());
    if (!EnsureGeneratedInputsReadyEvent(*generated_inputs, result.error)) {
        return result;
    }

    const auto submit_wait_start = std::chrono::steady_clock::now();
    error = cudaEventRecord(
        reinterpret_cast<cudaEvent_t>(generated_inputs->ready_event),
        workspace.stream);
    const double submit_wait_us = std::chrono::duration<double, std::micro>(
                                      std::chrono::steady_clock::now() - submit_wait_start)
                                      .count();
    if (error != cudaSuccess) {
        result.error = "CUDA oracle ready-event record failed:" + std::string(cudaGetErrorString(error));
        return result;
    }

    result.success = true;
    result.inputs = std::move(generated);
    UpdateProfile(encode_noise_us, encode_compress_us, submit_wait_us, "cuda_noise4_plus_compress_device");
    return result;
}

} // namespace btx::cuda
