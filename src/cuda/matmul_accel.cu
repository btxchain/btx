// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cuda/matmul_accel.h>

#include <cuda/cuda_context.h>
#include <cuda/cuda_scheduler.h>
#include <cuda/oracle_accel.h>

#include <cuda_runtime.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <future>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace btx::cuda {
namespace {

using Element = matmul::field::Element;
constexpr Element MODULUS = matmul::field::MODULUS;
constexpr uint32_t REDUCE_INTERVAL{4};
constexpr uint32_t MAX_BLOCK_THREADS{256};
constexpr uint32_t WORKSPACE_THREADS{256};

std::string CudaErrorString(cudaError_t error);

struct DeviceSeedBytes {
    uint8_t data[32];
};

struct DigestWorkspace {
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
                error = "cudaMallocHost failed:" + CudaErrorString(alloc_error) + "; falling back to pageable host memory";
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

    uint256 cached_matrix_a_key;
    uint256 cached_matrix_b_key;
    uint32_t cached_matrix_elements{0};
    bool cached_matrix_keys_valid{false};

    Element* device_base_a{nullptr};
    Element* device_base_b{nullptr};
    size_t base_a_capacity{0};
    size_t base_b_capacity{0};

    Element* device_matrix_a{nullptr};
    Element* device_matrix_b{nullptr};
    size_t matrix_a_capacity{0};
    size_t matrix_b_capacity{0};
    DeviceSeedBytes* device_seed_a{nullptr};
    DeviceSeedBytes* device_seed_b{nullptr};
    size_t seed_a_capacity{0};
    size_t seed_b_capacity{0};

    Element* device_noise_e_l{nullptr};
    Element* device_noise_e_r{nullptr};
    Element* device_noise_f_l{nullptr};
    Element* device_noise_f_r{nullptr};
    size_t noise_e_l_capacity{0};
    size_t noise_e_r_capacity{0};
    size_t noise_f_l_capacity{0};
    size_t noise_f_r_capacity{0};
    const Element** device_prepared_input_ptrs{nullptr};
    size_t prepared_input_ptr_capacity{0};

    Element* device_compress{nullptr};
    size_t compress_capacity{0};

    Element* device_output{nullptr};
    size_t output_capacity{0};

    // Factored-compression staging (PRODUCT_FINAL_BLOCKS path): D[j][x][m]
    // per request - block_size * n * blocks_per_axis words (1 MiB at n=512).
    Element* device_factored_rhs{nullptr};
    size_t factored_rhs_capacity{0};

    // Per-seed SHA midstates for matrix generation: 16 words/seed (8 packed seed
    // words + 8 post-round-7 state words). Tiny (batch_size * 64 B).
    uint32_t* device_seed_midstates{nullptr};
    size_t seed_midstates_capacity{0};

    HostStageBuffer host_matrix_a;
    HostStageBuffer host_matrix_b;
    HostStageBuffer host_noise_e_l;
    HostStageBuffer host_noise_e_r;
    HostStageBuffer host_noise_f_l;
    HostStageBuffer host_noise_f_r;
    HostStageBuffer host_compress;
    HostStageBuffer host_output;

    void ReleaseDeviceBuffers()
    {
        cudaFree(device_seed_midstates);
        cudaFree(device_factored_rhs);
        cudaFree(device_output);
        cudaFree(device_compress);
        cudaFree(device_noise_f_r);
        cudaFree(device_noise_f_l);
        cudaFree(device_noise_e_r);
        cudaFree(device_noise_e_l);
        cudaFree(device_prepared_input_ptrs);
        cudaFree(device_seed_b);
        cudaFree(device_seed_a);
        cudaFree(device_matrix_b);
        cudaFree(device_matrix_a);
        cudaFree(device_base_b);
        cudaFree(device_base_a);

        device_seed_midstates = nullptr;
        device_factored_rhs = nullptr;
        device_output = nullptr;
        device_compress = nullptr;
        device_noise_f_r = nullptr;
        device_noise_f_l = nullptr;
        device_noise_e_r = nullptr;
        device_noise_e_l = nullptr;
        device_prepared_input_ptrs = nullptr;
        device_seed_b = nullptr;
        device_seed_a = nullptr;
        device_matrix_b = nullptr;
        device_matrix_a = nullptr;
        device_base_b = nullptr;
        device_base_a = nullptr;

        seed_midstates_capacity = 0;
        factored_rhs_capacity = 0;
        output_capacity = 0;
        compress_capacity = 0;
        noise_f_r_capacity = 0;
        noise_f_l_capacity = 0;
        noise_e_r_capacity = 0;
        noise_e_l_capacity = 0;
        prepared_input_ptr_capacity = 0;
        seed_b_capacity = 0;
        seed_a_capacity = 0;
        matrix_b_capacity = 0;
        matrix_a_capacity = 0;
        base_b_capacity = 0;
        base_a_capacity = 0;

        cached_matrix_a_key.SetNull();
        cached_matrix_b_key.SetNull();
        cached_matrix_elements = 0;
        cached_matrix_keys_valid = false;
    }

    void ReleaseStream()
    {
        if (stream != nullptr) {
            cudaStreamDestroy(stream);
            stream = nullptr;
        }
    }

    ~DigestWorkspace()
    {
        if (device_index >= 0) {
            cudaSetDevice(device_index);
        }
        ReleaseStream();
        ReleaseDeviceBuffers();
    }
};

struct DigestPoolSlot {
    DigestWorkspace workspace;
    bool in_use{false};
};

struct DigestPoolContext {
    std::mutex mutex;
    std::condition_variable cv;
    std::vector<std::unique_ptr<DigestPoolSlot>> slots;
    uint32_t next_slot{0};
    uint32_t active_slots{0};
    uint32_t high_water_slots{0};
    uint64_t allocation_events{0};
    uint64_t reuse_events{0};
    uint64_t wait_events{0};
    uint64_t completed_submissions{0};
    uint32_t inflight_submissions{0};
    uint32_t peak_inflight_submissions{0};
    uint32_t last_n{0};
    uint32_t last_b{0};
    uint32_t last_r{0};
    bool initialized{false};
    std::string reason{"buffer_pool_uninitialized"};
};

struct DigestProfilingSample {
    uint32_t n{0};
    uint32_t b{0};
    uint32_t r{0};
    uint32_t batch_size{0};
    double host_stage_us{0.0};
    double submit_h2d_us{0.0};
    double submit_d2d_us{0.0};
    double stream_wait_event_us{0.0};
    double launch_build_perturbed_us{0.0};
    double launch_finalize_us{0.0};
    double submit_d2h_us{0.0};
    double stream_sync_us{0.0};
    double total_wall_ms{0.0};
    bool used_low_rank_path{false};
    bool used_device_prepared_inputs{false};
    bool used_pinned_host_staging{true};
    bool base_matrix_cache_hit{false};
    std::string mode;
};

struct DigestProfilingContext {
    std::mutex mutex;
    uint64_t samples{0};
    uint32_t last_n{0};
    uint32_t last_b{0};
    uint32_t last_r{0};
    uint32_t last_batch_size{0};
    double last_host_stage_us{0.0};
    double last_submit_h2d_us{0.0};
    double last_submit_d2d_us{0.0};
    double last_stream_wait_event_us{0.0};
    double last_launch_build_perturbed_us{0.0};
    double last_launch_finalize_us{0.0};
    double last_submit_d2h_us{0.0};
    double last_stream_sync_us{0.0};
    double last_total_wall_ms{0.0};
    bool last_used_low_rank_path{false};
    bool last_used_device_prepared_inputs{false};
    bool last_used_pinned_host_staging{false};
    bool last_base_matrix_cache_hit{false};
    std::string last_mode;
    std::string reason{"no_samples"};
};

CudaRuntimeProbe RuntimeProbeFromDeviceInfo(const CudaTopologyProbe& topology, const CudaDeviceInfo& device)
{
    CudaRuntimeProbe probe;
    probe.compiled = topology.compiled;
    probe.available = topology.available && device.supported;
    probe.reason = probe.available ? "ready" : device.reason;
    probe.device_index = device.device_index;
    probe.device_name = device.device_name;
    probe.compute_capability_major = device.compute_capability_major;
    probe.compute_capability_minor = device.compute_capability_minor;
    probe.global_memory_bytes = device.global_memory_bytes;
    probe.multiprocessor_count = device.multiprocessor_count;
    probe.driver_api_version = topology.driver_api_version;
    probe.runtime_version = topology.runtime_version;
    return probe;
}

std::optional<CudaRuntimeProbe> ResolveCudaRuntimeForSelectedDevice(int device_index, std::string& error)
{
    const auto topology = ProbeCudaTopology();
    if (!topology.available) {
        error = topology.reason;
        return std::nullopt;
    }

    for (const auto& device : topology.selected_devices) {
        if (device.device_index == device_index) {
            return RuntimeProbeFromDeviceInfo(topology, device);
        }
    }

    error = "selected_cuda_device_not_enabled:" + std::to_string(device_index);
    return std::nullopt;
}

bool ParsePoolSlotCount(const std::string& value, uint32_t& slots)
{
    constexpr uint32_t MAX_SLOTS{32};
    try {
        size_t consumed{0};
        const unsigned long parsed = std::stoul(value, &consumed, 10);
        if (consumed != value.size() || parsed == 0) {
            return false;
        }
        slots = std::min<uint32_t>(static_cast<uint32_t>(parsed), MAX_SLOTS);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

std::optional<uint32_t> ResolveCudaPoolSlotOverride(int device_index)
{
    const char* env = std::getenv("BTX_MATMUL_CUDA_POOL_SLOTS");
    if (env == nullptr || *env == '\0') {
        return std::nullopt;
    }

    const std::string value{env};
    if (value.find(':') == std::string::npos) {
        uint32_t slots{0};
        return ParsePoolSlotCount(value, slots) ? std::optional<uint32_t>{slots} : std::nullopt;
    }

    size_t begin{0};
    while (begin <= value.size()) {
        const size_t comma = value.find(',', begin);
        const std::string token = value.substr(begin, comma == std::string::npos ? std::string::npos : comma - begin);
        const size_t colon = token.find(':');
        if (colon == std::string::npos) {
            return std::nullopt;
        }

        int parsed_device{-1};
        uint32_t parsed_slots{0};
        try {
            size_t consumed{0};
            parsed_device = std::stoi(token.substr(0, colon), &consumed, 10);
            if (consumed != token.substr(0, colon).size() || parsed_device < 0) {
                return std::nullopt;
            }
        } catch (const std::exception&) {
            return std::nullopt;
        }
        if (!ParsePoolSlotCount(token.substr(colon + 1), parsed_slots)) {
            return std::nullopt;
        }
        if (parsed_device == device_index) {
            return parsed_slots;
        }

        if (comma == std::string::npos) {
            break;
        }
        begin = comma + 1;
    }

    return std::nullopt;
}

uint32_t ResolveCudaPoolSlotCount(int device_index)
{
    constexpr uint32_t DEFAULT_SLOTS{1};
    constexpr uint32_t MAX_SLOTS{32};

    if (const auto override_slots = ResolveCudaPoolSlotOverride(device_index)) {
        return *override_slots;
    }

    const auto topology = ProbeCudaTopology();
    uint32_t multiprocessor_count{0};
    if (topology.available) {
        for (const auto& device : topology.selected_devices) {
            if (device.device_index == device_index) {
                multiprocessor_count = device.multiprocessor_count;
                break;
            }
        }
    }
    if (multiprocessor_count == 0) {
        return DEFAULT_SLOTS;
    }

    const uint32_t hw = std::thread::hardware_concurrency();
    const uint32_t cpu_limit =
        hw >= 24 ? 8U :
        hw >= 16 ? 6U :
        hw >= 12 ? 4U :
        hw >= 8 ? 3U :
        hw >= 4 ? 2U : 1U;
    const uint32_t gpu_limit =
        multiprocessor_count >= 128 ? 8U :
        multiprocessor_count >= 96 ? 7U :
        multiprocessor_count >= 64 ? 6U :
        multiprocessor_count >= 48 ? 5U :
        multiprocessor_count >= 24 ? 4U :
        multiprocessor_count >= 12 ? 2U : 1U;
    return std::clamp<uint32_t>(std::min(cpu_limit, gpu_limit), 1U, MAX_SLOTS);
}

DigestPoolContext& GetPoolContext(int device_index)
{
    static std::mutex contexts_mutex;
    static std::map<int, std::unique_ptr<DigestPoolContext>> contexts;

    std::lock_guard<std::mutex> lock(contexts_mutex);
    auto& context = contexts[device_index];
    if (context == nullptr) {
        context = std::make_unique<DigestPoolContext>();
        context->slots.resize(ResolveCudaPoolSlotCount(device_index));
        for (auto& slot : context->slots) {
            slot = std::make_unique<DigestPoolSlot>();
        }
    }
    return *context;
}

DigestProfilingContext& GetProfilingContext()
{
    static DigestProfilingContext context;
    return context;
}

using SteadyClock = std::chrono::steady_clock;

double DurationMicros(const SteadyClock::time_point start, const SteadyClock::time_point end)
{
    return std::chrono::duration<double, std::micro>(end - start).count();
}

double DurationMillis(const SteadyClock::time_point start, const SteadyClock::time_point end)
{
    return std::chrono::duration<double, std::milli>(end - start).count();
}

std::string ModeToString(MatMulCompressedWordsMode mode)
{
    switch (mode) {
    case MatMulCompressedWordsMode::TRANSCRIPT_PREFIXES:
        return "transcript_prefixes";
    case MatMulCompressedWordsMode::PRODUCT_FINAL_BLOCKS:
        return "product_final_blocks";
    }
    return "unknown";
}

bool IsBaseMatrixCacheHit(const DigestWorkspace& workspace,
                          const uint256* matrix_a_cache_key,
                          const uint256* matrix_b_cache_key,
                          uint32_t matrix_elements)
{
    return matrix_a_cache_key != nullptr &&
        matrix_b_cache_key != nullptr &&
        workspace.cached_matrix_keys_valid &&
        workspace.cached_matrix_a_key == *matrix_a_cache_key &&
        workspace.cached_matrix_b_key == *matrix_b_cache_key &&
        workspace.cached_matrix_elements == matrix_elements &&
        workspace.device_base_a != nullptr &&
        workspace.device_base_b != nullptr;
}

void RecordProfilingSample(const DigestProfilingSample& sample)
{
    auto& context = GetProfilingContext();
    std::lock_guard<std::mutex> lock(context.mutex);
    ++context.samples;
    context.last_n = sample.n;
    context.last_b = sample.b;
    context.last_r = sample.r;
    context.last_batch_size = sample.batch_size;
    context.last_host_stage_us = sample.host_stage_us;
    context.last_submit_h2d_us = sample.submit_h2d_us;
    context.last_submit_d2d_us = sample.submit_d2d_us;
    context.last_stream_wait_event_us = sample.stream_wait_event_us;
    context.last_launch_build_perturbed_us = sample.launch_build_perturbed_us;
    context.last_launch_finalize_us = sample.launch_finalize_us;
    context.last_submit_d2h_us = sample.submit_d2h_us;
    context.last_stream_sync_us = sample.stream_sync_us;
    context.last_total_wall_ms = sample.total_wall_ms;
    context.last_used_low_rank_path = sample.used_low_rank_path;
    context.last_used_device_prepared_inputs = sample.used_device_prepared_inputs;
    context.last_used_pinned_host_staging = sample.used_pinned_host_staging;
    context.last_base_matrix_cache_hit = sample.base_matrix_cache_hit;
    context.last_mode = sample.mode;
    context.reason = "samples_recorded";
}

class BufferPoolLease
{
public:
    BufferPoolLease() = default;

    BufferPoolLease(DigestPoolContext* context, DigestPoolSlot* slot)
        : m_context(context), m_slot(slot)
    {
    }

    BufferPoolLease(BufferPoolLease&& other) noexcept
        : m_context(other.m_context), m_slot(other.m_slot)
    {
        other.m_context = nullptr;
        other.m_slot = nullptr;
    }

    ~BufferPoolLease() { Release(); }

    DigestWorkspace& workspace() const { return m_slot->workspace; }

    void RecordRequest(uint32_t n, uint32_t b, uint32_t r, bool allocated_buffers) const
    {
        if (m_context == nullptr) {
            return;
        }

        std::lock_guard<std::mutex> lock(m_context->mutex);
        m_context->initialized = true;
        m_context->last_n = n;
        m_context->last_b = b;
        m_context->last_r = r;
        if (allocated_buffers) {
            ++m_context->allocation_events;
        } else {
            ++m_context->reuse_events;
        }
        m_context->reason = "buffer_pool_slots_ready";
    }

private:
    void Release()
    {
        if (m_context == nullptr || m_slot == nullptr) {
            return;
        }

        {
            std::lock_guard<std::mutex> lock(m_context->mutex);
            if (m_slot->in_use) {
                m_slot->in_use = false;
                if (m_context->active_slots > 0) {
                    --m_context->active_slots;
                }
                if (m_context->inflight_submissions > 0) {
                    --m_context->inflight_submissions;
                }
                ++m_context->completed_submissions;
            }
        }

        m_context->cv.notify_one();
        m_context = nullptr;
        m_slot = nullptr;
    }

    DigestPoolContext* m_context{nullptr};
    DigestPoolSlot* m_slot{nullptr};
};

std::optional<BufferPoolLease> AcquireBufferPoolSlot(int device_index, std::string& error)
{
    auto& context = GetPoolContext(device_index);
    std::unique_lock<std::mutex> lock(context.mutex);
    if (context.slots.empty()) {
        error = "No CUDA buffer pool slots are configured";
        return std::nullopt;
    }

    bool waited{false};
    constexpr uint32_t kMaxWaitRounds = 40; // 40 * 50ms = 2 seconds
    uint32_t wait_rounds{0};
    while (true) {
        auto acquire_slot = [&](bool prefer_reused_buffers) -> std::optional<BufferPoolLease> {
            for (size_t offset = 0; offset < context.slots.size(); ++offset) {
                const size_t slot_index = (context.next_slot + offset) % context.slots.size();
                auto& slot = context.slots[slot_index];
                if (slot->in_use) {
                    continue;
                }

                const bool has_reusable_buffers =
                    slot->workspace.stream != nullptr ||
                    slot->workspace.base_a_capacity > 0 ||
                    slot->workspace.base_b_capacity > 0 ||
                    slot->workspace.matrix_a_capacity > 0 ||
                    slot->workspace.matrix_b_capacity > 0 ||
                    slot->workspace.output_capacity > 0 ||
                    slot->workspace.compress_capacity > 0 ||
                    slot->workspace.prepared_input_ptr_capacity > 0;
                if (prefer_reused_buffers && !has_reusable_buffers) {
                    continue;
                }

                slot->in_use = true;
                ++context.active_slots;
                context.high_water_slots = std::max(context.high_water_slots, context.active_slots);
                ++context.inflight_submissions;
                context.peak_inflight_submissions = std::max(context.peak_inflight_submissions, context.inflight_submissions);
                context.next_slot = static_cast<uint32_t>((slot_index + 1) % context.slots.size());
                if (waited) {
                    ++context.wait_events;
                }
                return BufferPoolLease{&context, slot.get()};
            }
            return std::nullopt;
        };

        if (auto lease = acquire_slot(/*prefer_reused_buffers=*/true)) {
            return lease;
        }
        if (auto lease = acquire_slot(/*prefer_reused_buffers=*/false)) {
            return lease;
        }

        waited = true;
        if (++wait_rounds > kMaxWaitRounds) {
            error = "CUDA buffer pool exhausted after timeout";
            return std::nullopt;
        }
        context.cv.wait_for(lock, std::chrono::milliseconds{50});
    }
}

__host__ __device__ __forceinline__ Element Reduce64(uint64_t value)
{
    const uint64_t fold1 = (value & static_cast<uint64_t>(MODULUS)) + (value >> 31);
    const uint32_t lo = static_cast<uint32_t>(fold1 & MODULUS);
    const uint32_t hi = static_cast<uint32_t>(fold1 >> 31);
    uint32_t result = lo + hi;
    const uint32_t ge_mask = static_cast<uint32_t>(-static_cast<int32_t>(result >= MODULUS));
    result -= (MODULUS & ge_mask);
    return result;
}

__host__ __device__ __forceinline__ Element FieldAdd(Element a, Element b)
{
    uint32_t sum = a + b;
    if (sum >= MODULUS) {
        sum -= MODULUS;
    }
    return sum;
}

__host__ __device__ __forceinline__ Element FieldMul(Element a, Element b)
{
    return Reduce64(static_cast<uint64_t>(a) * static_cast<uint64_t>(b));
}

__device__ __forceinline__ uint32_t RotR(uint32_t x, uint32_t n)
{
    return (x >> n) | (x << (32U - n));
}

__device__ __forceinline__ uint32_t ShaCh(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ ((~x) & z);
}

__device__ __forceinline__ uint32_t ShaMaj(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

__device__ __forceinline__ uint32_t ShaBSig0(uint32_t x)
{
    return RotR(x, 2U) ^ RotR(x, 13U) ^ RotR(x, 22U);
}

__device__ __forceinline__ uint32_t ShaBSig1(uint32_t x)
{
    return RotR(x, 6U) ^ RotR(x, 11U) ^ RotR(x, 25U);
}

__device__ __forceinline__ uint32_t ShaSSig0(uint32_t x)
{
    return RotR(x, 7U) ^ RotR(x, 18U) ^ (x >> 3U);
}

__device__ __forceinline__ uint32_t ShaSSig1(uint32_t x)
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

__device__ __forceinline__ void SetShaByte(uint32_t w[16], uint32_t offset, uint32_t byte)
{
    const uint32_t word_index = offset >> 2U;
    const uint32_t shift = (3U - (offset & 3U)) * 8U;
    w[word_index] |= (byte & 0xffU) << shift;
}

__device__ __forceinline__ uint32_t Bswap32(uint32_t x)
{
    return ((x & 0x000000ffU) << 24U) |
        ((x & 0x0000ff00U) << 8U) |
        ((x & 0x00ff0000U) >> 8U) |
        ((x & 0xff000000U) >> 24U);
}

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

// WINDOWED SHA-256 compression: 16-word sliding schedule instead of a 64-word
// array - the same transform as sha-windowed-scanner.patch (oracle_accel.cu),
// applied to this file's duplicate of the SHA code. Hot via the per-candidate
// GenerateBaseMatrixFromSeedBatchKernel (2 x n^2 = 524k compressions per
// candidate at n=512), where the 64-word local array spills to local memory.
__device__ inline void Sha256Compress(uint32_t state[8], uint32_t w[16])
{
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

    #pragma unroll
    for (uint32_t t = 0; t < 64; ++t) {
        uint32_t wt;
        if (t < 16) {
            wt = w[t];
        } else {
            wt = ShaSSig1(w[(t - 2) & 15U]) + w[(t - 7) & 15U] + ShaSSig0(w[(t - 15) & 15U]) + w[(t - 16) & 15U];
            w[t & 15U] = wt;
        }
        const uint32_t t1 = h + ShaBSig1(e) + ShaCh(e, f, g) + SHA256_K[t] + wt;
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

__device__ inline uint32_t CandidateFromSeedAndIndex(const DeviceSeedBytes& seed,
                                                     uint32_t index,
                                                     bool with_retry,
                                                     uint32_t retry)
{
    uint32_t w[16] = {};
    for (uint32_t i = 0; i < 32; ++i) {
        SetShaByte(w, i, seed.data[31U - i]);
    }

    SetShaByte(w, 32U, index & 0xffU);
    SetShaByte(w, 33U, (index >> 8U) & 0xffU);
    SetShaByte(w, 34U, (index >> 16U) & 0xffU);
    SetShaByte(w, 35U, (index >> 24U) & 0xffU);

    uint32_t message_len = 36U;
    if (with_retry) {
        SetShaByte(w, 36U, retry & 0xffU);
        SetShaByte(w, 37U, (retry >> 8U) & 0xffU);
        SetShaByte(w, 38U, (retry >> 16U) & 0xffU);
        SetShaByte(w, 39U, (retry >> 24U) & 0xffU);
        message_len = 40U;
    }

    SetShaByte(w, message_len, 0x80U);
    w[15] = message_len * 8U;

    uint32_t state[8];
    Sha256Init(state);
    Sha256Compress(state, w);
    return Bswap32(state[0]) & MODULUS;
}

__device__ inline uint32_t FallbackCandidate(const DeviceSeedBytes& seed, uint32_t index)
{
    uint32_t w[16] = {};
    for (uint32_t i = 0; i < 32; ++i) {
        SetShaByte(w, i, seed.data[31U - i]);
    }

    SetShaByte(w, 32U, index & 0xffU);
    SetShaByte(w, 33U, (index >> 8U) & 0xffU);
    SetShaByte(w, 34U, (index >> 16U) & 0xffU);
    SetShaByte(w, 35U, (index >> 24U) & 0xffU);

    constexpr uint8_t fallback_tag[15] = {
        'o', 'r', 'a', 'c', 'l', 'e', '-', 'f', 'a', 'l', 'l', 'b', 'a', 'c', 'k'
    };
    for (uint32_t i = 0; i < 15; ++i) {
        SetShaByte(w, 36U + i, fallback_tag[i]);
    }

    SetShaByte(w, 51U, 0x80U);
    w[15] = 51U * 8U;

    uint32_t state[8];
    Sha256Init(state);
    Sha256Compress(state, w);
    return Bswap32(state[0]) % MODULUS;
}

__device__ inline uint32_t FromOracle(const DeviceSeedBytes& seed, uint32_t index)
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

// --- Seed-midstate matrix generation (2-kernel form) ---
// Every element of a base matrix hashes seed||index with the SAME 32-byte seed
// in w[0..7]; SHA-256 rounds 0-7 consume only those words, so the post-round-7
// state is identical across all 2^18 elements. PrecomputeSeedMidstatesKernel
// computes it once per seed (one thread each) into a 16-word record (8 packed
// seed words + 8 state words); the generation kernel loads those as scalars and
// resumes each element's hash at round 8 - 8 of 64 rounds saved per element,
// with no per-block barrier (which is why a precompute kernel beats a shared-
// memory hoist here). Byte-identical to FromOracle's retry==0 result; the
// ~2^-31 retry/fallback case defers to the full FromOracle path.

__device__ inline void PackSeedWords(const DeviceSeedBytes& seed, uint32_t seed_w[8])
{
    #pragma unroll
    for (uint32_t i = 0; i < 8; ++i) {
        seed_w[i] = 0U;
    }
    for (uint32_t i = 0; i < 32; ++i) {
        SetShaByte(seed_w, i, seed.data[31U - i]);
    }
}

__global__ void PrecomputeSeedMidstatesKernel(const DeviceSeedBytes* seeds,
                                              uint32_t seed_count,
                                              uint32_t* midstates)
{
    const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= seed_count) {
        return;
    }
    uint32_t w[8];
    PackSeedWords(seeds[i], w);
    uint32_t a = 0x6a09e667U, b = 0xbb67ae85U, c = 0x3c6ef372U, d = 0xa54ff53aU;
    uint32_t e = 0x510e527fU, f = 0x9b05688cU, g = 0x1f83d9abU, h = 0x5be0cd19U;
    #pragma unroll
    for (uint32_t t = 0; t < 8; ++t) {
        const uint32_t t1 = h + ShaBSig1(e) + ShaCh(e, f, g) + SHA256_K[t] + w[t];
        const uint32_t t2 = ShaBSig0(a) + ShaMaj(a, b, c);
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    uint32_t* o = midstates + static_cast<size_t>(i) * 16U;
    o[0] = w[0]; o[1] = w[1]; o[2] = w[2]; o[3] = w[3];
    o[4] = w[4]; o[5] = w[5]; o[6] = w[6]; o[7] = w[7];
    o[8] = a; o[9] = b; o[10] = c; o[11] = d;
    o[12] = e; o[13] = f; o[14] = g; o[15] = h;
}

// retry==0 candidate resuming from a precomputed midstate (loaded as scalars so
// the window and state stay in registers - no local-memory array parameters).
__device__ inline uint32_t CandidateFromMidstateScalars(const uint32_t* mb, uint32_t index)
{
    uint32_t w[16];
    w[0] = mb[0]; w[1] = mb[1]; w[2] = mb[2]; w[3] = mb[3];
    w[4] = mb[4]; w[5] = mb[5]; w[6] = mb[6]; w[7] = mb[7];
    #pragma unroll
    for (uint32_t i = 8; i < 16; ++i) {
        w[i] = 0U;
    }
    SetShaByte(w, 32U, index & 0xffU);
    SetShaByte(w, 33U, (index >> 8U) & 0xffU);
    SetShaByte(w, 34U, (index >> 16U) & 0xffU);
    SetShaByte(w, 35U, (index >> 24U) & 0xffU);
    SetShaByte(w, 36U, 0x80U);
    w[15] = 36U * 8U;

    uint32_t a = mb[8], b = mb[9], c = mb[10], d = mb[11];
    uint32_t e = mb[12], f = mb[13], g = mb[14], h = mb[15];
    #pragma unroll
    for (uint32_t t = 8; t < 64; ++t) {
        uint32_t wt;
        if (t < 16) {
            wt = w[t];
        } else {
            wt = ShaSSig1(w[(t - 2) & 15U]) + w[(t - 7) & 15U] + ShaSSig0(w[(t - 15) & 15U]) + w[(t - 16) & 15U];
            w[t & 15U] = wt;
        }
        const uint32_t t1 = h + ShaBSig1(e) + ShaCh(e, f, g) + SHA256_K[t] + wt;
        const uint32_t t2 = ShaBSig0(a) + ShaMaj(a, b, c);
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    return Bswap32(0x6a09e667U + a) & MODULUS;
}

__global__ void GenerateBaseMatrixFromSeedMidstateKernel(const DeviceSeedBytes* seeds,
                                                         const uint32_t* midstates,
                                                         uint32_t n,
                                                         size_t total_matrix_elements,
                                                         uint32_t matrix_elements,
                                                         Element* output_batch)
{
    const size_t gid = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (gid >= total_matrix_elements) {
        return;
    }
    const uint32_t batch_index = static_cast<uint32_t>(gid / matrix_elements);
    const uint32_t local_index = static_cast<uint32_t>(gid % matrix_elements);
    (void)n;
    const uint32_t* mb = midstates + static_cast<size_t>(batch_index) * 16U;
    const uint32_t candidate = CandidateFromMidstateScalars(mb, local_index);
    output_batch[gid] = candidate < MODULUS
        ? candidate
        : FromOracle(seeds[batch_index], local_index);
}

__device__ __forceinline__ void ReducePartialsInPlace(Element* partials, uint32_t tid)
{
#if defined(__CUDA_ARCH__) && __CUDA_ARCH__ >= 700
    for (uint32_t stride = blockDim.x / 2; stride > 32; stride >>= 1) {
        if (tid < stride) {
            partials[tid] = FieldAdd(partials[tid], partials[tid + stride]);
        }
        __syncthreads();
    }

    if (tid < 32) {
        const uint32_t warp_lanes = blockDim.x < 32 ? blockDim.x : 32U;
        const uint32_t lane = tid & 31U;
        Element value = partials[tid];

        if (blockDim.x >= 64) {
            value = FieldAdd(value, partials[tid + 32]);
        }

        const unsigned warp_mask = __activemask();
        for (uint32_t offset = warp_lanes / 2; offset > 0; offset >>= 1) {
            const Element other = __shfl_down_sync(warp_mask, value, offset);
            if (lane + offset < warp_lanes) {
                value = FieldAdd(value, other);
            }
        }

        if (tid == 0) {
            partials[0] = value;
        }
    }
#else
    for (uint32_t stride = blockDim.x / 2; stride > 0; stride >>= 1) {
        if (tid < stride) {
            partials[tid] = FieldAdd(partials[tid], partials[tid + stride]);
        }
        __syncthreads();
    }
#endif
}

__global__ void BuildPerturbedMatrixKernel(const Element* base_matrix,
                                           const Element* noise_left_batch,
                                           const Element* noise_right_batch,
                                           uint32_t n,
                                           uint32_t r,
                                           size_t total_matrix_elements,
                                           uint32_t matrix_elements,
                                           uint32_t noise_left_elements,
                                           uint32_t noise_right_elements,
                                           Element* output_batch)
{
    const size_t gid = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (gid >= total_matrix_elements) {
        return;
    }

    const uint32_t batch_index = static_cast<uint32_t>(gid / matrix_elements);
    const uint32_t local_index = static_cast<uint32_t>(gid % matrix_elements);
    const uint32_t row = local_index / n;
    const uint32_t col = local_index % n;
    const Element* noise_left = noise_left_batch + static_cast<size_t>(batch_index) * noise_left_elements;
    const Element* noise_right = noise_right_batch + static_cast<size_t>(batch_index) * noise_right_elements;

    uint64_t acc{0};
    uint32_t pending{0};
    for (uint32_t k = 0; k < r; ++k) {
        acc += static_cast<uint64_t>(noise_left[row * r + k]) * noise_right[k * n + col];
        if (++pending == REDUCE_INTERVAL) {
            acc = Reduce64(acc);
            pending = 0;
        }
    }

    output_batch[gid] = FieldAdd(base_matrix[local_index], Reduce64(acc));
}

__global__ void BuildPerturbedMatrixPackedPointersKernel(const Element* base_matrix,
                                                         const Element* const* packed_input_ptrs,
                                                         uint32_t noise_left_offset_words,
                                                         uint32_t noise_right_offset_words,
                                                         uint32_t n,
                                                         uint32_t r,
                                                         size_t total_matrix_elements,
                                                         uint32_t matrix_elements,
                                                         Element* output_batch)
{
    const size_t gid = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (gid >= total_matrix_elements) {
        return;
    }

    const uint32_t batch_index = static_cast<uint32_t>(gid / matrix_elements);
    const uint32_t local_index = static_cast<uint32_t>(gid % matrix_elements);
    const uint32_t row = local_index / n;
    const uint32_t col = local_index % n;
    const Element* packed_inputs = packed_input_ptrs[batch_index];
    const Element* noise_left = packed_inputs + noise_left_offset_words;
    const Element* noise_right = packed_inputs + noise_right_offset_words;

    uint64_t acc{0};
    uint32_t pending{0};
    for (uint32_t k = 0; k < r; ++k) {
        acc += static_cast<uint64_t>(noise_left[row * r + k]) * noise_right[k * n + col];
        if (++pending == REDUCE_INTERVAL) {
            acc = Reduce64(acc);
            pending = 0;
        }
    }

    output_batch[gid] = FieldAdd(base_matrix[local_index], Reduce64(acc));
}

__global__ void GenerateBaseMatrixFromSeedBatchKernel(const DeviceSeedBytes* seeds,
                                                      uint32_t n,
                                                      size_t total_matrix_elements,
                                                      uint32_t matrix_elements,
                                                      Element* output_batch)
{
    const size_t gid = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (gid >= total_matrix_elements) {
        return;
    }

    const uint32_t batch_index = static_cast<uint32_t>(gid / matrix_elements);
    const uint32_t local_index = static_cast<uint32_t>(gid % matrix_elements);
    (void)n;
    output_batch[gid] = FromOracle(seeds[batch_index], local_index);
}

__global__ void ApplyPerturbationPackedPointersVariableBaseKernel(
    const Element* const* packed_input_ptrs,
    uint32_t noise_left_offset_words,
    uint32_t noise_right_offset_words,
    uint32_t n,
    uint32_t r,
    size_t total_matrix_elements,
    uint32_t matrix_elements,
    Element* matrix_batch)
{
    const size_t gid = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (gid >= total_matrix_elements) {
        return;
    }

    const uint32_t batch_index = static_cast<uint32_t>(gid / matrix_elements);
    const uint32_t local_index = static_cast<uint32_t>(gid % matrix_elements);
    const uint32_t row = local_index / n;
    const uint32_t col = local_index % n;
    const Element* packed_inputs = packed_input_ptrs[batch_index];
    const Element* noise_left = packed_inputs + noise_left_offset_words;
    const Element* noise_right = packed_inputs + noise_right_offset_words;

    uint64_t acc{0};
    uint32_t pending{0};
    for (uint32_t k = 0; k < r; ++k) {
        acc += static_cast<uint64_t>(noise_left[row * r + k]) * noise_right[k * n + col];
        if (++pending == REDUCE_INTERVAL) {
            acc = Reduce64(acc);
            pending = 0;
        }
    }

    matrix_batch[gid] = FieldAdd(matrix_batch[gid], Reduce64(acc));
}

template <bool PrefixMode>
__global__ void ComputeCompressedWordsFusedKernel(const Element* __restrict__ matrix_a_batch,
                                                  const Element* __restrict__ matrix_b_batch,
                                                  const Element* __restrict__ compress_batch,
                                                  uint32_t n,
                                                  uint32_t block_size,
                                                  uint32_t blocks_per_axis,
                                                  uint32_t pair_count_per_request,
                                                  uint32_t words_per_request,
                                                  uint32_t matrix_elements,
                                                  uint32_t compress_elements,
                                                  Element* __restrict__ output)
{
    __shared__ Element partials[MAX_BLOCK_THREADS];

    const uint32_t pair_index = blockIdx.x;
    const uint32_t batch_index = pair_index / pair_count_per_request;
    const uint32_t local_pair_index = pair_index % pair_count_per_request;
    const uint32_t j = local_pair_index % blocks_per_axis;
    const uint32_t i = local_pair_index / blocks_per_axis;
    const uint32_t tid = threadIdx.x;
    const uint32_t active_threads = block_size * block_size;
    const Element* matrix_a = matrix_a_batch + static_cast<size_t>(batch_index) * matrix_elements;
    const Element* matrix_b = matrix_b_batch + static_cast<size_t>(batch_index) * matrix_elements;
    const Element* compress_vec = compress_batch + static_cast<size_t>(batch_index) * compress_elements;
    const uint32_t output_offset = batch_index * words_per_request +
        (PrefixMode ? local_pair_index * blocks_per_axis : local_pair_index);
    const bool active = tid < active_threads;
    const uint32_t x = active ? (tid / block_size) : 0;
    const uint32_t y = active ? (tid % block_size) : 0;
    const uint32_t row = i * block_size + x;
    const uint32_t col = j * block_size + y;
    const size_t row_offset = static_cast<size_t>(row) * n;
    const Element compress_coeff = active ? compress_vec[tid] : 0;

    Element running_total{0};
    if constexpr (!PrefixMode) {
        // PRODUCT_FINAL_BLOCKS emits ONE word per block pair: the compress-
        // weighted sum over the whole block product. Mod-field arithmetic is
        // distributive, so fold the full length-n dot product per thread in
        // registers and reduce across the block exactly once - instead of one
        // shared-memory tree reduction (plus barriers) per ell iteration.
        // Same memory-access order, same Reduce64 cadence, identical canonical
        // mod-M31 output word.
        if (active) {
            uint64_t acc{0};
            uint32_t pending{0};
            for (uint32_t m = 0; m < n; ++m) {
                acc += static_cast<uint64_t>(matrix_a[row_offset + m]) *
                    matrix_b[static_cast<size_t>(m) * n + col];
                if (++pending == REDUCE_INTERVAL) {
                    acc = Reduce64(acc);
                    pending = 0;
                }
            }
            running_total = FieldMul(Reduce64(acc), compress_coeff);
        }
        partials[tid] = running_total;
        __syncthreads();

        ReducePartialsInPlace(partials, tid);

        if (tid == 0) {
            output[output_offset] = partials[0];
        }
        return;
    }

    for (uint32_t ell = 0; ell < blocks_per_axis; ++ell) {
        Element partial{0};
        if (active) {
            const uint32_t middle_base = ell * block_size;

            uint64_t acc{0};
            uint32_t pending{0};
            for (uint32_t k = 0; k < block_size; ++k) {
                acc += static_cast<uint64_t>(matrix_a[row_offset + (middle_base + k)]) *
                    matrix_b[static_cast<size_t>(middle_base + k) * n + col];
                if (++pending == REDUCE_INTERVAL) {
                    acc = Reduce64(acc);
                    pending = 0;
                }
            }

            partial = FieldMul(Reduce64(acc), compress_coeff);
        }

        partials[tid] = partial;
        __syncthreads();

        ReducePartialsInPlace(partials, tid);

        if (tid == 0) {
            running_total = FieldAdd(running_total, partials[0]);
            if constexpr (PrefixMode) {
                output[output_offset + ell] = running_total;
            }
        }
        __syncthreads();
    }

    if constexpr (!PrefixMode) {
        if (tid == 0) {
            output[output_offset] = running_total;
        }
    }
}

template <bool PrefixMode>
__global__ void ComputeCompressedWordsFusedPackedPointersKernel(
    const Element* __restrict__ matrix_a_batch,
    const Element* __restrict__ matrix_b_batch,
    const Element* const* __restrict__ packed_input_ptrs,
    uint32_t n,
    uint32_t block_size,
    uint32_t blocks_per_axis,
    uint32_t pair_count_per_request,
    uint32_t words_per_request,
    uint32_t matrix_elements,
    uint32_t compress_offset_words,
    Element* __restrict__ output)
{
    __shared__ Element partials[MAX_BLOCK_THREADS];

    const uint32_t pair_index = blockIdx.x;
    const uint32_t batch_index = pair_index / pair_count_per_request;
    const uint32_t local_pair_index = pair_index % pair_count_per_request;
    const uint32_t j = local_pair_index % blocks_per_axis;
    const uint32_t i = local_pair_index / blocks_per_axis;
    const uint32_t tid = threadIdx.x;
    const uint32_t active_threads = block_size * block_size;
    const Element* matrix_a = matrix_a_batch + static_cast<size_t>(batch_index) * matrix_elements;
    const Element* matrix_b = matrix_b_batch + static_cast<size_t>(batch_index) * matrix_elements;
    const Element* compress_vec = packed_input_ptrs[batch_index] + compress_offset_words;
    const uint32_t output_offset = batch_index * words_per_request +
        (PrefixMode ? local_pair_index * blocks_per_axis : local_pair_index);
    const bool active = tid < active_threads;
    const uint32_t x = active ? (tid / block_size) : 0;
    const uint32_t y = active ? (tid % block_size) : 0;
    const uint32_t row = i * block_size + x;
    const uint32_t col = j * block_size + y;
    const size_t row_offset = static_cast<size_t>(row) * n;
    const Element compress_coeff = active ? compress_vec[tid] : 0;

    Element running_total{0};
    if constexpr (!PrefixMode) {
        // PRODUCT_FINAL_BLOCKS emits ONE word per block pair: the compress-
        // weighted sum over the whole block product. Mod-field arithmetic is
        // distributive, so fold the full length-n dot product per thread in
        // registers and reduce across the block exactly once - instead of one
        // shared-memory tree reduction (plus barriers) per ell iteration.
        // Same memory-access order, same Reduce64 cadence, identical canonical
        // mod-M31 output word.
        if (active) {
            uint64_t acc{0};
            uint32_t pending{0};
            for (uint32_t m = 0; m < n; ++m) {
                acc += static_cast<uint64_t>(matrix_a[row_offset + m]) *
                    matrix_b[static_cast<size_t>(m) * n + col];
                if (++pending == REDUCE_INTERVAL) {
                    acc = Reduce64(acc);
                    pending = 0;
                }
            }
            running_total = FieldMul(Reduce64(acc), compress_coeff);
        }
        partials[tid] = running_total;
        __syncthreads();

        ReducePartialsInPlace(partials, tid);

        if (tid == 0) {
            output[output_offset] = partials[0];
        }
        return;
    }

    for (uint32_t ell = 0; ell < blocks_per_axis; ++ell) {
        Element partial{0};
        if (active) {
            const uint32_t middle_base = ell * block_size;

            uint64_t acc{0};
            uint32_t pending{0};
            for (uint32_t k = 0; k < block_size; ++k) {
                acc += static_cast<uint64_t>(matrix_a[row_offset + (middle_base + k)]) *
                    matrix_b[static_cast<size_t>(middle_base + k) * n + col];
                if (++pending == REDUCE_INTERVAL) {
                    acc = Reduce64(acc);
                    pending = 0;
                }
            }

            partial = FieldMul(Reduce64(acc), compress_coeff);
        }

        partials[tid] = partial;
        __syncthreads();

        ReducePartialsInPlace(partials, tid);

        if (tid == 0) {
            running_total = FieldAdd(running_total, partials[0]);
            if constexpr (PrefixMode) {
                output[output_offset + ell] = running_total;
            }
        }
        __syncthreads();
    }

    if constexpr (!PrefixMode) {
        if (tid == 0) {
            output[output_offset] = running_total;
        }
    }
}

// ---- Factored compression (PRODUCT_FINAL_BLOCKS only) ----
// word(i,j) = sum_{x,y} W[x*bs+y] * (A'B')[i*bs+x][j*bs+y]. The compress
// weights distribute over the block product (mod-field ring arithmetic is
// exact, so the reassociation is byte-identical):
//   D[j][x][m] = sum_y W[x*bs+y] * B'[m][j*bs+y]     (bs * n * bpa words, once)
//   word(i,j)  = sum_x sum_m A'[i*bs+x][m] * D[j][x][m]
// cutting per-request MACs from n^3 (full block product) to
// bs^2*n*bpa + pair_count*bs*n - ~10.6x fewer at n=512, b=16.

__global__ void BuildFactoredRhsKernel(const Element* __restrict__ matrix_b_batch,
                                       const Element* __restrict__ compress_batch,
                                       uint32_t n,
                                       uint32_t block_size,
                                       size_t total_rhs_elements,
                                       uint32_t rhs_elements,
                                       uint32_t matrix_elements,
                                       uint32_t compress_elements,
                                       Element* __restrict__ rhs_batch)
{
    const size_t gid = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (gid >= total_rhs_elements) {
        return;
    }
    const uint32_t batch_index = static_cast<uint32_t>(gid / rhs_elements);
    const uint32_t local_index = static_cast<uint32_t>(gid % rhs_elements);
    // Layout [j][x][m], m fastest - keeps the consumer's A' and D reads coalesced.
    const uint32_t m = local_index % n;
    const uint32_t jx = local_index / n;
    const uint32_t x = jx % block_size;
    const uint32_t j = jx / block_size;
    const Element* b_row = matrix_b_batch + static_cast<size_t>(batch_index) * matrix_elements +
        static_cast<size_t>(m) * n + j * block_size;
    const Element* w_row = compress_batch + static_cast<size_t>(batch_index) * compress_elements +
        x * block_size;
    uint64_t acc{0};
    uint32_t pending{0};
    for (uint32_t y = 0; y < block_size; ++y) {
        acc += static_cast<uint64_t>(w_row[y]) * b_row[y];
        if (++pending == REDUCE_INTERVAL) {
            acc = Reduce64(acc);
            pending = 0;
        }
    }
    rhs_batch[gid] = Reduce64(acc);
}

__global__ void BuildFactoredRhsPackedPointersKernel(const Element* __restrict__ matrix_b_batch,
                                                     const Element* const* __restrict__ packed_input_ptrs,
                                                     uint32_t compress_offset_words,
                                                     uint32_t n,
                                                     uint32_t block_size,
                                                     size_t total_rhs_elements,
                                                     uint32_t rhs_elements,
                                                     uint32_t matrix_elements,
                                                     Element* __restrict__ rhs_batch)
{
    const size_t gid = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (gid >= total_rhs_elements) {
        return;
    }
    const uint32_t batch_index = static_cast<uint32_t>(gid / rhs_elements);
    const uint32_t local_index = static_cast<uint32_t>(gid % rhs_elements);
    const uint32_t m = local_index % n;
    const uint32_t jx = local_index / n;
    const uint32_t x = jx % block_size;
    const uint32_t j = jx / block_size;
    const Element* b_row = matrix_b_batch + static_cast<size_t>(batch_index) * matrix_elements +
        static_cast<size_t>(m) * n + j * block_size;
    const Element* w_row = packed_input_ptrs[batch_index] + compress_offset_words + x * block_size;
    uint64_t acc{0};
    uint32_t pending{0};
    for (uint32_t y = 0; y < block_size; ++y) {
        acc += static_cast<uint64_t>(w_row[y]) * b_row[y];
        if (++pending == REDUCE_INTERVAL) {
            acc = Reduce64(acc);
            pending = 0;
        }
    }
    rhs_batch[gid] = Reduce64(acc);
}

__global__ void ComputeFactoredWordsKernel(const Element* __restrict__ matrix_a_batch,
                                           const Element* __restrict__ rhs_batch,
                                           uint32_t n,
                                           uint32_t block_size,
                                           uint32_t blocks_per_axis,
                                           uint32_t pair_count_per_request,
                                           uint32_t words_per_request,
                                           uint32_t matrix_elements,
                                           uint32_t rhs_elements,
                                           uint32_t total_tile_count,
                                           Element* __restrict__ output)
{
    // One warp per 2x2 tile of output words (i0..i0+1) x (j0..j0+1): the A rows
    // feed both j-words and the D rows feed both i-words, so the 2x2 shape
    // halves L2 traffic vs warp-per-word (4 MACs per 4 loads instead of 1 per 2).
    // Lanes split the middle dimension m (stride 32; n % 32 == 0 and
    // blocks_per_axis % 2 == 0 are guarded at dispatch), x loops serially, then
    // four warp shuffle reductions. No shared memory, no block barriers.
    const uint32_t lane = threadIdx.x & 31U;
    const uint32_t tile_index = blockIdx.x * (blockDim.x >> 5U) + (threadIdx.x >> 5U);
    if (tile_index >= total_tile_count) {
        return;
    }
    const uint32_t tiles_per_axis = blocks_per_axis >> 1U;
    const uint32_t tiles_per_request = tiles_per_axis * tiles_per_axis;
    const uint32_t batch_index = tile_index / tiles_per_request;
    const uint32_t local_tile_index = tile_index % tiles_per_request;
    const uint32_t j0 = (local_tile_index % tiles_per_axis) * 2U;
    const uint32_t i0 = (local_tile_index / tiles_per_axis) * 2U;
    const Element* matrix_a = matrix_a_batch + static_cast<size_t>(batch_index) * matrix_elements;
    const Element* rhs = rhs_batch + static_cast<size_t>(batch_index) * rhs_elements;
    uint64_t acc00{0};
    uint64_t acc01{0};
    uint64_t acc10{0};
    uint64_t acc11{0};
    uint32_t pending{0};
    for (uint32_t x = 0; x < block_size; ++x) {
        const Element* a_row0 = matrix_a + static_cast<size_t>(i0 * block_size + x) * n;
        const Element* a_row1 = a_row0 + static_cast<size_t>(block_size) * n;
        const Element* d_row0 = rhs + static_cast<size_t>(j0 * block_size + x) * n;
        const Element* d_row1 = d_row0 + static_cast<size_t>(block_size) * n;
        for (uint32_t m = lane; m < n; m += 32U) {
            const uint64_t a0 = a_row0[m];
            const uint64_t a1 = a_row1[m];
            const uint64_t d0 = d_row0[m];
            const uint64_t d1 = d_row1[m];
            acc00 += a0 * d0;
            acc01 += a0 * d1;
            acc10 += a1 * d0;
            acc11 += a1 * d1;
            if (++pending == REDUCE_INTERVAL) {
                acc00 = Reduce64(acc00);
                acc01 = Reduce64(acc01);
                acc10 = Reduce64(acc10);
                acc11 = Reduce64(acc11);
                pending = 0;
            }
        }
    }
    Element value00 = Reduce64(acc00);
    Element value01 = Reduce64(acc01);
    Element value10 = Reduce64(acc10);
    Element value11 = Reduce64(acc11);
    for (uint32_t offset = 16U; offset > 0U; offset >>= 1U) {
        value00 = FieldAdd(value00, __shfl_down_sync(0xffffffffU, value00, offset));
        value01 = FieldAdd(value01, __shfl_down_sync(0xffffffffU, value01, offset));
        value10 = FieldAdd(value10, __shfl_down_sync(0xffffffffU, value10, offset));
        value11 = FieldAdd(value11, __shfl_down_sync(0xffffffffU, value11, offset));
    }
    if (lane == 0) {
        const uint32_t base = batch_index * words_per_request;
        output[base + i0 * blocks_per_axis + j0] = value00;
        output[base + i0 * blocks_per_axis + j0 + 1U] = value01;
        output[base + (i0 + 1U) * blocks_per_axis + j0] = value10;
        output[base + (i0 + 1U) * blocks_per_axis + j0 + 1U] = value11;
    }
}

std::string CudaErrorString(cudaError_t error)
{
    return cudaGetErrorString(error);
}

uint32_t ResolveThreadCount(uint32_t block_size)
{
    uint32_t threads{1};
    const uint32_t required = std::min<uint32_t>(block_size * block_size, MAX_BLOCK_THREADS);
    while (threads < required) {
        threads <<= 1;
    }
    return std::min<uint32_t>(threads, MAX_BLOCK_THREADS);
}

void ResetWorkspaceForDevice(DigestWorkspace& workspace, int device_index)
{
    if (workspace.device_index == device_index) {
        return;
    }

    if (workspace.device_index >= 0) {
        cudaSetDevice(workspace.device_index);
    }
    workspace.ReleaseStream();
    workspace.ReleaseDeviceBuffers();
    workspace.device_index = device_index;
}

bool EnsureWorkspaceStream(DigestWorkspace& workspace, std::string& error)
{
    if (workspace.stream != nullptr) {
        return true;
    }

    const cudaError_t stream_error = cudaStreamCreateWithFlags(&workspace.stream, cudaStreamNonBlocking);
    if (stream_error != cudaSuccess) {
        error = "cudaStreamCreateWithFlags failed:" + CudaErrorString(stream_error);
        workspace.stream = nullptr;
        return false;
    }
    return true;
}

template <typename T>
bool EnsureDeviceBuffer(T*& buffer, size_t& capacity, size_t required, std::string& error, bool& allocated)
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

    const cudaError_t alloc_error = cudaMalloc(reinterpret_cast<void**>(&buffer), required * sizeof(T));
    if (alloc_error != cudaSuccess) {
        error = "cudaMalloc failed:" + CudaErrorString(alloc_error);
        return false;
    }

    allocated = true;
    capacity = required;
    return true;
}

bool EnsureCachedBaseMatrices(DigestWorkspace& workspace,
                              const CudaRuntimeProbe& runtime,
                              const Element* matrix_a,
                              const Element* matrix_b,
                              const uint256* matrix_a_cache_key,
                              const uint256* matrix_b_cache_key,
                              uint32_t matrix_elements,
                              std::string& error,
                              bool& allocated)
{
    if (IsBaseMatrixCacheHit(workspace, matrix_a_cache_key, matrix_b_cache_key, matrix_elements)) {
        return true;
    }

    if (!EnsureDeviceBuffer(workspace.device_base_a, workspace.base_a_capacity, matrix_elements, error, allocated) ||
        !EnsureDeviceBuffer(workspace.device_base_b, workspace.base_b_capacity, matrix_elements, error, allocated)) {
        return false;
    }

    cudaError_t copy_error = cudaSetDevice(runtime.device_index);
    if (copy_error == cudaSuccess) {
        copy_error = cudaMemcpyAsync(workspace.device_base_a,
                                     matrix_a,
                                     matrix_elements * sizeof(Element),
                                     cudaMemcpyHostToDevice,
                                     workspace.stream);
    }
    if (copy_error == cudaSuccess) {
        copy_error = cudaMemcpyAsync(workspace.device_base_b,
                                     matrix_b,
                                     matrix_elements * sizeof(Element),
                                     cudaMemcpyHostToDevice,
                                     workspace.stream);
    }
    if (copy_error != cudaSuccess) {
        error = "cudaMemcpy base_matrices failed:" + CudaErrorString(copy_error);
        return false;
    }

    if (matrix_a_cache_key != nullptr && matrix_b_cache_key != nullptr) {
        workspace.cached_matrix_a_key = *matrix_a_cache_key;
        workspace.cached_matrix_b_key = *matrix_b_cache_key;
        workspace.cached_matrix_keys_valid = true;
    } else {
        workspace.cached_matrix_a_key.SetNull();
        workspace.cached_matrix_b_key.SetNull();
        workspace.cached_matrix_keys_valid = false;
    }
    workspace.cached_matrix_elements = matrix_elements;
    return true;
}

bool ValidateBatchRequest(const MatMulCompressedWordsBatchRequest& request, std::string& error)
{
    if (request.batch_size == 0) {
        error = "CUDA digest batch request requires at least one entry";
        return false;
    }
    if (request.n == 0 || request.b == 0) {
        error = "matrix dimension and transcript block size must be non-zero";
        return false;
    }
    if ((request.n % request.b) != 0) {
        error = "matrix dimension must be divisible by transcript block size";
        return false;
    }
    if (request.matrix_a_perturbed == nullptr || request.matrix_b_perturbed == nullptr || request.compress_vec == nullptr) {
        error = "CUDA digest batch request requires perturbed matrices and compression vectors";
        return false;
    }
    if (request.b * request.b > MAX_BLOCK_THREADS) {
        error = "CUDA digest request block size exceeds supported thread budget";
        return false;
    }
    for (uint32_t i = 0; i < request.batch_size; ++i) {
        if (request.matrix_a_perturbed[i] == nullptr ||
            request.matrix_b_perturbed[i] == nullptr ||
            request.compress_vec[i] == nullptr) {
            error = "CUDA digest batch request contains null matrix or compression-vector pointers";
            return false;
        }
    }
    return true;
}

bool ValidateLowRankBatchRequest(const MatMulLowRankCompressedWordsBatchRequest& request, std::string& error)
{
    if (request.batch_size == 0) {
        error = "CUDA digest batch request requires at least one entry";
        return false;
    }
    if (request.n == 0 || request.b == 0 || request.r == 0) {
        error = "matrix dimension, transcript block size, and noise rank must be non-zero";
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
    if (request.b * request.b > MAX_BLOCK_THREADS) {
        error = "CUDA digest request block size exceeds supported thread budget";
        return false;
    }
    if (request.matrix_a == nullptr ||
        request.matrix_b == nullptr ||
        request.noise_e_l == nullptr ||
        request.noise_e_r == nullptr ||
        request.noise_f_l == nullptr ||
        request.noise_f_r == nullptr ||
        request.compress_vec == nullptr) {
        error = "CUDA digest batch request requires base matrices, noise factors, and compression vectors";
        return false;
    }
    for (uint32_t i = 0; i < request.batch_size; ++i) {
        if (request.noise_e_l[i] == nullptr ||
            request.noise_e_r[i] == nullptr ||
            request.noise_f_l[i] == nullptr ||
            request.noise_f_r[i] == nullptr ||
            request.compress_vec[i] == nullptr) {
            error = "CUDA digest batch request contains null noise or compression-vector pointers";
            return false;
        }
    }
    return true;
}

bool ValidateLowRankDeviceBatchRequest(const MatMulLowRankCompressedWordsDeviceBatchRequest& request, std::string& error)
{
    if (request.batch_size == 0) {
        error = "CUDA digest batch request requires at least one entry";
        return false;
    }
    if (request.n == 0 || request.b == 0 || request.r == 0) {
        error = "matrix dimension, transcript block size, and noise rank must be non-zero";
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
    if (request.b * request.b > MAX_BLOCK_THREADS) {
        error = "CUDA digest request block size exceeds supported thread budget";
        return false;
    }
    if (request.matrix_a == nullptr ||
        request.matrix_b == nullptr ||
        request.generated_inputs == nullptr) {
        error = "CUDA digest batch request requires base matrices and device-generated inputs";
        return false;
    }
    for (uint32_t i = 0; i < request.batch_size; ++i) {
        if (request.generated_inputs[i] == nullptr) {
            error = "CUDA digest batch request contains null device-generated input handles";
            return false;
        }
    }
    return true;
}

bool ValidateLowRankVariableBaseDeviceBatchRequest(const MatMulLowRankVariableBaseDeviceBatchRequest& request, std::string& error)
{
    if (request.batch_size == 0) {
        error = "CUDA variable-base digest batch request requires at least one entry";
        return false;
    }
    if (request.n == 0 || request.b == 0 || request.r == 0) {
        error = "matrix dimension, transcript block size, and noise rank must be non-zero";
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
    if (request.b * request.b > MAX_BLOCK_THREADS) {
        error = "CUDA digest request block size exceeds supported thread budget";
        return false;
    }
    if (request.matrix_a_seeds == nullptr ||
        request.matrix_b_seeds == nullptr ||
        request.generated_inputs == nullptr) {
        error = "CUDA variable-base digest batch request requires matrix seeds and device-generated inputs";
        return false;
    }
    for (uint32_t i = 0; i < request.batch_size; ++i) {
        if (request.generated_inputs[i] == nullptr) {
            error = "CUDA variable-base digest batch request contains null device-generated input handles";
            return false;
        }
    }
    return true;
}

bool FinalizeCompressedWordsBatch(const BufferPoolLease& lease,
                                  DigestWorkspace& workspace,
                                  uint32_t n,
                                  uint32_t b,
                                  uint32_t r,
                                  uint32_t batch_size,
                                  MatMulCompressedWordsMode mode,
                                  MatMulCompressedWordsBatchResult& result,
                                  DigestProfilingSample& sample,
                                  bool& allocated_buffers)
{
    const uint32_t blocks_per_axis = n / b;
    const uint32_t matrix_elements = n * n;
    const uint32_t compress_elements = b * b;
    const uint32_t pair_count_per_request = blocks_per_axis * blocks_per_axis;
    const uint32_t words_per_request = mode == MatMulCompressedWordsMode::TRANSCRIPT_PREFIXES
        ? pair_count_per_request * blocks_per_axis
        : pair_count_per_request;
    const size_t total_output_count = static_cast<size_t>(batch_size) * words_per_request;

    if (!EnsureDeviceBuffer(workspace.device_output,
                            workspace.output_capacity,
                            total_output_count,
                            result.error,
                            allocated_buffers)) {
        return false;
    }

    lease.RecordRequest(n, b, r, allocated_buffers);

    const uint32_t thread_count = ResolveThreadCount(b);
    const uint32_t total_pair_count = batch_size * pair_count_per_request;
    const auto finalize_start = SteadyClock::now();
    if (mode == MatMulCompressedWordsMode::TRANSCRIPT_PREFIXES) {
        ComputeCompressedWordsFusedKernel<true><<<total_pair_count, thread_count, 0, workspace.stream>>>(
            workspace.device_matrix_a,
            workspace.device_matrix_b,
            workspace.device_compress,
            n,
            b,
            blocks_per_axis,
            pair_count_per_request,
            words_per_request,
            matrix_elements,
            compress_elements,
            workspace.device_output);
    } else if (n % 32U == 0U && (blocks_per_axis & 1U) == 0U) {
        // Factored compression: build D once per request, then warp-per-word.
        // Byte-identical to the fused kernel (see kernel comment); ~10x fewer MACs.
        const uint32_t rhs_elements = b * n * blocks_per_axis;
        const size_t total_rhs_elements = static_cast<size_t>(batch_size) * rhs_elements;
        if (!EnsureDeviceBuffer(workspace.device_factored_rhs,
                                workspace.factored_rhs_capacity,
                                total_rhs_elements,
                                result.error,
                                allocated_buffers)) {
            return false;
        }
        const uint32_t rhs_blocks = static_cast<uint32_t>(
            (total_rhs_elements + WORKSPACE_THREADS - 1) / WORKSPACE_THREADS);
        BuildFactoredRhsKernel<<<rhs_blocks, WORKSPACE_THREADS, 0, workspace.stream>>>(
            workspace.device_matrix_b,
            workspace.device_compress,
            n,
            b,
            total_rhs_elements,
            rhs_elements,
            matrix_elements,
            compress_elements,
            workspace.device_factored_rhs);
        const uint32_t warps_per_block = WORKSPACE_THREADS / 32U;
        const uint32_t tiles_per_request = (blocks_per_axis >> 1U) * (blocks_per_axis >> 1U);
        const uint32_t total_tile_count = batch_size * tiles_per_request;
        const uint32_t word_blocks = (total_tile_count + warps_per_block - 1U) / warps_per_block;
        ComputeFactoredWordsKernel<<<word_blocks, WORKSPACE_THREADS, 0, workspace.stream>>>(
            workspace.device_matrix_a,
            workspace.device_factored_rhs,
            n,
            b,
            blocks_per_axis,
            pair_count_per_request,
            words_per_request,
            matrix_elements,
            rhs_elements,
            total_tile_count,
            workspace.device_output);
    } else {
        ComputeCompressedWordsFusedKernel<false><<<total_pair_count, thread_count, 0, workspace.stream>>>(
            workspace.device_matrix_a,
            workspace.device_matrix_b,
            workspace.device_compress,
            n,
            b,
            blocks_per_axis,
            pair_count_per_request,
            words_per_request,
            matrix_elements,
            compress_elements,
            workspace.device_output);
    }
    cudaError_t error = cudaGetLastError();
    sample.launch_finalize_us = DurationMicros(finalize_start, SteadyClock::now());
    if (error != cudaSuccess) {
        result.error = "CUDA finalize kernel failed:" + CudaErrorString(error);
        return false;
    }

    std::string staging_warning;
    if (!workspace.host_output.Ensure(total_output_count, staging_warning)) {
        result.error = staging_warning;
        return false;
    }
    sample.used_pinned_host_staging = sample.used_pinned_host_staging && workspace.host_output.pinned != nullptr;

    result.words_per_request = words_per_request;
    const auto d2h_start = SteadyClock::now();
    error = cudaMemcpyAsync(workspace.host_output.data(),
                            workspace.device_output,
                            total_output_count * sizeof(Element),
                            cudaMemcpyDeviceToHost,
                            workspace.stream);
    sample.submit_d2h_us = DurationMicros(d2h_start, SteadyClock::now());
    const auto sync_start = SteadyClock::now();
    if (error == cudaSuccess) {
        error = cudaStreamSynchronize(workspace.stream);
    }
    sample.stream_sync_us = DurationMicros(sync_start, SteadyClock::now());
    if (error != cudaSuccess) {
        result.words_per_request = 0;
        result.error = "CUDA stream completion failed:" + CudaErrorString(error);
        return false;
    }

    result.words.assign(workspace.host_output.data(), workspace.host_output.data() + total_output_count);
    result.success = true;
    return true;
}

bool FinalizeCompressedWordsPackedPointerBatch(const BufferPoolLease& lease,
                                               DigestWorkspace& workspace,
                                               uint32_t n,
                                               uint32_t b,
                                               uint32_t r,
                                               uint32_t batch_size,
                                               uint32_t compress_offset_words,
                                               MatMulCompressedWordsMode mode,
                                               MatMulCompressedWordsBatchResult& result,
                                               DigestProfilingSample& sample,
                                               bool& allocated_buffers)
{
    const uint32_t blocks_per_axis = n / b;
    const uint32_t matrix_elements = n * n;
    const uint32_t pair_count_per_request = blocks_per_axis * blocks_per_axis;
    const uint32_t words_per_request = mode == MatMulCompressedWordsMode::TRANSCRIPT_PREFIXES
        ? pair_count_per_request * blocks_per_axis
        : pair_count_per_request;
    const size_t total_output_count = static_cast<size_t>(batch_size) * words_per_request;

    if (!EnsureDeviceBuffer(workspace.device_output,
                            workspace.output_capacity,
                            total_output_count,
                            result.error,
                            allocated_buffers)) {
        return false;
    }

    lease.RecordRequest(n, b, r, allocated_buffers);

    const uint32_t thread_count = ResolveThreadCount(b);
    const uint32_t total_pair_count = batch_size * pair_count_per_request;
    const auto finalize_start = SteadyClock::now();
    if (mode == MatMulCompressedWordsMode::TRANSCRIPT_PREFIXES) {
        ComputeCompressedWordsFusedPackedPointersKernel<true><<<total_pair_count, thread_count, 0, workspace.stream>>>(
            workspace.device_matrix_a,
            workspace.device_matrix_b,
            workspace.device_prepared_input_ptrs,
            n,
            b,
            blocks_per_axis,
            pair_count_per_request,
            words_per_request,
            matrix_elements,
            compress_offset_words,
            workspace.device_output);
    } else if (n % 32U == 0U && (blocks_per_axis & 1U) == 0U) {
        // Factored compression (see BuildFactoredRhsKernel): byte-identical
        // to the fused kernel with ~10x fewer MACs.
        const uint32_t rhs_elements = b * n * blocks_per_axis;
        const size_t total_rhs_elements = static_cast<size_t>(batch_size) * rhs_elements;
        if (!EnsureDeviceBuffer(workspace.device_factored_rhs,
                                workspace.factored_rhs_capacity,
                                total_rhs_elements,
                                result.error,
                                allocated_buffers)) {
            return false;
        }
        const uint32_t rhs_blocks = static_cast<uint32_t>(
            (total_rhs_elements + WORKSPACE_THREADS - 1) / WORKSPACE_THREADS);
        BuildFactoredRhsPackedPointersKernel<<<rhs_blocks, WORKSPACE_THREADS, 0, workspace.stream>>>(
            workspace.device_matrix_b,
            workspace.device_prepared_input_ptrs,
            compress_offset_words,
            n,
            b,
            total_rhs_elements,
            rhs_elements,
            matrix_elements,
            workspace.device_factored_rhs);
        const uint32_t warps_per_block = WORKSPACE_THREADS / 32U;
        const uint32_t tiles_per_request = (blocks_per_axis >> 1U) * (blocks_per_axis >> 1U);
        const uint32_t total_tile_count = batch_size * tiles_per_request;
        const uint32_t word_blocks = (total_tile_count + warps_per_block - 1U) / warps_per_block;
        ComputeFactoredWordsKernel<<<word_blocks, WORKSPACE_THREADS, 0, workspace.stream>>>(
            workspace.device_matrix_a,
            workspace.device_factored_rhs,
            n,
            b,
            blocks_per_axis,
            pair_count_per_request,
            words_per_request,
            matrix_elements,
            rhs_elements,
            total_tile_count,
            workspace.device_output);
    } else {
        ComputeCompressedWordsFusedPackedPointersKernel<false><<<total_pair_count, thread_count, 0, workspace.stream>>>(
            workspace.device_matrix_a,
            workspace.device_matrix_b,
            workspace.device_prepared_input_ptrs,
            n,
            b,
            blocks_per_axis,
            pair_count_per_request,
            words_per_request,
            matrix_elements,
            compress_offset_words,
            workspace.device_output);
    }
    cudaError_t error = cudaGetLastError();
    sample.launch_finalize_us = DurationMicros(finalize_start, SteadyClock::now());
    if (error != cudaSuccess) {
        result.error = "CUDA finalize kernel failed:" + CudaErrorString(error);
        return false;
    }

    std::string staging_warning;
    if (!workspace.host_output.Ensure(total_output_count, staging_warning)) {
        result.error = staging_warning;
        return false;
    }
    sample.used_pinned_host_staging = sample.used_pinned_host_staging && workspace.host_output.pinned != nullptr;

    result.words_per_request = words_per_request;
    const auto d2h_start = SteadyClock::now();
    error = cudaMemcpyAsync(workspace.host_output.data(),
                            workspace.device_output,
                            total_output_count * sizeof(Element),
                            cudaMemcpyDeviceToHost,
                            workspace.stream);
    sample.submit_d2h_us = DurationMicros(d2h_start, SteadyClock::now());
    const auto sync_start = SteadyClock::now();
    if (error == cudaSuccess) {
        error = cudaStreamSynchronize(workspace.stream);
    }
    sample.stream_sync_us = DurationMicros(sync_start, SteadyClock::now());
    if (error != cudaSuccess) {
        result.words_per_request = 0;
        result.error = "CUDA stream completion failed:" + CudaErrorString(error);
        return false;
    }

    result.words.assign(workspace.host_output.data(), workspace.host_output.data() + total_output_count);
    result.success = true;
    return true;
}

} // namespace

MatMulAccelerationProbe ProbeMatMulDigestAcceleration()
{
    const auto runtime = ProbeCudaRuntime();
    return MatMulAccelerationProbe{
        .available = runtime.available,
        .reason = runtime.reason,
        .device_name = runtime.device_name,
        .compute_capability_major = runtime.compute_capability_major,
        .compute_capability_minor = runtime.compute_capability_minor,
        .global_memory_bytes = runtime.global_memory_bytes,
        .multiprocessor_count = runtime.multiprocessor_count,
        .driver_api_version = runtime.driver_api_version,
        .runtime_version = runtime.runtime_version,
    };
}

MatMulBufferPoolStats ProbeMatMulBufferPool()
{
    MatMulBufferPoolStats stats;

    const auto topology = ProbeCudaTopology();
    if (!topology.available) {
        stats.available = false;
        stats.initialized = false;
        stats.reason = topology.reason;
        return stats;
    }

    stats.available = true;
    for (const auto& device : topology.selected_devices) {
        auto& context = GetPoolContext(device.device_index);
        std::lock_guard<std::mutex> lock(context.mutex);
        stats.initialized = stats.initialized || context.initialized;
        stats.allocation_events += context.allocation_events;
        stats.reuse_events += context.reuse_events;
        stats.wait_events += context.wait_events;
        stats.completed_submissions += context.completed_submissions;
        stats.slot_count += static_cast<uint32_t>(context.slots.size());
        stats.active_slots += context.active_slots;
        stats.high_water_slots += context.high_water_slots;
        stats.inflight_submissions += context.inflight_submissions;
        stats.peak_inflight_submissions += context.peak_inflight_submissions;
        if (context.initialized) {
            stats.n = context.last_n;
            stats.b = context.last_b;
            stats.r = context.last_r;
        }
    }
    stats.reason = stats.initialized ? "buffer_pool_slots_ready" : "buffer_pool_uninitialized";
    if (stats.reason.empty()) {
        stats.reason = stats.initialized ? "buffer_pool_slots_ready" : "buffer_pool_uninitialized";
    }
    return stats;
}

MatMulDispatchConfig ProbeMatMulDispatchConfig()
{
    MatMulDispatchConfig config;

    const auto runtime = ProbeCudaRuntime();
    if (!runtime.available) {
        config.reason = runtime.reason;
        return config;
    }

    config.available = true;
    config.build_perturbed_threads = WORKSPACE_THREADS;
    config.finalize_max_threads = MAX_BLOCK_THREADS;
    config.finalize_threads_b4 = ResolveThreadCount(4);
    config.finalize_threads_b8 = ResolveThreadCount(8);
    config.finalize_threads_b16 = ResolveThreadCount(16);
    config.max_supported_block_size = 16;
    config.nonblocking_streams = true;
    config.reason = "ready";
    return config;
}

MatMulKernelProfile ProbeMatMulKernelProfile()
{
    MatMulKernelProfile profile;

    const auto runtime = ProbeCudaRuntime();
    if (!runtime.available) {
        profile.reason = runtime.reason;
        return profile;
    }

    const char* device_prepared_env = std::getenv("BTX_MATMUL_CUDA_DEVICE_PREPARED_INPUTS");
    profile.available = true;
    profile.low_rank_perturbation_kernel = true;
    profile.fused_compressed_words_finalize = true;
    profile.pinned_host_staging = true;
    profile.base_matrix_cache = true;
    profile.shared_buffer_pool = true;
    profile.nonblocking_streams = true;
    profile.device_prepared_inputs_supported = true;
    profile.device_prepared_inputs_default = false;
    profile.device_prepared_inputs_enabled = device_prepared_env != nullptr &&
        device_prepared_env[0] != '\0' &&
        device_prepared_env[0] != '0';
    profile.execution_model = "nonblocking_stream_per_device_pool_slot";
    profile.staging_strategy = "pinned_host_with_pageable_fallback";
    profile.device_prepared_inputs_policy = "auto_product_digest_shape_plus_env";
    profile.reason = "ready";
    return profile;
}

MatMulProfilingStats ProbeMatMulProfilingStats()
{
    MatMulProfilingStats stats;

    const auto runtime = ProbeCudaRuntime();
    if (!runtime.available) {
        stats.reason = runtime.reason;
        return stats;
    }

    auto& context = GetProfilingContext();
    std::lock_guard<std::mutex> lock(context.mutex);
    stats.available = true;
    stats.samples = context.samples;
    stats.last_n = context.last_n;
    stats.last_b = context.last_b;
    stats.last_r = context.last_r;
    stats.last_batch_size = context.last_batch_size;
    stats.last_host_stage_us = context.last_host_stage_us;
    stats.last_submit_h2d_us = context.last_submit_h2d_us;
    stats.last_submit_d2d_us = context.last_submit_d2d_us;
    stats.last_stream_wait_event_us = context.last_stream_wait_event_us;
    stats.last_launch_build_perturbed_us = context.last_launch_build_perturbed_us;
    stats.last_launch_finalize_us = context.last_launch_finalize_us;
    stats.last_submit_d2h_us = context.last_submit_d2h_us;
    stats.last_stream_sync_us = context.last_stream_sync_us;
    stats.last_total_wall_ms = context.last_total_wall_ms;
    stats.last_used_low_rank_path = context.last_used_low_rank_path;
    stats.last_used_device_prepared_inputs = context.last_used_device_prepared_inputs;
    stats.last_used_pinned_host_staging = context.last_used_pinned_host_staging;
    stats.last_base_matrix_cache_hit = context.last_base_matrix_cache_hit;
    stats.last_mode = context.last_mode;
    stats.reason = context.reason;
    return stats;
}

MatMulCompressedWordsResult ComputeCompressedWords(const MatMulCompressedWordsRequest& request,
                                                  MatMulCompressedWordsMode mode)
{
    const Element* matrix_a_ptrs[] = {request.matrix_a_perturbed};
    const Element* matrix_b_ptrs[] = {request.matrix_b_perturbed};
    const Element* compress_ptrs[] = {request.compress_vec};
    auto batch_result = ComputeCompressedWordsBatch(
        {
            .n = request.n,
            .b = request.b,
            .batch_size = 1,
            .matrix_a_perturbed = matrix_a_ptrs,
            .matrix_b_perturbed = matrix_b_ptrs,
            .compress_vec = compress_ptrs,
        },
        mode);

    MatMulCompressedWordsResult result;
    result.available = batch_result.available;
    result.success = batch_result.success;
    result.words = std::move(batch_result.words);
    result.error = std::move(batch_result.error);
    return result;
}

MatMulCompressedWordsBatchResult ComputeCompressedWordsBatch(const MatMulCompressedWordsBatchRequest& request,
                                                            MatMulCompressedWordsMode mode)
{
    MatMulCompressedWordsBatchResult result;
    DigestProfilingSample sample;
    const auto runtime = ProbeCudaRuntime();
    result.available = runtime.available;
    if (!runtime.available) {
        result.error = runtime.reason;
        return result;
    }

    if (!ValidateBatchRequest(request, result.error)) {
        return result;
    }

    auto lease = AcquireBufferPoolSlot(runtime.device_index, result.error);
    if (!lease.has_value()) {
        return result;
    }

    auto& workspace = lease->workspace();
    ResetWorkspaceForDevice(workspace, runtime.device_index);

    cudaError_t error = cudaSetDevice(runtime.device_index);
    if (error != cudaSuccess) {
        result.error = "cudaSetDevice failed:" + CudaErrorString(error);
        return result;
    }
    if (!EnsureWorkspaceStream(workspace, result.error)) {
        return result;
    }

    sample.n = request.n;
    sample.b = request.b;
    sample.batch_size = request.batch_size;
    sample.mode = ModeToString(mode);
    const uint32_t matrix_elements = request.n * request.n;
    const uint32_t compress_elements = request.b * request.b;
    const size_t total_matrix_elements = static_cast<size_t>(request.batch_size) * matrix_elements;
    const size_t total_compress_elements = static_cast<size_t>(request.batch_size) * compress_elements;
    bool allocated_buffers{false};

    if (!EnsureDeviceBuffer(workspace.device_matrix_a, workspace.matrix_a_capacity, total_matrix_elements, result.error, allocated_buffers) ||
        !EnsureDeviceBuffer(workspace.device_matrix_b, workspace.matrix_b_capacity, total_matrix_elements, result.error, allocated_buffers) ||
        !EnsureDeviceBuffer(workspace.device_compress, workspace.compress_capacity, total_compress_elements, result.error, allocated_buffers)) {
        return result;
    }

    std::string staging_warning;
    if (!workspace.host_matrix_a.Ensure(total_matrix_elements, staging_warning) ||
        !workspace.host_matrix_b.Ensure(total_matrix_elements, staging_warning) ||
        !workspace.host_compress.Ensure(total_compress_elements, staging_warning)) {
        result.error = staging_warning;
        return result;
    }
    sample.used_pinned_host_staging = workspace.host_matrix_a.pinned != nullptr &&
        workspace.host_matrix_b.pinned != nullptr &&
        workspace.host_compress.pinned != nullptr;
    const auto total_start = SteadyClock::now();
    const auto host_stage_start = SteadyClock::now();
    for (uint32_t i = 0; i < request.batch_size; ++i) {
        std::memcpy(workspace.host_matrix_a.data() + static_cast<size_t>(i) * matrix_elements,
                    request.matrix_a_perturbed[i],
                    matrix_elements * sizeof(Element));
        std::memcpy(workspace.host_matrix_b.data() + static_cast<size_t>(i) * matrix_elements,
                    request.matrix_b_perturbed[i],
                    matrix_elements * sizeof(Element));
        std::memcpy(workspace.host_compress.data() + static_cast<size_t>(i) * compress_elements,
                    request.compress_vec[i],
                    compress_elements * sizeof(Element));
    }
    sample.host_stage_us = DurationMicros(host_stage_start, SteadyClock::now());

    const auto h2d_start = SteadyClock::now();
    error = cudaMemcpyAsync(workspace.device_matrix_a,
                            workspace.host_matrix_a.data(),
                            total_matrix_elements * sizeof(Element),
                            cudaMemcpyHostToDevice,
                            workspace.stream);
    if (error == cudaSuccess) {
        error = cudaMemcpyAsync(workspace.device_matrix_b,
                                workspace.host_matrix_b.data(),
                                total_matrix_elements * sizeof(Element),
                                cudaMemcpyHostToDevice,
                                workspace.stream);
    }
    if (error == cudaSuccess) {
        error = cudaMemcpyAsync(workspace.device_compress,
                                workspace.host_compress.data(),
                                total_compress_elements * sizeof(Element),
                                cudaMemcpyHostToDevice,
                                workspace.stream);
    }
    sample.submit_h2d_us = DurationMicros(h2d_start, SteadyClock::now());
    if (error != cudaSuccess) {
        result.error = "cudaMemcpy host_to_device failed:" + CudaErrorString(error);
        return result;
    }

    if (!FinalizeCompressedWordsBatch(
            *lease,
            workspace,
            request.n,
            request.b,
            /*r=*/0,
            request.batch_size,
            mode,
            result,
            sample,
            allocated_buffers)) {
        return result;
    }

    sample.total_wall_ms = DurationMillis(total_start, SteadyClock::now());
    RecordProfilingSample(sample);
    return result;
}

MatMulCompressedWordsBatchResult ComputeCompressedWordsLowRankBatchOnDevice(
    const MatMulLowRankCompressedWordsBatchRequest& request,
    MatMulCompressedWordsMode mode,
    int device_index)
{
    MatMulCompressedWordsBatchResult result;
    DigestProfilingSample sample;
    const auto runtime_probe = ResolveCudaRuntimeForSelectedDevice(device_index, result.error);
    result.available = runtime_probe.has_value();
    if (!runtime_probe.has_value()) {
        return result;
    }
    const auto runtime = *runtime_probe;

    if (!ValidateLowRankBatchRequest(request, result.error)) {
        return result;
    }

    auto lease = AcquireBufferPoolSlot(runtime.device_index, result.error);
    if (!lease.has_value()) {
        return result;
    }

    auto& workspace = lease->workspace();
    ResetWorkspaceForDevice(workspace, runtime.device_index);

    cudaError_t error = cudaSetDevice(runtime.device_index);
    if (error != cudaSuccess) {
        result.error = "cudaSetDevice failed:" + CudaErrorString(error);
        return result;
    }
    if (!EnsureWorkspaceStream(workspace, result.error)) {
        return result;
    }

    sample.n = request.n;
    sample.b = request.b;
    sample.r = request.r;
    sample.batch_size = request.batch_size;
    sample.mode = ModeToString(mode);
    sample.used_low_rank_path = true;
    const uint32_t matrix_elements = request.n * request.n;
    const uint32_t noise_left_elements = request.n * request.r;
    const uint32_t noise_right_elements = request.r * request.n;
    const uint32_t compress_elements = request.b * request.b;
    const size_t total_matrix_elements = static_cast<size_t>(request.batch_size) * matrix_elements;
    const size_t total_noise_left_elements = static_cast<size_t>(request.batch_size) * noise_left_elements;
    const size_t total_noise_right_elements = static_cast<size_t>(request.batch_size) * noise_right_elements;
    const size_t total_compress_elements = static_cast<size_t>(request.batch_size) * compress_elements;
    bool allocated_buffers{false};
    sample.base_matrix_cache_hit = IsBaseMatrixCacheHit(
        workspace,
        request.matrix_a_cache_key,
        request.matrix_b_cache_key,
        matrix_elements);

    if (!EnsureCachedBaseMatrices(
            workspace,
            runtime,
            request.matrix_a,
            request.matrix_b,
            request.matrix_a_cache_key,
            request.matrix_b_cache_key,
            matrix_elements,
            result.error,
            allocated_buffers)) {
        return result;
    }
    if (!EnsureDeviceBuffer(workspace.device_noise_e_l, workspace.noise_e_l_capacity, total_noise_left_elements, result.error, allocated_buffers) ||
        !EnsureDeviceBuffer(workspace.device_noise_e_r, workspace.noise_e_r_capacity, total_noise_right_elements, result.error, allocated_buffers) ||
        !EnsureDeviceBuffer(workspace.device_noise_f_l, workspace.noise_f_l_capacity, total_noise_left_elements, result.error, allocated_buffers) ||
        !EnsureDeviceBuffer(workspace.device_noise_f_r, workspace.noise_f_r_capacity, total_noise_right_elements, result.error, allocated_buffers) ||
        !EnsureDeviceBuffer(workspace.device_matrix_a, workspace.matrix_a_capacity, total_matrix_elements, result.error, allocated_buffers) ||
        !EnsureDeviceBuffer(workspace.device_matrix_b, workspace.matrix_b_capacity, total_matrix_elements, result.error, allocated_buffers) ||
        !EnsureDeviceBuffer(workspace.device_compress, workspace.compress_capacity, total_compress_elements, result.error, allocated_buffers)) {
        return result;
    }

    std::string staging_warning;
    if (!workspace.host_noise_e_l.Ensure(total_noise_left_elements, staging_warning) ||
        !workspace.host_noise_e_r.Ensure(total_noise_right_elements, staging_warning) ||
        !workspace.host_noise_f_l.Ensure(total_noise_left_elements, staging_warning) ||
        !workspace.host_noise_f_r.Ensure(total_noise_right_elements, staging_warning) ||
        !workspace.host_compress.Ensure(total_compress_elements, staging_warning)) {
        result.error = staging_warning;
        return result;
    }
    sample.used_pinned_host_staging = workspace.host_noise_e_l.pinned != nullptr &&
        workspace.host_noise_e_r.pinned != nullptr &&
        workspace.host_noise_f_l.pinned != nullptr &&
        workspace.host_noise_f_r.pinned != nullptr &&
        workspace.host_compress.pinned != nullptr;
    const auto total_start = SteadyClock::now();
    const auto host_stage_start = SteadyClock::now();
    for (uint32_t i = 0; i < request.batch_size; ++i) {
        std::memcpy(workspace.host_noise_e_l.data() + static_cast<size_t>(i) * noise_left_elements,
                    request.noise_e_l[i],
                    noise_left_elements * sizeof(Element));
        std::memcpy(workspace.host_noise_e_r.data() + static_cast<size_t>(i) * noise_right_elements,
                    request.noise_e_r[i],
                    noise_right_elements * sizeof(Element));
        std::memcpy(workspace.host_noise_f_l.data() + static_cast<size_t>(i) * noise_left_elements,
                    request.noise_f_l[i],
                    noise_left_elements * sizeof(Element));
        std::memcpy(workspace.host_noise_f_r.data() + static_cast<size_t>(i) * noise_right_elements,
                    request.noise_f_r[i],
                    noise_right_elements * sizeof(Element));
        std::memcpy(workspace.host_compress.data() + static_cast<size_t>(i) * compress_elements,
                    request.compress_vec[i],
                    compress_elements * sizeof(Element));
    }
    sample.host_stage_us = DurationMicros(host_stage_start, SteadyClock::now());

    const auto h2d_start = SteadyClock::now();
    error = cudaMemcpyAsync(workspace.device_noise_e_l,
                            workspace.host_noise_e_l.data(),
                            total_noise_left_elements * sizeof(Element),
                            cudaMemcpyHostToDevice,
                            workspace.stream);
    if (error == cudaSuccess) {
        error = cudaMemcpyAsync(workspace.device_noise_e_r,
                                workspace.host_noise_e_r.data(),
                                total_noise_right_elements * sizeof(Element),
                                cudaMemcpyHostToDevice,
                                workspace.stream);
    }
    if (error == cudaSuccess) {
        error = cudaMemcpyAsync(workspace.device_noise_f_l,
                                workspace.host_noise_f_l.data(),
                                total_noise_left_elements * sizeof(Element),
                                cudaMemcpyHostToDevice,
                                workspace.stream);
    }
    if (error == cudaSuccess) {
        error = cudaMemcpyAsync(workspace.device_noise_f_r,
                                workspace.host_noise_f_r.data(),
                                total_noise_right_elements * sizeof(Element),
                                cudaMemcpyHostToDevice,
                                workspace.stream);
    }
    if (error == cudaSuccess) {
        error = cudaMemcpyAsync(workspace.device_compress,
                                workspace.host_compress.data(),
                                total_compress_elements * sizeof(Element),
                                cudaMemcpyHostToDevice,
                                workspace.stream);
    }
    sample.submit_h2d_us = DurationMicros(h2d_start, SteadyClock::now());
    if (error != cudaSuccess) {
        result.error = "cudaMemcpy host_to_device failed:" + CudaErrorString(error);
        return result;
    }

    const uint32_t build_blocks = static_cast<uint32_t>((total_matrix_elements + WORKSPACE_THREADS - 1) / WORKSPACE_THREADS);
    const auto build_start = SteadyClock::now();
    BuildPerturbedMatrixKernel<<<build_blocks, WORKSPACE_THREADS, 0, workspace.stream>>>(
        workspace.device_base_a,
        workspace.device_noise_e_l,
        workspace.device_noise_e_r,
        request.n,
        request.r,
        total_matrix_elements,
        matrix_elements,
        noise_left_elements,
        noise_right_elements,
        workspace.device_matrix_a);
    error = cudaGetLastError();
    if (error == cudaSuccess) {
        BuildPerturbedMatrixKernel<<<build_blocks, WORKSPACE_THREADS, 0, workspace.stream>>>(
            workspace.device_base_b,
            workspace.device_noise_f_l,
            workspace.device_noise_f_r,
            request.n,
            request.r,
            total_matrix_elements,
            matrix_elements,
            noise_left_elements,
            noise_right_elements,
            workspace.device_matrix_b);
        error = cudaGetLastError();
    }
    sample.launch_build_perturbed_us = DurationMicros(build_start, SteadyClock::now());
    if (error != cudaSuccess) {
        result.error = "CUDA perturbed-matrix kernel failed:" + CudaErrorString(error);
        return result;
    }

    if (!FinalizeCompressedWordsBatch(
            *lease,
            workspace,
            request.n,
            request.b,
            request.r,
            request.batch_size,
            mode,
            result,
            sample,
            allocated_buffers)) {
        return result;
    }

    sample.total_wall_ms = DurationMillis(total_start, SteadyClock::now());
    RecordProfilingSample(sample);
    return result;
}

MatMulCompressedWordsBatchResult ComputeCompressedWordsLowRankBatch(
    const MatMulLowRankCompressedWordsBatchRequest& request,
    MatMulCompressedWordsMode mode)
{
    return ComputeCompressedWordsLowRankBatchMultiDevice(request, mode);
}

MatMulCompressedWordsBatchResult ComputeCompressedWordsLowRankBatchMultiDevice(
    const MatMulLowRankCompressedWordsBatchRequest& request,
    MatMulCompressedWordsMode mode)
{
    MatMulCompressedWordsBatchResult result;

    const auto topology = ProbeCudaTopology();
    result.available = topology.available;
    if (!topology.available) {
        result.error = topology.reason;
        return result;
    }

    if (!ValidateLowRankBatchRequest(request, result.error)) {
        return result;
    }

    const auto shards = PlanCudaBatchShards(topology.selected_devices, request.batch_size);
    if (shards.empty()) {
        result.error = "no_cuda_batch_shards_available";
        return result;
    }
    if (shards.size() == 1) {
        return ComputeCompressedWordsLowRankBatchOnDevice(request, mode, shards.front().device_index);
    }

    struct ShardResult {
        CudaBatchShard shard;
        MatMulCompressedWordsBatchResult result;
    };

    std::vector<std::future<ShardResult>> futures;
    futures.reserve(shards.size());
    for (const auto& shard : shards) {
        futures.push_back(std::async(std::launch::async, [request, mode, shard]() {
            const MatMulLowRankCompressedWordsBatchRequest shard_request{
                .n = request.n,
                .b = request.b,
                .r = request.r,
                .batch_size = static_cast<uint32_t>(shard.count),
                .matrix_a = request.matrix_a,
                .matrix_b = request.matrix_b,
                .matrix_a_cache_key = request.matrix_a_cache_key,
                .matrix_b_cache_key = request.matrix_b_cache_key,
                .noise_e_l = request.noise_e_l + shard.start_index,
                .noise_e_r = request.noise_e_r + shard.start_index,
                .noise_f_l = request.noise_f_l + shard.start_index,
                .noise_f_r = request.noise_f_r + shard.start_index,
                .compress_vec = request.compress_vec + shard.start_index,
            };
            return ShardResult{
                .shard = shard,
                .result = ComputeCompressedWordsLowRankBatchOnDevice(shard_request, mode, shard.device_index),
            };
        }));
    }

    std::vector<ShardResult> shard_results;
    shard_results.reserve(futures.size());
    try {
        for (auto& future : futures) {
            shard_results.push_back(future.get());
        }
    } catch (const std::exception& e) {
        result.error = std::string{"cuda_multi_device_batch_exception:"} + e.what();
        return result;
    }

    for (const auto& shard_result : shard_results) {
        if (!shard_result.result.success) {
            result.available = shard_result.result.available;
            result.error = "cuda_device_" + std::to_string(shard_result.shard.device_index) + "_batch_failed:" +
                (shard_result.result.error.empty() ? "unknown_error" : shard_result.result.error);
            return result;
        }
        if (result.words_per_request == 0) {
            result.words_per_request = shard_result.result.words_per_request;
        } else if (result.words_per_request != shard_result.result.words_per_request) {
            result.error = "cuda_multi_device_batch_words_per_request_mismatch";
            return result;
        }
    }

    if (result.words_per_request == 0) {
        result.error = "cuda_multi_device_batch_empty_result";
        return result;
    }

    result.words.assign(static_cast<size_t>(request.batch_size) * result.words_per_request, Element{0});
    for (const auto& shard_result : shard_results) {
        const size_t expected_words = shard_result.shard.count * result.words_per_request;
        if (shard_result.result.words.size() != expected_words) {
            result.success = false;
            result.error = "cuda_multi_device_batch_result_size_mismatch";
            result.words.clear();
            result.words_per_request = 0;
            return result;
        }
        std::copy(
            shard_result.result.words.begin(),
            shard_result.result.words.end(),
            result.words.begin() + static_cast<size_t>(shard_result.shard.start_index) * result.words_per_request);
    }

    result.success = true;
    return result;
}

MatMulCompressedWordsBatchResult ComputeCompressedWordsLowRankDeviceBatchOnDevice(
    const MatMulLowRankCompressedWordsDeviceBatchRequest& request,
    MatMulCompressedWordsMode mode,
    int device_index)
{
    MatMulCompressedWordsBatchResult result;
    DigestProfilingSample sample;
    const auto runtime_probe = ResolveCudaRuntimeForSelectedDevice(device_index, result.error);
    result.available = runtime_probe.has_value();
    if (!runtime_probe.has_value()) {
        return result;
    }
    const auto runtime = *runtime_probe;

    if (!ValidateLowRankDeviceBatchRequest(request, result.error)) {
        return result;
    }

    auto lease = AcquireBufferPoolSlot(runtime.device_index, result.error);
    if (!lease.has_value()) {
        return result;
    }

    auto& workspace = lease->workspace();
    ResetWorkspaceForDevice(workspace, runtime.device_index);

    cudaError_t error = cudaSetDevice(runtime.device_index);
    if (error != cudaSuccess) {
        result.error = "cudaSetDevice failed:" + CudaErrorString(error);
        return result;
    }
    if (!EnsureWorkspaceStream(workspace, result.error)) {
        return result;
    }

    sample.n = request.n;
    sample.b = request.b;
    sample.r = request.r;
    sample.batch_size = request.batch_size;
    sample.mode = ModeToString(mode);
    sample.used_low_rank_path = true;
    sample.used_device_prepared_inputs = true;
    const uint32_t matrix_elements = request.n * request.n;
    const uint32_t noise_left_elements = request.n * request.r;
    const uint32_t noise_right_elements = request.r * request.n;
    const uint32_t compress_elements = request.b * request.b;
    const size_t total_matrix_elements = static_cast<size_t>(request.batch_size) * matrix_elements;
    const uint32_t noise_e_l_offset_words = 0;
    const uint32_t noise_e_r_offset_words = noise_e_l_offset_words + noise_left_elements;
    const uint32_t noise_f_l_offset_words = noise_e_r_offset_words + noise_right_elements;
    const uint32_t noise_f_r_offset_words = noise_f_l_offset_words + noise_left_elements;
    const uint32_t compress_offset_words = noise_f_r_offset_words + noise_right_elements;
    bool allocated_buffers{false};
    sample.base_matrix_cache_hit = IsBaseMatrixCacheHit(
        workspace,
        request.matrix_a_cache_key,
        request.matrix_b_cache_key,
        matrix_elements);

    if (!EnsureCachedBaseMatrices(
            workspace,
            runtime,
            request.matrix_a,
            request.matrix_b,
            request.matrix_a_cache_key,
            request.matrix_b_cache_key,
            matrix_elements,
            result.error,
            allocated_buffers)) {
        return result;
    }
    if (!EnsureDeviceBuffer(workspace.device_matrix_a, workspace.matrix_a_capacity, total_matrix_elements, result.error, allocated_buffers) ||
        !EnsureDeviceBuffer(workspace.device_matrix_b, workspace.matrix_b_capacity, total_matrix_elements, result.error, allocated_buffers) ||
        !EnsureDeviceBuffer(workspace.device_prepared_input_ptrs,
                            workspace.prepared_input_ptr_capacity,
                            request.batch_size,
                            result.error,
                            allocated_buffers)) {
        return result;
    }

    const auto total_start = SteadyClock::now();
    std::vector<const Element*> prepared_input_ptrs;
    prepared_input_ptrs.reserve(request.batch_size);
    const auto wait_start = SteadyClock::now();
    for (uint32_t i = 0; i < request.batch_size; ++i) {
        const auto* generated = request.generated_inputs[i];
        if (generated->device_index != runtime.device_index ||
            generated->n != request.n ||
            generated->b != request.b ||
            generated->r != request.r ||
            generated->noise_words != noise_left_elements ||
            generated->compress_words != compress_elements ||
            generated->noise_e_l == nullptr ||
            generated->noise_e_r == nullptr ||
            generated->noise_f_l == nullptr ||
            generated->noise_f_r == nullptr ||
            generated->compress_vec == nullptr) {
            result.error = "CUDA digest batch request contains incompatible device-generated inputs";
            return result;
        }

        if (generated->ready_event != nullptr) {
            error = cudaStreamWaitEvent(
                workspace.stream,
                reinterpret_cast<cudaEvent_t>(generated->ready_event),
                0);
            if (error != cudaSuccess) {
                result.error = "cudaStreamWaitEvent failed:" + CudaErrorString(error);
                return result;
            }
        }

        prepared_input_ptrs.push_back(generated->storage);
    }
    sample.stream_wait_event_us = DurationMicros(wait_start, SteadyClock::now());

    const auto pointer_copy_start = SteadyClock::now();
    error = cudaMemcpyAsync(workspace.device_prepared_input_ptrs,
                            prepared_input_ptrs.data(),
                            request.batch_size * sizeof(const Element*),
                            cudaMemcpyHostToDevice,
                            workspace.stream);
    sample.submit_h2d_us = DurationMicros(pointer_copy_start, SteadyClock::now());
    if (error != cudaSuccess) {
        result.error = "cudaMemcpy prepared_input_ptrs failed:" + CudaErrorString(error);
        return result;
    }

    const uint32_t build_blocks = static_cast<uint32_t>((total_matrix_elements + WORKSPACE_THREADS - 1) / WORKSPACE_THREADS);
    const auto build_start = SteadyClock::now();
    BuildPerturbedMatrixPackedPointersKernel<<<build_blocks, WORKSPACE_THREADS, 0, workspace.stream>>>(
        workspace.device_base_a,
        workspace.device_prepared_input_ptrs,
        noise_e_l_offset_words,
        noise_e_r_offset_words,
        request.n,
        request.r,
        total_matrix_elements,
        matrix_elements,
        workspace.device_matrix_a);
    error = cudaGetLastError();
    if (error == cudaSuccess) {
        BuildPerturbedMatrixPackedPointersKernel<<<build_blocks, WORKSPACE_THREADS, 0, workspace.stream>>>(
            workspace.device_base_b,
            workspace.device_prepared_input_ptrs,
            noise_f_l_offset_words,
            noise_f_r_offset_words,
            request.n,
            request.r,
            total_matrix_elements,
            matrix_elements,
            workspace.device_matrix_b);
        error = cudaGetLastError();
    }
    sample.launch_build_perturbed_us = DurationMicros(build_start, SteadyClock::now());
    if (error != cudaSuccess) {
        result.error = "CUDA perturbed-matrix kernel failed:" + CudaErrorString(error);
        return result;
    }

    if (!FinalizeCompressedWordsPackedPointerBatch(
            *lease,
            workspace,
            request.n,
            request.b,
            request.r,
            request.batch_size,
            compress_offset_words,
            mode,
            result,
            sample,
            allocated_buffers)) {
        return result;
    }

    sample.total_wall_ms = DurationMillis(total_start, SteadyClock::now());
    RecordProfilingSample(sample);
    return result;
}

MatMulCompressedWordsBatchResult ComputeCompressedWordsLowRankVariableBaseDeviceBatchOnDevice(
    const MatMulLowRankVariableBaseDeviceBatchRequest& request,
    MatMulCompressedWordsMode mode,
    int device_index)
{
    MatMulCompressedWordsBatchResult result;
    DigestProfilingSample sample;
    const auto runtime_probe = ResolveCudaRuntimeForSelectedDevice(device_index, result.error);
    result.available = runtime_probe.has_value();
    if (!runtime_probe.has_value()) {
        return result;
    }
    const auto runtime = *runtime_probe;

    if (!ValidateLowRankVariableBaseDeviceBatchRequest(request, result.error)) {
        return result;
    }

    auto lease = AcquireBufferPoolSlot(runtime.device_index, result.error);
    if (!lease.has_value()) {
        return result;
    }

    auto& workspace = lease->workspace();
    ResetWorkspaceForDevice(workspace, runtime.device_index);

    cudaError_t error = cudaSetDevice(runtime.device_index);
    if (error != cudaSuccess) {
        result.error = "cudaSetDevice failed:" + CudaErrorString(error);
        return result;
    }
    if (!EnsureWorkspaceStream(workspace, result.error)) {
        return result;
    }

    sample.n = request.n;
    sample.b = request.b;
    sample.r = request.r;
    sample.batch_size = request.batch_size;
    sample.mode = ModeToString(mode);
    sample.used_low_rank_path = true;
    sample.used_device_prepared_inputs = true;
    const uint32_t matrix_elements = request.n * request.n;
    const uint32_t noise_left_elements = request.n * request.r;
    const uint32_t noise_right_elements = request.r * request.n;
    const uint32_t compress_elements = request.b * request.b;
    const size_t total_matrix_elements = static_cast<size_t>(request.batch_size) * matrix_elements;
    const uint32_t noise_e_l_offset_words = 0;
    const uint32_t noise_e_r_offset_words = noise_e_l_offset_words + noise_left_elements;
    const uint32_t noise_f_l_offset_words = noise_e_r_offset_words + noise_right_elements;
    const uint32_t noise_f_r_offset_words = noise_f_l_offset_words + noise_left_elements;
    const uint32_t compress_offset_words = noise_f_r_offset_words + noise_right_elements;
    bool allocated_buffers{false};

    if (!EnsureDeviceBuffer(workspace.device_seed_a,
                            workspace.seed_a_capacity,
                            request.batch_size,
                            result.error,
                            allocated_buffers) ||
        !EnsureDeviceBuffer(workspace.device_seed_b,
                            workspace.seed_b_capacity,
                            request.batch_size,
                            result.error,
                            allocated_buffers) ||
        !EnsureDeviceBuffer(workspace.device_matrix_a,
                            workspace.matrix_a_capacity,
                            total_matrix_elements,
                            result.error,
                            allocated_buffers) ||
        !EnsureDeviceBuffer(workspace.device_matrix_b,
                            workspace.matrix_b_capacity,
                            total_matrix_elements,
                            result.error,
                            allocated_buffers) ||
        !EnsureDeviceBuffer(workspace.device_prepared_input_ptrs,
                            workspace.prepared_input_ptr_capacity,
                            request.batch_size,
                            result.error,
                            allocated_buffers)) {
        return result;
    }

    const auto total_start = SteadyClock::now();
    std::vector<DeviceSeedBytes> seed_a_batch(request.batch_size);
    std::vector<DeviceSeedBytes> seed_b_batch(request.batch_size);
    std::vector<const Element*> prepared_input_ptrs;
    prepared_input_ptrs.reserve(request.batch_size);
    const auto wait_start = SteadyClock::now();
    for (uint32_t i = 0; i < request.batch_size; ++i) {
        std::memcpy(seed_a_batch[i].data, request.matrix_a_seeds[i].data(), sizeof(seed_a_batch[i].data));
        std::memcpy(seed_b_batch[i].data, request.matrix_b_seeds[i].data(), sizeof(seed_b_batch[i].data));

        const auto* generated = request.generated_inputs[i];
        if (generated->device_index != runtime.device_index ||
            generated->n != request.n ||
            generated->b != request.b ||
            generated->r != request.r ||
            generated->noise_words != noise_left_elements ||
            generated->compress_words != compress_elements ||
            generated->noise_e_l == nullptr ||
            generated->noise_e_r == nullptr ||
            generated->noise_f_l == nullptr ||
            generated->noise_f_r == nullptr ||
            generated->compress_vec == nullptr) {
            result.error = "CUDA variable-base digest batch request contains incompatible device-generated inputs";
            return result;
        }

        if (generated->ready_event != nullptr) {
            error = cudaStreamWaitEvent(
                workspace.stream,
                reinterpret_cast<cudaEvent_t>(generated->ready_event),
                0);
            if (error != cudaSuccess) {
                result.error = "cudaStreamWaitEvent failed:" + CudaErrorString(error);
                return result;
            }
        }

        prepared_input_ptrs.push_back(generated->storage);
    }
    sample.stream_wait_event_us = DurationMicros(wait_start, SteadyClock::now());

    const auto h2d_start = SteadyClock::now();
    error = cudaMemcpyAsync(workspace.device_seed_a,
                            seed_a_batch.data(),
                            request.batch_size * sizeof(DeviceSeedBytes),
                            cudaMemcpyHostToDevice,
                            workspace.stream);
    if (error == cudaSuccess) {
        error = cudaMemcpyAsync(workspace.device_seed_b,
                                seed_b_batch.data(),
                                request.batch_size * sizeof(DeviceSeedBytes),
                                cudaMemcpyHostToDevice,
                                workspace.stream);
    }
    if (error == cudaSuccess) {
        error = cudaMemcpyAsync(workspace.device_prepared_input_ptrs,
                                prepared_input_ptrs.data(),
                                request.batch_size * sizeof(const Element*),
                                cudaMemcpyHostToDevice,
                                workspace.stream);
    }
    sample.submit_h2d_us = DurationMicros(h2d_start, SteadyClock::now());
    if (error != cudaSuccess) {
        result.error = "cudaMemcpy variable-base request data failed:" + CudaErrorString(error);
        return result;
    }

    const uint32_t build_blocks = static_cast<uint32_t>((total_matrix_elements + WORKSPACE_THREADS - 1) / WORKSPACE_THREADS);
    // Per-seed SHA midstate buffer (16 words/seed), reused for the A then B pass.
    const uint32_t seed_midstate_words = request.batch_size * 16U;
    if (!EnsureDeviceBuffer(workspace.device_seed_midstates,
                            workspace.seed_midstates_capacity,
                            seed_midstate_words,
                            result.error,
                            allocated_buffers)) {
        return result;
    }
    const uint32_t midstate_blocks = (request.batch_size + WORKSPACE_THREADS - 1U) / WORKSPACE_THREADS;
    const auto build_start = SteadyClock::now();
    PrecomputeSeedMidstatesKernel<<<midstate_blocks, WORKSPACE_THREADS, 0, workspace.stream>>>(
        workspace.device_seed_a,
        request.batch_size,
        workspace.device_seed_midstates);
    error = cudaGetLastError();
    if (error == cudaSuccess) {
        GenerateBaseMatrixFromSeedMidstateKernel<<<build_blocks, WORKSPACE_THREADS, 0, workspace.stream>>>(
            workspace.device_seed_a,
            workspace.device_seed_midstates,
            request.n,
            total_matrix_elements,
            matrix_elements,
            workspace.device_matrix_a);
        error = cudaGetLastError();
    }
    if (error == cudaSuccess) {
        PrecomputeSeedMidstatesKernel<<<midstate_blocks, WORKSPACE_THREADS, 0, workspace.stream>>>(
            workspace.device_seed_b,
            request.batch_size,
            workspace.device_seed_midstates);
        error = cudaGetLastError();
    }
    if (error == cudaSuccess) {
        GenerateBaseMatrixFromSeedMidstateKernel<<<build_blocks, WORKSPACE_THREADS, 0, workspace.stream>>>(
            workspace.device_seed_b,
            workspace.device_seed_midstates,
            request.n,
            total_matrix_elements,
            matrix_elements,
            workspace.device_matrix_b);
        error = cudaGetLastError();
    }
    if (error == cudaSuccess) {
        ApplyPerturbationPackedPointersVariableBaseKernel<<<build_blocks, WORKSPACE_THREADS, 0, workspace.stream>>>(
            workspace.device_prepared_input_ptrs,
            noise_e_l_offset_words,
            noise_e_r_offset_words,
            request.n,
            request.r,
            total_matrix_elements,
            matrix_elements,
            workspace.device_matrix_a);
        error = cudaGetLastError();
    }
    if (error == cudaSuccess) {
        ApplyPerturbationPackedPointersVariableBaseKernel<<<build_blocks, WORKSPACE_THREADS, 0, workspace.stream>>>(
            workspace.device_prepared_input_ptrs,
            noise_f_l_offset_words,
            noise_f_r_offset_words,
            request.n,
            request.r,
            total_matrix_elements,
            matrix_elements,
            workspace.device_matrix_b);
        error = cudaGetLastError();
    }
    sample.launch_build_perturbed_us = DurationMicros(build_start, SteadyClock::now());
    if (error != cudaSuccess) {
        result.error = "CUDA variable-base matrix kernel failed:" + CudaErrorString(error);
        return result;
    }

    if (!FinalizeCompressedWordsPackedPointerBatch(
            *lease,
            workspace,
            request.n,
            request.b,
            request.r,
            request.batch_size,
            compress_offset_words,
            mode,
            result,
            sample,
            allocated_buffers)) {
        return result;
    }

    sample.total_wall_ms = DurationMillis(total_start, SteadyClock::now());
    RecordProfilingSample(sample);
    return result;
}

MatMulCompressedWordsBatchResult ComputeCompressedWordsLowRankDeviceBatch(
    const MatMulLowRankCompressedWordsDeviceBatchRequest& request,
    MatMulCompressedWordsMode mode)
{
    return ComputeCompressedWordsLowRankDeviceBatchMultiDevice(request, mode);
}

MatMulCompressedWordsBatchResult ComputeCompressedWordsLowRankDeviceBatchMultiDevice(
    const MatMulLowRankCompressedWordsDeviceBatchRequest& request,
    MatMulCompressedWordsMode mode)
{
    MatMulCompressedWordsBatchResult result;

    const auto topology = ProbeCudaTopology();
    result.available = topology.available;
    if (!topology.available) {
        result.error = topology.reason;
        return result;
    }

    if (!ValidateLowRankDeviceBatchRequest(request, result.error)) {
        return result;
    }

    struct DeviceShard {
        int device_index{-1};
        std::vector<size_t> indices;
        std::vector<const MatMulGeneratedInputsDevice*> inputs;
    };

    std::map<int, DeviceShard> shard_map;
    for (uint32_t i = 0; i < request.batch_size; ++i) {
        const auto* generated = request.generated_inputs[i];
        auto& shard = shard_map[generated->device_index];
        shard.device_index = generated->device_index;
        shard.indices.push_back(i);
        shard.inputs.push_back(generated);
    }

    if (shard_map.size() == 1) {
        return ComputeCompressedWordsLowRankDeviceBatchOnDevice(request, mode, shard_map.begin()->first);
    }

    struct ShardResult {
        DeviceShard shard;
        MatMulCompressedWordsBatchResult result;
    };

    std::vector<std::future<ShardResult>> futures;
    futures.reserve(shard_map.size());
    for (const auto& entry : shard_map) {
        const auto& shard = entry.second;
        futures.push_back(std::async(std::launch::async, [request, mode, shard]() {
            const MatMulLowRankCompressedWordsDeviceBatchRequest shard_request{
                .n = request.n,
                .b = request.b,
                .r = request.r,
                .batch_size = static_cast<uint32_t>(shard.inputs.size()),
                .matrix_a = request.matrix_a,
                .matrix_b = request.matrix_b,
                .matrix_a_cache_key = request.matrix_a_cache_key,
                .matrix_b_cache_key = request.matrix_b_cache_key,
                .generated_inputs = shard.inputs.data(),
            };
            return ShardResult{
                .shard = shard,
                .result = ComputeCompressedWordsLowRankDeviceBatchOnDevice(shard_request, mode, shard.device_index),
            };
        }));
    }

    std::vector<ShardResult> shard_results;
    shard_results.reserve(futures.size());
    try {
        for (auto& future : futures) {
            shard_results.push_back(future.get());
        }
    } catch (const std::exception& e) {
        result.error = std::string{"cuda_multi_device_prepared_batch_exception:"} + e.what();
        return result;
    }

    for (const auto& shard_result : shard_results) {
        if (!shard_result.result.success) {
            result.available = shard_result.result.available;
            result.error = "cuda_device_" + std::to_string(shard_result.shard.device_index) + "_prepared_batch_failed:" +
                (shard_result.result.error.empty() ? "unknown_error" : shard_result.result.error);
            return result;
        }
        if (result.words_per_request == 0) {
            result.words_per_request = shard_result.result.words_per_request;
        } else if (result.words_per_request != shard_result.result.words_per_request) {
            result.error = "cuda_multi_device_prepared_batch_words_per_request_mismatch";
            return result;
        }
    }

    if (result.words_per_request == 0) {
        result.error = "cuda_multi_device_prepared_batch_empty_result";
        return result;
    }

    result.words.assign(static_cast<size_t>(request.batch_size) * result.words_per_request, Element{0});
    for (const auto& shard_result : shard_results) {
        const size_t expected_words = shard_result.shard.inputs.size() * result.words_per_request;
        if (shard_result.result.words.size() != expected_words ||
            shard_result.shard.indices.size() != shard_result.shard.inputs.size()) {
            result.success = false;
            result.error = "cuda_multi_device_prepared_batch_result_size_mismatch";
            result.words.clear();
            result.words_per_request = 0;
            return result;
        }
        for (size_t i = 0; i < shard_result.shard.indices.size(); ++i) {
            std::copy(
                shard_result.result.words.begin() + i * result.words_per_request,
                shard_result.result.words.begin() + (i + 1) * result.words_per_request,
                result.words.begin() + shard_result.shard.indices[i] * result.words_per_request);
        }
    }

    result.success = true;
    return result;
}

MatMulCompressedWordsBatchResult ComputeCompressedWordsLowRankVariableBaseDeviceBatch(
    const MatMulLowRankVariableBaseDeviceBatchRequest& request,
    MatMulCompressedWordsMode mode)
{
    return ComputeCompressedWordsLowRankVariableBaseDeviceBatchMultiDevice(request, mode);
}

MatMulCompressedWordsBatchResult ComputeCompressedWordsLowRankVariableBaseDeviceBatchMultiDevice(
    const MatMulLowRankVariableBaseDeviceBatchRequest& request,
    MatMulCompressedWordsMode mode)
{
    MatMulCompressedWordsBatchResult result;

    const auto topology = ProbeCudaTopology();
    result.available = topology.available;
    if (!topology.available) {
        result.error = topology.reason;
        return result;
    }

    if (!ValidateLowRankVariableBaseDeviceBatchRequest(request, result.error)) {
        return result;
    }

    struct DeviceShard {
        int device_index{-1};
        std::vector<size_t> indices;
        std::vector<uint256> seed_a;
        std::vector<uint256> seed_b;
        std::vector<const MatMulGeneratedInputsDevice*> inputs;
    };

    std::map<int, DeviceShard> shard_map;
    for (uint32_t i = 0; i < request.batch_size; ++i) {
        const auto* generated = request.generated_inputs[i];
        auto& shard = shard_map[generated->device_index];
        shard.device_index = generated->device_index;
        shard.indices.push_back(i);
        shard.seed_a.push_back(request.matrix_a_seeds[i]);
        shard.seed_b.push_back(request.matrix_b_seeds[i]);
        shard.inputs.push_back(generated);
    }

    if (shard_map.size() == 1) {
        return ComputeCompressedWordsLowRankVariableBaseDeviceBatchOnDevice(
            request,
            mode,
            shard_map.begin()->first);
    }

    struct ShardResult {
        DeviceShard shard;
        MatMulCompressedWordsBatchResult result;
    };

    std::vector<std::future<ShardResult>> futures;
    futures.reserve(shard_map.size());
    for (const auto& entry : shard_map) {
        const auto& shard = entry.second;
        futures.push_back(std::async(std::launch::async, [request, mode, shard]() {
            const MatMulLowRankVariableBaseDeviceBatchRequest shard_request{
                .n = request.n,
                .b = request.b,
                .r = request.r,
                .batch_size = static_cast<uint32_t>(shard.inputs.size()),
                .matrix_a_seeds = shard.seed_a.data(),
                .matrix_b_seeds = shard.seed_b.data(),
                .generated_inputs = shard.inputs.data(),
            };
            return ShardResult{
                .shard = shard,
                .result = ComputeCompressedWordsLowRankVariableBaseDeviceBatchOnDevice(
                    shard_request,
                    mode,
                    shard.device_index),
            };
        }));
    }

    std::vector<ShardResult> shard_results;
    shard_results.reserve(futures.size());
    try {
        for (auto& future : futures) {
            shard_results.push_back(future.get());
        }
    } catch (const std::exception& e) {
        result.error = std::string{"cuda_multi_device_variable_base_batch_exception:"} + e.what();
        return result;
    }

    for (const auto& shard_result : shard_results) {
        if (!shard_result.result.success) {
            result.available = shard_result.result.available;
            result.error = "cuda_device_" + std::to_string(shard_result.shard.device_index) + "_variable_base_batch_failed:" +
                (shard_result.result.error.empty() ? "unknown_error" : shard_result.result.error);
            return result;
        }
        if (result.words_per_request == 0) {
            result.words_per_request = shard_result.result.words_per_request;
        } else if (result.words_per_request != shard_result.result.words_per_request) {
            result.error = "cuda_multi_device_variable_base_batch_words_per_request_mismatch";
            return result;
        }
    }

    if (result.words_per_request == 0) {
        result.error = "cuda_multi_device_variable_base_batch_empty_result";
        return result;
    }

    result.words.assign(static_cast<size_t>(request.batch_size) * result.words_per_request, Element{0});
    for (const auto& shard_result : shard_results) {
        const size_t expected_words = shard_result.shard.inputs.size() * result.words_per_request;
        if (shard_result.result.words.size() != expected_words ||
            shard_result.shard.indices.size() != shard_result.shard.inputs.size()) {
            result.success = false;
            result.error = "cuda_multi_device_variable_base_batch_result_size_mismatch";
            result.words.clear();
            result.words_per_request = 0;
            return result;
        }
        for (size_t i = 0; i < shard_result.shard.indices.size(); ++i) {
            std::copy(
                shard_result.result.words.begin() + i * result.words_per_request,
                shard_result.result.words.begin() + (i + 1) * result.words_per_request,
                result.words.begin() + shard_result.shard.indices[i] * result.words_per_request);
        }
    }

    result.success = true;
    return result;
}

} // namespace btx::cuda
