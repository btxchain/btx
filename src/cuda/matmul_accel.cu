// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cuda/matmul_accel.h>

#include <cuda/cuda_context.h>
#include <cuda/oracle_accel.h>

#include <cuda_runtime.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace btx::cuda {
namespace {

using Element = matmul::field::Element;
constexpr Element MODULUS = matmul::field::MODULUS;
constexpr uint32_t REDUCE_INTERVAL{4};
constexpr uint32_t MAX_BLOCK_THREADS{256};
constexpr uint32_t WORKSPACE_THREADS{256};

std::string CudaErrorString(cudaError_t error);

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
        cudaFree(device_output);
        cudaFree(device_compress);
        cudaFree(device_noise_f_r);
        cudaFree(device_noise_f_l);
        cudaFree(device_noise_e_r);
        cudaFree(device_noise_e_l);
        cudaFree(device_prepared_input_ptrs);
        cudaFree(device_matrix_b);
        cudaFree(device_matrix_a);
        cudaFree(device_base_b);
        cudaFree(device_base_a);

        device_output = nullptr;
        device_compress = nullptr;
        device_noise_f_r = nullptr;
        device_noise_f_l = nullptr;
        device_noise_e_r = nullptr;
        device_noise_e_l = nullptr;
        device_prepared_input_ptrs = nullptr;
        device_matrix_b = nullptr;
        device_matrix_a = nullptr;
        device_base_b = nullptr;
        device_base_a = nullptr;

        output_capacity = 0;
        compress_capacity = 0;
        noise_f_r_capacity = 0;
        noise_f_l_capacity = 0;
        noise_e_r_capacity = 0;
        noise_e_l_capacity = 0;
        prepared_input_ptr_capacity = 0;
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

uint32_t ResolveCudaPoolSlotCount()
{
    constexpr uint32_t DEFAULT_SLOTS{1};
    constexpr uint32_t MAX_SLOTS{32};

    const char* env = std::getenv("BTX_MATMUL_CUDA_POOL_SLOTS");
    if (env != nullptr && *env != '\0') {
        try {
            size_t consumed{0};
            const unsigned long parsed = std::stoul(env, &consumed, 10);
            if (consumed != std::strlen(env) || parsed == 0) {
                return DEFAULT_SLOTS;
            }
            return std::min<uint32_t>(static_cast<uint32_t>(parsed), MAX_SLOTS);
        } catch (const std::exception&) {
            return DEFAULT_SLOTS;
        }
    }

    const auto runtime = ProbeCudaRuntime();
    if (!runtime.available) {
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
        runtime.multiprocessor_count >= 128 ? 8U :
        runtime.multiprocessor_count >= 96 ? 7U :
        runtime.multiprocessor_count >= 64 ? 6U :
        runtime.multiprocessor_count >= 48 ? 5U :
        runtime.multiprocessor_count >= 24 ? 4U :
        runtime.multiprocessor_count >= 12 ? 2U : 1U;
    return std::clamp<uint32_t>(std::min(cpu_limit, gpu_limit), 1U, MAX_SLOTS);
}

DigestPoolContext& GetPoolContext()
{
    static DigestPoolContext context;
    static std::once_flag init_once;
    std::call_once(init_once, [] {
        context.slots.resize(ResolveCudaPoolSlotCount());
        for (auto& slot : context.slots) {
            slot = std::make_unique<DigestPoolSlot>();
        }
    });
    return context;
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

std::optional<BufferPoolLease> AcquireBufferPoolSlot(std::string& error)
{
    auto& context = GetPoolContext();
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

    const auto runtime = ProbeCudaRuntime();
    if (!runtime.available) {
        stats.available = false;
        stats.initialized = false;
        stats.reason = runtime.reason;
        return stats;
    }

    auto& context = GetPoolContext();
    std::lock_guard<std::mutex> lock(context.mutex);
    stats.available = true;
    stats.initialized = context.initialized;
    stats.allocation_events = context.allocation_events;
    stats.reuse_events = context.reuse_events;
    stats.wait_events = context.wait_events;
    stats.completed_submissions = context.completed_submissions;
    stats.slot_count = static_cast<uint32_t>(context.slots.size());
    stats.active_slots = context.active_slots;
    stats.high_water_slots = context.high_water_slots;
    stats.inflight_submissions = context.inflight_submissions;
    stats.peak_inflight_submissions = context.peak_inflight_submissions;
    stats.n = context.last_n;
    stats.b = context.last_b;
    stats.r = context.last_r;
    stats.reason = context.reason;
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
    profile.execution_model = "nonblocking_stream_per_pool_slot";
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

    auto lease = AcquireBufferPoolSlot(result.error);
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

MatMulCompressedWordsBatchResult ComputeCompressedWordsLowRankBatch(
    const MatMulLowRankCompressedWordsBatchRequest& request,
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

    if (!ValidateLowRankBatchRequest(request, result.error)) {
        return result;
    }

    auto lease = AcquireBufferPoolSlot(result.error);
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

MatMulCompressedWordsBatchResult ComputeCompressedWordsLowRankDeviceBatch(
    const MatMulLowRankCompressedWordsDeviceBatchRequest& request,
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

    if (!ValidateLowRankDeviceBatchRequest(request, result.error)) {
        return result;
    }

    auto lease = AcquireBufferPoolSlot(result.error);
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

} // namespace btx::cuda
