// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <matmul/backend_capabilities.h>
#include <cuda/matmul_accel.h>
#include <cuda/oracle_accel.h>
#include <metal/matmul_accel.h>
#include <metal/oracle_accel.h>
#include <util/translation.h>

#include <univalue.h>

#include <iostream>
#include <string>
#include <vector>

const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace {

void PrintUsage(std::ostream& out)
{
    out << "Usage: btx-matmul-backend-info [--backend <cpu|metal|mlx|cuda>]" << std::endl;
}

} // namespace

int main(int argc, char* argv[])
{
#if defined(__APPLE__)
    std::string requested_backend{"metal"};
#else
    std::string requested_backend{"cpu"};
#endif

    for (int i = 1; i < argc; ++i) {
        const std::string arg{argv[i]};
        if (arg == "--help" || arg == "-h") {
            PrintUsage(std::cout);
            return 0;
        }

        if (arg == "--backend") {
            if (i + 1 >= argc) {
                std::cerr << "error: --backend requires a value" << std::endl;
                PrintUsage(std::cerr);
                return 1;
            }
            requested_backend = argv[++i];
            continue;
        }

        static const std::string prefix{"--backend="};
        if (arg.rfind(prefix, 0) == 0) {
            requested_backend = arg.substr(prefix.size());
            continue;
        }

        std::cerr << "error: unknown argument: " << arg << std::endl;
        PrintUsage(std::cerr);
        return 1;
    }

    const auto selection = matmul::backend::ResolveRequestedBackend(requested_backend);
    const auto capabilities = matmul::backend::AllCapabilities();

    UniValue capability_obj(UniValue::VOBJ);
    for (const auto& [kind, capability] : capabilities) {
        UniValue item(UniValue::VOBJ);
        item.pushKV("compiled", capability.compiled);
        item.pushKV("available", capability.available);
        item.pushKV("reason", capability.reason);
        capability_obj.pushKV(matmul::backend::ToString(kind), std::move(item));
    }

    UniValue output(UniValue::VOBJ);
    output.pushKV("requested_input", selection.requested_input);
    output.pushKV("requested_known", selection.requested_known);
    output.pushKV("requested_backend", matmul::backend::ToString(selection.requested));
    output.pushKV("active_backend", matmul::backend::ToString(selection.active));
    output.pushKV("selection_reason", selection.reason);
    output.pushKV("capabilities", std::move(capability_obj));

    UniValue metal_runtime(UniValue::VOBJ);
    const auto pool_stats = btx::metal::ProbeMatMulBufferPool();
    const auto dispatch_config = btx::metal::ProbeMatMulDispatchConfig();
    const auto kernel_profile = btx::metal::ProbeMatMulKernelProfile();
    const auto profiling_stats = btx::metal::ProbeMatMulProfilingStats();
    const auto oracle_profile = btx::metal::ProbeMatMulInputGenerationProfile();

    UniValue pool_obj(UniValue::VOBJ);
    pool_obj.pushKV("available", pool_stats.available);
    pool_obj.pushKV("initialized", pool_stats.initialized);
    pool_obj.pushKV("allocation_events", pool_stats.allocation_events);
    pool_obj.pushKV("reuse_events", pool_stats.reuse_events);
    pool_obj.pushKV("wait_events", pool_stats.wait_events);
    pool_obj.pushKV("slot_count", pool_stats.slot_count);
    pool_obj.pushKV("active_slots", pool_stats.active_slots);
    pool_obj.pushKV("high_water_slots", pool_stats.high_water_slots);
    pool_obj.pushKV("n", pool_stats.n);
    pool_obj.pushKV("b", pool_stats.b);
    pool_obj.pushKV("r", pool_stats.r);
    pool_obj.pushKV("reason", pool_stats.reason);

    UniValue dispatch_obj(UniValue::VOBJ);
    dispatch_obj.pushKV("available", dispatch_config.available);
    dispatch_obj.pushKV("build_perturbed_threads", dispatch_config.build_perturbed_threads);
    dispatch_obj.pushKV("build_prefix_threads", dispatch_config.build_prefix_threads);
    dispatch_obj.pushKV("compress_prefix_threads", dispatch_config.compress_prefix_threads);
    dispatch_obj.pushKV("reason", dispatch_config.reason);

    UniValue kernel_obj(UniValue::VOBJ);
    kernel_obj.pushKV("available", kernel_profile.available);
    kernel_obj.pushKV("tiled_build_prefix", kernel_profile.tiled_build_prefix);
    kernel_obj.pushKV("fused_prefix_compress", kernel_profile.fused_prefix_compress);
    kernel_obj.pushKV("gpu_transcript_hash", kernel_profile.gpu_transcript_hash);
    kernel_obj.pushKV("function_constant_specialization", kernel_profile.function_constant_specialization);
    kernel_obj.pushKV("specialized_shape_count", kernel_profile.specialized_shape_count);
    kernel_obj.pushKV("cooperative_tensor_prepared", kernel_profile.cooperative_tensor_prepared);
    kernel_obj.pushKV("cooperative_tensor_active", kernel_profile.cooperative_tensor_active);
    kernel_obj.pushKV("uses_prefix_buffer", kernel_profile.uses_prefix_buffer);
    kernel_obj.pushKV("build_prefix_threadgroup_width", kernel_profile.build_prefix_threadgroup_width);
    kernel_obj.pushKV("build_prefix_threadgroup_height", kernel_profile.build_prefix_threadgroup_height);
    kernel_obj.pushKV("fused_prefix_threadgroup_threads", kernel_profile.fused_prefix_threadgroup_threads);
    kernel_obj.pushKV("specialization_reason", kernel_profile.specialization_reason);
    kernel_obj.pushKV("cooperative_tensor_reason", kernel_profile.cooperative_tensor_reason);
    kernel_obj.pushKV("library_source", kernel_profile.library_source);
    kernel_obj.pushKV("reason", kernel_profile.reason);

    UniValue profiling_obj(UniValue::VOBJ);
    profiling_obj.pushKV("available", profiling_stats.available);
    profiling_obj.pushKV("capture_supported", profiling_stats.capture_supported);
    profiling_obj.pushKV("samples", profiling_stats.samples);
    profiling_obj.pushKV("last_encode_build_perturbed_us", profiling_stats.last_encode_build_perturbed_us);
    profiling_obj.pushKV("last_encode_fused_prefix_compress_us", profiling_stats.last_encode_fused_prefix_compress_us);
    profiling_obj.pushKV("last_encode_transcript_sha256_us", profiling_stats.last_encode_transcript_sha256_us);
    profiling_obj.pushKV("last_submit_wait_us", profiling_stats.last_submit_wait_us);
    profiling_obj.pushKV("last_gpu_execution_ms", profiling_stats.last_gpu_execution_ms);
    profiling_obj.pushKV("last_zero_copy_inputs", profiling_stats.last_zero_copy_inputs);
    profiling_obj.pushKV("reason", profiling_stats.reason);

    UniValue oracle_obj(UniValue::VOBJ);
    oracle_obj.pushKV("available", oracle_profile.available);
    oracle_obj.pushKV("pool_initialized", oracle_profile.pool_initialized);
    oracle_obj.pushKV("samples", oracle_profile.samples);
    oracle_obj.pushKV("allocation_events", oracle_profile.allocation_events);
    oracle_obj.pushKV("reuse_events", oracle_profile.reuse_events);
    oracle_obj.pushKV("last_encode_noise_us", oracle_profile.last_encode_noise_us);
    oracle_obj.pushKV("last_encode_compress_us", oracle_profile.last_encode_compress_us);
    oracle_obj.pushKV("last_submit_wait_us", oracle_profile.last_submit_wait_us);
    oracle_obj.pushKV("last_gpu_generation_ms", oracle_profile.last_gpu_generation_ms);
    oracle_obj.pushKV("library_source", oracle_profile.library_source);
    oracle_obj.pushKV("reason", oracle_profile.reason);

    metal_runtime.pushKV("buffer_pool", std::move(pool_obj));
    metal_runtime.pushKV("dispatch", std::move(dispatch_obj));
    metal_runtime.pushKV("kernel_profile", std::move(kernel_obj));
    metal_runtime.pushKV("profiling", std::move(profiling_obj));
    metal_runtime.pushKV("oracle_input_generation", std::move(oracle_obj));
    output.pushKV("metal_runtime", std::move(metal_runtime));

    const auto cuda_runtime = btx::cuda::ProbeMatMulDigestAcceleration();
    const auto cuda_pool_stats = btx::cuda::ProbeMatMulBufferPool();
    const auto cuda_dispatch_config = btx::cuda::ProbeMatMulDispatchConfig();
    const auto cuda_kernel_profile = btx::cuda::ProbeMatMulKernelProfile();
    const auto cuda_profiling_stats = btx::cuda::ProbeMatMulProfilingStats();
    const auto cuda_oracle_profile = btx::cuda::ProbeMatMulInputGenerationProfile();
    UniValue cuda_obj(UniValue::VOBJ);
    cuda_obj.pushKV("available", cuda_runtime.available);
    cuda_obj.pushKV("reason", cuda_runtime.reason);
    cuda_obj.pushKV("device_name", cuda_runtime.device_name);
    cuda_obj.pushKV("compute_capability_major", cuda_runtime.compute_capability_major);
    cuda_obj.pushKV("compute_capability_minor", cuda_runtime.compute_capability_minor);
    cuda_obj.pushKV("global_memory_bytes", static_cast<uint64_t>(cuda_runtime.global_memory_bytes));
    cuda_obj.pushKV("multiprocessor_count", cuda_runtime.multiprocessor_count);
    cuda_obj.pushKV("driver_api_version", cuda_runtime.driver_api_version);
    cuda_obj.pushKV("runtime_version", cuda_runtime.runtime_version);

    UniValue cuda_pool_obj(UniValue::VOBJ);
    cuda_pool_obj.pushKV("available", cuda_pool_stats.available);
    cuda_pool_obj.pushKV("initialized", cuda_pool_stats.initialized);
    cuda_pool_obj.pushKV("allocation_events", cuda_pool_stats.allocation_events);
    cuda_pool_obj.pushKV("reuse_events", cuda_pool_stats.reuse_events);
    cuda_pool_obj.pushKV("wait_events", cuda_pool_stats.wait_events);
    cuda_pool_obj.pushKV("completed_submissions", cuda_pool_stats.completed_submissions);
    cuda_pool_obj.pushKV("slot_count", cuda_pool_stats.slot_count);
    cuda_pool_obj.pushKV("active_slots", cuda_pool_stats.active_slots);
    cuda_pool_obj.pushKV("high_water_slots", cuda_pool_stats.high_water_slots);
    cuda_pool_obj.pushKV("inflight_submissions", cuda_pool_stats.inflight_submissions);
    cuda_pool_obj.pushKV("peak_inflight_submissions", cuda_pool_stats.peak_inflight_submissions);
    cuda_pool_obj.pushKV("n", cuda_pool_stats.n);
    cuda_pool_obj.pushKV("b", cuda_pool_stats.b);
    cuda_pool_obj.pushKV("r", cuda_pool_stats.r);
    cuda_pool_obj.pushKV("reason", cuda_pool_stats.reason);
    cuda_obj.pushKV("buffer_pool", std::move(cuda_pool_obj));

    UniValue cuda_dispatch_obj(UniValue::VOBJ);
    cuda_dispatch_obj.pushKV("available", cuda_dispatch_config.available);
    cuda_dispatch_obj.pushKV("build_perturbed_threads", cuda_dispatch_config.build_perturbed_threads);
    cuda_dispatch_obj.pushKV("finalize_max_threads", cuda_dispatch_config.finalize_max_threads);
    cuda_dispatch_obj.pushKV("finalize_threads_b4", cuda_dispatch_config.finalize_threads_b4);
    cuda_dispatch_obj.pushKV("finalize_threads_b8", cuda_dispatch_config.finalize_threads_b8);
    cuda_dispatch_obj.pushKV("finalize_threads_b16", cuda_dispatch_config.finalize_threads_b16);
    cuda_dispatch_obj.pushKV("max_supported_block_size", cuda_dispatch_config.max_supported_block_size);
    cuda_dispatch_obj.pushKV("nonblocking_streams", cuda_dispatch_config.nonblocking_streams);
    cuda_dispatch_obj.pushKV("reason", cuda_dispatch_config.reason);
    cuda_obj.pushKV("dispatch", std::move(cuda_dispatch_obj));

    UniValue cuda_kernel_obj(UniValue::VOBJ);
    cuda_kernel_obj.pushKV("available", cuda_kernel_profile.available);
    cuda_kernel_obj.pushKV("low_rank_perturbation_kernel", cuda_kernel_profile.low_rank_perturbation_kernel);
    cuda_kernel_obj.pushKV("fused_compressed_words_finalize", cuda_kernel_profile.fused_compressed_words_finalize);
    cuda_kernel_obj.pushKV("pinned_host_staging", cuda_kernel_profile.pinned_host_staging);
    cuda_kernel_obj.pushKV("base_matrix_cache", cuda_kernel_profile.base_matrix_cache);
    cuda_kernel_obj.pushKV("shared_buffer_pool", cuda_kernel_profile.shared_buffer_pool);
    cuda_kernel_obj.pushKV("nonblocking_streams", cuda_kernel_profile.nonblocking_streams);
    cuda_kernel_obj.pushKV("device_prepared_inputs_supported", cuda_kernel_profile.device_prepared_inputs_supported);
    cuda_kernel_obj.pushKV("device_prepared_inputs_default", cuda_kernel_profile.device_prepared_inputs_default);
    cuda_kernel_obj.pushKV("device_prepared_inputs_enabled", cuda_kernel_profile.device_prepared_inputs_enabled);
    cuda_kernel_obj.pushKV("execution_model", cuda_kernel_profile.execution_model);
    cuda_kernel_obj.pushKV("staging_strategy", cuda_kernel_profile.staging_strategy);
    cuda_kernel_obj.pushKV("device_prepared_inputs_policy", cuda_kernel_profile.device_prepared_inputs_policy);
    cuda_kernel_obj.pushKV("reason", cuda_kernel_profile.reason);
    cuda_obj.pushKV("kernel_profile", std::move(cuda_kernel_obj));

    UniValue cuda_profiling_obj(UniValue::VOBJ);
    cuda_profiling_obj.pushKV("available", cuda_profiling_stats.available);
    cuda_profiling_obj.pushKV("samples", cuda_profiling_stats.samples);
    cuda_profiling_obj.pushKV("last_n", cuda_profiling_stats.last_n);
    cuda_profiling_obj.pushKV("last_b", cuda_profiling_stats.last_b);
    cuda_profiling_obj.pushKV("last_r", cuda_profiling_stats.last_r);
    cuda_profiling_obj.pushKV("last_batch_size", cuda_profiling_stats.last_batch_size);
    cuda_profiling_obj.pushKV("last_host_stage_us", cuda_profiling_stats.last_host_stage_us);
    cuda_profiling_obj.pushKV("last_submit_h2d_us", cuda_profiling_stats.last_submit_h2d_us);
    cuda_profiling_obj.pushKV("last_submit_d2d_us", cuda_profiling_stats.last_submit_d2d_us);
    cuda_profiling_obj.pushKV("last_stream_wait_event_us", cuda_profiling_stats.last_stream_wait_event_us);
    cuda_profiling_obj.pushKV("last_launch_build_perturbed_us", cuda_profiling_stats.last_launch_build_perturbed_us);
    cuda_profiling_obj.pushKV("last_launch_finalize_us", cuda_profiling_stats.last_launch_finalize_us);
    cuda_profiling_obj.pushKV("last_submit_d2h_us", cuda_profiling_stats.last_submit_d2h_us);
    cuda_profiling_obj.pushKV("last_stream_sync_us", cuda_profiling_stats.last_stream_sync_us);
    cuda_profiling_obj.pushKV("last_total_wall_ms", cuda_profiling_stats.last_total_wall_ms);
    cuda_profiling_obj.pushKV("last_used_low_rank_path", cuda_profiling_stats.last_used_low_rank_path);
    cuda_profiling_obj.pushKV("last_used_device_prepared_inputs", cuda_profiling_stats.last_used_device_prepared_inputs);
    cuda_profiling_obj.pushKV("last_used_pinned_host_staging", cuda_profiling_stats.last_used_pinned_host_staging);
    cuda_profiling_obj.pushKV("last_base_matrix_cache_hit", cuda_profiling_stats.last_base_matrix_cache_hit);
    cuda_profiling_obj.pushKV("last_mode", cuda_profiling_stats.last_mode);
    cuda_profiling_obj.pushKV("reason", cuda_profiling_stats.reason);
    cuda_obj.pushKV("profiling", std::move(cuda_profiling_obj));

    UniValue cuda_oracle_obj(UniValue::VOBJ);
    cuda_oracle_obj.pushKV("available", cuda_oracle_profile.available);
    cuda_oracle_obj.pushKV("pool_initialized", cuda_oracle_profile.pool_initialized);
    cuda_oracle_obj.pushKV("samples", cuda_oracle_profile.samples);
    cuda_oracle_obj.pushKV("allocation_events", cuda_oracle_profile.allocation_events);
    cuda_oracle_obj.pushKV("reuse_events", cuda_oracle_profile.reuse_events);
    cuda_oracle_obj.pushKV("last_encode_noise_us", cuda_oracle_profile.last_encode_noise_us);
    cuda_oracle_obj.pushKV("last_encode_compress_us", cuda_oracle_profile.last_encode_compress_us);
    cuda_oracle_obj.pushKV("last_submit_wait_us", cuda_oracle_profile.last_submit_wait_us);
    cuda_oracle_obj.pushKV("last_gpu_generation_ms", cuda_oracle_profile.last_gpu_generation_ms);
    cuda_oracle_obj.pushKV("library_source", cuda_oracle_profile.library_source);
    cuda_oracle_obj.pushKV("reason", cuda_oracle_profile.reason);
    cuda_obj.pushKV("oracle_input_generation", std::move(cuda_oracle_obj));
    output.pushKV("cuda_runtime", std::move(cuda_obj));

    std::cout << output.write(2) << std::endl;
    return 0;
}
