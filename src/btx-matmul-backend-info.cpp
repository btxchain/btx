// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <matmul/backend_capabilities.h>
#include <metal/matmul_accel.h>
#include <metal/oracle_accel.h>

#include <univalue.h>

#include <iostream>
#include <string>
#include <vector>

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

    std::cout << output.write(2) << std::endl;
    return 0;
}
