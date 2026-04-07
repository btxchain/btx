// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <matmul/matmul_pow.h>
#include <matmul/noise.h>
#include <matmul/transcript.h>
#include <metal/matmul_accel.h>
#include <primitives/block.h>
#include <uint256.h>

#include <univalue.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <limits>
#include <mutex>
#include <numeric>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

struct Options {
    uint32_t n{512};
    uint32_t b{16};
    uint32_t r{8};
    uint32_t batch_size{1};
    uint32_t parallel{1};
    uint32_t warmup{2};
    uint32_t iterations{8};
    bool uploaded_base{true};
    std::optional<uint32_t> pool_slots_override;
    btx::metal::MatMulDigestMode digest_mode{btx::metal::MatMulDigestMode::TRANSCRIPT};
};

struct Sample {
    double request_us{0.0};
    double per_digest_us{0.0};
    double encode_build_us{0.0};
    double encode_fused_prefix_compress_us{0.0};
    double encode_transcript_sha256_us{0.0};
    double submit_wait_us{0.0};
    bool zero_copy_inputs{false};
    bool async_submission{false};
};

class IterationGate
{
public:
    explicit IterationGate(uint32_t participants) : m_participants(participants)
    {
    }

    bool ArriveAndWait()
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        if (m_aborted) {
            return false;
        }

        const uint64_t generation = m_generation;
        ++m_arrived;
        if (m_arrived == m_participants) {
            m_arrived = 0;
            ++m_generation;
            lock.unlock();
            m_cv.notify_all();
            return true;
        }

        m_cv.wait(lock, [&] {
            return m_aborted || generation != m_generation;
        });
        return !m_aborted;
    }

    void Abort()
    {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_aborted = true;
        }
        m_cv.notify_all();
    }

private:
    const uint32_t m_participants;
    uint32_t m_arrived{0};
    uint64_t m_generation{0};
    bool m_aborted{false};
    std::mutex m_mutex;
    std::condition_variable m_cv;
};

struct ThreadRunState {
    std::vector<Sample> samples;
    std::optional<std::chrono::steady_clock::time_point> first_measured_start;
    std::optional<std::chrono::steady_clock::time_point> last_measured_stop;
    std::string error;
};

std::optional<uint64_t> ParseUintArg(std::string_view text)
{
    try {
        size_t consumed{0};
        const uint64_t value = std::stoull(std::string{text}, &consumed, 10);
        if (consumed != text.size()) {
            return std::nullopt;
        }
        return value;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

bool ParseBoolArg(std::string_view text, bool& out)
{
    if (text == "1" || text == "true" || text == "yes") {
        out = true;
        return true;
    }
    if (text == "0" || text == "false" || text == "no") {
        out = false;
        return true;
    }
    return false;
}

uint256 ParseUint256(std::string_view hex)
{
    const auto parsed = uint256::FromHex(hex);
    if (!parsed.has_value()) {
        throw std::runtime_error("invalid uint256 literal in matmul metal benchmark");
    }
    return *parsed;
}

CBlockHeader BuildTemplateHeader(uint32_t n)
{
    CBlockHeader header{};
    header.nVersion = 1;
    header.nTime = 1'738'800'000U;
    header.nBits = 0x2100ffffU;
    header.nNonce = 1U;
    header.nNonce64 = 1U;
    header.hashPrevBlock = ParseUint256("0000000000000000000000000000000000000000000000000000000000000001");
    header.hashMerkleRoot = ParseUint256("0000000000000000000000000000000000000000000000000000000000000002");
    header.matmul_dim = static_cast<uint16_t>(n);
    header.seed_a = ParseUint256("0000000000000000000000000000000000000000000000000000000000000011");
    header.seed_b = ParseUint256("0000000000000000000000000000000000000000000000000000000000000022");
    return header;
}

void PrintUsage(std::ostream& out)
{
    out << "Usage: btx-matmul-metal-bench"
        << " [--n <dim>] [--b <block>] [--r <rank>]"
        << " [--batch-size <count>] [--parallel <threads>]"
        << " [--warmup <count>] [--iterations <count>]"
        << " [--pool-slots <count>]"
        << " [--digest-mode <transcript|product>]"
        << " [--uploaded-base <0|1>]" << std::endl;
}

bool ParseArgs(int argc, char* argv[], Options& options)
{
    auto parse_uint32 = [&](std::string_view arg_name, std::string_view value, uint32_t& out) -> bool {
        const auto parsed = ParseUintArg(value);
        if (!parsed.has_value() || *parsed == 0 || *parsed > std::numeric_limits<uint32_t>::max()) {
            std::cerr << "error: invalid value for " << arg_name << ": " << value << std::endl;
            return false;
        }
        out = static_cast<uint32_t>(*parsed);
        return true;
    };

    for (int i = 1; i < argc; ++i) {
        const std::string arg{argv[i]};
        if (arg == "--help" || arg == "-h") {
            PrintUsage(std::cout);
            return false;
        }

        auto parse_kv = [&](std::string_view name, auto&& setter) -> bool {
            const std::string prefix = std::string{name} + "=";
            if (arg.rfind(prefix, 0) == 0) {
                return setter(std::string_view{arg}.substr(prefix.size()));
            }
            if (arg == name) {
                if (i + 1 >= argc) {
                    std::cerr << "error: " << name << " requires a value" << std::endl;
                    return false;
                }
                return setter(argv[++i]);
            }
            return true;
        };

        bool consumed = false;
        if (arg == "--n" || arg.rfind("--n=", 0) == 0) {
            consumed = true;
            if (!parse_kv("--n", [&](std::string_view value) { return parse_uint32("--n", value, options.n); })) return false;
        } else if (arg == "--b" || arg.rfind("--b=", 0) == 0) {
            consumed = true;
            if (!parse_kv("--b", [&](std::string_view value) { return parse_uint32("--b", value, options.b); })) return false;
        } else if (arg == "--r" || arg.rfind("--r=", 0) == 0) {
            consumed = true;
            if (!parse_kv("--r", [&](std::string_view value) { return parse_uint32("--r", value, options.r); })) return false;
        } else if (arg == "--batch-size" || arg.rfind("--batch-size=", 0) == 0) {
            consumed = true;
            if (!parse_kv("--batch-size", [&](std::string_view value) { return parse_uint32("--batch-size", value, options.batch_size); })) return false;
        } else if (arg == "--parallel" || arg.rfind("--parallel=", 0) == 0) {
            consumed = true;
            if (!parse_kv("--parallel", [&](std::string_view value) { return parse_uint32("--parallel", value, options.parallel); })) return false;
        } else if (arg == "--warmup" || arg.rfind("--warmup=", 0) == 0) {
            consumed = true;
            if (!parse_kv("--warmup", [&](std::string_view value) { return parse_uint32("--warmup", value, options.warmup); })) return false;
        } else if (arg == "--iterations" || arg.rfind("--iterations=", 0) == 0) {
            consumed = true;
            if (!parse_kv("--iterations", [&](std::string_view value) { return parse_uint32("--iterations", value, options.iterations); })) return false;
        } else if (arg == "--pool-slots" || arg.rfind("--pool-slots=", 0) == 0) {
            consumed = true;
            if (!parse_kv("--pool-slots", [&](std::string_view value) {
                    uint32_t parsed{0};
                    if (!parse_uint32("--pool-slots", value, parsed)) {
                        return false;
                    }
                    options.pool_slots_override = parsed;
                    return true;
                })) return false;
        } else if (arg == "--uploaded-base" || arg.rfind("--uploaded-base=", 0) == 0) {
            consumed = true;
            if (!parse_kv("--uploaded-base", [&](std::string_view value) {
                    bool parsed{false};
                    if (!ParseBoolArg(value, parsed)) {
                        std::cerr << "error: invalid value for --uploaded-base: " << value << std::endl;
                        return false;
                    }
                    options.uploaded_base = parsed;
                    return true;
                })) return false;
        } else if (arg == "--digest-mode" || arg.rfind("--digest-mode=", 0) == 0) {
            consumed = true;
            if (!parse_kv("--digest-mode", [&](std::string_view value) {
                    if (value == "transcript") {
                        options.digest_mode = btx::metal::MatMulDigestMode::TRANSCRIPT;
                        return true;
                    }
                    if (value == "product") {
                        options.digest_mode = btx::metal::MatMulDigestMode::PRODUCT_COMMITTED;
                        return true;
                    }
                    std::cerr << "error: invalid value for --digest-mode: " << value << std::endl;
                    return false;
                })) return false;
        }

        if (!consumed) {
            std::cerr << "error: unknown argument: " << arg << std::endl;
            PrintUsage(std::cerr);
            return false;
        }
    }

    return true;
}

double Mean(const std::vector<double>& values)
{
    if (values.empty()) {
        return 0.0;
    }
    const double total = std::accumulate(values.begin(), values.end(), 0.0);
    return total / static_cast<double>(values.size());
}

double Median(std::vector<double> values)
{
    if (values.empty()) {
        return 0.0;
    }
    std::sort(values.begin(), values.end());
    const size_t mid = values.size() / 2;
    if ((values.size() & 1U) == 0U) {
        return (values[mid - 1] + values[mid]) / 2.0;
    }
    return values[mid];
}

UniValue SummarizeSeries(const std::vector<double>& values)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("count", static_cast<uint64_t>(values.size()));
    if (values.empty()) {
        out.pushKV("mean", 0.0);
        out.pushKV("median", 0.0);
        out.pushKV("min", 0.0);
        out.pushKV("max", 0.0);
        return out;
    }

    const auto [min_it, max_it] = std::minmax_element(values.begin(), values.end());
    out.pushKV("mean", Mean(values));
    out.pushKV("median", Median(values));
    out.pushKV("min", *min_it);
    out.pushKV("max", *max_it);
    return out;
}

bool RunDigestRequest(const Options& options,
                      const matmul::Matrix& matrix_a,
                      const matmul::Matrix& matrix_b,
                      const std::vector<uint256>& sigmas,
                      const std::vector<const matmul::field::Element*>& noise_e_l_ptrs,
                      const std::vector<const matmul::field::Element*>& noise_e_r_ptrs,
                      const std::vector<const matmul::field::Element*>& noise_f_l_ptrs,
                      const std::vector<const matmul::field::Element*>& noise_f_r_ptrs,
                      const std::vector<const matmul::field::Element*>& compress_ptrs,
                      std::string& error)
{
    if (options.batch_size == 1) {
        const auto result = btx::metal::ComputeCanonicalTranscriptDigest({
            .n = options.n,
            .b = options.b,
            .r = options.r,
            .digest_mode = options.digest_mode,
            .sigma = sigmas[0],
            .matrix_a = options.uploaded_base ? nullptr : matrix_a.data(),
            .matrix_b = options.uploaded_base ? nullptr : matrix_b.data(),
            .use_uploaded_base_matrices = options.uploaded_base,
            .noise_e_l = noise_e_l_ptrs[0],
            .noise_e_r = noise_e_r_ptrs[0],
            .noise_f_l = noise_f_l_ptrs[0],
            .noise_f_r = noise_f_r_ptrs[0],
            .compress_vec = compress_ptrs[0],
        });
        error = result.error;
        return result.success;
    }

    const auto result = btx::metal::ComputeCanonicalTranscriptDigestBatch({
        .n = options.n,
        .b = options.b,
        .r = options.r,
        .batch_size = options.batch_size,
        .digest_mode = options.digest_mode,
        .sigmas = sigmas.data(),
        .matrix_a = options.uploaded_base ? nullptr : matrix_a.data(),
        .matrix_b = options.uploaded_base ? nullptr : matrix_b.data(),
        .use_uploaded_base_matrices = options.uploaded_base,
        .noise_e_l = noise_e_l_ptrs.data(),
        .noise_e_r = noise_e_r_ptrs.data(),
        .noise_f_l = noise_f_l_ptrs.data(),
        .noise_f_r = noise_f_r_ptrs.data(),
        .compress_vec = compress_ptrs.data(),
    });
    error = result.error;
    return result.success;
}

} // namespace

int main(int argc, char* argv[])
{
    for (int i = 1; i < argc; ++i) {
        const std::string arg{argv[i]};
        if (arg == "--help" || arg == "-h") {
            PrintUsage(std::cout);
            return 0;
        }
    }

    Options options;
    if (!ParseArgs(argc, argv, options)) {
        return argc > 1 ? 1 : 0;
    }

    UniValue output(UniValue::VOBJ);
    UniValue options_obj(UniValue::VOBJ);
    options_obj.pushKV("n", options.n);
    options_obj.pushKV("b", options.b);
    options_obj.pushKV("r", options.r);
    options_obj.pushKV("batch_size", options.batch_size);
    options_obj.pushKV("parallel", options.parallel);
    options_obj.pushKV("warmup", options.warmup);
    options_obj.pushKV("iterations", options.iterations);
    options_obj.pushKV("uploaded_base", options.uploaded_base);
    options_obj.pushKV("digest_mode",
                       options.digest_mode == btx::metal::MatMulDigestMode::PRODUCT_COMMITTED
                           ? "product"
                           : "transcript");
    options_obj.pushKV("pool_slots_override",
                       options.pool_slots_override.has_value() ? UniValue(static_cast<uint64_t>(*options.pool_slots_override))
                                                               : UniValue());
    output.pushKV("options", std::move(options_obj));

    std::optional<std::string> pool_slots_env;
    if (options.pool_slots_override.has_value()) {
        pool_slots_env = std::to_string(*options.pool_slots_override);
#if defined(WIN32)
        _putenv_s("BTX_MATMUL_METAL_POOL_SLOTS", pool_slots_env->c_str());
#else
        setenv("BTX_MATMUL_METAL_POOL_SLOTS", pool_slots_env->c_str(), 1);
#endif
    }

    const auto probe = btx::metal::ProbeMatMulDigestAcceleration();
    const auto kernel_profile = btx::metal::ProbeMatMulKernelProfile();
    UniValue probe_obj(UniValue::VOBJ);
    probe_obj.pushKV("available", probe.available);
    probe_obj.pushKV("reason", probe.reason);
    probe_obj.pushKV("library_source", kernel_profile.library_source);
    output.pushKV("probe", std::move(probe_obj));

    if (!probe.available) {
        std::cout << output.write(2) << std::endl;
        return 1;
    }

    const CBlockHeader template_header = BuildTemplateHeader(options.n);
    const matmul::Matrix matrix_a = matmul::FromSeed(template_header.seed_a, options.n);
    const matmul::Matrix matrix_b = matmul::FromSeed(template_header.seed_b, options.n);

    UniValue upload_obj(UniValue::VOBJ);
    if (options.uploaded_base) {
        const auto uploaded = btx::metal::UploadBaseMatrices({
            .n = options.n,
            .matrix_a = matrix_a.data(),
            .matrix_b = matrix_b.data(),
        });
        upload_obj.pushKV("requested", true);
        upload_obj.pushKV("success", uploaded.success);
        upload_obj.pushKV("error", uploaded.error);
        output.pushKV("uploaded_base", std::move(upload_obj));
        if (!uploaded.success) {
            std::cout << output.write(2) << std::endl;
            return 1;
        }
    } else {
        upload_obj.pushKV("requested", false);
        upload_obj.pushKV("success", false);
        upload_obj.pushKV("error", "");
        output.pushKV("uploaded_base", std::move(upload_obj));
    }

    const uint32_t total_runs = options.warmup + options.iterations;

    std::vector<Sample> samples;
    samples.reserve(static_cast<size_t>(options.iterations) * options.parallel);
    const auto pool_before = btx::metal::ProbeMatMulBufferPool();
    std::optional<std::chrono::steady_clock::time_point> aggregate_start;
    std::optional<std::chrono::steady_clock::time_point> aggregate_stop;

    if (options.parallel == 1) {
        CBlockHeader nonce_header{template_header};
        std::vector<matmul::noise::NoisePair> noises;
        std::vector<std::vector<matmul::field::Element>> compress_vectors;
        std::vector<uint256> sigmas;
        std::vector<const matmul::field::Element*> noise_e_l_ptrs(options.batch_size);
        std::vector<const matmul::field::Element*> noise_e_r_ptrs(options.batch_size);
        std::vector<const matmul::field::Element*> noise_f_l_ptrs(options.batch_size);
        std::vector<const matmul::field::Element*> noise_f_r_ptrs(options.batch_size);
        std::vector<const matmul::field::Element*> compress_ptrs(options.batch_size);
        noises.reserve(options.batch_size);
        compress_vectors.reserve(options.batch_size);
        sigmas.reserve(options.batch_size);

        for (uint32_t run = 0; run < total_runs; ++run) {
            noises.clear();
            compress_vectors.clear();
            sigmas.clear();
            for (uint32_t i = 0; i < options.batch_size; ++i) {
                nonce_header.nNonce64 += 1;
                nonce_header.nNonce = static_cast<uint32_t>(nonce_header.nNonce64);
                const uint256 sigma = matmul::DeriveSigma(nonce_header);
                sigmas.push_back(sigma);
                noises.push_back(matmul::noise::Generate(sigma, options.n, options.r));
                compress_vectors.push_back(matmul::transcript::DeriveCompressionVector(sigma, options.b));
                noise_e_l_ptrs[i] = noises[i].E_L.data();
                noise_e_r_ptrs[i] = noises[i].E_R.data();
                noise_f_l_ptrs[i] = noises[i].F_L.data();
                noise_f_r_ptrs[i] = noises[i].F_R.data();
                compress_ptrs[i] = compress_vectors[i].data();
            }

            std::string error;
            const auto start = std::chrono::steady_clock::now();
            const bool ok = RunDigestRequest(options,
                                             matrix_a,
                                             matrix_b,
                                             sigmas,
                                             noise_e_l_ptrs,
                                             noise_e_r_ptrs,
                                             noise_f_l_ptrs,
                                             noise_f_r_ptrs,
                                             compress_ptrs,
                                             error);
            const auto stop = std::chrono::steady_clock::now();
            if (!ok) {
                output.pushKV("error", error);
                std::cout << output.write(2) << std::endl;
                return 1;
            }

            if (run >= options.warmup) {
                const auto profiling = btx::metal::ProbeMatMulProfilingStats();
                const double request_us = std::chrono::duration<double, std::micro>(stop - start).count();
                samples.push_back({
                    .request_us = request_us,
                    .per_digest_us = request_us / static_cast<double>(options.batch_size),
                    .encode_build_us = profiling.last_encode_build_perturbed_us,
                    .encode_fused_prefix_compress_us = profiling.last_encode_fused_prefix_compress_us,
                    .encode_transcript_sha256_us = profiling.last_encode_transcript_sha256_us,
                    .submit_wait_us = profiling.last_submit_wait_us,
                    .zero_copy_inputs = profiling.last_zero_copy_inputs,
                    .async_submission = profiling.last_async_submission,
                });
                if (!aggregate_start.has_value()) {
                    aggregate_start = start;
                }
                aggregate_stop = stop;
            }
        }
    } else {
        IterationGate gate(options.parallel);
        std::vector<ThreadRunState> thread_states(options.parallel);
        std::vector<std::thread> workers;
        workers.reserve(options.parallel);

        for (uint32_t thread_index = 0; thread_index < options.parallel; ++thread_index) {
            workers.emplace_back([&, thread_index] {
                CBlockHeader nonce_header{template_header};
                nonce_header.nNonce64 += static_cast<uint64_t>(thread_index) << 32;
                nonce_header.nNonce = static_cast<uint32_t>(nonce_header.nNonce64);

                std::vector<matmul::noise::NoisePair> noises;
                std::vector<std::vector<matmul::field::Element>> compress_vectors;
                std::vector<uint256> sigmas;
                std::vector<const matmul::field::Element*> noise_e_l_ptrs(options.batch_size);
                std::vector<const matmul::field::Element*> noise_e_r_ptrs(options.batch_size);
                std::vector<const matmul::field::Element*> noise_f_l_ptrs(options.batch_size);
                std::vector<const matmul::field::Element*> noise_f_r_ptrs(options.batch_size);
                std::vector<const matmul::field::Element*> compress_ptrs(options.batch_size);
                noises.reserve(options.batch_size);
                compress_vectors.reserve(options.batch_size);
                sigmas.reserve(options.batch_size);

                auto& state = thread_states[thread_index];
                state.samples.reserve(options.iterations);
                for (uint32_t run = 0; run < total_runs; ++run) {
                    noises.clear();
                    compress_vectors.clear();
                    sigmas.clear();
                    for (uint32_t i = 0; i < options.batch_size; ++i) {
                        nonce_header.nNonce64 += 1;
                        nonce_header.nNonce = static_cast<uint32_t>(nonce_header.nNonce64);
                        const uint256 sigma = matmul::DeriveSigma(nonce_header);
                        sigmas.push_back(sigma);
                        noises.push_back(matmul::noise::Generate(sigma, options.n, options.r));
                        compress_vectors.push_back(matmul::transcript::DeriveCompressionVector(sigma, options.b));
                        noise_e_l_ptrs[i] = noises[i].E_L.data();
                        noise_e_r_ptrs[i] = noises[i].E_R.data();
                        noise_f_l_ptrs[i] = noises[i].F_L.data();
                        noise_f_r_ptrs[i] = noises[i].F_R.data();
                        compress_ptrs[i] = compress_vectors[i].data();
                    }

                    if (!gate.ArriveAndWait()) {
                        return;
                    }

                    std::string error;
                    const auto start = std::chrono::steady_clock::now();
                    const bool ok = RunDigestRequest(options,
                                                     matrix_a,
                                                     matrix_b,
                                                     sigmas,
                                                     noise_e_l_ptrs,
                                                     noise_e_r_ptrs,
                                                     noise_f_l_ptrs,
                                                     noise_f_r_ptrs,
                                                     compress_ptrs,
                                                     error);
                    const auto stop = std::chrono::steady_clock::now();
                    if (!ok) {
                        state.error = error;
                        gate.Abort();
                        return;
                    }

                    if (run >= options.warmup) {
                        const auto profiling = btx::metal::ProbeMatMulProfilingStats();
                        const double request_us = std::chrono::duration<double, std::micro>(stop - start).count();
                        state.samples.push_back({
                            .request_us = request_us,
                            .per_digest_us = request_us / static_cast<double>(options.batch_size),
                            .encode_build_us = profiling.last_encode_build_perturbed_us,
                            .encode_fused_prefix_compress_us = profiling.last_encode_fused_prefix_compress_us,
                            .encode_transcript_sha256_us = profiling.last_encode_transcript_sha256_us,
                            .submit_wait_us = profiling.last_submit_wait_us,
                            .zero_copy_inputs = profiling.last_zero_copy_inputs,
                            .async_submission = profiling.last_async_submission,
                        });
                        if (!state.first_measured_start.has_value()) {
                            state.first_measured_start = start;
                        }
                        state.last_measured_stop = stop;
                    }
                }
            });
        }

        for (auto& worker : workers) {
            worker.join();
        }

        for (const auto& state : thread_states) {
            if (!state.error.empty()) {
                output.pushKV("error", state.error);
                std::cout << output.write(2) << std::endl;
                return 1;
            }
            samples.insert(samples.end(), state.samples.begin(), state.samples.end());
            if (state.first_measured_start.has_value()) {
                aggregate_start = aggregate_start.has_value()
                    ? std::min(*aggregate_start, *state.first_measured_start)
                    : state.first_measured_start;
            }
            if (state.last_measured_stop.has_value()) {
                aggregate_stop = aggregate_stop.has_value()
                    ? std::max(*aggregate_stop, *state.last_measured_stop)
                    : state.last_measured_stop;
            }
        }
    }

    const auto pool_after = btx::metal::ProbeMatMulBufferPool();

    std::vector<double> request_us_values;
    std::vector<double> per_digest_us_values;
    std::vector<double> encode_build_us_values;
    std::vector<double> encode_fused_us_values;
    std::vector<double> encode_hash_us_values;
    std::vector<double> submit_wait_us_values;
    uint64_t zero_copy_samples{0};
    uint64_t async_samples{0};
    request_us_values.reserve(samples.size());
    per_digest_us_values.reserve(samples.size());
    encode_build_us_values.reserve(samples.size());
    encode_fused_us_values.reserve(samples.size());
    encode_hash_us_values.reserve(samples.size());
    submit_wait_us_values.reserve(samples.size());
    for (const auto& sample : samples) {
        request_us_values.push_back(sample.request_us);
        per_digest_us_values.push_back(sample.per_digest_us);
        encode_build_us_values.push_back(sample.encode_build_us);
        encode_fused_us_values.push_back(sample.encode_fused_prefix_compress_us);
        encode_hash_us_values.push_back(sample.encode_transcript_sha256_us);
        submit_wait_us_values.push_back(sample.submit_wait_us);
        if (sample.zero_copy_inputs) {
            ++zero_copy_samples;
        }
        if (sample.async_submission) {
            ++async_samples;
        }
    }

    UniValue summary(UniValue::VOBJ);
    summary.pushKV("requests_measured", static_cast<uint64_t>(samples.size()));
    summary.pushKV("digests_measured", static_cast<uint64_t>(samples.size()) * options.batch_size);
    const double mean_per_digest_us = Mean(per_digest_us_values);
    const double mean_request_digests_per_sec = mean_per_digest_us > 0.0 ? 1'000'000.0 / mean_per_digest_us : 0.0;
    summary.pushKV("mean_request_digests_per_sec", mean_request_digests_per_sec);
    summary.pushKV("request_us", SummarizeSeries(request_us_values));
    summary.pushKV("per_digest_us", SummarizeSeries(per_digest_us_values));
    summary.pushKV("zero_copy_samples", zero_copy_samples);
    summary.pushKV("async_samples", async_samples);
    if (aggregate_start.has_value() && aggregate_stop.has_value() && *aggregate_stop >= *aggregate_start) {
        const double aggregate_wall_us = std::chrono::duration<double, std::micro>(*aggregate_stop - *aggregate_start).count();
        const double aggregate_requests_per_sec = aggregate_wall_us > 0.0
            ? static_cast<double>(samples.size()) * 1'000'000.0 / aggregate_wall_us
            : 0.0;
        const double aggregate_digests_per_sec = aggregate_wall_us > 0.0
            ? static_cast<double>(samples.size()) * options.batch_size * 1'000'000.0 / aggregate_wall_us
            : 0.0;
        summary.pushKV("aggregate_wall_us", aggregate_wall_us);
        summary.pushKV("aggregate_requests_per_sec", aggregate_requests_per_sec);
        summary.pushKV("aggregate_digests_per_sec", aggregate_digests_per_sec);
    } else {
        summary.pushKV("aggregate_wall_us", 0.0);
        summary.pushKV("aggregate_requests_per_sec", 0.0);
        summary.pushKV("aggregate_digests_per_sec", 0.0);
    }
    summary.pushKV("parallel_profiling_reliable", options.parallel == 1);
    if (options.parallel == 1) {
        summary.pushKV("encode_build_perturbed_us", SummarizeSeries(encode_build_us_values));
        summary.pushKV("encode_fused_prefix_compress_us", SummarizeSeries(encode_fused_us_values));
        summary.pushKV("encode_transcript_sha256_us", SummarizeSeries(encode_hash_us_values));
        summary.pushKV("submit_wait_us", SummarizeSeries(submit_wait_us_values));
    } else {
        summary.pushKV("encode_build_perturbed_us", UniValue());
        summary.pushKV("encode_fused_prefix_compress_us", UniValue());
        summary.pushKV("encode_transcript_sha256_us", UniValue());
        summary.pushKV("submit_wait_us", UniValue());
    }
    output.pushKV("summary", std::move(summary));

    UniValue pool_obj(UniValue::VOBJ);
    pool_obj.pushKV("allocation_events_before", pool_before.allocation_events);
    pool_obj.pushKV("allocation_events_after", pool_after.allocation_events);
    pool_obj.pushKV("reuse_events_before", pool_before.reuse_events);
    pool_obj.pushKV("reuse_events_after", pool_after.reuse_events);
    pool_obj.pushKV("wait_events_before", pool_before.wait_events);
    pool_obj.pushKV("wait_events_after", pool_after.wait_events);
    pool_obj.pushKV("slot_count_before", pool_before.slot_count);
    pool_obj.pushKV("slot_count_after", pool_after.slot_count);
    pool_obj.pushKV("active_slots_before", pool_before.active_slots);
    pool_obj.pushKV("active_slots_after", pool_after.active_slots);
    pool_obj.pushKV("high_water_slots_before", pool_before.high_water_slots);
    pool_obj.pushKV("high_water_slots_after", pool_after.high_water_slots);
    pool_obj.pushKV("allocation_events_delta", pool_after.allocation_events - pool_before.allocation_events);
    pool_obj.pushKV("reuse_events_delta", pool_after.reuse_events - pool_before.reuse_events);
    pool_obj.pushKV("wait_events_delta", pool_after.wait_events - pool_before.wait_events);
    pool_obj.pushKV("contention_observed", pool_after.wait_events > pool_before.wait_events);
    output.pushKV("buffer_pool", std::move(pool_obj));

    std::cout << output.write(2) << std::endl;
    return 0;
}
