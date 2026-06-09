// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cuda/cuda_context.h>

#include <cuda_runtime_api.h>

#include <logging.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <climits>
#include <csetjmp>
#include <csignal>
#include <cstdlib>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace btx::cuda {
namespace {

// Default minimum compute capability the bundled CUDA kernels are built and
// validated for (sm_80 / Ampere). A pool independently validated GPU-vs-CPU
// digest equivalence on Pascal (sm_6x), so operators can opt in to running on
// older GPUs via BTX_CUDA_ALLOW_OLDER_GPUS, which lowers the floor to 6.
constexpr int DEFAULT_MIN_SUPPORTED_COMPUTE_CAPABILITY_MAJOR{8};
constexpr int OPT_IN_MIN_SUPPORTED_COMPUTE_CAPABILITY_MAJOR{6};

std::string ComputeCapabilityString(int major, int minor)
{
    return "sm_" + std::to_string(major) + std::to_string(minor);
}

std::string TrimAscii(const std::string& value)
{
    size_t begin{0};
    while (begin < value.size() && (value[begin] == ' ' || value[begin] == '\t' || value[begin] == '\n' || value[begin] == '\r')) {
        ++begin;
    }

    size_t end{value.size()};
    while (end > begin && (value[end - 1] == ' ' || value[end - 1] == '\t' || value[end - 1] == '\n' || value[end - 1] == '\r')) {
        --end;
    }

    return value.substr(begin, end - begin);
}

bool AllowOlderGpusRequested()
{
    const char* env = std::getenv("BTX_CUDA_ALLOW_OLDER_GPUS");
    if (env == nullptr || env[0] == '\0') {
        return false;
    }
    // Treat "0"/"false"/"no"/"off" (any case) as disabled; anything else enables.
    std::string value = TrimAscii(env);
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    if (value == "0" || value == "false" || value == "no" || value == "off") {
        return false;
    }
    return true;
}

int MinSupportedComputeCapabilityMajor()
{
    static const int resolved = [] {
        if (AllowOlderGpusRequested()) {
            LogPrintf("MATMUL NOTE: BTX_CUDA_ALLOW_OLDER_GPUS is set; lowering minimum CUDA "
                      "compute capability gate from sm_%d0 to sm_%d0 (opt-in; GPU-vs-CPU digest "
                      "equivalence must be validated for your hardware)\n",
                      DEFAULT_MIN_SUPPORTED_COMPUTE_CAPABILITY_MAJOR,
                      OPT_IN_MIN_SUPPORTED_COMPUTE_CAPABILITY_MAJOR);
            return OPT_IN_MIN_SUPPORTED_COMPUTE_CAPABILITY_MAJOR;
        }
        return DEFAULT_MIN_SUPPORTED_COMPUTE_CAPABILITY_MAJOR;
    }();
    return resolved;
}

bool ParseNonNegativeInt(const std::string& value, int& parsed)
{
    const std::string trimmed = TrimAscii(value);
    if (trimmed.empty()) {
        return false;
    }

    char* end{nullptr};
    errno = 0;
    const long result = std::strtol(trimmed.c_str(), &end, 10);
    if (errno != 0 || end == trimmed.c_str() || *end != '\0' || result < 0 || result > INT_MAX) {
        return false;
    }

    parsed = static_cast<int>(result);
    return true;
}

std::vector<std::string> SplitCommaList(const std::string& value)
{
    std::vector<std::string> parts;
    size_t begin{0};
    while (begin <= value.size()) {
        const size_t comma = value.find(',', begin);
        if (comma == std::string::npos) {
            parts.push_back(value.substr(begin));
            break;
        }
        parts.push_back(value.substr(begin, comma - begin));
        begin = comma + 1;
    }
    return parts;
}

const CudaDeviceInfo* FindVisibleDevice(const CudaTopologyProbe& topology, int device_index)
{
    for (const auto& device : topology.visible_devices) {
        if (device.device_index == device_index) {
            return &device;
        }
    }
    return nullptr;
}

uint32_t QueryDeviceAttributeUInt(int device_index, cudaDeviceAttr attribute)
{
    int value{0};
    const cudaError_t error = cudaDeviceGetAttribute(&value, attribute, device_index);
    if (error != cudaSuccess || value <= 0) {
        return 0;
    }
    return static_cast<uint32_t>(value);
}

std::string UnsupportedDeviceSummary(const CudaTopologyProbe& topology)
{
    int best_major{0};
    int best_minor{0};
    bool saw_too_old_device{false};
    std::string first_failure_reason;
    for (const auto& device : topology.visible_devices) {
        best_major = std::max(best_major, static_cast<int>(device.compute_capability_major));
        if (best_major == static_cast<int>(device.compute_capability_major)) {
            best_minor = std::max(best_minor, static_cast<int>(device.compute_capability_minor));
        }
        if (!device.supported && device.reason.rfind("device_compute_capability_too_old:", 0) == 0) {
            saw_too_old_device = true;
        } else if (!device.supported && first_failure_reason.empty()) {
            first_failure_reason = device.reason;
        }
    }

    if (saw_too_old_device) {
        return "device_compute_capability_too_old:" + ComputeCapabilityString(best_major, best_minor);
    }
    if (!first_failure_reason.empty()) {
        return first_failure_reason;
    }
    return "no_supported_device";
}

CudaTopologyProbe ProbeCudaHardwareTopology()
{
    CudaTopologyProbe probe;
    probe.compiled = true;

    // Make CUDA module/PTX resolution eager and deterministic before the first runtime call. CUDA's
    // default lazy loading defers PTX JIT to the first API call; on some driver/toolkit combinations
    // (e.g. Blackwell sm_120 + CUDA 13.x + WSL2) that JIT runs inside libcuda during this very probe
    // and can crash in libnvidia-ptxjitcompiler BELOW the cudaError_t boundary, segfaulting the whole
    // process (issue #46). Eager loading surfaces incompatibilities as ordinary error codes we handle
    // below. Do not override an explicit operator choice.
    static const bool cuda_module_loading_pinned = [] {
#if defined(_WIN32)
        if (std::getenv("CUDA_MODULE_LOADING") == nullptr) {
            _putenv_s("CUDA_MODULE_LOADING", "EAGER");
        }
#else
        setenv("CUDA_MODULE_LOADING", "EAGER", /*overwrite=*/0);
#endif
        return true;
    }();
    (void)cuda_module_loading_pinned;

    int runtime_version{0};
    const cudaError_t runtime_version_error = cudaRuntimeGetVersion(&runtime_version);
    if (runtime_version_error != cudaSuccess) {
        probe.reason = "cuda_runtime_unavailable:" + std::string(cudaGetErrorString(runtime_version_error));
        return probe;
    }
    probe.runtime_version = static_cast<uint32_t>(runtime_version);

    int driver_api_version{0};
    const cudaError_t driver_version_error = cudaDriverGetVersion(&driver_api_version);
    if (driver_version_error == cudaSuccess) {
        probe.driver_api_version = static_cast<uint32_t>(driver_api_version);
    }

    int device_count{0};
    const cudaError_t count_error = cudaGetDeviceCount(&device_count);
    if (count_error != cudaSuccess) {
        probe.reason = count_error == cudaErrorNoDevice
            ? "no_supported_device"
            : "cuda_runtime_unavailable:" + std::string(cudaGetErrorString(count_error));
        return probe;
    }
    if (device_count <= 0) {
        probe.reason = "no_supported_device";
        return probe;
    }

    for (int device_index = 0; device_index < device_count; ++device_index) {
        cudaDeviceProp properties{};
        const cudaError_t properties_error = cudaGetDeviceProperties(&properties, device_index);
        if (properties_error != cudaSuccess) {
            CudaDeviceInfo device;
            device.device_index = device_index;
            device.supported = false;
            device.reason = "cuda_device_properties_unavailable:" + std::string(cudaGetErrorString(properties_error));
            probe.visible_devices.push_back(std::move(device));
            continue;
        }

        CudaDeviceInfo device;
        device.device_index = device_index;
        device.supported = properties.major >= MinSupportedComputeCapabilityMajor();
        device.reason = device.supported
            ? "ready"
            : "device_compute_capability_too_old:" + ComputeCapabilityString(properties.major, properties.minor);
        device.device_name = properties.name;
        device.compute_capability_major = static_cast<uint32_t>(properties.major);
        device.compute_capability_minor = static_cast<uint32_t>(properties.minor);
        device.global_memory_bytes = static_cast<uint64_t>(properties.totalGlobalMem);
        device.multiprocessor_count = static_cast<uint32_t>(std::max(properties.multiProcessorCount, 0));
        device.clock_rate_khz = QueryDeviceAttributeUInt(device_index, cudaDevAttrClockRate);
        device.memory_clock_rate_khz = QueryDeviceAttributeUInt(device_index, cudaDevAttrMemoryClockRate);
        device.memory_bus_width_bits = static_cast<uint32_t>(std::max(properties.memoryBusWidth, 0));
        device.pci_domain_id = static_cast<uint32_t>(std::max(properties.pciDomainID, 0));
        device.pci_bus_id = static_cast<uint32_t>(std::max(properties.pciBusID, 0));
        device.pci_device_id = static_cast<uint32_t>(std::max(properties.pciDeviceID, 0));
        probe.visible_devices.push_back(std::move(device));
    }

    probe.available = true;
    probe.reason = "hardware_enumerated";
    return probe;
}

const CudaTopologyProbe& CachedCudaHardwareTopology()
{
    static std::once_flag once;
    static CudaTopologyProbe probe;
    std::call_once(once, [] {
#if !defined(_WIN32)
        // A backend *probe* must never crash the binary. If the CUDA driver faults internally (e.g.
        // a ptxjitcompiler SIGSEGV on an unsupported arch, issue #46) despite eager module loading,
        // catch it and report the backend unavailable so callers fall back to CPU. Last-resort
        // backstop; the eager-loading change in ProbeCudaHardwareTopology() prevents the fault in the
        // first place on the reported configuration.
        static sigjmp_buf cuda_probe_jmp;
        struct sigaction old_segv{};
        struct sigaction old_ill{};
        struct sigaction guard{};
        guard.sa_flags = 0;
        sigemptyset(&guard.sa_mask);
        guard.sa_handler = [](int) { siglongjmp(cuda_probe_jmp, 1); };
        sigaction(SIGSEGV, &guard, &old_segv);
        sigaction(SIGILL, &guard, &old_ill);
        if (sigsetjmp(cuda_probe_jmp, 1) == 0) {
            probe = ProbeCudaHardwareTopology();
        } else {
            probe = CudaTopologyProbe{};
            probe.compiled = true;
            probe.available = false;
            probe.reason = "cuda_driver_probe_faulted";
        }
        sigaction(SIGSEGV, &old_segv, nullptr);
        sigaction(SIGILL, &old_ill, nullptr);
#else
        probe = ProbeCudaHardwareTopology();
#endif
    });
    return probe;
}

} // namespace

void ResolveSelectedCudaDevices(CudaTopologyProbe& topology, const std::string& device_selection)
{
    topology.selected_devices.clear();

    const std::string selection = TrimAscii(device_selection);
    if (selection.empty() || selection == "auto" || selection == "all") {
        for (const auto& device : topology.visible_devices) {
            if (device.supported) {
                topology.selected_devices.push_back(device);
            }
        }

        topology.available = !topology.selected_devices.empty();
        topology.reason = topology.available ? "ready" : UnsupportedDeviceSummary(topology);
        return;
    }

    std::vector<int> selected_indices;
    for (const auto& token : SplitCommaList(selection)) {
        int parsed{-1};
        if (!ParseNonNegativeInt(token, parsed)) {
            topology.available = false;
            topology.reason = "invalid_cuda_device_selection:" + TrimAscii(token);
            return;
        }
        if (std::find(selected_indices.begin(), selected_indices.end(), parsed) == selected_indices.end()) {
            selected_indices.push_back(parsed);
        }
    }

    for (const int device_index : selected_indices) {
        const CudaDeviceInfo* device = FindVisibleDevice(topology, device_index);
        if (device == nullptr) {
            topology.available = false;
            topology.reason = "selected_cuda_device_not_visible:" + std::to_string(device_index);
            topology.selected_devices.clear();
            return;
        }
        if (!device->supported) {
            topology.available = false;
            topology.reason = "selected_cuda_device_unsupported:" + std::to_string(device_index) + ":" + device->reason;
            topology.selected_devices.clear();
            return;
        }
        topology.selected_devices.push_back(*device);
    }

    topology.available = !topology.selected_devices.empty();
    topology.reason = topology.available ? "ready" : "no_supported_device";
}

CudaTopologyProbe ProbeCudaTopology()
{
    CudaTopologyProbe probe = CachedCudaHardwareTopology();
    if (probe.visible_devices.empty()) {
        return probe;
    }
    const char* env_devices = std::getenv("BTX_MATMUL_CUDA_DEVICES");
    ResolveSelectedCudaDevices(probe, env_devices != nullptr ? env_devices : "");
    return probe;
}

CudaRuntimeProbe ProbeCudaRuntime()
{
    const auto topology = ProbeCudaTopology();
    CudaRuntimeProbe probe;
    probe.compiled = topology.compiled;
    probe.available = topology.available;
    probe.reason = topology.reason;
    probe.driver_api_version = topology.driver_api_version;
    probe.runtime_version = topology.runtime_version;

    if (!topology.selected_devices.empty()) {
        const auto& device = topology.selected_devices.front();
        probe.available = true;
        probe.reason = topology.reason;
        probe.device_index = device.device_index;
        probe.device_name = device.device_name;
        probe.compute_capability_major = device.compute_capability_major;
        probe.compute_capability_minor = device.compute_capability_minor;
        probe.global_memory_bytes = device.global_memory_bytes;
        probe.multiprocessor_count = device.multiprocessor_count;
    }

    return probe;
}

} // namespace btx::cuda
