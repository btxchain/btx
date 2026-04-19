// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <matmul/backend_capabilities.h>

#include <cuda/matmul_accel.h>
#include <metal/matmul_accel.h>

#include <algorithm>
#include <utility>

namespace matmul::backend {
namespace {

char ToLowerAscii(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return static_cast<char>(c + ('a' - 'A'));
    }
    return c;
}

std::string ToLower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](char c) {
        return ToLowerAscii(c);
    });
    return value;
}

Capability CpuCapability()
{
    return Capability{
        .compiled = true,
        .available = true,
        .reason = "always_available",
    };
}

Capability MetalCapability()
{
#if defined(BTX_ENABLE_METAL)
    const auto probe = btx::metal::ProbeMatMulDigestAcceleration();

    Capability capability{
        .compiled = true,
        .available = probe.available,
        .reason = probe.reason,
    };
    return capability;
#else
    return Capability{
        .compiled = false,
        .available = false,
        .reason = "disabled_by_build",
    };
#endif
}

Capability CudaCapability()
{
#if defined(BTX_ENABLE_CUDA_EXPERIMENTAL)
    const auto probe = btx::cuda::ProbeMatMulDigestAcceleration();
    return Capability{
        .compiled = true,
        .available = probe.available,
        .reason = probe.reason,
    };
#else
    return Capability{
        .compiled = false,
        .available = false,
        .reason = "disabled_by_build",
    };
#endif
}

Kind ParseKind(const std::string& requested, bool& known)
{
    const std::string normalized = ToLower(requested);
    if (normalized == "cpu") {
        known = true;
        return Kind::CPU;
    }
    if (normalized == "metal" || normalized == "mlx") {
        known = true;
        return Kind::METAL;
    }
    if (normalized == "cuda") {
        known = true;
        return Kind::CUDA;
    }

    known = false;
    return Kind::CPU;
}

} // namespace

std::string ToString(Kind kind)
{
    switch (kind) {
    case Kind::CPU:
        return "cpu";
    case Kind::METAL:
        return "metal";
    case Kind::CUDA:
        return "cuda";
    }

    return "cpu";
}

Capability CapabilityFor(Kind kind)
{
    switch (kind) {
    case Kind::CPU:
        return CpuCapability();
    case Kind::METAL:
        return MetalCapability();
    case Kind::CUDA:
        return CudaCapability();
    }

    return CpuCapability();
}

std::vector<std::pair<Kind, Capability>> AllCapabilities()
{
    return {
        {Kind::CPU, CapabilityFor(Kind::CPU)},
        {Kind::METAL, CapabilityFor(Kind::METAL)},
        {Kind::CUDA, CapabilityFor(Kind::CUDA)},
    };
}

Selection ResolveRequestedBackend(const std::string& requested)
{
    Selection selection;
    selection.requested_input = requested;

    bool known{false};
    selection.requested = ParseKind(requested, known);
    selection.requested_known = known;

    if (!known) {
        selection.active = Kind::CPU;
        selection.reason = "unknown_backend_fallback_to_cpu";
        return selection;
    }

    const auto requested_capability = CapabilityFor(selection.requested);
    if (requested_capability.available) {
        selection.active = selection.requested;
        selection.reason = "requested_backend_available";
        return selection;
    }

    selection.active = Kind::CPU;
    selection.reason = ToString(selection.requested) + "_unavailable_fallback_to_cpu:" + requested_capability.reason;
    return selection;
}

} // namespace matmul::backend
