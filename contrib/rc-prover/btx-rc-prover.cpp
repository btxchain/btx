// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// Experimental operator-owned ExactReplay service. See README.md for trust limits.
#include <arith_uint256.h>
#include <chainparams.h>
#include <cuda/cuda_context.h>
#include <cuda/matmul_v4_lt_tensor_gemm.h>
#include <matmul/exact_gemm_resolve.h>
#include <matmul/matmul_v4_rc_accelerator_scheduler.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_gkr.h>
#include <matmul/matmul_v4_rc_production_canary.h>
#include <primitives/block.h>
#include <streams.h>
#include <univalue.h>
#include <util/chaintype.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <chrono>
#include <cstdio>
#include <limits>
#include <stdexcept>
#include <string>
// Include WinSock after core headers: Windows STRICT must not rewrite core enums.
#include "request_protocol.h"
#include "request_listener.h"
#include "token_file.h"

const TranslateFn G_TRANSLATION_FUN{nullptr};
namespace {
rc_prover::ServiceState g_service;

bool Qualify()
{
    rc_prover::ConfigureReplayPolicy();
    const auto& consensus{Params().GetConsensus()};
    auto resolved{matmul_v4::accel::ResolveExactGemmBackendForRC()};
    g_service.provider = resolved.provider;
    if (!resolved.self_qualified || resolved.backend.gemm_s8s8 == nullptr) return false;
    const int32_t height{consensus.nMatMulRCHeight};
    if (height <= 0 || height == std::numeric_limits<int32_t>::max()) return false;
    const auto episode{matmul::v4::rc::ResolveRCEpisodeParams(consensus, height)};
    if (!matmul::v4::rc::ValidateRCEpisodeParams(episode)) return false;
    g_service.workspace_required = matmul::v4::rc::EstimateRCExactReplayWorkspaceBytes(episode);
    if (resolved.provider.find("cuda") != std::string::npos) {
        const auto probe{btx::cuda::ProbeCudaRuntime()};
        if (probe.available) g_service.workspace_capacity = probe.global_memory_bytes - probe.global_memory_bytes / 4;
    } else if (resolved.provider.find("metal") != std::string::npos) {
        const auto probe{matmul_v4::metal::ProbeLtMetalArch()};
        if (probe.available) g_service.workspace_capacity = probe.recommended_working_set_bytes - probe.recommended_working_set_bytes / 4;
    }
    matmul::v4::rc::GetRCAcceleratorScheduler().ConfigureWorkspaceCapacity(resolved.provider, g_service.workspace_capacity);
    if (!matmul::v4::rc::RCExactReplayWorkspaceFits(episode, g_service.workspace_capacity)) {
        std::fprintf(stderr, "GPU workspace unavailable/too small: required=%llu usable=%llu\n",
                     static_cast<unsigned long long>(g_service.workspace_required), static_cast<unsigned long long>(g_service.workspace_capacity));
        return false;
    }
    const auto canary{matmul::v4::rc::RunRCProductionStartupCanary(
        resolved.provider, resolved.backend, consensus, height)};
    g_service.canary = matmul::v4::rc::RCProductionCanaryOutcomeName(canary.outcome);
    resolved = matmul_v4::accel::ResolveExactGemmBackendForRC();
    g_service.provider = resolved.provider;
    if (!rc_prover::CanaryAdmits(canary) || !resolved.self_qualified ||
        !resolved.production_eligible || !resolved.activation_ready || resolved.backend.gemm_s8s8 == nullptr) return false;
    std::string reason;
    const auto capability{matmul::v4::rc::GetRCProductionProviderCapability(
        resolved.provider, resolved.backend, consensus, height, &reason)};
    return capability && matmul::v4::rc::RegisterRCExactReplayAlternateProvider(
        {.backend = resolved.backend, .provider = resolved.provider, .capability = *capability}, &reason);
}
int Serve(uint16_t port)
{
    using namespace rc_prover;
    RequestListener listener{port};
    std::fprintf(stderr, "Experimental RC verifier listening on loopback:%u\n", listener.Port());
    for (;;) {
        auto incoming{listener.Next()};
        const auto reply{ProcessRequest(incoming.line, Params().GetConsensus(), g_service,
            [](const CBlockHeader& header, const matmul::v4::rc::RCEpisodeParams& params,
               int32_t height, const arith_uint256& target) {
                return matmul::v4::rc::VerifyBoundedExactReplay(header, params, height, &target, 1);
            })};
        (void)WriteAll(incoming.socket->Get(), reply.write() + "\n", std::chrono::seconds(5));
        // One request per connection; GPU execution stays on this single thread.
    }
}
} // namespace

int main(int argc, char** argv)
{
    try {
        std::string token_file;
        unsigned long port{0};
        for (int i{1}; i < argc; ++i) {
            const std::string a{argv[i]};
            if (a == "--help") {
                std::puts("Experimental btx-rc-prover --serve=PORT --token-file=PATH\n"
                          "Loopback only. Mainnet Profile-1. One JSON request per connection.\n"
                          "No node integration or release qualification is implied.");
                return 0;
            }
            if (a.starts_with("--serve=")) {
                size_t used{0};
                const std::string value{a.substr(8)};
                port = std::stoul(value, &used);
                if (used != value.size() || port == 0 || port > 65535) throw std::runtime_error("invalid port");
            } else if (a.starts_with("--token-file=")) token_file = a.substr(13);
            else throw std::runtime_error("unknown argument");
        }
        if (!port || token_file.empty()) throw std::runtime_error("serve and token-file are required");
        g_service.token = rc_prover::LoadPrivateToken(token_file);
        SelectParams(ChainType::MAIN);
        rc_prover::Network network;
        if (!network.Ok()) throw std::runtime_error("socket initialization failed");
        g_service.ready = Qualify();
        if (!g_service.ready) throw std::runtime_error("GPU qualification/canary failed; no listener started");
        return Serve(static_cast<uint16_t>(port));
    } catch (const std::exception& e) {
        std::fprintf(stderr, "btx-rc-prover: %s\n", e.what());
        return 1;
    }
}
