// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// The real protocol handler with a CPU-only replay double. No node or GPU.
#include "request_protocol.h"
#include <cstdio>
#include <limits>

namespace matmul::v4::rc {
namespace {
RCExactReplayExecutionPolicy test_policy{RCExactReplayExecutionPolicy::AutoFallback};
bool test_cpu_confirmation{true};
}
void SetRCExactReplayExecutionPolicy(RCExactReplayExecutionPolicy policy) { test_policy = policy; }
RCExactReplayExecutionPolicy GetRCExactReplayExecutionPolicy() { return test_policy; }
void SetRCExactReplayCpuConfirmation(bool enabled) { test_cpu_confirmation = enabled; }
bool GetRCExactReplayCpuConfirmation() { return test_cpu_confirmation; }
const char* RCExactReplayExecutionPolicyName(RCExactReplayExecutionPolicy policy)
{
    switch (policy) {
    case RCExactReplayExecutionPolicy::StrictDevice: return "strict-device";
    case RCExactReplayExecutionPolicy::AutoFallback: return "auto-fallback";
    case RCExactReplayExecutionPolicy::CpuDiagnostic: return "cpu-diagnostic";
    }
    return "unknown";
}
RCEpisodeParams ResolveRCEpisodeParams(const Consensus::Params&, int32_t) { return {}; }
bool ValidateRCEpisodeParams(const RCEpisodeParams&) { return true; }
const char* RCExactReplayFailureKindName(RCExactReplayFailureKind kind)
{
    switch (kind) {
    case RCExactReplayFailureKind::None: return "none";
    case RCExactReplayFailureKind::ExecutionFailure: return "execution-failure";
    case RCExactReplayFailureKind::UnconfirmedDigestMismatch: return "unconfirmed-digest-mismatch";
    case RCExactReplayFailureKind::ProviderUnavailable: return "provider-unavailable";
    case RCExactReplayFailureKind::Cancelled: return "cancelled";
    }
    return "unknown";
}
}
int main()
{
    using namespace matmul::v4::rc;
    Consensus::Params consensus{};
    consensus.nMatMulRCHeight = 1000;
    consensus.nMatMulV4Dimension = 4096;
    consensus.powLimit = *uint256::FromHex("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    rc_prover::ServiceState state;
    state.token = std::string(32, 'x');
    state.ready = true;
    CBlockHeader header;
    header.nBits = 0x1d00ffff;
    header.matmul_dim = 4096;
    header.seed_a.begin()[0] = 1;
    header.seed_b.begin()[0] = 2;
    header.matmul_digest.begin()[0] = 3;
    header.nNonce64 = std::numeric_limits<uint64_t>::max();
    const auto make = [&] {
        DataStream stream;
        stream << header;
        UniValue request(UniValue::VOBJ);
        request.pushKV("token", state.token);
        request.pushKV("op", "verify");
        request.pushKV("id", 1);
        request.pushKV("height", 250000);
        request.pushKV("profile", 1);
        request.pushKV("header", HexStr(Span<const std::byte>{stream.data(), stream.size()}));
        return request;
    };
    unsigned calls{0};
    RCExactReplayFailureKind failure{RCExactReplayFailureKind::None};
    const rc_prover::ReplayCallback replay = [&](const CBlockHeader& h, const RCEpisodeParams&, int32_t height, const arith_uint256&) {
        ++calls;
        if (h.nNonce64 != std::numeric_limits<uint64_t>::max() || height != 250000) throw std::runtime_error("header fields changed");
        ExactReplayVerifyResult result;
        result.failure_kind = failure;
        result.ok = failure == RCExactReplayFailureKind::None;
        result.outcome = result.ok ? ExactReplayVerifyOutcome::Valid : ExactReplayVerifyOutcome::LocalAcceleratorFailure;
        result.digest = h.matmul_digest;
        return result;
    };
    const auto run = [&](const UniValue& request) {
        return rc_prover::ProcessRequest(request.write(), consensus, state, replay);
    };
    const auto reject = [&](UniValue request, const char* outcome = "protocol_error") {
        const auto before{calls};
        const auto result{run(request)};
        if (result["ok"].get_bool() || result["outcome"].get_str() != outcome || calls != before || !state.ready) throw std::runtime_error("bad request reached replay or changed readiness");
    };
    try {
        if (rc_prover::ProcessRequest("{", consensus, state, replay)["outcome"].get_str() != "protocol_error") return 1;
        for (const char* field : {"token", "op", "header", "height", "id", "profile"}) {
            auto request{make()}; request.pushKV(field, UniValue()); reject(request);
        }
        auto request{make()}; request.pushKV("token", "wrong"); reject(request);
        request = make(); request.pushKV("token", 42); reject(request);
        request = make(); request.pushKV("op", "unknown"); reject(request);
        request = make(); request.pushKV("header", "zz"); reject(request);
        request = make(); request.pushKV("header", "00"); reject(request);
        request = make(); request.pushKV("header", request["header"].get_str() + "00"); reject(request);
        request = make(); request.pushKV("height", 999); reject(request);
        request = make(); request.pushKV("height", int64_t{1} << 40); reject(request);
        request = make(); request.pushKV("profile", 2); reject(request);
        request = make(); request.pushKV("id", 0.5); reject(request);
        request = make(); request.pushKV("target", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); reject(request);
        request = make(); request.pushKV("target", 2); reject(request);
        header.nBits = 0x1d80ffff; reject(make()); header.nBits = 0x1d00ffff;
        header.matmul_dim = 2048; reject(make(), "invalid"); header.matmul_dim = 4096;
        header.seed_a.SetNull(); reject(make(), "invalid"); header.seed_a.begin()[0] = 1;
        header.seed_b.SetNull(); reject(make(), "invalid"); header.seed_b.begin()[0] = 2;
        header.matmul_digest.SetNull(); reject(make(), "invalid"); header.matmul_digest.begin()[0] = 3;
        if (!run(make())["ok"].get_bool() || calls != 1) return 2;
        failure = RCExactReplayFailureKind::UnconfirmedDigestMismatch;
        const auto mismatch{run(make())};
        if (mismatch["ok"].get_bool() || !state.ready ||
            mismatch["failure_kind"].get_str() != "unconfirmed-digest-mismatch") return 3;
        failure = RCExactReplayFailureKind::None;
        if (!run(make())["ok"].get_bool()) return 4;
        failure = RCExactReplayFailureKind::ExecutionFailure;
        const auto execution_fault{run(make())};
        if (execution_fault["ok"].get_bool() || state.ready ||
            execution_fault["failure_kind"].get_str() != "execution-failure") return 5;
        const auto before{calls};
        const auto unavailable{run(make())};
        if (unavailable["error"].get_str() != "provider_unavailable" ||
            unavailable["failure_kind"].get_str() != "provider-unavailable" || calls != before) return 6;
        request = make(); request.pushKV("op", "status");
        const auto status{run(request)};
        if (!status["ok"].get_bool() || status["ready"].get_bool()) return 7;
        if (status["execution_policy"].get_str() != "auto-fallback" ||
            !status["cpu_confirmation"].get_bool()) return 9;
        rc_prover::ConfigureReplayPolicy();
        const auto strict{run(request)};
        if (strict["execution_policy"].get_str() != "strict-device" || strict["cpu_confirmation"].get_bool()) return 10;
        SetRCExactReplayExecutionPolicy(RCExactReplayExecutionPolicy::CpuDiagnostic);
        SetRCExactReplayCpuConfirmation(true);
        const auto diagnostic{run(request)};
        if (diagnostic["execution_policy"].get_str() != "cpu-diagnostic" || !diagnostic["cpu_confirmation"].get_bool()) return 11;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "%s\n", e.what());
        return 8;
    }
    std::puts("Real request handler: malformed/auth/target/header rejection and readiness sequences passed");
    return 0;
}
