// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
#ifndef BITCOIN_CONTRIB_RC_PROVER_REQUEST_PROTOCOL_H
#define BITCOIN_CONTRIB_RC_PROVER_REQUEST_PROTOCOL_H

#include "replay_policy.h"
#include <arith_uint256.h>
#include <consensus/params.h>
#include <streams.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <chrono>
#include <functional>
#include <stdexcept>

namespace rc_prover {
struct ServiceState {
    std::string token, provider, canary;
    bool ready{false};
    uint64_t workspace_required{0}, workspace_capacity{0};
};
using ReplayCallback = std::function<matmul::v4::rc::ExactReplayVerifyResult(
    const CBlockHeader&, const matmul::v4::rc::RCEpisodeParams&, int32_t, const arith_uint256&)>;

inline UniValue Error(const std::string& message, const char* outcome = "protocol_error", const char* failure = "none")
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("ok", false);
    out.pushKV("outcome", outcome);
    out.pushKV("error", message);
    out.pushKV("failure_kind", failure);
    return out;
}
inline std::string Outcome(matmul::v4::rc::ExactReplayVerifyOutcome o)
{
    using O = matmul::v4::rc::ExactReplayVerifyOutcome;
    switch (o) {
    case O::Valid: return "valid";
    case O::InvalidConsensus: return "invalid";
    case O::LocalAcceleratorFailure: return "accel_failure";
    case O::Cancelled: return "cancelled";
    }
    return "accel_failure";
}
inline UniValue HandleRequest(const UniValue& request, const Consensus::Params& consensus, ServiceState& state, const ReplayCallback& replay)
{
    if (!request.isObject() || !request["token"].isStr() || !TimingResistantEqual(request["token"].get_str(), state.token)) return Error("authentication_failed");
    if (!request["op"].isStr()) return Error("missing_op");
    const std::string op{request["op"].get_str()};
    if (op == "status") {
        UniValue out(UniValue::VOBJ);
        out.pushKV("ok", true);
        out.pushKV("protocol", "btx-rc-prover-prototype");
        out.pushKV("version", 1);
        out.pushKV("ready", state.ready);
        out.pushKV("provider", state.provider);
        out.pushKV("canary", state.canary);
        out.pushKV("execution_policy", "strict-device");
        out.pushKV("cpu_confirmation", false);
        out.pushKV("workspace_required", state.workspace_required);
        out.pushKV("workspace_capacity", state.workspace_capacity);
        return out;
    }
    if (op != "verify") return Error("unsupported_op");
    if (!state.ready) return Error("provider_unavailable", "accel_failure", "provider_unavailable");
    if (!request["header"].isStr() || !request["height"].isNum() || !request["id"].isNum()) return Error("missing_verify_fields");
    const int64_t id{request["id"].getInt<int64_t>()};
    const int32_t height{request["height"].getInt<int32_t>()};
    if (height < consensus.nMatMulRCHeight) return Error("unsupported_height");
    if (!request["profile"].isNum() || request["profile"].getInt<int64_t>() != 1) return Error("unsupported_profile");
    const std::string hex{request["header"].get_str()};
    if (!IsHex(hex) || hex.size() > 4096) return Error("invalid_header");
    CBlockHeader header;
    DataStream stream{ParseHex(hex)};
    stream >> header;
    if (!stream.empty()) return Error("trailing_header_bytes");
    if (const char* error = rc_prover::HeaderPrecheck(header, consensus.nMatMulV4Dimension)) {
        UniValue out{Error(error, "invalid")};
        out.pushKV("id", id);
        return out;
    }
    bool negative{false}, overflow{false};
    arith_uint256 target;
    target.SetCompact(header.nBits, &negative, &overflow);
    if (negative || overflow || target == 0 || target > UintToArith256(consensus.powLimit)) return Error("invalid_compact_target");
    if (request["target"].isStr()) {
        const auto parsed{uint256::FromHex(request["target"].get_str())};
        if (!parsed) return Error("invalid_target");
        const auto supplied{UintToArith256(*parsed)};
        if (supplied == 0 || supplied > target) return Error("target_exceeds_header");
        target = supplied; // A caller may tighten, never relax, the header target.
    } else if (!request["target"].isNull()) return Error("invalid_target_type");
    const auto params{matmul::v4::rc::ResolveRCEpisodeParams(consensus, height)};
    if (!matmul::v4::rc::ValidateRCEpisodeParams(params)) return Error("unsupported_episode");
    const auto start{std::chrono::steady_clock::now()};
    const auto result{replay(header, params, height, target)};
    state.ready = rc_prover::ReadyAfterReplay(state.ready, result);
    UniValue out(UniValue::VOBJ);
    out.pushKV("id", id);
    out.pushKV("ok", result.ok);
    out.pushKV("outcome", Outcome(result.outcome));
    out.pushKV("failure_kind", matmul::v4::rc::RCExactReplayFailureKindName(result.failure_kind));
    out.pushKV("height", height);
    out.pushKV("profile", 1);
    out.pushKV("target", ArithToUint256(target).ToString());
    out.pushKV("digest", result.digest.ToString());
    out.pushKV("backend", result.acceleration_backend);
    out.pushKV("note", result.note);
    out.pushKV("verify_s", std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count());
    return out;
}
inline UniValue ProcessRequest(const std::string& line, const Consensus::Params& consensus,
                               ServiceState& state, const ReplayCallback& replay)
{
    UniValue request;
    try {
        return request.read(line) ? HandleRequest(request, consensus, state, replay) : Error("invalid_json");
    } catch (const std::exception&) {
        return Error("invalid_request");
    }
}
} // namespace rc_prover
#endif
