// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// Experimental operator-owned ExactReplay service. See README.md for trust limits.
#include <arith_uint256.h>
#include <chainparams.h>
#include <matmul/exact_gemm_resolve.h>
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
#include <fstream>
#include <iterator>
#include <limits>
#include <stdexcept>
#include <string>
// Include WinSock after core headers: Windows STRICT must not rewrite core enums.
#include "socket_io.h"

const TranslateFn G_TRANSLATION_FUN{nullptr};
namespace {
std::string g_token, g_provider, g_canary;
bool g_ready{false};

UniValue Error(const std::string& message)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("ok", false);
    out.pushKV("outcome", "accel_failure");
    out.pushKV("error", message);
    return out;
}
std::string Outcome(matmul::v4::rc::ExactReplayVerifyOutcome o)
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
bool Qualify()
{
    const auto& consensus{Params().GetConsensus()};
    const auto resolved{matmul_v4::accel::ResolveExactGemmBackendForRC()};
    g_provider = resolved.provider;
    if (!resolved.self_qualified || resolved.backend.gemm_s8s8 == nullptr) return false;
    const int32_t height{consensus.nMatMulRCHeight};
    if (height <= 0 || height == std::numeric_limits<int32_t>::max()) return false;
    const auto canary{matmul::v4::rc::RunRCProductionStartupCanary(
        resolved.provider, resolved.backend, consensus, height)};
    g_canary = matmul::v4::rc::RCProductionCanaryOutcomeName(canary.outcome);
    if (canary.outcome != matmul::v4::rc::RCProductionCanaryOutcome::Passed) return false;
    std::string reason;
    const auto capability{matmul::v4::rc::GetRCProductionProviderCapability(
        resolved.provider, resolved.backend, consensus, height, &reason)};
    return capability && matmul::v4::rc::RegisterRCExactReplayAlternateProvider(
        {.backend = resolved.backend, .provider = resolved.provider, .capability = *capability}, &reason);
}
UniValue Handle(const UniValue& request)
{
    if (!request.isObject() || !request["token"].isStr() || request["token"].get_str() != g_token) return Error("authentication_failed");
    if (!request["op"].isStr()) return Error("missing_op");
    const std::string op{request["op"].get_str()};
    if (op == "status") {
        UniValue out(UniValue::VOBJ);
        out.pushKV("ok", true);
        out.pushKV("protocol", "btx-rc-prover-prototype");
        out.pushKV("version", 1);
        out.pushKV("ready", g_ready);
        out.pushKV("provider", g_provider);
        out.pushKV("canary", g_canary);
        return out;
    }
    if (op != "verify") return Error("unsupported_op");
    if (!g_ready) return Error("provider_unavailable");
    if (!request["header"].isStr() || !request["height"].isNum() || !request["id"].isNum()) return Error("missing_verify_fields");
    const int64_t id{request["id"].getInt<int64_t>()};
    const int32_t height{request["height"].getInt<int32_t>()};
    const auto& consensus{Params().GetConsensus()};
    if (height < consensus.nMatMulRCHeight) return Error("unsupported_height");
    if (!request["profile"].isNum() || request["profile"].getInt<int64_t>() != 1) return Error("unsupported_profile");
    const std::string hex{request["header"].get_str()};
    if (!IsHex(hex) || hex.size() > 4096) return Error("invalid_header");
    CBlockHeader header;
    DataStream stream{ParseHex(hex)};
    stream >> header;
    if (!stream.empty()) return Error("trailing_header_bytes");
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
    const auto result{matmul::v4::rc::VerifyBoundedExactReplay(header, params, height, &target, 1)};
    if (result.outcome == matmul::v4::rc::ExactReplayVerifyOutcome::LocalAcceleratorFailure) g_ready = false;
    UniValue out(UniValue::VOBJ);
    out.pushKV("id", id);
    out.pushKV("ok", result.ok);
    out.pushKV("outcome", Outcome(result.outcome));
    out.pushKV("digest", result.digest.ToString());
    out.pushKV("backend", result.acceleration_backend);
    out.pushKV("note", result.note);
    out.pushKV("verify_s", std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count());
    return out;
}
int Serve(uint16_t port)
{
    using namespace rc_prover;
    OwnedSocket listener{socket(AF_INET, SOCK_STREAM, 0)};
    if (!listener.Valid()) return 1;
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    if (bind(listener.Get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 || listen(listener.Get(), 16) != 0) return 1;
    std::fprintf(stderr, "Experimental RC verifier listening on loopback:%u\n", port);
    for (;;) {
        OwnedSocket client{accept(listener.Get(), nullptr, nullptr)};
        if (!client.Valid()) return 1;
        std::string line;
        if (!ReadLine(client.Get(), line, std::chrono::seconds(5))) continue;
        UniValue request, reply;
        try {
            reply = request.read(line) ? Handle(request) : Error("invalid_json");
        } catch (const std::exception&) {
            reply = Error("invalid_request");
        }
        (void)WriteAll(client.Get(), reply.write() + "\n", std::chrono::seconds(5));
        // One request per connection. No thread growth or persistent client ownership.
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
        std::ifstream input(token_file, std::ios::binary);
        if (!input) throw std::runtime_error("cannot open token file");
        char byte;
        while (input.get(byte) && g_token.size() <= 4096) g_token.push_back(byte);
        while (!g_token.empty() && (g_token.back() == '\r' || g_token.back() == '\n')) g_token.pop_back();
        if (g_token.size() < 32 || g_token.size() > 4096) throw std::runtime_error("token must contain 32..4096 bytes");
        SelectParams(ChainType::MAIN);
        rc_prover::Network network;
        if (!network.Ok()) throw std::runtime_error("socket initialization failed");
        g_ready = Qualify();
        if (!g_ready) throw std::runtime_error("GPU qualification/canary failed; no listener started");
        return Serve(static_cast<uint16_t>(port));
    } catch (const std::exception& e) {
        std::fprintf(stderr, "btx-rc-prover: %s\n", e.what());
        return 1;
    }
}
