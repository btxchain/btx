// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Local generate matching: SafeTensors architectures this tree will attempt
// with BTX_MODEL_GENERATE, and GGUF with BTX_LLAMA_CLI. No remote endpoints,
// no trust_remote_code, no spend. execution_profile is identity, not a PASS.

#include <modelnet/generate.h>

#include <util/fs.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <string>
#include <system_error>
#include <unistd.h>
#include <vector>

namespace modelnet {
namespace {

std::string LowerCopy(std::string s)
{
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

bool EndsWithLower(const std::string& name, const char* suf)
{
    const std::string n = LowerCopy(name);
    const std::string s = suf;
    return n.size() >= s.size() && n.compare(n.size() - s.size(), s.size(), s) == 0;
}

bool IsExecutableFile(const fs::path& p)
{
    if (!fs::exists(p) || !fs::is_regular_file(p)) return false;
    return ::access(fs::PathToString(p).c_str(), X_OK) == 0;
}

const char* kStArch[] = {
    "LlamaForCausalLM",
    "MistralForCausalLM",
    "MixtralForCausalLM",
    "Qwen2ForCausalLM",
    "Qwen2MoeForCausalLM",
    "Qwen3ForCausalLM",
    "GemmaForCausalLM",
    "Gemma2ForCausalLM",
    "Gemma3ForCausalLM",
    "PhiForCausalLM",
    "Phi3ForCausalLM",
    "GPT2LMHeadModel",
    "GPTNeoForCausalLM",
    "GPTNeoXForCausalLM",
    "BloomForCausalLM",
    "MptForCausalLM",
    "OlmoForCausalLM",
    "Olmo2ForCausalLM",
    "GraniteForCausalLM",
    "GraniteMoeForCausalLM",
    "GraniteMoeHybridForCausalLM",
    "CohereForCausalLM",
    "StableLmForCausalLM",
    "FalconForCausalLM",
    "MambaForCausalLM",
    "FalconMambaForCausalLM",
};

std::string FirstArchitecture(const UniValue& cfg)
{
    if (!cfg.isObject()) return {};
    if (cfg.exists("architectures") && cfg["architectures"].isArray() &&
        cfg["architectures"].size() > 0 && cfg["architectures"][0].isStr()) {
        return cfg["architectures"][0].get_str();
    }
    if (cfg.exists("auto_map") && cfg["auto_map"].isObject()) {
        return "custom_auto_map";
    }
    return {};
}

void WalkCheckout(const fs::path& dir, int depth, ArtifactGenerateView& v)
{
    if (depth > 4) return;
    std::error_code ec;
    fs::directory_iterator it(dir, ec);
    if (ec) return;
    const fs::directory_iterator end;
    for (; it != end; it.increment(ec)) {
        if (ec) break;
        const fs::path p = it->path();
        const std::string name = fs::PathToString(p.filename());
        if (it->is_directory(ec) && !ec) {
            WalkCheckout(p, depth + 1, v);
            continue;
        }
        if (!it->is_regular_file(ec) || ec) continue;
        if (EndsWithLower(name, ".pt") || EndsWithLower(name, ".pth") ||
            EndsWithLower(name, ".pkl") || EndsWithLower(name, ".pickle") ||
            EndsWithLower(name, ".so")) {
            v.pickle_or_executable = true;
            v.format = GenerateFormat::Unsafe;
            return;
        }
        if (EndsWithLower(name, ".gguf") && v.format != GenerateFormat::Unsafe) {
            v.format = GenerateFormat::Gguf;
            if (v.weights_path.empty()) v.weights_path = fs::PathToString(p);
        }
        if (EndsWithLower(name, ".safetensors") && v.format != GenerateFormat::Unsafe &&
            v.format != GenerateFormat::Gguf) {
            v.format = GenerateFormat::SafeTensors;
            if (v.weights_path.empty()) v.weights_path = fs::PathToString(p);
        }
        if (LowerCopy(name) == "config.json" && v.architecture.empty()) {
            std::ifstream in(p);
            std::string body((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            UniValue cfg;
            if (cfg.read(body) && cfg.isObject()) {
                v.architecture = FirstArchitecture(cfg);
                v.config_path = fs::PathToString(p);
            }
        }
    }
}

} // namespace

bool SafeTensorsArchitectureIsHostCompatible(const std::string& architecture)
{
    if (architecture.empty()) return false;
    if (LowerCopy(architecture) == "custom_auto_map") return false;
    for (const char* a : kStArch) {
        if (architecture == a) return true;
    }
    return false;
}

HostGenerateProfile ProbeHostGenerateProfile()
{
    HostGenerateProfile p;
    if (const char* e = std::getenv("BTX_LLAMA_CLI")) {
        const fs::path path = fs::PathFromString(e);
        if (IsExecutableFile(path)) {
            p.llama_cli = true;
            p.llama_cli_path = e;
        }
    }
    if (const char* e = std::getenv("BTX_MODEL_GENERATE")) {
        const fs::path path = fs::PathFromString(e);
        if (IsExecutableFile(path)) {
            p.generate_adapter = true;
            p.generate_adapter_path = e;
        }
    }
    if (const char* e = std::getenv("BTX_MODEL_CUDA_LOADER")) {
        const fs::path path = fs::PathFromString(e);
        if (IsExecutableFile(path)) {
            p.cuda_loader = true;
            p.cuda_loader_path = e;
        }
    }
    return p;
}

UniValue HostGenerateProfileJson(const HostGenerateProfile& p)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", 2);
    o.pushKV("llama_cli", p.llama_cli);
    o.pushKV("generate_adapter", p.generate_adapter);
    o.pushKV("cuda_loader", p.cuda_loader);
    UniValue formats(UniValue::VARR);
    if (p.generate_adapter) formats.push_back("safetensors");
    if (p.llama_cli || p.generate_adapter) formats.push_back("gguf");
    o.pushKV("formats", formats);
    UniValue backends(UniValue::VARR);
    if (p.generate_adapter) backends.push_back("BTX_MODEL_GENERATE");
    if (p.llama_cli) backends.push_back("llama.cpp");
    if (p.cuda_loader) backends.push_back("safetensors-cuda-smoke");
    o.pushKV("backends", backends);
    o.pushKV("can_generate", p.generate_adapter || p.llama_cli);
    o.pushKV("cuda_smoke_is_not_generate", true);
    o.pushKV("trust_remote_code", false);
    o.pushKV("remote_inference", false);
    o.pushKV("automatic_spend_atoms", 0);
    o.pushKV("execution_profile_unqualified", 0);
    o.pushKV("note",
             "Local generate only for host-compatible GGUF (BTX_LLAMA_CLI) or "
             "allowlisted SafeTensors architectures (BTX_MODEL_GENERATE). "
             "CUDA --hold --smoke is not a generate. Granite hybrid is not GGUF.");
    return o;
}

ArtifactGenerateView InspectCheckoutForGenerate(const fs::path& checkout)
{
    ArtifactGenerateView v;
    if (!fs::exists(checkout)) return v;
    if (fs::is_regular_file(checkout)) {
        const std::string name = fs::PathToString(checkout.filename());
        if (EndsWithLower(name, ".gguf")) {
            v.format = GenerateFormat::Gguf;
            v.weights_path = fs::PathToString(checkout);
        } else if (EndsWithLower(name, ".safetensors")) {
            v.format = GenerateFormat::SafeTensors;
            v.weights_path = fs::PathToString(checkout);
        } else if (EndsWithLower(name, ".pt") || EndsWithLower(name, ".pkl")) {
            v.format = GenerateFormat::Unsafe;
            v.pickle_or_executable = true;
        }
        return v;
    }
    WalkCheckout(checkout, 0, v);
    return v;
}

bool ArtifactCompatibleWithHost(const ArtifactGenerateView& art,
                                const HostGenerateProfile& host,
                                std::string& reason)
{
    if (art.pickle_or_executable || art.format == GenerateFormat::Unsafe) {
        reason = "unsafe_format";
        return false;
    }
    if (art.format == GenerateFormat::None) {
        reason = "no_weights";
        return false;
    }
    if (art.format == GenerateFormat::Gguf) {
        if (host.llama_cli || host.generate_adapter) return true;
        reason = "no_gguf_backend";
        return false;
    }
    if (!SafeTensorsArchitectureIsHostCompatible(art.architecture)) {
        reason = art.architecture.empty() ? "missing_architecture" : "unknown_architecture";
        return false;
    }
    if (!host.generate_adapter) {
        reason = "no_generate_adapter";
        return false;
    }
    return true;
}

std::string PickGenerateAdapter(const ArtifactGenerateView& art, const HostGenerateProfile& host)
{
    (void)art;
    if (host.generate_adapter) return host.generate_adapter_path;
    return {};
}

} // namespace modelnet
