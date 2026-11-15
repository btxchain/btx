// Copyright (c) 2026 The BTX developers. MIT license. See COPYING.
// Owner-local, explicit native qualification. No RPC server and no wallet.
#include <modelnet/load01/load01.h>
#include <modelnet/cap02/cap02.h>
#include <modelnet/hire01/hire01.h>
#include <modelnet/identity.h>
#include <modelnet/swarm_native_io.h>
#include <modelnet/swarm_windows_sandbox.h>
#include <util/fs.h>
#include <util/translation.h>
#include <univalue.h>
#include <chrono>
#include <cmath>
#include <fstream>
#include <iostream>
#include <set>
#include <stdexcept>
#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif

const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace {
using namespace modelnet;
std::string Text(const UniValue& object, const char* field)
{
    if (!object[field].isStr()) throw std::runtime_error(std::string("STRING_FIELD:") + field);
    return object[field].get_str();
}
uint64_t Number(const UniValue& object, const char* field)
{
    if (!object[field].isNum()) throw std::runtime_error(std::string("INTEGER_FIELD:") + field);
    return object[field].getInt<uint64_t>();
}
const UniValue& Array(const UniValue& object, const char* field, size_t limit)
{
    if (!object[field].isArray() || object[field].size() > limit)
        throw std::runtime_error(std::string("ARRAY_FIELD:") + field);
    return object[field];
}
void RejectDuplicateKeys(const UniValue& value)
{
    if (value.isObject()) {
        std::set<std::string> keys;
        for (const auto& key : value.getKeys()) if (!keys.insert(key).second) throw std::runtime_error("DUPLICATE_JSON_KEY");
    }
    if (value.isObject() || value.isArray()) for (const auto& child : value.getValues()) RejectDuplicateKeys(child);
}
std::vector<unsigned char> Hex(const std::string& text, size_t expected)
{
    if (!native_io::IsDigest(text, expected)) throw std::runtime_error("HEX_FIELD");
    std::vector<unsigned char> result(expected);
    auto digit = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
    for (size_t i = 0; i < expected; ++i) result[i] = static_cast<unsigned char>((digit(text[2*i]) << 4) | digit(text[2*i+1]));
    return result;
}
std::string HexText(std::span<const unsigned char> bytes)
{
    static constexpr char digits[]="0123456789abcdef";
    std::string out; out.reserve(bytes.size()*2);
    for(unsigned char value:bytes){out+=digits[value>>4];out+=digits[value&15];}
    return out;
}
struct SecretText {
    std::string bytes;
    ~SecretText(){volatile char* ptr=bytes.data();for(size_t i=0;i<bytes.size();++i)ptr[i]=0;}
};
struct SecretBytes {
    std::vector<unsigned char> bytes;
    ~SecretBytes(){volatile unsigned char* ptr=bytes.data();for(size_t i=0;i<bytes.size();++i)ptr[i]=0;}
};
std::string ReadBoundedText(const fs::path& path, size_t limit)
{
    std::ifstream input(path,std::ios::binary);
    if(!input)throw std::runtime_error("FILE_READ");
    std::string value(limit+1,'\0');
    input.read(value.data(),static_cast<std::streamsize>(value.size()));
    if(input.bad() || static_cast<size_t>(input.gcount())>limit)throw std::runtime_error("FILE_LIMIT");
    value.resize(static_cast<size_t>(input.gcount()));return value;
}
int64_t Now()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}
std::string ExistingPath(const std::string& value)
{
    if (value.find('\0') != std::string::npos) throw std::runtime_error("NUL_PATH");
    return fs::PathToString(fs::canonical(fs::PathFromString(value)));
}
NativeToolProbe Probe(const UniValue& input)
{
    NativeToolProbe out;
    out.root = ExistingPath(Text(input, "root")); out.executable = Text(input, "executable");
    out.output_relative_path = Text(input, "output_relative_path");
    out.expected_output_sha384 = Text(input, "expected_output_sha384");
    out.expected_output_bytes = Number(input, "expected_output_bytes");
    out.max_package_bytes = Number(input, "max_package_bytes");
    const auto seconds = Number(input, "wall_seconds");
    if (seconds == 0 || seconds > 86400) throw std::runtime_error("WALL_LIMIT");
    out.wall_seconds = static_cast<int>(seconds);
    for (const auto& file : Array(input, "files", 4096).getValues())
        out.files.push_back({Text(file, "path"), Text(file, "sha384"), Number(file, "bytes")});
    return out;
}
UniValue Evidence(const NativeToolEvidence& evidence)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("package_sha384", evidence.package_sha384);
    out.pushKV("executable_sha384", evidence.executable_sha384);
    out.pushKV("output_sha384", evidence.output_sha384);
    out.pushKV("operating_system", evidence.operating_system);
    out.pushKV("architecture", evidence.architecture);
    out.pushKV("exit_code", evidence.exit_code); out.pushKV("elapsed_ms", evidence.elapsed_ms);
    return out;
}
std::vector<unsigned char> ReadSigningSecret(const std::string& value)
{
    const fs::path path = fs::PathFromString(value);
    std::error_code ec;
    const auto status = fs::symlink_status(path, ec);
    if (ec || !fs::is_regular_file(status) || fs::is_symlink(status) || fs::file_size(path, ec) > 8192 || ec)
        throw std::runtime_error("SIGNING_SECRET_FILE");
#ifndef _WIN32
    struct stat st{};
    if (stat(path.c_str(), &st) != 0 || st.st_uid != geteuid() || (st.st_mode & 077) != 0)
        throw std::runtime_error("SIGNING_SECRET_PERMISSION");
#else
    if(!WindowsOwnerOnlyFile(path))throw std::runtime_error("SIGNING_SECRET_PERMISSION");
#endif
    SecretText hex{ReadBoundedText(path,8192)};
    if (!hex.bytes.empty() && hex.bytes.back() == '\n') hex.bytes.pop_back();
    return Hex(hex.bytes, MLDSA44_SK);
}
bool SignCheckpoint(const UniValue& request, UniValue& result, std::string& error)
{
    CheckpointSourceReceipt receipt;
    receipt.artifact_id=Text(request,"artifact_id");receipt.request_nonce=Text(request,"request_nonce");
    receipt.source_public_key=Hex(Text(request,"source_public_key"),MLDSA44_PK);
    const uint64_t expiry=Number(request,"expires_at_ms"),cap=Number(request,"max_checkpoint_bytes");
    const int64_t now=Now();
    if(!native_io::IsDigest(receipt.artifact_id) || !native_io::IsDigest(receipt.request_nonce,32) ||
       expiry>INT64_MAX || now<0 || expiry<=static_cast<uint64_t>(now) || expiry-static_cast<uint64_t>(now)>3600000 ||
       cap==0 || cap>static_cast<uint64_t>(INT64_MAX)) {error="RECEIPT_POLICY";return false;}
    receipt.expires_at_ms=static_cast<int64_t>(expiry);
    const fs::path path=fs::PathFromString(ExistingPath(Text(request,"checkpoint_path")));
    std::error_code ec;receipt.bytes=fs::file_size(path,ec);
    if(ec || !fs::is_regular_file(path,ec) || ec || receipt.bytes==0 || receipt.bytes>cap || receipt.bytes>SIZE_MAX) {
        error="CHECKPOINT_SIZE";return false;
    }
    const std::string raw=ReadBoundedText(path,static_cast<size_t>(receipt.bytes));
    if(raw.size()!=receipt.bytes){error="CHECKPOINT_SIZE";return false;}
    receipt.checkpoint_sha384=native_io::Digest(std::span<const unsigned char>{
        reinterpret_cast<const unsigned char*>(raw.data()),raw.size()});
    SecretBytes secret{ReadSigningSecret(Text(request,"source_secret_file"))};
    const auto message=CheckpointSourceMessage(receipt);
    if(!SignMlDsa44(secret.bytes,message,receipt.signature,error) ||
       !VerifyMlDsa44(receipt.source_public_key,message,receipt.signature)){error="SOURCE_KEY_MISMATCH";return false;}
    UniValue output(UniValue::VOBJ);
    output.pushKV("artifact_id",receipt.artifact_id);output.pushKV("checkpoint_sha384",receipt.checkpoint_sha384);
    output.pushKV("bytes",receipt.bytes);output.pushKV("request_nonce",receipt.request_nonce);
    output.pushKV("expires_at_ms",receipt.expires_at_ms);output.pushKV("source_public_key",HexText(receipt.source_public_key));
    output.pushKV("signature",HexText(receipt.signature));result.pushKV("receipt",output);
    result.pushKV("scope","SOURCE_ATTESTATION_ONLY");return true;
}
bool RunLoad(const UniValue& request, UniValue& result, std::string& error)
{
    Load01 loader;
    const uint64_t cap = Number(request, "max_checkpoint_bytes");
    const auto& sources = Array(request, "sources", 16);
    if (sources.size() < 2) { error = "SECOND_SOURCE_REQUIRED"; return false; }
    for (const auto& source : sources.getValues()) {
        const auto& object = source["receipt"];
        CheckpointSourceReceipt receipt;
        receipt.artifact_id = Text(object, "artifact_id");
        receipt.checkpoint_sha384 = Text(object, "checkpoint_sha384");
        receipt.bytes = Number(object, "bytes"); receipt.request_nonce = Text(object, "request_nonce");
        const auto expires = Number(object, "expires_at_ms");
        if (expires > INT64_MAX) { error = "RECEIPT_EXPIRY"; return false; }
        receipt.expires_at_ms = static_cast<int64_t>(expires);
        receipt.source_public_key = Hex(Text(object, "source_public_key"), MLDSA44_PK);
        receipt.signature = Hex(Text(object, "signature"), MLDSA44_SIG);
        const auto pinned = Hex(Text(source, "expected_source_public_key"), MLDSA44_PK);
        if (!loader.LoadVerified(ExistingPath(Text(source, "path")), receipt, pinned,
                                 Text(source, "expected_request_nonce"), Now(), cap, error)) return false;
    }
    const auto& linear = request["linear"];
    std::vector<float> input, expected;
    for (const auto& value : Array(linear, "input", 1 << 20).getValues()) {
        if (!value.isNum()) { error = "LINEAR_INPUT"; return false; }
        const float f = static_cast<float>(value.get_real());
        if (!std::isfinite(f)) { error = "LINEAR_INPUT"; return false; }
        input.push_back(f);
    }
    for (const auto& value : Array(linear, "expected_output", 1 << 20).getValues()) {
        if (!value.isNum()) { error = "LINEAR_EXPECTED"; return false; }
        expected.push_back(static_cast<float>(value.get_real()));
    }
    std::vector<float> output;
    if (!loader.LinearF32(Text(linear, "weights"), Text(linear, "bias"), input, output, error)) return false;
    if (output != expected) { error = "LINEAR_OUTCOME_MISMATCH"; return false; }
    result.pushKV("checkpoint_sha384", loader.checkpoint_sha384());
    result.pushKV("bytes_consumed", loader.bytes_read());
    result.pushKV("verified_source_identities", static_cast<uint64_t>(loader.verified_source_count()));
    result.pushKV("tensor_count", static_cast<uint64_t>(loader.tensors().size()));
    result.pushKV("physical_host_count", 1);
    result.pushKV("gpu_qualified", false); result.pushKV("module_passed", loader.passed());
    UniValue values(UniValue::VARR); for (float value : output) values.push_back(UniValue(static_cast<double>(value)));
    result.pushKV("output", values);
    if (!loader.passed()) { error = "INDEPENDENT_SOURCE_REQUIRED"; return false; }
    return true;
}
bool RunTool(const UniValue& request, UniValue& result, std::string& error)
{
    Cap02 runner;
    if (!runner.QualifyNative(Probe(request["probe"]), error)) return false;
    result.pushKV("evidence", Evidence(runner.native_evidence()));
    result.pushKV("module_passed", runner.native_qualified());
    return runner.native_qualified();
}
bool RunRelease(const UniValue& request, UniValue& result, std::string& error)
{
    const auto& p = request["policy"];
    DefensiveReleasePolicy policy;
    policy.model_id = Text(p, "model_id"); policy.model_path = ExistingPath(Text(p, "model_path"));
    policy.model_sha384 = Text(p, "model_sha384"); policy.model_bytes = Number(p, "model_bytes");
    policy.max_model_bytes = Number(p, "max_model_bytes"); policy.parent_model_sha384 = Text(p, "parent_model_sha384");
    policy.controls_sha384 = Text(p, "controls_sha384"); policy.source_revision = Text(p, "source_revision");
    policy.runtime_image_sha384 = Text(p, "runtime_image_sha384"); policy.realm_id = Text(p, "realm_id");
    const auto expires = Number(p, "expires_at_ms");
    if (expires > INT64_MAX) { error = "POLICY_EXPIRY"; return false; }
    policy.expires_at_ms = static_cast<int64_t>(expires);
    policy.release_public_key = Hex(Text(p, "release_public_key"), MLDSA44_PK);
    std::vector<DefensiveGateProbe> probes;
    for (const auto& gate : Array(request, "gates", 6).getValues())
        probes.push_back({Text(gate, "gate_id"), Probe(gate["probe"])});
    // Parse all authority inputs before any protected execution.
    const auto version = Text(request, "version"), output_path = Text(request, "output_path");
    SecretBytes secret{ReadSigningSecret(Text(request, "release_secret_file"))};
    Hire01 release;
    const bool qualified = release.QualifyModifiedNative(policy, probes, Now(), error);
    const bool issued = qualified && release.IssueReleaseNative(version, output_path, secret.bytes, Now(), error);
    if (!issued) return false;
    result.pushKV("module_passed", release.passed());
    result.pushKV("model_release_qualified", release.release_qualified());
    result.pushKV("release_document_sha384", release.release_document_sha384());
    result.pushKV("output_path", output_path);
    return true;
}
}
int main(int argc, char** argv)
{
    if (argc != 3) {
        std::cerr << "usage: btx-native-qualify <sign-checkpoint|load|tool|release> <owner-request.json>\n"
                     "Explicit local execution; no wallet, server, network or automatic spend.\n";
        return 1;
    }
    UniValue result(UniValue::VOBJ);
    result.pushKV("schema", "BTX/NativeQualificationResult/v1");
    result.pushKV("automatic_spend_atoms", "0");
    result.pushKV("btx_deployment_qualified", false);
    std::string error;
    bool ok = false;
    try {
        std::string mode = argv[1];
        if (mode.starts_with("--")) mode.erase(0, 2);
        if (mode != "sign-checkpoint" && mode != "load" && mode != "tool" && mode != "release") throw std::runtime_error("UNKNOWN_MODE");
        const fs::path path = fs::PathFromString(argv[2]);
        std::error_code ec;
        const auto status = fs::symlink_status(path, ec);
        if (ec || !fs::is_regular_file(status) || fs::is_symlink(status) || fs::file_size(path, ec) > 1024 * 1024 || ec)
            throw std::runtime_error("REQUEST_FILE");
        const std::string raw=ReadBoundedText(path,1024*1024);
        UniValue request;
        if (!request.read(raw) || !request.isObject()) throw std::runtime_error("REQUEST_JSON");
        RejectDuplicateKeys(request);
        result.pushKV("request_sha384", native_io::Digest(std::span<const unsigned char>{
            reinterpret_cast<const unsigned char*>(raw.data()), raw.size()}));
        result.pushKV("mode", mode); result.pushKV("started_at_ms", Now());
        if (mode == "sign-checkpoint") ok = SignCheckpoint(request, result, error);
        if (mode == "load") ok = RunLoad(request, result, error);
        if (mode == "tool") ok = RunTool(request, result, error);
        if (mode == "release") ok = RunRelease(request, result, error);
    } catch (const std::exception& exception) { error = exception.what(); }
    result.pushKV("finished_at_ms", Now()); result.pushKV("success", ok);
    if (!ok) result.pushKV("error", error.empty() ? "UNQUALIFIED" : error);
    std::cout << result.write(0, 0) << '\n';
    return ok ? 0 : 2;
}
