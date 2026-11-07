// Copyright (c) 2026 The BTX developers. MIT license. See COPYING.
#include <modelnet/load01/load01.h>
#include <modelnet/cap02/cap02.h>
#include <modelnet/hire01/hire01.h>
#include <modelnet/identity.h>
#include <modelnet/swarm_native_io.h>
#include <modelnet/swarm_confine.h>
#include <modelnet/swarm_fsjail.h>
#include <univalue.h>
extern "C" {
#include <libbitcoinpqc/ml_dsa.h>
}
#include <array>
#include <bit>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>

using namespace modelnet;
namespace {
size_t checks = 0;
void Check(bool value, const char* name)
{
    if (!value) throw std::runtime_error(name);
    ++checks;
}
void Write(const fs::path& path, const std::vector<unsigned char>& bytes)
{
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    Check(static_cast<bool>(out), "write fixture");
}
void WriteText(const fs::path& path, const std::string& text)
{
    Write(path, {text.begin(), text.end()});
}
std::string Hex(const std::vector<unsigned char>& bytes)
{
    static const char* chars = "0123456789abcdef";
    std::string out;
    for (auto b : bytes) { out += chars[b >> 4]; out += chars[b & 15]; }
    return out;
}
std::vector<unsigned char> MakeTensor(const std::string& header, std::vector<float> data)
{
    std::vector<unsigned char> bytes;
    native_io::AppendNumber(bytes, header.size());
    bytes.insert(bytes.end(), header.begin(), header.end());
    for (float value : data) {
        const auto bits = std::bit_cast<uint32_t>(value);
        for (int i = 0; i < 4; ++i) bytes.push_back(static_cast<unsigned char>(bits >> (i * 8)));
    }
    return bytes;
}
void Keys(unsigned char label, std::vector<unsigned char>& pk, std::vector<unsigned char>& sk)
{
    // Deterministic test-only keys, never installed as an owner identity.
    std::array<unsigned char, 128> seed{};
    for (size_t i = 0; i < seed.size(); ++i) seed[i] = static_cast<unsigned char>(i + label);
    pk.resize(MLDSA44_PK); sk.resize(MLDSA44_SK);
    Check(ml_dsa_44_keygen(pk.data(), sk.data(), seed.data(), seed.size()) == 0, "actual ML-DSA keygen");
}
void Sign(CheckpointSourceReceipt& receipt, const std::vector<unsigned char>& sk)
{
    const auto message = CheckpointSourceMessage(receipt);
    std::string error;
    Check(SignMlDsa44(sk, message, receipt.signature, error), "actual ML-DSA sign");
}
UniValue Receipt(const CheckpointSourceReceipt& receipt)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("artifact_id", receipt.artifact_id); out.pushKV("checkpoint_sha384", receipt.checkpoint_sha384);
    out.pushKV("bytes", receipt.bytes); out.pushKV("request_nonce", receipt.request_nonce);
    out.pushKV("expires_at_ms", receipt.expires_at_ms); out.pushKV("source_public_key", Hex(receipt.source_public_key));
    out.pushKV("signature", Hex(receipt.signature)); return out;
}
}
int main(int argc, char** argv)
{
    try {
        Check(argc == 2, "fixture directory argument");
        const fs::path root = fs::canonical(fs::PathFromString(argv[1]));
        const auto a = root / "source-a.safetensors", b = root / "source-b.safetensors";
        const std::string header = "{\"weight\":{\"dtype\":\"F32\",\"shape\":[2,3],\"data_offsets\":[0,24]},\"bias\":{\"dtype\":\"F32\",\"shape\":[2],\"data_offsets\":[24,32]}}";
        const auto bytes = MakeTensor(header, {1,2,3,4,5,6,0.5f,-0.5f});
        Write(a, bytes); Write(b, bytes);
        std::vector<unsigned char> pk1,sk1,pk2,sk2;
        Keys(7,pk1,sk1); Keys(19,pk2,sk2);
        const int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        CheckpointSourceReceipt r1{std::string(96,'a'), native_io::Digest(bytes), bytes.size(), std::string(64,'b'), now+600000, pk1, {}};
        Sign(r1,sk1);
        auto r2 = r1; r2.source_public_key = pk2; r2.request_nonce = std::string(64,'c'); Sign(r2,sk2);
        Load01 loader; std::string error;
        Check(loader.LoadVerified(fs::PathToString(a),r1,pk1,r1.request_nonce,now,1<<20,error), "first signed source loads");
        Check(loader.verified_source_count()==1 && !loader.passed(), "one source does not pass two-source gate");
        std::vector<float> result;
        const std::array<float,3> input{1,2,3};
        Check(loader.LinearF32("weight","bias",input,result,error) && result==std::vector<float>{14.5f,31.5f}, "resident bytes execute a real dense layer");
        Check(loader.LoadVerified(fs::PathToString(b),r2,pk2,r2.request_nonce,now,1<<20,error), "second authenticated source loads");
        Check(loader.verified_source_count()==2 && !loader.passed(), "new source must be consumed");
        Check(loader.LinearF32("weight","bias",input,result,error) && loader.passed(), "second-source bytes consumed");
        Check(!loader.release_qualified() && !loader.hardware_qualified() && !loader.gpu_passed(), "component test is not hardware/release qualification");
        Check(!loader.LoadVerified(fs::PathToString(b),r2,pk1,r2.request_nonce,now,1<<20,error), "pin substitution rejected");
        Check(!loader.LoadVerified(fs::PathToString(b),r2,pk2,r1.request_nonce,now,1<<20,error), "nonce substitution rejected");
        auto bad = r2; bad.signature[20] ^= 1;
        Check(!loader.LoadVerified(fs::PathToString(b),bad,pk2,bad.request_nonce,now,1<<20,error), "signature tamper rejected");
        Check(!loader.LoadVerified(fs::PathToString(b),r2,pk2,r2.request_nonce,now+600000,1<<20,error), "expired receipt rejected");
        Check(loader.passed(), "failed replacement preserves active checkpoint");
        auto corrupt = bytes; corrupt.back() ^= 1; Write(b,corrupt);
        Check(!loader.LoadVerified(fs::PathToString(b),r2,pk2,r2.request_nonce,now,1<<20,error) && error=="DIGEST", "corrupt second-source bytes rejected");
        Check(loader.LinearF32("weight","bias",input,result,error) && result==std::vector<float>{14.5f,31.5f}, "path modification cannot modify resident bytes");
        Write(b,bytes);
        const std::array<float,3> nan_input{1,std::numeric_limits<float>::quiet_NaN(),3};
        result={99}; Check(!loader.LinearF32("weight","bias",nan_input,result,error) && result==std::vector<float>{99}, "nonfinite consumer rejected transactionally");
        const fs::path link = root / "linked.safetensors";
        fs::create_symlink(a,link);
        Check(!loader.LoadVerified(fs::PathToString(link),r1,pk1,r1.request_nonce,now,1<<20,error), "symlink checkpoint refused");
        const auto invalid = MakeTensor("{\"x\":{\"dtype\":\"F32\",\"shape\":[2],\"data_offsets\":[4,12]}}", {1,2,3});
        Write(b,invalid); bad=r2; bad.bytes=invalid.size(); bad.checkpoint_sha384=native_io::Digest(invalid); Sign(bad,sk2);
        Check(!loader.LoadVerified(fs::PathToString(b),bad,pk2,bad.request_nonce,now,1<<20,error) && error=="CHECKPOINT_OVERLAP_OR_HOLE", "validly signed malformed tensor rejected");
        Write(b,bytes);
        Hire01 hire;
        Check(hire.QualifyModified("model",true,true,error), "legacy controls can record");
        Check(!hire.IssueRelease("v1",true,error) && !hire.release_issued(), "caller booleans cannot mint release");
        DefensiveReleasePolicy empty;
        Check(!hire.QualifyModifiedNative(empty,{},now,error), "missing native policy refused");
        SwarmConfineRequest confine;
        confine.helper=a; confine.root=root; confine.max_address_bytes=1<<20; confine.max_cpu_seconds=1; confine.max_nofile=64; confine.network_denied=true;
        confine.helper=link;
        Check(SwarmRunConfined(confine,error).code=="PATH", "sandbox symlink executable refused");
        Cap02 cap;
        NativeToolProbe probe;
        probe.root=fs::PathToString(root); probe.executable="source-a.safetensors";
        probe.output_relative_path="source-b.safetensors"; probe.expected_output_bytes=bytes.size(); probe.expected_output_sha384=native_io::Digest(bytes);
        probe.files={{"source-a.safetensors",native_io::Digest(bytes),bytes.size()}};
        Check(!cap.QualifyNative(probe,error) && error=="NATIVE_TOOL_STALE_OUTPUT", "preexisting probe result cannot qualify environment");
        probe.output_relative_path="new-native-output";
        const auto correct_digest=probe.files[0].sha384;
        probe.files[0].sha384=std::string(96,'f');
        Check(!cap.QualifyNative(probe,error) && error=="DIGEST","pinned package corruption fails before execution");
        probe.files[0].sha384=correct_digest;
        const fs::path tool_case=root/"tool-case";fs::create_directory(tool_case);
        Write(tool_case/"probe",bytes);WriteText(tool_case/"extra.bin","unlisted");
        probe.root=fs::PathToString(tool_case);probe.executable="probe";probe.files[0].relative_path="probe";
        Check(!cap.QualifyNative(probe,error) && error=="NATIVE_TOOL_UNPINNED_FILE","unlisted package inputs cannot qualify");
        DefensiveReleasePolicy unbound;
        unbound.model_id=std::string(96,'a');unbound.model_path=fs::PathToString(a);
        unbound.model_sha384=correct_digest;unbound.model_bytes=bytes.size();
        unbound.parent_model_sha384=std::string(96,'b');unbound.controls_sha384=correct_digest;
        unbound.runtime_image_sha384=std::string(96,'c');unbound.realm_id=std::string(96,'d');
        unbound.source_revision=std::string(40,'e');unbound.release_public_key=pk1;unbound.expires_at_ms=now+600000;
        std::vector<DefensiveGateProbe> gates;
        for(const auto* id:{"external-controls","outcome","revocation","rollback","privacy","adversarial"})gates.push_back({id,probe});
        Check(!hire.QualifyModifiedNative(unbound,gates,now,error) && error=="DEFENSIVE_UNBOUND_PROBE","runtime identity must bind actual gate input bytes");
        UniValue sources(UniValue::VARR);
        for (const auto& pair : {std::pair{a,r1},std::pair{b,r2}}) {
            UniValue source(UniValue::VOBJ); source.pushKV("path",fs::PathToString(pair.first)); source.pushKV("receipt",Receipt(pair.second));
            source.pushKV("expected_source_public_key",Hex(pair.second.source_public_key)); source.pushKV("expected_request_nonce",pair.second.request_nonce); sources.push_back(source);
        }
        UniValue request(UniValue::VOBJ); request.pushKV("max_checkpoint_bytes",1<<20); request.pushKV("sources",sources);
        UniValue linear(UniValue::VOBJ); linear.pushKV("weights","weight"); linear.pushKV("bias","bias");
        UniValue inputs(UniValue::VARR); for(int v:{1,2,3})inputs.push_back(v);
        UniValue expected(UniValue::VARR); expected.push_back(UniValue(14.5));expected.push_back(UniValue(31.5));
        linear.pushKV("input",inputs);linear.pushKV("expected_output",expected);request.pushKV("linear",linear);
        WriteText(root/"load-request.json",request.write(0,0));
        WriteText(root/"test-source-secret.hex",Hex(sk1));
        fs::permissions(root/"test-source-secret.hex",fs::perms::owner_read|fs::perms::owner_write);
        UniValue signing(UniValue::VOBJ);
        signing.pushKV("checkpoint_path",fs::PathToString(a));signing.pushKV("artifact_id",r1.artifact_id);
        signing.pushKV("request_nonce",r1.request_nonce);signing.pushKV("expires_at_ms",r1.expires_at_ms);
        signing.pushKV("max_checkpoint_bytes",1<<20);signing.pushKV("source_public_key",Hex(pk1));
        signing.pushKV("source_secret_file",fs::PathToString(root/"test-source-secret.hex"));
        WriteText(root/"sign-request.json",signing.write(0,0));
        UniValue summary(UniValue::VOBJ);summary.pushKV("checks_passed",static_cast<uint64_t>(checks));summary.pushKV("real_mldsa",true);summary.pushKV("native_sandbox_qualified",false);
        std::cout<<summary.write(0,0)<<'\n';return 0;
    } catch(const std::exception& e) {std::cerr<<"FAIL: "<<e.what()<<'\n';return 1;}
}
