// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/canonical_codec.h>
#include <modelnet/identity.h>
#include <modelnet/types.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <univalue.h>
#include <util/check.h>
#include <util/strencodings.h>

#include <cstdint>
#include <string>
#include <vector>

namespace {

// The same generated payload rules the verifier uses.
#include <modelnet/payload_schema_v11.inc>

constexpr size_t PAYLOAD_RULES{sizeof(kV11PayloadRules) / sizeof(kV11PayloadRules[0])};

std::vector<unsigned char> g_pk;
std::vector<unsigned char> g_sk;
std::string g_signer_id;

void initialize_modelnet_signed_envelope()
{
    std::string err;
    Assert(modelnet::GenerateMlDsa44(g_pk, g_sk, err));
    g_signer_id = modelnet::ResearchIdentityId(g_pk).Hex();
}

std::string LowerHexOf(FuzzedDataProvider& fdp, size_t nbytes)
{
    std::vector<uint8_t> bytes = fdp.ConsumeBytes<uint8_t>(nbytes);
    bytes.resize(nbytes);
    return HexStr(bytes);
}

std::string DecimalOf(FuzzedDataProvider& fdp)
{
    return std::to_string(fdp.ConsumeIntegral<uint64_t>());
}

UniValue FuzzedJsonValue(FuzzedDataProvider& fdp)
{
    UniValue v;
    if (!v.read(fdp.ConsumeRandomLengthString(256))) v = UniValue{fdp.ConsumeRandomLengthString(64)};
    return v;
}

} // namespace

// A v1.1 signed record verifies once its body is signed. If the serialized
// envelope is changed after signing, a passing verdict must still mean that
// readers of the parsed body see exactly the values the signer signed.
FUZZ_TARGET(modelnet_signed_envelope_v11, .init = initialize_modelnet_signed_envelope)
{
    FuzzedDataProvider fdp(buffer.data(), buffer.size());
    const V11PayloadRule& rule = kV11PayloadRules[fdp.ConsumeIntegralInRange<size_t>(0, PAYLOAD_RULES - 1)];
    if (rule.required == nullptr) return;
    // Pick the change made after signing first, so that short inputs reach it.
    const bool existing_key{fdp.ConsumeBool()};
    const uint8_t key_pick{fdp.ConsumeIntegral<uint8_t>()};
    const bool edit_member{fdp.ConsumeBool()};
    const uint8_t member_pick{fdp.ConsumeIntegral<uint8_t>()};

    UniValue payload(UniValue::VOBJ);
    for (const char* const* name = rule.required; *name != nullptr; ++name) {
        payload.pushKV(*name, FuzzedJsonValue(fdp));
    }
    UniValue body(UniValue::VOBJ);
    body.pushKV("envelope_version", 2);
    body.pushKV("contract_revision", "1.1.0");
    body.pushKV("record_type", rule.record_type);
    body.pushKV("network_id", LowerHexOf(fdp, 32));
    body.pushKV("realm_id", LowerHexOf(fdp, 48));
    body.pushKV("principal_id", LowerHexOf(fdp, 48));
    body.pushKV("signer_id", g_signer_id);
    body.pushKV("key_epoch", DecimalOf(fdp));
    body.pushKV("public_key_hex", HexStr(g_pk));
    body.pushKV("delegation_id", fdp.ConsumeBool() ? UniValue{} : UniValue{LowerHexOf(fdp, 48)});
    body.pushKV("created_ms", DecimalOf(fdp));
    body.pushKV("expires_ms", DecimalOf(fdp));
    body.pushKV("critical_extensions", UniValue(UniValue::VARR));
    body.pushKV("payload", payload);

    std::string err;
    modelnet::Digest48 record_id;
    std::vector<unsigned char> preimage;
    // The codec refuses some fuzzed bodies (number form, UTF-8, bounds, size).
    if (!modelnet::RecordIdV11(body, record_id, err)) return;
    Assert(modelnet::RecordPreimageV11(body, preimage, err));
    std::vector<unsigned char> sig;
    Assert(modelnet::SignMlDsa44(g_sk, preimage, sig, err));

    UniValue envelope(UniValue::VOBJ);
    envelope.pushKV("record_id", record_id.Hex());
    envelope.pushKV("body", body);
    envelope.pushKV("signature_hex", HexStr(sig));
    const bool signed_ok = modelnet::VerifySignedEnvelopeV11(envelope, err);
    if (!signed_ok) {
        // Only the canonical size budget may refuse a body the signer built.
        Assert(err == "BTX035_LIMIT_EXCEEDED");
        return;
    }

    // Change the serialized envelope: one more "key": value pair at the front
    // of the body, then parse it as the lab request path does.
    const std::vector<std::string>& keys = body.getKeys();
    const std::string key = existing_key ? keys[key_pick % keys.size()] : fdp.ConsumeRandomLengthString(16);
    UniValue injected = FuzzedJsonValue(fdp);
    if (edit_member && body.exists(key) && body[key].isObject() && !body[key].empty()) {
        // Same object with one member changed.
        injected = body[key];
        const std::vector<std::string>& members = injected.getKeys();
        const std::string member = members[member_pick % members.size()];
        UniValue edited(UniValue::VOBJ);
        UniValue replacement = FuzzedJsonValue(fdp);
        if (replacement.write() == injected[member].write()) replacement = UniValue{injected[member].write() + "."};
        for (const std::string& m : members) edited.pushKV(m, m == member ? replacement : injected[m]);
        injected = edited;
    }
    std::string text = envelope.write();
    const std::string anchor = "\"body\":{";
    const size_t at = text.find(anchor);
    Assert(at != std::string::npos);
    text.insert(at + anchor.size(), UniValue{key}.write() + ":" + injected.write() + ",");

    UniValue tampered;
    if (!tampered.read(text) || !tampered.isObject()) return;
    if (!modelnet::VerifySignedEnvelopeV11(tampered, err)) return;

    // A verdict of "valid" must mean the body readers see is the signed body.
    const UniValue& seen = tampered["body"];
    for (const std::string& k : keys) {
        Assert(seen[k].write() == body[k].write());
    }
}
