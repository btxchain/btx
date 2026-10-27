// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// A signed envelope whose JSON repeats a body key must not verify.
// CanonicalEncode (signature preimage, record id) used the last of two equal
// keys, while UniValue::operator[] and every reader of the parsed body use the
// first, so a copy edited after signing kept a valid signature.

#include <modelnet/bounty.h>
#include <modelnet/canonical_codec.h>
#include <modelnet/identity.h>
#include <modelnet/types.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_envelope_dupkey_tests, BasicTestingSetup)

namespace {

/** Put `"key":value,` first in the object that follows `anchor`. */
std::string InsertFirst(const std::string& text, const std::string& anchor, const std::string& member)
{
    const size_t at = text.find(anchor);
    BOOST_REQUIRE(at != std::string::npos);
    std::string out = text;
    out.insert(at + anchor.size(), member + ",");
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(canonical_encode_rejects_duplicate_keys)
{
    // Repeated keys are refused at any depth, also when both values are equal.
    for (const char* text : {R"({"a":1,"a":2})", R"({"a":1,"a":1})", R"({"o":{"k":"x","k":"y"}})",
                             R"({"l":[{"k":1},{"k":1,"k":2}]})"}) {
        UniValue parsed;
        BOOST_REQUIRE(parsed.read(text));
        std::vector<unsigned char> out;
        std::string err;
        BOOST_CHECK_MESSAGE(!modelnet::CanonicalEncode(parsed, out, err), text);
        BOOST_CHECK_EQUAL(err, "duplicate JSON key");
    }
    // The same key in two different objects is not a repeat.
    UniValue parsed;
    BOOST_REQUIRE(parsed.read(R"({"a":{"k":1},"b":{"k":1},"l":[{"k":1},{"k":2}]})"));
    std::vector<unsigned char> out;
    std::string err;
    BOOST_CHECK(modelnet::CanonicalEncode(parsed, out, err));
}

BOOST_AUTO_TEST_CASE(v1_envelope_with_repeated_payload_does_not_verify)
{
    std::vector<unsigned char> pk, sk;
    std::string err;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(pk, sk, err));
    modelnet::NetworkId network;
    BOOST_REQUIRE(modelnet::NetworkId::FromHex(std::string(64, '1'), network, err));
    UniValue payload(UniValue::VOBJ);
    payload.pushKV("price_atoms", "100");
    modelnet::SignedEnvelope env;
    BOOST_REQUIRE(modelnet::BuildSignedEnvelope("ComputeOffer", network, pk, sk, payload, UniValue(), env, err));
    BOOST_REQUIRE(modelnet::VerifySignedEnvelope(env, network, err));

    const std::string edited = InsertFirst(modelnet::EnvelopeToJson(env).write(), "\"body\":{",
                                           R"("payload":{"price_atoms":"1"})");
    UniValue parsed;
    BOOST_REQUIRE(parsed.read(edited));
    modelnet::SignedEnvelope copy;
    BOOST_REQUIRE(modelnet::EnvelopeFromJson(parsed, copy, err));
    BOOST_CHECK_EQUAL(copy.body["payload"]["price_atoms"].get_str(), "1");
    BOOST_CHECK(!modelnet::VerifySignedEnvelope(copy, network, err));
}

BOOST_AUTO_TEST_CASE(v11_envelope_with_repeated_payload_does_not_verify)
{
    std::vector<unsigned char> pk, sk;
    std::string err;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(pk, sk, err));
    const std::string id96(96, 'a');
    UniValue payload(UniValue::VOBJ);
    payload.pushKV("issuer_root", id96);
    payload.pushKV("revocation_epoch", "1");
    UniValue targets(UniValue::VARR);
    targets.push_back(id96);
    payload.pushKV("targets", targets);
    payload.pushKV("effective_after_ms", "0");
    payload.pushKV("reason_code", "KEY_COMPROMISE");
    payload.pushKV("prior_revocation_id", UniValue());
    payload.pushKV("quarantine_since_ms", "0");
    UniValue body(UniValue::VOBJ);
    body.pushKV("envelope_version", 2);
    body.pushKV("contract_revision", "1.1.0");
    body.pushKV("record_type", "Revocation");
    body.pushKV("network_id", std::string(64, 'a'));
    body.pushKV("realm_id", id96);
    body.pushKV("principal_id", id96);
    body.pushKV("signer_id", modelnet::ResearchIdentityId(pk).Hex());
    body.pushKV("key_epoch", "0");
    body.pushKV("public_key_hex", HexStr(pk));
    body.pushKV("delegation_id", UniValue());
    body.pushKV("created_ms", "1");
    body.pushKV("expires_ms", "9999999999999");
    body.pushKV("critical_extensions", UniValue(UniValue::VARR));
    body.pushKV("payload", payload);
    modelnet::Digest48 record_id;
    std::vector<unsigned char> preimage, sig;
    BOOST_REQUIRE(modelnet::RecordIdV11(body, record_id, err));
    BOOST_REQUIRE(modelnet::RecordPreimageV11(body, preimage, err));
    BOOST_REQUIRE(modelnet::SignMlDsa44(sk, preimage, sig, err));
    UniValue envelope(UniValue::VOBJ);
    envelope.pushKV("record_id", record_id.Hex());
    envelope.pushKV("body", body);
    envelope.pushKV("signature_hex", HexStr(sig));
    BOOST_REQUIRE(modelnet::VerifySignedEnvelopeV11(envelope, err));

    UniValue edited_payload = payload;
    UniValue other(UniValue::VARR);
    other.push_back(std::string(96, 'b'));
    edited_payload.pushKV("targets", other);
    const std::string edited = InsertFirst(envelope.write(), "\"body\":{", "\"payload\":" + edited_payload.write());
    UniValue parsed;
    BOOST_REQUIRE(parsed.read(edited));
    BOOST_CHECK_EQUAL(parsed["body"]["payload"]["targets"][0].get_str(), std::string(96, 'b'));
    BOOST_CHECK(!modelnet::VerifySignedEnvelopeV11(parsed, err));
}

BOOST_AUTO_TEST_SUITE_END()
