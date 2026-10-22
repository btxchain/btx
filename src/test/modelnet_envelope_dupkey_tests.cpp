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
    // The same key in separate objects is not a repeat.
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

BOOST_AUTO_TEST_SUITE_END()
