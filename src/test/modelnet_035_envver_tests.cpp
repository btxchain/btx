// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// Regression: a v1.1 signed-record body whose envelope_version is a JSON number
// outside int range must be reported as BTX035_ENVELOPE_VERSION, not throw
// std::runtime_error ("JSON integer out of range") from getInt<int>().

#include <modelnet/canonical_codec.h>
#include <test/util/setup_common.h>
#include <univalue.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_035_envver_tests, BasicTestingSetup)

namespace {

UniValue BodyWithVersion(const UniValue& envelope_version)
{
    // A body that passes BodyFieldsV11 (14 well-formed fields) except that the
    // caller supplies envelope_version, which BodyFieldsV11 does not constrain.
    UniValue payload(UniValue::VOBJ);
    payload.pushKV("device_id", std::string(96, 'a'));
    payload.pushKV("realm_id", std::string(96, 'a'));
    payload.pushKV("observation_epoch", "0");
    payload.pushKV("previous_observation_head", std::string(96, 'a'));
    payload.pushKV("device_runtime_key_id", std::string(96, 'a'));
    payload.pushKV("fleet_policy_id", std::string(96, 'a'));
    payload.pushKV("recovery_anchor_id", std::string(96, 'a'));

    UniValue body(UniValue::VOBJ);
    body.pushKV("envelope_version", envelope_version);
    body.pushKV("contract_revision", "1.1.0");
    body.pushKV("record_type", "DeviceObservationGenesis");
    body.pushKV("network_id", std::string(64, 'a'));
    body.pushKV("realm_id", std::string(96, 'a'));
    body.pushKV("principal_id", std::string(96, 'a'));
    body.pushKV("signer_id", std::string(96, 'a'));
    body.pushKV("key_epoch", "0");
    body.pushKV("public_key_hex", std::string(2624, 'a'));
    body.pushKV("delegation_id", UniValue());
    body.pushKV("created_ms", "1");
    body.pushKV("expires_ms", "1");
    body.pushKV("critical_extensions", UniValue(UniValue::VARR));
    body.pushKV("payload", payload);
    return body;
}

UniValue ParseNum(const std::string& token)
{
    // Store an out-of-int-range integer the way UniValue::read would from JSON.
    UniValue parsed;
    BOOST_REQUIRE(parsed.read("{\"envelope_version\":" + token + "}"));
    return parsed["envelope_version"];
}

} // namespace

// RecordPreimageV11 is the patched function: it must not throw on an out-of-range
// envelope_version, and it must report BTX035_ENVELOPE_VERSION.
BOOST_AUTO_TEST_CASE(record_preimage_out_of_range_envelope_version_is_rejected)
{
    for (const char* token : {"18446744073709551616", "99999999999999999999", "2147483648", "-1", "3"}) {
        UniValue body = BodyWithVersion(ParseNum(token));
        std::vector<unsigned char> preimage;
        std::string err;
        bool ok = true;
        BOOST_CHECK_NO_THROW(ok = modelnet::RecordPreimageV11(body, preimage, err));
        BOOST_CHECK(!ok);
        BOOST_CHECK_EQUAL(err, "BTX035_ENVELOPE_VERSION");
    }
}

// The exact integer 2 still produces a preimage.
BOOST_AUTO_TEST_CASE(record_preimage_accepts_version_two)
{
    UniValue body = BodyWithVersion(UniValue(2));
    std::vector<unsigned char> preimage;
    std::string err;
    bool ok = false;
    BOOST_CHECK_NO_THROW(ok = modelnet::RecordPreimageV11(body, preimage, err));
    BOOST_CHECK(ok);
    BOOST_CHECK(!preimage.empty());
}

// End-to-end: lab.record_verify / lab.record_import reach RecordIdV11 through
// VerifySignedEnvelopeV11 after BodyFieldsV11 (which does not constrain the
// version), so the same out-of-range value must be a clean reason code, not a
// thrown exception. A value in (INT_MAX, UINT64_MAX] is accepted by the whole-
// envelope CanonicalEncode step and only fails the int cast inside RecordIdV11,
// which is exactly the code path this patch guards. The signature is never
// reached, so a placeholder is fine.
BOOST_AUTO_TEST_CASE(verify_signed_envelope_out_of_range_version_does_not_throw)
{
    UniValue envelope(UniValue::VOBJ);
    envelope.pushKV("record_id", std::string(96, 'a'));
    envelope.pushKV("body", BodyWithVersion(ParseNum("2147483648")));
    envelope.pushKV("signature_hex", std::string(4840, '0'));
    std::string err;
    bool valid = true;
    BOOST_CHECK_NO_THROW(valid = modelnet::VerifySignedEnvelopeV11(envelope, err));
    BOOST_CHECK(!valid);
    BOOST_CHECK_EQUAL(err, "BTX035_ENVELOPE_VERSION");
}

BOOST_AUTO_TEST_SUITE_END()
