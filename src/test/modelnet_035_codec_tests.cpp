// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/canonical_codec.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <cstdlib>
#include <fstream>
#include <sstream>

BOOST_FIXTURE_TEST_SUITE(modelnet_035_codec_tests, BasicTestingSetup)

namespace {

bool VectorsConfigured()
{
    return std::getenv("BTX035_VECTORS") != nullptr || std::getenv("BTX035_SPEC") != nullptr;
}

fs::path VectorDir()
{
    if (const char* env = std::getenv("BTX035_VECTORS")) return fs::path(env);
    if (const char* spec = std::getenv("BTX035_SPEC")) return fs::path(spec) / "vectors" / "signed_records";
    return {};
}

std::string PathText(const std::filesystem::path& path)
{
    const std::u8string u = path.u8string();
    return std::string(u.begin(), u.end());
}

bool ReadEnvelope(const std::filesystem::path& path, UniValue& out)
{
    std::ifstream in(path);
    if (!in) return false;
    std::stringstream ss;
    ss << in.rdbuf();
    return out.read(ss.str());
}

UniValue EnvelopeWithPayload(const UniValue& envelope, const UniValue& payload)
{
    UniValue body = envelope["body"];
    body.pushKV("payload", payload);
    UniValue out = envelope;
    out.pushKV("body", body);
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(v11_signed_record_vectors_verify)
{
    if (!VectorsConfigured()) {
        BOOST_TEST_MESSAGE("BTX035_VECTORS and BTX035_SPEC are unset; skipping v11_signed_record_vectors_verify");
        return;
    }
    const fs::path dir = VectorDir();
    BOOST_REQUIRE_MESSAGE(fs::is_directory(dir), "v1.1 signed-record vectors are not available at " + PathText(dir));
    int n = 0;
    for (const auto& ent : fs::directory_iterator(dir)) {
        if (ent.path().extension() != ".json") continue;
        UniValue envelope;
        BOOST_REQUIRE_MESSAGE(ReadEnvelope(ent.path(), envelope), PathText(ent.path()));
        std::string err;
        BOOST_CHECK_MESSAGE(modelnet::VerifySignedEnvelopeV11(envelope, err),
                            PathText(ent.path().filename()) + " " + err);
        ++n;
    }
    BOOST_CHECK_EQUAL(n, 74);
}

BOOST_AUTO_TEST_CASE(v11_rejects_version_1_and_bad_signature)
{
    UniValue body(UniValue::VOBJ);
    body.pushKV("envelope_version", 1);
    std::vector<unsigned char> pre;
    std::string err;
    BOOST_CHECK(!modelnet::RecordPreimageV11(body, pre, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ENVELOPE_VERSION");

    if (!VectorsConfigured()) {
        BOOST_TEST_MESSAGE("BTX035_VECTORS and BTX035_SPEC are unset; skipping signed-record vector checks in v11_rejects_version_1_and_bad_signature");
        return;
    }
    const fs::path sample = VectorDir() / "IdentityGenesis.json";
    UniValue envelope;
    BOOST_REQUIRE(ReadEnvelope(sample, envelope));
    std::string sig = envelope["signature_hex"].get_str();
    sig[0] = (sig[0] == '0') ? '1' : '0';
    envelope.pushKV("signature_hex", sig);
    BOOST_CHECK(!modelnet::VerifySignedEnvelopeV11(envelope, err));
    BOOST_CHECK_EQUAL(err, "BTX035_SIGNATURE");
}

BOOST_AUTO_TEST_CASE(v11_payload_schema_rejects_extra_key_and_missing_label)
{
    if (!VectorsConfigured()) {
        BOOST_TEST_MESSAGE("BTX035_VECTORS and BTX035_SPEC are unset; skipping v11_payload_schema_rejects_extra_key_and_missing_label");
        return;
    }
    const fs::path sample = VectorDir() / "IdentityGenesis.json";
    UniValue envelope;
    BOOST_REQUIRE(ReadEnvelope(sample, envelope));
    const UniValue& payload = envelope["body"]["payload"];

    UniValue extra_payload = payload;
    extra_payload.pushKV("extra", "nope");
    std::string err;
    BOOST_CHECK(!modelnet::VerifySignedEnvelopeV11(EnvelopeWithPayload(envelope, extra_payload), err));
    BOOST_CHECK_EQUAL(err, "BTX035_OBJECT_KEYS");

    UniValue missing_payload(UniValue::VOBJ);
    const std::vector<std::string>& keys = payload.getKeys();
    const std::vector<UniValue>& values = payload.getValues();
    for (size_t i = 0; i < keys.size(); ++i) {
        if (keys[i] == "label") continue;
        missing_payload.pushKV(keys[i], values[i]);
    }
    BOOST_CHECK(!modelnet::VerifySignedEnvelopeV11(EnvelopeWithPayload(envelope, missing_payload), err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCHEMA");
}

BOOST_AUTO_TEST_SUITE_END()
