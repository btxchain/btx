// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/data/key_io_invalid.json.h>
#include <test/data/key_io_valid.json.h>

#include <key.h>
#include <key_io.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <test/util/json.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/chaintype.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>

BOOST_FIXTURE_TEST_SUITE(key_io_tests, BasicTestingSetup)

// Goal: check that parsed keys match test payload
BOOST_AUTO_TEST_CASE(key_io_valid_parse)
{
    UniValue tests = read_json(json_tests::key_io_valid);

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = test.write();
        if (test.size() < 3) { // Allow for extra stuff (useful for comments)
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        const std::vector<unsigned char> exp_payload{ParseHex(test[1].get_str())};
        const UniValue &metadata = test[2].get_obj();
        bool isPrivkey = metadata.find_value("isPrivkey").get_bool();
        SelectParams(ChainTypeFromString(metadata.find_value("chain").get_str()).value());
        if (isPrivkey) {
            bool isCompressed = metadata.find_value("isCompressed").get_bool();
            CKey expected_key;
            expected_key.Set(exp_payload.begin(), exp_payload.end(), isCompressed);
            BOOST_REQUIRE_MESSAGE(expected_key.IsValid(), "Invalid expected key payload: " + strTest);
            const std::string encoded = EncodeSecret(expected_key);
            CKey decoded = DecodeSecret(encoded);
            BOOST_CHECK_MESSAGE(decoded.IsValid(), "!IsValid:" + strTest);
            BOOST_CHECK_MESSAGE(decoded.IsCompressed() == isCompressed, "compressed mismatch:" + strTest);
            BOOST_CHECK_MESSAGE(HexStr(decoded) == HexStr(exp_payload), "key mismatch:" + strTest);

            // Private key encoding must not decode as a destination.
            const CTxDestination destination = DecodeDestination(encoded);
            BOOST_CHECK_MESSAGE(!IsValidDestination(destination), "IsValid privkey as pubkey:" + strTest);
        } else {
            CScript expected_script(exp_payload.begin(), exp_payload.end());
            CTxDestination expected_destination;
            BOOST_REQUIRE_MESSAGE(ExtractDestination(expected_script, expected_destination), "Failed to extract destination: " + strTest);
            const std::string encoded = EncodeDestination(expected_destination);

            // Must decode into the same destination and script in current chain params.
            CTxDestination destination = DecodeDestination(encoded);
            if (std::holds_alternative<WitnessUnknown>(expected_destination)) {
                const WitnessUnknown& wit_unknown = std::get<WitnessUnknown>(expected_destination);
                if (wit_unknown.GetWitnessVersion() == 2 && wit_unknown.GetWitnessProgram().size() != WITNESS_V2_P2MR_SIZE) {
                    // BTX reserves witness v2 for P2MR (32-byte program); other lengths are invalid by policy.
                    BOOST_CHECK_MESSAGE(!IsValidDestination(destination), "Expected invalid BTX witness v2 non-P2MR address: " + strTest);
                    continue;
                }
            }
            CScript script = GetScriptForDestination(destination);
            BOOST_CHECK_MESSAGE(IsValidDestination(destination), "!IsValid:" + strTest);
            BOOST_CHECK_EQUAL(HexStr(script), HexStr(exp_payload));

            // Try flipped case version
            std::string case_flipped = encoded;
            for (char& c : case_flipped) {
                if (c >= 'a' && c <= 'z') {
                    c = (c - 'a') + 'A';
                } else if (c >= 'A' && c <= 'Z') {
                    c = (c - 'A') + 'a';
                }
            }
            destination = DecodeDestination(case_flipped);
            if (IsValidDestination(destination)) {
                script = GetScriptForDestination(destination);
                BOOST_CHECK_EQUAL(HexStr(script), HexStr(exp_payload));
            }

            // Public key must be invalid private key
            CKey privkey = DecodeSecret(encoded);
            BOOST_CHECK_MESSAGE(!privkey.IsValid(), "IsValid pubkey as privkey:" + strTest);
        }
    }
}

// Goal: check that generated keys match test vectors
BOOST_AUTO_TEST_CASE(key_io_valid_gen)
{
    UniValue tests = read_json(json_tests::key_io_valid);

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = test.write();
        if (test.size() < 3) // Allow for extra stuff (useful for comments)
        {
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        std::vector<unsigned char> exp_payload = ParseHex(test[1].get_str());
        const UniValue &metadata = test[2].get_obj();
        bool isPrivkey = metadata.find_value("isPrivkey").get_bool();
        SelectParams(ChainTypeFromString(metadata.find_value("chain").get_str()).value());
        if (isPrivkey) {
            bool isCompressed = metadata.find_value("isCompressed").get_bool();
            CKey key;
            key.Set(exp_payload.begin(), exp_payload.end(), isCompressed);
            assert(key.IsValid());
            const std::string encoded = EncodeSecret(key);
            CKey decoded = DecodeSecret(encoded);
            BOOST_CHECK_MESSAGE(decoded.IsValid(), "result mismatch: " + strTest);
            BOOST_CHECK_MESSAGE(HexStr(decoded) == HexStr(exp_payload), "payload mismatch: " + strTest);
            BOOST_CHECK_MESSAGE(decoded.IsCompressed() == isCompressed, "compression mismatch: " + strTest);
        } else {
            CTxDestination dest;
            CScript exp_script(exp_payload.begin(), exp_payload.end());
            BOOST_CHECK(ExtractDestination(exp_script, dest));
            const std::string address = EncodeDestination(dest);
            const CTxDestination decoded = DecodeDestination(address);
            if (std::holds_alternative<WitnessUnknown>(dest)) {
                const WitnessUnknown& wit_unknown = std::get<WitnessUnknown>(dest);
                if (wit_unknown.GetWitnessVersion() == 2 && wit_unknown.GetWitnessProgram().size() != WITNESS_V2_P2MR_SIZE) {
                    BOOST_CHECK(!IsValidDestination(decoded));
                    continue;
                }
            }
            BOOST_CHECK(IsValidDestination(decoded));
            BOOST_CHECK_EQUAL(HexStr(GetScriptForDestination(decoded)), HexStr(exp_payload));
        }
    }

    SelectParams(ChainType::MAIN);
}


// Goal: check that base58 parsing code is robust against a variety of corrupted data
BOOST_AUTO_TEST_CASE(key_io_invalid)
{
    UniValue tests = read_json(json_tests::key_io_invalid); // Negative testcases
    CKey privkey;
    CTxDestination destination;

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = test.write();
        if (test.size() < 1) // Allow for extra stuff (useful for comments)
        {
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        std::string exp_base58string = test[0].get_str();

        // must be invalid as public and as private key
        for (const auto& chain : {ChainType::MAIN, ChainType::TESTNET, ChainType::SIGNET, ChainType::REGTEST, ChainType::SHIELDEDV2DEV}) {
            SelectParams(chain);
            destination = DecodeDestination(exp_base58string);
            BOOST_CHECK_MESSAGE(!IsValidDestination(destination), "IsValid pubkey in mainnet:" + strTest);
            privkey = DecodeSecret(exp_base58string);
            BOOST_CHECK_MESSAGE(!privkey.IsValid(), "IsValid privkey in mainnet:" + strTest);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
