// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <addresstype.h>
#include <bech32.h>
#include <key_io.h>
#include <outputtype.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

namespace {

uint256 ParseU256(std::string_view hex)
{
    const auto parsed = uint256::FromHex(hex);
    assert(parsed.has_value());
    return *parsed;
}

std::string EncodeWitnessV2WithProgram(Span<const unsigned char> program)
{
    std::vector<unsigned char> data = {2};
    ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, program.begin(), program.end());
    return bech32::Encode(bech32::Encoding::BECH32M, Params().Bech32HRP(), data);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_address_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(witness_v2_p2mr_destination_type_exists)
{
    const uint256 mr = ParseU256("11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff");
    const WitnessV2P2MR p2mr{mr};

    BOOST_CHECK_EQUAL(uint256{p2mr}.ToString(), mr.ToString());
    BOOST_CHECK(!std::holds_alternative<WitnessV1Taproot>(CTxDestination{p2mr}));
}

BOOST_AUTO_TEST_CASE(encode_p2mr_address_mainnet)
{
    SelectParams(ChainType::MAIN);

    const uint256 mr = ParseU256("00112233445566778899aabbccddeeffffeeddccbbaa99887766554433221100");
    const std::string addr = EncodeDestination(CTxDestination{WitnessV2P2MR{mr}});

    BOOST_CHECK(addr.rfind("btx1z", 0) == 0);
    const auto decoded = bech32::Decode(addr);
    BOOST_CHECK_EQUAL(decoded.encoding, bech32::Encoding::BECH32M);
}

BOOST_AUTO_TEST_CASE(decode_p2mr_address_mainnet)
{
    SelectParams(ChainType::MAIN);

    const uint256 mr = ParseU256("f0e1d2c3b4a5968778695a4b3c2d1e0f00112233445566778899aabbccddeeff");
    const CTxDestination encoded_dest = CTxDestination{WitnessV2P2MR{mr}};
    const std::string addr = EncodeDestination(encoded_dest);

    const CTxDestination decoded = DecodeDestination(addr);
    BOOST_REQUIRE(std::holds_alternative<WitnessV2P2MR>(decoded));

    const auto& p2mr = std::get<WitnessV2P2MR>(decoded);
    BOOST_CHECK_EQUAL(uint256{p2mr}.ToString(), mr.ToString());
}

BOOST_AUTO_TEST_CASE(p2mr_address_rejects_wrong_length)
{
    SelectParams(ChainType::MAIN);

    const std::vector<unsigned char> short_program(20, 0x42);
    const std::string bad_addr = EncodeWitnessV2WithProgram(short_program);

    const CTxDestination decoded = DecodeDestination(bad_addr);
    BOOST_CHECK(std::holds_alternative<CNoDestination>(decoded));
}

BOOST_AUTO_TEST_CASE(output_type_p2mr_exists)
{
    const auto parsed = ParseOutputType("p2mr");
    BOOST_REQUIRE(parsed.has_value());
    BOOST_CHECK_EQUAL(*parsed, OutputType::P2MR);
    BOOST_CHECK_EQUAL(FormatOutputType(OutputType::P2MR), "p2mr");
}

BOOST_AUTO_TEST_CASE(output_type_from_p2mr_destination)
{
    const uint256 mr = ParseU256("abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd");
    const auto type = OutputTypeFromDestination(CTxDestination{WitnessV2P2MR{mr}});

    BOOST_REQUIRE(type.has_value());
    BOOST_CHECK_EQUAL(*type, OutputType::P2MR);
}

BOOST_AUTO_TEST_CASE(get_script_for_p2mr_destination)
{
    const uint256 mr = ParseU256("1234123412341234123412341234123412341234123412341234123412341234");
    const CScript script = GetScriptForDestination(CTxDestination{WitnessV2P2MR{mr}});

    int witver{-1};
    std::vector<unsigned char> witprog;
    BOOST_REQUIRE(script.IsWitnessProgram(witver, witprog));
    BOOST_CHECK_EQUAL(witver, 2);
    BOOST_CHECK_EQUAL(witprog.size(), WITNESS_V2_P2MR_SIZE);
    BOOST_CHECK(witprog == ToByteVector(WitnessV2P2MR{mr}));
}

BOOST_AUTO_TEST_SUITE_END()
