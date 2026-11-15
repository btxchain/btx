// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying file COPYING.
#include <chainparams.h>
#include <chainparamsbase.h>
#include <modelnet/model_nat.h>
#include <modelnet/native_discovery.h>
#include <modelnet/native_participation.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>
#include <boost/test/unit_test.hpp>
#include <array>
#include <limits>

BOOST_AUTO_TEST_SUITE(native_discovery_tests)

static modelnet::LanBeacon Beacon(uint16_t port = 30001)
{
    modelnet::LanBeacon b;
    b.network = "regtest";
    b.port = port;
    b.instance.fill(7);
    return b;
}

BOOST_AUTO_TEST_CASE(canonical_packet_and_chain_isolation)
{
    std::array<unsigned char, modelnet::MODEL_LAN_BEACON_SIZE> wire{};
    BOOST_REQUIRE(modelnet::EncodeLanBeacon(Beacon(), wire));
    modelnet::LanBeacon decoded;
    BOOST_REQUIRE(modelnet::DecodeLanBeacon(wire.data(), wire.size(), "regtest", decoded));
    BOOST_CHECK_EQUAL(decoded.port, 30001);
    BOOST_CHECK_EQUAL(decoded.network, "regtest");
    BOOST_CHECK(!modelnet::DecodeLanBeacon(wire.data(), wire.size(), "main", decoded));
    BOOST_CHECK(!modelnet::DecodeLanBeacon(wire.data(), wire.size() - 1, "regtest", decoded));
    wire[26] = 1;
    BOOST_CHECK(!modelnet::DecodeLanBeacon(wire.data(), wire.size(), "regtest", decoded));
}

BOOST_AUTO_TEST_CASE(no_rpc_metadata_public_or_hostname_hints)
{
    for (const char* ip : {"127.0.0.1", "169.254.169.254", "0.0.0.0", "8.8.8.8", "10.0.0.1.evil", "localhost", "::1", "172.32.0.1"})
        BOOST_CHECK(!modelnet::LanHintSourceAllowed(ip));
    for (const char* ip : {"10.0.0.1", "172.16.1.3", "172.31.255.254", "192.168.2.1"})
        BOOST_CHECK(modelnet::LanHintSourceAllowed(ip));
    std::array<unsigned char, modelnet::MODEL_LAN_BEACON_SIZE> wire{};
    for (uint16_t port : {0, 22, 80, 443, 8332, 18332, 18443, 29443, 29448})
        BOOST_CHECK(!modelnet::EncodeLanBeacon(Beacon(port), wire));
}

BOOST_FIXTURE_TEST_CASE(node_rpc_and_p2p_ports_are_never_hints_or_dials, BasicTestingSetup)
{
    std::array<unsigned char, modelnet::MODEL_LAN_BEACON_SIZE> wire{};
    for (const ChainType chain : {ChainType::MAIN, ChainType::TESTNET, ChainType::TESTNET4, ChainType::SIGNET,
                                  ChainType::REGTEST, ChainType::SHIELDEDV2DEV}) {
        const uint16_t rpc_port{CreateBaseChainParams(chain)->RPCPort()};
        const uint16_t p2p_port{CreateChainParams(*m_node.args, chain)->GetDefaultPort()};
        for (const uint16_t port : {rpc_port, p2p_port}) {
            BOOST_CHECK_MESSAGE(modelnet::IsForbiddenControlPort(port), ChainTypeToString(chain) << " port " << port);
            BOOST_CHECK_MESSAGE(!modelnet::EncodeLanBeacon(Beacon(port), wire), ChainTypeToString(chain) << " port " << port);
        }
    }
}

BOOST_AUTO_TEST_CASE(expiration_refresh_and_clock_reversal)
{
    modelnet::LanHintBook book;
    BOOST_REQUIRE(book.Observe("192.168.1.2", Beacon(), 100));
    BOOST_CHECK_EQUAL(book.Endpoints(101).size(), 1U);
    BOOST_CHECK(book.Endpoints(30100).empty());
    BOOST_REQUIRE(book.Observe("192.168.1.2", Beacon(), 50000));
    BOOST_CHECK(book.Endpoints(49999).empty());
    BOOST_REQUIRE(book.Observe("192.168.1.2", Beacon(), 60000));
    BOOST_REQUIRE(book.Observe("192.168.1.2", Beacon(), 80000));
    BOOST_CHECK_EQUAL(book.Endpoints(90000).size(), 1U);
    BOOST_CHECK(book.Endpoints(110000).empty());
}

BOOST_AUTO_TEST_CASE(global_and_per_source_bounds)
{
    modelnet::LanHintBook book;
    for (int i = 0; i < 4; ++i) BOOST_CHECK(book.Observe("10.1.1.1", Beacon(30000 + i), 1));
    BOOST_CHECK(!book.Observe("10.1.1.1", Beacon(30005), 1));
    for (int i = 2; i <= 61; ++i) BOOST_CHECK(book.Observe("10.1.1." + std::to_string(i), Beacon(), 1));
    BOOST_CHECK_EQUAL(book.Endpoints(1).size(), modelnet::MODEL_LAN_MAX_HINTS);
    BOOST_CHECK(!book.Observe("10.2.1.1", Beacon(), 1));
    BOOST_CHECK(book.Observe("10.2.1.1", Beacon(), 30001));
    BOOST_CHECK_EQUAL(book.Endpoints(30001).size(), 1U);
}

BOOST_AUTO_TEST_CASE(malformed_nonce_padding_and_network)
{
    std::array<unsigned char, modelnet::MODEL_LAN_BEACON_SIZE> wire{};
    auto b = Beacon(); b.instance.fill(0);
    BOOST_CHECK(!modelnet::EncodeLanBeacon(b, wire));
    b = Beacon(); b.network = "regtest\n";
    BOOST_CHECK(!modelnet::EncodeLanBeacon(b, wire));
    BOOST_REQUIRE(modelnet::EncodeLanBeacon(Beacon(), wire));
    wire[20] = 'x';
    BOOST_CHECK(!modelnet::DecodeLanBeacon(wire.data(), wire.size(), "regtest", b));
    BOOST_CHECK(!modelnet::DecodeLanBeacon(nullptr, wire.size(), "regtest", b));
}

BOOST_AUTO_TEST_CASE(automatic_policy_revocation_has_one_gate)
{
    modelnet::PreservationPolicy policy;
    policy.storage_quota_bytes = 1024;
    policy.follow_configured_peers = true;
    policy.preserve_rare = false;
    BOOST_CHECK(modelnet::AutomaticAcquisitionAllowed(policy, false));
    for (const auto seed : {modelnet::SeedMode::OFF, modelnet::SeedMode::MANUAL}) {
        policy.seed_mode = seed;
        BOOST_CHECK(!modelnet::AutomaticAcquisitionAllowed(policy, true));
    }
    policy.preserve_rare = true;
    BOOST_CHECK(modelnet::AutomaticAcquisitionAllowed(policy, true));
    BOOST_CHECK(!modelnet::AutomaticAcquisitionAllowed(policy, false));
    policy.seed_mode = modelnet::SeedMode::AUTO;
    // A denied rare-preservation permit does not revoke independent follow consent.
    BOOST_CHECK(modelnet::AutomaticAcquisitionAllowed(policy, false));
    policy.follow_configured_peers = false;
    BOOST_CHECK(!modelnet::AutomaticAcquisitionAllowed(policy, false));
    BOOST_CHECK(modelnet::AutomaticAcquisitionAllowed(policy, true));
    policy.storage_quota_bytes = 0;
    BOOST_CHECK(!modelnet::AutomaticAcquisitionAllowed(policy, true));
}

BOOST_AUTO_TEST_CASE(automatic_candidates_are_retained_chain_and_identity_observations)
{
    modelnet::NativePeerObservation observation;
    observation.endpoint = "192.168.1.2:30001";
    observation.network = "regtest";
    observation.transport_pin.assign(96, 'a');
    observation.observed_at_ms = 100;
    std::vector<modelnet::PreserveCandidate> candidates;
    modelnet::Digest48 outside;
    for (size_t i = 0; i <= modelnet::NATIVE_PEER_MODEL_LIMIT; ++i) {
        modelnet::PreserveCandidate candidate;
        candidate.model_id.data[0] = static_cast<unsigned char>(i + 1);
        candidate.bytes = i == modelnet::NATIVE_PEER_MODEL_LIMIT ? 1 : 100 + i;
        candidate.admission = modelnet::AdmissionLevel::BYTES_VERIFIED;
        if (modelnet::RecordNativeAdvertisedModel(observation, candidate.model_id.Hex())) candidates.push_back(candidate);
        else outside = candidate.model_id;
    }
    BOOST_REQUIRE_EQUAL(observation.advertised_models.size(), modelnet::NATIVE_PEER_MODEL_LIMIT);
    BOOST_REQUIRE_EQUAL(candidates.size(), modelnet::NATIVE_PEER_MODEL_LIMIT);
    BOOST_CHECK(modelnet::RecordNativeAdvertisedModel(observation, candidates.front().model_id.Hex()));
    BOOST_CHECK(!modelnet::RecordNativeAdvertisedModel(observation, outside.Hex()));
    modelnet::PreservationPolicy policy;
    policy.storage_quota_bytes = 1024;
    modelnet::PreserveCandidate selected;
    BOOST_REQUIRE(modelnet::SelectPeerFollow(candidates, {}, 1024, policy, selected));
    const auto model = selected.model_id.Hex();
    BOOST_CHECK(modelnet::NativePeerObservationAllows(observation, "regtest", model, 101, observation.transport_pin));
    // The old selector picked this cheapest 129th object, then had no authorized source.
    BOOST_CHECK(selected.model_id != outside);
    BOOST_CHECK(!modelnet::NativePeerObservationAllows(observation, "regtest", outside.Hex(), 101));
    BOOST_CHECK(!modelnet::NativePeerObservationAllows(observation, "main", model, 101));
    BOOST_CHECK(!modelnet::NativePeerObservationAllows(observation, "", model, 101));
    BOOST_CHECK(!modelnet::NativePeerObservationAllows(observation, "regtest", model, 101, std::string(96, 'b')));
    BOOST_CHECK(!modelnet::NativePeerObservationAllows(observation, "regtest", model, 99));
    BOOST_CHECK(!modelnet::NativePeerObservationAllows(observation, "regtest", model, 100 + modelnet::NATIVE_PEER_TTL_MS));
    observation.transport_pin.clear();
    BOOST_CHECK(!modelnet::NativePeerObservationAllows(observation, "regtest", model, 101));
}

BOOST_AUTO_TEST_CASE(every_automatic_transport_requires_an_explicit_network_response)
{
    UniValue response(UniValue::VOBJ);
    BOOST_CHECK(!modelnet::NativeAvailabilityMatchesNetwork(response, "regtest"));
    response.pushKV("network", false);
    BOOST_CHECK(!modelnet::NativeAvailabilityMatchesNetwork(response, "regtest"));
    response.pushKV("network", "main");
    BOOST_CHECK(!modelnet::NativeAvailabilityMatchesNetwork(response, "regtest"));
    response.pushKV("network", "regtest");
    BOOST_CHECK(modelnet::NativeAvailabilityMatchesNetwork(response, "regtest"));
    BOOST_CHECK(!modelnet::NativeAvailabilityMatchesNetwork(response, ""));
    BOOST_CHECK(!modelnet::NativeAvailabilityMatchesNetwork(UniValue(UniValue::VARR), "regtest"));
}

BOOST_AUTO_TEST_SUITE_END()
