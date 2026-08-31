// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <compat/compat.h>
#include <net.h>
#include <net_processing.h>
#include <netaddress.h>
#include <netbase.h>
#include <netgroup.h>
#include <node/connection_types.h>
#include <node/protocol_version.h>
#include <protocol.h>
#include <random.h>
#include <test/util/logging.h>
#include <test/util/net.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <util/chaintype.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

struct LogIPsTestingSetup : public TestingSetup {
    LogIPsTestingSetup()
        : TestingSetup{ChainType::MAIN, {.extra_args = {"-logips"}}} {}
};

BOOST_FIXTURE_TEST_SUITE(net_peer_connection_tests, LogIPsTestingSetup)

static CService ip(uint32_t i)
{
    struct in_addr s;
    s.s_addr = i;
    return CService{CNetAddr{s}, Params().GetDefaultPort()};
}

struct PeerTest : LogIPsTestingSetup {
/** Create a peer and connect to it. If the optional `address` (IP/CJDNS only) isn't passed, a random address is created. */
void AddPeer(NodeId& id, std::vector<CNode*>& nodes, PeerManager& peerman, ConnmanTestMsg& connman, ConnectionType conn_type, bool onion_peer = false, std::optional<std::string> address = std::nullopt)
{
    CAddress addr{};

    if (address.has_value()) {
        addr = CAddress{MaybeFlipIPv6toCJDNS(LookupNumeric(address.value(), Params().GetDefaultPort())), NODE_NONE};
    } else if (onion_peer) {
        auto tor_addr{m_rng.randbytes(ADDR_TORV3_SIZE)};
        BOOST_REQUIRE(addr.SetSpecial(OnionToString(tor_addr)));
    }

    while (!addr.IsLocal() && !addr.IsRoutable()) {
        addr = CAddress{ip(m_rng.randbits(32)), NODE_NONE};
    }

    BOOST_REQUIRE(addr.IsValid());

    const bool inbound_onion{onion_peer && conn_type == ConnectionType::INBOUND};

    nodes.emplace_back(new CNode{++id,
                                 /*sock=*/nullptr,
                                 addr,
                                 /*nKeyedNetGroupIn=*/0,
                                 /*nLocalHostNonceIn=*/0,
                                 CAddress{},
                                 /*addrNameIn=*/"",
                                 conn_type,
                                 /*inbound_onion=*/inbound_onion,
                                 /*network_key=*/0});
    CNode& node = *nodes.back();
    node.SetCommonVersion(PROTOCOL_VERSION);

    peerman.InitializeNode(node, ServiceFlags(NODE_NETWORK | NODE_WITNESS));
    node.fSuccessfullyConnected = true;

    connman.AddTestNode(node);
}
}; // struct PeerTest

BOOST_FIXTURE_TEST_CASE(test_addnode_getaddednodeinfo_and_connection_detection, PeerTest)
{
    auto connman = std::make_unique<ConnmanTestMsg>(0x1337, 0x1337, *m_node.addrman, *m_node.netgroupman, Params());
    auto peerman = PeerManager::make(*connman, *m_node.addrman, nullptr, *m_node.chainman, *m_node.mempool, *m_node.warnings, {});
    NodeId id{0};
    std::vector<CNode*> nodes;

    // Connect a localhost peer.
    {
        AddPeer(id, nodes, *peerman, *connman, ConnectionType::MANUAL, /*onion_peer=*/false, /*address=*/"127.0.0.1");
        BOOST_REQUIRE(nodes.back() != nullptr);
    }

    // Call ConnectNode(), which is also called by RPC addnode onetry, for a localhost
    // address that resolves to multiple IPs, including that of the connected peer.
    // The connection attempt should consistently fail due to the check in ConnectNode().
    for (int i = 0; i < 10; ++i) {
        BOOST_CHECK(!connman->ConnectNodePublic(*peerman, "localhost", ConnectionType::MANUAL));
    }

    // Add 3 more peer connections.
    AddPeer(id, nodes, *peerman, *connman, ConnectionType::OUTBOUND_FULL_RELAY);
    AddPeer(id, nodes, *peerman, *connman, ConnectionType::BLOCK_RELAY, /*onion_peer=*/true);
    AddPeer(id, nodes, *peerman, *connman, ConnectionType::INBOUND);

    // Add a CJDNS peer connection.
    AddPeer(id, nodes, *peerman, *connman, ConnectionType::INBOUND, /*onion_peer=*/false,
            /*address=*/"[fc00:3344:5566:7788:9900:aabb:ccdd:eeff]:1234");
    BOOST_CHECK(nodes.back()->IsInboundConn());
    BOOST_CHECK_EQUAL(nodes.back()->ConnectedThroughNetwork(), Network::NET_CJDNS);

    BOOST_TEST_MESSAGE("Call AddNode() for all the peers");
    for (auto node : connman->TestNodes()) {
        BOOST_CHECK(connman->AddNode({/*m_added_node=*/node->addr.ToStringAddrPort(), /*m_use_v2transport=*/true}));
        BOOST_TEST_MESSAGE(strprintf("peer id=%s addr=%s", node->GetId(), node->addr.ToStringAddrPort()));
    }

    BOOST_TEST_MESSAGE("\nCall AddNode() with 2 addrs resolving to existing localhost addnode entry; neither should be added");
    BOOST_CHECK(!connman->AddNode({/*m_added_node=*/"127.0.0.1", /*m_use_v2transport=*/true}));
    // OpenBSD doesn't support the IPv4 shorthand notation with omitted zero-bytes.
#if !defined(__OpenBSD__)
    BOOST_CHECK(!connman->AddNode({/*m_added_node=*/"127.1", /*m_use_v2transport=*/true}));
#endif

    BOOST_TEST_MESSAGE("\nCall AddNode() with a CJDNS service equal to an existing addnode entry; it should not be added");
    BOOST_CHECK(!connman->AddNode({/*m_added_node=*/"[fc00:3344:5566:7788:9900:aabb:ccdd:eeff]:1234", /*m_use_v2transport=*/false}));

    BOOST_TEST_MESSAGE("\nCall AddNode() with a CJDNS addr equal to an existing inbound one but with a different port specified; it should not be added");
    BOOST_CHECK(!connman->AddNode({/*m_added_node=*/"[fc00:3344:5566:7788:9900:aabb:ccdd:eeff]:8333", /*m_use_v2transport=*/false}));

    BOOST_TEST_MESSAGE("\nCall AddNode() with a CJDNS addr equal to an existing inbound one but resolving to a different port; it should not be added");
    BOOST_CHECK(!connman->AddNode({/*m_added_node=*/"fc00:3344:5566:7788:9900:aabb:ccdd:eeff", /*m_use_v2transport=*/false}));

    BOOST_TEST_MESSAGE("\nExpect GetAddedNodeInfo to return expected number of peers with `include_connected` true/false");
    BOOST_CHECK_EQUAL(connman->GetAddedNodeInfo(/*include_connected=*/true).size(), nodes.size());
    BOOST_CHECK(connman->GetAddedNodeInfo(/*include_connected=*/false).empty());

    // Test AddedNodesContain()
    for (auto node : connman->TestNodes()) {
        BOOST_CHECK(connman->AddedNodesContain(node->addr));
    }
    AddPeer(id, nodes, *peerman, *connman, ConnectionType::OUTBOUND_FULL_RELAY);
    BOOST_CHECK(!connman->AddedNodesContain(nodes.back()->addr));

    BOOST_TEST_MESSAGE("\nPrint GetAddedNodeInfo contents:");
    for (const auto& info : connman->GetAddedNodeInfo(/*include_connected=*/true)) {
        BOOST_TEST_MESSAGE(strprintf("\nadded node: %s", info.m_params.m_added_node));
        BOOST_TEST_MESSAGE(strprintf("connected: %s", info.fConnected));
        if (info.fConnected) {
            BOOST_TEST_MESSAGE(strprintf("IP address: %s", info.resolvedAddress.ToStringAddrPort()));
            BOOST_TEST_MESSAGE(strprintf("direction: %s", info.fInbound ? "inbound" : "outbound"));
        }
    }

    BOOST_TEST_MESSAGE("\nCheck that all connected peers are correctly detected as connected");
    for (auto node : connman->TestNodes()) {
        BOOST_CHECK(connman->AlreadyConnectedPublic(node->addr));
    }

    // Clean up
    for (auto node : connman->TestNodes()) {
        peerman->FinalizeNode(*node);
    }
    connman->ClearTestNodes();
}

BOOST_AUTO_TEST_CASE(snapshot_background_download_not_gated_on_header_gap)
{
    BOOST_CHECK(!ShouldFetchBackgroundSnapshotBlocks(
        /*background_sync=*/false, /*limited_peer=*/false,
        /*initial_block_download=*/false, /*active_height=*/200,
        /*best_header_height=*/200));
    BOOST_CHECK(!ShouldFetchBackgroundSnapshotBlocks(
        /*background_sync=*/true, /*limited_peer=*/true,
        /*initial_block_download=*/false, /*active_height=*/200,
        /*best_header_height=*/200));
    BOOST_CHECK(!ShouldFetchBackgroundSnapshotBlocks(
        /*background_sync=*/true, /*limited_peer=*/false,
        /*initial_block_download=*/true, /*active_height=*/200,
        /*best_header_height=*/200));
    // MendeMatthias / v0.34.4: loadtxoutset tip 199300, headers 199303.
    // The old active >= best_header-1 gate (199300 >= 199302) starved
    // background fetch forever. Height gap is not a gate.
    BOOST_CHECK(ShouldFetchBackgroundSnapshotBlocks(
        /*background_sync=*/true, /*limited_peer=*/false,
        /*initial_block_download=*/false, /*active_height=*/199300,
        /*best_header_height=*/199303));
    BOOST_CHECK(ShouldFetchBackgroundSnapshotBlocks(
        /*background_sync=*/true, /*limited_peer=*/false,
        /*initial_block_download=*/false, /*active_height=*/150,
        /*best_header_height=*/200));
    BOOST_CHECK(ShouldFetchBackgroundSnapshotBlocks(
        /*background_sync=*/true, /*limited_peer=*/false,
        /*initial_block_download=*/false, /*active_height=*/199,
        /*best_header_height=*/200));
    BOOST_CHECK(ShouldFetchBackgroundSnapshotBlocks(
        /*background_sync=*/true, /*limited_peer=*/false,
        /*initial_block_download=*/false, /*active_height=*/200,
        /*best_header_height=*/200));
}

BOOST_AUTO_TEST_CASE(snapshot_background_inflight_share_reserves_active_capacity)
{
    // Floor of 1 at the MendeMatthias 199300/199303 gap — not a height gate.
    BOOST_CHECK_EQUAL(BackgroundSnapshotInflightShare(16, 199300, 199303), 1);
    BOOST_CHECK_EQUAL(BackgroundSnapshotAdditionalSlots(
        16, /*active_queued=*/0, /*existing_peer_bg=*/0, /*existing_global_bg=*/0,
        199300, 199303), 1);
    BOOST_CHECK_EQUAL(BackgroundSnapshotAdditionalSlots(
        16, /*active_queued=*/3, 0, 0, 199300, 199303), 1);
    // Active filled the window this pass: background waits, no height gate.
    BOOST_CHECK_EQUAL(BackgroundSnapshotAdditionalSlots(
        16, /*active_queued=*/16, 0, 0, 199300, 199303), 0);
    // Already at the floor globally: second scarce peer gets nothing extra.
    BOOST_CHECK_EQUAL(BackgroundSnapshotAdditionalSlots(
        16, 0, 0, /*existing_global_bg=*/1, 199300, 199303), 0);
    // Caught up: leftover after the always-reserved active slot.
    BOOST_CHECK_EQUAL(BackgroundSnapshotInflightShare(16, 200, 200), 15);
    BOOST_CHECK_EQUAL(BackgroundSnapshotAdditionalSlots(
        16, /*active_queued=*/0, 0, 0, 200, 200), 15);
    BOOST_CHECK_EQUAL(BackgroundSnapshotAdditionalSlots(
        16, /*active_queued=*/4, 0, 0, 200, 200), 12);
    BOOST_CHECK_EQUAL(BackgroundSnapshotInflightShare(2, 200, 200), 1);
    // One header of lag: quarter share, at least 1, never the last slot.
    BOOST_CHECK_EQUAL(BackgroundSnapshotInflightShare(16, 199, 200), 4);
    BOOST_CHECK_EQUAL(BackgroundSnapshotInflightShare(2, 199, 200), 1);
}

BOOST_AUTO_TEST_CASE(snapshot_unvalidated_peer_skip_allows_tip_chain)
{
    // Competing BestKnown without the snapshot base: still skip.
    BOOST_CHECK(SnapshotUnvalidatedPeerLacksBase(
        /*has_snapshot_base=*/true, /*snapshot_validated=*/false,
        /*peer_best_contains_snapshot_base=*/false,
        /*peer_best_extends_active_tip=*/false));
    // Same-chain suffix above the snapshot tip: do not skip (gate 3).
    BOOST_CHECK(!SnapshotUnvalidatedPeerLacksBase(
        true, false, /*peer_best_contains_snapshot_base=*/true,
        /*peer_best_extends_active_tip=*/true));
    BOOST_CHECK(!SnapshotUnvalidatedPeerLacksBase(
        true, false, /*contains_base=*/false, /*extends_tip=*/true));
    BOOST_CHECK(!SnapshotUnvalidatedPeerLacksBase(
        true, /*snapshot_validated=*/true, false, false));
    BOOST_CHECK(!SnapshotUnvalidatedPeerLacksBase(
        /*has_snapshot_base=*/false, false, false, false));
}

BOOST_AUTO_TEST_SUITE_END()
