// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

// Randomized one- and two-block races on a trusted mirror (threshold 2 of 3,
// no local signer, -matmulvalidation=trusted). Each seed builds a network
// chain and one or two short twin branches below its top, then delivers the
// headers, bodies and signer attestations of every block in a seed-chosen
// order through the P2P handlers, with scheduling rounds in between. Peers
// answer GETDATA, GETHEADERS and GETMMATTEST from what has been published so
// far. Once the signers have signed K blocks past the highest race height,
// the mirror must reach the network tip within a bounded number of rounds,
// and no block of the signed chain may stay in a HEADER_ONLY skip set. A
// mirror that only gets there after one more signed block is reported as
// TAIL (a delay), one that does not as STUCK (a freeze, the check fails).
//
// One seed per process keeps every seed on a fresh chain:
//   MIRROR_RACE_SEED=<n> test_btx --run_test=<this suite>/<the random case>
// Without the variable seed 1 runs. Optional: MIRROR_RACE_WIDE (larger
// shapes, -reorgpolicy=bounded), MIRROR_RACE_SIGS_FIRST (every signature
// before its block's header), MIRROR_RACE_ROUNDS=<n> (default 16),
// MIRROR_RACE_VERBOSE.

#include <chain.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <kernel/chainstatemanager_opts.h>
#include <key.h>
#include <matmul/trusted_exact_replay_attestation.h>
#include <net_processing.h>
#include <netbase.h>
#include <node/matmul_trusted_attestations.h>
#include <node/miner.h>
#include <protocol.h>
#include <streams.h>
#include <test/util/mining.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <deque>
#include <limits>
#include <map>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace {

CService RaceTestService(uint32_t ipv4)
{
    struct in_addr s{};
    s.s_addr = ipv4;
    return CService(CNetAddr(s), Params().GetDefaultPort());
}

CBlock MineOnParent(const node::NodeContext& node, const uint256& prev_hash,
                    int32_t height, uint32_t n_time, int64_t median_time_past)
{
    CBlock block = node::BlockAssembler{
        node.chainman->ActiveChainstate(), nullptr, {}, node}
                       .CreateNewBlock()
                       ->block;
    block.hashPrevBlock = prev_hash;
    block.nTime = n_time;
    {
        CMutableTransaction coinbase{*block.vtx[0]};
        coinbase.vin[0].scriptSig = CScript() << height << OP_0;
        block.vtx[0] = MakeTransactionRef(coinbase);
    }
    block.hashMerkleRoot = BlockMerkleRoot(block);
    BOOST_REQUIRE(MineHeaderForConsensus(
        block, height, node.chainman->GetConsensus(), 5'000'000,
        median_time_past));
    return block;
}

struct OutMsg {
    std::string type;
    std::vector<unsigned char> data;
};

//! Every message the node queued to `node`: the one already in the V1
//! transport (header and payload come out as separate segments with a null
//! socket), then vSendMsg. Leaves the send side empty.
std::vector<OutMsg> TakeOutgoing(CNode& node)
{
    std::vector<OutMsg> out;
    LOCK(node.cs_vSend);
    {
        const auto [bytes, more, msg_type] = node.m_transport->GetBytesToSend(false);
        (void)more;
        if (!bytes.empty()) {
            std::string type{msg_type};
            std::vector<unsigned char> head(bytes.begin(), bytes.end());
            node.m_transport->MarkBytesSent(head.size());
            uint32_t size{0};
            if (head.size() == CMessageHeader::HEADER_SIZE) {
                DataStream hs{head};
                CMessageHeader hdr;
                hs >> hdr;
                size = hdr.nMessageSize;
            }
            std::vector<unsigned char> payload;
            if (size > 0) {
                const auto [pbytes, pmore, ptype] = node.m_transport->GetBytesToSend(false);
                (void)pmore;
                (void)ptype;
                payload.assign(pbytes.begin(), pbytes.end());
                node.m_transport->MarkBytesSent(payload.size());
            }
            out.push_back({type, std::move(payload)});
        }
    }
    for (const auto& msg : node.vSendMsg) out.push_back({msg.m_type, msg.data});
    node.vSendMsg.clear();
    node.m_send_memusage = 0;
    while (true) {
        const auto [bytes, more, msg_type] = node.m_transport->GetBytesToSend(false);
        (void)more;
        (void)msg_type;
        if (bytes.empty()) break;
        node.m_transport->MarkBytesSent(bytes.size());
    }
    return out;
}

struct RaceBlock {
    CBlock block;
    uint256 hash;
    int32_t height{0};
    int parent{-1};      //!< index in the block list, -1 = the base block
    int branch{0};       //!< 0 = network chain, r + 1 = twin of race r
    std::string label;
    int pins{0};         //!< pins that sign it (0, 1 or 2)
    bool late{false};    //!< its signatures go out with the extension
    bool push{false};    //!< a peer pushes the body unsolicited
};

enum class Ev { HDR, BODY, SIG, ROUND };
struct Event {
    Ev kind;
    int blk{-1};
    int arg{0};  //!< HDR/BODY: peer slot; SIG: pin; ROUND: seconds
};

struct Scenario {
    uint64_t seed{0};
    int races{1};
    std::vector<int> race_at;      //!< network index the twin replaces
    std::vector<int> twin_len;     //!< 1 or 2
    std::vector<int> twin_sign;    //!< 0 none, 1 quorum on all, 2 quorum on first only, 3 one pin
    std::vector<bool> twin_late;
    bool twin_first{false};
    bool network_first{false};
    int k_past{1};
    bool park_config{false};
    bool wide{false};
    bool bounded{false};
    int final_rounds{16};
    std::string Describe() const
    {
        std::ostringstream s;
        s << "seed=" << seed << " races=" << races;
        for (int r = 0; r < races; ++r) {
            s << " [r" << r << " at=N" << race_at[r] << " len=" << twin_len[r]
              << " sign=" << twin_sign[r] << (twin_late[r] ? " late" : "") << "]";
        }
        s << " twin_first=" << twin_first << " k=" << k_past
          << " park=" << park_config;
        if (wide) s << " wide network_first=" << network_first << " bounded=" << bounded;
        return s.str();
    }
};

//! A fixed network chain N0..N(net_len-1) with no twins and a fixed event
//! order, for a minimized reproduction of one seed's behaviour.
struct ScriptStep {
    Ev kind;
    std::string label;  //!< block label ("N2"); empty for ROUND
    int arg{0};
};
struct Script {
    int net_len{3};
    std::map<std::string, int> pins;  //!< pins per block label (default 2)
    std::vector<ScriptStep> steps;
};

Scenario MakeScenario(uint64_t seed, std::mt19937_64& rng)
{
    Scenario sc;
    sc.seed = seed;
    auto pick = [&](int n) { return static_cast<int>(rng() % static_cast<uint64_t>(n)); };
    // MIRROR_RACE_WIDE: up to three races, two twins at one height, three-
    // block twins, K up to 5, one-pin network blocks, network-first order and
    // -reorgpolicy=bounded. Without it the seed space is the first campaign's.
    sc.wide = std::getenv("MIRROR_RACE_WIDE") != nullptr;
    sc.races = 1 + pick(sc.wide ? 3 : 2);
    int at{0};
    for (int r = 0; r < sc.races; ++r) {
        if (r > 0) at += sc.wide ? pick(5) : 1 + pick(5);
        sc.race_at.push_back(at);
        sc.twin_len.push_back(1 + pick(sc.wide ? 3 : 2));
        sc.twin_sign.push_back(pick(4));
        sc.twin_late.push_back(pick(3) == 0);
    }
    sc.twin_first = pick(2) == 0;
    sc.k_past = 1 + pick(sc.wide ? 5 : 3);
    sc.park_config = pick(2) == 0;
    if (sc.wide) {
        sc.network_first = !sc.twin_first && pick(2) == 0;
        sc.bounded = pick(2) == 0;
    }
    if (const char* v{std::getenv("MIRROR_RACE_ROUNDS")}) sc.final_rounds = std::atoi(v);
    return sc;
}

uint64_t SeedFromEnv(bool& from_env)
{
    from_env = false;
    if (const char* v{std::getenv("MIRROR_RACE_SEED")}) {
        from_env = true;
        return std::strtoull(v, nullptr, 10);
    }
    return 0;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(trusted_mirror_race_tests, RegTestingSetup)

static bool RunMirrorRace(node::NodeContext& m_node, uint64_t seed, const Script* script = nullptr)
    EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex)
{
    std::mt19937_64 rng{seed * 0x9E3779B97F4A7C15ULL + 0x632BE59BD9B4E019ULL};
    auto pick = [&](int n) { return static_cast<int>(rng() % static_cast<uint64_t>(n)); };
    const Scenario sc{[&] {
        if (script == nullptr) return MakeScenario(seed, rng);
        Scenario fixed;
        fixed.seed = seed;
        fixed.races = 0;
        fixed.k_past = script->net_len - 1;
        if (const char* v{std::getenv("MIRROR_RACE_ROUNDS")}) fixed.final_rounds = std::atoi(v);
        return fixed;
    }()};
    BOOST_TEST_MESSAGE("mirror-race " << sc.Describe());

    ChainstateManager& chainman{*Assert(m_node.chainman)};
    ConnmanTestMsg& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    PeerManager& peerman = *m_node.peerman;

    node::matmul_trusted::ResetForTest();
    peerman.ResetMatMulVerifyAdmissionForTest();
    chainman.m_blockman.m_blockfiles_indexed = true;
    chainman.m_blockman.m_importing = false;

    const CBlockIndex* base{WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    BOOST_REQUIRE(base != nullptr);
    SetMockTime(std::chrono::seconds{base->GetBlockTime() + 1});

    // Node configuration as on a GPU-less archive.
    auto& consensus = const_cast<Consensus::Params&>(chainman.GetParams().GetConsensus());
    auto& action = const_cast<kernel::DeepReorgAction&>(chainman.m_options.deep_reorg_action);
    auto& park_depth = const_cast<std::optional<uint32_t>&>(chainman.m_options.max_reorg_depth_park);
    auto& mode = const_cast<kernel::MatMulValidationMode&>(chainman.m_options.matmul_validation_mode);
    auto& check_index = const_cast<std::optional<int32_t>&>(chainman.m_options.check_block_index);
    auto& reorg_policy = const_cast<ChainstateManager::Options::ReorgPolicyMode&>(chainman.m_options.reorg_policy);
    struct RestorePolicy {
        ChainstateManager::Options::ReorgPolicyMode& policy;
        ChainstateManager::Options::ReorgPolicyMode saved;
        ~RestorePolicy() { policy = saved; }
    } restore_policy{reorg_policy, reorg_policy};
    if (sc.bounded) reorg_policy = ChainstateManager::Options::ReorgPolicyMode::BOUNDED;
    struct Restore {
        Consensus::Params& consensus;
        Consensus::Params saved;
        kernel::DeepReorgAction& action;
        kernel::DeepReorgAction saved_action;
        std::optional<uint32_t>& park_depth;
        std::optional<uint32_t> saved_park_depth;
        kernel::MatMulValidationMode& mode;
        kernel::MatMulValidationMode saved_mode;
        std::optional<int32_t>& check_index;
        std::optional<int32_t> saved_check_index;
        ~Restore()
        {
            node::matmul_trusted::ResetForTest();
            check_index = saved_check_index;
            consensus = saved;
            action = saved_action;
            park_depth = saved_park_depth;
            mode = saved_mode;
        }
    } restore{consensus, consensus, action, action, park_depth, park_depth, mode, mode,
              check_index, check_index};
    // CheckBlockIndex is a regtest consistency check (off on mainnet).
    // Convergence is measured with it off.
    check_index = 0;
    consensus.nMatMulV4Height = base->nHeight;
    consensus.nMatMulBMX4CHeight = base->nHeight;
    consensus.nMatMulDRLTHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulRCHeight = base->nHeight;
    consensus.nMatMulRCCoupledHeight = std::numeric_limits<int32_t>::max();
    mode = kernel::MatMulValidationMode::TRUSTED;
    if (sc.park_config) {
        consensus.nReorgProtectionStartHeight = base->nHeight;
        action = kernel::DeepReorgAction::PARK;
        park_depth = 32;
    }
    peerman.SetBestBlock(base->nHeight, std::chrono::seconds{base->GetBlockTime()});

    // Fixed pin keys keep a seed's run reproducible (key order and
    // signature bytes would otherwise change between processes).
    std::array<CKey, 3> pins;
    for (size_t i = 0; i < pins.size(); ++i) {
        std::array<unsigned char, 32> secret{};
        secret[0] = 0x5a;
        secret[31] = static_cast<unsigned char>(i + 1);
        pins[i].Set(secret.begin(), secret.end(), /*fCompressedIn=*/true);
        BOOST_REQUIRE(pins[i].IsValid());
    }
    const uint256 chain_id{uint256::FromHex(std::string(64, '1')).value()};
    const uint256 authority{uint256::FromHex(std::string(64, '2')).value()};
    {
        matmul::trusted::StoreConfig config;
        config.chain_id = chain_id;
        config.replay_authority_context = authority;
        config.trusted_signers = {pins[0].GetPubKey(), pins[1].GetPubKey(), pins[2].GetPubKey()};
        config.threshold = 2;
        std::string error;
        BOOST_REQUIRE(node::matmul_trusted::Configure(
            std::move(config), /*trusted_mirror=*/true, /*serve=*/false,
            std::chrono::milliseconds{50}, error));
    }
    BOOST_REQUIRE(node::matmul_trusted::IsTrustedMirror());
    BOOST_REQUIRE(!node::matmul_trusted::HasLocalSigner());

    // Blocks. Network chain N0..N(L-1) on the base; twin r replaces
    // N(race_at[r]) with twin_len[r] blocks on the same parent.
    std::vector<RaceBlock> blocks;
    int top{0};
    for (int r = 0; r < sc.races; ++r) top = std::max(top, sc.race_at[r] + sc.twin_len[r] - 1);
    const int net_len{top + 1 + sc.k_past};
    std::vector<int> net(net_len);
    const int64_t mtp{base->GetMedianTimePast()};
    for (int i = 0; i < net_len; ++i) {
        RaceBlock b;
        b.parent = i == 0 ? -1 : net[i - 1];
        const uint256 prev{i == 0 ? base->GetBlockHash() : blocks[net[i - 1]].hash};
        b.height = base->nHeight + 1 + i;
        b.block = MineOnParent(m_node, prev, b.height,
                               static_cast<uint32_t>(base->GetBlockTime() + 1 + 2 * i), mtp);
        b.hash = b.block.GetHash();
        b.branch = 0;
        b.label = "N" + std::to_string(i);
        // Race-height network blocks: signed on time, signed late, or only
        // covered by the signed blocks above them.
        if (i <= top) {
            const int s{pick(sc.wide ? 5 : 4)};
            b.pins = s == 3 ? 0 : (s == 4 ? 1 : 2);
            b.late = s == 2;
        } else {
            b.pins = 2;
        }
        b.push = pick(10) < 6;
        net[i] = static_cast<int>(blocks.size());
        blocks.push_back(std::move(b));
    }
    for (int r = 0; r < sc.races; ++r) {
        int parent{sc.race_at[r] == 0 ? -1 : net[sc.race_at[r] - 1]};
        for (int j = 0; j < sc.twin_len[r]; ++j) {
            RaceBlock b;
            b.parent = parent;
            const uint256 prev{parent < 0 ? base->GetBlockHash() : blocks[parent].hash};
            b.height = base->nHeight + 1 + sc.race_at[r] + j;
            const int i{sc.race_at[r] + j};
            b.block = MineOnParent(m_node, prev, b.height,
                                   static_cast<uint32_t>(base->GetBlockTime() + 2 + 2 * i + (sc.wide ? r : 0)), mtp);
            b.hash = b.block.GetHash();
            b.branch = r + 1;
            b.label = "T" + std::to_string(r) + "." + std::to_string(j);
            switch (sc.twin_sign[r]) {
            case 0: b.pins = 0; break;
            case 1: b.pins = 2; break;
            case 2: b.pins = j == 0 ? 2 : 0; break;
            default: b.pins = 1; break;
            }
            b.late = sc.twin_late[r];
            b.push = pick(10) < 7;
            parent = static_cast<int>(blocks.size());
            blocks.push_back(std::move(b));
        }
    }
    // A further signed block on the network tip. Published only when the
    // mirror has not converged, to tell a mirror that waits for the next
    // signature (a delay) from one that stays put (a freeze).
    const int tail{static_cast<int>(blocks.size())};
    {
        RaceBlock b;
        b.parent = net[net_len - 1];
        b.height = blocks[b.parent].height + 1;
        b.block = MineOnParent(m_node, blocks[b.parent].hash, b.height,
                               static_cast<uint32_t>(base->GetBlockTime() + 1 + 2 * net_len), mtp);
        b.hash = b.block.GetHash();
        b.branch = 0;
        b.label = "N" + std::to_string(net_len) + "tail";
        b.pins = 2;
        blocks.push_back(std::move(b));
        net.push_back(tail);
    }
    if (script != nullptr) {
        for (RaceBlock& b : blocks) {
            const auto it{script->pins.find(b.label)};
            b.pins = it == script->pins.end() ? 2 : it->second;
            b.late = false;
            b.push = false;
        }
    }
    std::map<uint256, int> by_hash;
    for (size_t i = 0; i < blocks.size(); ++i) {
        BOOST_REQUIRE(by_hash.emplace(blocks[i].hash, static_cast<int>(i)).second);
    }

    // Peers: two block sources and one attestation relay, distinct netgroups.
    const ServiceFlags services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS |
        NODE_MATMUL_ATTESTATION_ARCHIVE)};
    CNode p0{/*id=*/701, /*sock=*/nullptr, CAddress{RaceTestService(0x0107000a), NODE_NETWORK},
             /*nKeyedNetGroupIn=*/0x701, /*nLocalHostNonceIn=*/0, CAddress{},
             /*addrNameIn=*/"race-source-0", ConnectionType::OUTBOUND_FULL_RELAY,
             /*inbound_onion=*/false, /*network_key=*/0};
    CNode p1{/*id=*/702, /*sock=*/nullptr, CAddress{RaceTestService(0x0207000b), NODE_NETWORK},
             /*nKeyedNetGroupIn=*/0x702, /*nLocalHostNonceIn=*/0, CAddress{},
             /*addrNameIn=*/"race-source-1", ConnectionType::OUTBOUND_FULL_RELAY,
             /*inbound_onion=*/false, /*network_key=*/0};
    CNode att{/*id=*/703, /*sock=*/nullptr, CAddress{RaceTestService(0x0307000c), NODE_NETWORK},
              /*nKeyedNetGroupIn=*/0x703, /*nLocalHostNonceIn=*/0, CAddress{},
              /*addrNameIn=*/"race-attestations", ConnectionType::OUTBOUND_FULL_RELAY,
              /*inbound_onion=*/false, /*network_key=*/0};
    std::array<CNode*, 3> peers{&p0, &p1, &att};
    for (CNode* node : peers) {
        connman.Handshake(*node, /*successfully_connected=*/true, services, services,
                          PROTOCOL_VERSION, /*relay_txs=*/true,
                          /*starting_height=*/base->nHeight);
        connman.AddTestNode(*node);
        connman.FlushSendBuffer(*node);
    }
    struct FinalizePeers {
        ConnmanTestMsg& connman;
        PeerManager& peerman;
        std::array<CNode*, 3> peers;
        ~FinalizePeers()
        {
            for (CNode* node : peers) {
                peerman.FinalizeNode(*node);
                connman.RemoveTestNode(*node);
            }
        }
    } finalize{connman, peerman, peers};

    // What the network has published so far, and the requests it owes.
    std::vector<bool> published(blocks.size(), false);
    std::vector<std::set<int>> signed_by(blocks.size());
    struct Pending {
        std::deque<uint256> getdata;
        std::deque<uint256> getmmattest;
        std::deque<CBlockLocator> getheaders;
    };
    std::array<Pending, 3> pending;
    // Peers forward attestations they have accepted (cache-and-forward):
    // source 0 one round after the signer releases one, source 1 two rounds.
    struct Forward {
        int due_round;
        int blk;
        int pin;
    };
    std::array<std::vector<Forward>, 2> forwards;
    int round_no{0};
    std::ostringstream trace;
    size_t n_getdata{0}, n_getmmattest{0}, n_getheaders{0};
    const bool sigs_first{std::getenv("MIRROR_RACE_SIGS_FIRST") != nullptr};

    auto collect = [&](size_t slot) {
        for (OutMsg& msg : TakeOutgoing(*peers[slot])) {
            DataStream s{msg.data};
            try {
                if (msg.type == NetMsgType::GETDATA) {
                    std::vector<CInv> inv;
                    s >> inv;
                    for (const CInv& item : inv) {
                        if (item.IsGenBlkMsg()) {
                            pending[slot].getdata.push_back(item.hash);
                            ++n_getdata;
                        }
                    }
                } else if (msg.type == NetMsgType::GETMMATTEST) {
                    uint256 hash;
                    s >> hash;
                    pending[slot].getmmattest.push_back(hash);
                    ++n_getmmattest;
                } else if (msg.type == NetMsgType::GETHEADERS) {
                    CBlockLocator locator;
                    uint256 stop;
                    s >> locator >> stop;
                    pending[slot].getheaders.push_back(locator);
                    ++n_getheaders;
                }
            } catch (const std::ios_base::failure&) {
            }
        }
    };
    auto collect_all = [&] {
        for (size_t slot = 0; slot < peers.size(); ++slot) collect(slot);
    };
    auto deliver = [&](size_t slot, CSerializedNetMsg&& msg)
                       EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex) {
        CNode& node{*peers[slot]};
        if (node.fDisconnect) return;
        collect_all();
        BOOST_REQUIRE(connman.ReceiveMsgFrom(node, std::move(msg)));
        node.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(node);
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        collect_all();
    };
    auto path_headers = [&](int idx) {
        std::vector<CBlock> path;
        for (int walk{idx}; walk >= 0; walk = blocks[walk].parent) {
            path.emplace_back(blocks[walk].block.GetBlockHeader());
        }
        std::reverse(path.begin(), path.end());
        return path;
    };
    auto attestation_for = [&](int idx, int pin) {
        matmul::trusted::ExactReplayStatement statement;
        statement.chain_id = chain_id;
        statement.block_hash = blocks[idx].hash;
        statement.block_height = blocks[idx].height;
        statement.replay_authority_context = authority;
        auto attestation{matmul::trusted::SignStatement(statement, pins[pin])};
        BOOST_REQUIRE(attestation.has_value());
        return *attestation;
    };
    // Peers answer from what is published: block bodies, attestations the
    // pins have released, and network-chain headers past the locator.
    auto answer = [&](size_t slot, bool allow_defer)
                      EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex) {
        Pending& p{pending[slot]};
        std::deque<uint256> keep;
        while (!p.getdata.empty()) {
            const uint256 hash{p.getdata.front()};
            p.getdata.pop_front();
            const auto it{by_hash.find(hash)};
            if (it == by_hash.end() || !published[it->second]) continue;
            if (allow_defer && pick(10) < 2) {
                keep.push_back(hash);
                continue;
            }
            trace << " ans:block " << blocks[it->second].label << "@p" << slot;
            deliver(slot, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(blocks[it->second].block)));
        }
        for (const uint256& hash : keep) p.getdata.push_back(hash);
        while (!p.getmmattest.empty()) {
            const uint256 hash{p.getmmattest.front()};
            p.getmmattest.pop_front();
            const auto it{by_hash.find(hash)};
            if (it == by_hash.end() || signed_by[it->second].empty()) continue;
            std::vector<matmul::trusted::ExactReplayAttestation> reply;
            for (int pin : signed_by[it->second]) reply.push_back(attestation_for(it->second, pin));
            trace << " ans:att " << blocks[it->second].label << "x" << reply.size() << "@p" << slot;
            deliver(slot, NetMsg::Make(NetMsgType::MMATTEST, reply));
        }
        while (!p.getheaders.empty()) {
            const CBlockLocator locator{p.getheaders.front()};
            p.getheaders.pop_front();
            int start{-1};  // network index after which to send
            bool found{false};
            for (const uint256& have : locator.vHave) {
                if (have == base->GetBlockHash()) { start = -1; found = true; break; }
                const auto it{by_hash.find(have)};
                if (it != by_hash.end() && blocks[it->second].branch == 0) {
                    for (int i = 0; i < static_cast<int>(net.size()); ++i) {
                        if (net[i] == it->second) start = i;
                    }
                    found = true;
                    break;
                }
                if (it == by_hash.end()) {
                    // An ancestor of the base: send from the base's child.
                    found = true;
                    start = -1;
                    break;
                }
            }
            if (!found) continue;
            std::vector<CBlock> headers;
            for (int i = start + 1; i < static_cast<int>(net.size()) && published[net[i]]; ++i) {
                headers.emplace_back(blocks[net[i]].block.GetBlockHeader());
            }
            trace << " ans:hdrs " << headers.size() << "@p" << slot;
            deliver(slot, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(headers)));
        }
    };
    auto round = [&](int seconds, bool allow_defer)
                     EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex) {
        SetMockTime(GetMockTime() + std::chrono::seconds{seconds});
        ++round_no;
        for (size_t slot = 0; slot < forwards.size(); ++slot) {
            std::vector<matmul::trusted::ExactReplayAttestation> batch;
            std::vector<Forward> later;
            for (const Forward& f : forwards[slot]) {
                if (f.due_round <= round_no) {
                    batch.push_back(attestation_for(f.blk, f.pin));
                    trace << " fwd " << blocks[f.blk].label << "/k" << f.pin << "@p" << slot;
                } else {
                    later.push_back(f);
                }
            }
            forwards[slot] = std::move(later);
            if (!batch.empty()) deliver(slot, NetMsg::Make(NetMsgType::MMATTEST, batch));
        }
        for (size_t slot = 0; slot < peers.size(); ++slot) {
            if (peers[slot]->fDisconnect) continue;
            collect_all();
            (void)peerman.SendMessages(peers[slot]);
            m_node.validation_signals->SyncWithValidationInterfaceQueue();
            collect_all();
        }
        for (int pass = 0; pass < 3; ++pass) {
            for (size_t slot = 0; slot < peers.size(); ++slot) answer(slot, allow_defer && pass == 0);
        }
    };

    // Events. Race phase: every block up to the highest race height, with
    // on-time signatures. Extension phase: the K blocks past it, their
    // signatures and every late signature.
    std::vector<Event> race_ev, twin_ev, ext_ev;
    for (size_t i = 0; script == nullptr && i < blocks.size(); ++i) {
        if (static_cast<int>(i) == tail) continue;
        const RaceBlock& b{blocks[i]};
        const bool extension{b.branch == 0 && b.height > base->nHeight + 1 + top};
        const bool twin_apart{b.branch != 0 && (sc.twin_first || sc.network_first)};
        std::vector<Event>& dst{extension ? ext_ev : (twin_apart ? twin_ev : race_ev)};
        dst.push_back({Ev::HDR, static_cast<int>(i), pick(2)});
        if (b.push) dst.push_back({Ev::BODY, static_cast<int>(i), pick(2)});
        for (int pin = 0; pin < b.pins; ++pin) {
            Event sig{Ev::SIG, static_cast<int>(i), pin};
            if (b.late && !extension) {
                ext_ev.push_back(sig);
            } else if (twin_apart) {
                twin_ev.push_back(sig);
            } else {
                dst.push_back(sig);
            }
        }
    }
    auto order = [&](std::vector<Event>& ev) {
        std::shuffle(ev.begin(), ev.end(), rng);
        // A body goes out after its own header.
        for (size_t i = 0; i < ev.size(); ++i) {
            if (ev[i].kind != Ev::BODY) continue;
            for (size_t j = i + 1; j < ev.size(); ++j) {
                if (ev[j].kind == Ev::HDR && ev[j].blk == ev[i].blk) {
                    const Event body{ev[i]};
                    ev.erase(ev.begin() + i);
                    ev.insert(ev.begin() + j, body);
                    --i;
                    break;
                }
            }
        }
        // MIRROR_RACE_SIGS_FIRST: every on-time signature reaches the mirror
        // before the block's own header (the MMATTEST handler notes that
        // attestations routinely arrive minutes before the header).
        if (sigs_first) {
            for (size_t i = 0; i < ev.size(); ++i) {
                if (ev[i].kind != Ev::HDR) continue;
                const int blk{ev[i].blk};
                std::vector<Event> sigs;
                for (size_t j = i + 1; j < ev.size();) {
                    if (ev[j].kind == Ev::SIG && ev[j].blk == blk) {
                        sigs.push_back(ev[j]);
                        ev.erase(ev.begin() + j);
                    } else {
                        ++j;
                    }
                }
                // Three short rounds between them: the forwarded copies
                // arrive before the header too.
                if (!sigs.empty()) {
                    for (int r = 0; r < 3; ++r) sigs.push_back({Ev::ROUND, -1, 1});
                }
                ev.insert(ev.begin() + i, sigs.begin(), sigs.end());
                i += sigs.size();
            }
        }
        std::vector<Event> with_rounds;
        for (const Event& e : ev) {
            with_rounds.push_back(e);
            if (pick(10) < 4) {
                static constexpr std::array<int, 4> steps{1, 2, 5, 31};
                with_rounds.push_back({Ev::ROUND, -1, steps[pick(4)]});
            }
        }
        ev = std::move(with_rounds);
    };
    order(twin_ev);
    order(race_ev);
    order(ext_ev);
    std::vector<Event> all;
    if (sc.network_first) {
        all.insert(all.end(), race_ev.begin(), race_ev.end());
        all.insert(all.end(), twin_ev.begin(), twin_ev.end());
    } else {
        all.insert(all.end(), twin_ev.begin(), twin_ev.end());
        all.insert(all.end(), race_ev.begin(), race_ev.end());
    }
    all.insert(all.end(), ext_ev.begin(), ext_ev.end());
    if (script != nullptr) {
        for (const ScriptStep& step : script->steps) {
            int idx{-1};
            for (size_t i = 0; i < blocks.size(); ++i) {
                if (blocks[i].label == step.label) idx = static_cast<int>(i);
            }
            BOOST_REQUIRE(step.kind == Ev::ROUND || idx >= 0);
            all.push_back({step.kind, idx, step.arg});
        }
    }

    auto tip_label = [&]() -> std::string {
        LOCK(::cs_main);
        const CBlockIndex* tip{chainman.ActiveTip()};
        if (tip == base) return "base";
        const auto it{by_hash.find(tip->GetBlockHash())};
        return it == by_hash.end() ? tip->GetBlockHash().ToString().substr(0, 8) : blocks[it->second].label;
    };
    const size_t ext_start{twin_ev.size() + race_ev.size()};
    std::string race_end{"?"};
    auto snapshot = [&]() {
        std::string out{"tip=" + tip_label() + " skipped="};
        for (size_t i = 0; i < blocks.size(); ++i) {
            if (peerman.HeaderFetchSuppressedForTest(blocks[i].hash)) out += blocks[i].label + ",";
        }
        return out;
    };
    for (size_t ev_i = 0; ev_i <= all.size(); ++ev_i) {
        if (ev_i == ext_start) race_end = snapshot();
        if (ev_i == all.size()) break;
        const Event& e{all[ev_i]};
        switch (e.kind) {
        case Ev::HDR:
            // A peer that sends a header has its ancestors too.
            for (int walk{e.blk}; walk >= 0; walk = blocks[walk].parent) published[walk] = true;
            trace << " | hdr " << blocks[e.blk].label << "@p" << e.arg;
            deliver(static_cast<size_t>(e.arg), NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(path_headers(e.blk))));
            break;
        case Ev::BODY:
            trace << " | push " << blocks[e.blk].label << "@p" << e.arg;
            deliver(static_cast<size_t>(e.arg), NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(blocks[e.blk].block)));
            break;
        case Ev::SIG: {
            signed_by[e.blk].insert(e.arg);
            forwards[0].push_back({round_no + 1, e.blk, e.arg});
            forwards[1].push_back({round_no + 2, e.blk, e.arg});
            trace << " | sig " << blocks[e.blk].label << "/k" << e.arg;
            std::vector<matmul::trusted::ExactReplayAttestation> one{attestation_for(e.blk, e.arg)};
            deliver(2, NetMsg::Make(NetMsgType::MMATTEST, one));
            break;
        }
        case Ev::ROUND:
            trace << " | round+" << e.arg << "s";
            round(e.arg, /*allow_defer=*/true);
            break;
        }
        trace << " tip=" << tip_label();
    }

    // Convergence: rounds 1 s and 31 s apart, as the scheduler would see them.
    auto tip_is = [&](int idx) {
        return WITH_LOCK(::cs_main, return chainman.ActiveTip()->GetBlockHash()) == blocks[idx].hash;
    };
    auto run_rounds = [&](int target_idx) EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex) {
        int used{0};
        for (; used < sc.final_rounds; ++used) {
            if (tip_is(target_idx)) break;
            round(used % 2 == 0 ? 1 : 31, /*allow_defer=*/false);
        }
        return used;
    };
    auto signed_chain_suppressed = [&]() {
        for (size_t i = 0; i < blocks.size(); ++i) {
            if (blocks[i].branch == 0 && published[i] &&
                peerman.HeaderFetchSuppressedForTest(blocks[i].hash)) {
                return true;
            }
        }
        return false;
    };
    const int target{net[net_len - 1]};
    const int rounds_used{run_rounds(target)};
    trace << " | final tip=" << tip_label() << " after " << rounds_used << " rounds";
    const bool converged{tip_is(target) && !signed_chain_suppressed()};
    bool tail_converged{false};
    int tail_rounds{0};
    if (!converged) {
        // One more signed block, header first (or, with sigs_first,
        // signatures first as the others), as the next one would arrive.
        auto tail_header = [&]() EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex) {
            for (int walk{tail}; walk >= 0; walk = blocks[walk].parent) published[walk] = true;
            trace << " | TAIL hdr " << blocks[tail].label << "@p0";
            deliver(0, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(path_headers(tail))));
            round(1, /*allow_defer=*/false);
        };
        if (!sigs_first) tail_header();
        for (int pin = 0; pin < 2; ++pin) {
            signed_by[tail].insert(pin);
            forwards[0].push_back({round_no + 1, tail, pin});
            forwards[1].push_back({round_no + 2, tail, pin});
            trace << " | sig " << blocks[tail].label << "/k" << pin;
            std::vector<matmul::trusted::ExactReplayAttestation> one{attestation_for(tail, pin)};
            deliver(2, NetMsg::Make(NetMsgType::MMATTEST, one));
        }
        if (sigs_first) {
            round(1, /*allow_defer=*/false);
            round(1, /*allow_defer=*/false);
            round(1, /*allow_defer=*/false);
            tail_header();
        }
        tail_rounds = run_rounds(tail);
        trace << " | tail tip=" << tip_label() << " after " << tail_rounds << " rounds";
        tail_converged = tip_is(tail) && !signed_chain_suppressed();
    }

    std::ostringstream state;
    int quorum_missing{0};  // signed-chain blocks the pins signed but the mirror lacks quorum for
    {
        LOCK(::cs_main);
        const auto frontier{chainman.GetSignedFrontierStatus()};
        state << "frontier h=" << frontier.height << " on_active=" << frontier.on_active_chain
              << " behind=" << frontier.blocks_behind;
        const CBlockIndex* unique{chainman.FindUniqueCompetingAttestedIndex()};
        state << " find_unique=" << (unique == nullptr ? std::string{"null"} :
                                     (by_hash.count(unique->GetBlockHash()) ? blocks[by_hash[unique->GetBlockHash()]].label : std::string{"?"}));
        for (size_t i = 0; i < blocks.size(); ++i) {
            const CBlockIndex* idx{chainman.m_blockman.LookupBlockIndex(blocks[i].hash)};
            const bool suppressed{peerman.HeaderFetchSuppressedForTest(blocks[i].hash)};
            if (blocks[i].branch == 0 && signed_by[i].size() >= 2 &&
                !node::matmul_trusted::HasQuorum(blocks[i].hash, blocks[i].height)) {
                ++quorum_missing;
            }
            state << "\n  " << blocks[i].label << " h=" << blocks[i].height << " pins=" << blocks[i].pins
                  << (blocks[i].late ? " late" : "") << " pub=" << published[i] << " signed_by=" << signed_by[i].size();
            if (idx == nullptr) {
                state << " no-index";
                continue;
            }
            state << " data=" << ((idx->nStatus & BLOCK_HAVE_DATA) != 0)
                  << " failed=" << ((idx->nStatus & BLOCK_FAILED_MASK) != 0)
                  << " active=" << chainman.ActiveChain().Contains(idx)
                  << " quorum=" << node::matmul_trusted::HasQuorum(blocks[i].hash, blocks[i].height)
                  << " suppressed=" << suppressed;
        }
        for (size_t slot = 0; slot < peers.size(); ++slot) {
            state << "\n  peer" << slot << " disconnect=" << peers[slot]->fDisconnect;
        }
        state << "\n  requests getdata=" << n_getdata << " getmmattest=" << n_getmmattest
              << " getheaders=" << n_getheaders;
    }
    const char* result{converged ? "CONVERGED" : (tail_converged ? "TAIL" : "STUCK")};
    BOOST_TEST_MESSAGE("mirror-race seed=" << seed << " result=" << result
                       << " rounds=" << rounds_used << "+" << tail_rounds << " tip=" << tip_label()
                       << " quorum_missing=" << quorum_missing
                       << " race_end=[" << race_end << "]"
                       << " suppressed_signed=" << signed_chain_suppressed());
    if (!converged || std::getenv("MIRROR_RACE_VERBOSE") != nullptr) {
        BOOST_TEST_MESSAGE("mirror-race trace seed=" << seed << ":" << trace.str());
        BOOST_TEST_MESSAGE("mirror-race state seed=" << seed << ": " << state.str());
    }
    // A mirror that waits for the next signed block (TAIL) is reported, not
    // failed: on a live chain that is one block interval. One that stays off
    // the signed tip after it is a freeze.
    if (script != nullptr) {
        BOOST_CHECK_MESSAGE(converged, "script: mirror not on the signed tip " << blocks[target].label
                                           << " within " << sc.final_rounds << " rounds");
        return converged;
    }
    BOOST_CHECK_MESSAGE(converged || tail_converged,
                        "seed " << seed << ": mirror not on the signed tip " << blocks[tail].label
                                << " after " << sc.final_rounds << " rounds past a further signed block ("
                                << sc.Describe() << ")");
    for (size_t slot = 0; slot < peers.size(); ++slot) {
        BOOST_CHECK_MESSAGE(!peers[slot]->fDisconnect, "seed " << seed << ": peer slot " << slot << " disconnected");
    }
    return converged;
}

BOOST_AUTO_TEST_CASE(trusted_mirror_converges_after_random_races)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);
    bool from_env{false};
    const uint64_t env_seed{SeedFromEnv(from_env)};
    if (from_env) {
        RunMirrorRace(m_node, env_seed);
        return;
    }
    // Without MIRROR_RACE_SEED: one fixed seed per process run.
    RunMirrorRace(m_node, 1);
}

// Minimized from the TAIL seeds of the random case (seed 192 is one): the
// mirror is on N0, which has quorum. N1 is not signed on its own (signers that were on
// a twin sign only past it). Both signatures for N2 reach the mirror before
// N2's header: each MMATTEST for an unknown header triggers GETHEADERS and is
// dropped. The headers and bodies then arrive. N2 is above the signed
// frontier (N0), so the mirror does not ask for its attestations
// (RejectAboveFrontier), N1 has no quorum and no signed frontier covers it, and
// the mirror waits for the next signed block although its peers hold N2's
// quorum.
BOOST_AUTO_TEST_CASE(trusted_mirror_follows_signed_block_whose_attestations_preceded_its_header)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);
    Script script;
    script.net_len = 3;
    script.pins = {{"N0", 2}, {"N1", 0}, {"N2", 2}};
    script.steps = {
        {Ev::HDR, "N0", 0},
        {Ev::SIG, "N0", 0},
        {Ev::SIG, "N0", 1},
        {Ev::ROUND, "", 1},
        {Ev::ROUND, "", 1},
        {Ev::SIG, "N2", 0},
        {Ev::SIG, "N2", 1},
        {Ev::ROUND, "", 1},
        {Ev::ROUND, "", 1},
        {Ev::ROUND, "", 1},
        {Ev::HDR, "N2", 1},
    };
    RunMirrorRace(m_node, /*seed=*/0, &script);
}

// The same with three signed blocks past the unsigned N1, each one's
// signatures ahead of its header: none of them is a tip child of N0 or the
// signed frontier the mirror knows, so it asks for none of them.
BOOST_AUTO_TEST_CASE(trusted_mirror_follows_signed_blocks_whose_attestations_precede_their_headers)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);
    Script script;
    script.net_len = 5;
    script.pins = {{"N0", 2}, {"N1", 0}, {"N2", 2}, {"N3", 2}, {"N4", 2}};
    script.steps = {
        {Ev::HDR, "N0", 0},
        {Ev::SIG, "N0", 0},
        {Ev::SIG, "N0", 1},
        {Ev::ROUND, "", 1},
        {Ev::ROUND, "", 1},
    };
    for (const char* label : {"N2", "N3", "N4"}) {
        script.steps.push_back({Ev::SIG, label, 0});
        script.steps.push_back({Ev::SIG, label, 1});
        script.steps.push_back({Ev::ROUND, "", 1});
        script.steps.push_back({Ev::ROUND, "", 1});
        script.steps.push_back({Ev::ROUND, "", 1});
        script.steps.push_back({Ev::HDR, label, 1});
        script.steps.push_back({Ev::ROUND, "", 31});
        script.steps.push_back({Ev::ROUND, "", 31});
    }
    RunMirrorRace(m_node, /*seed=*/0, &script);
}

// Seeds of the random case that froze a mirror on a signed twin while the
// signers signed past it on the network chain; each stays put on cbf65894.
// 7: a signed one-block twin, the network sibling dropped HEADER_ONLY (the
// 27 Oct archive). 100: two signed one-block twins five heights apart (the
// 26 Oct archive). 29: a two-block twin signed on its first block and a
// signed two-block twin four heights above it; it needs both fixes.
BOOST_AUTO_TEST_CASE(trusted_mirror_race_seed_7_leaves_twin_past_skipped_sibling)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);
    BOOST_CHECK(RunMirrorRace(m_node, 7));
}

BOOST_AUTO_TEST_CASE(trusted_mirror_race_seed_100_leaves_upper_of_two_signed_twins)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);
    BOOST_CHECK(RunMirrorRace(m_node, 100));
}

BOOST_AUTO_TEST_CASE(trusted_mirror_race_seed_29_leaves_twins_with_both_fixes)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);
    BOOST_CHECK(RunMirrorRace(m_node, 29));
}

BOOST_AUTO_TEST_SUITE_END()
