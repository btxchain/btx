// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <boost/signals2/connection.hpp>
#include <boost/test/unit_test.hpp>

#include <chainparams.h>
#include <common/args.h>
#include <hash.h>
#include <init.h>
#include <kernel/chainstatemanager_opts.h>
#include <key_io.h>
#include <node/discovery_relay.h>
#include <netbase.h>
#include <protocol.h>
#include <matmul/trusted_exact_replay_attestation.h>
#include <node/interface_ui.h>
#include <node/matmul_trusted_attestations.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <univalue.h>
#include <util/chaintype.h>
#include <util/fs.h>
#include <util/readwritefile.h>
#include <util/strencodings.h>
#include <util/translation.h>

#include <array>
#include <chrono>
#include <limits>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace {

CKey NewKey()
{
    CKey key;
    key.MakeNewKey(/*fCompressed=*/true);
    return key;
}

uint256 Hex256(char digit)
{
    return uint256::FromHex(
               std::string(64, digit))
        .value();
}

struct RuntimeReset {
    ~RuntimeReset()
    {
        node::matmul_trusted::ResetForTest();
        node::discovery_relay::ResetHiddenNetAddrs();
    }
};

//! Capture the message text passed to the last InitError() so a startup
//! refusal can be asserted on its reason, not merely on the false return.
class InitErrorCapture
{
public:
    InitErrorCapture()
        : m_connection{uiInterface.ThreadSafeMessageBox_connect(
              [this](const bilingual_str& message, const std::string&,
                     unsigned int style) {
                  if ((style & CClientUIInterface::MSG_ERROR) ==
                      CClientUIInterface::MSG_ERROR) {
                      m_last_error = message.original;
                  }
                  return true; // Handled: keep the message off the test log.
              })}
    {
    }
    const std::string& LastError() const { return m_last_error; }

private:
    std::string m_last_error;
    boost::signals2::scoped_connection m_connection;
};

std::string HexPubKey(const CKey& key)
{
    const CPubKey pubkey{key.GetPubKey()};
    return HexStr(pubkey);
}

//! Each simulated startup gets a private argument value store. Registration is
//! intentionally unnecessary here: AppInitParameterInteraction reads these
//! values but parsing/help is not under test. Reusing the fixture's global
//! manager would leak ForceSet values into later fixtures, while registering a
//! second complete server option table recursively constructs chain params.
bool TrustedMirrorStartupAccepted(const std::vector<std::string>& pubkeys,
                                  int64_t threshold,
                                  std::string& error,
                                  bool allow_single_key = false)
{
    node::matmul_trusted::ResetForTest();
    ArgsManager args;
    args.ForceSetArg("-matmulvalidation", "trusted");
    UniValue keys{UniValue::VARR};
    for (const auto& hex : pubkeys) keys.push_back(hex);
    args.ForceSetArgV("-matmultrustedpubkey", keys);
    args.ForceSetArg("-matmultrustedthreshold", threshold);
    if (allow_single_key) {
        args.ForceSetArg("-allowsinglekeytrustedmirror", "1");
    }
    InitErrorCapture capture;
    const bool ok{AppInitParameterInteraction(args)};
    error = capture.LastError();
    return ok;
}

bool DiscoveryRelayStartupAccepted(std::string& error,
                                   const std::vector<std::pair<std::string, std::string>>& extra_args = {})
{
    node::matmul_trusted::ResetForTest();
    ArgsManager args;
    args.ForceSetArg("-matmulvalidation", "relay");
    args.ForceSetArg("-disablewallet", "1");
    for (const auto& [key, value] : extra_args) {
        args.ForceSetArg(key, value);
    }
    InitErrorCapture capture;
    const bool ok{AppInitParameterInteraction(args)};
    error = capture.LastError();
    return ok;
}

//! AppInitParameterInteraction only STAGES the signer configuration; the store
//! is built later in AppInitMain. Complete that step the same way and report
//! whether a live trusted-mirror quorum was actually installed.
bool FinalizedTrustedMirrorInstalled(std::string& error)
{
    if (!node::matmul_trusted::FinalizeConfiguration(error)) return false;
    return node::matmul_trusted::IsTrustedMirror();
}

struct RegtestParamSetup : public BasicTestingSetup {
    RegtestParamSetup() : BasicTestingSetup{ChainType::REGTEST} {}
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(matmul_trusted_mirror_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(valid_quorum_and_config_rotation_fail_closed)
{
    RuntimeReset reset;
    const CKey a{NewKey()};
    const CKey b{NewKey()};
    const CKey c{NewKey()};
    const uint256 chain{Hex256('1')};
    const uint256 block{Hex256('2')};

    matmul::trusted::StoreConfig config;
    config.chain_id = chain;
    config.replay_authority_context = Hex256('a');
    config.trusted_signers = {
        a.GetPubKey(), b.GetPubKey(), c.GetPubKey()};
    config.threshold = 2;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/true,
        /*serve=*/false, std::chrono::milliseconds{20},
        error));
    BOOST_CHECK(node::matmul_trusted::IsTrustedMirror());
    BOOST_CHECK(!node::matmul_trusted::ServesAttestations());
    BOOST_CHECK(!node::matmul_trusted::HasLocalSigner());
    BOOST_CHECK_EQUAL(node::matmul_trusted::Threshold(), 2U);
    BOOST_REQUIRE(node::matmul_trusted::ReplayAuthorityContext());
    BOOST_CHECK(*node::matmul_trusted::ReplayAuthorityContext() == Hex256('a'));

    matmul::trusted::ExactReplayStatement statement;
    statement.chain_id = chain;
    statement.block_hash = block;
    statement.block_height = 77;
    statement.replay_authority_context = Hex256('a');
    const auto att_a{
        matmul::trusted::SignStatement(statement, a)};
    const auto att_b{
        matmul::trusted::SignStatement(statement, b)};
    BOOST_REQUIRE(att_a);
    BOOST_REQUIRE(att_b);
    BOOST_CHECK(node::matmul_trusted::Add(
                    *att_a, block, 77) ==
                matmul::trusted::AddResult::Accepted);
    BOOST_CHECK(!node::matmul_trusted::HasQuorum(block, 77));
    BOOST_CHECK(node::matmul_trusted::Add(
                    *att_a, block, 77) ==
                matmul::trusted::AddResult::Duplicate);
    BOOST_CHECK(node::matmul_trusted::Add(
                    *att_b, block, 77) ==
                matmul::trusted::AddResult::Accepted);
    BOOST_CHECK(node::matmul_trusted::HasQuorum(block, 77));

    // A restart/key rotation creates a new empty authority store. A persisted
    // BLOCK_TRUSTED_REPLAY_ATTESTED bit cannot recreate quorum for new or
    // explicitly revalidated blocks under the changed configuration. Already
    // connected chainstate needs an operator-requested reindex for retroactive
    // application of that policy.
    node::matmul_trusted::ResetForTest();
    matmul::trusted::StoreConfig rotated;
    rotated.chain_id = chain;
    rotated.replay_authority_context = Hex256('a');
    rotated.trusted_signers = {c.GetPubKey()};
    rotated.threshold = 1;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(rotated), /*trusted_mirror=*/true,
        /*serve=*/false, std::chrono::milliseconds{1},
        error));
    BOOST_CHECK(!node::matmul_trusted::HasQuorum(block, 77));
    BOOST_CHECK(node::matmul_trusted::Add(
                    *att_a, block, 77) ==
                matmul::trusted::AddResult::UntrustedSigner);
    BOOST_CHECK(node::matmul_trusted::WaitForQuorum(
                    block, 77, [] { return false; }) ==
                matmul::trusted::WaitResult::Timeout);
}

BOOST_AUTO_TEST_CASE(trusted_mirror_may_serve_cached_attestations)
{
    RuntimeReset reset;
    const CKey signer{NewKey()};
    matmul::trusted::StoreConfig config;
    config.chain_id = Hex256('1');
    config.replay_authority_context = Hex256('a');
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/true,
        /*serve=*/true, std::chrono::milliseconds{20},
        error));
    BOOST_CHECK(node::matmul_trusted::IsTrustedMirror());
    BOOST_CHECK(node::matmul_trusted::ServesAttestations());
    BOOST_CHECK(!node::matmul_trusted::HasLocalSigner());
}

BOOST_AUTO_TEST_CASE(local_signer_and_expected_context)
{
    RuntimeReset reset;
    const CKey signer{NewKey()};
    const uint256 chain{Hex256('3')};
    const uint256 block{Hex256('4')};
    matmul::trusted::StoreConfig config;
    config.chain_id = chain;
    config.replay_authority_context = Hex256('b');
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    config.local_signer = signer;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/false,
        /*serve=*/true, std::chrono::milliseconds{10},
        error));
    matmul::trusted::ExactReplayAttestation produced;
    BOOST_CHECK(node::matmul_trusted::SignAuthoritative(
                    block, 9, &produced) ==
                matmul::trusted::AddResult::Accepted);
    BOOST_CHECK(produced.statement.replay_authority_context == Hex256('b'));
    BOOST_CHECK(node::matmul_trusted::HasQuorum(block, 9));
    BOOST_CHECK(node::matmul_trusted::SignAuthoritative(Hex256('5'), 9) ==
                matmul::trusted::AddResult::HeightOccupied);
    BOOST_CHECK(node::matmul_trusted::Add(
                    produced, block, 10) ==
                matmul::trusted::AddResult::WrongHeight);
    BOOST_CHECK(node::matmul_trusted::Add(
                    produced, Hex256('5'), 9) ==
                matmul::trusted::AddResult::WrongBlock);
}

BOOST_AUTO_TEST_CASE(staged_signer_finalizes_after_ecc_and_resets_cleanly)
{
    RuntimeReset reset;
    const CKey signer{NewKey()};
    matmul::trusted::StoreConfig config;
    config.chain_id = Hex256('6');
    config.replay_authority_context = Hex256('c');
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    std::string error;

    BOOST_REQUIRE(node::matmul_trusted::StageConfiguration(
        std::move(config), EncodeSecret(signer),
        /*trusted_mirror=*/false, /*serve=*/true,
        std::chrono::milliseconds{10}, error));
    BOOST_CHECK(!node::matmul_trusted::IsConfigured());
    BOOST_REQUIRE(node::matmul_trusted::FinalizeConfiguration(error));
    BOOST_CHECK(node::matmul_trusted::IsConfigured());
    BOOST_CHECK(node::matmul_trusted::HasLocalSigner());
    BOOST_CHECK(node::matmul_trusted::ServesAttestations());

    node::matmul_trusted::ResetForTest();
    BOOST_CHECK(!node::matmul_trusted::IsConfigured());
    BOOST_CHECK(!node::matmul_trusted::HasLocalSigner());
    BOOST_CHECK(!node::matmul_trusted::ReplayAuthorityContext());
}

// A trusted mirror does not merely accelerate the Profile-1 MatMul check, it
// replaces it: above the Profile-1 height the local ExactReplay is skipped and
// the attestation quorum is the node's only MatMul proof-of-work authority. A
// 1-of-1 (or 1-of-N) quorum therefore hands one key the power to make the node
// accept MatMul-invalid blocks. 0.34 refuses that topology on mainnet unless
// the operator passes -allowsinglekeytrustedmirror=1.
BOOST_AUTO_TEST_CASE(mainnet_trusted_mirror_refuses_single_key_quorum)
{
    RuntimeReset reset;
    BOOST_REQUIRE(Params().GetChainType() == ChainType::MAIN);
    const std::string key_a{HexPubKey(NewKey())};
    const std::string key_b{HexPubKey(NewKey())};
    std::string error;

    BOOST_CHECK(!TrustedMirrorStartupAccepted(
        {key_a}, /*threshold=*/1, error));
    BOOST_CHECK_MESSAGE(
        error.find("allowsinglekeytrustedmirror") != std::string::npos, error);

    RuntimeReset reset_m_of_n;
    BOOST_CHECK(!TrustedMirrorStartupAccepted(
        {key_a, key_b}, /*threshold=*/1, error));
    BOOST_CHECK_MESSAGE(
        error.find("allowsinglekeytrustedmirror") != std::string::npos, error);

    RuntimeReset reset_override;
    BOOST_CHECK_MESSAGE(
        TrustedMirrorStartupAccepted(
            {key_a}, /*threshold=*/1, error, /*allow_single_key=*/true),
        error);

    RuntimeReset reset_unmet;
    BOOST_CHECK(!TrustedMirrorStartupAccepted(
        {key_a}, /*threshold=*/2, error));
}

BOOST_AUTO_TEST_CASE(mainnet_hijack_predicates_fail_closed)
{
    using node::matmul_trusted::CollocatedSignerPinIsHijackAmplifier;
    using node::matmul_trusted::MainnetTrustedMirrorRefusesSingleKey;
    using node::matmul_trusted::TrustedMirrorIsSingleKeyAuthority;

    BOOST_CHECK(MainnetTrustedMirrorRefusesSingleKey(
        /*trusted_mirror=*/true, /*mainnet=*/true, /*n_signers=*/1,
        /*threshold=*/1, /*allow_single_key_override=*/false));
    BOOST_CHECK(MainnetTrustedMirrorRefusesSingleKey(
        true, true, /*n_signers=*/2, /*threshold=*/1, false));
    BOOST_CHECK(!MainnetTrustedMirrorRefusesSingleKey(
        true, true, 2, 2, false));
    BOOST_CHECK(!MainnetTrustedMirrorRefusesSingleKey(
        true, true, 1, 1, /*allow_single_key_override=*/true));
    BOOST_CHECK(!MainnetTrustedMirrorRefusesSingleKey(
        /*trusted_mirror=*/true, /*mainnet=*/false, 1, 1, false));
    BOOST_CHECK(!MainnetTrustedMirrorRefusesSingleKey(
        /*trusted_mirror=*/false, /*mainnet=*/true, 1, 1, false));

    BOOST_CHECK(TrustedMirrorIsSingleKeyAuthority(true, 1, 1));
    BOOST_CHECK(TrustedMirrorIsSingleKeyAuthority(true, 2, 1));
    BOOST_CHECK(!TrustedMirrorIsSingleKeyAuthority(true, 2, 2));
    BOOST_CHECK(!TrustedMirrorIsSingleKeyAuthority(false, 1, 1));

    BOOST_CHECK(CollocatedSignerPinIsHijackAmplifier(
        /*trusted_mirror=*/true, /*has_local_signer=*/true,
        /*signer_in_pin=*/true, /*n_signers=*/2, /*threshold=*/2));
    BOOST_CHECK(CollocatedSignerPinIsHijackAmplifier(
        false, true, true, /*n_signers=*/1, /*threshold=*/1));
    BOOST_CHECK(!CollocatedSignerPinIsHijackAmplifier(
        false, true, true, /*n_signers=*/2, /*threshold=*/2));
    BOOST_CHECK(!CollocatedSignerPinIsHijackAmplifier(
        false, true, /*signer_in_pin=*/false, 1, 1));
}

BOOST_AUTO_TEST_CASE(mainnet_discovery_relay_is_not_authority)
{
    RuntimeReset reset;
    BOOST_REQUIRE(Params().GetChainType() == ChainType::MAIN);
    std::string error;

    BOOST_CHECK(kernel::MatMulModeIsDiscoveryRelay(
        kernel::MatMulValidationMode::RELAY));
    BOOST_CHECK(!kernel::MatMulModeIsChainAuthority(
        kernel::MatMulValidationMode::RELAY));
    BOOST_CHECK(kernel::MatMulModeIsChainAuthority(
        kernel::MatMulValidationMode::CONSENSUS));
    BOOST_CHECK(kernel::MatMulModeIsChainAuthority(
        kernel::MatMulValidationMode::TRUSTED));
    BOOST_CHECK_EQUAL(
        std::string{kernel::MatMulValidationModeName(
            kernel::MatMulValidationMode::RELAY)},
        "relay");

    BOOST_CHECK_MESSAGE(DiscoveryRelayStartupAccepted(error), error);

    RuntimeReset reset_pin;
    {
        node::matmul_trusted::ResetForTest();
        ArgsManager args;
        args.ForceSetArg("-matmulvalidation", "relay");
        args.ForceSetArg("-disablewallet", "1");
        UniValue keys{UniValue::VARR};
        keys.push_back(HexPubKey(NewKey()));
        args.ForceSetArgV("-matmultrustedpubkey", keys);
        InitErrorCapture capture;
        BOOST_CHECK(!AppInitParameterInteraction(args));
        BOOST_CHECK_MESSAGE(
            capture.LastError().find("not MatMul authority") !=
                std::string::npos,
            capture.LastError());
    }

    RuntimeReset reset_serve;
    BOOST_CHECK(!DiscoveryRelayStartupAccepted(
        error, {{"-matmulattestationserve", "1"}}));
    BOOST_CHECK_MESSAGE(
        error.find("serve attestations") != std::string::npos ||
            error.find("not MatMul authority") != std::string::npos,
        error);

    RuntimeReset reset_economic;
    {
        node::matmul_trusted::ResetForTest();
        ArgsManager args;
        args.ForceSetArg("-matmulvalidation", "economic");
        InitErrorCapture capture;
        BOOST_CHECK(!AppInitParameterInteraction(args));
        BOOST_CHECK_MESSAGE(
            capture.LastError().find("relay") != std::string::npos ||
                capture.LastError().find("Economic/SPV") != std::string::npos,
            capture.LastError());
    }

    RuntimeReset reset_hide;
    BOOST_CHECK(!DiscoveryRelayStartupAccepted(
        error,
        {{"-discoveryrelayhideaddr", "203.0.113.8"},
         {"-addnode", "203.0.113.8"}}));
    BOOST_CHECK_MESSAGE(
        error.find("discoveryrelayhideaddr") != std::string::npos ||
            error.find("hidden") != std::string::npos,
        error);

    RuntimeReset reset_hide_bad;
    BOOST_CHECK(!DiscoveryRelayStartupAccepted(
        error, {{"-discoveryrelayhideaddr", "not-an-ip"}}));
    BOOST_CHECK_MESSAGE(
        error.find("discoveryrelayhideaddr") != std::string::npos, error);
}

BOOST_AUTO_TEST_CASE(discovery_relay_addr_policy_hides_gpu_attestors)
{
    using namespace node::discovery_relay;

    BOOST_CHECK(ServicesLookLikeServingGpuAttestor(
        NODE_MATMUL_CONSENSUS | NODE_MATMUL_ATTESTATION_ARCHIVE));
    BOOST_CHECK(!ServicesLookLikeServingGpuAttestor(NODE_MATMUL_CONSENSUS));
    BOOST_CHECK(!ServicesLookLikeServingGpuAttestor(
        NODE_MATMUL_ATTESTATION_ARCHIVE | NODE_MATMUL_TRUSTED_MIRROR));
    BOOST_CHECK(!MayAdvertiseAddress(
        NODE_MATMUL_CONSENSUS | NODE_MATMUL_ATTESTATION_ARCHIVE));
    BOOST_CHECK(MayAdvertiseAddress(NODE_NETWORK | NODE_WITNESS));
    BOOST_CHECK(MayAdvertiseAddress(NODE_MATMUL_CONSENSUS));
    BOOST_CHECK(MayAdvertiseAddress(
        NODE_MATMUL_TRUSTED_MIRROR | NODE_MATMUL_ATTESTATION_ARCHIVE));
    BOOST_CHECK(MayAdvertiseAddress(NODE_MATMUL_DISCOVERY));
    BOOST_CHECK(!MayAdvertiseAddress(NODE_NONE));

    BOOST_CHECK(!MayLearnAddressFromPeer(
        /*inbound=*/true, /*manual=*/false, /*addr_fetch=*/false));
    BOOST_CHECK(MayLearnAddressFromPeer(true, /*manual=*/true, false));
    BOOST_CHECK(MayLearnAddressFromPeer(true, false, /*addr_fetch=*/true));
    BOOST_CHECK(MayLearnAddressFromPeer(
        /*inbound=*/false, false, false));

    BOOST_CHECK(!MayRaiseArchiveReportedHeight(
        /*inbound=*/true, /*manual=*/false,
        NODE_NETWORK | NODE_MATMUL_ATTESTATION_ARCHIVE, /*starting_height=*/100));
    BOOST_CHECK(MayRaiseArchiveReportedHeight(
        false, false, NODE_NETWORK | NODE_MATMUL_ATTESTATION_ARCHIVE, 100));
    BOOST_CHECK(MayRaiseArchiveReportedHeight(
        true, /*manual=*/true, NODE_NETWORK | NODE_MATMUL_TRUSTED_MIRROR, 100));
    BOOST_CHECK(!MayRaiseArchiveReportedHeight(
        false, false, NODE_MATMUL_ATTESTATION_ARCHIVE, 100));
    // Public miners raise the watermark. Relays must not depend on CPU
    // archives as the only recent-network oracle.
    BOOST_CHECK(MayRaiseArchiveReportedHeight(
        false, false, NODE_NETWORK | NODE_MATMUL_CONSENSUS, 100));
    BOOST_CHECK(!MayRaiseArchiveReportedHeight(
        false, false, NODE_NETWORK | NODE_WITNESS, 100));
    BOOST_CHECK(!MayRaiseArchiveReportedHeight(
        false, false, NODE_NETWORK | NODE_MATMUL_ATTESTATION_ARCHIVE,
        /*starting_height=*/-1));
    BOOST_CHECK(!MayRaiseArchiveReportedHeight(
        false, false, NODE_NETWORK | NODE_MATMUL_ATTESTATION_ARCHIVE, 200,
        /*current_watermark=*/100));
    BOOST_CHECK(MayRaiseArchiveReportedHeight(
        false, false, NODE_NETWORK | NODE_MATMUL_ATTESTATION_ARCHIVE, 150, 100));
    BOOST_CHECK(!MayRaiseArchiveReportedHeight(
        false, false, NODE_NETWORK | NODE_MATMUL_ATTESTATION_ARCHIVE, 90, 100));

    BOOST_CHECK(AddrFetchMayKeepDiscoveryPeer(NODE_MATMUL_DISCOVERY));
    BOOST_CHECK(AddrFetchMayKeepDiscoveryPeer(
        NODE_MATMUL_DISCOVERY | NODE_WITNESS));
    BOOST_CHECK(!AddrFetchMayKeepDiscoveryPeer(NODE_NETWORK | NODE_WITNESS));
    BOOST_CHECK(!AddrFetchMayKeepDiscoveryPeer(NODE_NONE));

    BOOST_CHECK(HandshakeKeepsDiscoveryPeer(
        /*addr_fetch=*/true, NODE_MATMUL_DISCOVERY));
    BOOST_CHECK(HandshakeKeepsDiscoveryPeer(
        /*addr_fetch=*/false, NODE_MATMUL_DISCOVERY));
    BOOST_CHECK(!HandshakeKeepsDiscoveryPeer(true, NODE_NETWORK | NODE_WITNESS));

    BOOST_CHECK_EQUAL(RobustConnectedWatermark({}), -1);
    BOOST_CHECK_EQUAL(RobustConnectedWatermark({199400}), 199400);
    BOOST_CHECK_EQUAL(RobustConnectedWatermark({199400, 199390}), 199390);
    BOOST_CHECK_EQUAL(
        RobustConnectedWatermark({999999, 199400, 199390, 185109}), 199390);
    BOOST_CHECK_EQUAL(EffectiveIntroductionWatermark(-1, {199400, 199390, 199380}),
                      199380);
    BOOST_CHECK_EQUAL(EffectiveIntroductionWatermark(199350, {199400, 199390, 199380}),
                      199380);
    BOOST_CHECK(MayAdvertiseConnectedPeer(
        NODE_NETWORK | NODE_WITNESS, 199400, 199390));
    BOOST_CHECK(!MayAdvertiseConnectedPeer(
        NODE_NETWORK | NODE_WITNESS, 185109, 199390));
    BOOST_CHECK(!MayAdvertiseConnectedPeer(NODE_MATMUL_DISCOVERY, 199400, 199390));
    BOOST_CHECK(MayRetainInboundHandshake(
        /*inbound=*/true, /*routable=*/true, NODE_NETWORK | NODE_WITNESS,
        199400, 199390));
    BOOST_CHECK(!MayRetainInboundHandshake(
        /*inbound=*/false, true, NODE_NETWORK | NODE_WITNESS, 199400, 199390));
    BOOST_CHECK(!MayRetainInboundHandshake(
        true, /*routable=*/false, NODE_NETWORK | NODE_WITNESS, 199400, 199390));

    BOOST_CHECK(ServicesAreDiscoveryOnly(NODE_MATMUL_DISCOVERY));
    BOOST_CHECK(!ServicesAreDiscoveryOnly(
        NODE_MATMUL_DISCOVERY | NODE_NETWORK));
    BOOST_CHECK(!ServicesAreDiscoveryOnly(NODE_NETWORK | NODE_WITNESS));
    BOOST_CHECK(MayAcceptInboundDiscoveryPeer(
        /*inbound=*/true, /*manual=*/false, NODE_MATMUL_DISCOVERY,
        /*inbound_discovery_only_count=*/0));
    BOOST_CHECK(MayAcceptInboundDiscoveryPeer(
        true, false, NODE_MATMUL_DISCOVERY, MAX_INBOUND_DISCOVERY_ONLY - 1));
    BOOST_CHECK(!MayAcceptInboundDiscoveryPeer(
        true, false, NODE_MATMUL_DISCOVERY, MAX_INBOUND_DISCOVERY_ONLY));
    BOOST_CHECK(MayAcceptInboundDiscoveryPeer(
        true, /*manual=*/true, NODE_MATMUL_DISCOVERY, MAX_INBOUND_DISCOVERY_ONLY));
    BOOST_CHECK(MayAcceptInboundDiscoveryPeer(
        /*inbound=*/false, false, NODE_MATMUL_DISCOVERY,
        MAX_INBOUND_DISCOVERY_ONLY));
    BOOST_CHECK(MayAcceptInboundDiscoveryPeer(
        true, false, NODE_NETWORK | NODE_MATMUL_DISCOVERY,
        MAX_INBOUND_DISCOVERY_ONLY));
    using node::discovery_relay::DiscoverySlowlorisShouldRelease;
    BOOST_CHECK(DiscoverySlowlorisShouldRelease(
        /*inbound=*/true, /*discovery_only=*/true, /*handshake_complete=*/false,
        std::chrono::seconds{15}));
    BOOST_CHECK(!DiscoverySlowlorisShouldRelease(
        true, true, /*handshake_complete=*/true, std::chrono::seconds{15}));
    BOOST_CHECK(!DiscoverySlowlorisShouldRelease(
        true, true, false, std::chrono::seconds{14}));
    BOOST_CHECK(!DiscoverySlowlorisShouldRelease(
        true, /*discovery_only=*/false, false, std::chrono::seconds{15}));

    const auto hidden{LookupHost("203.0.113.8", /*fAllowLookup=*/false)};
    BOOST_REQUIRE(hidden.has_value());
    ResetHiddenNetAddrs();
    BOOST_CHECK(!IsHiddenNetAddr(*hidden));
    AddHiddenNetAddr(*hidden);
    BOOST_CHECK(IsHiddenNetAddr(*hidden));
    BOOST_CHECK(MayAdvertiseAddress(NODE_NETWORK | NODE_WITNESS));
    BOOST_CHECK(!MayAdvertiseEndpoint(NODE_NETWORK | NODE_WITNESS, *hidden));
    const auto other{LookupHost("203.0.113.9", /*fAllowLookup=*/false)};
    BOOST_REQUIRE(other.has_value());
    BOOST_CHECK(MayAdvertiseEndpoint(NODE_NETWORK | NODE_WITNESS, *other));
    ResetHiddenNetAddrs();
    // ADDR trickle on mirrors/signers uses MayAdvertiseEndpoint alone
    // (no !IsDiscoveryRelay short-circuit), so hideaddr and
    // CONSENSUS|ARCHIVE endpoints never leave the node.

    BOOST_CHECK(PeerLooksOnRecentNetwork(50, /*archive_reported_height=*/-1));
    BOOST_CHECK(!PeerLooksOnRecentNetwork(-1, 50));
    BOOST_CHECK(PeerLooksOnRecentNetwork(100, 100));
    BOOST_CHECK(PeerLooksOnRecentNetwork(100 + RECENT_HEIGHT_LAG, 100));
    BOOST_CHECK(!PeerLooksOnRecentNetwork(100 + RECENT_HEIGHT_LAG + 1, 100));
    BOOST_CHECK(PeerLooksOnRecentNetwork(100 - RECENT_HEIGHT_LAG, 100));
    BOOST_CHECK(!PeerLooksOnRecentNetwork(100 - RECENT_HEIGHT_LAG - 1, 100));
}

BOOST_AUTO_TEST_CASE(mainnet_trusted_mirror_accepts_two_of_two)
{
    RuntimeReset reset;
    BOOST_REQUIRE(Params().GetChainType() == ChainType::MAIN);
    const std::string key_a{HexPubKey(NewKey())};
    const std::string key_b{HexPubKey(NewKey())};
    std::string error;

    BOOST_CHECK_MESSAGE(
        TrustedMirrorStartupAccepted(
            {key_a, key_b}, /*threshold=*/2, error),
        error);
    std::string finalize_error;
    BOOST_CHECK_MESSAGE(FinalizedTrustedMirrorInstalled(finalize_error),
                        finalize_error);
    BOOST_CHECK_EQUAL(node::matmul_trusted::Threshold(), 2U);
    BOOST_CHECK_EQUAL(node::matmul_trusted::TrustedSigners().size(), 2U);
    BOOST_CHECK_EQUAL(node::matmul_trusted::WaitTimeout().count(), 60'000);
}

// Without this, "-matmultrustedpubkey=X -matmultrustedpubkey=X
// -matmultrustedthreshold=2" would falsely claim two independent authorities
// while the quorum still rests on one private key.
BOOST_AUTO_TEST_CASE(duplicate_trusted_pubkeys_are_refused)
{
    RuntimeReset reset;
    const std::string key_a{HexPubKey(NewKey())};
    const std::string key_b{HexPubKey(NewKey())};
    std::string error;
    std::string finalize_error;

    BOOST_CHECK(!TrustedMirrorStartupAccepted(
        {key_a, key_a}, /*threshold=*/2, error));
    BOOST_CHECK_MESSAGE(
        error.find("Duplicate -matmultrustedpubkey") != std::string::npos,
        error);
    BOOST_CHECK(!FinalizedTrustedMirrorInstalled(finalize_error));
    BOOST_CHECK(!node::matmul_trusted::IsConfigured());

    // Also refused when the duplicate is not adjacent and N would otherwise be
    // large enough on its own.
    BOOST_CHECK(!TrustedMirrorStartupAccepted(
        {key_a, key_b, key_a}, /*threshold=*/2, error));
    BOOST_CHECK_MESSAGE(
        error.find("Duplicate -matmultrustedpubkey") != std::string::npos,
        error);
    BOOST_CHECK(!FinalizedTrustedMirrorInstalled(finalize_error));
    BOOST_CHECK(!node::matmul_trusted::IsConfigured());
}

// Functional/rehearsal harnesses use supported single-signer mirrors and must
// keep working without the mainnet warning path.
BOOST_FIXTURE_TEST_CASE(non_mainnet_trusted_mirror_keeps_one_of_one,
                        RegtestParamSetup)
{
    RuntimeReset reset;
    BOOST_REQUIRE(Params().GetChainType() == ChainType::REGTEST);
    const std::string key_a{HexPubKey(NewKey())};
    std::string error;

    BOOST_CHECK_MESSAGE(
        TrustedMirrorStartupAccepted(
            {key_a}, /*threshold=*/1, error),
        error);
    std::string finalize_error;
    BOOST_CHECK_MESSAGE(FinalizedTrustedMirrorInstalled(finalize_error),
                        finalize_error);
    BOOST_CHECK_EQUAL(node::matmul_trusted::Threshold(), 1U);

    // The duplicate rejection is chain-independent.
    BOOST_CHECK(!TrustedMirrorStartupAccepted(
        {key_a, key_a}, /*threshold=*/2, error));
    BOOST_CHECK_MESSAGE(
        error.find("Duplicate -matmultrustedpubkey") != std::string::npos,
        error);
    BOOST_CHECK(!FinalizedTrustedMirrorInstalled(finalize_error));
    BOOST_CHECK(!node::matmul_trusted::IsConfigured());
}

BOOST_AUTO_TEST_CASE(tip_priority_orders_tip_extender_before_backfill)
{
    using node::matmul_trusted::MakeTrustedWorkRank;
    using node::matmul_trusted::PreferTrustedWork;

    const int32_t tip_height{185787};
    const auto tip_child{MakeTrustedWorkRank(
        /*tip_extending=*/true, /*height=*/185788, tip_height,
        /*priority_rank=*/2, /*sequence=*/10)};
    const auto far_above{MakeTrustedWorkRank(
        false, 186093, tip_height, /*priority_rank=*/1, /*sequence=*/1)};
    const auto near_above{MakeTrustedWorkRank(
        false, 185860, tip_height, /*priority_rank=*/1, /*sequence=*/2)};
    const auto below_tip{MakeTrustedWorkRank(
        false, 185589, tip_height, /*priority_rank=*/1, /*sequence=*/0)};

    BOOST_CHECK(PreferTrustedWork(tip_child, far_above));
    BOOST_CHECK(PreferTrustedWork(tip_child, below_tip));
    BOOST_CHECK(PreferTrustedWork(near_above, far_above));
    BOOST_CHECK(PreferTrustedWork(near_above, below_tip));
    BOOST_CHECK(PreferTrustedWork(far_above, below_tip));
    BOOST_CHECK(!PreferTrustedWork(below_tip, tip_child));
}

BOOST_AUTO_TEST_CASE(partial_quorum_is_never_accepted)
{
    RuntimeReset reset;
    const CKey a{NewKey()};
    const CKey b{NewKey()};
    const uint256 chain{Hex256('c')};
    const uint256 block{Hex256('d')};

    matmul::trusted::StoreConfig config;
    config.chain_id = chain;
    config.replay_authority_context = Hex256('e');
    config.trusted_signers = {a.GetPubKey(), b.GetPubKey()};
    config.threshold = 2;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/true,
        /*serve=*/false, std::chrono::milliseconds{5},
        error));

    matmul::trusted::ExactReplayStatement statement;
    statement.chain_id = chain;
    statement.block_hash = block;
    statement.block_height = 42;
    statement.replay_authority_context = Hex256('e');
    const auto att_a{matmul::trusted::SignStatement(statement, a)};
    BOOST_REQUIRE(att_a);
    BOOST_CHECK(node::matmul_trusted::Add(*att_a, block, 42) ==
                matmul::trusted::AddResult::Accepted);
    BOOST_CHECK(!node::matmul_trusted::HasQuorum(block, 42));
    BOOST_CHECK(node::matmul_trusted::WaitForQuorum(
                    block, 42, [] { return false; }) ==
                matmul::trusted::WaitResult::Timeout);
}

BOOST_AUTO_TEST_CASE(wait_timeout_clamp_rejects_insane_values)
{
    RuntimeReset reset;
    matmul::trusted::StoreConfig config;
    config.chain_id = Hex256('f');
    config.replay_authority_context = Hex256('0');
    config.trusted_signers = {NewKey().GetPubKey()};
    config.threshold = 1;
    std::string error;
    BOOST_CHECK(!node::matmul_trusted::Configure(
        config, /*trusted_mirror=*/true, /*serve=*/false,
        std::chrono::milliseconds{-1}, error));
    BOOST_CHECK(error.find("600000") != std::string::npos);
    error.clear();
    BOOST_CHECK(!node::matmul_trusted::Configure(
        config, /*trusted_mirror=*/true, /*serve=*/false,
        std::chrono::milliseconds{600'001}, error));
    BOOST_CHECK(error.find("600000") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(above_frontier_and_parked_branch_do_not_admit)
{
    using node::matmul_trusted::EvaluateTrustedAttestationAdmit;
    using node::matmul_trusted::TrustedAttestationAdmit;
    using node::matmul_trusted::TrustedAttestationAdmitView;

    // Competing height above the authority tip must not consume a slot.
    BOOST_CHECK(
        EvaluateTrustedAttestationAdmit(TrustedAttestationAdmitView{
            .tip_extending = false,
            .extends_active_tip_chain = true,
            .on_parked_reorg_branch = false,
            .height = 186087,
            .authority_frontier = 186011,
            .in_backoff = false,
        }) == TrustedAttestationAdmit::RejectAboveFrontier);

    // Followed HAVE_DATA / retained GPU body above the lagging local
    // frontier must still GETMMATTEST (live 2026-08-16: retain then
    // RejectAboveFrontier left tip frozen while bodies sat on disk).
    BOOST_CHECK(
        EvaluateTrustedAttestationAdmit(TrustedAttestationAdmitView{
            .tip_extending = false,
            .extends_active_tip_chain = true,
            .followed_body_awaiting_attestation = true,
            .on_parked_reorg_branch = false,
            .height = 190668,
            .authority_frontier = 190666,
            .in_backoff = false,
        }) == TrustedAttestationAdmit::Allow);
    BOOST_CHECK(
        EvaluateTrustedAttestationAdmit(TrustedAttestationAdmitView{
            .tip_extending = false,
            .extends_active_tip_chain = true,
            .followed_body_awaiting_attestation = true,
            .on_parked_reorg_branch = true,
            .height = 190668,
            .authority_frontier = 190666,
            .in_backoff = false,
        }) == TrustedAttestationAdmit::RejectParkedReorg);

    BOOST_CHECK(
        EvaluateTrustedAttestationAdmit(TrustedAttestationAdmitView{
            .tip_extending = false,
            .extends_active_tip_chain = true,
            .is_signed_frontier_hash = true,
            .on_parked_reorg_branch = false,
            .height = 190788,
            .authority_frontier = 190666,
            .in_backoff = false,
        }) == TrustedAttestationAdmit::Allow);

    // Parked deep-reorg branch is never attestable by our policy.
    BOOST_CHECK(
        EvaluateTrustedAttestationAdmit(TrustedAttestationAdmitView{
            .tip_extending = false,
            .extends_active_tip_chain = false,
            .on_parked_reorg_branch = true,
            .height = 186074,
            .authority_frontier = 186011,
            .in_backoff = false,
        }) == TrustedAttestationAdmit::RejectParkedReorg);

    // Fork that does not extend the active tip is refused even below frontier.
    BOOST_CHECK(
        EvaluateTrustedAttestationAdmit(TrustedAttestationAdmitView{
            .tip_extending = false,
            .extends_active_tip_chain = false,
            .on_parked_reorg_branch = false,
            .height = 185950,
            .authority_frontier = 186011,
            .in_backoff = false,
        }) == TrustedAttestationAdmit::RejectNotForwardOfTip);

    // A better-work branch IS admissible even though it does not extend the
    // active tip -- that is what a reorg looks like. Regression: a mirror lost a
    // same-height race at 186355 and sat on the losing sibling while the
    // authority ran 23 blocks ahead. Nothing on the winning branch extended its
    // tip, so every rescuing block was refused as not-forward-of-tip and the
    // node was stuck until an operator ran invalidateblock.
    BOOST_CHECK(
        EvaluateTrustedAttestationAdmit(TrustedAttestationAdmitView{
            .tip_extending = false,
            .extends_active_tip_chain = false,
            .better_work_reorg_candidate = true,
            .on_parked_reorg_branch = false,
            .height = 186356,
            .authority_frontier = 186383,
            .in_backoff = false,
        }) == TrustedAttestationAdmit::Allow);

    // The lower roots of an explicitly selected shallow recovery branch can
    // have less work than the losing active tip. They remain admissible so the
    // already-followed/authenticated upper branch can connect. This does not
    // bypass PARK, which is evaluated first.
    BOOST_CHECK(
        EvaluateTrustedAttestationAdmit(TrustedAttestationAdmitView{
            .tip_extending = false,
            .extends_active_tip_chain = false,
            .better_work_reorg_candidate = false,
            .on_recovery_branch = true,
            .on_parked_reorg_branch = false,
            .height = 186350,
            .authority_frontier = 186390,
            .in_backoff = false,
        }) == TrustedAttestationAdmit::Allow);

    // Equal-work sibling must also be admissible. This is the exact production
    // stall: a mirror connected one side of a same-height race, so the winning
    // side carried EQUAL work, not greater. With a strict > test it never
    // fetched the branch that could rescue it, and it could not wait for the
    // authority to extend because being stranded froze its header sync.
    BOOST_CHECK(
        EvaluateTrustedAttestationAdmit(TrustedAttestationAdmitView{
            .tip_extending = false,
            .extends_active_tip_chain = false,
            .better_work_reorg_candidate = true,
            .on_parked_reorg_branch = false,
            .height = 186335,
            .authority_frontier = 186390,
            .in_backoff = false,
        }) == TrustedAttestationAdmit::Allow);

    // Better work does NOT override the park policy: a refused deep reorg stays
    // refused, so this cannot become a back door around deep-reorg finality.
    BOOST_CHECK(
        EvaluateTrustedAttestationAdmit(TrustedAttestationAdmitView{
            .tip_extending = false,
            .extends_active_tip_chain = false,
            .better_work_reorg_candidate = true,
            .on_parked_reorg_branch = true,
            .height = 186356,
            .authority_frontier = 186383,
            .in_backoff = false,
        }) == TrustedAttestationAdmit::RejectParkedReorg);

    // Tip-extender is always allowed, including a one-step frontier probe.
    BOOST_CHECK(
        EvaluateTrustedAttestationAdmit(TrustedAttestationAdmitView{
            .tip_extending = true,
            .extends_active_tip_chain = true,
            .on_parked_reorg_branch = false,
            .height = 186012,
            .authority_frontier = 186011,
            .in_backoff = true,
        }) == TrustedAttestationAdmit::Allow);

    // Forward of tip at/under frontier is allowed.
    BOOST_CHECK(
        EvaluateTrustedAttestationAdmit(TrustedAttestationAdmitView{
            .tip_extending = false,
            .extends_active_tip_chain = true,
            .on_parked_reorg_branch = false,
            .height = 185944,
            .authority_frontier = 186011,
            .in_backoff = false,
        }) == TrustedAttestationAdmit::Allow);

    // Active tip / last few ancestors: populate getmatmulattestedtip on a
    // linear chain (signer typically attests ~1 behind).
    BOOST_CHECK(
        EvaluateTrustedAttestationAdmit(TrustedAttestationAdmitView{
            .tip_extending = false,
            .extends_active_tip_chain = false,
            .on_recent_active_ancestor = true,
            .on_parked_reorg_branch = false,
            .height = 186010,
            .authority_frontier = 186011,
            .in_backoff = true,
        }) == TrustedAttestationAdmit::Allow);
    BOOST_CHECK(
        EvaluateTrustedAttestationAdmit(TrustedAttestationAdmitView{
            .tip_extending = false,
            .extends_active_tip_chain = false,
            .on_recent_active_ancestor = true,
            .on_parked_reorg_branch = true,
            .height = 186010,
            .authority_frontier = 186011,
            .in_backoff = false,
        }) == TrustedAttestationAdmit::RejectParkedReorg);

    // Signer-absent backoff blocks re-admission of non-tip work.
    BOOST_CHECK(
        EvaluateTrustedAttestationAdmit(TrustedAttestationAdmitView{
            .tip_extending = false,
            .extends_active_tip_chain = true,
            .on_parked_reorg_branch = false,
            .height = 185944,
            .authority_frontier = 186011,
            .in_backoff = true,
        }) == TrustedAttestationAdmit::RejectBackoff);

    // Short tip-race reorg is first-class: admit even when it does not
    // extend the losing tip and would otherwise sit above a stale frontier
    // or in signer-absent backoff. Live: 187773 sibling vs 250c7e53.
    BOOST_CHECK(
        EvaluateTrustedAttestationAdmit(TrustedAttestationAdmitView{
            .tip_extending = false,
            .short_tip_reorg = true,
            .extends_active_tip_chain = false,
            .better_work_reorg_candidate = true,
            .on_parked_reorg_branch = false,
            .height = 187774,
            .authority_frontier = 187773,
            .in_backoff = false,
        }) == TrustedAttestationAdmit::Allow);
    BOOST_CHECK(
        EvaluateTrustedAttestationAdmit(TrustedAttestationAdmitView{
            .tip_extending = false,
            .short_tip_reorg = true,
            .extends_active_tip_chain = false,
            .on_parked_reorg_branch = false,
            .height = 187773,
            .authority_frontier = 187859,
            .in_backoff = true,
        }) == TrustedAttestationAdmit::Allow);
    // Competing miner fork hundreds ahead is not a short reorg (live ~187975).
    BOOST_CHECK(
        EvaluateTrustedAttestationAdmit(TrustedAttestationAdmitView{
            .tip_extending = false,
            .short_tip_reorg = false,
            .extends_active_tip_chain = false,
            .on_parked_reorg_branch = false,
            .height = 187975,
            .authority_frontier = 187859,
            .in_backoff = false,
        }) == TrustedAttestationAdmit::RejectNotForwardOfTip);
    // Park still wins over a short-reorg flag (must not be a back door).
    BOOST_CHECK(
        EvaluateTrustedAttestationAdmit(TrustedAttestationAdmitView{
            .tip_extending = false,
            .short_tip_reorg = true,
            .extends_active_tip_chain = false,
            .on_parked_reorg_branch = true,
            .height = 187774,
            .authority_frontier = 187773,
            .in_backoff = false,
        }) == TrustedAttestationAdmit::RejectParkedReorg);

    using node::matmul_trusted::TrustedMirrorIsShortTipReorg;
    using node::matmul_trusted::TrustedMirrorPreferGetMmAttest;
    using node::matmul_trusted::TRUSTED_MIRROR_SHORT_REORG_DEPTH;
    BOOST_CHECK_EQUAL(TRUSTED_MIRROR_SHORT_REORG_DEPTH, 6);
    BOOST_CHECK(!TrustedMirrorIsShortTipReorg(0));
    BOOST_CHECK(TrustedMirrorIsShortTipReorg(1));
    BOOST_CHECK(TrustedMirrorIsShortTipReorg(6));
    BOOST_CHECK(!TrustedMirrorIsShortTipReorg(7));
    BOOST_CHECK(!TrustedMirrorIsShortTipReorg(187975 - 187773));
    using node::matmul_trusted::TrustedMirrorIndexExtendsActiveTip;
    using node::matmul_trusted::TrustedMirrorIndexIsCatchUpSuffix;
    BOOST_CHECK(!TrustedMirrorIndexExtendsActiveTip(
        /*has_tip=*/false, /*has_index=*/true, 2, 1, true));
    BOOST_CHECK(!TrustedMirrorIndexExtendsActiveTip(
        true, true, /*index_height=*/100, /*tip_height=*/100, true));
    BOOST_CHECK(!TrustedMirrorIndexExtendsActiveTip(
        true, true, 101, 100, /*index_ancestor_at_tip_is_tip=*/false));
    BOOST_CHECK(TrustedMirrorIndexExtendsActiveTip(true, true, 101, 100, true));
    BOOST_CHECK(TrustedMirrorIndexExtendsActiveTip(true, true, 102, 100, true));
    BOOST_CHECK(!TrustedMirrorIndexIsCatchUpSuffix(true, true, 101, 100, true));
    BOOST_CHECK(TrustedMirrorIndexIsCatchUpSuffix(true, true, 102, 100, true));
    BOOST_CHECK(!TrustedMirrorIndexIsCatchUpSuffix(true, true, 102, 100, false));
    using node::matmul_trusted::HeaderOnlyMustFetchLostTwinPath;
    // Live 2026-08-24: attested 199295, HEADER_ONLY twin 8b5da5a5, miners
    // extended to 199300. Local signer *and* trusted archives fetch the
    // twin (archives persist HAVE_DATA; signers ExactReplay). Independent
    // consensus miners without a local signer keep skip. Lone EncDr sibling
    // (no pulled-ahead headers) stays off the device.
    BOOST_CHECK(HeaderOnlyMustFetchLostTwinPath(
        /*has_local_signer=*/true, /*is_trusted_mirror=*/false,
        /*has_tip=*/true, /*has_index=*/true, /*index_is_tip=*/false,
        /*index_failed=*/false, /*index_height=*/199295, /*tip_height=*/199295,
        /*same_parent=*/true, /*lca_depth=*/1, /*better_or_equal_work=*/true,
        /*parent_has_data_or_is_lca=*/true,
        /*competing_headers_pulled_ahead=*/true));
    BOOST_CHECK(HeaderOnlyMustFetchLostTwinPath(
        /*has_local_signer=*/false, /*is_trusted_mirror=*/true,
        true, true, false, false, 199295, 199295, true, 1, true, true, true));
    BOOST_CHECK(HeaderOnlyMustFetchLostTwinPath(
        true, /*is_trusted_mirror=*/true, true, true, false, false, 199295,
        199295, true, 1, true, true, true));
    // Live HeightOccupied: a different hash at 199295 already has quorum.
    // Fetching 8b5da5a5 cannot be signed and wedges GETDATA as root_in_flight.
    BOOST_CHECK(!HeaderOnlyMustFetchLostTwinPath(
        true, false, true, true, false, false, 199295, 199295, true, 1, true,
        true, true, /*competing_quorum_at_index=*/true));
    BOOST_CHECK(!HeaderOnlyMustFetchLostTwinPath(
        true, false, true, true, false, false, 199295, 199295, true, 1, true,
        true, /*competing_headers_pulled_ahead=*/false));
    BOOST_CHECK(!HeaderOnlyMustFetchLostTwinPath(
        /*has_local_signer=*/false, false, true, true, false, false, 199295,
        199295, true, 1, true, true, true));
    BOOST_CHECK(!HeaderOnlyMustFetchLostTwinPath(
        true, false, true, true, false, false, 199295, 199295,
        /*same_parent=*/false, /*lca_depth=*/7, true, true, true));
    BOOST_CHECK(!HeaderOnlyMustFetchLostTwinPath(
        true, false, true, true, false, false, 199295, 199295, true, 1,
        /*better_or_equal_work=*/false, true, true));
    // Same-parent ancestor-twin persist must stay inside the short-reorg
    // window or BlockRequestAllowed will not serve the body.
    BOOST_CHECK(!HeaderOnlyMustFetchLostTwinPath(
        true, false, true, true, false, false, 199295, 199295,
        /*same_parent=*/true, /*lca_depth=*/7, true, true, true));
    // Better-work child of the twin after the twin body exists (199296).
    BOOST_CHECK(HeaderOnlyMustFetchLostTwinPath(
        true, false, true, true, false, false, /*index_height=*/199296,
        /*tip_height=*/199295, /*same_parent=*/false, /*lca_depth=*/1, true,
        /*parent_has_data_or_is_lca=*/true, false));
    BOOST_CHECK(!HeaderOnlyMustFetchLostTwinPath(
        true, false, true, true, false, false, 199296, 199295, false, 1, true,
        /*parent_has_data_or_is_lca=*/false, false));
    BOOST_CHECK(!HeaderOnlyMustFetchLostTwinPath(
        true, false, true, true, false, false, 199296, 199295, false,
        /*lca_depth=*/7, true, true, false));
    using node::matmul_trusted::SeedLocalSignerLostTwinBestKnown;
    BOOST_CHECK(SeedLocalSignerLostTwinBestKnown(
        /*has_local_signer=*/true, /*is_trusted_mirror=*/false,
        /*best_known_unset=*/true, /*starting_height=*/199309,
        /*tip_height=*/199297, /*claimed_height=*/199309,
        /*claimed_is_short_reorg_competing_fork=*/true,
        /*claimed_work_ge_tip=*/true));
    BOOST_CHECK(!SeedLocalSignerLostTwinBestKnown(
        true, false, true, 199309, 199297, 199309, true, true,
        /*fork_child_height_occupied=*/true));
    BOOST_CHECK(!SeedLocalSignerLostTwinBestKnown(
        true, false, /*best_known_unset=*/false, 199309, 199297, 199309, true,
        true));
    BOOST_CHECK(!SeedLocalSignerLostTwinBestKnown(
        true, false, true, /*starting_height=*/199297, 199297, 199309, true,
        true));
    BOOST_CHECK(SeedLocalSignerLostTwinBestKnown(
        true, /*is_trusted_mirror=*/true, true, 199309, 199297, 199309, true,
        true));
    BOOST_CHECK(SeedLocalSignerLostTwinBestKnown(
        /*has_local_signer=*/false, /*is_trusted_mirror=*/true, true, 199309,
        199297, 199309, true, true));
    BOOST_CHECK(!SeedLocalSignerLostTwinBestKnown(
        /*has_local_signer=*/false, /*is_trusted_mirror=*/false, true, 199309,
        199297, 199309, true, true));
    BOOST_CHECK(!SeedLocalSignerLostTwinBestKnown(
        true, false, true, 199309, 199297, 199309,
        /*claimed_is_short_reorg_competing_fork=*/false, true));
    // Live 2026-08-24: attested tip moved to 199297; unsigned twin still at
    // 199295 with less work than the tip. Fetch it once headers pulled ahead.
    BOOST_CHECK(HeaderOnlyMustFetchLostTwinPath(
        true, false, true, true, false, false, /*index_height=*/199295,
        /*tip_height=*/199297, /*same_parent=*/true, /*lca_depth=*/3,
        /*better_or_equal_work=*/false, true,
        /*competing_headers_pulled_ahead=*/true));
    BOOST_CHECK(!HeaderOnlyMustFetchLostTwinPath(
        true, false, true, true, false, false, 199295, 199297, true, 3, false,
        true, true, /*competing_quorum_at_index=*/true));
    BOOST_CHECK(!HeaderOnlyMustFetchLostTwinPath(
        true, false, true, true, false, false, 199295, 199297, true, 3, false,
        true, /*competing_headers_pulled_ahead=*/false));
    // Intermediate competing 199296 after the twin body exists.
    BOOST_CHECK(HeaderOnlyMustFetchLostTwinPath(
        true, false, true, true, false, false, /*index_height=*/199296,
        /*tip_height=*/199297, /*same_parent=*/false, /*lca_depth=*/3,
        /*better_or_equal_work=*/false, /*parent_has_data_or_is_lca=*/true,
        true));
    BOOST_CHECK(!HeaderOnlyMustFetchLostTwinPath(
        true, false, true, true, false, false, 199296, 199297, false, 3, false,
        /*parent_has_data_or_is_lca=*/false, true));
    // PR 117 review: depth-2 cousin. Tip H, equal-work twin at H, LCA H-2.
    // The twin is not same-parent; fetch it once the fork-child has a body.
    BOOST_CHECK(HeaderOnlyMustFetchLostTwinPath(
        true, false, true, true, false, false, /*index_height=*/199297,
        /*tip_height=*/199297, /*same_parent=*/false, /*lca_depth=*/2,
        /*better_or_equal_work=*/true, /*parent_has_data_or_is_lca=*/true,
        /*competing_headers_pulled_ahead=*/true));
    BOOST_CHECK(!HeaderOnlyMustFetchLostTwinPath(
        true, false, true, true, false, false, 199297, 199297, false, 2, true,
        /*parent_has_data_or_is_lca=*/false, true));
    BOOST_CHECK(!HeaderOnlyMustFetchLostTwinPath(
        true, false, true, true, false, false, 199297, 199297, false, 2, true,
        true, /*competing_headers_pulled_ahead=*/false));
    // Fork-child at H-1 is still the same-parent ancestor twin of attested H-1.
    BOOST_CHECK(HeaderOnlyMustFetchLostTwinPath(
        true, false, true, true, false, false, /*index_height=*/199296,
        /*tip_height=*/199297, /*same_parent=*/true, /*lca_depth=*/2,
        /*better_or_equal_work=*/false, true, true));
    using node::matmul_trusted::TrustedMirrorMaySelectMostWorkCandidate;
    BOOST_CHECK(TrustedMirrorMaySelectMostWorkCandidate(
        /*extends_active_tip_chain=*/true, /*short_tip_reorg=*/false,
        /*has_quorum=*/false));
    BOOST_CHECK(TrustedMirrorMaySelectMostWorkCandidate(
        /*extends_active_tip_chain=*/false, /*short_tip_reorg=*/true,
        /*has_quorum=*/true));
    BOOST_CHECK(!TrustedMirrorMaySelectMostWorkCandidate(
        /*extends_active_tip_chain=*/false, /*short_tip_reorg=*/true,
        /*has_quorum=*/false));
    BOOST_CHECK(!TrustedMirrorMaySelectMostWorkCandidate(
        /*extends_active_tip_chain=*/false, /*short_tip_reorg=*/false,
        /*has_quorum=*/true));
    BOOST_CHECK(!TrustedMirrorMaySelectMostWorkCandidate(
        /*extends_active_tip_chain=*/false, /*short_tip_reorg=*/false,
        /*has_quorum=*/false));
    // Signed tip must not be abandoned for a heavier attested short fork.
    BOOST_CHECK(!TrustedMirrorMaySelectMostWorkCandidate(
        /*extends_active_tip_chain=*/false, /*short_tip_reorg=*/true,
        /*has_quorum=*/true, /*active_tip_has_quorum=*/true));
    BOOST_CHECK(TrustedMirrorMaySelectMostWorkCandidate(
        /*extends_active_tip_chain=*/true, /*short_tip_reorg=*/false,
        /*has_quorum=*/false, /*active_tip_has_quorum=*/true));
    BOOST_CHECK(!TrustedMirrorMaySelectMostWorkCandidate(
        /*extends_active_tip_chain=*/true, /*short_tip_reorg=*/false,
        /*has_quorum=*/false, /*active_tip_has_quorum=*/true,
        /*immediate_tip_child=*/false));
    BOOST_CHECK(TrustedMirrorMaySelectMostWorkCandidate(
        /*extends_active_tip_chain=*/true, /*short_tip_reorg=*/false,
        /*has_quorum=*/true, /*active_tip_has_quorum=*/true,
        /*immediate_tip_child=*/false));
    BOOST_CHECK(!TrustedMirrorMaySelectMostWorkCandidate(
        /*extends_active_tip_chain=*/true, /*short_tip_reorg=*/false,
        /*has_quorum=*/false, /*active_tip_has_quorum=*/true,
        /*immediate_tip_child=*/true, /*would_abandon_attested=*/true));
    BOOST_CHECK(!TrustedMirrorMaySelectMostWorkCandidate(
        /*extends_active_tip_chain=*/true, /*short_tip_reorg=*/false,
        /*has_quorum=*/false, /*active_tip_has_quorum=*/true,
        /*immediate_tip_child=*/true, /*would_abandon_attested=*/false,
        /*competing_attested_height=*/true));
    // Off-chain signed frontier (stranded on a competing fork): do not
    // crawl unattested tip-children (live archives 2026-08-16 at
    // 190333–190346). Catch-up *behind* the frontier on the same chain
    // is not this flag.
    BOOST_CHECK(!TrustedMirrorMaySelectMostWorkCandidate(
        /*extends_active_tip_chain=*/true, /*short_tip_reorg=*/false,
        /*has_quorum=*/false, /*active_tip_has_quorum=*/false,
        /*immediate_tip_child=*/true, /*would_abandon_attested=*/false,
        /*competing_attested_height=*/false,
        /*signed_frontier_on_competing_fork=*/true));
    BOOST_CHECK(TrustedMirrorMaySelectMostWorkCandidate(
        /*extends_active_tip_chain=*/true, /*short_tip_reorg=*/false,
        /*has_quorum=*/true, /*active_tip_has_quorum=*/false,
        /*immediate_tip_child=*/false, /*would_abandon_attested=*/false,
        /*competing_attested_height=*/false,
        /*signed_frontier_on_competing_fork=*/true));
    // Behind the frontier on the attested chain: still select the
    // unattested HEADER_ONLY tip-child (live miners 2026-08-16).
    BOOST_CHECK(TrustedMirrorMaySelectMostWorkCandidate(
        /*extends_active_tip_chain=*/true, /*short_tip_reorg=*/false,
        /*has_quorum=*/false, /*active_tip_has_quorum=*/true,
        /*immediate_tip_child=*/true, /*would_abandon_attested=*/false,
        /*competing_attested_height=*/false,
        /*signed_frontier_on_competing_fork=*/false));
    using node::matmul_trusted::TrustedMirrorMustDeferUnattestedConnect;
    BOOST_CHECK(TrustedMirrorMustDeferUnattestedConnect(
        /*trusted_mirror_profile1=*/true, /*has_quorum=*/false));
    BOOST_CHECK(!TrustedMirrorMustDeferUnattestedConnect(
        /*trusted_mirror_profile1=*/true, /*has_quorum=*/true));
    BOOST_CHECK(!TrustedMirrorMustDeferUnattestedConnect(
        /*trusted_mirror_profile1=*/false, /*has_quorum=*/false));
    BOOST_CHECK(!TrustedMirrorMustDeferUnattestedConnect(
        /*trusted_mirror_profile1=*/false, /*has_quorum=*/true));
    BOOST_CHECK(!TrustedMirrorMustDeferUnattestedConnect(
        /*trusted_mirror_profile1=*/true, /*has_quorum=*/false,
        /*covered_by_signed_frontier=*/true));
    // Catch-up height is not a GPU attestation: ExactReplay / ConnectTip
    // stay in place until quorum or signed-frontier coverage.
    BOOST_CHECK(TrustedMirrorMustDeferUnattestedConnect(
        /*trusted_mirror_profile1=*/true, /*has_quorum=*/false,
        /*covered_by_signed_frontier=*/false));
    using node::matmul_trusted::TrustedMirrorPreferCoveredConnectCandidate;
    BOOST_CHECK(TrustedMirrorPreferCoveredConnectCandidate(
        /*trusted_mirror=*/true, /*extends_active_tip=*/true,
        /*have_data_connectable=*/true, /*covered_or_quorum=*/true));
    BOOST_CHECK(!TrustedMirrorPreferCoveredConnectCandidate(
        false, true, true, true));
    BOOST_CHECK(!TrustedMirrorPreferCoveredConnectCandidate(
        true, /*extends_active_tip=*/false, true, true));
    BOOST_CHECK(!TrustedMirrorPreferCoveredConnectCandidate(
        true, true, /*have_data_connectable=*/false, true));
    BOOST_CHECK(!TrustedMirrorPreferCoveredConnectCandidate(
        true, true, true, /*covered_or_quorum=*/false));
    using node::matmul_trusted::TrustedMirrorMostWorkYieldsUnattestedTower;
    BOOST_CHECK(TrustedMirrorMostWorkYieldsUnattestedTower(
        /*trusted_mirror=*/true, /*have_attested_connectable=*/false,
        /*have_immediate_have_data_tip_child=*/false));
    BOOST_CHECK(!TrustedMirrorMostWorkYieldsUnattestedTower(
        true, /*have_attested_connectable=*/true, false));
    BOOST_CHECK(!TrustedMirrorMostWorkYieldsUnattestedTower(
        true, false, /*have_immediate_have_data_tip_child=*/true));
    BOOST_CHECK(!TrustedMirrorMostWorkYieldsUnattestedTower(
        /*trusted_mirror=*/false, false, false));
    using node::matmul_trusted::TrustedMirrorSkipUnattestedClaimedWorkTower;
    BOOST_CHECK(TrustedMirrorSkipUnattestedClaimedWorkTower(
        /*trusted_mirror=*/true, /*leads_to_signed_frontier=*/false,
        /*immediate_tip_child=*/false, /*unique_abandon_target=*/false));
    BOOST_CHECK(!TrustedMirrorSkipUnattestedClaimedWorkTower(
        true, /*leads_to_signed_frontier=*/true, false, false));
    BOOST_CHECK(!TrustedMirrorSkipUnattestedClaimedWorkTower(
        true, false, /*immediate_tip_child=*/true, false));
    BOOST_CHECK(!TrustedMirrorSkipUnattestedClaimedWorkTower(
        true, false, false, /*unique_abandon_target=*/true));
    BOOST_CHECK(!TrustedMirrorSkipUnattestedClaimedWorkTower(
        /*trusted_mirror=*/false, false, false, false));
    using node::matmul_trusted::TrustedMirrorFrontierCoversBlock;
    BOOST_CHECK(TrustedMirrorFrontierCoversBlock(
        /*frontier_available=*/true, /*block_height=*/190582,
        /*frontier_height=*/190621, /*frontier_descends_from_block=*/true));
    BOOST_CHECK(!TrustedMirrorFrontierCoversBlock(
        /*frontier_available=*/true, /*block_height=*/190622,
        /*frontier_height=*/190621, /*frontier_descends_from_block=*/true));
    BOOST_CHECK(!TrustedMirrorFrontierCoversBlock(
        /*frontier_available=*/true, /*block_height=*/190582,
        /*frontier_height=*/190621, /*frontier_descends_from_block=*/false));
    BOOST_CHECK(!TrustedMirrorFrontierCoversBlock(
        /*frontier_available=*/false, /*block_height=*/190582,
        /*frontier_height=*/190621, /*frontier_descends_from_block=*/true));
    using node::matmul_trusted::MustDeferConflictingAttestedHeight;
    BOOST_CHECK(MustDeferConflictingAttestedHeight(
        /*trusted_mirror=*/true, /*candidate_has_quorum=*/false,
        /*competing_attested_height=*/true));
    BOOST_CHECK(!MustDeferConflictingAttestedHeight(
        /*trusted_mirror=*/true, /*candidate_has_quorum=*/true,
        /*competing_attested_height=*/true));
    BOOST_CHECK(!MustDeferConflictingAttestedHeight(
        /*trusted_mirror=*/true, /*candidate_has_quorum=*/false,
        /*competing_attested_height=*/false));
    BOOST_CHECK(!MustDeferConflictingAttestedHeight(
        /*trusted_mirror=*/true, /*candidate_has_quorum=*/false,
        /*competing_attested_height=*/true,
        /*covered_by_signed_frontier=*/true));
    using node::matmul_trusted::DescendantSignedFrontierRecoversExpiredHeight;
    BOOST_CHECK(DescendantSignedFrontierRecoversExpiredHeight(
        /*covered_by_signed_frontier=*/true));
    BOOST_CHECK(!DescendantSignedFrontierRecoversExpiredHeight(false));
    using node::matmul_trusted::DualQuorumIncomparableFailClosed;
    using node::matmul_trusted::DualQuorumSameHeightTwinsFailClosed;
    BOOST_CHECK(DualQuorumIncomparableFailClosed(
        /*both_have_quorum=*/true, /*incomparable=*/true));
    BOOST_CHECK(!DualQuorumIncomparableFailClosed(true, /*incomparable=*/false));
    BOOST_CHECK(!DualQuorumIncomparableFailClosed(
        /*both_have_quorum=*/false, true));
    BOOST_CHECK(DualQuorumSameHeightTwinsFailClosed(
        /*tip_has_quorum=*/true, /*competing_same_height_has_quorum=*/true,
        /*signed_frontier_strictly_ahead=*/false));
    BOOST_CHECK(!DualQuorumSameHeightTwinsFailClosed(true, true,
                                                    /*signed_frontier_strictly_ahead=*/true));
    BOOST_CHECK(!MustDeferConflictingAttestedHeight(
        /*trusted_mirror=*/false, /*candidate_has_quorum=*/false,
        /*competing_attested_height=*/true));
    BOOST_CHECK(!MustDeferConflictingAttestedHeight(
        /*trusted_mirror=*/false, /*candidate_has_quorum=*/true,
        /*competing_attested_height=*/true));
    using node::matmul_trusted::TrustedMirrorAttestedSiblingIsActionable;
    // Qualifier 3ed2619c: the attested tip / self candidate must not defer
    // a sole linear tip-child.
    BOOST_CHECK(!TrustedMirrorAttestedSiblingIsActionable(
        /*distinct_from_candidate=*/false, /*same_parent=*/true,
        /*same_height_as_tip_child=*/true, /*has_quorum=*/true));
    BOOST_CHECK(!TrustedMirrorAttestedSiblingIsActionable(
        /*distinct_from_candidate=*/true, /*same_parent=*/false,
        /*same_height_as_tip_child=*/true, /*has_quorum=*/true));
    BOOST_CHECK(!TrustedMirrorAttestedSiblingIsActionable(
        /*distinct_from_candidate=*/true, /*same_parent=*/true,
        /*same_height_as_tip_child=*/false, /*has_quorum=*/true));
    BOOST_CHECK(!TrustedMirrorAttestedSiblingIsActionable(
        /*distinct_from_candidate=*/true, /*same_parent=*/true,
        /*same_height_as_tip_child=*/true, /*has_quorum=*/false));
    BOOST_CHECK(!TrustedMirrorAttestedSiblingIsActionable(
        /*distinct_from_candidate=*/true, /*same_parent=*/true,
        /*same_height_as_tip_child=*/true, /*has_quorum=*/true,
        /*failed=*/true));
    BOOST_CHECK(TrustedMirrorAttestedSiblingIsActionable(
        /*distinct_from_candidate=*/true, /*same_parent=*/true,
        /*same_height_as_tip_child=*/true, /*has_quorum=*/true));
    using node::matmul_trusted::TrustedMirrorDeferUnattestedMostWorkForAttestedSibling;
    BOOST_CHECK(TrustedMirrorDeferUnattestedMostWorkForAttestedSibling(
        /*configured_profile1=*/true, /*candidate_extends_tip=*/true,
        /*candidate_has_quorum=*/false, /*attested_tip_child_exists=*/true));
    BOOST_CHECK(!TrustedMirrorDeferUnattestedMostWorkForAttestedSibling(
        /*configured_profile1=*/true, /*candidate_extends_tip=*/true,
        /*candidate_has_quorum=*/false, /*attested_tip_child_exists=*/false));
    BOOST_CHECK(!TrustedMirrorDeferUnattestedMostWorkForAttestedSibling(
        /*configured_profile1=*/true, /*candidate_extends_tip=*/true,
        /*candidate_has_quorum=*/true, /*attested_tip_child_exists=*/true));
    BOOST_CHECK(!TrustedMirrorDeferUnattestedMostWorkForAttestedSibling(
        /*configured_profile1=*/false, /*candidate_extends_tip=*/true,
        /*candidate_has_quorum=*/false, /*attested_tip_child_exists=*/true));
    BOOST_CHECK(!TrustedMirrorDeferUnattestedMostWorkForAttestedSibling(
        /*configured_profile1=*/true, /*candidate_extends_tip=*/false,
        /*candidate_has_quorum=*/false, /*attested_tip_child_exists=*/true));
    using node::matmul_trusted::BlocksBehindSignedFrontier;
    BOOST_CHECK_EQUAL(BlocksBehindSignedFrontier(188160, 187947), 213);
    BOOST_CHECK_EQUAL(BlocksBehindSignedFrontier(187947, 187947), 0);
    BOOST_CHECK_EQUAL(BlocksBehindSignedFrontier(187946, 187947), 0);
    BOOST_CHECK_EQUAL(BlocksBehindSignedFrontier(-1, 187947), 0);
    BOOST_CHECK_EQUAL(BlocksBehindSignedFrontier(188160, -1), 0);
    BOOST_CHECK(TrustedMirrorPreferGetMmAttest(
        /*active_tip_child=*/true, /*short_tip_reorg_missing_root=*/false));
    BOOST_CHECK(TrustedMirrorPreferGetMmAttest(
        /*active_tip_child=*/false, /*short_tip_reorg_missing_root=*/true));
    BOOST_CHECK(!TrustedMirrorPreferGetMmAttest(
        /*active_tip_child=*/false, /*short_tip_reorg_missing_root=*/false));
    BOOST_CHECK(TrustedMirrorPreferGetMmAttest(
        /*active_tip_child=*/false, /*short_tip_reorg_missing_root=*/false,
        /*on_parked_reorg_branch=*/false, /*recent_active_ancestor=*/true));
    BOOST_CHECK(TrustedMirrorPreferGetMmAttest(
        /*active_tip_child=*/false, /*short_tip_reorg_missing_root=*/false,
        /*on_parked_reorg_branch=*/false, /*recent_active_ancestor=*/false,
        /*followed_body_awaiting_attestation=*/true));
    BOOST_CHECK(TrustedMirrorPreferGetMmAttest(
        /*active_tip_child=*/false, /*short_tip_reorg_missing_root=*/false,
        /*on_parked_reorg_branch=*/false, /*recent_active_ancestor=*/false,
        /*followed_body_awaiting_attestation=*/false,
        /*is_signed_frontier_hash=*/true));
    BOOST_CHECK(!TrustedMirrorPreferGetMmAttest(
        /*active_tip_child=*/false, /*short_tip_reorg_missing_root=*/false,
        /*on_parked_reorg_branch=*/true, /*recent_active_ancestor=*/false,
        /*followed_body_awaiting_attestation=*/true));
    BOOST_CHECK(!TrustedMirrorPreferGetMmAttest(
        /*active_tip_child=*/false, /*short_tip_reorg_missing_root=*/false,
        /*on_parked_reorg_branch=*/true, /*recent_active_ancestor=*/true));
    BOOST_CHECK(!TrustedMirrorPreferGetMmAttest(
        /*active_tip_child=*/true, /*short_tip_reorg_missing_root=*/true,
        /*on_parked_reorg_branch=*/true));
    BOOST_CHECK(!TrustedMirrorPreferGetMmAttest(
        /*active_tip_child=*/false, /*short_tip_reorg_missing_root=*/true,
        /*on_parked_reorg_branch=*/true));
    // Catch-up: only the first hole. Frontier / ancestor preference is
    // near-tip work and was the live 194999 GETMMATTEST hammer.
    BOOST_CHECK(TrustedMirrorPreferGetMmAttest(
        /*active_tip_child=*/true, /*short_tip_reorg_missing_root=*/false,
        /*on_parked_reorg_branch=*/false, /*recent_active_ancestor=*/false,
        /*followed_body_awaiting_attestation=*/false,
        /*is_signed_frontier_hash=*/false,
        /*signed_frontier_catch_up=*/true));
    BOOST_CHECK(TrustedMirrorPreferGetMmAttest(
        /*active_tip_child=*/false, /*short_tip_reorg_missing_root=*/true,
        /*on_parked_reorg_branch=*/false, /*recent_active_ancestor=*/false,
        /*followed_body_awaiting_attestation=*/false,
        /*is_signed_frontier_hash=*/false,
        /*signed_frontier_catch_up=*/true));
    BOOST_CHECK(TrustedMirrorPreferGetMmAttest(
        /*active_tip_child=*/false, /*short_tip_reorg_missing_root=*/false,
        /*on_parked_reorg_branch=*/false, /*recent_active_ancestor=*/false,
        /*followed_body_awaiting_attestation=*/true,
        /*is_signed_frontier_hash=*/false,
        /*signed_frontier_catch_up=*/true));
    BOOST_CHECK(!TrustedMirrorPreferGetMmAttest(
        /*active_tip_child=*/false, /*short_tip_reorg_missing_root=*/false,
        /*on_parked_reorg_branch=*/false, /*recent_active_ancestor=*/false,
        /*followed_body_awaiting_attestation=*/false,
        /*is_signed_frontier_hash=*/true,
        /*signed_frontier_catch_up=*/true));
    BOOST_CHECK(!TrustedMirrorPreferGetMmAttest(
        /*active_tip_child=*/false, /*short_tip_reorg_missing_root=*/false,
        /*on_parked_reorg_branch=*/false, /*recent_active_ancestor=*/true,
        /*followed_body_awaiting_attestation=*/false,
        /*is_signed_frontier_hash=*/false,
        /*signed_frontier_catch_up=*/true));
    BOOST_CHECK(!TrustedMirrorPreferGetMmAttest(
        /*active_tip_child=*/true, /*short_tip_reorg_missing_root=*/false,
        /*on_parked_reorg_branch=*/true, /*recent_active_ancestor=*/false,
        /*followed_body_awaiting_attestation=*/false,
        /*is_signed_frontier_hash=*/false,
        /*signed_frontier_catch_up=*/true));
    using node::matmul_trusted::TrustedMirrorCatchUpShouldRequestGetMmAttest;
    BOOST_CHECK(TrustedMirrorCatchUpShouldRequestGetMmAttest(
        /*signed_frontier_catch_up=*/false, /*preferred=*/false));
    BOOST_CHECK(TrustedMirrorCatchUpShouldRequestGetMmAttest(
        /*signed_frontier_catch_up=*/true, /*preferred=*/true));
    BOOST_CHECK(!TrustedMirrorCatchUpShouldRequestGetMmAttest(
        /*signed_frontier_catch_up=*/true, /*preferred=*/false));
    using node::matmul_trusted::PreferGetMmAttestPeer;
    BOOST_CHECK(PreferGetMmAttestPeer(
        /*has_attestation_archive_bit=*/true, /*recent_valid_mmattest=*/false));
    BOOST_CHECK(PreferGetMmAttestPeer(
        /*has_attestation_archive_bit=*/false, /*recent_valid_mmattest=*/true));
    BOOST_CHECK(PreferGetMmAttestPeer(
        /*has_attestation_archive_bit=*/true, /*recent_valid_mmattest=*/true));
    BOOST_CHECK(PreferGetMmAttestPeer(
        /*has_attestation_archive_bit=*/false, /*recent_valid_mmattest=*/false,
        /*trusted_mirror=*/true));
    BOOST_CHECK(PreferGetMmAttestPeer(
        /*has_attestation_archive_bit=*/false, /*recent_valid_mmattest=*/false,
        /*trusted_mirror=*/false, /*consensus_node=*/true));
    BOOST_CHECK(!PreferGetMmAttestPeer(
        /*has_attestation_archive_bit=*/false,
        /*recent_valid_mmattest=*/false));
    BOOST_CHECK(!PreferGetMmAttestPeer(
        /*has_attestation_archive_bit=*/false, /*recent_valid_mmattest=*/false,
        /*trusted_mirror=*/false, /*consensus_node=*/true,
        /*signed_frontier_catch_up=*/true));
    BOOST_CHECK(PreferGetMmAttestPeer(
        /*has_attestation_archive_bit=*/false, /*recent_valid_mmattest=*/false,
        /*trusted_mirror=*/false, /*consensus_node=*/true,
        /*signed_frontier_catch_up=*/true, /*gpu_attestor=*/true));
    BOOST_CHECK(PreferGetMmAttestPeer(
        /*has_attestation_archive_bit=*/true, /*recent_valid_mmattest=*/false,
        /*trusted_mirror=*/false, /*consensus_node=*/false,
        /*signed_frontier_catch_up=*/true));
    using node::matmul_trusted::IsSignedFrontierCatchUp;
    BOOST_CHECK(IsSignedFrontierCatchUp(
        /*trusted_mirror=*/true, /*configured=*/true,
        /*blocks_behind=*/34, /*followed_ahead=*/36));
    BOOST_CHECK(!IsSignedFrontierCatchUp(
        /*trusted_mirror=*/true, /*configured=*/true,
        /*blocks_behind=*/0, /*followed_ahead=*/36));
    BOOST_CHECK(!IsSignedFrontierCatchUp(
        /*trusted_mirror=*/false, /*configured=*/true,
        /*blocks_behind=*/34, /*followed_ahead=*/36));
    BOOST_CHECK(!IsSignedFrontierCatchUp(
        /*trusted_mirror=*/true, /*configured=*/true,
        /*blocks_behind=*/34, /*followed_ahead=*/1));
    // Restart: no in-memory frontier, HEADER_ONLY suffix already followed.
    BOOST_CHECK(IsSignedFrontierCatchUp(
        /*trusted_mirror=*/true, /*configured=*/true,
        /*blocks_behind=*/0, /*followed_ahead=*/98,
        /*stall_headers_ahead=*/2, /*frontier_available=*/false));
    BOOST_CHECK(!IsSignedFrontierCatchUp(
        /*trusted_mirror=*/true, /*configured=*/true,
        /*blocks_behind=*/0, /*followed_ahead=*/1,
        /*stall_headers_ahead=*/2, /*frontier_available=*/false));
    // Known frontier at the tip: miner HEADER_ONLY children stay 16-wide IBD,
    // not 1-wide catch-up (would spray GETDATA at miners).
    BOOST_CHECK(!IsSignedFrontierCatchUp(
        /*trusted_mirror=*/true, /*configured=*/true,
        /*blocks_behind=*/0, /*followed_ahead=*/36,
        /*stall_headers_ahead=*/2, /*frontier_available=*/true));
    using node::matmul_trusted::CappedFollowedCatchUpAhead;
    // Live signer 2026-08-16: 13 unattested HEADER_ONLY children of the
    // attested tip must not look like a 13-block catch-up hole.
    BOOST_CHECK_EQUAL(CappedFollowedCatchUpAhead(
        /*configured=*/true, /*frontier_available=*/true,
        /*tip_height=*/190617, /*followed_header_height=*/190630,
        /*signed_frontier_height=*/190617, /*tip_leads_to_frontier=*/true), 0);
    BOOST_CHECK_EQUAL(CappedFollowedCatchUpAhead(
        /*configured=*/true, /*frontier_available=*/true,
        /*tip_height=*/190575, /*followed_header_height=*/190602,
        /*signed_frontier_height=*/190611, /*tip_leads_to_frontier=*/true), 27);
    BOOST_CHECK_EQUAL(CappedFollowedCatchUpAhead(
        /*configured=*/true, /*frontier_available=*/true,
        /*tip_height=*/190575, /*followed_header_height=*/190630,
        /*signed_frontier_height=*/190611, /*tip_leads_to_frontier=*/true), 36);
    BOOST_CHECK_EQUAL(CappedFollowedCatchUpAhead(
        /*configured=*/true, /*frontier_available=*/true,
        /*tip_height=*/190575, /*followed_header_height=*/190630,
        /*signed_frontier_height=*/190611, /*tip_leads_to_frontier=*/false), 0);
    BOOST_CHECK_EQUAL(CappedFollowedCatchUpAhead(
        /*configured=*/false, /*frontier_available=*/false,
        /*tip_height=*/190617, /*followed_header_height=*/190630,
        /*signed_frontier_height=*/190617, /*tip_leads_to_frontier=*/true), 13);
    using node::matmul_trusted::IsNarrowCatchUpWindowForPolicy;
    BOOST_CHECK(IsNarrowCatchUpWindowForPolicy(
        /*ibd=*/false, /*ahead=*/40, /*signed_frontier_catch_up=*/true));
    BOOST_CHECK(IsNarrowCatchUpWindowForPolicy(
        /*ibd=*/false, /*ahead=*/8, /*signed_frontier_catch_up=*/true));
    BOOST_CHECK(!IsNarrowCatchUpWindowForPolicy(
        /*ibd=*/false, /*ahead=*/32, /*signed_frontier_catch_up=*/false));
    BOOST_CHECK(!IsNarrowCatchUpWindowForPolicy(
        /*ibd=*/true, /*ahead=*/40, /*signed_frontier_catch_up=*/true));
    BOOST_CHECK(IsNarrowCatchUpWindowForPolicy(
        /*ibd=*/false, /*ahead=*/8, /*signed_frontier_catch_up=*/false));
    BOOST_CHECK(!IsNarrowCatchUpWindowForPolicy(
        /*ibd=*/false, /*ahead=*/40, /*signed_frontier_catch_up=*/true,
        /*stall_headers_ahead=*/2, /*narrow_max_ahead=*/32,
        /*far_behind_yield=*/200, /*uncapped_ahead=*/1136));
    BOOST_CHECK(!IsNarrowCatchUpWindowForPolicy(
        /*ibd=*/false, /*ahead=*/8, /*signed_frontier_catch_up=*/false,
        2, 32, 200, /*uncapped_ahead=*/200));
    using node::matmul_trusted::PersistFollowedSuffixBodyWithoutGpu;
    BOOST_CHECK(PersistFollowedSuffixBodyWithoutGpu(
        /*trusted_mirror=*/false, /*extends_active_tip=*/true,
        /*pprev_is_tip=*/false, /*index_height=*/199338, /*tip_height=*/199336));
    BOOST_CHECK(!PersistFollowedSuffixBodyWithoutGpu(
        false, true, /*pprev_is_tip=*/true, 199337, 199336));
    BOOST_CHECK(!PersistFollowedSuffixBodyWithoutGpu(
        /*trusted_mirror=*/true, true, false, 199338, 199336));
    BOOST_CHECK(!PersistFollowedSuffixBodyWithoutGpu(
        false, /*extends_active_tip=*/false, false, 199338, 199336));
    BOOST_CHECK(PersistFollowedSuffixBodyWithoutGpu(
        false, true, /*pprev_is_tip=*/true, 199337, 199336, /*far_behind=*/true));
    BOOST_CHECK(PersistFollowedSuffixBodyWithoutGpu(
        /*trusted_mirror=*/true, true, false, 199338, 199336, /*far_behind=*/true));
    BOOST_CHECK(!PersistFollowedSuffixBodyWithoutGpu(
        false, /*extends_active_tip=*/false, false, 199338, 199336,
        /*far_behind=*/true));
    using node::matmul_trusted::TicketlessRcBodyMayPersistWithoutGpu;
    BOOST_CHECK(TicketlessRcBodyMayPersistWithoutGpu(
        /*trusted_mirror_authority_cover=*/true, /*followed_tip_child=*/false));
    BOOST_CHECK(TicketlessRcBodyMayPersistWithoutGpu(
        false, /*followed_tip_child=*/true));
    BOOST_CHECK(!TicketlessRcBodyMayPersistWithoutGpu(false, false));
    using node::matmul_trusted::SignedFrontierIsOnActiveChain;
    BOOST_CHECK(SignedFrontierIsOnActiveChain(
        true, true, /*tip_height=*/199801, /*frontier_height=*/199801,
        /*tip_ancestor_at_frontier_is_frontier=*/true,
        /*frontier_ancestor_at_tip_is_tip=*/true));
    BOOST_CHECK(SignedFrontierIsOnActiveChain(
        true, true, /*tip_height=*/199378, /*frontier_height=*/199801,
        /*tip_ancestor_at_frontier_is_frontier=*/false,
        /*frontier_ancestor_at_tip_is_tip=*/true));
    BOOST_CHECK(!SignedFrontierIsOnActiveChain(
        true, true, 199378, 199801, false, /*frontier_ancestor_at_tip_is_tip=*/false));
    BOOST_CHECK(!SignedFrontierIsOnActiveChain(
        true, /*has_frontier=*/false, 199378, 199801, false, false));
    using node::matmul_trusted::PreferSignedFrontierCatchUpBlockPeer;
    BOOST_CHECK(!PreferSignedFrontierCatchUpBlockPeer(
        /*signed_frontier_catch_up=*/true, /*has_archive_bit=*/false,
        /*trusted_mirror_peer=*/false, /*node_network=*/true,
        /*recent_valid_mmattest=*/false, /*manual_or_noban=*/false));
    BOOST_CHECK(PreferSignedFrontierCatchUpBlockPeer(
        /*signed_frontier_catch_up=*/true, /*has_archive_bit=*/true,
        /*trusted_mirror_peer=*/false, /*node_network=*/true,
        /*recent_valid_mmattest=*/false, /*manual_or_noban=*/false));
    BOOST_CHECK(PreferSignedFrontierCatchUpBlockPeer(
        /*signed_frontier_catch_up=*/true, /*has_archive_bit=*/false,
        /*trusted_mirror_peer=*/true, /*node_network=*/true,
        /*recent_valid_mmattest=*/false, /*manual_or_noban=*/false));
    BOOST_CHECK(PreferSignedFrontierCatchUpBlockPeer(
        /*signed_frontier_catch_up=*/true, /*has_archive_bit=*/false,
        /*trusted_mirror_peer=*/true, /*node_network=*/false,
        /*recent_valid_mmattest=*/false, /*manual_or_noban=*/false));
    BOOST_CHECK(PreferSignedFrontierCatchUpBlockPeer(
        /*signed_frontier_catch_up=*/true, /*has_archive_bit=*/true,
        /*trusted_mirror_peer=*/false, /*node_network=*/false,
        /*recent_valid_mmattest=*/false, /*manual_or_noban=*/false));
    BOOST_CHECK(PreferSignedFrontierCatchUpBlockPeer(
        /*signed_frontier_catch_up=*/true, /*has_archive_bit=*/false,
        /*trusted_mirror_peer=*/false, /*node_network=*/true,
        /*recent_valid_mmattest=*/false, /*manual_or_noban=*/true));
    BOOST_CHECK(PreferSignedFrontierCatchUpBlockPeer(
        /*signed_frontier_catch_up=*/false, /*has_archive_bit=*/false,
        /*trusted_mirror_peer=*/false, /*node_network=*/true,
        /*recent_valid_mmattest=*/false, /*manual_or_noban=*/false));
    // A miner that relayed one MMATTEST is not an exclusive body source
    // (live public CPU archive peer=94305: 16-wide HEADER_ONLY getdata, tip+1 timeout).
    BOOST_CHECK(!PreferSignedFrontierCatchUpBlockPeer(
        /*signed_frontier_catch_up=*/true, /*has_archive_bit=*/false,
        /*trusted_mirror_peer=*/false, /*node_network=*/true,
        /*recent_valid_mmattest=*/true, /*manual_or_noban=*/false));
    // Inbound archives are served, not used as catch-up GETDATA sources.
    BOOST_CHECK(!PreferSignedFrontierCatchUpBlockPeer(
        /*signed_frontier_catch_up=*/true, /*has_archive_bit=*/true,
        /*trusted_mirror_peer=*/false, /*node_network=*/true,
        /*recent_valid_mmattest=*/false, /*manual_or_noban=*/false,
        /*outbound=*/false));
    BOOST_CHECK(PreferSignedFrontierCatchUpBlockPeer(
        /*signed_frontier_catch_up=*/true, /*has_archive_bit=*/true,
        /*trusted_mirror_peer=*/false, /*node_network=*/true,
        /*recent_valid_mmattest=*/false, /*manual_or_noban=*/false,
        /*outbound=*/true));
    BOOST_CHECK(PreferSignedFrontierCatchUpBlockPeer(
        /*signed_frontier_catch_up=*/true, /*has_archive_bit=*/false,
        /*trusted_mirror_peer=*/false, /*node_network=*/false,
        /*recent_valid_mmattest=*/false, /*manual_or_noban=*/true,
        /*outbound=*/false));
    using node::matmul_trusted::SkipNonPreferredSignedFrontierBodyPeer;
    BOOST_CHECK(SkipNonPreferredSignedFrontierBodyPeer(
        /*signed_frontier_catch_up=*/true, /*this_peer_preferred=*/false,
        /*any_capable_preferred_peer_connected=*/true));
    // Hung GPU must not fall through to inbound miners.
    BOOST_CHECK(SkipNonPreferredSignedFrontierBodyPeer(
        /*signed_frontier_catch_up=*/true, /*this_peer_preferred=*/false,
        /*any_capable_preferred_peer_connected=*/false));
    BOOST_CHECK(!SkipNonPreferredSignedFrontierBodyPeer(
        /*signed_frontier_catch_up=*/true, /*this_peer_preferred=*/true,
        /*any_capable_preferred_peer_connected=*/true));
    BOOST_CHECK(!SkipNonPreferredSignedFrontierBodyPeer(
        /*signed_frontier_catch_up=*/false, /*this_peer_preferred=*/false,
        /*any_capable_preferred_peer_connected=*/true));
    using node::matmul_trusted::SignedFrontierBodySourceCanServeCatchUp;
    BOOST_CHECK(SignedFrontierBodySourceCanServeCatchUp(
        /*preferred=*/true, /*has_best_known=*/true, /*best_known_height=*/190632,
        /*tip_height=*/190588, /*best_known_extends_tip=*/true));
    BOOST_CHECK(!SignedFrontierBodySourceCanServeCatchUp(
        /*preferred=*/true, /*has_best_known=*/false, /*best_known_height=*/-1,
        /*tip_height=*/190588, /*best_known_extends_tip=*/false));
    BOOST_CHECK(!SignedFrontierBodySourceCanServeCatchUp(
        /*preferred=*/true, /*has_best_known=*/true, /*best_known_height=*/1412,
        /*tip_height=*/190588, /*best_known_extends_tip=*/false));
    BOOST_CHECK(!SignedFrontierBodySourceCanServeCatchUp(
        /*preferred=*/true, /*has_best_known=*/true, /*best_known_height=*/190632,
        /*tip_height=*/190588, /*best_known_extends_tip=*/true,
        /*version_handshake_complete=*/false));
    // VERSION == tip is not "had bodies past tip at connect", but BestKnown
    // extending the active tip still lets us GETDATA tip+1 (handshake snapshot
    // is stale once we have climbed; hung-connect starting=-1 stays refused).
    BOOST_CHECK(SignedFrontierBodySourceCanServeCatchUp(
        /*preferred=*/true, /*has_best_known=*/true, /*best_known_height=*/190632,
        /*tip_height=*/190588, /*best_known_extends_tip=*/true,
        /*version_handshake_complete=*/true, /*starting_height=*/190588));
    BOOST_CHECK(!SignedFrontierBodySourceCanServeCatchUp(
        /*preferred=*/true, /*has_best_known=*/true, /*best_known_height=*/190632,
        /*tip_height=*/190588, /*best_known_extends_tip=*/true,
        /*version_handshake_complete=*/true, /*starting_height=*/-1));
    BOOST_CHECK(SignedFrontierBodySourceCanServeCatchUp(
        /*preferred=*/true, /*has_best_known=*/true, /*best_known_height=*/190632,
        /*tip_height=*/190588, /*best_known_extends_tip=*/true,
        /*version_handshake_complete=*/true, /*starting_height=*/190632));
    using node::matmul_trusted::SignedFrontierPeerHadCatchUpBodiesAtConnect;
    BOOST_CHECK(!SignedFrontierPeerHadCatchUpBodiesAtConnect(-1, 190781));
    BOOST_CHECK(!SignedFrontierPeerHadCatchUpBodiesAtConnect(190781, 190781));
    BOOST_CHECK(SignedFrontierPeerHadCatchUpBodiesAtConnect(190858, 190781));
    using node::matmul_trusted::ShouldDropInFlightForRootFirstRerequest;
    BOOST_CHECK(!ShouldDropInFlightForRootFirstRerequest(
        /*already_requested=*/true, /*all_owners_stale=*/false));
    BOOST_CHECK(ShouldDropInFlightForRootFirstRerequest(true, true));
    BOOST_CHECK(!ShouldDropInFlightForRootFirstRerequest(false, true));
    using node::matmul_trusted::CanonicalFirstHoleMayReassign;
    BOOST_CHECK(CanonicalFirstHoleMayReassign(
        /*already_requested=*/false, /*all_owners_stale_or_missing_stamp=*/false));
    BOOST_CHECK(!CanonicalFirstHoleMayReassign(true, /*stale=*/false));
    BOOST_CHECK(CanonicalFirstHoleMayReassign(true, /*stale=*/true));
    using node::matmul_trusted::SeedTrustedMirrorGpuBestKnownFromFrontier;
    BOOST_CHECK(SeedTrustedMirrorGpuBestKnownFromFrontier(
        /*signed_frontier_catch_up=*/true,
        /*best_known_usable_for_catch_up=*/false, /*seed_extends_tip=*/true,
        /*seed_height=*/191690, /*tip_height=*/191592));
    BOOST_CHECK(!SeedTrustedMirrorGpuBestKnownFromFrontier(
        true, /*best_known_usable_for_catch_up=*/true, true, 190647, 190602));
    BOOST_CHECK(!SeedTrustedMirrorGpuBestKnownFromFrontier(
        /*signed_frontier_catch_up=*/false, false, true, 190647, 190602));
    BOOST_CHECK(!SeedTrustedMirrorGpuBestKnownFromFrontier(
        true, false, /*seed_extends_tip=*/false, 190647, 190602));
    BOOST_CHECK(!SeedTrustedMirrorGpuBestKnownFromFrontier(
        true, false, true, 190647, 190602,
        /*version_handshake_complete=*/false));
    BOOST_CHECK(!SeedTrustedMirrorGpuBestKnownFromFrontier(
        true, false, true, 190647, 190602,
        /*version_handshake_complete=*/true, /*may_seed_this_peer=*/false));
    using node::matmul_trusted::SignedFrontierMaySeedBestKnownFromFrontier;
    BOOST_CHECK(SignedFrontierMaySeedBestKnownFromFrontier(
        /*gpu_manual_or_noban=*/true, /*outbound=*/false,
        /*archive_or_mirror=*/false, /*starting_height=*/-1,
        /*tip_height=*/190781));
    BOOST_CHECK(!SignedFrontierMaySeedBestKnownFromFrontier(
        false, /*outbound=*/false, /*archive_or_mirror=*/true, 190858, 190781));
    BOOST_CHECK(!SignedFrontierMaySeedBestKnownFromFrontier(
        false, /*outbound=*/true, /*archive_or_mirror=*/false, 190858, 190781));
    BOOST_CHECK(!SignedFrontierMaySeedBestKnownFromFrontier(
        false, true, true, /*starting_height=*/190781, /*tip_height=*/190781));
    BOOST_CHECK(SignedFrontierMaySeedBestKnownFromFrontier(
        false, true, true, /*starting_height=*/190858, /*tip_height=*/190781));
    using node::matmul_trusted::SignedFrontierMayRequestCatchUpGetData;
    BOOST_CHECK(SignedFrontierMayRequestCatchUpGetData(
        /*signed_frontier_catch_up=*/false, /*gpu_manual_or_noban=*/false,
        /*outbound=*/false, /*archive_or_mirror=*/false,
        /*version_handshake_complete=*/false));
    BOOST_CHECK(!SignedFrontierMayRequestCatchUpGetData(
        true, /*gpu_manual_or_noban=*/true, true, false,
        /*version_handshake_complete=*/false));
    BOOST_CHECK(SignedFrontierMayRequestCatchUpGetData(
        true, /*gpu_manual_or_noban=*/true, /*outbound=*/false, false,
        /*version_handshake_complete=*/true));
    BOOST_CHECK(!SignedFrontierMayRequestCatchUpGetData(
        true, /*gpu_manual_or_noban=*/true, true, false, true,
        /*starting_height=*/190767, /*tip_height=*/190816));
    BOOST_CHECK(SignedFrontierMayRequestCatchUpGetData(
        true, /*gpu_manual_or_noban=*/true, false, false, true,
        /*starting_height=*/190899, /*tip_height=*/190816));
    BOOST_CHECK(!SignedFrontierMayRequestCatchUpGetData(
        true, false, /*outbound=*/false, /*archive_or_mirror=*/true, true,
        /*starting_height=*/190858, /*tip_height=*/190781));
    BOOST_CHECK(!SignedFrontierMayRequestCatchUpGetData(
        true, false, /*outbound=*/true, /*archive_or_mirror=*/false, true,
        190858, 190781));
    BOOST_CHECK(!SignedFrontierMayRequestCatchUpGetData(
        true, false, true, true, true,
        /*starting_height=*/190781, /*tip_height=*/190781));
    BOOST_CHECK(SignedFrontierMayRequestCatchUpGetData(
        true, false, true, true, true,
        /*starting_height=*/190858, /*tip_height=*/190781));
    using node::matmul_trusted::SignedFrontierPeerMayServeCatchUpTipPlusOne;
    // Miner HEADER_ONLY tower above the active tip must not gate GETDATA.
    // VERSION 194111 is behind m_best_header 194116 but ahead of tip 189534.
    BOOST_CHECK(SignedFrontierMayRequestCatchUpGetData(
        true, /*gpu_manual_or_noban=*/true, true, true, true,
        /*starting_height=*/194111, /*tip_height=*/189534));
    BOOST_CHECK(SignedFrontierPeerMayServeCatchUpTipPlusOne(
        /*starting_height=*/194111, /*active_tip_height=*/189534));
    BOOST_CHECK(!SignedFrontierPeerMayServeCatchUpTipPlusOne(194111, 194116));
    // Climbed past handshake snapshot; BestKnown still extends the active tip.
    BOOST_CHECK(SignedFrontierMayRequestCatchUpGetData(
        true, true, true, true, true,
        /*starting_height=*/194111, /*tip_height=*/194121,
        /*best_known_height=*/194160, /*best_known_extends_tip=*/true));
    BOOST_CHECK(SignedFrontierPeerMayServeCatchUpTipPlusOne(
        194111, 194121, 194160, true));
    // Behind sibling: VERSION < tip, BestKnown does not extend past tip.
    BOOST_CHECK(!SignedFrontierMayRequestCatchUpGetData(
        true, true, true, true, true,
        /*starting_height=*/190767, /*tip_height=*/190816,
        /*best_known_height=*/190767, /*best_known_extends_tip=*/false));
    BOOST_CHECK(!SignedFrontierPeerMayServeCatchUpTipPlusOne(
        190767, 190816, 190767, false));
    BOOST_CHECK(!SignedFrontierPeerMayServeCatchUpTipPlusOne(-1, 190781, 190858, true));
    using node::matmul_trusted::ShouldAdvanceBestKnownFromMmAttest;
    using node::matmul_trusted::ShouldAdvanceBestKnownFromPeerBody;
    using matmul::trusted::AddResult;
    BOOST_CHECK(ShouldAdvanceBestKnownFromMmAttest(
        true, false, AddResult::Accepted));
    BOOST_CHECK(ShouldAdvanceBestKnownFromMmAttest(
        true, false, AddResult::Duplicate));
    BOOST_CHECK(!ShouldAdvanceBestKnownFromMmAttest(
        true, false, AddResult::Capacity));
    BOOST_CHECK(!ShouldAdvanceBestKnownFromMmAttest(
        true, false, AddResult::InvalidSignature));
    BOOST_CHECK(!ShouldAdvanceBestKnownFromMmAttest(
        true, false, AddResult::UntrustedSigner));
    BOOST_CHECK(!ShouldAdvanceBestKnownFromMmAttest(
        /*known_profile1=*/false, false, AddResult::Accepted));
    BOOST_CHECK(!ShouldAdvanceBestKnownFromMmAttest(
        true, /*header_failed=*/true, AddResult::Accepted));
    BOOST_CHECK(!ShouldAdvanceBestKnownFromMmAttest(
        true, false, AddResult::Heard));
    BOOST_CHECK(!ShouldAdvanceBestKnownFromMmAttest(
        true, false, AddResult::Equivocation));
    BOOST_CHECK(!ShouldAdvanceBestKnownFromMmAttest(
        true, false, AddResult::FrozenSigner));
    BOOST_CHECK(!ShouldAdvanceBestKnownFromMmAttest(
        true, false, AddResult::BlocklistedSigner));
    BOOST_CHECK(ShouldAdvanceBestKnownFromPeerBody(
        /*have_index=*/true, /*header_failed=*/false, /*have_data=*/true));
    BOOST_CHECK(!ShouldAdvanceBestKnownFromPeerBody(true, true, true));
    BOOST_CHECK(!ShouldAdvanceBestKnownFromPeerBody(true, false, false));
    BOOST_CHECK(!ShouldAdvanceBestKnownFromPeerBody(false, false, true));
    using node::matmul_trusted::SignedFrontierVersionHandshakeComplete;
    BOOST_CHECK(!SignedFrontierVersionHandshakeComplete(-1));
    BOOST_CHECK(SignedFrontierVersionHandshakeComplete(0));
    BOOST_CHECK(SignedFrontierVersionHandshakeComplete(190858));
    using node::matmul_trusted::TrustedMirrorPeerIsGpuAuthority;
    BOOST_CHECK(TrustedMirrorPeerIsGpuAuthority(
        /*manual_or_noban=*/true, /*recent_valid_configured_mmattest=*/false));
    BOOST_CHECK(TrustedMirrorPeerIsGpuAuthority(false, true));
    BOOST_CHECK(!TrustedMirrorPeerIsGpuAuthority(false, false));
    using node::matmul_trusted::TrustedMirrorGpuAuthorityHandshakeComplete;
    BOOST_CHECK(TrustedMirrorGpuAuthorityHandshakeComplete(
        /*is_gpu_authority=*/true, /*version_handshake_complete=*/true));
    BOOST_CHECK(!TrustedMirrorGpuAuthorityHandshakeComplete(true, false));
    BOOST_CHECK(!TrustedMirrorGpuAuthorityHandshakeComplete(false, true));
    using node::matmul_trusted::TrustedMirrorIgnoreNonAuthorityInboundBlock;
    BOOST_CHECK(TrustedMirrorIgnoreNonAuthorityInboundBlock(
        /*trusted_mirror=*/true, /*this_peer_is_gpu_authority=*/false,
        /*authority_only_inbound=*/true));
    BOOST_CHECK(!TrustedMirrorIgnoreNonAuthorityInboundBlock(true, true, true));
    BOOST_CHECK(!TrustedMirrorIgnoreNonAuthorityInboundBlock(true, false, false));
    BOOST_CHECK(!TrustedMirrorIgnoreNonAuthorityInboundBlock(false, false, true));
    BOOST_CHECK(!TrustedMirrorIgnoreNonAuthorityInboundBlock(
        true, false, true, /*this_inbound=*/false));
    BOOST_CHECK(TrustedMirrorIgnoreNonAuthorityInboundBlock(
        true, false, true, /*this_inbound=*/true));
    using node::matmul_trusted::WeakSubjectivityBootstrapHeight;
    using node::matmul_trusted::TrustedMirrorIgnoreNonAuthorityInboundHeaders;
    using node::matmul_trusted::TrustedMirrorSeedRaisesBestKnown;
    // Mainnet: checkpoint 201500, AssumeUTXO 201500 → ceiling 201500.
    BOOST_CHECK_EQUAL(WeakSubjectivityBootstrapHeight(186000, 199299), 199299);
    BOOST_CHECK_EQUAL(WeakSubjectivityBootstrapHeight(186000, 0), 186000);
    BOOST_CHECK_EQUAL(WeakSubjectivityBootstrapHeight(0, 61010), 61010);
    BOOST_CHECK_EQUAL(
        WeakSubjectivityBootstrapHeight(
            Params().Checkpoints().GetHeight(),
            Params().HighestAssumeutxoHeight()),
        201500);
    // Fresh mirror tip=0 must ingest HEADERS (the 2026-08-26 deadlock).
    BOOST_CHECK(!TrustedMirrorIgnoreNonAuthorityInboundHeaders(
        /*ignore_non_authority_block=*/true, /*tip_height=*/0,
        /*weak_subjectivity_bootstrap_height=*/199299));
    BOOST_CHECK(!TrustedMirrorIgnoreNonAuthorityInboundHeaders(
        true, /*tip_height=*/-1, 199299));
    BOOST_CHECK(!TrustedMirrorIgnoreNonAuthorityInboundHeaders(
        true, /*tip_height=*/199298, 199299));
    BOOST_CHECK(TrustedMirrorIgnoreNonAuthorityInboundHeaders(
        true, /*tip_height=*/199299, 199299));
    BOOST_CHECK(TrustedMirrorIgnoreNonAuthorityInboundHeaders(
        true, /*tip_height=*/199300, 199299));
    BOOST_CHECK(!TrustedMirrorIgnoreNonAuthorityInboundHeaders(
        /*ignore_non_authority_block=*/false, /*tip_height=*/0, 199299));
    BOOST_CHECK(!TrustedMirrorIgnoreNonAuthorityInboundHeaders(
        false, /*tip_height=*/199300, 199299));
    // Null BestKnown may be filled; a higher peer BestKnown must not be
    // pinned down to the local signed-frontier seed.
    BOOST_CHECK(TrustedMirrorSeedRaisesBestKnown(
        /*have_current_best_known=*/false, /*current_best_known_height=*/-1,
        /*seed_height=*/2000));
    BOOST_CHECK(!TrustedMirrorSeedRaisesBestKnown(
        /*have_current_best_known=*/true, /*current_best_known_height=*/199300,
        /*seed_height=*/2000));
    BOOST_CHECK(TrustedMirrorSeedRaisesBestKnown(true, /*current=*/100, 2000));
    BOOST_CHECK(!TrustedMirrorSeedRaisesBestKnown(true, /*current=*/2000, 2000));
    using node::matmul_trusted::MayServeGetHeaders;
    BOOST_CHECK(MayServeGetHeaders(
        /*download_permission=*/true, /*tip_has_quorum=*/false,
        /*chain_work_meets_minimum=*/false));
    BOOST_CHECK(MayServeGetHeaders(false, /*tip_has_quorum=*/true, false));
    BOOST_CHECK(MayServeGetHeaders(false, false, /*chain_work_meets_minimum=*/true));
    BOOST_CHECK(!MayServeGetHeaders(false, false, false));
    using node::matmul_trusted::TrustedMirrorShouldRequestAuthorityHeaders;
    BOOST_CHECK(TrustedMirrorShouldRequestAuthorityHeaders(
        /*gpu_authority=*/false, /*tip_height=*/191690, /*target_height=*/191713));
    BOOST_CHECK(!TrustedMirrorShouldRequestAuthorityHeaders(false, 191713, 191713));
    BOOST_CHECK(TrustedMirrorShouldRequestAuthorityHeaders(
        /*gpu_authority=*/true, 191713, 191713));
    BOOST_CHECK(TrustedMirrorShouldRequestAuthorityHeaders(true, 191713, 191690));
    using node::matmul_trusted::TrustedMirrorAuthorityHeadersFollowBest;
    BOOST_CHECK(TrustedMirrorAuthorityHeadersFollowBest(
        /*tip_height=*/0, /*best_height=*/2076, /*best_extends_tip=*/true));
    BOOST_CHECK(!TrustedMirrorAuthorityHeadersFollowBest(0, 0, true));
    BOOST_CHECK(!TrustedMirrorAuthorityHeadersFollowBest(
        199297, 199309, /*best_extends_tip=*/false));
    using node::matmul_trusted::TrustedMirrorMayAcceptPeerBlockBody;
    BOOST_CHECK(TrustedMirrorMayAcceptPeerBlockBody(
        /*this_gpu=*/true, /*this_inbound=*/true, /*this_archive_or_mirror=*/false));
    BOOST_CHECK(TrustedMirrorMayAcceptPeerBlockBody(true, false, false));
    BOOST_CHECK(TrustedMirrorMayAcceptPeerBlockBody(
        false, /*this_inbound=*/false, /*this_archive_or_mirror=*/true));
    BOOST_CHECK(!TrustedMirrorMayAcceptPeerBlockBody(
        false, /*this_inbound=*/true, /*this_archive_or_mirror=*/true));
    BOOST_CHECK(!TrustedMirrorMayAcceptPeerBlockBody(false, true, false));
    BOOST_CHECK(!TrustedMirrorMayAcceptPeerBlockBody(false, false, false));
    using node::matmul_trusted::AuthorityMayIngestInboundMinerAnnouncement;
    BOOST_CHECK(AuthorityMayIngestInboundMinerAnnouncement(
        /*authority_node=*/true, /*inbound=*/true, /*discovery_only=*/false,
        /*addr_fetch=*/false, /*announce_msg=*/true));
    BOOST_CHECK(AuthorityMayIngestInboundMinerAnnouncement(
        true, /*inbound=*/false, false, false, true));
    BOOST_CHECK(!AuthorityMayIngestInboundMinerAnnouncement(
        true, true, /*discovery_only=*/true, false, true));
    BOOST_CHECK(!AuthorityMayIngestInboundMinerAnnouncement(
        true, true, false, /*addr_fetch=*/true, true));
    BOOST_CHECK(!AuthorityMayIngestInboundMinerAnnouncement(
        true, true, false, false, /*announce_msg=*/false));
    BOOST_CHECK(!AuthorityMayIngestInboundMinerAnnouncement(
        true, true, /*discovery_only=*/true, /*addr_fetch=*/true, true));
    using node::matmul_trusted::AuthorityMayAcceptInboundMinerSolicitedBlock;
    BOOST_CHECK(AuthorityMayAcceptInboundMinerSolicitedBlock(
        true, true, false, false, /*peer_has_block_in_flight=*/true));
    BOOST_CHECK(!AuthorityMayAcceptInboundMinerSolicitedBlock(
        true, true, false, false, /*peer_has_block_in_flight=*/false));
    BOOST_CHECK(!AuthorityMayAcceptInboundMinerSolicitedBlock(
        true, true, /*discovery_only=*/true, false, true));
    BOOST_CHECK(!AuthorityMayAcceptInboundMinerSolicitedBlock(
        true, true, true, /*addr_fetch=*/true, true));
    using node::matmul_trusted::TrustedMirrorRetainLostTwinBodyForSignerFetch;
    BOOST_CHECK(TrustedMirrorRetainLostTwinBodyForSignerFetch(
        true, /*has_quorum=*/false, /*lost_twin_or_unique_tip_child=*/true));
    BOOST_CHECK(!TrustedMirrorRetainLostTwinBodyForSignerFetch(
        true, /*has_quorum=*/true, true));
    BOOST_CHECK(!TrustedMirrorRetainLostTwinBodyForSignerFetch(
        true, false, /*lost_twin_or_unique_tip_child=*/false));
    BOOST_CHECK(!TrustedMirrorRetainLostTwinBodyForSignerFetch(
        /*trusted_mirror=*/false, false, true));
    using node::matmul_trusted::DivergentPowForkShouldWarn;
    BOOST_CHECK(DivergentPowForkShouldWarn(
        /*stall_recovery_configured=*/true, /*stall_recovery_height=*/199299,
        /*header_height=*/199303, "bad-diffbits"));
    BOOST_CHECK(!DivergentPowForkShouldWarn(true, 199299, 199298, "bad-diffbits"));
    BOOST_CHECK(!DivergentPowForkShouldWarn(false, 199299, 199303, "bad-diffbits"));
    BOOST_CHECK(!DivergentPowForkShouldWarn(true, 199299, 199303, "bad-prevblk"));
    using node::matmul_trusted::TrustedMirrorMayServeNonAuthorityGetData;
    BOOST_CHECK(TrustedMirrorMayServeNonAuthorityGetData(
        /*this_peer_is_gpu_authority=*/true, /*catching_up_behind_frontier=*/true));
    BOOST_CHECK(TrustedMirrorMayServeNonAuthorityGetData(true, false));
    BOOST_CHECK(!TrustedMirrorMayServeNonAuthorityGetData(false, true));
    BOOST_CHECK(TrustedMirrorMayServeNonAuthorityGetData(false, false));
    BOOST_CHECK(TrustedMirrorMayServeNonAuthorityGetData(
        /*this_peer_is_gpu_authority=*/false, /*catching_up_behind_frontier=*/true,
        /*this_archive_or_mirror=*/true));
    BOOST_CHECK(TrustedMirrorMayServeNonAuthorityGetData(false, true, true));
    using node::matmul_trusted::TrustedMirrorGpuMayServeBlocks;
    BOOST_CHECK(TrustedMirrorGpuMayServeBlocks(
        /*gpu_authority=*/true, /*has_network_service=*/false));
    BOOST_CHECK(TrustedMirrorGpuMayServeBlocks(true, true));
    BOOST_CHECK(!TrustedMirrorGpuMayServeBlocks(false, false));
    BOOST_CHECK(TrustedMirrorGpuMayServeBlocks(false, true));
    BOOST_CHECK(!TrustedMirrorGpuMayServeBlocks(
        /*gpu_authority=*/true, /*has_network_service=*/false,
        /*version_handshake_complete=*/false));
    using node::matmul_trusted::TrustedMirrorKeepFetchingCoveredUnconnected;
    BOOST_CHECK(TrustedMirrorKeepFetchingCoveredUnconnected(
        /*signed_frontier_catch_up=*/true,
        /*unconnected_has_gpu_attestation=*/true));
    BOOST_CHECK(!TrustedMirrorKeepFetchingCoveredUnconnected(true, false));
    BOOST_CHECK(!TrustedMirrorKeepFetchingCoveredUnconnected(false, true));
    using node::matmul_trusted::IsNarrowCatchUpWindowForPolicy;
    BOOST_CHECK(IsNarrowCatchUpWindowForPolicy(
        /*ibd=*/false, /*ahead=*/45, /*signed_frontier_catch_up=*/true));
    BOOST_CHECK(IsNarrowCatchUpWindowForPolicy(false, 10, false));
    BOOST_CHECK(!IsNarrowCatchUpWindowForPolicy(/*ibd=*/true, 10, false));
    using node::matmul_trusted::SignedFrontierPreferredCatchUpTimeout;
    BOOST_CHECK_EQUAL(
        SignedFrontierPreferredCatchUpTimeout(std::chrono::milliseconds{60000}).count(),
        90);
    BOOST_CHECK_EQUAL(
        SignedFrontierPreferredCatchUpTimeout(std::chrono::milliseconds{50}).count(),
        15);
    using node::matmul_trusted::SignedFrontierCatchUpUsesGpuTimeout;
    BOOST_CHECK(SignedFrontierCatchUpUsesGpuTimeout(
        /*manual_or_noban=*/true, /*version_handshake_complete=*/true));
    BOOST_CHECK(!SignedFrontierCatchUpUsesGpuTimeout(true, false));
    BOOST_CHECK(!SignedFrontierCatchUpUsesGpuTimeout(false, true));
    BOOST_CHECK(!SignedFrontierCatchUpUsesGpuTimeout(
        true, true, /*starting_height=*/194111, /*active_tip_height=*/194121));
    BOOST_CHECK(SignedFrontierCatchUpUsesGpuTimeout(
        true, true, /*starting_height=*/194111, /*active_tip_height=*/189534));
    using node::matmul_trusted::KeepGpuSignedFrontierInFlightPipeline;
    BOOST_CHECK(KeepGpuSignedFrontierInFlightPipeline(
        /*signed_frontier_catch_up=*/true, /*manual_or_noban=*/true,
        /*version_handshake_complete=*/true));
    BOOST_CHECK(!KeepGpuSignedFrontierInFlightPipeline(true, true, false));
    BOOST_CHECK(!KeepGpuSignedFrontierInFlightPipeline(true, false, true));
    BOOST_CHECK(!KeepGpuSignedFrontierInFlightPipeline(false, true, true));
    using node::matmul_trusted::TrustedMirrorGpuHandshakeTimeout;
    BOOST_CHECK_EQUAL(
        TrustedMirrorGpuHandshakeTimeout(std::chrono::seconds{60}, false).count(),
        60);
    BOOST_CHECK_EQUAL(
        TrustedMirrorGpuHandshakeTimeout(std::chrono::seconds{60}, true).count(),
        180);
    BOOST_CHECK_EQUAL(
        TrustedMirrorGpuHandshakeTimeout(std::chrono::seconds{300}, true).count(),
        300);
    BOOST_CHECK_EQUAL(
        TrustedMirrorGpuHandshakeTimeout(std::chrono::seconds{60}, false,
                                         /*handshake_incomplete=*/true).count(),
        180);
    BOOST_CHECK_EQUAL(
        TrustedMirrorGpuHandshakeTimeout(std::chrono::seconds{60}, false,
                                         /*handshake_incomplete=*/false).count(),
        60);
    BOOST_CHECK_EQUAL(
        TrustedMirrorGpuHandshakeTimeout(std::chrono::seconds{60}, true,
                                         /*handshake_incomplete=*/true,
                                         /*never_received=*/true).count(),
        15);
    BOOST_CHECK_EQUAL(
        TrustedMirrorGpuHandshakeTimeout(std::chrono::seconds{60}, true,
                                         /*handshake_incomplete=*/true,
                                         /*never_received=*/false).count(),
        180);
    using node::matmul_trusted::ClassifyMsghandPeer;
    using node::matmul_trusted::MsghandPeerClass;
    BOOST_CHECK(ClassifyMsghandPeer(false, false) == MsghandPeerClass::Handshake);
    BOOST_CHECK(ClassifyMsghandPeer(false, true) == MsghandPeerClass::Handshake);
    BOOST_CHECK(ClassifyMsghandPeer(true, true) == MsghandPeerClass::Preferred);
    BOOST_CHECK(ClassifyMsghandPeer(true, false) == MsghandPeerClass::Other);
    BOOST_CHECK(ClassifyMsghandPeer(true, false, /*pending_block_serve=*/true) ==
                MsghandPeerClass::Preferred);
    BOOST_CHECK(ClassifyMsghandPeer(true, false, false) == MsghandPeerClass::Other);
    using node::matmul_trusted::MsghandPreferLiveGetData;
    BOOST_CHECK(MsghandPreferLiveGetData(/*queued_getdata=*/true, false));
    BOOST_CHECK(MsghandPreferLiveGetData(false, /*inflight_getdata_requests=*/true));
    BOOST_CHECK(!MsghandPreferLiveGetData(false, false));
    using node::matmul_trusted::TrustedSignerDropMinerIngestWhileGetData;
    BOOST_CHECK(TrustedSignerDropMinerIngestWhileGetData(
        /*local_signer=*/true, /*getdata_pending=*/true,
        /*this_inbound=*/true, /*this_manual=*/false,
        /*this_is_archive_serve_target=*/false));
    BOOST_CHECK(!TrustedSignerDropMinerIngestWhileGetData(
        true, true, true, false, /*this_is_archive_serve_target=*/true));
    BOOST_CHECK(TrustedSignerDropMinerIngestWhileGetData(
        true, /*getdata_pending=*/false, true, false, false));
    // Outbound / manual miners must also drop ingest while archives fetch.
    BOOST_CHECK(TrustedSignerDropMinerIngestWhileGetData(
        true, true, /*this_inbound=*/false, /*this_manual=*/false, false));
    BOOST_CHECK(TrustedSignerDropMinerIngestWhileGetData(
        true, true, false, /*this_manual=*/true, false));
    using node::matmul_trusted::MsghandPeerIsArchiveServeTarget;
    BOOST_CHECK(!MsghandPeerIsArchiveServeTarget(/*manual_or_outbound=*/true, false));
    BOOST_CHECK(MsghandPeerIsArchiveServeTarget(true, /*archive_or_mirror_service=*/true));
    BOOST_CHECK(MsghandPeerIsArchiveServeTarget(false, /*archive_or_mirror_service=*/true));
    BOOST_CHECK(!MsghandPeerIsArchiveServeTarget(false, false));
    using node::matmul_trusted::MsghandPreferArchiveLiveGetData;
    BOOST_CHECK(MsghandPreferArchiveLiveGetData(/*live_getdata=*/true, /*is_archive_serve_target=*/true));
    BOOST_CHECK(!MsghandPreferArchiveLiveGetData(true, /*is_archive_serve_target=*/false));
    BOOST_CHECK(!MsghandPreferArchiveLiveGetData(false, true));
    using node::matmul_trusted::PreferredPeerHandshakePending;
    BOOST_CHECK(PreferredPeerHandshakePending(
        /*handshake_complete=*/false, /*manual_or_outbound=*/true,
        /*local_signer=*/false));
    BOOST_CHECK(PreferredPeerHandshakePending(false, false, true));
    BOOST_CHECK(!PreferredPeerHandshakePending(false, false, false));
    BOOST_CHECK(!PreferredPeerHandshakePending(true, true, true));
    using node::matmul_trusted::SkipFullyConnectedInboundDuringPreferredHandshake;
    BOOST_CHECK(SkipFullyConnectedInboundDuringPreferredHandshake(
        /*preferred_handshake_pending=*/true, /*this_peer_inbound=*/true,
        /*this_peer_handshake_complete=*/true, /*this_peer_manual=*/false));
    BOOST_CHECK(!SkipFullyConnectedInboundDuringPreferredHandshake(
        true, true, /*this_peer_handshake_complete=*/false, false));
    BOOST_CHECK(!SkipFullyConnectedInboundDuringPreferredHandshake(
        true, false, true, false));
    BOOST_CHECK(!SkipFullyConnectedInboundDuringPreferredHandshake(
        false, true, true, false));
    BOOST_CHECK(!SkipFullyConnectedInboundDuringPreferredHandshake(
        true, true, true, false, /*this_peer_needs_serve=*/true));
    using node::matmul_trusted::SkipMinerProcessMessagesDuringArchiveGetData;
    BOOST_CHECK(SkipMinerProcessMessagesDuringArchiveGetData(
        /*local_signer=*/true, /*archive_getdata_pending=*/true,
        /*trusted_mirror_catch_up=*/false,
        /*this_peer_inbound=*/true, /*this_peer_manual=*/false,
        /*this_peer_handshake_complete=*/true,
        /*this_is_archive_serve_target=*/false));
    // Miner GETDATA must still be skipped (live 45s/block hole).
    BOOST_CHECK(SkipMinerProcessMessagesDuringArchiveGetData(
        true, true, false, true, false, true,
        /*this_is_archive_serve_target=*/false));
    BOOST_CHECK(!SkipMinerProcessMessagesDuringArchiveGetData(
        true, true, false, true, false, true,
        /*this_is_archive_serve_target=*/true));
    BOOST_CHECK(!SkipMinerProcessMessagesDuringArchiveGetData(
        true, true, false, true, false,
        /*this_peer_handshake_complete=*/false, false));
    BOOST_CHECK(!SkipMinerProcessMessagesDuringArchiveGetData(
        /*local_signer=*/false, true, /*trusted_mirror_catch_up=*/false,
        true, false, true, false));
    BOOST_CHECK(SkipMinerProcessMessagesDuringArchiveGetData(
        /*local_signer=*/false, false, /*trusted_mirror_catch_up=*/true,
        true, false, true, false));
    // A signer with NO archive GETDATA pending must NOT skip: the
    // unconditional form starved every non-ARCHIVE/MIRROR peer of all
    // message processing (0 header bytes served to consensus peers,
    // measured live 2026-08-27).
    BOOST_CHECK(!SkipMinerProcessMessagesDuringArchiveGetData(
        true, /*archive_getdata_pending=*/false, false, true, false, true,
        false));
    // Outbound miners are Preferred in msghand order; they must still skip.
    BOOST_CHECK(SkipMinerProcessMessagesDuringArchiveGetData(
        true, true, false, /*this_peer_inbound=*/false, false, true, false));
    BOOST_CHECK(SkipMinerProcessMessagesDuringArchiveGetData(
        true, true, false, false, /*this_peer_manual=*/true, true, false));
    using node::matmul_trusted::KeepCatchupSourceOnDownloadTimeout;
    BOOST_CHECK(KeepCatchupSourceOnDownloadTimeout(
        /*signed_frontier_catch_up=*/true, /*persistent_timeout=*/false,
        /*last_gpu_or_frontier_source=*/false));
    BOOST_CHECK(!KeepCatchupSourceOnDownloadTimeout(true, true, false));
    BOOST_CHECK(KeepCatchupSourceOnDownloadTimeout(true, true, true));
    BOOST_CHECK(KeepCatchupSourceOnDownloadTimeout(false, true, true));
    BOOST_CHECK(!KeepCatchupSourceOnDownloadTimeout(false, true, false));
    using node::matmul_trusted::CatchUpNeverPunishSlowDelivery;
    using node::matmul_trusted::CatchUpMayPauseOnSlowDelivery;
    using node::matmul_trusted::CatchUpMayDisconnectOnSlowDelivery;
    using node::matmul_trusted::CatchUpInFlightExpireDeadline;
    BOOST_CHECK(!CatchUpNeverPunishSlowDelivery(/*far_behind=*/false));
    BOOST_CHECK(CatchUpNeverPunishSlowDelivery(/*far_behind=*/true));
    BOOST_CHECK(!CatchUpMayPauseOnSlowDelivery(
        /*far_behind=*/true, /*keep_catchup_source=*/false,
        /*last_gpu_or_frontier_source=*/false));
    BOOST_CHECK(CatchUpMayPauseOnSlowDelivery(false, false, false));
    BOOST_CHECK(!CatchUpMayPauseOnSlowDelivery(false, true, true));
    BOOST_CHECK(CatchUpMayPauseOnSlowDelivery(false, true, false));
    BOOST_CHECK(!CatchUpMayPauseOnSlowDelivery(
        false, false, false, /*peers_downloading_before=*/1));
    BOOST_CHECK(!CatchUpMayDisconnectOnSlowDelivery(
        /*far_behind=*/true, /*persistent=*/true, /*manual_or_noban=*/false,
        /*keep_catchup_source=*/false, /*only_eligible_source=*/false));
    BOOST_CHECK(CatchUpMayDisconnectOnSlowDelivery(
        false, true, false, false, false));
    BOOST_CHECK(!CatchUpMayDisconnectOnSlowDelivery(
        false, true, false, false, /*only_eligible_source=*/true));
    BOOST_CHECK(!CatchUpMayDisconnectOnSlowDelivery(
        false, true, /*manual_or_noban=*/true, false, false));
    {
        const auto spacing{std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::seconds{90})};
        const auto clamp{std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::seconds{15})};
        BOOST_CHECK_EQUAL(
            CatchUpInFlightExpireDeadline(false, spacing, clamp, false).count(),
            spacing.count());
        BOOST_CHECK_EQUAL(
            CatchUpInFlightExpireDeadline(false, spacing, clamp, true).count(),
            clamp.count());
        BOOST_CHECK_EQUAL(
            CatchUpInFlightExpireDeadline(true, spacing, clamp, true).count(),
            std::chrono::microseconds{
                node::matmul_trusted::CATCHUP_PEER_SILENCE_TIMEOUT}
                .count());
    }
    using node::matmul_trusted::SkipExactReplayForGpuAttestation;
    using node::matmul_trusted::HistoricalExactReplayCoveredByPinQuorum;
    using node::matmul_trusted::SignAuthoritativeServesGetMmAttest;
    using node::matmul_trusted::TrustedMirrorPinSteersForkChoice;
    using node::matmul_trusted::MatMulAttestedMiningParentRequired;
    using node::matmul_trusted::PinSteersFindUniqueCompetingAttestedIndex;
    using node::matmul_trusted::MmAttestRefuteKnownProfile1Block;
    // 2x2: skip iff trusted mirror AND pin quorum covers the hash.
    BOOST_CHECK(!SkipExactReplayForGpuAttestation(
        /*has_valid_gpu_attestation=*/false, /*trusted_mirror=*/false));
    BOOST_CHECK(!SkipExactReplayForGpuAttestation(true, /*trusted_mirror=*/false));
    BOOST_CHECK(!SkipExactReplayForGpuAttestation(false, /*trusted_mirror=*/true));
    BOOST_CHECK(SkipExactReplayForGpuAttestation(true, /*trusted_mirror=*/true));
    // Serve-budget coverage: direct pin quorum on any role; frontier
    // ancestry only on trusted mirrors. Consensus + ancestry MUST regen.
    BOOST_CHECK(!HistoricalExactReplayCoveredByPinQuorum(
        /*trusted_mirror=*/true, /*direct_quorum=*/false, /*frontier_covers=*/false));
    BOOST_CHECK(HistoricalExactReplayCoveredByPinQuorum(true, true, false));
    BOOST_CHECK(HistoricalExactReplayCoveredByPinQuorum(true, false, true));
    BOOST_CHECK(HistoricalExactReplayCoveredByPinQuorum(false, true, false));
    BOOST_CHECK(!HistoricalExactReplayCoveredByPinQuorum(false, false, true));
    BOOST_CHECK(!HistoricalExactReplayCoveredByPinQuorum(false, false, false));
    BOOST_CHECK(!SkipExactReplayForGpuAttestation(true, false));
    BOOST_CHECK(SignAuthoritativeServesGetMmAttest(AddResult::Accepted));
    BOOST_CHECK(SignAuthoritativeServesGetMmAttest(AddResult::Duplicate));
    BOOST_CHECK(SignAuthoritativeServesGetMmAttest(AddResult::Heard));
    BOOST_CHECK(!SignAuthoritativeServesGetMmAttest(AddResult::HeightOccupied));
    BOOST_CHECK(!SignAuthoritativeServesGetMmAttest(AddResult::NoLocalSigner));
    BOOST_CHECK(TrustedMirrorPinSteersForkChoice(/*trusted_mirror=*/true));
    BOOST_CHECK(!TrustedMirrorPinSteersForkChoice(false));
    BOOST_CHECK(MatMulAttestedMiningParentRequired(
        /*trusted_mirror=*/true, /*configured=*/true));
    BOOST_CHECK(!MatMulAttestedMiningParentRequired(true, false));
    BOOST_CHECK(!MatMulAttestedMiningParentRequired(false, true));
    BOOST_CHECK(!MatMulAttestedMiningParentRequired(false, false));
    BOOST_CHECK(!PinSteersFindUniqueCompetingAttestedIndex(
        /*trusted_mirror=*/false, /*has_local_signer=*/false));
    BOOST_CHECK(PinSteersFindUniqueCompetingAttestedIndex(false, true));
    BOOST_CHECK(PinSteersFindUniqueCompetingAttestedIndex(true, false));
    BOOST_CHECK(PinSteersFindUniqueCompetingAttestedIndex(true, true));
    BOOST_CHECK(!MmAttestRefuteKnownProfile1Block(
        /*have_index=*/false, /*failed=*/false, /*profile1_active=*/true,
        /*height_matches=*/true));
    BOOST_CHECK(!MmAttestRefuteKnownProfile1Block(true, /*failed=*/true, true, true));
    BOOST_CHECK(!MmAttestRefuteKnownProfile1Block(true, false, /*profile1_active=*/false, true));
    BOOST_CHECK(!MmAttestRefuteKnownProfile1Block(true, false, true, /*height_matches=*/false));
    BOOST_CHECK(MmAttestRefuteKnownProfile1Block(true, false, true, true));
    using node::matmul_trusted::MayPersistTrustedReplayAttestationBit;
    BOOST_CHECK(!MayPersistTrustedReplayAttestationBit(
        /*trusted_mirror=*/false, /*pin_covers_this_hash=*/true));
    BOOST_CHECK(!MayPersistTrustedReplayAttestationBit(true, /*pin_covers_this_hash=*/false));
    BOOST_CHECK(!MayPersistTrustedReplayAttestationBit(false, false));
    BOOST_CHECK(MayPersistTrustedReplayAttestationBit(true, true));
    using node::matmul_trusted::PinMayVetoUnattestedTipChildGpu;
    using node::matmul_trusted::ConsensusMayClaimUnattestedTipChildBody;
    using node::matmul_trusted::TrustedMirrorMayClaimUnattestedTipChildBody;
    using node::matmul_trusted::GetMmAttestIsConnectTipValidityGate;
    using node::matmul_trusted::ArchiveServiceBitIsValidityRequirement;
    using node::matmul_trusted::UnconnectedHaveDataMayKickAbc;
    using node::matmul_trusted::KeepFetchingWhileUnconnectedHaveData;
    // Gold standard: archives/pin are not GPU-admission or ConnectTip
    // oracles for consensus miners.
    BOOST_CHECK(!PinMayVetoUnattestedTipChildGpu(/*trusted_mirror=*/false));
    BOOST_CHECK(PinMayVetoUnattestedTipChildGpu(true));
    BOOST_CHECK(!GetMmAttestIsConnectTipValidityGate(false));
    BOOST_CHECK(GetMmAttestIsConnectTipValidityGate(true));
    BOOST_CHECK(!ArchiveServiceBitIsValidityRequirement());
    BOOST_CHECK(ConsensusMayClaimUnattestedTipChildBody(
        /*pprev_is_tip=*/true, /*failed=*/false,
        /*already_claimed_other_hash=*/false, /*progress_child=*/false,
        /*sibling_already_has_body=*/false));
    // Competing pin quorum is not an argument: unique unattested child
    // still ExactReplays when archives signed a sibling.
    BOOST_CHECK(ConsensusMayClaimUnattestedTipChildBody(
        true, false, false, false, false));
    BOOST_CHECK(!ConsensusMayClaimUnattestedTipChildBody(
        true, false, /*already_claimed_other_hash=*/true,
        /*progress_child=*/false, false));
    BOOST_CHECK(ConsensusMayClaimUnattestedTipChildBody(
        true, false, true, /*progress_child=*/true, false));
    BOOST_CHECK(!ConsensusMayClaimUnattestedTipChildBody(
        true, false, false, false, /*sibling_already_has_body=*/true));
    BOOST_CHECK(!ConsensusMayClaimUnattestedTipChildBody(
        /*pprev_is_tip=*/false, false, false, false, false));
    BOOST_CHECK(!TrustedMirrorMayClaimUnattestedTipChildBody(
        true, false, /*competing_quorum=*/true, false,
        /*attested_height_exists=*/false, true, false, false));
    BOOST_CHECK(!TrustedMirrorMayClaimUnattestedTipChildBody(
        true, false, false, false, /*attested_height_exists=*/true,
        /*tip_on_attested_chain=*/false, false, false));
    BOOST_CHECK(TrustedMirrorMayClaimUnattestedTipChildBody(
        true, false, false, false, false, true, false, false));
    BOOST_CHECK(UnconnectedHaveDataMayKickAbc(
        /*trusted_mirror=*/false, /*pin_quorum=*/false, /*exact=*/false));
    BOOST_CHECK(UnconnectedHaveDataMayKickAbc(false, false, true));
    BOOST_CHECK(!UnconnectedHaveDataMayKickAbc(
        /*trusted_mirror=*/true, /*pin_quorum=*/false, /*exact=*/true));
    BOOST_CHECK(UnconnectedHaveDataMayKickAbc(true, true, false));
    BOOST_CHECK(!KeepFetchingWhileUnconnectedHaveData(
        false, false, false, /*exact=*/false));
    BOOST_CHECK(KeepFetchingWhileUnconnectedHaveData(
        false, false, false, /*exact=*/true));
    BOOST_CHECK(!KeepFetchingWhileUnconnectedHaveData(
        true, /*catch_up=*/true, /*pin=*/false, /*exact=*/true));
    BOOST_CHECK(KeepFetchingWhileUnconnectedHaveData(true, true, true, false));
    using node::matmul_trusted::PinMayDenyAttestedChainTipChild;
    using node::matmul_trusted::ConsensusMinerMayFetchCompetingShortReorg;
    BOOST_CHECK(!PinMayDenyAttestedChainTipChild(
        /*trusted_mirror=*/false, /*has_local_signer=*/false));
    BOOST_CHECK(PinMayDenyAttestedChainTipChild(true, false));
    BOOST_CHECK(PinMayDenyAttestedChainTipChild(false, true));
    BOOST_CHECK(ConsensusMinerMayFetchCompetingShortReorg(
        /*trusted_mirror=*/false, /*peer_advertises_consensus=*/true,
        /*short_reorg=*/true, /*peer_work_ge_tip=*/true));
    BOOST_CHECK(!ConsensusMinerMayFetchCompetingShortReorg(
        true, true, true, true));
    BOOST_CHECK(!ConsensusMinerMayFetchCompetingShortReorg(
        false, /*peer_advertises_consensus=*/false, true, true));
    BOOST_CHECK(!ConsensusMinerMayFetchCompetingShortReorg(
        false, true, /*short_reorg=*/false, true));
    using node::matmul_trusted::ConsensusMinerMayFetchCompetingHeavierFork;
    BOOST_CHECK(ConsensusMinerMayFetchCompetingHeavierFork(
        /*trusted_mirror=*/false, /*extends_tip=*/false,
        /*peer_work_gt_tip=*/true));
    BOOST_CHECK(!ConsensusMinerMayFetchCompetingHeavierFork(
        false, /*extends_tip=*/true, true));
    BOOST_CHECK(!ConsensusMinerMayFetchCompetingHeavierFork(
        false, false, /*peer_work_gt_tip=*/false));
    BOOST_CHECK(!ConsensusMinerMayFetchCompetingHeavierFork(
        /*trusted_mirror=*/true, false, true));
    using node::matmul_trusted::ConsensusMinerMayFollowHeavierDisconnectedHeader;
    BOOST_CHECK(ConsensusMinerMayFollowHeavierDisconnectedHeader(
        /*trusted_mirror=*/false, /*extends_tip=*/false,
        /*failed_or_invalid=*/false, /*parked=*/false,
        /*candidate_work_gt_tip=*/true, /*candidate_height_ge_tip=*/true));
    BOOST_CHECK(ConsensusMinerMayFollowHeavierDisconnectedHeader(
        false, /*extends_tip=*/true, false, false, true, true));
    BOOST_CHECK(!ConsensusMinerMayFollowHeavierDisconnectedHeader(
        /*trusted_mirror=*/true, false, false, false, true, true));
    BOOST_CHECK(!ConsensusMinerMayFollowHeavierDisconnectedHeader(
        false, false, /*failed_or_invalid=*/true, false, true, true));
    BOOST_CHECK(!ConsensusMinerMayFollowHeavierDisconnectedHeader(
        false, false, false, /*parked=*/true, true, true));
    BOOST_CHECK(!ConsensusMinerMayFollowHeavierDisconnectedHeader(
        false, false, false, false, /*candidate_work_gt_tip=*/false, true));
    BOOST_CHECK(!ConsensusMinerMayFollowHeavierDisconnectedHeader(
        false, false, false, false, true, /*candidate_height_ge_tip=*/false));
    using node::matmul_trusted::HeavierCompetingForkHoleMayExactReplay;
    BOOST_CHECK(HeavierCompetingForkHoleMayExactReplay(
        /*may_fetch=*/true, /*is_immediate_fork_child=*/true,
        /*parent_has_data=*/false));
    BOOST_CHECK(HeavierCompetingForkHoleMayExactReplay(true, false, true));
    BOOST_CHECK(!HeavierCompetingForkHoleMayExactReplay(true, false, false));
    BOOST_CHECK(!HeavierCompetingForkHoleMayExactReplay(false, true, true));
    using node::matmul_trusted::HeavierHeaderTowerHoleMayGetData;
    // Fetch is not ExactReplay: extends_tip still GETDATA's the remaining
    // holes. ConsensusMinerMayFetchCompetingHeavierFork(..., extends_tip)
    // stays false so GPU replay does not burst the tower.
    BOOST_CHECK(HeavierHeaderTowerHoleMayGetData(
        /*trusted_mirror=*/false, /*on_active_chain=*/false, /*failed=*/false,
        /*tower_contains_index=*/true, /*tower_work_gt_tip=*/true));
    BOOST_CHECK(!HeavierHeaderTowerHoleMayGetData(
        false, false, false, true, /*tower_work_gt_tip=*/false));
    BOOST_CHECK(!HeavierHeaderTowerHoleMayGetData(
        false, /*on_active_chain=*/true, false, true, true));
    BOOST_CHECK(!HeavierHeaderTowerHoleMayGetData(
        false, false, /*failed=*/true, true, true));
    BOOST_CHECK(!HeavierHeaderTowerHoleMayGetData(
        false, false, false, /*tower_contains_index=*/false, true));
    BOOST_CHECK(!HeavierHeaderTowerHoleMayGetData(
        /*trusted_mirror=*/true, false, false, true, true));
    BOOST_CHECK(!ConsensusMinerMayFetchCompetingHeavierFork(
        false, /*extends_tip=*/true, true));
    BOOST_CHECK(!HeavierCompetingForkHoleMayExactReplay(
        /*may_fetch=*/false, /*is_immediate_fork_child=*/true,
        /*parent_has_data=*/true));
    using node::matmul_trusted::ConsensusMinerMayReorgPastParkForStaleHeavierFork;
    using node::matmul_trusted::ConsensusMinerTipStaleVsDirectFetchWindow;
    BOOST_CHECK(ConsensusMinerMayReorgPastParkForStaleHeavierFork(
        /*trusted_mirror=*/false, /*extends_tip=*/false,
        /*work_gt=*/true, /*tip_stale=*/true));
    BOOST_CHECK(!ConsensusMinerMayReorgPastParkForStaleHeavierFork(
        false, false, true, /*tip_stale=*/false));
    BOOST_CHECK(!ConsensusMinerMayReorgPastParkForStaleHeavierFork(
        false, /*extends_tip=*/true, true, true));
    BOOST_CHECK(!ConsensusMinerMayReorgPastParkForStaleHeavierFork(
        /*trusted_mirror=*/true, false, true, true));
    BOOST_CHECK(!ConsensusMinerMayReorgPastParkForStaleHeavierFork(
        false, false, /*work_gt=*/false, true));
    // Predicate true must not be passed as recovery_escape: park still
    // fires at the measured dump-and-run depths (and at live branchlen 90).
    BOOST_CHECK(kernel::DeepReorgShouldPark(
        kernel::DeepReorgAction::PARK, 6, 8, /*recovery_escape=*/false));
    BOOST_CHECK(kernel::DeepReorgShouldPark(
        kernel::DeepReorgAction::PARK, 6, 151, false));
    BOOST_CHECK(kernel::DeepReorgShouldPark(
        kernel::DeepReorgAction::PARK, 6, 90, false));
    BOOST_CHECK(ConsensusMinerTipStaleVsDirectFetchWindow(
        /*tip_time=*/1000, /*now=*/1000 + 20 * 90, /*spacing=*/90));
    BOOST_CHECK(!ConsensusMinerTipStaleVsDirectFetchWindow(
        1000, 1000 + 20 * 90 - 1, 90));
    using node::matmul_trusted::ExactReplayGpuThrottleRequiresPin;
    using node::matmul_trusted::ExactReplayAdmissionThrottleApplies;
    using node::matmul_trusted::MatMulSpeculativeRcPendingLimit;
    BOOST_CHECK(!ExactReplayGpuThrottleRequiresPin());
    BOOST_CHECK(ExactReplayAdmissionThrottleApplies(
        /*exact_recompute_required=*/true, /*pin_configured=*/false));
    BOOST_CHECK(ExactReplayAdmissionThrottleApplies(true, true));
    BOOST_CHECK(!ExactReplayAdmissionThrottleApplies(false, false));
    BOOST_CHECK(!ExactReplayAdmissionThrottleApplies(false, true));
    BOOST_CHECK_EQUAL(MatMulSpeculativeRcPendingLimit(false), 1u);
    BOOST_CHECK_EQUAL(MatMulSpeculativeRcPendingLimit(true), 1u);
    using node::matmul_trusted::MsghandTreatAsOutboundPreferred;
    BOOST_CHECK(!MsghandTreatAsOutboundPreferred(/*local_signer=*/true, true));
    BOOST_CHECK(MsghandTreatAsOutboundPreferred(false, /*manual_or_outbound=*/true));
    BOOST_CHECK(!MsghandTreatAsOutboundPreferred(false, false));
    using node::matmul_trusted::IsTrustedMirrorMsghandCatchUp;
    BOOST_CHECK(IsTrustedMirrorMsghandCatchUp(true, true, /*blocks_behind=*/0,
                                             /*followed_ahead_uncapped=*/112));
    BOOST_CHECK(IsTrustedMirrorMsghandCatchUp(true, true, 7, 0));
    BOOST_CHECK(!IsTrustedMirrorMsghandCatchUp(true, true, 0, 0));
    BOOST_CHECK(!IsTrustedMirrorMsghandCatchUp(false, true, 0, 112));
    using node::matmul_trusted::TrustedMirrorRetainGpuBodyAwaitingAttestation;
    BOOST_CHECK(TrustedMirrorRetainGpuBodyAwaitingAttestation(
        true, /*from_gpu_attestor=*/true, /*has_quorum=*/false));
    BOOST_CHECK(!TrustedMirrorRetainGpuBodyAwaitingAttestation(
        true, true, /*has_quorum=*/true));
    BOOST_CHECK(!TrustedMirrorRetainGpuBodyAwaitingAttestation(
        true, /*from_gpu_attestor=*/false, false));
    BOOST_CHECK_EQUAL(
        node::matmul_trusted::GPU_RETAIN_ATTESTATION_RETRY.count(), 2);
}

BOOST_AUTO_TEST_CASE(open_heard_does_not_advance_signed_frontier)
{
    RuntimeReset reset;
    node::matmul_trusted::ResetForTest();
    const CKey pin{NewKey()};
    const CKey open{NewKey()};
    matmul::trusted::StoreConfig config;
    config.chain_id = Hex256('1');
    config.replay_authority_context = Hex256('a');
    config.trusted_signers = {pin.GetPubKey()};
    config.threshold = 1;
    config.open_attestors = true;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/false, /*serve=*/false,
        std::chrono::milliseconds{20}, error));
    const uint256 block{Hex256('2')};
    matmul::trusted::ExactReplayStatement statement;
    statement.chain_id = Hex256('1');
    statement.block_hash = block;
    statement.block_height = 88;
    statement.replay_authority_context = Hex256('a');
    const auto heard{matmul::trusted::SignStatement(statement, open)};
    BOOST_REQUIRE(heard);
    BOOST_CHECK(node::matmul_trusted::Add(*heard, block, 88) ==
                matmul::trusted::AddResult::Heard);
    BOOST_CHECK(node::matmul_trusted::Add(*heard, block, 88) ==
                matmul::trusted::AddResult::Heard);
    BOOST_CHECK(!node::matmul_trusted::HighestAttestedHeight().has_value());
    const auto pin_att{matmul::trusted::SignStatement(statement, pin)};
    BOOST_REQUIRE(pin_att);
    BOOST_CHECK(node::matmul_trusted::Add(*pin_att, block, 88) ==
                matmul::trusted::AddResult::Accepted);
    BOOST_REQUIRE(node::matmul_trusted::HighestAttestedHeight().has_value());
    BOOST_CHECK_EQUAL(*node::matmul_trusted::HighestAttestedHeight(), 88);
}

BOOST_AUTO_TEST_CASE(attestor_drift_yield_follows_longer_attested_chain)
{
    using node::matmul_trusted::ATTESTOR_DRIFT_YIELD_DEPTH;
    using node::matmul_trusted::AttestorDriftYieldDepth;
    using node::matmul_trusted::AttestorShouldYieldToPeerAttestedChain;
    using node::matmul_trusted::AttestorShouldYieldToSignedFrontier;
    using node::matmul_trusted::AttestorYieldHashIsCatchUpTarget;
    using node::matmul_trusted::AttestorYieldMustReadmitRetainedBody;
    using node::matmul_trusted::AttestorYieldPreferGetMmAttestPeer;
    using node::matmul_trusted::AttestorYieldShouldRequestGetMmAttest;

    BOOST_CHECK_EQUAL(ATTESTOR_DRIFT_YIELD_DEPTH, 6);
    BOOST_CHECK_EQUAL(AttestorDriftYieldDepth(6), 6);
    BOOST_CHECK_EQUAL(AttestorDriftYieldDepth(12), 12);
    BOOST_CHECK_EQUAL(AttestorDriftYieldDepth(0), ATTESTOR_DRIFT_YIELD_DEPTH);
    BOOST_CHECK_EQUAL(
        AttestorDriftYieldDepth(std::numeric_limits<uint32_t>::max()),
        ATTESTOR_DRIFT_YIELD_DEPTH);

    constexpr int32_t kPark{6};
    // Live 2026-08-20: loser tip 194828, winner BestKnown 194851.
    BOOST_CHECK(AttestorShouldYieldToPeerAttestedChain(
        /*local_signer=*/true, /*peer_is_gpu_attestor=*/true,
        /*local_tip_height=*/194828, /*peer_known_height=*/194851, kPark));
    BOOST_CHECK(!AttestorShouldYieldToPeerAttestedChain(
        true, true, 194828, 194833, kPark));
    BOOST_CHECK(AttestorShouldYieldToPeerAttestedChain(
        true, true, 194828, 194834, kPark));
    BOOST_CHECK(!AttestorShouldYieldToPeerAttestedChain(
        /*local_signer=*/false, true, 194828, 194851, kPark));
    BOOST_CHECK(!AttestorShouldYieldToPeerAttestedChain(
        true, /*peer_is_gpu_attestor=*/false, 194828, 194851, kPark));
    BOOST_CHECK(!AttestorShouldYieldToPeerAttestedChain(
        true, true, /*local_tip_height=*/-1, 194851, kPark));
    BOOST_CHECK(!AttestorShouldYieldToPeerAttestedChain(
        true, true, 194828, /*peer_known_height=*/-1, kPark));
    BOOST_CHECK(!AttestorShouldYieldToPeerAttestedChain(
        true, true, 194828, 194851, /*park_depth=*/0));

    BOOST_CHECK(AttestorShouldYieldToSignedFrontier(
        /*local_signer=*/true, /*blocks_behind=*/23, kPark));
    BOOST_CHECK(!AttestorShouldYieldToSignedFrontier(true, 5, kPark));
    BOOST_CHECK(AttestorShouldYieldToSignedFrontier(true, 6, kPark));
    BOOST_CHECK(!AttestorShouldYieldToSignedFrontier(
        /*local_signer=*/false, 23, kPark));
    BOOST_CHECK(!AttestorShouldYieldToSignedFrontier(true, -1, kPark));

    // Canonical 194829 on the winner chain: catch-up target.
    BOOST_CHECK(AttestorYieldHashIsCatchUpTarget(
        /*yielding=*/true, /*on_winner_or_signed_frontier_chain=*/true,
        /*header_failed=*/false));
    // Competing same-height HEADER_ONLY twin: not a target.
    BOOST_CHECK(!AttestorYieldHashIsCatchUpTarget(true, false, false));
    BOOST_CHECK(!AttestorYieldHashIsCatchUpTarget(
        true, true, /*header_failed=*/true));
    BOOST_CHECK(!AttestorYieldHashIsCatchUpTarget(
        /*yielding=*/false, true, false));

    BOOST_CHECK(AttestorYieldPreferGetMmAttestPeer(
        /*yielding=*/false, /*gpu_attestor=*/false));
    BOOST_CHECK(!AttestorYieldPreferGetMmAttestPeer(true, false));
    BOOST_CHECK(AttestorYieldPreferGetMmAttestPeer(true, true));

    BOOST_CHECK(AttestorYieldShouldRequestGetMmAttest(
        /*yielding=*/false, /*on_winner_or_signed_frontier_chain=*/false));
    BOOST_CHECK(!AttestorYieldShouldRequestGetMmAttest(true, false));
    BOOST_CHECK(AttestorYieldShouldRequestGetMmAttest(true, true));

    BOOST_CHECK(AttestorYieldMustReadmitRetainedBody(
        /*yielding=*/true, /*have_retained_body=*/true,
        /*hash_is_catch_up_target=*/true));
    BOOST_CHECK(!AttestorYieldMustReadmitRetainedBody(false, true, true));
    BOOST_CHECK(!AttestorYieldMustReadmitRetainedBody(true, false, true));
    BOOST_CHECK(!AttestorYieldMustReadmitRetainedBody(true, true, false));
}

BOOST_AUTO_TEST_CASE(signer_getmmattest_historical_and_hammer_ban)
{
    using node::matmul_trusted::AggressiveGetMmAttestShouldBan;
    using node::matmul_trusted::GETMMATTEST_HAMMER_BAN_AFTER;
    using node::matmul_trusted::SIGNER_GETMMATTEST_SERVE_WINDOW;
    using node::matmul_trusted::TrustedSignerMayServeGetMmAttest;

    // Archives serve history. Signers serve only the live window.
    BOOST_CHECK(TrustedSignerMayServeGetMmAttest(
        /*has_local_signer=*/false, /*height=*/187432, /*tip_height=*/190567));
    BOOST_CHECK(TrustedSignerMayServeGetMmAttest(true, 190567, 190567));
    BOOST_CHECK(TrustedSignerMayServeGetMmAttest(
        true, 190567 - SIGNER_GETMMATTEST_SERVE_WINDOW, 190567));
    BOOST_CHECK(TrustedSignerMayServeGetMmAttest(
        true, 190568, 190567)); // catch-up suffix
    BOOST_CHECK(!TrustedSignerMayServeGetMmAttest(
        true, 190567 - SIGNER_GETMMATTEST_SERVE_WINDOW - 1, 190567));
    BOOST_CHECK(!TrustedSignerMayServeGetMmAttest(true, 187432, 190567));
    BOOST_CHECK(!TrustedSignerMayServeGetMmAttest(true, -1, 190567));

    using node::matmul_trusted::GetMmAttestConsumeRequestToken;
    using node::matmul_trusted::GetMmAttestHasRequestToken;
    using node::matmul_trusted::GetMmAttestIsLiveWindow;
    using node::matmul_trusted::GETMMATTEST_HISTORICAL_REQUEST_BURST;
    using node::matmul_trusted::GETMMATTEST_LIVE_REQUEST_BURST;
    BOOST_CHECK(GetMmAttestIsLiveWindow(190567, 190567));
    BOOST_CHECK(GetMmAttestIsLiveWindow(
        190567 - SIGNER_GETMMATTEST_SERVE_WINDOW, 190567));
    BOOST_CHECK(!GetMmAttestIsLiveWindow(
        190567 - SIGNER_GETMMATTEST_SERVE_WINDOW - 1, 190567));
    BOOST_CHECK(GetMmAttestIsLiveWindow(190568, 190567));
    // Archives must classify by height too (not HasLocalSigner==false).
    BOOST_CHECK(!GetMmAttestIsLiveWindow(187432, 190567));

    double live{GETMMATTEST_LIVE_REQUEST_BURST};
    double historical{GETMMATTEST_HISTORICAL_REQUEST_BURST};
    BOOST_CHECK(GetMmAttestHasRequestToken(true, live, historical));
    BOOST_CHECK(GetMmAttestConsumeRequestToken(true, live, historical));
    BOOST_CHECK_EQUAL(live, GETMMATTEST_LIVE_REQUEST_BURST - 1.0);
    BOOST_CHECK_EQUAL(historical, GETMMATTEST_HISTORICAL_REQUEST_BURST);
    for (int i = 0; i < 4; ++i) {
        BOOST_CHECK(GetMmAttestConsumeRequestToken(false, live, historical));
    }
    BOOST_CHECK(!GetMmAttestConsumeRequestToken(false, live, historical));
    BOOST_CHECK(GetMmAttestHasRequestToken(true, live, historical));
    BOOST_CHECK(!GetMmAttestHasRequestToken(false, live, historical));

    using node::matmul_trusted::SIGNER_GETMMATTEST_CACHED_CATCHUP_WINDOW;
    using node::matmul_trusted::TrustedSignerMayServeCachedCatchUpGetMmAttest;
    BOOST_CHECK(TrustedSignerMayServeCachedCatchUpGetMmAttest(
        true, /*requester_is_catchup_peer=*/true, /*on_active_chain=*/true,
        /*height=*/190689, /*tip_height=*/190795));
    BOOST_CHECK(!TrustedSignerMayServeCachedCatchUpGetMmAttest(
        true, /*requester_is_catchup_peer=*/false, /*on_active_chain=*/true,
        190689, 190795));
    BOOST_CHECK(!TrustedSignerMayServeCachedCatchUpGetMmAttest(
        true, true, /*on_active_chain=*/false, 190689, 190795));
    BOOST_CHECK(TrustedSignerMayServeCachedCatchUpGetMmAttest(
        true, false, false, 190795, 190795));
    // Deep historical probes must not drain signer tokens (live 185006 / 190041).
    BOOST_CHECK(!TrustedSignerMayServeCachedCatchUpGetMmAttest(
        true, true, true, 185020, 190801));
    BOOST_CHECK(!TrustedSignerMayServeCachedCatchUpGetMmAttest(
        true, true, true, 190041, 190801));
    BOOST_CHECK(TrustedSignerMayServeCachedCatchUpGetMmAttest(
        true, true, true, 190801 - SIGNER_GETMMATTEST_CACHED_CATCHUP_WINDOW,
        190801));
    BOOST_CHECK(!TrustedSignerMayServeCachedCatchUpGetMmAttest(
        true, true, true,
        190801 - SIGNER_GETMMATTEST_CACHED_CATCHUP_WINDOW - 1, 190801));
    // Live 2026-08-17: a public CPU archive 191593 vs GPU 191713 (120 behind, cache empty).
    BOOST_CHECK(TrustedSignerMayServeCachedCatchUpGetMmAttest(
        true, true, true, 191593, 191713));

    using node::matmul_trusted::TrustedSignerMayRegenerateCatchUpGetMmAttest;
    BOOST_CHECK(TrustedSignerMayRegenerateCatchUpGetMmAttest(
        true, true, true, /*height=*/191593, /*tip_height=*/191713));
    BOOST_CHECK(!TrustedSignerMayRegenerateCatchUpGetMmAttest(
        true, true, true, 191713, 191713)); // live window
    BOOST_CHECK(!TrustedSignerMayRegenerateCatchUpGetMmAttest(
        true, /*requester_is_catchup_peer=*/false, true, 191593, 191713));
    BOOST_CHECK(!TrustedSignerMayRegenerateCatchUpGetMmAttest(
        true, true, /*on_active_chain=*/false, 191593, 191713));
    BOOST_CHECK(!TrustedSignerMayRegenerateCatchUpGetMmAttest(
        /*has_local_signer=*/false, true, true, 191593, 191713));
    // IBD historical probes must not regenerate (token / uplink starvation).
    BOOST_CHECK(!TrustedSignerMayRegenerateCatchUpGetMmAttest(
        true, true, true, 185020, 190801));
    BOOST_CHECK(!TrustedSignerMayRegenerateCatchUpGetMmAttest(
        true, true, true, 190041, 190801));

    using node::matmul_trusted::TrustedArchiveMayServeGetMmAttest;
    BOOST_CHECK(TrustedArchiveMayServeGetMmAttest(
        /*catching_up_behind_frontier=*/false, 187432, 190567));
    BOOST_CHECK(TrustedArchiveMayServeGetMmAttest(true, 190568, 190567));
    BOOST_CHECK(TrustedArchiveMayServeGetMmAttest(
        true, 190567 - SIGNER_GETMMATTEST_SERVE_WINDOW, 190567));
    BOOST_CHECK(!TrustedArchiveMayServeGetMmAttest(true, 189308, 190588));

    BOOST_CHECK(!AggressiveGetMmAttestShouldBan(0));
    BOOST_CHECK(!AggressiveGetMmAttestShouldBan(GETMMATTEST_HAMMER_BAN_AFTER - 1));
    BOOST_CHECK(AggressiveGetMmAttestShouldBan(GETMMATTEST_HAMMER_BAN_AFTER));
    BOOST_CHECK(AggressiveGetMmAttestShouldBan(GETMMATTEST_HAMMER_BAN_AFTER + 8));
}

BOOST_AUTO_TEST_CASE(competing_attested_index_rejects_fossil_depth)
{
    using node::matmul_trusted::TrustedMirrorMayAdoptCompetingAttestedIndex;
    using node::matmul_trusted::TRUSTED_MIRROR_SHORT_REORG_DEPTH;
    BOOST_CHECK(TrustedMirrorMayAdoptCompetingAttestedIndex(
        /*attested_suffix_of_active_tip=*/true, /*lca_depth=*/0));
    BOOST_CHECK(TrustedMirrorMayAdoptCompetingAttestedIndex(false, 1));
    BOOST_CHECK(TrustedMirrorMayAdoptCompetingAttestedIndex(
        false, TRUSTED_MIRROR_SHORT_REORG_DEPTH));
    BOOST_CHECK(!TrustedMirrorMayAdoptCompetingAttestedIndex(
        false, TRUSTED_MIRROR_SHORT_REORG_DEPTH + 1));
    BOOST_CHECK(!TrustedMirrorMayAdoptCompetingAttestedIndex(false, 510));
    BOOST_CHECK(!TrustedMirrorMayAdoptCompetingAttestedIndex(false, 0));
    // Signed-frontier chain (live archives 2026-08-16): depth 7+ is not a
    // fossil when the candidate is the current attested tower.
    BOOST_CHECK(TrustedMirrorMayAdoptCompetingAttestedIndex(
        false, TRUSTED_MIRROR_SHORT_REORG_DEPTH + 1,
        /*on_signed_frontier_chain=*/true));
    BOOST_CHECK(TrustedMirrorMayAdoptCompetingAttestedIndex(
        false, 180, /*on_signed_frontier_chain=*/true));
    BOOST_CHECK(!TrustedMirrorMayAdoptCompetingAttestedIndex(
        false, 180, /*on_signed_frontier_chain=*/false));
    using node::matmul_trusted::ConsensusSignerMayAbandonQuorumTipForSignedFrontier;
    // Same-height dual-quorum twin: keep 190354 (do not flip-flop).
    BOOST_CHECK(!ConsensusSignerMayAbandonQuorumTipForSignedFrontier(
        /*unique_on_signed_frontier_chain=*/true, /*unique_height=*/191323,
        /*tip_height=*/191323));
    BOOST_CHECK(!ConsensusSignerMayAbandonQuorumTipForSignedFrontier(
        false, 191338, 191323));
    // Signed frontier pulled ahead on the competing fork (live 2026-08-17
    // miner: self-mined losing twin 191323, frontier 191338+).
    BOOST_CHECK(ConsensusSignerMayAbandonQuorumTipForSignedFrontier(
        true, 191338, 191323));
    BOOST_CHECK(ConsensusSignerMayAbandonQuorumTipForSignedFrontier(
        true, 191365, 191323));
    using node::matmul_trusted::IndependentConsensusMaySpendExactReplayGpu;
    constexpr int32_t kNearTip{3};
    // Historical / pull-ahead helper: unattested pprev==tip stays off this
    // path so a twin burst cannot occupy every slot. Unique tip-child
    // ExactReplay is ConsensusMayClaimUnattestedTipChildBody, which pin
    // quorum must not veto.
    BOOST_CHECK(!IndependentConsensusMaySpendExactReplayGpu(
        /*pprev_is_tip=*/true, /*on_or_extends_active_tip=*/false, 101, 100,
        kNearTip, /*covered_by_attestation=*/false));
    BOOST_CHECK(IndependentConsensusMaySpendExactReplayGpu(
        true, false, 101, 100, kNearTip, /*covered_by_attestation=*/true));
    // Already-canonical near-tip hole: still on-device for IBD.
    BOOST_CHECK(IndependentConsensusMaySpendExactReplayGpu(
        false, /*on_or_extends_active_tip=*/true, 99, 100, kNearTip, false));
    BOOST_CHECK(IndependentConsensusMaySpendExactReplayGpu(
        false, true, 100, 100, kNearTip, false));
    // Catch-up above the connected tip (a live consensus-archive node 2026-08-29): unattested
    // bodies that extend the active chain must occupy ExactReplay. The old
    // upper bound (index_height <= tip_height) HEADER_ONLY-skipped them
    // while a competing twin sat on m_best_header.
    BOOST_CHECK(IndependentConsensusMaySpendExactReplayGpu(
        false, true, 102, 100, kNearTip, false));
    BOOST_CHECK(IndependentConsensusMaySpendExactReplayGpu(
        false, true, 104, 100, kNearTip, false));
    BOOST_CHECK(IndependentConsensusMaySpendExactReplayGpu(
        false, true, 199380, 199378, kNearTip, false));
    // Immediate unattested tip-child stays off this helper (twin storm).
    // ClaimConfigured / ConsensusMayClaimUnattestedTipChildBody owns it.
    BOOST_CHECK(!IndependentConsensusMaySpendExactReplayGpu(
        /*pprev_is_tip=*/true, /*on_or_extends_active_tip=*/true, 101, 100,
        kNearTip, false));
    // Competing unattested fork that does not extend the connected tip.
    BOOST_CHECK(!IndependentConsensusMaySpendExactReplayGpu(
        false, false, 199382, 199378, kNearTip, false));
    // Competing unattested twin at the same height: off the device.
    BOOST_CHECK(!IndependentConsensusMaySpendExactReplayGpu(
        false, false, 191323, 191323, kNearTip, false));
    BOOST_CHECK(IndependentConsensusMaySpendExactReplayGpu(
        false, false, 191323, 191323, kNearTip,
        /*covered_by_attestation=*/true));
    // Parked dump-and-run branch: never re-occupy the device, even if
    // a stolen pin later covers the hash.
    BOOST_CHECK(!IndependentConsensusMaySpendExactReplayGpu(
        false, false, 191323, 191323, kNearTip, true, /*on_parked=*/true));
    BOOST_CHECK(!IndependentConsensusMaySpendExactReplayGpu(
        true, false, 101, 100, kNearTip, true, /*on_parked=*/true));
    using node::matmul_trusted::ConsensusMaySpendExactReplayGpuForShortReorgForkChild;
    // Live 2026-08-20: unattested tip 195603 489884e4, attested sibling
    // b8971871 (LCA depth 1), signed frontier 195635 HEADER_ONLY.
    BOOST_CHECK(ConsensusMaySpendExactReplayGpuForShortReorgForkChild(
        /*configured=*/true, /*tip_has_quorum=*/false,
        /*index_covered_by_attestation=*/true, /*index_is_tip=*/false,
        /*lca_depth=*/1, /*is_immediate_fork_child=*/true,
        /*index_on_active_chain=*/false, /*has_competing_quorum=*/false,
        /*on_parked=*/false));
    BOOST_CHECK(!ConsensusMaySpendExactReplayGpuForShortReorgForkChild(
        true, /*tip_has_quorum=*/true, true, false, 1, true, false, false,
        false));
    BOOST_CHECK(!ConsensusMaySpendExactReplayGpuForShortReorgForkChild(
        true, false, /*index_covered_by_attestation=*/false, false, 1, true,
        false, false, false));
    BOOST_CHECK(!ConsensusMaySpendExactReplayGpuForShortReorgForkChild(
        true, false, true, false, 1, /*is_immediate_fork_child=*/false,
        false, false, false));
    BOOST_CHECK(!ConsensusMaySpendExactReplayGpuForShortReorgForkChild(
        true, false, true, false, 1, true, /*index_on_active_chain=*/true,
        false, false));
    BOOST_CHECK(!ConsensusMaySpendExactReplayGpuForShortReorgForkChild(
        true, false, true, false, 1, true, false,
        /*has_competing_quorum=*/true, false));
    BOOST_CHECK(!ConsensusMaySpendExactReplayGpuForShortReorgForkChild(
        true, false, true, false, 1, true, false, false, /*on_parked=*/true));
    BOOST_CHECK(!ConsensusMaySpendExactReplayGpuForShortReorgForkChild(
        true, false, true, false, /*lca_depth=*/0, true, false, false,
        false));
    BOOST_CHECK(!ConsensusMaySpendExactReplayGpuForShortReorgForkChild(
        true, false, true, false, /*lca_depth=*/7, true, false, false,
        false));
    using node::matmul_trusted::ShouldRetryBudgetDeferredWhileFrontierOffChain;
    BOOST_CHECK(ShouldRetryBudgetDeferredWhileFrontierOffChain(
        /*frontier_off_active_chain=*/false, /*fork_child=*/false,
        /*on_frontier=*/false, /*followed_tip_child=*/false));
    BOOST_CHECK(ShouldRetryBudgetDeferredWhileFrontierOffChain(
        true, /*hash_is_short_reorg_attested_fork_child=*/true, false, false));
    BOOST_CHECK(ShouldRetryBudgetDeferredWhileFrontierOffChain(
        true, false, /*hash_on_signed_frontier_chain=*/true, false));
    BOOST_CHECK(ShouldRetryBudgetDeferredWhileFrontierOffChain(
        true, false, false, /*hash_is_followed_tip_child=*/true));
    // Historical losing twins 195579/195599/195601.
    BOOST_CHECK(!ShouldRetryBudgetDeferredWhileFrontierOffChain(
        true, false, false, false));
    using node::matmul_trusted::TrustedMirrorAttestedHintIsActiveAncestor;
    BOOST_CHECK(TrustedMirrorAttestedHintIsActiveAncestor(
        /*on_active_chain=*/true, /*lca_is_index=*/false));
    BOOST_CHECK(TrustedMirrorAttestedHintIsActiveAncestor(false, true));
    BOOST_CHECK(!TrustedMirrorAttestedHintIsActiveAncestor(false, false));
}

BOOST_AUTO_TEST_CASE(tip_extender_capacity_reserved_under_slot_pressure)
{
    using node::matmul_trusted::TrustedAttestationRequestCapacityAllows;

    constexpr size_t kMax{1024};
    constexpr size_t kReserved{1};
    // Backfill cannot fill the last reserved slot.
    BOOST_CHECK(!TrustedAttestationRequestCapacityAllows(
        /*tip_extending=*/false, /*outstanding=*/kMax - kReserved, kMax,
        kReserved));
    BOOST_CHECK(TrustedAttestationRequestCapacityAllows(
        /*tip_extending=*/false, /*outstanding=*/kMax - kReserved - 1, kMax,
        kReserved));
    // Tip-extender may always attempt admission (displace path handles full).
    BOOST_CHECK(TrustedAttestationRequestCapacityAllows(
        /*tip_extending=*/true, /*outstanding=*/kMax, kMax, kReserved));
    BOOST_CHECK(TrustedAttestationRequestCapacityAllows(
        /*tip_extending=*/true, /*outstanding=*/kMax - 1, kMax, kReserved));
}

BOOST_AUTO_TEST_CASE(tip_extending_occupancy_cap_blocks_sibling_flood)
{
    using node::matmul_trusted::EvaluateTipExtendingCapacity;
    using node::matmul_trusted::MakeTrustedWorkRank;
    using node::matmul_trusted::TrustedWorkRank;

    constexpr size_t kTipCapacity{8};
    std::vector<TrustedWorkRank> occupants;
    for (uint64_t sequence{1}; sequence <= kTipCapacity; ++sequence) {
        occupants.push_back(MakeTrustedWorkRank(
            /*tip_extending=*/true, /*height=*/101, /*tip_height=*/100,
            /*priority_rank=*/0, sequence));
    }

    // A ninth free Phase-1 sibling with identical work cannot grow the set.
    auto decision{EvaluateTipExtendingCapacity(
        MakeTrustedWorkRank(true, 101, 100, 0, 9), occupants,
        kTipCapacity)};
    BOOST_CHECK(!decision.allow);
    BOOST_CHECK(!decision.replace_index.has_value());

    // Capacity replacement is permitted only for a strictly better-ranked
    // request; total tip-extending occupancy remains bounded at eight.
    decision = EvaluateTipExtendingCapacity(
        MakeTrustedWorkRank(true, 101, 100, /*priority_rank=*/1, 9),
        occupants, kTipCapacity);
    BOOST_REQUIRE(decision.allow);
    BOOST_REQUIRE(decision.replace_index.has_value());
    BOOST_CHECK_LT(*decision.replace_index, occupants.size());

    occupants.pop_back();
    decision = EvaluateTipExtendingCapacity(
        MakeTrustedWorkRank(true, 101, 100, 0, 10), occupants,
        kTipCapacity);
    BOOST_CHECK(decision.allow);
    BOOST_CHECK(!decision.replace_index.has_value());
}

BOOST_AUTO_TEST_CASE(refutation_index_height_lookup_blocks_poisoned_key)
{
    RuntimeReset reset;
    const CKey pin{NewKey()};
    const uint256 chain{Hex256('a')};
    const uint256 hash{Hex256('b')};
    const uint256 context{Hex256('c')};
    matmul::trusted::StoreConfig config;
    config.chain_id = chain;
    config.replay_authority_context = context;
    config.trusted_signers = {pin.GetPubKey()};
    config.threshold = 1;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/false,
        /*serve=*/false, std::chrono::milliseconds{10}, error));

    matmul::trusted::ExactReplayStatement statement;
    statement.chain_id = chain;
    statement.block_hash = hash;
    statement.block_height = 40;
    statement.replay_authority_context = context;
    const auto refute{matmul::trusted::SignRefutation(statement, pin)};
    BOOST_REQUIRE(refute.has_value());

    // Lookup says the header lives at 12. A caller that forwards the
    // self-declared height 40 must not store under 40.
    node::matmul_trusted::SetBlockIndexHeightLookup(
        [hash](const uint256& query) -> std::optional<int32_t> {
            if (query == hash) return 12;
            return std::nullopt;
        });
    BOOST_CHECK(node::matmul_trusted::AddRefutation(*refute, hash, 40) ==
                matmul::trusted::AddResult::WrongHeight);

    statement.block_height = 12;
    const auto honest{matmul::trusted::SignRefutation(statement, pin)};
    BOOST_REQUIRE(honest.has_value());
    BOOST_CHECK(node::matmul_trusted::AddRefutation(*honest, hash, 999) ==
                matmul::trusted::AddResult::Accepted);

    node::matmul_trusted::SetBlockIndexHeightLookup(
        [](const uint256&) -> std::optional<int32_t> { return std::nullopt; });
    BOOST_CHECK(node::matmul_trusted::AddRefutation(*honest, hash, 12) ==
                matmul::trusted::AddResult::WrongHeight);
}

BOOST_AUTO_TEST_CASE(authority_frontier_tracks_accepted_attestations)
{
    RuntimeReset reset;
    const CKey a{NewKey()};
    const uint256 chain{Hex256('1')};
    const uint256 block_lo{Hex256('2')};
    const uint256 block_hi{Hex256('3')};

    matmul::trusted::StoreConfig config;
    config.chain_id = chain;
    config.replay_authority_context = Hex256('4');
    config.trusted_signers = {a.GetPubKey()};
    config.threshold = 1;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/true,
        /*serve=*/false, std::chrono::milliseconds{50},
        error));

    BOOST_CHECK(!node::matmul_trusted::AuthorityAttestedFrontier().has_value());

    matmul::trusted::ExactReplayStatement statement;
    statement.chain_id = chain;
    statement.block_hash = block_lo;
    statement.block_height = 100;
    statement.replay_authority_context = Hex256('4');
    const auto att_lo{matmul::trusted::SignStatement(statement, a)};
    BOOST_REQUIRE(att_lo);
    BOOST_CHECK(node::matmul_trusted::Add(*att_lo, block_lo, 100) ==
                matmul::trusted::AddResult::Accepted);
    BOOST_REQUIRE(node::matmul_trusted::AuthorityAttestedFrontier().has_value());
    BOOST_CHECK_EQUAL(*node::matmul_trusted::AuthorityAttestedFrontier(), 100);

    statement.block_hash = block_hi;
    statement.block_height = 250;
    const auto att_hi{matmul::trusted::SignStatement(statement, a)};
    BOOST_REQUIRE(att_hi);
    BOOST_CHECK(node::matmul_trusted::Add(*att_hi, block_hi, 250) ==
                matmul::trusted::AddResult::Accepted);
    BOOST_CHECK_EQUAL(*node::matmul_trusted::AuthorityAttestedFrontier(), 250);
    const auto hints{node::matmul_trusted::AttestedFrontierHints()};
    BOOST_REQUIRE(!hints.empty());
    BOOST_CHECK_EQUAL(hints.back().height, 250);
    BOOST_CHECK(hints.back().hash == block_hi);

    statement.block_hash = uint256::ONE;
    statement.block_height = 250;
    const auto att_twin{matmul::trusted::SignStatement(statement, a)};
    BOOST_REQUIRE(att_twin);
    BOOST_CHECK(node::matmul_trusted::Add(*att_twin, uint256::ONE, 250) ==
                matmul::trusted::AddResult::Accepted);
    const auto dual{node::matmul_trusted::AttestedFrontierHints()};
    size_t at_250{0};
    bool saw_hi{false};
    bool saw_one{false};
    for (const auto& hint : dual) {
        if (hint.height != 250) continue;
        ++at_250;
        if (hint.hash == block_hi) saw_hi = true;
        if (hint.hash == uint256::ONE) saw_one = true;
    }
    BOOST_CHECK_EQUAL(at_250, 2);
    BOOST_CHECK(saw_hi);
    BOOST_CHECK(saw_one);
    BOOST_CHECK(node::matmul_trusted::HasCompetingQuorum(block_hi, 250));
    BOOST_CHECK(node::matmul_trusted::HasCompetingQuorum(uint256::ONE, 250));
    BOOST_CHECK(!node::matmul_trusted::HasCompetingQuorum(block_lo, 100));

    // Soft peer-tip hint can raise the raw high-water further.
    node::matmul_trusted::NoteAuthorityPeerTipHint(300);
    BOOST_CHECK_EQUAL(*node::matmul_trusted::AuthorityAttestedFrontier(), 300);
    // Production admit/park must not use that raw max when the hint is a
    // competing/unauthenticated height.
    using node::matmul_trusted::SelectAuthorityAttestedFrontier;
    using node::matmul_trusted::AuthorityFrontierCandidateUsable;
    BOOST_CHECK(!AuthorityFrontierCandidateUsable({
        .on_or_extends_active_tip_chain = false,
        .short_tip_reorg = false,
        .on_parked_reorg_branch = false,
    }));
    BOOST_CHECK(!AuthorityFrontierCandidateUsable({
        .on_or_extends_active_tip_chain = true,
        .short_tip_reorg = false,
        .on_parked_reorg_branch = true,
    }));
    BOOST_CHECK(AuthorityFrontierCandidateUsable({
        .on_or_extends_active_tip_chain = true,
        .short_tip_reorg = false,
        .on_parked_reorg_branch = false,
    }));
    BOOST_CHECK(AuthorityFrontierCandidateUsable({
        .on_or_extends_active_tip_chain = false,
        .short_tip_reorg = true,
        .on_parked_reorg_branch = false,
    }));
    // Live: attested 187773 on the losing sibling, peer hint 187859 on the
    // miner fork, signer actually at 187791. Effective frontier must not be
    // 187859.
    const auto capped{SelectAuthorityAttestedFrontier(
        /*attested_height=*/187773, /*attested_usable=*/true,
        /*peer_tip_hint=*/187859, /*hint_usable=*/false)};
    BOOST_REQUIRE(capped.has_value());
    BOOST_CHECK_EQUAL(*capped, 187773);
    const auto signer_short{SelectAuthorityAttestedFrontier(
        /*attested_height=*/187791, /*attested_usable=*/true,
        /*peer_tip_hint=*/187859, /*hint_usable=*/false)};
    BOOST_REQUIRE(signer_short.has_value());
    BOOST_CHECK_EQUAL(*signer_short, 187791);
    BOOST_CHECK(!SelectAuthorityAttestedFrontier(
                     /*attested_height=*/187859, /*attested_usable=*/false,
                     /*peer_tip_hint=*/187859, /*hint_usable=*/false)
                     .has_value());
}

BOOST_AUTO_TEST_CASE(tip_chain_header_preference_ignores_competing_fork)
{
    using node::matmul_trusted::PreferTrustedMirrorTipChainHeader;
    using node::matmul_trusted::TrustedMirrorTipChainHeaderView;

    // Tip-chain extension past the authenticated tip must become best-header.
    BOOST_CHECK(PreferTrustedMirrorTipChainHeader(TrustedMirrorTipChainHeaderView{
        .extends_active_tip_chain = true,
        .on_parked_reorg_branch = false,
        .candidate_height = 186051,
        .tip_height = 186050,
        .current_best_height = 186050,
        .current_best_extends_tip = true,
        .candidate_extends_current_best = true,
    }));

    // Competing fork (not a tip-chain extension) must never displace via the
    // tip-chain-only path (AcceptBlockHeader / ordinary peers).
    BOOST_CHECK(!PreferTrustedMirrorTipChainHeader(TrustedMirrorTipChainHeaderView{
        .extends_active_tip_chain = false,
        .on_parked_reorg_branch = false,
        .candidate_height = 186291,
        .tip_height = 186050,
        .current_best_height = 186050,
        .current_best_extends_tip = true,
        .candidate_extends_current_best = false,
    }));

    // Parked deep-reorg branch is excluded even if heights look ahead.
    BOOST_CHECK(!PreferTrustedMirrorTipChainHeader(TrustedMirrorTipChainHeaderView{
        .extends_active_tip_chain = true,
        .on_parked_reorg_branch = true,
        .candidate_height = 186060,
        .tip_height = 186050,
        .current_best_height = 186050,
        .current_best_extends_tip = true,
        .candidate_extends_current_best = true,
    }));

    // A tip-chain header may displace a stale best-header that is not on tip.
    BOOST_CHECK(PreferTrustedMirrorTipChainHeader(TrustedMirrorTipChainHeaderView{
        .extends_active_tip_chain = true,
        .on_parked_reorg_branch = false,
        .candidate_height = 186051,
        .tip_height = 186050,
        .current_best_height = 186200,
        .current_best_extends_tip = false,
        .candidate_extends_current_best = false,
    }));
}

BOOST_AUTO_TEST_CASE(one_pin_vote_does_not_raise_signed_frontier)
{
    RuntimeReset reset;
    const CKey a{NewKey()};
    const CKey b{NewKey()};
    const uint256 chain{Hex256('1')};
    const uint256 block{Hex256('2')};
    matmul::trusted::StoreConfig config;
    config.chain_id = chain;
    config.replay_authority_context = Hex256('4');
    config.trusted_signers = {a.GetPubKey(), b.GetPubKey()};
    config.threshold = 2;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/true,
        /*serve=*/false, std::chrono::milliseconds{50},
        error));

    matmul::trusted::ExactReplayStatement statement;
    statement.chain_id = chain;
    statement.block_hash = block;
    statement.block_height = 100;
    statement.replay_authority_context = Hex256('4');
    const auto att_a{matmul::trusted::SignStatement(statement, a)};
    BOOST_REQUIRE(att_a);
    BOOST_CHECK(node::matmul_trusted::Add(*att_a, block, 100) ==
                matmul::trusted::AddResult::Accepted);
    BOOST_CHECK(!node::matmul_trusted::HasQuorum(block, 100));
    BOOST_CHECK(!node::matmul_trusted::AuthorityAttestedFrontier().has_value());

    const auto att_b{matmul::trusted::SignStatement(statement, b)};
    BOOST_REQUIRE(att_b);
    BOOST_CHECK(node::matmul_trusted::Add(*att_b, block, 100) ==
                matmul::trusted::AddResult::Accepted);
    BOOST_CHECK(node::matmul_trusted::HasQuorum(block, 100));
    BOOST_REQUIRE(node::matmul_trusted::AuthorityAttestedFrontier().has_value());
    BOOST_CHECK_EQUAL(*node::matmul_trusted::AuthorityAttestedFrontier(), 100);
}

BOOST_AUTO_TEST_CASE(authority_header_preference_rescues_divergent_tip)
{
    using node::matmul_trusted::PreferTrustedMirrorAuthorityHeader;
    using node::matmul_trusted::TrustedMirrorAuthorityHeaderView;
    using node::matmul_trusted::TrustedMirrorMayDownloadCompetingBranch;

    // Non-authority competing fork must still be refused (archive-A regression).
    BOOST_CHECK(!PreferTrustedMirrorAuthorityHeader(TrustedMirrorAuthorityHeaderView{
        .from_authority_peer = false,
        .extends_active_tip_chain = false,
        .better_work_reorg_candidate = true,
        .on_parked_reorg_branch = false,
        .candidate_height = 186394,
        .tip_height = 186393,
        .current_best_height = 186393,
        .current_best_extends_tip = true,
        .candidate_extends_current_best = false,
    }));

    // Authority equal-work sibling (same-height race loser) must displace the
    // tip-pinned best-header so headers can advance off the stranded tip.
    BOOST_CHECK(PreferTrustedMirrorAuthorityHeader(TrustedMirrorAuthorityHeaderView{
        .from_authority_peer = true,
        .extends_active_tip_chain = false,
        .better_work_reorg_candidate = true,
        .on_parked_reorg_branch = false,
        .candidate_height = 186393,
        .tip_height = 186393,
        .current_best_height = 186393,
        .current_best_extends_tip = true,
        .candidate_extends_current_best = false,
    }));

    // Authority heavier extension past the fork must become best-header.
    BOOST_CHECK(PreferTrustedMirrorAuthorityHeader(TrustedMirrorAuthorityHeaderView{
        .from_authority_peer = true,
        .extends_active_tip_chain = false,
        .better_work_reorg_candidate = true,
        .on_parked_reorg_branch = false,
        .candidate_height = 186674,
        .tip_height = 186393,
        .current_best_height = 186393,
        .current_best_extends_tip = true,
        .candidate_extends_current_best = false,
    }));

    // Parked deep-reorg branch stays refused even from an authority peer —
    // EMERGENCY park_depth must not be bypassable via header follow.
    BOOST_CHECK(!PreferTrustedMirrorAuthorityHeader(TrustedMirrorAuthorityHeaderView{
        .from_authority_peer = true,
        .extends_active_tip_chain = false,
        .better_work_reorg_candidate = true,
        .on_parked_reorg_branch = true,
        .candidate_height = 186674,
        .tip_height = 186393,
        .current_best_height = 186393,
        .current_best_extends_tip = true,
        .candidate_extends_current_best = false,
    }));

    // Authority short-reorg must displace a taller claimed-heaviest miner
    // fork that is not on the active tip (live: m_best_header 187978 vs
    // signer sibling 187791 while tip is 187773).
    BOOST_CHECK(PreferTrustedMirrorAuthorityHeader(TrustedMirrorAuthorityHeaderView{
        .from_authority_peer = true,
        .extends_active_tip_chain = false,
        .better_work_reorg_candidate = true,
        .on_parked_reorg_branch = false,
        .short_tip_reorg = true,
        .candidate_height = 187791,
        .tip_height = 187773,
        .current_best_height = 187978,
        .current_best_extends_tip = false,
        .candidate_extends_current_best = false,
    }));
    // Without the short-reorg bit, a shorter authority header must not
    // displace the taller competing best-header (deep fork stays parked).
    BOOST_CHECK(!PreferTrustedMirrorAuthorityHeader(TrustedMirrorAuthorityHeaderView{
        .from_authority_peer = true,
        .extends_active_tip_chain = false,
        .better_work_reorg_candidate = true,
        .on_parked_reorg_branch = false,
        .short_tip_reorg = false,
        .candidate_height = 187791,
        .tip_height = 187773,
        .current_best_height = 187978,
        .current_best_extends_tip = false,
        .candidate_extends_current_best = false,
    }));

    // Download gate mirrors the same authority / park / followed-chain split.
    BOOST_CHECK(TrustedMirrorMayDownloadCompetingBranch(
        /*is_authority_peer=*/true, /*best_known_extends_tip=*/false,
        /*better_or_equal_work=*/true, /*on_parked_reorg_branch=*/false));
    BOOST_CHECK(!TrustedMirrorMayDownloadCompetingBranch(
        /*is_authority_peer=*/false, /*best_known_extends_tip=*/false,
        /*better_or_equal_work=*/true, /*on_parked_reorg_branch=*/false));
    BOOST_CHECK(!TrustedMirrorMayDownloadCompetingBranch(
        /*is_authority_peer=*/true, /*best_known_extends_tip=*/false,
        /*better_or_equal_work=*/true, /*on_parked_reorg_branch=*/true));
    BOOST_CHECK(TrustedMirrorMayDownloadCompetingBranch(
        /*is_authority_peer=*/false, /*best_known_extends_tip=*/true,
        /*better_or_equal_work=*/false, /*on_parked_reorg_branch=*/false));
    // Ordinary peer on the claimed-heaviest best-header chain must NOT open
    // the download gate: that header is the competing miner fork. Only a
    // short tip-race reorg (or an authority peer) may fetch a non-extending
    // branch.
    BOOST_CHECK(!TrustedMirrorMayDownloadCompetingBranch(
        /*is_authority_peer=*/false, /*best_known_extends_tip=*/false,
        /*better_or_equal_work=*/true, /*on_parked_reorg_branch=*/false,
        /*on_followed_best_header_chain=*/true));
    BOOST_CHECK(TrustedMirrorMayDownloadCompetingBranch(
        /*is_authority_peer=*/false, /*best_known_extends_tip=*/false,
        /*better_or_equal_work=*/true, /*on_parked_reorg_branch=*/false,
        /*on_followed_best_header_chain=*/false,
        /*short_tip_reorg=*/true));
    // Equal-work short reorg is the consensus-miner race-loss fetch:
    // IsConfigured (not only IsTrustedMirror) callers use this helper.
    // Followed-chain does not bypass park-depth finality.
    BOOST_CHECK(!TrustedMirrorMayDownloadCompetingBranch(
        /*is_authority_peer=*/false, /*best_known_extends_tip=*/false,
        /*better_or_equal_work=*/true, /*on_parked_reorg_branch=*/true,
        /*on_followed_best_header_chain=*/true));
    BOOST_CHECK(!TrustedMirrorMayDownloadCompetingBranch(
        /*is_authority_peer=*/false, /*best_known_extends_tip=*/false,
        /*better_or_equal_work=*/true, /*on_parked_reorg_branch=*/true,
        /*on_followed_best_header_chain=*/false,
        /*short_tip_reorg=*/true));
    // Less-work competing branch stays refused even when followed.
    BOOST_CHECK(!TrustedMirrorMayDownloadCompetingBranch(
        /*is_authority_peer=*/false, /*best_known_extends_tip=*/false,
        /*better_or_equal_work=*/false, /*on_parked_reorg_branch=*/false,
        /*on_followed_best_header_chain=*/true));
    // Claimed-heavier must pass even when trust-adjusted work would lose
    // (headers-only suffix deeper than TRUST_ADJUSTED_WORK_ALLOWANCE_BLOCKS
    // while the active tip holds more authenticated work than fork+allowance).
    // Callers pass better_or_equal_work from nChainWork, never TrustAdjustedWork.
    BOOST_CHECK(TrustedMirrorMayDownloadCompetingBranch(
        /*is_authority_peer=*/true, /*best_known_extends_tip=*/false,
        /*better_or_equal_work=*/true, /*on_parked_reorg_branch=*/false));
    BOOST_CHECK(!TrustedMirrorMayDownloadCompetingBranch(
        /*is_authority_peer=*/false, /*best_known_extends_tip=*/false,
        /*better_or_equal_work=*/true, /*on_parked_reorg_branch=*/false,
        /*on_followed_best_header_chain=*/true));
    using node::matmul_trusted::TrustedMirrorOnFollowedHeaderChain;
    BOOST_CHECK(TrustedMirrorOnFollowedHeaderChain(
        /*best_header_known=*/true,
        /*peer_best_is_ancestor_of_best_header=*/true,
        /*peer_best_extends_best_header=*/false));
    BOOST_CHECK(TrustedMirrorOnFollowedHeaderChain(
        /*best_header_known=*/true,
        /*peer_best_is_ancestor_of_best_header=*/false,
        /*peer_best_extends_best_header=*/true));
    BOOST_CHECK(!TrustedMirrorOnFollowedHeaderChain(
        /*best_header_known=*/false,
        /*peer_best_is_ancestor_of_best_header=*/true,
        /*peer_best_extends_best_header=*/true));
}

BOOST_AUTO_TEST_CASE(authority_peer_proof_is_branch_bound)
{
    using node::matmul_trusted::AuthorityProofCoversCandidate;

    BOOST_CHECK(AuthorityProofCoversCandidate(
        /*proof_recent=*/true, /*proof_index_known=*/true,
        /*proof_height=*/100, /*candidate_height=*/120,
        /*candidate_descends_proof=*/true));

    // An old valid signature relayed by a peer is not authority for an
    // unrelated equal/heavier fork, and expiry closes even the certified
    // branch's temporary routing preference.
    BOOST_CHECK(!AuthorityProofCoversCandidate(
        /*proof_recent=*/true, /*proof_index_known=*/true,
        /*proof_height=*/100, /*candidate_height=*/120,
        /*candidate_descends_proof=*/false));
    BOOST_CHECK(!AuthorityProofCoversCandidate(
        /*proof_recent=*/false, /*proof_index_known=*/true,
        /*proof_height=*/100, /*candidate_height=*/120,
        /*candidate_descends_proof=*/true));
    // A replayed signature below the current tip is a common-ancestor token,
    // not a branch certificate; accepting it would authorize either sibling.
    BOOST_CHECK(!AuthorityProofCoversCandidate(
        /*proof_recent=*/true, /*proof_index_known=*/true,
        /*proof_height=*/100, /*candidate_height=*/120,
        /*candidate_descends_proof=*/true,
        /*proof_not_behind_active_tip=*/false));
    BOOST_CHECK(!AuthorityProofCoversCandidate(
        /*proof_recent=*/true, /*proof_index_known=*/true,
        /*proof_height=*/100, /*candidate_height=*/120,
        /*candidate_descends_proof=*/true,
        /*proof_not_behind_active_tip=*/true,
        /*authority_context_matches=*/false));
}

BOOST_AUTO_TEST_CASE(unattestable_reject_counter_is_distinct_not_hot_loop)
{
    using node::matmul_trusted::CountTrustedRejectAsDistinct;
    using node::matmul_trusted::TrustedRejectStickyView;

    // First sighting of a hash counts.
    BOOST_CHECK(CountTrustedRejectAsDistinct(TrustedRejectStickyView{
        .already_cached = false,
        .window_active = false,
    }));
    // Repeats inside the sticky window must not count again.
    BOOST_CHECK(!CountTrustedRejectAsDistinct(TrustedRejectStickyView{
        .already_cached = true,
        .window_active = true,
    }));
    // After the window expires, a re-arm may count once more.
    BOOST_CHECK(CountTrustedRejectAsDistinct(TrustedRejectStickyView{
        .already_cached = true,
        .window_active = false,
    }));

    using node::matmul_trusted::AttestationBackoffMapMustEvict;
    using node::matmul_trusted::MATMUL_ATTESTATION_BACKOFF_MAX;
    BOOST_CHECK(!AttestationBackoffMapMustEvict(0));
    BOOST_CHECK(!AttestationBackoffMapMustEvict(MATMUL_ATTESTATION_BACKOFF_MAX - 1));
    BOOST_CHECK(AttestationBackoffMapMustEvict(MATMUL_ATTESTATION_BACKOFF_MAX));
    BOOST_CHECK(AttestationBackoffMapMustEvict(MATMUL_ATTESTATION_BACKOFF_MAX + 1));
    BOOST_CHECK(!AttestationBackoffMapMustEvict(/*map_size=*/10, /*max_size=*/0));
}

BOOST_AUTO_TEST_CASE(attestation_backoff_ttl_and_newest_victim_bound_the_map)
{
    using node::matmul_trusted::AttestationBackoffArmBudgetAllows;
    using node::matmul_trusted::AttestationBackoffEntryExpired;
    using node::matmul_trusted::AttestationBackoffPreferNewerVictim;
    using node::matmul_trusted::EvictNewestAttestationBackoffToCap;
    using node::matmul_trusted::MATMUL_ATTESTATION_BACKOFF_ARM_MAX;
    using node::matmul_trusted::PruneExpiredAttestationBackoff;

    BOOST_CHECK(AttestationBackoffEntryExpired(/*now=*/10, /*not_before=*/10));
    BOOST_CHECK(AttestationBackoffEntryExpired(/*now=*/11, /*not_before=*/10));
    BOOST_CHECK(!AttestationBackoffEntryExpired(/*now=*/9, /*not_before=*/10));

    BOOST_CHECK(AttestationBackoffPreferNewerVictim(/*candidate=*/5, /*current=*/3));
    BOOST_CHECK(!AttestationBackoffPreferNewerVictim(/*candidate=*/3, /*current=*/5));

    struct Backoff {
        std::chrono::steady_clock::time_point not_before{};
    };
    const auto t0{std::chrono::steady_clock::time_point{}};
    const auto HashN = [](uint64_t n) {
        uint256 h{};
        h.data()[0] = static_cast<unsigned char>(n);
        h.data()[1] = static_cast<unsigned char>(n >> 8);
        h.data()[2] = static_cast<unsigned char>(n >> 16);
        return h;
    };

    std::map<uint256, Backoff> ttl;
    ttl[HashN(1)].not_before = t0 + std::chrono::seconds{1};
    ttl[HashN(2)].not_before = t0 + std::chrono::seconds{3};
    PruneExpiredAttestationBackoff(ttl, t0 + std::chrono::seconds{2});
    BOOST_CHECK_EQUAL(ttl.size(), 1U);
    BOOST_CHECK(ttl.count(HashN(2)));
    BOOST_CHECK(!ttl.count(HashN(1)));

    std::map<uint256, Backoff> newest;
    newest[HashN(0)].not_before = t0 + std::chrono::seconds{1};
    newest[HashN(1)].not_before = t0 + std::chrono::seconds{2};
    newest[HashN(2)].not_before = t0 + std::chrono::seconds{3};
    EvictNewestAttestationBackoffToCap(newest, /*max_size=*/3);
    BOOST_CHECK_EQUAL(newest.size(), 2U);
    BOOST_CHECK(newest.count(HashN(0)));
    BOOST_CHECK(newest.count(HashN(1)));
    BOOST_CHECK(!newest.count(HashN(2)));

    constexpr size_t cap{32};
    std::map<uint256, Backoff> flood;
    for (size_t i = 0; i < cap + 1000; ++i) {
        PruneExpiredAttestationBackoff(flood, t0);
        EvictNewestAttestationBackoffToCap(flood, cap);
        flood[HashN(i)].not_before = t0 + std::chrono::seconds{static_cast<long>(i + 1)};
    }
    BOOST_CHECK_LE(flood.size(), cap);
    BOOST_CHECK(flood.count(HashN(0)));
    BOOST_CHECK(flood.count(HashN(cap - 2)));
    BOOST_CHECK(!flood.count(HashN(cap - 1)));
    BOOST_CHECK(!flood.count(HashN(cap)));
    BOOST_CHECK(flood.count(HashN(cap + 999)));

    BOOST_CHECK(AttestationBackoffArmBudgetAllows(0, 1000, 0));
    BOOST_CHECK(AttestationBackoffArmBudgetAllows(0, 1000, 1000));
    BOOST_CHECK(AttestationBackoffArmBudgetAllows(
        MATMUL_ATTESTATION_BACKOFF_ARM_MAX - 1, 1000, 1000));
    BOOST_CHECK(!AttestationBackoffArmBudgetAllows(
        MATMUL_ATTESTATION_BACKOFF_ARM_MAX, 1000, 1000));
    BOOST_CHECK(AttestationBackoffArmBudgetAllows(
        MATMUL_ATTESTATION_BACKOFF_ARM_MAX, 1060, 1000));
}

BOOST_AUTO_TEST_CASE(attestations_survive_simulated_restart)
{
    RuntimeReset reset;
    const CKey signer{NewKey()};
    const uint256 chain{Hex256('a')};
    const uint256 block{Hex256('b')};
    const fs::path archive{
        m_args.GetDataDirNet() / "matmul_attestations_test.dat"};

    {
        matmul::trusted::StoreConfig config;
        config.chain_id = chain;
        config.replay_authority_context = Hex256('c');
        config.trusted_signers = {signer.GetPubKey()};
        config.threshold = 1;
        config.local_signer = signer;
        std::string error;
        BOOST_REQUIRE(node::matmul_trusted::Configure(
            std::move(config), /*trusted_mirror=*/false,
            /*serve=*/true, std::chrono::milliseconds{50}, error));
        BOOST_REQUIRE(node::matmul_trusted::OpenPersistence(archive, error));
        BOOST_CHECK(node::matmul_trusted::SignAuthoritative(block, 42) ==
                    matmul::trusted::AddResult::Accepted);
        BOOST_REQUIRE(!node::matmul_trusted::Get(block, 42).empty());
        BOOST_REQUIRE(node::matmul_trusted::FlushPersistence(error));
    }

    // Simulate process restart: drop the in-memory store, then reload.
    node::matmul_trusted::ResetForTest();
    {
        matmul::trusted::StoreConfig config;
        config.chain_id = chain;
        config.replay_authority_context = Hex256('c');
        config.trusted_signers = {signer.GetPubKey()};
        config.threshold = 1;
        config.local_signer = signer;
        std::string error;
        BOOST_REQUIRE(node::matmul_trusted::Configure(
            std::move(config), /*trusted_mirror=*/false,
            /*serve=*/true, std::chrono::milliseconds{50}, error));
        BOOST_REQUIRE(node::matmul_trusted::OpenPersistence(archive, error));
        const auto restored{node::matmul_trusted::Get(block, 42)};
        BOOST_REQUIRE_EQUAL(restored.size(), 1U);
        BOOST_CHECK(restored[0].statement.block_hash == block);
        BOOST_CHECK_EQUAL(restored[0].statement.block_height, 42);
        BOOST_CHECK(node::matmul_trusted::HasQuorum(block, 42));
    }
}

BOOST_AUTO_TEST_CASE(open_archive_records_do_not_seed_signed_frontier)
{
    RuntimeReset reset;
    const CKey pin{NewKey()};
    const CKey open{NewKey()};
    const uint256 chain{Hex256('d')};
    const uint256 context{Hex256('e')};
    const uint256 pin_block{Hex256('1')};
    const uint256 open_block{Hex256('2')};
    const fs::path archive{
        m_args.GetDataDirNet() / "matmul_attestations_open_archive.dat"};

    constexpr char magic[16] = "BTX_MMATTEST_V1";
    DataStream encoded;
    encoded.write(AsBytes(Span{magic, sizeof(magic)}));
    encoded << uint64_t{2};
    {
        matmul::trusted::ExactReplayStatement statement;
        statement.chain_id = chain;
        statement.block_hash = pin_block;
        statement.block_height = 10;
        statement.replay_authority_context = context;
        const auto attestation{matmul::trusted::SignStatement(statement, pin)};
        BOOST_REQUIRE(attestation.has_value());
        encoded << *attestation;
    }
    {
        matmul::trusted::ExactReplayStatement statement;
        statement.chain_id = chain;
        statement.block_hash = open_block;
        statement.block_height = 50;
        statement.replay_authority_context = context;
        const auto attestation{matmul::trusted::SignStatement(statement, open)};
        BOOST_REQUIRE(attestation.has_value());
        encoded << *attestation;
    }
    BOOST_REQUIRE(WriteBinaryFile(
        archive,
        std::string{reinterpret_cast<const char*>(encoded.data()),
                    encoded.size()}));

    matmul::trusted::StoreConfig config;
    config.chain_id = chain;
    config.replay_authority_context = context;
    config.trusted_signers = {pin.GetPubKey()};
    config.threshold = 1;
    config.open_attestors = true;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/true,
        /*serve=*/true, std::chrono::milliseconds{50}, error));
    BOOST_REQUIRE(node::matmul_trusted::OpenPersistence(archive, error));
    BOOST_CHECK(node::matmul_trusted::HasQuorum(pin_block, 10));
    BOOST_CHECK(!node::matmul_trusted::HasQuorum(open_block, 50));
    BOOST_REQUIRE(node::matmul_trusted::HighestAttestedHeight().has_value());
    BOOST_CHECK_EQUAL(*node::matmul_trusted::HighestAttestedHeight(), 10);
    BOOST_CHECK(node::matmul_trusted::Get(open_block, 50).empty());
    BOOST_CHECK(node::matmul_trusted::HeardAttestations().empty());
}

BOOST_AUTO_TEST_CASE(durable_history_outlives_bounded_hot_cache)
{
    RuntimeReset reset;
    const CKey signer{NewKey()};
    const uint256 chain{Hex256('7')};
    const uint256 context{Hex256('8')};
    const fs::path archive{
        m_args.GetDataDirNet() / "matmul_attestations_long_history.dat"};
    constexpr size_t BLOCK_COUNT{4097};
    const uint256 first_block{(HashWriter{} << uint64_t{0}).GetHash()};
    const uint256 last_block{
        (HashWriter{} << uint64_t{BLOCK_COUNT - 1}).GetHash()};

    // Build a legacy flat archive one entry beyond the default 4096-block hot
    // cache. OpenPersistence migrates it to disk-backed authority history.
    constexpr char magic[16] = "BTX_MMATTEST_V1";
    DataStream encoded;
    encoded.write(AsBytes(Span{magic, sizeof(magic)}));
    encoded << uint64_t{BLOCK_COUNT};
    for (size_t i{0}; i < BLOCK_COUNT; ++i) {
        matmul::trusted::ExactReplayStatement statement;
        statement.chain_id = chain;
        statement.block_hash = (HashWriter{} << uint64_t{i}).GetHash();
        statement.block_height = static_cast<int32_t>(i);
        statement.replay_authority_context = context;
        const auto attestation{matmul::trusted::SignStatement(statement, signer)};
        BOOST_REQUIRE(attestation.has_value());
        encoded << *attestation;
    }
    BOOST_REQUIRE(WriteBinaryFile(
        archive,
        std::string{reinterpret_cast<const char*>(encoded.data()),
                    encoded.size()}));

    auto configure = [&] {
        matmul::trusted::StoreConfig config;
        config.chain_id = chain;
        config.replay_authority_context = context;
        config.trusted_signers = {signer.GetPubKey()};
        config.threshold = 1;
        std::string error;
        BOOST_REQUIRE(node::matmul_trusted::Configure(
            std::move(config), /*trusted_mirror=*/true,
            /*serve=*/true, std::chrono::milliseconds{50}, error));
    };

    configure();
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::OpenPersistence(archive, error));
    const auto stats{node::matmul_trusted::Stats()};
    BOOST_CHECK_LE(stats.stored_blocks, 4096U);
    BOOST_CHECK_LE(stats.stored_attestations, 16384U);
    BOOST_CHECK(node::matmul_trusted::HasQuorum(first_block, 0));
    BOOST_CHECK(node::matmul_trusted::HasQuorum(
        last_block, static_cast<int32_t>(BLOCK_COUNT - 1)));
    BOOST_REQUIRE_EQUAL(node::matmul_trusted::Get(first_block, 0).size(), 1U);
    node::matmul_trusted::ClosePersistence();

    // Prove the LevelDB, rather than a rewritten bounded archive, owns the
    // full history after restart.
    std::error_code remove_ec;
    fs::remove(archive, remove_ec);
    node::matmul_trusted::ResetForTest();
    configure();
    error.clear();
    BOOST_REQUIRE(node::matmul_trusted::OpenPersistence(archive, error));
    BOOST_CHECK(node::matmul_trusted::HasQuorum(first_block, 0));
    BOOST_CHECK(node::matmul_trusted::HasQuorum(
        last_block, static_cast<int32_t>(BLOCK_COUNT - 1)));
    const auto restart_stats{node::matmul_trusted::Stats()};
    BOOST_CHECK_EQUAL(restart_stats.stored_blocks, 4096U);
    // Startup verifies all 4097 database records but hydrates only the bounded
    // tail. An accepted count of 4097 would prove the old O(history*cache)
    // add/evict loop was still running.
    BOOST_CHECK_EQUAL(restart_stats.accepted, 4096U);
    BOOST_CHECK_EQUAL(restart_stats.evicted_blocks, 0U);
}

BOOST_AUTO_TEST_CASE(durable_history_is_namespaced_across_signer_rotation)
{
    RuntimeReset reset;
    const CKey old_signer{NewKey()};
    const CKey new_signer{NewKey()};
    const uint256 chain{Hex256('9')};
    const uint256 context{Hex256('a')};
    const uint256 block{Hex256('b')};
    const fs::path archive{
        m_args.GetDataDirNet() / "matmul_attestations_rotation_test.dat"};

    auto configure = [&](const CKey& signer) {
        matmul::trusted::StoreConfig config;
        config.chain_id = chain;
        config.replay_authority_context = context;
        config.trusted_signers = {signer.GetPubKey()};
        config.threshold = 1;
        config.local_signer = signer;
        std::string error;
        BOOST_REQUIRE(node::matmul_trusted::Configure(
            std::move(config), /*trusted_mirror=*/false,
            /*serve=*/true, std::chrono::milliseconds{50}, error));
    };

    configure(old_signer);
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::OpenPersistence(archive, error));
    BOOST_CHECK(node::matmul_trusted::SignAuthoritative(block, 51) ==
                matmul::trusted::AddResult::Accepted);
    BOOST_REQUIRE(node::matmul_trusted::FlushPersistence(error));
    node::matmul_trusted::ResetForTest();

    // An intentional authority change must neither trust the old quorum nor
    // make startup fatal. It gets a separate durable namespace.
    configure(new_signer);
    error.clear();
    BOOST_REQUIRE(node::matmul_trusted::OpenPersistence(archive, error));
    BOOST_CHECK(!node::matmul_trusted::HasQuorum(block, 51));
    BOOST_CHECK(node::matmul_trusted::SignAuthoritative(block, 51) ==
                matmul::trusted::AddResult::Accepted);
    BOOST_CHECK(node::matmul_trusted::HasQuorum(block, 51));
}

BOOST_AUTO_TEST_CASE(durable_worker_checkpoints_wal_under_sustained_history)
{
    RuntimeReset reset;
    const CKey signer{NewKey()};
    const uint256 chain{Hex256('c')};
    const uint256 context{Hex256('d')};
    const fs::path archive{
        m_args.GetDataDirNet() / "matmul_attestations_wal_checkpoint.dat"};
    const fs::path wal{archive + ".wal"};
    constexpr size_t BLOCK_COUNT{4097};

    auto configure = [&] {
        matmul::trusted::StoreConfig config;
        config.chain_id = chain;
        config.replay_authority_context = context;
        config.trusted_signers = {signer.GetPubKey()};
        config.threshold = 1;
        config.local_signer = signer;
        std::string error;
        BOOST_REQUIRE(node::matmul_trusted::Configure(
            std::move(config), /*trusted_mirror=*/false,
            /*serve=*/true, std::chrono::milliseconds{50}, error));
    };

    configure();
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::OpenPersistence(archive, error));
    for (size_t i{0}; i < BLOCK_COUNT; ++i) {
        const uint256 block{(HashWriter{} << uint64_t{i}).GetHash()};
        BOOST_CHECK(node::matmul_trusted::SignAuthoritative(
                        block, static_cast<int32_t>(i)) ==
                    matmul::trusted::AddResult::Accepted);
    }
    BOOST_REQUIRE(node::matmul_trusted::FlushPersistence(error));
    // Header-only is the steady checkpoint. This proves the worker did not
    // retain one legacy WAL record per historical block.
    BOOST_REQUIRE(fs::exists(wal));
    BOOST_CHECK_LE(fs::file_size(wal), 16U);
    node::matmul_trusted::ResetForTest();

    configure();
    error.clear();
    BOOST_REQUIRE(node::matmul_trusted::OpenPersistence(archive, error));
    const uint256 first{(HashWriter{} << uint64_t{0}).GetHash()};
    const uint256 last{
        (HashWriter{} << uint64_t{BLOCK_COUNT - 1}).GetHash()};
    BOOST_CHECK(node::matmul_trusted::HasQuorum(first, 0));
    BOOST_CHECK(node::matmul_trusted::HasQuorum(
        last, static_cast<int32_t>(BLOCK_COUNT - 1)));
    BOOST_CHECK_LE(node::matmul_trusted::Stats().stored_blocks, 4096U);
}

BOOST_AUTO_TEST_CASE(truncated_attestation_wal_fails_closed_and_is_preserved)
{
    RuntimeReset reset;
    const CKey signer{NewKey()};
    const fs::path archive{
        m_args.GetDataDirNet() / "matmul_attestations_truncated_test.dat"};
    const fs::path wal{archive + ".wal"};

    auto configure = [&] {
        matmul::trusted::StoreConfig config;
        config.chain_id = Hex256('d');
        config.replay_authority_context = Hex256('e');
        config.trusted_signers = {signer.GetPubKey()};
        config.threshold = 1;
        std::string error;
        BOOST_REQUIRE(node::matmul_trusted::Configure(
            std::move(config), /*trusted_mirror=*/true,
            /*serve=*/false, std::chrono::milliseconds{50}, error));
    };
    configure();
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::OpenPersistence(archive, error));
    node::matmul_trusted::ClosePersistence();

    // Simulate a torn record after the durable WAL header. Startup must not
    // discard or truncate it while reporting the failure.
    {
        FILE* file{fsbridge::fopen(wal, "ab")};
        BOOST_REQUIRE(file);
        const std::array<unsigned char, 3> torn{0x7f, 0x01, 0x02};
        BOOST_REQUIRE_EQUAL(fwrite(torn.data(), 1, torn.size(), file),
                            torn.size());
        BOOST_REQUIRE_EQUAL(fclose(file), 0);
    }
    const auto size_before{fs::file_size(wal)};

    node::matmul_trusted::ResetForTest();
    configure();
    error.clear();
    BOOST_CHECK(!node::matmul_trusted::OpenPersistence(archive, error));
    BOOST_CHECK(!error.empty());
    BOOST_CHECK(fs::exists(wal));
    BOOST_CHECK_EQUAL(fs::file_size(wal), size_before);
}

BOOST_AUTO_TEST_CASE(invalid_signed_wal_record_fails_closed_and_is_preserved)
{
    RuntimeReset reset;
    const CKey signer{NewKey()};
    const uint256 chain{Hex256('4')};
    const uint256 context{Hex256('5')};
    const uint256 block{Hex256('6')};
    const fs::path archive{
        m_args.GetDataDirNet() / "matmul_attestations_invalid_sig_test.dat"};
    const fs::path wal{archive + ".wal"};

    auto configure = [&] {
        matmul::trusted::StoreConfig config;
        config.chain_id = chain;
        config.replay_authority_context = context;
        config.trusted_signers = {signer.GetPubKey()};
        config.threshold = 1;
        std::string error;
        BOOST_REQUIRE(node::matmul_trusted::Configure(
            std::move(config), /*trusted_mirror=*/true,
            /*serve=*/false, std::chrono::milliseconds{50}, error));
    };
    configure();
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::OpenPersistence(archive, error));
    node::matmul_trusted::ClosePersistence();

    matmul::trusted::ExactReplayStatement statement;
    statement.chain_id = chain;
    statement.block_hash = block;
    statement.block_height = 73;
    statement.replay_authority_context = context;
    auto invalid{matmul::trusted::SignStatement(statement, signer)};
    BOOST_REQUIRE(invalid);
    BOOST_REQUIRE(!invalid->signature.empty());
    invalid->signature.front() = 0; // Valid encoding, invalid ECDSA payload.

    DataStream record;
    record << *invalid;
    DataStream prefix;
    prefix << static_cast<uint32_t>(record.size());
    {
        FILE* file{fsbridge::fopen(wal, "ab")};
        BOOST_REQUIRE(file);
        BOOST_REQUIRE_EQUAL(
            fwrite(prefix.data(), 1, prefix.size(), file), prefix.size());
        BOOST_REQUIRE_EQUAL(
            fwrite(record.data(), 1, record.size(), file), record.size());
        BOOST_REQUIRE_EQUAL(fclose(file), 0);
    }
    const auto [read_before, bytes_before]{ReadBinaryFile(wal)};
    BOOST_REQUIRE(read_before);

    node::matmul_trusted::ResetForTest();
    configure();
    error.clear();
    BOOST_CHECK(!node::matmul_trusted::OpenPersistence(archive, error));
    BOOST_CHECK(error.find("invalid-signature") != std::string::npos);
    const auto [read_after, bytes_after]{ReadBinaryFile(wal)};
    BOOST_REQUIRE(read_after);
    BOOST_CHECK(bytes_after == bytes_before);
}

BOOST_AUTO_TEST_CASE(historical_reverify_is_rate_limited)
{
    RuntimeReset reset;
    node::matmul_trusted::ResetHistoricalReverifyBudgetForTest();

    const uint256 a{Hex256('1')};
    const uint256 b{Hex256('2')};
    const uint256 c{Hex256('3')};
    const uint256 d{Hex256('4')};

    BOOST_CHECK(
        node::matmul_trusted::TryAdmitHistoricalReverify(a) ==
        node::matmul_trusted::HistoricalReverifyAdmit::Allow);
    BOOST_CHECK(
        node::matmul_trusted::TryAdmitHistoricalReverify(a) ==
        node::matmul_trusted::HistoricalReverifyAdmit::AlreadyQueued);
    BOOST_CHECK(
        node::matmul_trusted::TryAdmitHistoricalReverify(b) ==
        node::matmul_trusted::HistoricalReverifyAdmit::Allow);
    // Burst exhausted (2 tokens); further distinct hashes are rate-limited
    // until refill, independent of queue room.
    BOOST_CHECK(
        node::matmul_trusted::TryAdmitHistoricalReverify(c) ==
        node::matmul_trusted::HistoricalReverifyAdmit::RateLimited);

    node::matmul_trusted::NoteHistoricalReverifyStarted(a);
    BOOST_CHECK_EQUAL(
        node::matmul_trusted::HistoricalReverifyInflightForTest(), 1U);
    // Inflight cap is checked before spending another token, so a fresh hash
    // is refused as InflightFull while one ExactReplay is already running.
    BOOST_CHECK(
        node::matmul_trusted::TryAdmitHistoricalReverify(d) ==
        node::matmul_trusted::HistoricalReverifyAdmit::InflightFull);

    node::matmul_trusted::NoteHistoricalReverifyFinished(a);
    node::matmul_trusted::NoteHistoricalReverifyFinished(b);
    node::matmul_trusted::ResetHistoricalReverifyBudgetForTest();
    const uint256 e{Hex256('5')};
    BOOST_CHECK(
        node::matmul_trusted::TryAdmitHistoricalReverify(
            e, /*live_gpu_busy=*/true) ==
        node::matmul_trusted::HistoricalReverifyAdmit::LiveGpuBusy);
    BOOST_CHECK_EQUAL(
        node::matmul_trusted::HistoricalReverifyQueuedForTest(), 0U);
    BOOST_CHECK(
        node::matmul_trusted::TryAdmitHistoricalReverify(
            e, /*live_gpu_busy=*/false) ==
        node::matmul_trusted::HistoricalReverifyAdmit::Allow);
    BOOST_CHECK(node::matmul_trusted::HistoricalReverifyAdmitIsDeferral(
        node::matmul_trusted::HistoricalReverifyAdmit::LiveGpuBusy));
    BOOST_CHECK(node::matmul_trusted::HistoricalReverifyAdmitIsDeferral(
        node::matmul_trusted::HistoricalReverifyAdmit::RateLimited));
    BOOST_CHECK(!node::matmul_trusted::HistoricalReverifyAdmitIsDeferral(
        node::matmul_trusted::HistoricalReverifyAdmit::Allow));

    node::matmul_trusted::NoteHistoricalReverifyStarted(e);
    node::matmul_trusted::NoteHistoricalReverifyFinished(e);
    BOOST_CHECK_EQUAL(
        node::matmul_trusted::HistoricalReverifyQueuedForTest(), 0U);
    BOOST_CHECK_EQUAL(
        node::matmul_trusted::HistoricalReverifyInflightForTest(), 0U);
}

BOOST_AUTO_TEST_CASE(sign_authoritative_height_occupied_after_hot_cache_eviction)
{
    RuntimeReset reset;
    const CKey signer{NewKey()};
    matmul::trusted::StoreConfig config;
    config.chain_id = Hex256('7');
    config.replay_authority_context = Hex256('8');
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    config.local_signer = signer;
    config.max_blocks = 1;
    config.max_attestations = 1;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/false,
        /*serve=*/true, std::chrono::milliseconds{10}, error));

    const uint256 first{Hex256('a')};
    const uint256 evict{Hex256('b')};
    const uint256 twin{Hex256('c')};
    constexpr int32_t occupied_height{42};
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      first, occupied_height) ==
                  matmul::trusted::AddResult::Accepted);
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      evict, occupied_height + 1) ==
                  matmul::trusted::AddResult::Accepted);
    BOOST_CHECK(!node::matmul_trusted::HasQuorumInMemory(first, occupied_height));
    BOOST_CHECK(node::matmul_trusted::HasCompetingQuorum(twin, occupied_height));
    BOOST_CHECK(node::matmul_trusted::HasLocalSignatureAtHeight(
        twin, occupied_height));
    BOOST_CHECK(!node::matmul_trusted::HasLocalSignatureAtHeight(
        first, occupied_height));
    BOOST_CHECK(node::matmul_trusted::SignAuthoritative(
                    twin, occupied_height) ==
                matmul::trusted::AddResult::HeightOccupied);
    const auto same{node::matmul_trusted::SignAuthoritative(
        first, occupied_height)};
    BOOST_CHECK(same == matmul::trusted::AddResult::Duplicate ||
                same == matmul::trusted::AddResult::Accepted);
}

BOOST_AUTO_TEST_CASE(sign_authoritative_height_occupied_after_durable_reload)
{
    RuntimeReset reset;
    const CKey signer{NewKey()};
    const uint256 chain{Hex256('9')};
    const uint256 context{Hex256('a')};
    const uint256 first{Hex256('b')};
    const uint256 newer{Hex256('c')};
    const uint256 twin{Hex256('d')};
    const fs::path archive{
        m_args.GetDataDirNet() / "matmul_attestations_local_height_map.dat"};

    auto configure = [&] {
        matmul::trusted::StoreConfig config;
        config.chain_id = chain;
        config.replay_authority_context = context;
        config.trusted_signers = {signer.GetPubKey()};
        config.threshold = 1;
        config.local_signer = signer;
        config.max_blocks = 1;
        config.max_attestations = 1;
        std::string error;
        BOOST_REQUIRE(node::matmul_trusted::Configure(
            std::move(config), /*trusted_mirror=*/false,
            /*serve=*/true, std::chrono::milliseconds{50}, error));
    };

    configure();
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::OpenPersistence(archive, error));
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(first, 10) ==
                  matmul::trusted::AddResult::Accepted);
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(newer, 11) ==
                  matmul::trusted::AddResult::Accepted);
    BOOST_REQUIRE(node::matmul_trusted::FlushPersistence(error));
    node::matmul_trusted::ResetForTest();

    configure();
    error.clear();
    BOOST_REQUIRE(node::matmul_trusted::OpenPersistence(archive, error));
    BOOST_CHECK(!node::matmul_trusted::HasQuorumInMemory(first, 10));
    BOOST_CHECK(node::matmul_trusted::HasCompetingQuorum(twin, 10));
    BOOST_CHECK(node::matmul_trusted::HasLocalSignatureAtHeight(twin, 10));
    BOOST_CHECK(node::matmul_trusted::SignAuthoritative(twin, 10) ==
                matmul::trusted::AddResult::HeightOccupied);
    const auto same{node::matmul_trusted::SignAuthoritative(first, 10)};
    BOOST_CHECK(same == matmul::trusted::AddResult::Duplicate ||
                same == matmul::trusted::AddResult::Accepted);
}

BOOST_AUTO_TEST_CASE(competing_quorum_survives_hint_window_eviction)
{
    RuntimeReset reset;
    const CKey local{NewKey()};
    const CKey other{NewKey()};
    const uint256 chain{Hex256('3')};
    const uint256 context{Hex256('4')};
    matmul::trusted::StoreConfig config;
    config.chain_id = chain;
    config.replay_authority_context = context;
    config.trusted_signers = {local.GetPubKey(), other.GetPubKey()};
    config.threshold = 1;
    config.local_signer = local;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/false,
        /*serve=*/true, std::chrono::milliseconds{10}, error));

    const uint256 occupied{(HashWriter{} << uint64_t{1}).GetHash()};
    matmul::trusted::ExactReplayStatement statement;
    statement.chain_id = chain;
    statement.block_hash = occupied;
    statement.block_height = 1;
    statement.replay_authority_context = context;
    const auto foreign{matmul::trusted::SignStatement(statement, other)};
    BOOST_REQUIRE(foreign.has_value());
    BOOST_REQUIRE(node::matmul_trusted::Add(*foreign, occupied, 1) ==
                  matmul::trusted::AddResult::Accepted);
    BOOST_CHECK(node::matmul_trusted::HasQuorum(occupied, 1));
    BOOST_CHECK(!node::matmul_trusted::HasLocalSignatureAtHeight(
        (HashWriter{} << uint64_t{0}).GetHash(), 1));

    for (int32_t height = 2; height <= 514; ++height) {
        const uint256 hash{(HashWriter{} << uint64_t{static_cast<uint64_t>(height)}).GetHash()};
        BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(hash, height) ==
                      matmul::trusted::AddResult::Accepted);
    }
    bool height_1_still_hinted{false};
    for (const auto& hint : node::matmul_trusted::AttestedFrontierHints()) {
        if (hint.height == 1) height_1_still_hinted = true;
    }
    BOOST_CHECK(!height_1_still_hinted);

    const uint256 twin{(HashWriter{} << uint64_t{999}).GetHash()};
    BOOST_CHECK(node::matmul_trusted::HasCompetingQuorum(twin, 1));
    BOOST_CHECK(node::matmul_trusted::SignAuthoritative(twin, 1) ==
                matmul::trusted::AddResult::HeightOccupied);
}

BOOST_AUTO_TEST_CASE(reorg_and_rpc_release_sign_authoritative_mint_slot)
{
    RuntimeReset reset;
    const CKey signer{NewKey()};
    const CKey other{NewKey()};
    const uint256 chain{Hex256('1')};
    const uint256 context{Hex256('2')};
    matmul::trusted::StoreConfig config;
    config.chain_id = chain;
    config.replay_authority_context = context;
    config.trusted_signers = {signer.GetPubKey(), other.GetPubKey()};
    config.threshold = 2;
    config.local_signer = signer;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/false,
        /*serve=*/true, std::chrono::milliseconds{10}, error));

    const uint256 hash_a{Hex256('a')};
    const uint256 hash_b{Hex256('b')};
    const uint256 hash_c{Hex256('c')};
    constexpr int32_t height{50};

    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(hash_a, height) ==
                  matmul::trusted::AddResult::Accepted);
    BOOST_CHECK(node::matmul_trusted::LocalMintedHash(height) == hash_a);
    BOOST_CHECK(node::matmul_trusted::HasLocalSignatureAtHeight(hash_b, height));
    BOOST_CHECK(node::matmul_trusted::SignAuthoritative(hash_b, height) ==
                matmul::trusted::AddResult::HeightOccupied);

    matmul::trusted::ExactReplayStatement stolen;
    stolen.chain_id = chain;
    stolen.block_hash = hash_c;
    stolen.block_height = height;
    stolen.replay_authority_context = context;
    const auto stolen_att{matmul::trusted::SignStatement(stolen, signer)};
    BOOST_REQUIRE(stolen_att);
    BOOST_CHECK(node::matmul_trusted::Add(*stolen_att, hash_c, height) ==
                matmul::trusted::AddResult::Accepted);
    BOOST_CHECK(node::matmul_trusted::LocalMintedHash(height) == hash_a);
    BOOST_CHECK(node::matmul_trusted::SignAuthoritative(hash_b, height) ==
                matmul::trusted::AddResult::HeightOccupied);

    BOOST_CHECK(node::matmul_trusted::NotifyActiveChainBlockDisconnected(
        height, hash_a));
    BOOST_CHECK(!node::matmul_trusted::LocalMintedHash(height).has_value());
    BOOST_CHECK(!node::matmul_trusted::HasLocalSignatureAtHeight(hash_b, height));

    matmul::trusted::ExactReplayAttestation produced;
    BOOST_CHECK(node::matmul_trusted::SignAuthoritative(
                    hash_b, height, &produced) ==
                matmul::trusted::AddResult::Accepted);
    BOOST_CHECK(produced.statement.block_hash == hash_b);
    BOOST_CHECK_EQUAL(
        node::matmul_trusted::Get(hash_b, height).size(), 1);

    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(hash_a, height + 1) ==
                  matmul::trusted::AddResult::Accepted);
    BOOST_CHECK_EQUAL(
        node::matmul_trusted::ClearMintedAttestations(height + 1, height + 1),
        1);
    BOOST_CHECK(!node::matmul_trusted::LocalMintedHash(height + 1).has_value());
    BOOST_CHECK(node::matmul_trusted::SignAuthoritative(hash_c, height + 1) ==
                matmul::trusted::AddResult::Accepted);
}

BOOST_AUTO_TEST_CASE(blocklist_pin_votes_and_persist_across_restart)
{
    RuntimeReset reset;
    const CKey a{NewKey()};
    const CKey b{NewKey()};
    const CKey c{NewKey()};
    const uint256 chain{Hex256('1')};
    const uint256 context{Hex256('c')};
    const uint256 block{Hex256('b')};
    const fs::path archive{
        m_args.GetDataDirNet() / "matmul_blocklist_test.dat"};

    auto configure = [&](bool with_runtime_store) {
        matmul::trusted::StoreConfig config;
        config.chain_id = chain;
        config.replay_authority_context = context;
        config.trusted_signers = {
            a.GetPubKey(), b.GetPubKey(), c.GetPubKey()};
        config.threshold = 2;
        std::string error;
        BOOST_REQUIRE(node::matmul_trusted::Configure(
            std::move(config), /*trusted_mirror=*/true,
            /*serve=*/false, std::chrono::milliseconds{20}, error));
        if (with_runtime_store) {
            BOOST_REQUIRE(node::matmul_trusted::OpenPersistence(archive, error));
        }
    };

    configure(/*with_runtime_store=*/true);
    BOOST_CHECK_EQUAL(node::matmul_trusted::UnblockedPinMembers(), 3U);
    std::string persist_error;
    BOOST_CHECK(node::matmul_trusted::AddBlocklistedSigner(
                    a.GetPubKey(), persist_error) ==
                matmul::trusted::BlocklistResult::Blocked);
    BOOST_CHECK(persist_error.empty());
    BOOST_CHECK(node::matmul_trusted::IsBlocked(a.GetPubKey()));
    BOOST_CHECK(!node::matmul_trusted::IsAuthoritySigner(a.GetPubKey()));
    BOOST_CHECK_EQUAL(node::matmul_trusted::UnblockedPinMembers(), 2U);
    BOOST_CHECK(node::matmul_trusted::PinQuorumReachable());
    BOOST_CHECK(node::matmul_trusted::AddBlocklistedSigner(
                    b.GetPubKey(), persist_error) ==
                matmul::trusted::BlocklistResult::WouldDisablePinQuorum);
    BOOST_CHECK(!node::matmul_trusted::IsBlocked(b.GetPubKey()));

    matmul::trusted::ExactReplayStatement statement;
    statement.chain_id = chain;
    statement.block_hash = block;
    statement.block_height = 88;
    statement.replay_authority_context = context;
    const auto att_a{matmul::trusted::SignStatement(statement, a)};
    const auto att_b{matmul::trusted::SignStatement(statement, b)};
    const auto att_c{matmul::trusted::SignStatement(statement, c)};
    BOOST_REQUIRE(att_a && att_b && att_c);
    BOOST_CHECK(node::matmul_trusted::Add(*att_a, block, 88) ==
                matmul::trusted::AddResult::BlocklistedSigner);
    BOOST_CHECK(node::matmul_trusted::Add(*att_b, block, 88) ==
                matmul::trusted::AddResult::Accepted);
    BOOST_CHECK(!node::matmul_trusted::HasQuorum(block, 88));
    BOOST_CHECK(!node::matmul_trusted::SkipExactReplayForGpuAttestation(
        node::matmul_trusted::HasQuorum(block, 88),
        /*trusted_mirror=*/true));
    BOOST_CHECK(node::matmul_trusted::Add(*att_c, block, 88) ==
                matmul::trusted::AddResult::Accepted);
    BOOST_CHECK(node::matmul_trusted::HasQuorum(block, 88));
    BOOST_CHECK(node::matmul_trusted::SkipExactReplayForGpuAttestation(
        true, /*trusted_mirror=*/true));
    BOOST_CHECK(node::matmul_trusted::HistoricalExactReplayCoveredByPinQuorum(
        /*trusted_mirror=*/true, /*direct_quorum=*/true,
        /*frontier_covers=*/false));

    node::matmul_trusted::ResetForTest();
    configure(/*with_runtime_store=*/true);
    BOOST_CHECK(node::matmul_trusted::IsBlocked(a.GetPubKey()));
    BOOST_CHECK_EQUAL(node::matmul_trusted::UnblockedPinMembers(), 2U);
    BOOST_CHECK(node::matmul_trusted::Add(*att_a, block, 88) ==
                matmul::trusted::AddResult::BlocklistedSigner);
}

BOOST_AUTO_TEST_CASE(blocklist_init_fail_closed_below_threshold)
{
    RuntimeReset reset;
    const CKey a{NewKey()};
    const CKey b{NewKey()};
    ArgsManager args;
    args.ForceSetArg("-matmulvalidation", "trusted");
    UniValue keys{UniValue::VARR};
    keys.push_back(HexPubKey(a));
    keys.push_back(HexPubKey(b));
    args.ForceSetArgV("-matmultrustedpubkey", keys);
    args.ForceSetArg("-matmultrustedthreshold", 2);
    UniValue blocked{UniValue::VARR};
    blocked.push_back(HexPubKey(a));
    args.ForceSetArgV("-matmulattestationblocklist", blocked);
    InitErrorCapture capture;
    BOOST_CHECK(!AppInitParameterInteraction(args));
    BOOST_CHECK(capture.LastError().find("unblocked pin") !=
                std::string::npos);
}

BOOST_AUTO_TEST_CASE(matmulattestationserve_default_off_without_signer_or_trusted)
{
    using node::matmul_trusted::DefaultMatMulAttestationServe;
    BOOST_CHECK(!DefaultMatMulAttestationServe(
        /*has_local_signer=*/false, /*trusted_mirror=*/false));
    BOOST_CHECK(DefaultMatMulAttestationServe(true, false));
    BOOST_CHECK(DefaultMatMulAttestationServe(false, true));
    BOOST_CHECK(DefaultMatMulAttestationServe(true, true));

    // Plain consensus, no pin, no WIF, serve unset → not configured, not serving.
    {
        RuntimeReset reset;
        ArgsManager args;
        args.ForceSetArg("-matmulvalidation", "consensus");
        InitErrorCapture capture;
        BOOST_REQUIRE(AppInitParameterInteraction(args));
        BOOST_CHECK(capture.LastError().empty());
        BOOST_CHECK(!node::matmul_trusted::IsConfigured());
        BOOST_CHECK(!node::matmul_trusted::HasLocalSigner());
        BOOST_CHECK(!node::matmul_trusted::IsTrustedMirror());
        BOOST_CHECK(!node::matmul_trusted::ServesAttestations());
    }

    // Consensus + telemetry pin, no local WIF, serve unset → default 0.
    {
        RuntimeReset reset;
        ArgsManager args;
        args.ForceSetArg("-matmulvalidation", "consensus");
        UniValue keys{UniValue::VARR};
        keys.push_back(HexPubKey(NewKey()));
        args.ForceSetArgV("-matmultrustedpubkey", keys);
        InitErrorCapture capture;
        BOOST_REQUIRE(AppInitParameterInteraction(args));
        std::string error;
        BOOST_REQUIRE(node::matmul_trusted::FinalizeConfiguration(error));
        BOOST_CHECK(node::matmul_trusted::IsConfigured());
        BOOST_CHECK(!node::matmul_trusted::HasLocalSigner());
        BOOST_CHECK(!node::matmul_trusted::IsTrustedMirror());
        BOOST_CHECK(!node::matmul_trusted::ServesAttestations());
    }

    // Local signing key, serve unset → default 1.
    // Regression: AppInitParameterInteraction used to call CKey::GetPubKey()
    // on this WIF before bitcoind constructed ECC_Context. That null-derefs
    // secp256k1_context_sign (<node> 0.34, kernel segfault at 0 in
    // secp256k1_ec_pubkey_create, ~1.2s after start). Staging must not
    // derive the pubkey; FinalizeConfiguration does that after ECC_Start.
    {
        RuntimeReset reset;
        const CKey signer{NewKey()};
        ArgsManager args;
        args.ForceSetArg("-matmulvalidation", "consensus");
        args.ForceSetArg("-matmulattestationsignerkey", EncodeSecret(signer));
        InitErrorCapture capture;
        BOOST_REQUIRE(AppInitParameterInteraction(args));
        std::string error;
        BOOST_REQUIRE(node::matmul_trusted::FinalizeConfiguration(error));
        BOOST_CHECK(node::matmul_trusted::HasLocalSigner());
        BOOST_CHECK(!node::matmul_trusted::IsTrustedMirror());
        BOOST_CHECK(node::matmul_trusted::ServesAttestations());
    }

    // Trusted mirror, serve unset → default 1.
    {
        RuntimeReset reset;
        ArgsManager args;
        args.ForceSetArg("-matmulvalidation", "trusted");
        UniValue keys{UniValue::VARR};
        keys.push_back(HexPubKey(NewKey()));
        keys.push_back(HexPubKey(NewKey()));
        args.ForceSetArgV("-matmultrustedpubkey", keys);
        args.ForceSetArg("-matmultrustedthreshold", 2);
        InitErrorCapture capture;
        BOOST_REQUIRE(AppInitParameterInteraction(args));
        std::string error;
        BOOST_REQUIRE(node::matmul_trusted::FinalizeConfiguration(error));
        BOOST_CHECK(node::matmul_trusted::IsTrustedMirror());
        BOOST_CHECK(!node::matmul_trusted::HasLocalSigner());
        BOOST_CHECK(node::matmul_trusted::ServesAttestations());
    }

    // Consensus signer may isolate: explicit serve=0 with a local WIF.
    {
        RuntimeReset reset;
        const CKey signer{NewKey()};
        ArgsManager args;
        args.ForceSetArg("-matmulvalidation", "consensus");
        args.ForceSetArg("-matmulattestationsignerkey", EncodeSecret(signer));
        args.ForceSetArg("-matmulattestationserve", "0");
        InitErrorCapture capture;
        BOOST_REQUIRE(AppInitParameterInteraction(args));
        std::string error;
        BOOST_REQUIRE(node::matmul_trusted::FinalizeConfiguration(error));
        BOOST_CHECK(node::matmul_trusted::HasLocalSigner());
        BOOST_CHECK(!node::matmul_trusted::ServesAttestations());
    }
}

BOOST_AUTO_TEST_SUITE_END()
