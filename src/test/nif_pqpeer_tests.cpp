// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/identity.h>
#include <modelnet/nif_pqpeer/nif_pqpeer.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

struct SignedPeer {
    std::vector<unsigned char> pk;
    std::vector<unsigned char> sk;
    std::vector<unsigned char> msg;
    std::vector<unsigned char> sig;
};

SignedPeer MakeSigned(const std::string& text)
{
    SignedPeer out;
    std::string err;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(out.pk, out.sk, err));
    out.msg.assign(text.begin(), text.end());
    BOOST_REQUIRE(modelnet::SignMlDsa44(out.sk, out.msg, out.sig, err));
    BOOST_REQUIRE_EQUAL(out.pk.size(), modelnet::kNifPqPeerPubkeyBytes);
    BOOST_REQUIRE_EQUAL(out.sig.size(), modelnet::kNifPqPeerSignatureBytes);
    return out;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(nif_pqpeer_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_peer_stores_nothing)
{
    modelnet::NifPqPeer engine;
    std::string err = "stale";
    const std::vector<unsigned char> pubkey(modelnet::kNifPqPeerPubkeyBytes, 0);
    const std::vector<unsigned char> message{'m'};
    const std::vector<unsigned char> signature(modelnet::kNifPqPeerSignatureBytes, 0);

    BOOST_CHECK(!engine.Admit("", pubkey, message, signature, false, err));
    BOOST_CHECK_EQUAL(err, "PEER");
    BOOST_CHECK(!engine.authenticated());
    BOOST_CHECK(!engine.authority());
    BOOST_CHECK(!engine.hint_only());
    BOOST_CHECK_EQUAL(engine.ranks(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(engine.connected(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(engine.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!engine.Admit("", pubkey, message, signature, true, err));
    BOOST_CHECK_EQUAL(err, "PEER");
    BOOST_CHECK(!engine.hint_only());
    BOOST_CHECK_EQUAL(engine.ranks(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(engine.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(engine.physical_hosts(), static_cast<int64_t>(1));
}

BOOST_AUTO_TEST_CASE(bad_key_length_stores_nothing)
{
    modelnet::NifPqPeer engine;
    std::string err;
    const SignedPeer signed_peer = MakeSigned("length");
    const std::vector<unsigned char> message = signed_peer.msg;
    std::vector<unsigned char> short_pk = signed_peer.pk;
    short_pk.pop_back();
    std::vector<unsigned char> short_sig = signed_peer.sig;
    short_sig.pop_back();
    std::vector<unsigned char> long_pk = signed_peer.pk;
    long_pk.push_back(0);
    std::vector<unsigned char> long_sig = signed_peer.sig;
    long_sig.push_back(0);

    BOOST_CHECK(!engine.Admit("peer-a", short_pk, message, signed_peer.sig, false, err));
    BOOST_CHECK_EQUAL(err, "KEY");
    BOOST_CHECK(!engine.Admit("peer-a", signed_peer.pk, message, short_sig, false, err));
    BOOST_CHECK_EQUAL(err, "KEY");
    BOOST_CHECK(!engine.Admit("peer-a", long_pk, message, signed_peer.sig, false, err));
    BOOST_CHECK_EQUAL(err, "KEY");
    BOOST_CHECK(!engine.Admit("peer-a", signed_peer.pk, message, long_sig, true, err));
    BOOST_CHECK_EQUAL(err, "KEY");

    BOOST_CHECK(!engine.authenticated());
    BOOST_CHECK(!engine.authority());
    BOOST_CHECK(!engine.hint_only());
    BOOST_CHECK_EQUAL(engine.ranks(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(engine.connected(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(engine.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!engine.Admit("peer-a", short_pk, message, signed_peer.sig, false, err));
    BOOST_CHECK_EQUAL(err, "KEY");
    BOOST_CHECK_EQUAL(engine.ranks(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(multicast_valid_signature_is_hint_not_authority)
{
    modelnet::NifPqPeer engine;
    std::string err;
    const SignedPeer signed_peer = MakeSigned("hint");
    BOOST_CHECK(modelnet::VerifyMlDsa44(signed_peer.pk, signed_peer.msg, signed_peer.sig));

    BOOST_CHECK(!engine.Admit("hint-peer", signed_peer.pk, signed_peer.msg, signed_peer.sig, true, err));
    BOOST_CHECK_EQUAL(err, "HINT");
    BOOST_CHECK(engine.hint_only());
    BOOST_CHECK(!engine.authenticated());
    BOOST_CHECK(!engine.authority());
    BOOST_CHECK_EQUAL(engine.ranks(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(engine.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(engine.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!engine.qualified());
    BOOST_CHECK_EQUAL(engine.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!engine.Connect("hint-peer", err));
    BOOST_CHECK_EQUAL(err, "AUTH");
    BOOST_CHECK_EQUAL(engine.connected(), static_cast<int64_t>(0));

    BOOST_CHECK(!engine.Admit("hint-peer", signed_peer.pk, signed_peer.msg, signed_peer.sig, false, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK(engine.hint_only());
    BOOST_CHECK(!engine.authenticated());
    BOOST_CHECK(!engine.authority());
    BOOST_CHECK_EQUAL(engine.ranks(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(engine.hosts(), static_cast<int64_t>(1));
}

BOOST_AUTO_TEST_CASE(generated_signature_authenticates_one_peer)
{
    modelnet::NifPqPeer engine;
    std::string err;
    const SignedPeer signed_peer = MakeSigned("auth");
    BOOST_CHECK(modelnet::VerifyMlDsa44(signed_peer.pk, signed_peer.msg, signed_peer.sig));

    BOOST_CHECK(engine.Admit("peer-a", signed_peer.pk, signed_peer.msg, signed_peer.sig, false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(engine.authenticated());
    BOOST_CHECK(engine.authority());
    BOOST_CHECK(!engine.hint_only());
    BOOST_CHECK(!engine.qualified());
    BOOST_CHECK_EQUAL(engine.ranks(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(engine.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(engine.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(engine.connected(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(engine.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!engine.launched());
    BOOST_CHECK(!engine.gpu());
    BOOST_CHECK(!engine.broadcast());
    BOOST_CHECK_EQUAL(engine.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(engine.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(bad_signature_is_auth_and_stores_nothing)
{
    modelnet::NifPqPeer engine;
    std::string err;
    const SignedPeer signed_peer = MakeSigned("reject");
    std::vector<unsigned char> bad_sig = signed_peer.sig;
    bad_sig[0] ^= 0x01;
    BOOST_CHECK(!modelnet::VerifyMlDsa44(signed_peer.pk, signed_peer.msg, bad_sig));
    BOOST_REQUIRE_EQUAL(bad_sig.size(), modelnet::kNifPqPeerSignatureBytes);

    BOOST_CHECK(!engine.Admit("peer-a", signed_peer.pk, signed_peer.msg, bad_sig, false, err));
    BOOST_CHECK_EQUAL(err, "AUTH");
    BOOST_CHECK(!engine.authenticated());
    BOOST_CHECK(!engine.authority());
    BOOST_CHECK(!engine.hint_only());
    BOOST_CHECK_EQUAL(engine.ranks(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(engine.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!engine.Admit("peer-a", signed_peer.pk, signed_peer.msg, bad_sig, false, err));
    BOOST_CHECK_EQUAL(err, "AUTH");
    BOOST_CHECK_EQUAL(engine.ranks(), static_cast<int64_t>(0));

    BOOST_CHECK(!engine.Connect("peer-a", err));
    BOOST_CHECK_EQUAL(err, "AUTH");
    BOOST_CHECK_EQUAL(engine.connected(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(replay_keeps_first_authenticated_peer)
{
    modelnet::NifPqPeer engine;
    std::string err;
    const SignedPeer signed_peer = MakeSigned("once");
    const std::vector<unsigned char> other_msg{'o', 't', 'h', 'e', 'r'};
    std::vector<unsigned char> other_sig;
    BOOST_REQUIRE(modelnet::SignMlDsa44(signed_peer.sk, other_msg, other_sig, err));

    BOOST_CHECK(engine.Admit("peer-a", signed_peer.pk, signed_peer.msg, signed_peer.sig, false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!engine.Admit("peer-a", signed_peer.pk, other_msg, other_sig, false, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(engine.authenticated());
    BOOST_CHECK(engine.authority());
    BOOST_CHECK(!engine.hint_only());
    BOOST_CHECK_EQUAL(engine.ranks(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(engine.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(engine.physical_hosts(), static_cast<int64_t>(1));
}

BOOST_AUTO_TEST_CASE(two_authenticated_peers_keep_one_host)
{
    modelnet::NifPqPeer engine;
    std::string err;
    const SignedPeer first = MakeSigned("first");
    const SignedPeer second = MakeSigned("second");

    BOOST_CHECK(engine.Admit("peer-a", first.pk, first.msg, first.sig, false, err));
    BOOST_CHECK(engine.Admit("peer-b", second.pk, second.msg, second.sig, false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(engine.authenticated());
    BOOST_CHECK(engine.authority());
    BOOST_CHECK_EQUAL(engine.ranks(), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(engine.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(engine.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!engine.qualified());

    BOOST_CHECK(engine.Connect("peer-a", err));
    BOOST_CHECK(engine.Connect("peer-b", err));
    BOOST_CHECK_EQUAL(engine.connected(), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(engine.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(engine.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(engine.ranks(), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(engine.bytes_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(connect_once_then_replay)
{
    modelnet::NifPqPeer engine;
    std::string err;
    const SignedPeer signed_peer = MakeSigned("connect");

    BOOST_CHECK(!engine.Connect("missing-peer", err));
    BOOST_CHECK_EQUAL(err, "AUTH");
    BOOST_CHECK_EQUAL(engine.connected(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(engine.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(engine.Admit("peer-a", signed_peer.pk, signed_peer.msg, signed_peer.sig, false, err));
    BOOST_CHECK(engine.Connect("peer-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(engine.connected(), static_cast<int64_t>(1));

    BOOST_CHECK(!engine.Connect("peer-a", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(engine.connected(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(engine.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(engine.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!engine.launched());
    BOOST_CHECK(!engine.gpu());
    BOOST_CHECK(!engine.broadcast());
}

BOOST_AUTO_TEST_CASE(wan_and_scan_refuse)
{
    modelnet::NifPqPeer engine;
    std::string err = "stale";
    BOOST_CHECK(!engine.Wan(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_NO_ROUTE);
    BOOST_CHECK_EQUAL(err, "NO_ROUTE");
    BOOST_CHECK_EQUAL(engine.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!engine.Scan(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_NOT_SCAN);
    BOOST_CHECK_EQUAL(err, "NOT_SCAN");
    BOOST_CHECK_EQUAL(engine.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(engine.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(engine.physical_hosts(), static_cast<int64_t>(1));

    const SignedPeer signed_peer = MakeSigned("route");
    BOOST_CHECK(engine.Admit("peer-a", signed_peer.pk, signed_peer.msg, signed_peer.sig, false, err));
    BOOST_CHECK(engine.Connect("peer-a", err));
    BOOST_CHECK(!engine.Wan(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_NO_ROUTE);
    BOOST_CHECK(!engine.Scan(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_NOT_SCAN);
    BOOST_CHECK_EQUAL(engine.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(engine.connected(), static_cast<int64_t>(1));
}

BOOST_AUTO_TEST_CASE(idle_flags_stay_false)
{
    modelnet::NifPqPeer engine;
    BOOST_CHECK(!engine.launched());
    BOOST_CHECK(!engine.gpu());
    BOOST_CHECK(!engine.broadcast());
    BOOST_CHECK(!engine.qualified());
    BOOST_CHECK(!engine.authenticated());
    BOOST_CHECK(!engine.authority());
    BOOST_CHECK(!engine.hint_only());
    BOOST_CHECK_EQUAL(engine.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(engine.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(engine.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(engine.ranks(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(engine.connected(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(engine.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(engine.physical_hosts(), static_cast<int64_t>(1));
}

BOOST_AUTO_TEST_SUITE_END()
