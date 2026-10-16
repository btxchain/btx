// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/identity.h>
#include <modelnet/pq_delegation.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_035_identity_tests, BasicTestingSetup)

namespace {

struct Keys {
    std::vector<unsigned char> pk;
    std::vector<unsigned char> sk;
};

Keys MakeKeys()
{
    Keys k;
    std::string err;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(k.pk, k.sk, err));
    BOOST_REQUIRE_EQUAL(k.pk.size(), modelnet::MLDSA44_PK);
    return k;
}

Span<const unsigned char> PkSpan(const Keys& k)
{
    return Span<const unsigned char>{k.pk.data(), k.pk.size()};
}

Span<const unsigned char> SkSpan(const Keys& k)
{
    return Span<const unsigned char>{k.sk.data(), k.sk.size()};
}

Span<const unsigned char> AsBytes(const std::string& s)
{
    return Span<const unsigned char>{reinterpret_cast<const unsigned char*>(s.data()), s.size()};
}

std::vector<unsigned char> Sign(const Keys& k, const std::string& msg)
{
    std::vector<unsigned char> sig;
    std::string err;
    BOOST_REQUIRE(modelnet::SignMlDsa44(SkSpan(k), AsBytes(msg), sig, err));
    BOOST_REQUIRE_EQUAL(sig.size(), modelnet::MLDSA44_SIG);
    return sig;
}

modelnet::CapabilityWindow Window(int64_t not_before, int64_t not_after, uint32_t depth,
                                  std::vector<std::string> audiences, std::vector<std::string> perms,
                                  std::vector<std::pair<std::string, uint64_t>> limits)
{
    modelnet::CapabilityWindow w;
    w.not_before_ms = not_before;
    w.not_after_ms = not_after;
    w.remaining_depth = depth;
    w.audience_ids = std::move(audiences);
    w.permissions = std::move(perms);
    w.limits = std::move(limits);
    return w;
}

} // namespace

BOOST_AUTO_TEST_CASE(create_root_epoch_zero_and_duplicate_fails)
{
    const Keys a = MakeKeys();
    const Keys b = MakeKeys();
    modelnet::IdentityChain chain;
    std::string err = "stale";
    modelnet::Digest48 id_a;
    BOOST_REQUIRE(chain.CreateRoot(PkSpan(a), id_a, err));
    BOOST_CHECK(id_a == modelnet::ResearchIdentityId(PkSpan(a)));
    BOOST_CHECK(id_a.Hex().size() == 96);

    uint64_t epoch = 99;
    BOOST_REQUIRE(chain.CurrentEpoch(id_a, epoch, err));
    BOOST_CHECK_EQUAL(epoch, uint64_t{0});
    std::vector<unsigned char> pk;
    BOOST_REQUIRE(chain.CurrentPublicKey(id_a, pk, err));
    BOOST_CHECK(pk == a.pk);

    BOOST_CHECK(!chain.CreateRoot(PkSpan(a), id_a, err));
    BOOST_CHECK_EQUAL(err, "BTX035_IDENTITY_CONFLICT");
    BOOST_CHECK(chain.CurrentEpoch(id_a, epoch, err));
    BOOST_CHECK_EQUAL(epoch, uint64_t{0});

    std::vector<unsigned char> short_pk(16, 1);
    modelnet::Digest48 ignored;
    BOOST_CHECK(!chain.CreateRoot(Span<const unsigned char>{short_pk.data(), short_pk.size()}, ignored, err));
    BOOST_CHECK_EQUAL(err, "BTX035_KEY_LENGTH");

    modelnet::Digest48 id_b;
    BOOST_REQUIRE(chain.CreateRoot(PkSpan(b), id_b, err));
    BOOST_CHECK(id_b == modelnet::ResearchIdentityId(PkSpan(b)));
    BOOST_CHECK(id_b != id_a);
}

BOOST_AUTO_TEST_CASE(advance_epoch_possession_proof)
{
    const Keys old_k = MakeKeys();
    const Keys next_k = MakeKeys();
    const Keys other_k = MakeKeys();
    modelnet::IdentityChain chain;
    std::string err;
    modelnet::Digest48 root;
    BOOST_REQUIRE(chain.CreateRoot(PkSpan(old_k), root, err));

    const std::string proof = std::string("BTX/035/NewKeyProof/v1.1\n") + root.Hex() + "\n1";
    BOOST_CHECK_EQUAL(proof, modelnet::NewKeyProofMessage(root, 1));
    const std::vector<unsigned char> sig = Sign(next_k, proof);

    BOOST_CHECK(!chain.AdvanceEpoch(root, PkSpan(next_k), 2, sig, err));
    BOOST_CHECK_EQUAL(err, "BTX035_STATE_CONFLICT");
    uint64_t epoch = 99;
    BOOST_REQUIRE(chain.CurrentEpoch(root, epoch, err));
    BOOST_CHECK_EQUAL(epoch, uint64_t{0});

    BOOST_CHECK(!chain.AdvanceEpoch(root, PkSpan(old_k), 1, sig, err));
    BOOST_CHECK_EQUAL(err, "BTX035_CONFLICT");

    const std::vector<unsigned char> wrong_signer = Sign(old_k, proof);
    BOOST_CHECK(!chain.AdvanceEpoch(root, PkSpan(next_k), 1, wrong_signer, err));
    BOOST_CHECK_EQUAL(err, "BTX035_SIGNATURE_INVALID");

    const std::string other_msg = modelnet::NewKeyProofMessage(root, 2);
    const std::vector<unsigned char> wrong_epoch_sig = Sign(next_k, other_msg);
    BOOST_CHECK(!chain.AdvanceEpoch(root, PkSpan(next_k), 1, wrong_epoch_sig, err));
    BOOST_CHECK_EQUAL(err, "BTX035_SIGNATURE_INVALID");

    modelnet::Digest48 missing;
    BOOST_CHECK(!chain.AdvanceEpoch(missing, PkSpan(next_k), 1, sig, err));
    BOOST_CHECK_EQUAL(err, "BTX035_IDENTITY_UNKNOWN");

    BOOST_REQUIRE(chain.AdvanceEpoch(root, PkSpan(next_k), 1, sig, err));
    BOOST_REQUIRE(chain.CurrentEpoch(root, epoch, err));
    BOOST_CHECK_EQUAL(epoch, uint64_t{1});
    std::vector<unsigned char> pk;
    BOOST_REQUIRE(chain.CurrentPublicKey(root, pk, err));
    BOOST_CHECK(pk == next_k.pk);
    BOOST_CHECK(root == modelnet::ResearchIdentityId(PkSpan(old_k)));
    BOOST_CHECK(root != modelnet::ResearchIdentityId(PkSpan(next_k)));

    const std::string proof2 = modelnet::NewKeyProofMessage(root, 2);
    const std::vector<unsigned char> sig2 = Sign(other_k, proof2);
    BOOST_REQUIRE(chain.AdvanceEpoch(root, PkSpan(other_k), 2, sig2, err));
    BOOST_CHECK(chain.CurrentEpoch(root, epoch, err));
    BOOST_CHECK_EQUAL(epoch, uint64_t{2});
}

BOOST_AUTO_TEST_CASE(revoked_current_key_blocks_advance_and_sign)
{
    const Keys a = MakeKeys();
    const Keys b = MakeKeys();
    const Keys c = MakeKeys();
    modelnet::IdentityChain chain;
    std::string err;
    modelnet::Digest48 root;
    BOOST_REQUIRE(chain.CreateRoot(PkSpan(a), root, err));

    const std::string msg = "BTX/035/typed-sign";
    const std::vector<unsigned char> sig_a = Sign(a, msg);
    BOOST_REQUIRE(chain.SignCheck(root, AsBytes(msg), sig_a, err));

    const modelnet::Digest48 id_b = modelnet::IdentityKeyId(PkSpan(b));
    BOOST_REQUIRE(chain.RevokeKey(root, id_b, 5000, err));
    bool revoked = false;
    BOOST_REQUIRE(chain.KeyRevoked(root, id_b, revoked, err));
    BOOST_CHECK(revoked);
    const std::string proof_b = modelnet::NewKeyProofMessage(root, 1);
    const std::vector<unsigned char> sig_b = Sign(b, proof_b);
    BOOST_CHECK(!chain.AdvanceEpoch(root, PkSpan(b), 1, sig_b, err));
    BOOST_CHECK_EQUAL(err, "BTX035_REVOKED");

    const modelnet::Digest48 id_a = modelnet::IdentityKeyId(PkSpan(a));
    BOOST_REQUIRE(chain.RevokeKey(root, id_a, 1000, err));
    BOOST_REQUIRE(chain.KeyRevoked(root, id_a, revoked, err));
    BOOST_CHECK(revoked);
    BOOST_CHECK(!chain.SignCheck(root, AsBytes(msg), sig_a, err));
    BOOST_CHECK_EQUAL(err, "BTX035_REVOKED");
    BOOST_CHECK(!chain.AdvanceEpoch(root, PkSpan(c), 1, Sign(c, proof_b), err));
    BOOST_CHECK_EQUAL(err, "BTX035_REVOKED");

    uint64_t epoch = 99;
    BOOST_REQUIRE(chain.CurrentEpoch(root, epoch, err));
    BOOST_CHECK_EQUAL(epoch, uint64_t{0});

    BOOST_CHECK(modelnet::AcceptFresh(1000, 1000, 0));
    BOOST_CHECK(modelnet::AcceptFresh(1000, 1500, 500));
    BOOST_CHECK(!modelnet::AcceptFresh(1000, 1501, 500));
    BOOST_CHECK(!modelnet::AcceptFresh(1000, 1000, -1));
    BOOST_CHECK(!modelnet::AcceptFresh(-1, 0, 10));
}

BOOST_AUTO_TEST_CASE(recovery_waits_then_installs_without_old_key)
{
    const Keys lost = MakeKeys();
    const Keys recovered = MakeKeys();
    modelnet::IdentityChain chain;
    std::string err;
    modelnet::Digest48 root;
    BOOST_REQUIRE(chain.CreateRoot(PkSpan(lost), root, err));
    BOOST_REQUIRE(chain.RevokeKey(root, modelnet::IdentityKeyId(PkSpan(lost)), 10, err));

    BOOST_CHECK(!chain.ActivateRecovery(root, 1000, err));
    BOOST_CHECK_EQUAL(err, "BTX035_RECOVERY_REQUIRED");

    BOOST_REQUIRE(chain.BeginRecovery(root, PkSpan(recovered), 1000, 500, err));
    BOOST_CHECK(!chain.BeginRecovery(root, PkSpan(recovered), 1000, 500, err));
    BOOST_CHECK_EQUAL(err, "BTX035_IDENTITY_CONFLICT");

    BOOST_CHECK(!chain.ActivateRecovery(root, 1499, err));
    BOOST_CHECK_EQUAL(err, "BTX035_RECOVERY_WAIT");
    uint64_t epoch = 99;
    BOOST_REQUIRE(chain.CurrentEpoch(root, epoch, err));
    BOOST_CHECK_EQUAL(epoch, uint64_t{0});

    BOOST_REQUIRE(chain.ActivateRecovery(root, 1500, err));
    BOOST_REQUIRE(chain.CurrentEpoch(root, epoch, err));
    BOOST_CHECK_EQUAL(epoch, uint64_t{1});
    std::vector<unsigned char> pk;
    BOOST_REQUIRE(chain.CurrentPublicKey(root, pk, err));
    BOOST_CHECK(pk == recovered.pk);
    BOOST_CHECK(root == modelnet::ResearchIdentityId(PkSpan(lost)));

    const std::string msg = "recovered-sign";
    const std::vector<unsigned char> sig = Sign(recovered, msg);
    BOOST_REQUIRE(chain.SignCheck(root, AsBytes(msg), sig, err));
    BOOST_CHECK(!chain.SignCheck(root, AsBytes(msg), Sign(lost, msg), err));
    BOOST_CHECK_EQUAL(err, "BTX035_SIGNATURE_INVALID");

    BOOST_CHECK(!chain.ActivateRecovery(root, 2000, err));
    BOOST_CHECK_EQUAL(err, "BTX035_RECOVERY_REQUIRED");
}

BOOST_AUTO_TEST_CASE(attenuate_narrows_and_rejects_widening)
{
    const modelnet::CapabilityWindow parent = Window(
        0, 1000, 2, {"aud-a", "aud-b"}, {"read", "write"}, {{"bytes", 100}, {"calls", 10}});
    const modelnet::CapabilityWindow child = Window(
        10, 500, 1, {"aud-a"}, {"read"}, {{"bytes", 50}, {"calls", 10}});
    std::string err = "stale";
    BOOST_CHECK(modelnet::Attenuate(parent, child, err));

    modelnet::CapabilityWindow later_parent = parent;
    later_parent.not_before_ms = 100;
    modelnet::CapabilityWindow early = child;
    early.not_before_ms = 50;
    BOOST_CHECK(!modelnet::Attenuate(later_parent, early, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ATTENUATE");

    modelnet::CapabilityWindow late = child;
    late.not_after_ms = 1001;
    BOOST_CHECK(!modelnet::Attenuate(parent, late, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ATTENUATE");

    modelnet::CapabilityWindow same_depth = child;
    same_depth.remaining_depth = 2;
    BOOST_CHECK(!modelnet::Attenuate(parent, same_depth, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ATTENUATE");

    modelnet::CapabilityWindow extra_aud = child;
    extra_aud.audience_ids.push_back("aud-c");
    BOOST_CHECK(!modelnet::Attenuate(parent, extra_aud, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ATTENUATE");

    modelnet::CapabilityWindow extra_perm = child;
    extra_perm.permissions.push_back("admin");
    BOOST_CHECK(!modelnet::Attenuate(parent, extra_perm, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ATTENUATE");

    modelnet::CapabilityWindow dropped = child;
    dropped.limits = {{"bytes", 50}};
    BOOST_CHECK(!modelnet::Attenuate(parent, dropped, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ATTENUATE");

    modelnet::CapabilityWindow wider = child;
    wider.limits = {{"bytes", 101}, {"calls", 10}};
    BOOST_CHECK(!modelnet::Attenuate(parent, wider, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ATTENUATE");

    modelnet::CapabilityWindow zero_depth = parent;
    zero_depth.remaining_depth = 0;
    BOOST_CHECK(!modelnet::Attenuate(zero_depth, child, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ATTENUATE");
}

BOOST_AUTO_TEST_CASE(signature_valid_is_not_resource_ownership)
{
    const Keys owner = MakeKeys();
    const Keys signer = MakeKeys();
    const std::string owner_id = modelnet::ResearchIdentityId(PkSpan(owner)).Hex();
    const std::string signer_id = modelnet::ResearchIdentityId(PkSpan(signer)).Hex();
    BOOST_CHECK(owner_id != signer_id);

    const std::string msg = "resource-bytes";
    const std::vector<unsigned char> sig = Sign(signer, msg);
    std::string err;
    BOOST_REQUIRE(modelnet::SignatureValid(PkSpan(signer), AsBytes(msg), sig, err));
    BOOST_CHECK(modelnet::ResourceOwner(owner_id, owner_id));
    BOOST_CHECK(!modelnet::ResourceOwner(owner_id, signer_id));
    BOOST_CHECK(!modelnet::ResourceOwner("aa", "aa"));

    std::vector<unsigned char> flipped = sig;
    flipped[0] ^= 0x01;
    BOOST_CHECK(!modelnet::SignatureValid(PkSpan(signer), AsBytes(msg), flipped, err));
    BOOST_CHECK_EQUAL(err, "BTX035_SIGNATURE_INVALID");
}

BOOST_AUTO_TEST_CASE(research_key_cannot_spend_wallet)
{
    BOOST_CHECK(!modelnet::ServiceKeyMayAuthorizeWalletSpend());
    BOOST_CHECK(!modelnet::ResearchMaySpendWallet());
    BOOST_CHECK_EQUAL(modelnet::ResearchMaySpendWallet(), modelnet::ServiceKeyMayAuthorizeWalletSpend());
}

BOOST_AUTO_TEST_SUITE_END()
