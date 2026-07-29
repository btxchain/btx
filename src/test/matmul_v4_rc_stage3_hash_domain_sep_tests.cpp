// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_hash_domain_sep.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

namespace ds = matmul::v4::rc::stage3::domain_sep;

BOOST_FIXTURE_TEST_SUITE(
    matmul_v4_rc_stage3_hash_domain_sep_tests,
    BasicTestingSetup)

// (b) The V8 registry is role-clean: no FS tag and no binding tag share a
// first-byte class. The legacy registry reproduces the exact overlap defect the
// doc found (ASCII "BTX_" first byte shared by FS draws and binding commits).
BOOST_AUTO_TEST_CASE(registry_first_byte_classes_are_disjoint)
{
    BOOST_CHECK(ds::RegistryFirstByteClassesDisjoint(
        ds::kRegistryV8, ds::kRegistryV8Size));
    BOOST_CHECK(!ds::RegistryFirstByteClassesDisjoint(
        ds::kRegistryLegacyDefect, ds::kRegistryLegacyDefectSize));

    // Spot-check the role bytes themselves.
    BOOST_CHECK(ds::InFsFirstByteClass(ds::kRoleFs));
    BOOST_CHECK(!ds::InBindFirstByteClass(ds::kRoleFs));
    BOOST_CHECK(ds::InBindFirstByteClass(ds::kRoleBindAscii));
    BOOST_CHECK(!ds::InFsFirstByteClass(ds::kRoleBindAscii));

    // Every V8 site's declared first byte lands in its own role's class.
    for (size_t i = 0; i < ds::kRegistryV8Size; ++i) {
        const auto& s = ds::kRegistryV8[i];
        if (s.role == ds::RoleClass::kFs) {
            BOOST_CHECK(ds::InFsFirstByteClass(s.first_byte));
        } else if (s.role == ds::RoleClass::kBind) {
            BOOST_CHECK(ds::InBindFirstByteClass(s.first_byte));
        }
    }
}

// (c) Cross-domain confusion: an FS digest's preimage (first byte 0xF5) reused
// as a binding commitment MUST be rejected, and vice versa.
BOOST_AUTO_TEST_CASE(cross_domain_confusion_is_rejected)
{
    // An FS absorb preimage: 0xF5 ‖ "BTX_RC_FS_V1" ‖ body.
    std::vector<uint8_t> fs_preimage;
    fs_preimage.push_back(ds::kRoleFs);
    const char* tag = "BTX_RC_FS_V1";
    fs_preimage.insert(fs_preimage.end(), tag, tag + 12);
    fs_preimage.push_back(0xDE);

    std::string why;
    BOOST_CHECK(ds::AcceptFsPreimage(fs_preimage, &why));  // valid as FS
    why.clear();
    BOOST_CHECK(!ds::AcceptBindingPreimage(fs_preimage, &why)); // rejected as bind
    BOOST_CHECK_EQUAL(why, "domain_sep:binding_first_byte_not_in_D_BIND");

    // A binding commitment preimage (0xB1 ...) rejected in the FS role.
    std::vector<uint8_t> bind_preimage;
    bind_preimage.push_back(ds::kRoleBindAscii);
    bind_preimage.push_back(0x01);
    why.clear();
    BOOST_CHECK(ds::AcceptBindingPreimage(bind_preimage, &why));
    why.clear();
    BOOST_CHECK(!ds::AcceptFsPreimage(bind_preimage, &why));
    BOOST_CHECK_EQUAL(why, "domain_sep:fs_first_byte_not_in_D_FS");

    // SHOULD guard: a tagged preimage of total length 182 (header alias).
    std::vector<uint8_t> len182(ds::kLegacyHeaderLen, ds::kTileNodeTag);
    why.clear();
    BOOST_CHECK(!ds::AcceptBindingPreimage(len182, &why));
    BOOST_CHECK_EQUAL(why, "domain_sep:tagged_length_182_header_alias");
}

// Wrappers actually produce role-prefixed SHA256d, and role/tag changes change
// the digest (separation is effective, not cosmetic).
BOOST_AUTO_TEST_CASE(wrappers_produce_role_separated_digests)
{
    std::vector<uint8_t> body{0x01, 0x02, 0x03};
    const uint256 fs = ds::Sha256dFs("BTX_RC_FS_V1", body);
    const uint256 bind = ds::Sha256dBindAscii("BTX_RC_FS_V1", body);
    // Same tag+body, different role byte -> different digest.
    BOOST_CHECK(fs != bind);

    // Receipt-internal fixed encoding is exactly 143 bytes and tag 0x04.
    uint256 kids[4]{};
    kids[0].data()[0] = 0xAB;
    const auto enc = ds::EncodeReceiptInternal(
        /*level=*/2, /*node_id=*/7, /*arity=*/4, /*live_mask=*/0x01, kids);
    BOOST_CHECK_EQUAL(enc.size(), ds::kReceiptInternalEncodingLen);
    BOOST_CHECK_EQUAL(enc.front(), ds::kReceiptInternalTag);
    // It is a valid BIND preimage (and not a length-182 alias).
    std::string why;
    BOOST_CHECK(ds::AcceptBindingPreimage(enc, &why));
}

// The audit surface flips exactly the domain-separation flags earned above and
// promotes ZERO consensus bits (O-EXACT / A-FS-INST remain open).
BOOST_AUTO_TEST_CASE(domain_separation_audit_flips_only_earned_flags)
{
    const auto a = ds::AssessHashDomainSeparation();
    BOOST_CHECK_EQUAL(a.version, 8U);
    BOOST_CHECK(a.role_bytes_assigned);
    BOOST_CHECK(a.fs_and_bind_first_byte_classes_disjoint);
    BOOST_CHECK(a.registry_enumerates_call_sites);
    BOOST_CHECK(a.cross_domain_confusion_rejected);
    BOOST_CHECK(a.length_182_guard_present);
    BOOST_CHECK(a.legacy_defect_reproduced);
    // Open obligations stay open.
    BOOST_CHECK(a.pre_activation_only);
    BOOST_CHECK_EQUAL(a.promoted_security_bits, 0U);
    BOOST_CHECK(!ds::kDomainSepPromotesConsensusAuthority);
}

// GOLDEN VECTORS for the transcript-breaking O-ENC change (§2 O-ENC). Pins the
// exact SHA256d bytes of the two real consensus chokepoints under both models:
//   - D_BIND ASCII commitment (CommitShaManifest): legacy vs 0xB1-prefixed V8.
//   - D_FS Fiat-Shamir draw (DeriveFSChallenges): legacy vs 0xF5-prefixed V8.
// The legacy vectors are byte-identical to the shipped transcript; the V8
// vectors differ only by the prepended role byte. A drift in either transcript
// (or a mis-wired role byte) fails these fixed digests.
BOOST_AUTO_TEST_CASE(oenc_transcript_golden_vectors)
{
    // ---- D_BIND ASCII commitment: tag ‖ {01,02,03} ------------------------
    const std::vector<uint8_t> bind_payload{0x01, 0x02, 0x03};
    const uint256 legacy_bind = ds::Sha256dAsciiCommitment(
        ds::RCStage3HashModel::kLegacyV7, "BTX_RC_STAGE3_SHA_MANIFEST_V1",
        bind_payload);
    const uint256 v8_bind = ds::Sha256dAsciiCommitment(
        ds::RCStage3HashModel::kV8, "BTX_RC_STAGE3_SHA_MANIFEST_V1",
        bind_payload);
    BOOST_CHECK_EQUAL(
        legacy_bind.ToString(),
        "d3ca2aad0e2db85d7c16d33625f780e98e5d7c74109afa9c82ac13703ae4c18f");
    BOOST_CHECK_EQUAL(
        v8_bind.ToString(),
        "69ec2073ca9a6a9546260ca82895556655855675af7c2d13cbb3714f01a6b930");
    BOOST_CHECK(legacy_bind != v8_bind);
    // The V8 vector equals the standalone D_BIND wrapper (0xB1 ‖ tag ‖ payload).
    BOOST_CHECK(v8_bind ==
                ds::Sha256dBindAscii("BTX_RC_STAGE3_SHA_MANIFEST_V1", bind_payload));

    // ---- D_FS Fiat-Shamir draw: "BTX_RC_FS_V1" ‖ {0xDE} -------------------
    const char* fs_tag = "BTX_RC_FS_V1";
    std::vector<uint8_t> fs_pre(fs_tag, fs_tag + 12);
    fs_pre.push_back(0xDE);
    const uint256 legacy_fs = ds::Sha256dFsPreimage(
        ds::RCStage3HashModel::kLegacyV7, fs_pre.data(), fs_pre.size());
    const uint256 v8_fs = ds::Sha256dFsPreimage(
        ds::RCStage3HashModel::kV8, fs_pre.data(), fs_pre.size());
    BOOST_CHECK_EQUAL(
        legacy_fs.ToString(),
        "5b7dfe50aa311ed3291dc65fc54cfd25463c9ed406b3e7f2ef2b611576b42703");
    BOOST_CHECK_EQUAL(
        v8_fs.ToString(),
        "62ab3ff225f9ab305a597053ffc382f2cb3e0471fbe79456d50b6ad704b58a26");
    BOOST_CHECK(legacy_fs != v8_fs);
    // The V8 vector equals the standalone D_FS wrapper (0xF5 ‖ preimage).
    {
        std::vector<uint8_t> body(fs_pre.begin() + 12, fs_pre.end());
        BOOST_CHECK(v8_fs == ds::Sha256dFs(fs_tag, body));
    }
}

// The active-model scope is thread-local, defaults to legacy, nests, and
// restores. This is what makes the chokepoint routing byte-identical to the
// shipped transcript on every un-scoped (mainnet / existing-test) path.
BOOST_AUTO_TEST_CASE(oenc_active_model_scope_defaults_legacy_and_restores)
{
    BOOST_CHECK(ds::ActiveHashModel() == ds::RCStage3HashModel::kLegacyV7);
    {
        ds::RCStage3HashModelScope outer(ds::RCStage3HashModel::kV8);
        BOOST_CHECK(ds::ActiveHashModel() == ds::RCStage3HashModel::kV8);
        {
            ds::RCStage3HashModelScope inner(ds::RCStage3HashModel::kLegacyV7);
            BOOST_CHECK(ds::ActiveHashModel() == ds::RCStage3HashModel::kLegacyV7);
        }
        BOOST_CHECK(ds::ActiveHashModel() == ds::RCStage3HashModel::kV8);
    }
    BOOST_CHECK(ds::ActiveHashModel() == ds::RCStage3HashModel::kLegacyV7);
}

// PR-89 re-refutation (residual B.1): the DECISION is that V8 stays activation-
// gated, NOT flipped to the compile-time default. This pins that decision and
// exhibits the concrete defect it defers to a height-gated fork: under the
// shipped default (legacy) the FS-draw tag "BTX_RC_FS_V1" begins with 'B' (0x42),
// which lands in the D_BIND ASCII first-byte class => D_FS and D_BIND OVERLAP.
// Only the V8 role byte (0xF5) makes the first-byte classes disjoint.
BOOST_AUTO_TEST_CASE(oenc_v8_is_activation_gated_not_default)
{
    // The decision is recorded and compile-time enforced in the header.
    BOOST_CHECK(ds::kV8IsActivationGatedNotDefault);

    // Un-scoped default is the shipped legacy transcript.
    BOOST_CHECK(ds::ActiveHashModel() == ds::RCStage3HashModel::kLegacyV7);

    // The un-role-byted overlap the re-refutation flagged: under the shipped
    // legacy transcript BOTH an FS draw and an ASCII binding commitment begin
    // their preimage with the ASCII tag "BTX_...", i.e. the SAME first byte 'B'
    // (0x42). They are therefore NOT distinguishable by first byte, and 0x42 is
    // in NEITHER role class (no role byte is applied) — that indistinguishability
    // IS the defect.
    const char* fs_tag = "BTX_RC_FS_V1";
    const char* bind_tag = "BTX_RC_STAGE3_SHA_MANIFEST_V1";
    const uint8_t fs_first = static_cast<uint8_t>(fs_tag[0]);
    const uint8_t bind_first = static_cast<uint8_t>(bind_tag[0]);
    BOOST_CHECK_EQUAL(fs_first, 0x42);
    BOOST_CHECK_EQUAL(bind_first, 0x42);
    BOOST_CHECK_EQUAL(fs_first, bind_first); // legacy: FS and BIND collide
    BOOST_CHECK(!ds::InFsFirstByteClass(fs_first));   // in neither role class =>
    BOOST_CHECK(!ds::InBindFirstByteClass(fs_first)); //   not role-separated
    // The legacy registry reproduces the overlap; the V8 registry is disjoint.
    BOOST_CHECK(!ds::RegistryFirstByteClassesDisjoint(
        ds::kRegistryLegacyDefect, ds::kRegistryLegacyDefectSize));
    BOOST_CHECK(ds::RegistryFirstByteClassesDisjoint(ds::kRegistryV8,
                                                     ds::kRegistryV8Size));

    // V8 fixes it: the FS role byte 0xF5 is in D_FS and NOT in D_BIND; the ASCII
    // binding role byte 0xB1 is in D_BIND and NOT in D_FS.
    BOOST_CHECK(ds::InFsFirstByteClass(ds::kRoleFs));
    BOOST_CHECK(!ds::InBindFirstByteClass(ds::kRoleFs));
    BOOST_CHECK(ds::InBindFirstByteClass(ds::kRoleBindAscii));
    BOOST_CHECK(!ds::InFsFirstByteClass(ds::kRoleBindAscii));

    // The fix is transcript-breaking (why it must be a height-gated fork, not a
    // default): the same real FS tag hashes to different bytes under the models.
    std::vector<uint8_t> pre(fs_tag, fs_tag + 12);
    pre.push_back(0x01);
    const uint256 legacy = ds::Sha256dFsPreimage(
        ds::RCStage3HashModel::kLegacyV7, pre.data(), pre.size());
    const uint256 v8 = ds::Sha256dFsPreimage(
        ds::RCStage3HashModel::kV8, pre.data(), pre.size());
    BOOST_CHECK(legacy != v8);
}

BOOST_AUTO_TEST_SUITE_END()
