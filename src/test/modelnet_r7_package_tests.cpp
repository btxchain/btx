// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Independent review lane R7 (.btx packages), SPEC 16. Coordinator: add this
// file to the test_btx source list in src/test/CMakeLists.txt. R7 is a
// review-only lane and did not edit CMake.
//
// The first half builds payloads inline. The vector_set_on_disk_* cases at the
// end read src/test/data/btx-package-vectors/ directly from the source tree:
// that directory is not in the json-header data pipeline (binary frames never
// were) and R7 does not edit CMake, so there is no -D path define for it. The
// path is derived from __FILE__, and a missing directory fails the case rather
// than skipping it. manifest.json records the expectation per file, and those
// cases assert the manifest and the code cannot drift apart.
//
// Cases named *_today assert the CURRENT behaviour of a defect so the suite
// stays green and flips loudly when the defect is fixed. Each carries the R7
// finding id and the assertion to swap in, and each also asserts the bound that
// must hold either way, so a case fails if the tree gets worse.

#include <crypto/common.h>
#include <crypto/hex_base.h>
#include <crypto/sha384.h>
#include <modelnet/canonical_codec.h>
#include <modelnet/package_bundle.h>
#include <modelnet/package_core.h>
#include <modelnet/package_economy.h>
#include <modelnet/package_export.h>
#include <modelnet/resource_uri.h>
#include <modelnet/types.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <cstring>
#include <fstream>
#include <iterator>
#include <limits>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_r7_package_tests, BasicTestingSetup)

namespace {

// Canonical R7 vector URIs. digest = sha384("BTX-R7-VECTOR/" + KIND), encoded by
// EncodeResource with the ResourceKind byte named below.
const std::string kUriModel =
    "btx://pqmtd78qmyk4f954vk4yksyyxkr0syfs298run4fzfk2s2a8yj6cqdesfqewgksq2xau5x0k3garxs6krxr5f";
const std::string kUriCollection =
    "btx://pzzmyz558pj3aftrk2udjmgxy0hakgx8t6f0k6ea0ks53mctrjddv6afe2zkqgx9qwnk5p3nxlltv3wm4up53";
const std::string kUriRelease =
    "btx://pyp9r7j5vft5ucggjaq36xp8fzh9352gteja23z3an2mvvmkt4nlt7ppa8eva0strcw3xwml3095l46p34hhs";
const std::string kUriBounty =
    "btx://pfk5gc4g6s99n4esa4tkg8ewmu5nwyqdphscxee35zdyeda2jhx4a3muz0kdaytzclrxq4wayv59kf5p2ygys";
const std::string kUriModelFamily =
    "btx://pzxsv02jv540unc3w7j4qmwtq97umz6z8rtv2jy49yyx78gphsa7k8xegzmpr8ppvxgjanuvl5nx6mufffwsa";

/** BTXPKG frame over exact payload bytes, so duplicate keys survive into the decoder. */
std::vector<unsigned char> Frame(const std::string& payload, uint32_t flags = 0)
{
    CSHA384 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(payload.data()), payload.size());
    unsigned char digest[48];
    hasher.Finalize(digest);
    std::vector<unsigned char> out(68 + payload.size());
    std::memcpy(out.data(), modelnet::BTXPKG_MAGIC, 8);
    WriteLE32(out.data() + 8, flags);
    WriteLE64(out.data() + 12, payload.size());
    std::memcpy(out.data() + 20, digest, 48);
    std::memcpy(out.data() + 68, payload.data(), payload.size());
    return out;
}

Span<const unsigned char> View(const std::vector<unsigned char>& v)
{
    return Span<const unsigned char>{v.data(), v.size()};
}

UniValue MagnetFields(const std::string& kind, const std::string& uri)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("kind", kind);
    o.pushKV("uri", uri);
    o.pushKV("copy_text", "R7 vector " + kind);
    return o;
}

UniValue Observation(const std::string& key, int64_t value)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV(key, value);
    return o;
}

/** src/test/data/btx-package-vectors, via CMake (not __FILE__, which is prefix-mapped). */
fs::path VectorDir()
{
#ifdef MODELNET_BTX_PACKAGE_VECTORS_PATH
    return fs::PathFromString(MODELNET_BTX_PACKAGE_VECTORS_PATH);
#else
    return fs::PathFromString(std::string{__FILE__}).parent_path() / "data" / "btx-package-vectors";
#endif
}

std::vector<unsigned char> ReadVectorBytes(const fs::path& p)
{
    std::ifstream in{p, std::ios::binary};
    BOOST_REQUIRE_MESSAGE(in.good(), "missing vector " + fs::PathToString(p));
    return std::vector<unsigned char>{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

/** Vector text without the trailing newline the files carry for git hygiene. */
std::string ReadVectorText(const fs::path& p)
{
    const auto bytes = ReadVectorBytes(p);
    std::string s{bytes.begin(), bytes.end()};
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
    return s;
}

std::string Sha384Hex(Span<const unsigned char> data)
{
    CSHA384 hasher;
    hasher.Write(data.data(), data.size());
    unsigned char digest[48];
    hasher.Finalize(digest);
    return HexStr(Span<const unsigned char>{digest, 48});
}

/** The .btx JSON body of a framed vector, i.e. everything after the 68-byte header. */
std::string FramePayload(const std::vector<unsigned char>& framed)
{
    BOOST_REQUIRE_GE(framed.size(), 68U);
    return std::string{framed.begin() + 68, framed.end()};
}

const std::vector<std::pair<std::string, std::string>>& VectorKinds()
{
    static const std::vector<std::pair<std::string, std::string>> kinds{
        {"MODEL", kUriModel},
        {"COLLECTION", kUriCollection},
        {"RELEASE", kUriRelease},
        {"BOUNTY", kUriBounty},
        {"MODEL_FAMILY", kUriModelFamily},
    };
    return kinds;
}

} // namespace

// ---------------------------------------------------------------------------
// Canonical vectors: the five kinds the lane requires.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(magnet_analog_five_kinds_are_canonical)
{
    for (const auto& [kind, uri] : VectorKinds()) {
        UniValue out;
        std::string err;
        BOOST_REQUIRE_MESSAGE(modelnet::EncodeMagnetAnalog(MagnetFields(kind, uri), out, err), kind + ": " + err);
        BOOST_CHECK_EQUAL(out["kind"].get_str(), kind);
        BOOST_CHECK_EQUAL(out["uri"].get_str(), uri);
        BOOST_CHECK_EQUAL(out["schema_version"].getInt<int>(), 2);
        // Emission order is part of the encoding: EncodeBtxBundle hashes
        // UniValue::write(), which preserves insertion order.
        const std::vector<std::string> expected{"schema_version", "kind", "uri", "copy_text"};
        BOOST_CHECK(out.getKeys() == expected);

        // The URI must survive the native decoder, not merely look btx-ish.
        modelnet::Resource r;
        BOOST_REQUIRE_MESSAGE(modelnet::DecodeResource(uri, r, err), kind + ": " + err);
        BOOST_CHECK_EQUAL(r.Uri(), uri);

        // Round trip through the binary framing.
        std::vector<unsigned char> bytes;
        BOOST_REQUIRE_MESSAGE(modelnet::EncodePublicBtxBundle(out, bytes, err), err);
        BOOST_CHECK(modelnet::LooksLikeBtxBundle(View(bytes)));
        UniValue back;
        BOOST_REQUIRE_MESSAGE(modelnet::DecodePublicBtxBundle(View(bytes), back, err), err);
        BOOST_CHECK_EQUAL(back.write(), out.write());
    }
}

BOOST_AUTO_TEST_CASE(model_family_has_no_resource_kind_today)
{
    // R7-09: MODEL_FAMILY is required by SPEC 16 but is not a ResourceKind and not
    // in kPackageTypes; the tree spells a family as package_type VARIANT_INDEX with
    // a variants[] array. EncodeMagnetAnalog accepts the label only because it never
    // validates kind against an enumeration.
    for (int i = 0; i <= 14; ++i) {
        modelnet::ResourceKind k;
        BOOST_REQUIRE(modelnet::ResourceKindFromInt(i, k));
        BOOST_CHECK(std::string(modelnet::ResourceKindName(k)) != "MODEL_FAMILY");
    }
    // Any unenumerated label is accepted, so the field carries no authority.
    UniValue out;
    std::string err;
    BOOST_CHECK(modelnet::EncodeMagnetAnalog(MagnetFields("NOT_A_KIND", kUriModel), out, err));
    BOOST_CHECK_EQUAL(out["kind"].get_str(), "NOT_A_KIND");
    // Fix: validate kind against a package-kind enumeration that names the family
    // form, then BOOST_CHECK(!modelnet::EncodeMagnetAnalog(...)).
}

// ---------------------------------------------------------------------------
// Preview-first / no auto-spend.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(magnet_analog_rejects_spend_mandate_and_dn)
{
    std::string err;
    UniValue out;

    UniValue spend = MagnetFields("RELEASE", kUriRelease);
    spend.pushKV("automatic_spend_atoms", 1);
    BOOST_CHECK(!modelnet::EncodeMagnetAnalog(spend, out, err));
    BOOST_CHECK_EQUAL(err, "spend mandate forbidden");

    UniValue dn = MagnetFields("MODEL", kUriModel + "?dn=display");
    BOOST_CHECK(!modelnet::EncodeMagnetAnalog(dn, out, err));
    BOOST_CHECK(modelnet::UriQueryHasDn(kUriModel + "?dn=display"));
    BOOST_CHECK(!modelnet::UriQueryHasDn(kUriModel));

    UniValue secret = MagnetFields("MODEL", kUriModel);
    secret.pushKV("api_key", "BTX_R7_SECRET_SENTINEL");
    BOOST_CHECK(!modelnet::EncodeMagnetAnalog(secret, out, err));
    BOOST_CHECK(!modelnet::PublicExportObjectAllowed(secret, err));
}

BOOST_AUTO_TEST_CASE(magnet_analog_drops_spend_and_preview_assertions_today)
{
    // R7-05: the encoder validates automatic_spend_atoms == 0 and preview_first but
    // emits neither, so nothing downstream of the export can see that no spend and
    // no execution were mandated.
    UniValue fields = MagnetFields("MODEL", kUriModel);
    fields.pushKV("automatic_spend_atoms", 0);
    fields.pushKV("preview_first", true);
    UniValue out;
    std::string err;
    BOOST_REQUIRE(modelnet::EncodeMagnetAnalog(fields, out, err));
    BOOST_CHECK(!out.exists("automatic_spend_atoms"));
    BOOST_CHECK(!out.exists("preview_first"));
    // Fix: emit automatic_spend_atoms=0 and preview_first=true, then
    // BOOST_CHECK_EQUAL(out["automatic_spend_atoms"].getInt<int64_t>(), 0).
}

BOOST_AUTO_TEST_CASE(magnet_analog_throws_on_out_of_range_spend_today)
{
    // R7-02: isNum() passes for any JSON integer literal, then getInt<int64_t>()
    // throws instead of returning the "spend mandate forbidden" refusal. The
    // no-auto-spend guard raises rather than rejects.
    UniValue fields = MagnetFields("MODEL", kUriModel);
    UniValue huge;
    huge.setNumStr("99999999999999999999");
    fields.pushKV("automatic_spend_atoms", huge);
    UniValue out;
    std::string err;
    BOOST_CHECK_THROW(modelnet::EncodeMagnetAnalog(fields, out, err), std::runtime_error);
    // Fix: range-check before getInt, then
    // BOOST_CHECK(!modelnet::EncodeMagnetAnalog(fields, out, err)).
}

BOOST_AUTO_TEST_CASE(magnet_analog_accepts_arbitrary_url_today)
{
    // R7-03: ValidateResources() requires a btx:// prefix on resource URIs, but the
    // magnet-analog path accepts any non-empty string, so an exported .btx can point
    // a reader at an arbitrary origin.
    UniValue out;
    std::string err;
    UniValue http = MagnetFields("MODEL", "https://attacker.example/weights.gguf");
    BOOST_CHECK(modelnet::EncodeMagnetAnalog(http, out, err));
    BOOST_CHECK_EQUAL(out["uri"].get_str(), "https://attacker.example/weights.gguf");
    modelnet::Resource r;
    BOOST_CHECK(!modelnet::DecodeResource(out["uri"].get_str(), r, err));
    // Fix: require DecodeResource(uri) to succeed, then
    // BOOST_CHECK(!modelnet::EncodeMagnetAnalog(http, out, err)).
}

BOOST_AUTO_TEST_CASE(magnet_analog_rewrites_unknown_schema_version_today)
{
    // R7-04: ParseMagnetAnalog only checks that schema_version exists. An unknown
    // future version is silently downgraded to 2 instead of being refused.
    UniValue fields = MagnetFields("MODEL", kUriModel);
    fields.pushKV("schema_version", 99);
    UniValue out;
    std::string err;
    BOOST_REQUIRE(modelnet::ParseMagnetAnalog(fields, out, err));
    BOOST_CHECK_EQUAL(out["schema_version"].getInt<int>(), 2);
    // Fix: refuse schema_version outside the supported set, then
    // BOOST_CHECK(!modelnet::ParseMagnetAnalog(fields, out, err)).
}

BOOST_AUTO_TEST_CASE(copy_text_keeps_control_and_bidi_characters_today)
{
    // R7-08: package_core runs SafeText() over label and ids to bar C0 controls and
    // directional overrides. copy_text is the string a UI shows and a user pastes,
    // and it is copied verbatim with no filter and no length cap.
    UniValue fields = MagnetFields("MODEL", kUriModel);
    const std::string spoof = std::string("safe\xe2\x80\xae") + "kcatta\r\naction=install";
    fields.pushKV("copy_text", spoof);
    UniValue out;
    std::string err;
    BOOST_REQUIRE(modelnet::EncodeMagnetAnalog(fields, out, err));
    BOOST_CHECK_EQUAL(out["copy_text"].get_str(), spoof);
    // Fix: apply the SafeText() filter to copy_text, then
    // BOOST_CHECK(!modelnet::EncodeMagnetAnalog(fields, out, err)).
}

// ---------------------------------------------------------------------------
// Deterministic encoding and the duplicate-key scan bypass.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(bundle_rejects_unshadowed_float)
{
    UniValue out;
    std::string err;
    const auto framed = Frame(R"({"n":1.5})");
    BOOST_CHECK(!modelnet::DecodeBtxBundle(View(framed), out, err));
    BOOST_CHECK_EQUAL(err, "floats prohibited");
}

BOOST_AUTO_TEST_CASE(bundle_duplicate_key_shadows_float_scan_today)
{
    // R7-01: RejectFloats() walks getKeys(), which yields a duplicated name once per
    // occurrence, but dereferences v[k], which findKey() resolves to the FIRST match.
    // Every value after the first under a duplicated key is never inspected. Both
    // DecodePjson1 and StrictParseJson reject duplicate keys; DecodeBtxBundle uses
    // plain UniValue::read, and it is the fallback that runs precisely when the
    // strict decoder rejects.
    UniValue out;
    std::string err;
    const auto framed = Frame(R"({"n":1,"n":1.5})");
    BOOST_CHECK(modelnet::DecodeBtxBundle(View(framed), out, err));
    // Fix: parse with modelnet::StrictParseJson in DecodeBtxBundle, then
    // BOOST_CHECK(!modelnet::DecodeBtxBundle(...)).
}

BOOST_AUTO_TEST_CASE(bundle_duplicate_key_shadows_secret_scan_today)
{
    // R7-01, same mechanism against the credential sentinels: ScanPublic() recurses
    // into v[key], so the second "a" subtree carrying api_key is never visited and
    // the secret survives both the writer lint and the import gate.
    UniValue out;
    std::string err;
    const std::string payload = R"({"a":{"public":1},"a":{"api_key":"BTX_R7_SECRET_SENTINEL"}})";
    const auto framed = Frame(payload);
    BOOST_CHECK(modelnet::DecodePublicBtxBundle(View(framed), out, err));
    BOOST_CHECK(modelnet::PublicExportObjectAllowed(out, err));
    // Fix: parse with modelnet::StrictParseJson before scanning, then
    // BOOST_CHECK(!modelnet::DecodePublicBtxBundle(...)).
}

BOOST_AUTO_TEST_CASE(bundle_duplicate_forbidden_key_name_still_caught)
{
    // Control for the two cases above: the key-NAME test runs once per getKeys()
    // entry, so a duplicated forbidden name is still refused. Only shadowed VALUES
    // escape.
    UniValue out;
    std::string err;
    const auto framed = Frame(R"({"secret":"x","secret":"y"})");
    BOOST_CHECK(!modelnet::DecodePublicBtxBundle(View(framed), out, err));
    BOOST_CHECK_EQUAL(err, "secret-bearing key: secret");
}

BOOST_AUTO_TEST_CASE(frame_rejects_flags_trailing_digest_and_oversize)
{
    UniValue out;
    std::string err;
    const std::string payload = R"({"core":{"version":2}})";

    auto trailing = Frame(payload);
    trailing.push_back('X');
    BOOST_CHECK(!modelnet::DecodeBtxBundle(View(trailing), out, err));

    auto flags = Frame(payload);
    WriteLE32(flags.data() + 8, 1);
    BOOST_CHECK(!modelnet::DecodeBtxBundle(View(flags), out, err));
    WriteLE32(flags.data() + 8, modelnet::BTXPKG_BUNDLE_FLAGS);
    BOOST_REQUIRE_MESSAGE(modelnet::DecodeBtxBundle(View(flags), out, err), err);

    auto lenlie = Frame(payload);
    WriteLE64(lenlie.data() + 12, payload.size() + 5);
    BOOST_CHECK(!modelnet::DecodeBtxBundle(View(lenlie), out, err));

    auto maxlen = Frame(payload);
    WriteLE64(maxlen.data() + 12, ~uint64_t{0});
    BOOST_CHECK(!modelnet::DecodeBtxBundle(View(maxlen), out, err));

    auto digest = Frame(payload);
    digest[20] ^= 1;
    BOOST_CHECK(!modelnet::DecodeBtxBundle(View(digest), out, err));
    BOOST_CHECK_EQUAL(err, "payload digest");

    auto magic = Frame(payload);
    magic[0] = 'N';
    BOOST_CHECK(!modelnet::DecodeBtxBundle(View(magic), out, err));
    BOOST_CHECK(!modelnet::LooksLikeBtxBundle(View(magic)));

    const std::vector<unsigned char> short_header(18, 0);
    BOOST_CHECK(!modelnet::DecodeBtxBundle(View(short_header), out, err));
    BOOST_CHECK_EQUAL(err, "invalid header");
}

BOOST_AUTO_TEST_CASE(bundle_encoding_follows_insertion_order)
{
    // EncodeBtxBundle hashes UniValue::write(), so the frame digest depends on key
    // insertion order while EncodePjson1 sorts keys. Two codecs share one magic;
    // package_core_id, not the frame hash, is the package identity.
    UniValue a(UniValue::VOBJ);
    a.pushKV("b", 1);
    a.pushKV("a", 2);
    UniValue b(UniValue::VOBJ);
    b.pushKV("a", 2);
    b.pushKV("b", 1);

    std::vector<unsigned char> ba, bb;
    std::string err;
    BOOST_REQUIRE(modelnet::EncodeBtxBundle(a, ba, err));
    BOOST_REQUIRE(modelnet::EncodeBtxBundle(b, bb, err));
    BOOST_CHECK(ba != bb);
    BOOST_CHECK_EQUAL(ReadLE32(ba.data() + 8), modelnet::BTXPKG_BUNDLE_FLAGS);
    BOOST_CHECK_EQUAL(ReadLE32(bb.data() + 8), modelnet::BTXPKG_BUNDLE_FLAGS);
    BOOST_CHECK_NE(modelnet::BTXPKG_BUNDLE_FLAGS, modelnet::BTXPKG_CORE_FLAGS);

    // Re-encoding a decoded bundle is stable, which is what a vector fixture needs.
    UniValue back;
    BOOST_REQUIRE(modelnet::DecodeBtxBundle(View(ba), back, err));
    std::vector<unsigned char> again;
    BOOST_REQUIRE(modelnet::EncodeBtxBundle(back, again, err));
    BOOST_CHECK(ba == again);
}

// ---------------------------------------------------------------------------
// Economic state: refresh vs stale cache, and explicit offline.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(reward_preview_is_observation_and_never_spends)
{
    UniValue core(UniValue::VOBJ);
    core.pushKV("automatic_spend_atoms", 0);
    UniValue cached(UniValue::VOBJ);
    cached.pushKV("state", "FUNDED");
    UniValue local(UniValue::VOBJ);
    local.pushKV("state", "FUNDED");

    modelnet::PackageRewardPreview p;
    std::string code, err;
    BOOST_REQUIRE(modelnet::EvaluatePackageRewardPreview(core, cached, local, p, code, err));
    BOOST_CHECK(!p.cached_stale);
    BOOST_CHECK(p.preview_is_observation);
    BOOST_CHECK(!p.controls_spending);
    BOOST_CHECK_EQUAL(p.automatic_spend_atoms, 0);

    // A refreshed local state that disagrees with the cache marks the cache stale.
    UniValue moved(UniValue::VOBJ);
    moved.pushKV("state", "AWAITING_RELEASE");
    BOOST_REQUIRE(modelnet::EvaluatePackageRewardPreview(core, cached, moved, p, code, err));
    BOOST_CHECK(p.cached_stale);
    BOOST_CHECK_EQUAL(p.current_state, "AWAITING_RELEASE");

    // Offline: no local observation at all, cache is stale and the unknown state is
    // stated rather than left blank.
    BOOST_REQUIRE(modelnet::EvaluatePackageRewardPreview(core, cached, UniValue(UniValue::VOBJ), p, code, err));
    BOOST_CHECK(p.cached_stale);
    BOOST_CHECK_EQUAL(p.current_state, "economic state unknown");

    // A nonzero spend mandate in the core is refused outright.
    UniValue paying(UniValue::VOBJ);
    paying.pushKV("automatic_spend_atoms", 1);
    BOOST_CHECK(!modelnet::EvaluatePackageRewardPreview(paying, cached, local, p, code, err));
    BOOST_CHECK_EQUAL(code, "NONCANONICAL_PAYLOAD");
}

BOOST_AUTO_TEST_CASE(reward_preview_misses_staleness_without_state_field_today)
{
    // R7-06: staleness is derived from the "state" string and from an amount
    // comparison that needs BOTH sides. A cached observation that carries only a
    // funding number, refreshed while offline, is reported fresh. The
    // cached_percent_funded_ignored flag is the only hint, and it is not the field a
    // caller reads to decide whether to trust the cache.
    UniValue core(UniValue::VOBJ);
    modelnet::PackageRewardPreview p;
    std::string code, err;
    BOOST_REQUIRE(modelnet::EvaluatePackageRewardPreview(core, Observation("percent_funded", 87),
                                                         UniValue(UniValue::VOBJ), p, code, err));
    BOOST_CHECK(!p.cached_stale);
    BOOST_CHECK(p.json["cached_percent_funded_ignored"].get_bool());
    // There is also no field that distinguishes "refreshed, chain says unknown" from
    // "could not reach the chain".
    BOOST_CHECK(!p.json.exists("observation_offline"));
    BOOST_CHECK(!p.json.exists("observed_at_height"));
    // Fix: treat any cached economic claim with no fresh local observation as stale
    // and emit an explicit offline flag, then BOOST_CHECK(p.cached_stale).
}

BOOST_AUTO_TEST_CASE(reward_preview_compares_percent_against_atoms_today)
{
    // R7-07: AmountMismatch() reads confirmed_funded_atoms OR percent_funded on each
    // side independently, so a cached 50 percent and a local 50 atoms compare equal
    // and the cache is called fresh across a unit change.
    UniValue core(UniValue::VOBJ);
    modelnet::PackageRewardPreview p;
    std::string code, err;
    BOOST_REQUIRE(modelnet::EvaluatePackageRewardPreview(core, Observation("percent_funded", 50),
                                                         Observation("confirmed_funded_atoms", 50), p, code, err));
    BOOST_CHECK(!p.cached_stale);
    // Fix: compare like units only, then BOOST_CHECK(p.cached_stale).
}

BOOST_AUTO_TEST_CASE(free_only_timer_never_converts_to_paid)
{
    UniValue acq(UniValue::VOBJ);
    acq.pushKV("retrieval_mode", "FREE_ONLY");
    UniValue handoff(UniValue::VOBJ);
    handoff.pushKV("acquisition", acq);
    UniValue core(UniValue::VOBJ);
    core.pushKV("agent_handoff", handoff);
    core.pushKV("automatic_spend_atoms", 0);

    UniValue out;
    std::string code, err;
    BOOST_REQUIRE(modelnet::PlanFreeOnlyAwaitingRelease(core, 365LL * 24 * 3600 * 1000, out, code, err));
    BOOST_CHECK_EQUAL(code, "WAITING_FOR_PUBLIC_RELEASE");
    BOOST_CHECK(!out["converted_to_paid"].get_bool());
    BOOST_CHECK(out["timer_cannot_convert_to_paid"].get_bool());
    BOOST_CHECK_EQUAL(out["spent_atoms"].getInt<int64_t>(), 0);
    BOOST_CHECK_EQUAL(out["automatic_spend_atoms"].getInt<int64_t>(), 0);
}

BOOST_AUTO_TEST_CASE(portable_lint_rejects_presigned_capability)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("mirror", "https://s3.example/w.gguf?X-Amz-Signature=deadbeef");
    std::string err;
    BOOST_CHECK(modelnet::PackageContainsPresignedCapability(o));
    BOOST_CHECK(!modelnet::LintPackagePortable(o, err));

    // R7-10: the magnet-analog encoder does not call the lint, so the export path
    // alone does not stop an embedded presigned capability.
    UniValue fields = MagnetFields("MODEL", kUriModel);
    fields.pushKV("mirror", "https://s3.example/w.gguf?X-Amz-Signature=deadbeef");
    UniValue out;
    BOOST_CHECK(modelnet::EncodeMagnetAnalog(fields, out, err));
    // Fix: call LintPackagePortable from the export path, then
    // BOOST_CHECK(!modelnet::EncodeMagnetAnalog(fields, out, err)).
}

BOOST_AUTO_TEST_CASE(legacy_acquisition_export_is_labeled_and_strips_handoff)
{
    UniValue core(UniValue::VOBJ);
    core.pushKV("version", 2);
    core.pushKV("agent_handoff", UniValue(UniValue::VOBJ));
    UniValue payload(UniValue::VOBJ);
    payload.pushKV("core", core);
    payload.pushKV("agent_handoff", UniValue(UniValue::VOBJ));

    std::vector<unsigned char> bytes;
    std::string err;
    BOOST_REQUIRE(modelnet::EncodeLegacyAcquisitionExport(payload, bytes, err));
    UniValue back;
    BOOST_REQUIRE(modelnet::DecodeBtxBundle(View(bytes), back, err));
    BOOST_CHECK(back["legacy_acquisition_export"].get_bool());
    BOOST_CHECK(!back.exists("agent_handoff"));
    BOOST_CHECK(!back["core"].exists("agent_handoff"));
}

// ---------------------------------------------------------------------------
// The on-disk vector set: src/test/data/btx-package-vectors/.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(vector_set_on_disk_valid_files_round_trip_both_codecs)
{
    const fs::path dir = VectorDir();
    BOOST_REQUIRE_MESSAGE(fs::exists(dir), "missing " + fs::PathToString(dir));

    for (const auto& [kind, uri] : VectorKinds()) {
        const std::string text = ReadVectorText(dir / "valid" / fs::PathFromString(kind + ".btx"));
        UniValue on_disk;
        BOOST_REQUIRE_MESSAGE(on_disk.read(text), kind);

        UniValue parsed;
        std::string err;
        BOOST_REQUIRE_MESSAGE(modelnet::ParseMagnetAnalog(on_disk, parsed, err), kind + ": " + err);
        // The file is exactly what the encoder emits, key order included. A
        // reordering or an added field breaks the .btxbundle digest below.
        BOOST_CHECK_EQUAL(parsed.write(), text);
        BOOST_CHECK_EQUAL(parsed["kind"].get_str(), kind);
        BOOST_CHECK_EQUAL(parsed["uri"].get_str(), uri);

        modelnet::Resource r;
        BOOST_REQUIRE_MESSAGE(modelnet::DecodeResource(uri, r, err), kind + ": " + err);
        BOOST_CHECK_EQUAL(r.Uri(), uri);
        // MODEL_FAMILY has no ResourceKind, so its vector carries the COLLECTION
        // kind byte (R7-09). The label is the only place the family form exists.
        BOOST_CHECK_EQUAL(std::string(modelnet::ResourceKindName(r.kind)),
                          kind == "MODEL_FAMILY" ? std::string("COLLECTION") : kind);

        const auto framed = ReadVectorBytes(dir / "valid" / fs::PathFromString(kind + ".btxbundle"));
        BOOST_CHECK(modelnet::LooksLikeBtxBundle(View(framed)));
        BOOST_CHECK_EQUAL(FramePayload(framed), text);
        UniValue back;
        BOOST_REQUIRE_MESSAGE(modelnet::DecodePublicBtxBundle(View(framed), back, err), kind + ": " + err);
        BOOST_CHECK_EQUAL(back.write(), text);

        // Re-encoding a decoded frame reproduces the file byte for byte, which
        // is what makes these usable as fixtures at all.
        std::vector<unsigned char> again;
        BOOST_REQUIRE_MESSAGE(modelnet::EncodeBtxBundle(back, again, err), err);
        BOOST_REQUIRE_GE(again.size(), 12U);
        BOOST_CHECK_EQUAL(ReadLE32(again.data() + 8), modelnet::BTXPKG_BUNDLE_FLAGS);
        BOOST_CHECK_EQUAL(FramePayload(again), text);
        // On-disk vectors still carry flags=0 (legacy JSON-only). Re-encode uses
        // BTXPKG_BUNDLE_FLAGS, so the header bytes differ; the body must not.
        BOOST_CHECK(again != framed);
        BOOST_CHECK_EQUAL(ReadLE32(framed.data() + 8), modelnet::BTXPKG_CORE_FLAGS);
    }
}

BOOST_AUTO_TEST_CASE(vector_set_on_disk_bad_frames_are_refused_with_the_stated_error)
{
    const fs::path bad = VectorDir() / "invalid";
    const std::vector<std::pair<std::string, std::string>> frames{
        {"frame-truncated.bin", "invalid header"},
        {"frame-wrong-magic.bin", "invalid header"},
        {"frame-nonzero-flags.btxbundle", "flags/size/trailing"},
        {"frame-trailing-bytes.btxbundle", "flags/size/trailing"},
        {"frame-declared-len-max.btxbundle", "flags/size/trailing"},
        {"frame-bad-digest.btxbundle", "payload digest"},
    };
    for (const auto& [name, expect] : frames) {
        const auto bytes = ReadVectorBytes(bad / fs::PathFromString(name));
        UniValue out;
        std::string err;
        BOOST_CHECK_MESSAGE(!modelnet::DecodeBtxBundle(View(bytes), out, err), name);
        BOOST_CHECK_EQUAL(err, expect);
        // The magic sniff is a routing hint, never an acceptance decision: five
        // of these six still look like bundles and are still refused.
        BOOST_CHECK_EQUAL(modelnet::LooksLikeBtxBundle(View(bytes)), name != "frame-wrong-magic.bin");
    }
}

BOOST_AUTO_TEST_CASE(vector_set_on_disk_pins_the_duplicate_key_shadowing)
{
    const fs::path bad = VectorDir() / "invalid";
    std::string err;

    // R7-01, float arm. The shadowed 1.5 is never inspected, so the frame is
    // accepted. Bound: the duplicate is still on the wire for any caller that
    // looks, and the hidden value cannot be read back by key.
    const auto floats = ReadVectorBytes(bad / "dup-key-shadowed-float.btxbundle");
    UniValue out;
    BOOST_CHECK(modelnet::DecodeBtxBundle(View(floats), out, err));
    BOOST_CHECK_EQUAL(out.getKeys().size(), 2U);
    BOOST_CHECK_EQUAL(out["n"].getInt<int64_t>(), 1);
    // The tree already owns a decoder that refuses this. DecodeBtxBundle uses
    // plain UniValue::read instead, which is the whole finding.
    UniValue strict;
    BOOST_CHECK(!modelnet::StrictParseJson(FramePayload(floats), strict, err));
    BOOST_CHECK_EQUAL(err, "floating JSON number forbidden");

    // R7-01, secret arm: the second "a" subtree is never visited, so the
    // credential survives the writer lint and the import gate.
    const auto secret = ReadVectorBytes(bad / "dup-key-shadowed-secret.btxbundle");
    UniValue leaked;
    BOOST_CHECK(modelnet::DecodePublicBtxBundle(View(secret), leaked, err));
    BOOST_CHECK(modelnet::PublicExportObjectAllowed(leaked, err));
    BOOST_CHECK_EQUAL(leaked.getKeys().size(), 2U);
    // Bound: unreachable by key, so no consumer reads the sentinel through the
    // decoded object; only a duplicate-aware parser can see it at all.
    BOOST_CHECK(leaked["a"]["api_key"].isNull());
    BOOST_CHECK(!modelnet::StrictParseJson(FramePayload(secret), strict, err));
    BOOST_CHECK_EQUAL(err, "duplicate JSON key");
    // Fix for both arms: parse with StrictParseJson in DecodeBtxBundle, then
    // BOOST_CHECK(!modelnet::DecodeBtxBundle(...)).

    // Control: a duplicated forbidden key NAME is still caught, because the
    // name test runs once per getKeys() entry. Only shadowed values escape.
    const auto named = ReadVectorBytes(bad / "dup-key-toplevel-secret.btxbundle");
    UniValue refused;
    BOOST_CHECK(!modelnet::DecodePublicBtxBundle(View(named), refused, err));
    BOOST_CHECK_EQUAL(err, "secret-bearing key: secret");
}

BOOST_AUTO_TEST_CASE(vector_set_on_disk_magnet_analog_negatives)
{
    const fs::path bad = VectorDir() / "invalid";
    auto load = [&](const char* name) {
        UniValue v;
        BOOST_REQUIRE_MESSAGE(v.read(ReadVectorText(bad / name)), name);
        return v;
    };
    UniValue out;
    std::string err;

    // Enforced today.
    BOOST_CHECK(!modelnet::ParseMagnetAnalog(load("dn-in-uri.btx"), out, err));
    BOOST_CHECK_EQUAL(err, "dn= stays on copy_text only");
    BOOST_CHECK(!modelnet::ParseMagnetAnalog(load("nonzero-auto-spend.btx"), out, err));
    BOOST_CHECK_EQUAL(err, "spend mandate forbidden");

    // R7-02: the no-auto-spend guard raises instead of refusing.
    BOOST_CHECK_THROW(modelnet::ParseMagnetAnalog(load("int-overflow-auto-spend.btx"), out, err),
                      std::runtime_error);

    // R7-03: any non-empty string is accepted as a resource URI. Bound: it is
    // still not resolvable natively, so a reader cannot fetch from it.
    const UniValue foreign = load("non-btx-uri.btx");
    BOOST_CHECK(modelnet::ParseMagnetAnalog(foreign, out, err));
    modelnet::Resource r;
    BOOST_CHECK(!modelnet::DecodeResource(out["uri"].get_str(), r, err));
    // Fix: require DecodeResource(uri) in EncodeMagnetAnalog, then
    // BOOST_CHECK(!modelnet::ParseMagnetAnalog(foreign, out, err)).

    // R7-04: an unknown future schema_version is silently rewritten to 2.
    BOOST_CHECK(modelnet::ParseMagnetAnalog(load("unknown-schema-version.btx"), out, err));
    BOOST_CHECK_EQUAL(out["schema_version"].getInt<int>(), 2);

    // R7-08: copy_text keeps its bidi override and CRLF. Bound: the payload is
    // inert data, it does not reach any other emitted field and it survives the
    // frame codec unchanged rather than being interpreted.
    const UniValue spoof = load("control-chars-in-copy-text.btx");
    BOOST_REQUIRE(modelnet::ParseMagnetAnalog(spoof, out, err));
    BOOST_CHECK_EQUAL(out["copy_text"].get_str(), spoof["copy_text"].get_str());
    BOOST_CHECK(out["copy_text"].get_str().find("\xe2\x80\xae") != std::string::npos);
    BOOST_CHECK_EQUAL(out["uri"].get_str(), kUriModel);
    BOOST_CHECK_EQUAL(out["kind"].get_str(), "MODEL");
    std::vector<unsigned char> framed;
    BOOST_REQUIRE(modelnet::EncodePublicBtxBundle(out, framed, err));
    UniValue back;
    BOOST_REQUIRE(modelnet::DecodePublicBtxBundle(View(framed), back, err));
    BOOST_CHECK_EQUAL(back.write(), out.write());

    // R7-10: the export path does not call the portable lint, which does reject
    // the embedded presigned capability.
    const UniValue presigned = load("presigned-url.btx");
    BOOST_CHECK(modelnet::ParseMagnetAnalog(presigned, out, err));
    BOOST_CHECK(modelnet::PackageContainsPresignedCapability(presigned));
    BOOST_CHECK(!modelnet::LintPackagePortable(presigned, err));
    BOOST_CHECK_EQUAL(err, "embedded presigned capability");

    // R7-02 again, this time on core.version: it is read with getInt<int>()
    // after an isNum() guard, so a value that only fits in 64 bits throws in the
    // caller instead of being reported. The parse itself is sound.
    const UniValue overflow = load("int-overflow-core-version.btx");
    BOOST_REQUIRE(overflow["core"]["version"].isNum());
    BOOST_CHECK_THROW(overflow["core"]["version"].getInt<int>(), std::runtime_error);
    BOOST_CHECK_EQUAL(overflow["core"]["version"].getInt<int64_t>(), 2147483648LL);
}

BOOST_AUTO_TEST_CASE(vector_set_on_disk_economy_observations)
{
    const fs::path bad = VectorDir() / "invalid";
    UniValue stale, cross;
    BOOST_REQUIRE(stale.read(ReadVectorText(bad / "stale-percent-funded-no-state.json")));
    BOOST_REQUIRE(cross.read(ReadVectorText(bad / "cross-unit-amount-match.json")));

    modelnet::PackageRewardPreview p;
    std::string code, err;

    // R7-06: a cached funding number with no "state" and no fresh observation is
    // reported fresh. Bound: the preview still spends nothing and still says the
    // funding number was ignored.
    BOOST_REQUIRE(modelnet::EvaluatePackageRewardPreview(UniValue(UniValue::VOBJ), stale,
                                                         UniValue(UniValue::VOBJ), p, code, err));
    BOOST_CHECK(!p.cached_stale);
    BOOST_CHECK(p.json["cached_percent_funded_ignored"].get_bool());
    BOOST_CHECK(p.preview_is_observation);
    BOOST_CHECK(!p.controls_spending);
    BOOST_CHECK_EQUAL(p.automatic_spend_atoms, 0);
    BOOST_CHECK_EQUAL(p.current_state, "economic state unknown");

    // R7-07: 50 percent and 50 atoms compare equal across a unit change.
    BOOST_REQUIRE(modelnet::EvaluatePackageRewardPreview(UniValue(UniValue::VOBJ), cross["cached"],
                                                         cross["local"], p, code, err));
    BOOST_CHECK(!p.cached_stale);
    BOOST_CHECK(!p.controls_spending);
    BOOST_CHECK_EQUAL(p.automatic_spend_atoms, 0);
    // Fix for both: compare like units only and treat an unrefreshed cached
    // claim as stale, then BOOST_CHECK(p.cached_stale).
}

BOOST_AUTO_TEST_CASE(vector_set_on_disk_codec_divergence_shares_one_magic)
{
    const fs::path div = VectorDir() / "codec-divergence";
    const auto write_order = ReadVectorBytes(div / "bundle-write-order.btxbundle");
    const auto sorted_order = ReadVectorBytes(div / "pjson1-sorted-order.btxbundle");

    BOOST_CHECK(modelnet::LooksLikeBtxBundle(View(write_order)));
    BOOST_CHECK(modelnet::LooksLikeBtxBundle(View(sorted_order)));
    BOOST_CHECK(write_order != sorted_order);

    UniValue a, b;
    std::string err;
    BOOST_REQUIRE(modelnet::DecodeBtxBundle(View(write_order), a, err));
    // Sorted PJSON1 is a valid package body under flags=0: dual-body conflict.
    BOOST_CHECK(!modelnet::DecodeBtxBundle(View(sorted_order), b, err));
    BOOST_CHECK_EQUAL(err, "conflicting dual body");
    modelnet::DecodedBtxPackage pkg;
    BOOST_REQUIRE_MESSAGE(modelnet::DecodeBtxPackage(View(sorted_order), pkg, err), err);
    BOOST_CHECK_EQUAL(pkg.core_version, 1);
    modelnet::DecodedBtxPackage write_pkg;
    BOOST_CHECK(!modelnet::DecodeBtxPackage(View(write_order), write_pkg, err));

    // Same logical package, two byte strings, one magic. The frame bytes are
    // malleable; identify a package by package_core_id, never by file hash.
    BOOST_REQUIRE(a.exists("core") && a["core"].isObject());
    BOOST_CHECK_EQUAL(a["core"]["version"].getInt<int>(), 1);
    BOOST_CHECK_EQUAL(a["core"]["aaa"].getInt<int>(), 1);
    BOOST_CHECK(a.write() != std::string(sorted_order.begin() + 68, sorted_order.end()));
    BOOST_CHECK(a["core"].getKeys() != pkg.core.getKeys());
}

BOOST_AUTO_TEST_CASE(vector_set_on_disk_manifest_matches_the_directory)
{
    const fs::path dir = VectorDir();
    UniValue manifest;
    BOOST_REQUIRE(manifest.read(ReadVectorText(dir / "manifest.json")));
    BOOST_REQUIRE(manifest.isObject());

    std::set<std::string> documented;
    for (const char* section : {"valid", "invalid"}) {
        BOOST_REQUIRE(manifest[section].isObject());
        for (const auto& name : manifest[section].getKeys()) documented.insert(name);
    }
    BOOST_REQUIRE(manifest["codec_divergence"].isObject());
    for (const auto& name : manifest["codec_divergence"].getKeys()) {
        if (name == "note") continue;
        documented.insert(name);
    }

    std::set<std::string> present;
    for (const char* sub : {"valid", "invalid", "codec-divergence"}) {
        const fs::path p = dir / sub;
        BOOST_REQUIRE_MESSAGE(fs::exists(p), "missing " + fs::PathToString(p));
        for (const auto& entry : fs::directory_iterator(p)) {
            present.insert(fs::PathToString(entry.path().filename()));
        }
    }
    // A vector added without a manifest entry, or an entry without a file, is a
    // silent hole in the lane.
    BOOST_CHECK(present == documented);
    BOOST_CHECK_EQUAL(present.size(), documented.size());
    BOOST_CHECK(!present.empty());

    // Every framed vector is pinned by digest, so an edit cannot pass unnoticed.
    for (const auto& [kind, uri] : VectorKinds()) {
        const std::string name = kind + ".btxbundle";
        const UniValue& entry = manifest["valid"][name];
        BOOST_REQUIRE_MESSAGE(entry.isObject(), name);
        const auto framed = ReadVectorBytes(dir / "valid" / fs::PathFromString(name));
        BOOST_CHECK_EQUAL(Sha384Hex(View(framed)), entry["frame_sha384"].get_str());
        // And the URI the manifest documents is the URI the .btx carries.
        BOOST_CHECK_EQUAL(manifest["valid"][kind + ".btx"]["uri"].get_str(), uri);
    }
    for (const char* name : {"bundle-write-order.btxbundle", "pjson1-sorted-order.btxbundle"}) {
        const auto framed = ReadVectorBytes(dir / "codec-divergence" / name);
        BOOST_CHECK_EQUAL(Sha384Hex(View(framed)), manifest["codec_divergence"][name].get_str());
    }
}

BOOST_AUTO_TEST_CASE(bundle_flags_zero_rejects_conflicting_dual_body)
{
    UniValue core(UniValue::VOBJ);
    core.pushKV("aaa", 1);
    core.pushKV("version", 1);
    UniValue payload(UniValue::VOBJ);
    payload.pushKV("core", core);
    std::vector<unsigned char> dual;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::EncodeBtxPackage(payload, dual, err), err);
    BOOST_CHECK_EQUAL(ReadLE32(dual.data() + 8), modelnet::BTXPKG_CORE_FLAGS);

    UniValue as_bundle;
    BOOST_CHECK(!modelnet::DecodeBtxBundle(View(dual), as_bundle, err));
    BOOST_CHECK_EQUAL(err, "conflicting dual body");
    modelnet::DecodedBtxPackage pkg;
    BOOST_REQUIRE_MESSAGE(modelnet::DecodeBtxPackage(View(dual), pkg, err), err);
    BOOST_CHECK_EQUAL(pkg.core_version, 1);
    BOOST_CHECK_EQUAL(pkg.flags, modelnet::BTXPKG_CORE_FLAGS);

    std::vector<unsigned char> marked;
    BOOST_REQUIRE_MESSAGE(modelnet::EncodeBtxBundle(payload, marked, err), err);
    BOOST_CHECK_EQUAL(ReadLE32(marked.data() + 8), modelnet::BTXPKG_BUNDLE_FLAGS);
    BOOST_REQUIRE_MESSAGE(modelnet::DecodeBtxBundle(View(marked), as_bundle, err), err);
    BOOST_CHECK(!modelnet::DecodeBtxPackage(View(marked), pkg, err));
}

BOOST_AUTO_TEST_CASE(bundle_rejects_claimed_length_overflow_without_copy)
{
    UniValue out;
    std::string err;
    auto bomb = Frame("{}", modelnet::BTXPKG_BUNDLE_FLAGS);
    WriteLE64(bomb.data() + 12, std::numeric_limits<uint64_t>::max());
    BOOST_CHECK(!modelnet::DecodeBtxBundle(View(bomb), out, err));
    BOOST_CHECK_EQUAL(err, "flags/size/trailing");

    bomb = Frame("{}", modelnet::BTXPKG_BUNDLE_FLAGS);
    bomb.resize(68);
    WriteLE64(bomb.data() + 12, std::numeric_limits<uint64_t>::max() - 10);
    BOOST_CHECK(!modelnet::DecodeBtxBundle(View(bomb), out, err));
    BOOST_CHECK_EQUAL(err, "flags/size/trailing");

    bomb = Frame("{}", modelnet::BTXPKG_BUNDLE_FLAGS);
    WriteLE64(bomb.data() + 12, 4ull * 1024 * 1024 + 1);
    BOOST_CHECK(!modelnet::DecodeBtxBundle(View(bomb), out, err));
    BOOST_CHECK_EQUAL(err, "flags/size/trailing");
}

BOOST_AUTO_TEST_SUITE_END()
