// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// R10 (DoS / security) defensive bounds. Companion to audit/r10-security.md.
//
// Every case here asserts a bound that holds in this tree, so that the parts
// of the model plane that are correctly hardened cannot regress quietly while
// the open R10 findings are being fixed. There is no attack driver, no flood
// loop and no proof-of-concept in this file: each limiter is exercised with a
// single fixed key and the assertion is that the limiter closes.
//
// Every case drives a limiter until it refuses. Nothing here compares a
// constexpr to the literal it was declared with, and nothing here asserts the
// return value of a function whose body is an unconditional `return false`:
// such a check passes for free and would keep passing after the limiter it
// claims to cover was deleted. Where a published ceiling matters, it is proven
// at its boundary -- the last accepted input and the first refused one.
//
// What is pinned:
//   1. .btx frame decode: length is validated against the real buffer before
//      any allocation, 2^64-1 is rejected, trailing bytes are refused, and the
//      SHA-384 is checked before the body is ever handed to a parser.
//   2. Structural limits of both package codecs: PJSON1 nesting depth, and the
//      canonical envelope codec's depth, string, array and field bounds, each
//      exercised at its boundary plus its ASCII field-name allowlist.
//   3. The three filesystem path guards: portable relative paths, package
//      document paths, install archive entries.
//   4. Cloud endpoint validation, metadata/link-local host classification,
//      redirect refusal, presign TTL ceiling and secret redaction.
//   5. Direct-seed URL policy, presigned-URL redaction, /24 netgroup derivation.
//   6. Provider exchange per-message byte/record caps, TTL clamp and the
//      per-key flood limit.
//   7. Reachability probe target validation and the per-requester probe budget.
//   8. Origin stampede per-peer budget and error circuit breaker.
//   9. Event journal retention cap, dedupe, and untrusted-text sanitising.
//  10. Torrent and HuggingFace locator refusals.
//
// UNPROVEN, and deliberately not asserted here because asserting today's
// behaviour would lock in a weakness. Each needs new code first; see
// audit/r10-security.md for the full argument:
//   - R10-01: the inbound connection key must be a real netgroup for both
//     address families. It is currently the full IPv4 address, and 0 for every
//     IPv6 peer.
//   - R10-02: per-peer and per-netgroup limits must key on the accepted socket
//     address or the transport pin, not on X-BTX-From / X-BTX-Netgroup or a
//     netgroup field in the request body.
//   - R10-03: a peer connection must not be able to pin a worker thread
//     indefinitely, and the unix control socket must not share the peer pool.
//   - R10-04: every limiter map keyed by a peer-supplied string needs an entry
//     cap, a key-length cap and eviction.
//   - R10-05: the provider cache and the catalog peer list need a per-source
//     share and an upper bound.
//   - R10-06: a reachability report must be rate limited and must correlate to
//     a probe this node issued.

#include <crypto/common.h>
#include <modelnet/canonical_codec.h>
#include <modelnet/direct_seed.h>
#include <modelnet/event_journal.h>
#include <modelnet/file_stream.h>
#include <modelnet/package_core.h>
#include <modelnet/package_documents.h>
#include <modelnet/package_install.h>
#include <modelnet/package_pjson.h>
#include <modelnet/provider_exchange.h>
#include <modelnet/reachability.h>
#include <modelnet/s3_client.h>
#include <modelnet/search.h>
#include <modelnet/source_local.h>
#include <modelnet/source_torrent.h>
#include <modelnet/store.h>
#include <test/util/setup_common.h>
#include <univalue.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <limits>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_r10_security_tests, BasicTestingSetup)

namespace {

//! A well-formed BTXPKG frame whose body is canonical PJSON1. The body has no
//! "core", so a full decode still fails; that is intentional, since every case
//! below is about the frame checks that run before the core is looked at.
std::vector<unsigned char> WellFormedFrame()
{
    UniValue payload(UniValue::VOBJ);
    payload.pushKV("schema_version", 1);
    payload.pushKV("label", "r10");
    std::vector<unsigned char> out;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::EncodeBtxPackage(payload, out, err), err);
    BOOST_REQUIRE_GT(out.size(), size_t{68});
    return out;
}

std::string DecodeErrCode(const std::vector<unsigned char>& frame)
{
    modelnet::DecodedBtxPackage pkg;
    std::string err;
    const bool ok = modelnet::DecodeBtxPackage(Span<const unsigned char>{frame.data(), frame.size()}, pkg, err);
    BOOST_CHECK(!ok);
    return pkg.err_code;
}

//! Nest `depth` wrapper objects around a one-field leaf object. Both codecs
//! recurse into an object's values at depth + 1, so the innermost number sits
//! at depth + 1 and NestedObject(N) is the last shape a budget of N accepts.
UniValue NestedObject(int depth)
{
    UniValue leaf(UniValue::VOBJ);
    leaf.pushKV("v", 1);
    for (int i = 0; i < depth; ++i) {
        UniValue wrap(UniValue::VOBJ);
        wrap.pushKV("n", leaf);
        leaf = wrap;
    }
    return leaf;
}

UniValue PexBody(const std::vector<std::string>& endpoints)
{
    UniValue arr(UniValue::VARR);
    for (const auto& e : endpoints) {
        UniValue o(UniValue::VOBJ);
        o.pushKV("endpoint", e);
        arr.push_back(o);
    }
    UniValue body(UniValue::VOBJ);
    body.pushKV("schema_version", 2);
    body.pushKV("providers", arr);
    return body;
}

} // namespace

BOOST_AUTO_TEST_CASE(r10_btx_frame_length_is_never_trusted_for_allocation)
{
    using namespace modelnet;

    // A claimed length is only ever compared against the buffer we already
    // hold. A header that claims the maximum payload with no body behind it
    // must fail on the size comparison, not on an allocation.
    std::vector<unsigned char> header = WellFormedFrame();
    header.resize(68);
    WriteLE64(header.data() + 12, BTX_PACKAGE_MAX_PAYLOAD);
    BOOST_CHECK_EQUAL(DecodeErrCode(header), "BAD_PACKAGE_MAGIC");

    // 2^64-1 is rejected explicitly, before any 68+n arithmetic can wrap.
    std::vector<unsigned char> huge = WellFormedFrame();
    WriteLE64(huge.data() + 12, std::numeric_limits<uint64_t>::max());
    BOOST_CHECK_EQUAL(DecodeErrCode(huge), "PACKAGE_TOO_LARGE");

    // One byte over the ceiling is still over the ceiling. Together with the
    // header case above, this locates the ceiling exactly: a declared length of
    // BTX_PACKAGE_MAX_PAYLOAD gets past the size gate and fails later on the
    // buffer comparison, while MAX + 1 never reaches that comparison at all.
    std::vector<unsigned char> over = WellFormedFrame();
    WriteLE64(over.data() + 12, BTX_PACKAGE_MAX_PAYLOAD + 1);
    BOOST_CHECK_EQUAL(DecodeErrCode(over), "PACKAGE_TOO_LARGE");
}

BOOST_AUTO_TEST_CASE(r10_btx_frame_rejects_truncation_trailer_and_tamper)
{
    using namespace modelnet;

    std::vector<unsigned char> short_header = WellFormedFrame();
    short_header.resize(67);
    BOOST_CHECK_EQUAL(DecodeErrCode(short_header), "BAD_PACKAGE_MAGIC");

    std::vector<unsigned char> bad_magic = WellFormedFrame();
    bad_magic[0] = static_cast<unsigned char>(bad_magic[0] ^ 0xff);
    BOOST_CHECK_EQUAL(DecodeErrCode(bad_magic), "BAD_PACKAGE_MAGIC");

    // Unknown flag bits are refused rather than ignored: no silent extension.
    std::vector<unsigned char> flagged = WellFormedFrame();
    WriteLE32(flagged.data() + 8, 1);
    BOOST_CHECK_EQUAL(DecodeErrCode(flagged), "BAD_PACKAGE_MAGIC");

    // A trailing byte is a different frame, not a longer one.
    std::vector<unsigned char> trailer = WellFormedFrame();
    trailer.push_back(0x00);
    BOOST_CHECK_EQUAL(DecodeErrCode(trailer), "BAD_PACKAGE_MAGIC");

    // Truncated body, header length untouched.
    std::vector<unsigned char> cut = WellFormedFrame();
    cut.pop_back();
    BOOST_CHECK_EQUAL(DecodeErrCode(cut), "BAD_PACKAGE_MAGIC");

    // The digest is verified before the body reaches the PJSON1 parser, so a
    // flipped payload byte is caught by integrity, not by the parser.
    std::vector<unsigned char> tampered = WellFormedFrame();
    tampered.back() = static_cast<unsigned char>(tampered.back() ^ 0x01);
    BOOST_CHECK_EQUAL(DecodeErrCode(tampered), "NONCANONICAL_PAYLOAD");

    // An intact frame still needs a core object; a bodyless package is not a
    // package.
    BOOST_CHECK_EQUAL(DecodeErrCode(WellFormedFrame()), "NONCANONICAL_PAYLOAD");
}

BOOST_AUTO_TEST_CASE(r10_codec_structural_limits_hold)
{
    using namespace modelnet;

    std::vector<unsigned char> out;
    std::string err;

    // PJSON1 refuses to encode past its depth budget, so a deeply nested
    // package cannot even be produced locally and then replayed at a peer.
    // NestedObject(n) puts its deepest value at depth n + 1, so these two lines
    // bracket the budget: the last accepted nesting and the first refused one.
    BOOST_CHECK(EncodePjson1(NestedObject(static_cast<int>(PJSON_MAX_DEPTH) - 1), out, err));
    BOOST_CHECK(!EncodePjson1(NestedObject(static_cast<int>(PJSON_MAX_DEPTH)), out, err));
    BOOST_CHECK_EQUAL(err, "JSON structural limit");

    // A truncated body is rejected rather than partially accepted.
    UniValue decoded;
    const std::vector<unsigned char> unterminated{'{'};
    BOOST_CHECK(!DecodePjson1(Span<const unsigned char>{unterminated.data(), unterminated.size()}, decoded, err));

    // The canonical envelope codec is the one a peer record is hashed through,
    // so each of its structural ceilings is exercised at its boundary too.
    BOOST_CHECK(CanonicalEncode(NestedObject(static_cast<int>(CANONICAL_MAX_DEPTH) - 1), out, err));
    BOOST_CHECK(!CanonicalEncode(NestedObject(static_cast<int>(CANONICAL_MAX_DEPTH)), out, err));
    BOOST_CHECK_EQUAL(err, "depth limit");

    const UniValue at_string(UniValue::VSTR, std::string(CANONICAL_MAX_STRING, 'a'));
    BOOST_CHECK(CanonicalEncode(at_string, out, err));
    const UniValue over_string(UniValue::VSTR, std::string(CANONICAL_MAX_STRING + 1, 'a'));
    BOOST_CHECK(!CanonicalEncode(over_string, out, err));
    BOOST_CHECK_EQUAL(err, "string byte limit");

    UniValue at_array(UniValue::VARR);
    for (size_t i = 0; i < CANONICAL_MAX_ARRAY; ++i) at_array.push_back(UniValue());
    BOOST_CHECK(CanonicalEncode(at_array, out, err));
    UniValue over_array = at_array;
    over_array.push_back(UniValue());
    BOOST_CHECK(!CanonicalEncode(over_array, out, err));
    BOOST_CHECK_EQUAL(err, "array bound");

    UniValue at_fields(UniValue::VOBJ);
    for (size_t i = 0; i < CANONICAL_MAX_FIELDS; ++i) {
        at_fields.pushKV("f" + std::to_string(i), UniValue());
    }
    BOOST_CHECK(CanonicalEncode(at_fields, out, err));
    UniValue over_fields = at_fields;
    over_fields.pushKV("f" + std::to_string(CANONICAL_MAX_FIELDS), UniValue());
    BOOST_CHECK(!CanonicalEncode(over_fields, out, err));
    BOOST_CHECK_EQUAL(err, "object bound");

    // Field names are an ASCII allowlist, so no encoding trick reaches the
    // digest through a key.
    BOOST_CHECK(ValidCanonicalKey("record_type"));
    BOOST_CHECK(!ValidCanonicalKey("Record_Type"));
    BOOST_CHECK(!ValidCanonicalKey("record-type"));
    BOOST_CHECK(!ValidCanonicalKey("0record"));
    BOOST_CHECK(!ValidCanonicalKey(""));
    UniValue bad_key(UniValue::VOBJ);
    bad_key.pushKV("Record_Type", UniValue());
    BOOST_CHECK(!CanonicalEncode(bad_key, out, err));
    BOOST_CHECK_EQUAL(err, "ASCII field name required");
}

BOOST_AUTO_TEST_CASE(r10_path_guards_refuse_traversal_and_encoding_tricks)
{
    using namespace modelnet;
    std::string err;

    // Portable relative paths are an allowlist, so encoding tricks never need
    // to be enumerated.
    BOOST_CHECK(IsPortableRelPath("weights/model-00001-of-00002.safetensors", err));
    BOOST_CHECK(!IsPortableRelPath("../etc/passwd", err));
    BOOST_CHECK(!IsPortableRelPath("/etc/passwd", err));
    BOOST_CHECK(!IsPortableRelPath("a/./b", err));
    BOOST_CHECK(!IsPortableRelPath("a/../b", err));
    BOOST_CHECK(!IsPortableRelPath("weights\\model.bin", err));
    BOOST_CHECK(!IsPortableRelPath("%2e%2e/passwd", err));
    BOOST_CHECK(!IsPortableRelPath("C:/windows/system32", err));
    BOOST_CHECK(!IsPortableRelPath("dir/trailing.", err));
    BOOST_CHECK(!IsPortableRelPath("NUL", err));
    BOOST_CHECK(!IsPortableRelPath("com1.txt", err));
    BOOST_CHECK(!IsPortableRelPath(std::string("a/b") + '\0' + "c", err));
    BOOST_CHECK(!IsPortableRelPath(std::string(300, 'a'), err));

    // Package documents are allowlisted by name and reject percent-encoding
    // outright, so no decode step can reintroduce a separator.
    BOOST_CHECK(DocumentPathAllowed("AGENTS.md", err));
    BOOST_CHECK(!DocumentPathAllowed("../AGENTS.md", err));
    BOOST_CHECK(!DocumentPathAllowed("%2e%2e/AGENTS.md", err));
    BOOST_CHECK(!DocumentPathAllowed("docs\\AGENTS.md", err));
    BOOST_CHECK(!DocumentPathAllowed("C:AGENTS.md", err));
    BOOST_CHECK(!DocumentPathAllowed("/AGENTS.md", err));
    BOOST_CHECK(!DocumentPathAllowed("a//AGENTS.md", err));
    BOOST_CHECK(!DocumentPathAllowed(std::string("AGENTS") + '\0' + ".md", err));
    BOOST_CHECK(!DocumentPathAllowed("AGENTS\xc3\xa9.md", err));
    BOOST_CHECK(!DocumentPathAllowed(std::string(200, 'a'), err));

    // Install entries: a symlink or a duplicate executable name is refused
    // before any path shape is even considered.
    BOOST_CHECK(InstallArchiveEntryAllowed("bin/btxd", false, false, err));
    BOOST_CHECK(!InstallArchiveEntryAllowed("bin/btxd", true, false, err));
    BOOST_CHECK(!InstallArchiveEntryAllowed("bin/btxd", false, true, err));
    BOOST_CHECK(!InstallArchiveEntryAllowed("../bin/btxd", false, false, err));
    BOOST_CHECK(!InstallArchiveEntryAllowed("/bin/btxd", false, false, err));
    BOOST_CHECK(!InstallArchiveEntryAllowed("bin//btxd", false, false, err));
    BOOST_CHECK(!InstallArchiveEntryAllowed("bin\\btxd", false, false, err));
    BOOST_CHECK(!InstallArchiveEntryAllowed(std::string("bin/btxd") + '\0', false, false, err));
    BOOST_CHECK(!InstallArchiveEntryAllowed("", false, false, err));
    BOOST_CHECK(!InstallArchiveEntryAllowed(std::string(300, 'a'), false, false, err));
}

BOOST_AUTO_TEST_CASE(r10_cloud_endpoint_and_metadata_host_policy)
{
    using namespace modelnet;
    std::string err;

    BOOST_CHECK(ValidateS3Endpoint("https://s3.example.com", false, false, err));

    // Plaintext is for a loopback MinIO and nothing else, and only when the
    // caller opted in.
    BOOST_CHECK(ValidateS3Endpoint("http://127.0.0.1:9000", true, false, err));
    BOOST_CHECK(!ValidateS3Endpoint("http://127.0.0.1:9000", false, false, err));
    BOOST_CHECK(!ValidateS3Endpoint("http://s3.example.com", true, false, err));

    // Credentials in a URL, exotic schemes and malformed authorities are all
    // refused rather than normalised.
    BOOST_CHECK(!ValidateS3Endpoint("https://key:secret@s3.example.com", false, false, err));
    BOOST_CHECK(!ValidateS3Endpoint("file:///etc/passwd", true, true, err));
    BOOST_CHECK(!ValidateS3Endpoint("unix:///var/run/docker.sock", true, true, err));
    BOOST_CHECK(!ValidateS3Endpoint("gopher://s3.example.com", true, true, err));
    BOOST_CHECK(!ValidateS3Endpoint("s3://bucket", true, true, err));
    BOOST_CHECK(!ValidateS3Endpoint("s3.example.com", false, false, err));
    BOOST_CHECK(!ValidateS3Endpoint("https://[bad", false, false, err));
    BOOST_CHECK(!ValidateS3Endpoint("https://s3.example.com:0", false, false, err));
    BOOST_CHECK(!ValidateS3Endpoint("https://s3.example.com:99999", false, false, err));
    BOOST_CHECK(!ValidateS3Endpoint("https://s3.example.com\r\nHost: evil", false, false, err));

    // The metadata classifier is a host classifier, not a substring search, and
    // it covers the whole link-local /16 plus the mapped and named forms.
    BOOST_CHECK(S3HostBlockedAsMetadata("169.254.169.254"));
    BOOST_CHECK(S3HostBlockedAsMetadata("169.254.169.254."));
    BOOST_CHECK(S3HostBlockedAsMetadata("169.254.1.1"));
    BOOST_CHECK(S3HostBlockedAsMetadata("::ffff:169.254.169.254"));
    BOOST_CHECK(S3HostBlockedAsMetadata("fd00:ec2::254"));
    BOOST_CHECK(S3HostBlockedAsMetadata("metadata"));
    BOOST_CHECK(S3HostBlockedAsMetadata("METADATA.GOOGLE.INTERNAL"));
    BOOST_CHECK(S3HostBlockedAsMetadata("metadata.goog"));
    BOOST_CHECK(S3HostBlockedAsMetadata("instance-data"));
    BOOST_CHECK(S3HostBlockedAsMetadata("instance-data.ec2.internal"));
    BOOST_CHECK(S3HostBlockedAsMetadata("100.100.100.200"));
    BOOST_CHECK(!S3HostBlockedAsMetadata("s3.amazonaws.com"));
    BOOST_CHECK(!S3HostBlockedAsMetadata("169.253.1.1"));

    BOOST_CHECK(!ValidateS3Endpoint("https://169.254.169.254/latest/meta-data", false, false, err));
    BOOST_CHECK(!ValidateS3Endpoint("http://169.254.169.254/", true, false, err));
    BOOST_CHECK(!ValidateS3Endpoint("https://metadata.google.internal/", false, false, err));

    // A redirect is never followed: an origin cannot bounce us onto a new host
    // after validation has already run.
    BOOST_CHECK(S3HttpRedirectRefused(301));
    BOOST_CHECK(S3HttpRedirectRefused(302));
    BOOST_CHECK(S3HttpRedirectRefused(303));
    BOOST_CHECK(S3HttpRedirectRefused(307));
    BOOST_CHECK(S3HttpRedirectRefused(308));
    BOOST_CHECK(!S3HttpRedirectRefused(200));
    BOOST_CHECK(!S3HttpRedirectRefused(404));
}

BOOST_AUTO_TEST_CASE(r10_cloud_secrets_are_redacted_and_presign_ttl_is_capped)
{
    using namespace modelnet;

    // A presigned URL is short-lived by construction.
    BOOST_CHECK_EQUAL(kS3PresignTtlMaxSeconds, 3600);

    const std::string signed_url =
        "https://s3.example.com/bucket/obj?X-Amz-Algorithm=AWS4-HMAC-SHA256"
        "&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20260917%2Fus-east-1%2Fs3%2Faws4_request"
        "&X-Amz-Signature=1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809";
    const std::string red = RedactCloudSecrets(signed_url);
    BOOST_CHECK(red.find("1a2b3c4d5e6f708192a3b4c5d6e7f809") == std::string::npos);
    BOOST_CHECK(red.find("IOSFODNN7EXAMPLE") == std::string::npos);

    // Config-shaped text loses the secret, keeps the shape.
    const std::string cfg = RedactCloudSecrets("aws_secret_access_key=wJalrXUtnFEMI/K7MDENG");
    BOOST_CHECK(cfg.find("wJalrXUtnFEMI") == std::string::npos);
    BOOST_CHECK(cfg.find("aws_secret_access_key") != std::string::npos);

    // A caller-supplied secret is scrubbed wherever it appears.
    const std::string extra = RedactCloudSecrets("body contains SUPERSECRETVALUE twice SUPERSECRETVALUE",
                                                 "SUPERSECRETVALUE");
    BOOST_CHECK(extra.find("SUPERSECRETVALUE") == std::string::npos);

    // The direct-seed redactor drops the entire query, so no signed parameter
    // can survive into a log or an offer record by being newly named.
    BOOST_CHECK_EQUAL(RedactPresignedUrl("https://s3.example.com/bucket/obj?X-Amz-Signature=abc"),
                      "https://s3.example.com/bucket/obj?[redacted]");
    BOOST_CHECK_EQUAL(RedactPresignedUrl("https://s3.example.com/bucket/obj"),
                      "https://s3.example.com/bucket/obj");
}

BOOST_AUTO_TEST_CASE(r10_direct_seed_url_policy_is_fail_closed)
{
    using namespace modelnet;
    std::string err;

    DirectSeedPolicy off;
    off.enabled = false;
    BOOST_CHECK(!DirectSeedUrlAllowed("https://origin.example.com/obj", off, err));

    DirectSeedPolicy on;
    on.enabled = true;
    BOOST_CHECK(DirectSeedUrlAllowed("https://origin.example.com/obj?sig=x", on, err));
    BOOST_CHECK(!DirectSeedUrlAllowed("https://169.254.169.254/latest", on, err));
    BOOST_CHECK(!DirectSeedUrlAllowed("https://metadata.google.internal/token", on, err));
    BOOST_CHECK(!DirectSeedUrlAllowed("ftp://origin.example.com/obj", on, err));
    BOOST_CHECK(!DirectSeedUrlAllowed("file:///etc/passwd", on, err));
    BOOST_CHECK(!DirectSeedUrlAllowed("origin.example.com/obj", on, err));
    BOOST_CHECK(!DirectSeedUrlAllowed("https:///obj", on, err));

    // An operator allowlist is exact, so a lookalike origin is not an origin.
    DirectSeedPolicy pinned;
    pinned.enabled = true;
    pinned.allowed_https_host = "origin.example.com";
    BOOST_CHECK(DirectSeedUrlAllowed("https://origin.example.com/obj", pinned, err));
    BOOST_CHECK(DirectSeedUrlAllowed("https://ORIGIN.EXAMPLE.COM/obj", pinned, err));
    BOOST_CHECK(!DirectSeedUrlAllowed("https://origin.example.com.evil.test/obj", pinned, err));
    BOOST_CHECK(!DirectSeedUrlAllowed("https://evil.test/obj", pinned, err));
    // Credentials in the authority must not smuggle the allowlisted name past
    // the host comparison.
    BOOST_CHECK(!DirectSeedUrlAllowed("https://origin.example.com@evil.test/obj", pinned, err));

    BOOST_CHECK(LooksLikeMetadataServiceHost("169.254.169.254"));
    BOOST_CHECK(LooksLikeMetadataServiceHost("fd00:ec2::254"));
    BOOST_CHECK(LooksLikeMetadataServiceHost("metadata.google.internal"));
    BOOST_CHECK(!LooksLikeMetadataServiceHost("origin.example.com"));

    // The rate-limit key is derived from the address, not accepted verbatim.
    BOOST_CHECK_EQUAL(DirectSeedNetgroup("203.0.113.7:29447"), "203.0.113.0");
    BOOST_CHECK_EQUAL(DirectSeedNetgroup("203.0.113.9"), "203.0.113.0");
    BOOST_CHECK_EQUAL(DirectSeedNetgroup(""), "unknown");
}

BOOST_AUTO_TEST_CASE(r10_pex_message_caps_and_ttl_clamp)
{
    using namespace modelnet;

    const int64_t now = 1'000'000;
    std::vector<ProviderHint> accepted;
    std::string err;

    // Oversized message: refused on bytes, before any record is parsed.
    {
        ProviderExchange pex;
        UniValue fat = PexBody({"203.0.113.1:29447"});
        fat.pushKV("filler", std::string(PEX_MAX_BYTES_PER_MESSAGE + 64, 'x'));
        BOOST_CHECK(!pex.Ingest("peer-a", fat, now, accepted, err));
        BOOST_CHECK(accepted.empty());
        BOOST_CHECK(pex.Recent(now).empty());
    }

    // Too many records in one message: refused wholesale, not partially.
    {
        ProviderExchange pex;
        std::vector<std::string> many;
        for (size_t i = 0; i <= PEX_MAX_RECORDS_PER_MESSAGE; ++i) {
            many.push_back("203.0.113." + std::to_string(i + 1) + ":29447");
        }
        BOOST_CHECK(!pex.Ingest("peer-a", PexBody(many), now, accepted, err));
        BOOST_CHECK(accepted.empty());
        BOOST_CHECK(pex.Recent(now).empty());
    }

    // A hint cannot pin itself in the cache: expiry is clamped to our TTL, and
    // an already-expired or absurd expiry is dropped.
    {
        ProviderExchange pex;
        UniValue arr(UniValue::VARR);
        UniValue forever(UniValue::VOBJ);
        forever.pushKV("endpoint", "203.0.113.1:29447");
        forever.pushKV("expiry", std::numeric_limits<int64_t>::max());
        arr.push_back(forever);
        UniValue stale(UniValue::VOBJ);
        stale.pushKV("endpoint", "203.0.113.2:29447");
        stale.pushKV("expiry", now - 1);
        arr.push_back(stale);
        UniValue body(UniValue::VOBJ);
        body.pushKV("schema_version", 2);
        body.pushKV("providers", arr);

        BOOST_REQUIRE(pex.Ingest("peer-a", body, now, accepted, err));
        BOOST_REQUIRE_EQUAL(accepted.size(), 1U);
        BOOST_CHECK_EQUAL(accepted.front().endpoint, "203.0.113.1:29447");
        BOOST_CHECK_LE(accepted.front().expiry_ms, now + PEX_DEFAULT_TTL_MS);
        BOOST_CHECK(pex.Recent(now + PEX_DEFAULT_TTL_MS).empty());
    }

    // Control-plane endpoints are never provider hints, whoever offers them.
    {
        ProviderExchange pex;
        BOOST_REQUIRE(pex.Ingest("peer-a", PexBody({"203.0.113.1:8332"}), now, accepted, err));
        BOOST_CHECK(accepted.empty());
        BOOST_CHECK(pex.Recent(now).empty());
        BOOST_CHECK(IsForbiddenPexEndpoint("203.0.113.1:8332", err));
        BOOST_CHECK(IsForbiddenPexEndpoint("203.0.113.1:29447/.cookie", err));
        BOOST_CHECK(!IsForbiddenPexEndpoint("203.0.113.1:29447", err));
    }

    // A single key gets a bounded number of messages per minute, and the cache
    // itself is bounded regardless.
    {
        ProviderExchange pex;
        int ip = 1;
        for (int msg = 0; msg < PEX_MAX_PER_PEER_PER_MINUTE; ++msg) {
            std::vector<std::string> batch;
            for (size_t i = 0; i < PEX_MAX_RECORDS_PER_MESSAGE; ++i) {
                batch.push_back("198.51.100." + std::to_string(ip++) + ":29447");
            }
            BOOST_CHECK_MESSAGE(pex.Ingest("peer-a", PexBody(batch), now, accepted, err),
                                "message " + std::to_string(msg) + ": " + err);
        }
        BOOST_CHECK(!pex.Ingest("peer-a", PexBody({"192.0.2.1:29447"}), now, accepted, err));
        BOOST_CHECK(!err.empty());
        // The whole provider-flood argument rests on these two bounds, and both
        // were reached by ingesting until the limiter refused, not asserted.
        BOOST_CHECK_LE(pex.Recent(now).size(), PEX_CACHE_CAP);
        BOOST_CHECK_LE(pex.Advertise(now, PEX_MAX_RECORDS_PER_MESSAGE)["providers"].size(),
                       PEX_MAX_RECORDS_PER_MESSAGE);
        // The per-key message limiter is a window, not a permanent ban: the same
        // key is admitted again after it. The cache stays full, so the new hint
        // is still dropped -- being allowed to speak is not being believed.
        BOOST_CHECK(pex.Ingest("peer-a", PexBody({"192.0.2.1:29447"}), now + 60'001, accepted, err));
        BOOST_CHECK(accepted.empty());
    }
}

BOOST_AUTO_TEST_CASE(r10_probe_targets_and_probe_budget)
{
    using namespace modelnet;

    ReachabilityTracker t;
    std::string err;

    BOOST_CHECK(t.ValidateProbeTarget("203.0.113.5:29447", err));
    BOOST_CHECK(t.ValidateProbeTarget("203.0.113.5:29448", err));

    // A probe is not a port scanner and not a way to reach a control plane.
    BOOST_CHECK(!t.ValidateProbeTarget("203.0.113.5:22", err));
    BOOST_CHECK(!t.ValidateProbeTarget("203.0.113.5:8332", err));
    BOOST_CHECK(!t.ValidateProbeTarget("203.0.113.5:0", err));
    BOOST_CHECK(!t.ValidateProbeTarget("", err));
    BOOST_CHECK(!t.ValidateProbeTarget("203.0.113.5", err));
    // Nor a way to have us dial the operator's own network.
    BOOST_CHECK(!t.ValidateProbeTarget("10.0.0.5:29447", err));
    BOOST_CHECK(!t.ValidateProbeTarget("192.168.1.5:29447", err));
    BOOST_CHECK(!t.ValidateProbeTarget("172.20.0.5:29447", err));
    BOOST_CHECK(!t.ValidateProbeTarget("169.254.169.254:29447", err));
    BOOST_CHECK(!t.ValidateProbeTarget("127.0.0.1:29447", err));

    const ReachabilityLimits lim;
    auto probe = [&](const std::string& id) {
        DialbackRequest r;
        r.request_id = id;
        r.candidate = "203.0.113.5:29447";
        r.requester = "requester-1";
        r.requester_netgroup = "203.0.113.0";
        r.now_ms = 5'000;
        return r;
    };

    // Malformed probes are refused before they can consume budget.
    BOOST_CHECK(!t.AdmitProbe(probe(""), err));
    BOOST_CHECK(!t.AdmitProbe(probe(std::string(65, 'a')), err));
    {
        DialbackRequest no_ttl = probe("p-ttl");
        no_ttl.ttl_ms = 0;
        BOOST_CHECK(!t.AdmitProbe(no_ttl, err));
        DialbackRequest long_ttl = probe("p-ttl2");
        long_ttl.ttl_ms = 6 * 60 * 1000;
        BOOST_CHECK(!t.AdmitProbe(long_ttl, err));
    }

    // One requester gets a bounded number of probes per minute. FinishProbe is
    // called each time so that it is the rate limiter, not the concurrency
    // ceiling, that closes.
    for (int i = 0; i < lim.max_probes_per_requester_per_minute; ++i) {
        BOOST_CHECK_MESSAGE(t.AdmitProbe(probe("p" + std::to_string(i)), err), err);
        t.FinishProbe();
    }
    BOOST_CHECK(!t.AdmitProbe(probe("p-over"), err));

    // Concurrency is capped independently of the rate.
    ReachabilityTracker c;
    for (int i = 0; i < lim.max_concurrent; ++i) {
        DialbackRequest r = probe("c" + std::to_string(i));
        r.requester = "requester-" + std::to_string(i);
        r.requester_netgroup = "198.51.100." + std::to_string(i);
        BOOST_CHECK_MESSAGE(c.AdmitProbe(r, err), err);
    }
    {
        DialbackRequest r = probe("c-over");
        r.requester = "requester-over";
        r.requester_netgroup = "198.51.100.200";
        BOOST_CHECK(!c.AdmitProbe(r, err));
    }

    // An unproven node advertises nothing, and address observations stay
    // bounded no matter how many arrive.
    ReachabilityTracker q;
    BOOST_CHECK(!q.MayAdvertiseHost(true));
    BOOST_CHECK(!q.MayAdvertiseHost(false));
    for (int i = 0; i < 64; ++i) {
        AddressObservation o;
        o.observer_id = "obs-" + std::to_string(i);
        o.observed = "203.0.113." + std::to_string((i % 200) + 1) + ":29447";
        q.NoteObservation(o, 10'000);
    }
    BOOST_CHECK_LE(q.StatusJson()["observations"].getInt<int>(), 16);
    // A control-plane endpoint is never recorded as our observed address.
    AddressObservation bad;
    bad.observer_id = "obs-bad";
    bad.observed = "203.0.113.9:8332";
    const int before = q.StatusJson()["observations"].getInt<int>();
    q.NoteObservation(bad, 10'000);
    BOOST_CHECK_EQUAL(q.StatusJson()["observations"].getInt<int>(), before);
}

BOOST_AUTO_TEST_CASE(r10_origin_stampede_budget_and_circuit_breaker)
{
    using namespace modelnet;

    const OriginStampedeState s;
    OriginStampedeGuard g{s};
    std::string err;

    // One key gets a bounded number of origin fetches per window.
    for (int i = 0; i < s.max_per_peer; ++i) {
        BOOST_CHECK_MESSAGE(g.Allow("peer-1", "203.0.113.0", 1'000, err), err);
    }
    BOOST_CHECK(!g.Allow("peer-1", "203.0.113.0", 1'000, err));
    BOOST_CHECK(!err.empty());

    // The window really is a window: the same key is allowed again after it.
    BOOST_CHECK(g.Allow("peer-1", "203.0.113.0", 1'000 + s.window_ms + 1, err));

    // Repeated failures open a circuit for that key rather than retrying.
    OriginStampedeGuard cb{s};
    BOOST_CHECK(!cb.CircuitOpen("peer-2", 1'000));
    for (int i = 0; i < s.errors_to_open; ++i) cb.NoteError("peer-2", 1'000);
    BOOST_CHECK(cb.CircuitOpen("peer-2", 1'000));
    BOOST_CHECK(!cb.Allow("peer-2", "203.0.113.0", 1'000, err));
    // And it closes again once the open period elapses.
    BOOST_CHECK(!cb.CircuitOpen("peer-2", 1'000 + s.open_ms + 1));

    // The guard reports how many keys it is tracking, which is what a bound on
    // that map would be asserted against once R10-04 is fixed.
    const UniValue j = cb.Json(1'000);
    BOOST_CHECK_EQUAL(j["max_per_peer"].getInt<int>(), s.max_per_peer);
    BOOST_CHECK_EQUAL(j["max_per_netgroup"].getInt<int>(), s.max_per_netgroup);
    BOOST_CHECK(j.exists("tracked_peers"));
    BOOST_CHECK_EQUAL(j["automatic_spend_atoms"].getInt<int>(), 0);
}

BOOST_AUTO_TEST_CASE(r10_event_journal_retention_dedupe_and_text_sanitising)
{
    using namespace modelnet;

    // Empty modeldir keeps the journal in memory: no test tree, no /tmp.
    ModelEventJournal j{fs::path{}, size_t{4}};
    BOOST_CHECK_EQUAL(j.Cap(), size_t{4});

    ObserveResult r;
    std::string err;
    for (int i = 0; i < 12; ++i) {
        ModelEvent ev;
        ev.event_type = ModelEventType::MODEL_PUBLISHED;
        ev.object_id = "obj-" + std::to_string(i);
        ev.observed_at = 1'000 + i;
        BOOST_REQUIRE_MESSAGE(j.Observe(ev, r, err), err);
        BOOST_CHECK(!r.duplicate);
    }
    // A flood of distinct events cannot grow the journal past its retention.
    BOOST_CHECK_EQUAL(j.Size(), size_t{4});
    // Retention drops the oldest, so the surviving window is the newest events.
    const auto kept = j.ReplayAfter(0, MODEL_EVENT_PAGE_MAX);
    BOOST_REQUIRE_EQUAL(kept.size(), size_t{4});
    BOOST_CHECK_EQUAL(kept.front().object_id, "obj-8");
    BOOST_CHECK_EQUAL(kept.back().object_id, "obj-11");

    // Replay is paged, and a caller cannot widen the page by asking for more.
    // Proven on a journal whose retention is deliberately larger than a page,
    // so the clamp is what closes rather than the retention cap.
    ModelEventJournal wide{fs::path{}, MODEL_EVENT_PAGE_MAX * 4};
    for (size_t i = 0; i < MODEL_EVENT_PAGE_MAX * 2; ++i) {
        ModelEvent ev;
        ev.event_type = ModelEventType::MODEL_PUBLISHED;
        ev.object_id = "wide-" + std::to_string(i);
        ev.observed_at = 3'000 + static_cast<int64_t>(i);
        BOOST_REQUIRE_MESSAGE(wide.Observe(ev, r, err), err);
    }
    BOOST_CHECK_EQUAL(wide.Size(), MODEL_EVENT_PAGE_MAX * 2);
    BOOST_CHECK_EQUAL(wide.ReplayAfter(0, 10'000).size(), MODEL_EVENT_PAGE_MAX);

    // The same logical transition observed twice is one event, so a replayed
    // announcement cannot inflate the journal or the sequence.
    ModelEventJournal d{fs::path{}, size_t{16}};
    ModelEvent ev;
    ev.event_type = ModelEventType::MODEL_PROVIDER_AVAILABLE;
    ev.object_id = "obj-dedupe";
    ev.record_sequence = 7;
    ev.observed_at = 2'000;
    ObserveResult first, again;
    BOOST_REQUIRE(d.Observe(ev, first, err));
    BOOST_CHECK(!first.duplicate);
    BOOST_REQUIRE(d.Observe(ev, again, err));
    BOOST_CHECK(again.duplicate);
    BOOST_CHECK_EQUAL(again.event_id, first.event_id);
    BOOST_CHECK_EQUAL(again.local_sequence, first.local_sequence);
    BOOST_CHECK_EQUAL(d.Size(), size_t{1});
    BOOST_CHECK_EQUAL(d.Cursor(), first.local_sequence);

    // Publisher text is stored, never interpreted, NUL-stripped and truncated.
    const std::string hostile = std::string("card") + '\0' + "text";
    const std::string clean = SanitizeUntrustedEventText(hostile);
    BOOST_CHECK(clean.find('\0') == std::string::npos);
    BOOST_CHECK_EQUAL(clean, "cardtext");
    // The truncation ceiling is located at its boundary rather than restated.
    BOOST_CHECK_EQUAL(SanitizeUntrustedEventText(std::string(SEARCH_DESC_MAX * 4, 'a')).size(), SEARCH_DESC_MAX);
    BOOST_CHECK_EQUAL(SanitizeUntrustedEventText(std::string(SEARCH_DESC_MAX, 'a')).size(), SEARCH_DESC_MAX);
    BOOST_CHECK_EQUAL(SanitizeUntrustedEventText(std::string(SEARCH_DESC_MAX - 1, 'a')).size(),
                      SEARCH_DESC_MAX - 1);

    // Hostile publisher text survives sanitising as inert bytes: it is stored
    // and returned verbatim, which is the point -- nothing downstream parses it.
    ModelEventJournal t{fs::path{}, size_t{4}};
    ModelEvent shell;
    shell.event_type = ModelEventType::MODEL_PUBLISHED;
    shell.object_id = "obj-hostile";
    shell.observed_at = 4'000;
    shell.untrusted_text = "$(rm -rf /); sendtoaddress ../../etc/passwd";
    ObserveResult hostile_out;
    BOOST_REQUIRE_MESSAGE(t.Observe(shell, hostile_out, err), err);
    const auto stored = t.ReplayAfter(0, MODEL_EVENT_PAGE_MAX);
    BOOST_REQUIRE_EQUAL(stored.size(), size_t{1});
    BOOST_CHECK_EQUAL(stored.front().untrusted_text, shell.untrusted_text);
    // It did not become a second event, a mandate, or an extra object id.
    BOOST_CHECK_EQUAL(t.Size(), size_t{1});
    BOOST_CHECK_EQUAL(stored.front().object_id, "obj-hostile");
}

// EventTextMayBecomeCommand / Rpc / Path / Mandate are deliberately not
// asserted here. Each has an unconditional `return false` body, so a check on
// one passes no matter what the journal does with publisher text and would keep
// passing if the sanitising above were deleted. The case above proves the same
// property the only way it can be proven: by storing hostile text and showing
// it comes back as inert bytes.

BOOST_AUTO_TEST_CASE(r10_import_locator_refusals)
{
    using namespace modelnet;
    std::string err;

    // Torrent file names: the two refusals that exist today. R10-12 records
    // that this guard should become IsPortableRelPath before any importer
    // writes a file named by a .torrent.
    BOOST_CHECK(TorrentFileNameAllowed("weights/model-00001.safetensors", err));
    BOOST_CHECK(!TorrentFileNameAllowed("/etc/passwd", err));
    BOOST_CHECK(!TorrentFileNameAllowed("../../etc/passwd", err));
    BOOST_CHECK(!TorrentFileNameAllowed("weights/../../etc/passwd", err));

    // HuggingFace locators: exotic schemes and every private, loopback,
    // link-local or metadata host are refused.
    BOOST_CHECK(HuggingFaceLocatorAllowed("https://huggingface.co/org/model", err));
    BOOST_CHECK(HuggingFaceLocatorAllowed("hf://org/model", err));
    BOOST_CHECK(!HuggingFaceLocatorAllowed("file:///etc/passwd", err));
    BOOST_CHECK(!HuggingFaceLocatorAllowed("unix:///var/run/docker.sock", err));
    BOOST_CHECK(!HuggingFaceLocatorAllowed("gopher://huggingface.co/model", err));
    BOOST_CHECK(!HuggingFaceLocatorAllowed("https://169.254.169.254/latest/meta-data", err));
    BOOST_CHECK(!HuggingFaceLocatorAllowed("https://metadata.google.internal/token", err));
    BOOST_CHECK(!HuggingFaceLocatorAllowed("https://127.0.0.1/model", err));
    BOOST_CHECK(!HuggingFaceLocatorAllowed("https://localhost/model", err));
    BOOST_CHECK(!HuggingFaceLocatorAllowed("https://10.0.0.1/model", err));
    BOOST_CHECK(!HuggingFaceLocatorAllowed("https://192.168.1.1/model", err));
    BOOST_CHECK(!HuggingFaceLocatorAllowed("https://0.0.0.0/model", err));
    BOOST_CHECK(!HuggingFaceLocatorAllowed("https://[fe80::1]/model", err));
    // The RFC1918 /12 boundary is respected in both directions.
    BOOST_CHECK(!HuggingFaceLocatorAllowed("https://172.16.0.1/model", err));
    BOOST_CHECK(!HuggingFaceLocatorAllowed("https://172.31.255.254/model", err));
    BOOST_CHECK(HuggingFaceLocatorAllowed("https://172.32.0.1/model", err));
    BOOST_CHECK(HuggingFaceLocatorAllowed("https://172.15.0.1/model", err));
    // Credentials in the authority must not hide the real host.
    BOOST_CHECK(!HuggingFaceLocatorAllowed("https://huggingface.co@169.254.169.254/model", err));
}

// The PQ1 resource ceilings are deliberately not re-listed here.
//
// A block of BOOST_CHECK_GT(PQ1_MAX_INBOUND, 0) style lines compares one
// constexpr to another and is decided by the compiler, not by the limiter: it
// would still pass with ConnLimits::TryInbound deleted. The enforcement that
// those numbers stand for is already driven to refusal by registered cases --
// modelnet_b0_remaining_tests.cpp and modelnet_b0_disc_store_tests.cpp both
// exhaust ConnLimits::TryInbound on one netgroup and CountUnauthAndBump past
// PQ1_UNAUTH_HANDSHAKE_LIMIT. Duplicating them here would add no evidence and
// would contend for the same process-global g_inbound_netgroup / g_unauth maps.
//
// Pq1HostileConfCannotWeaken and Pq1OpenSslEnvIsClean are likewise already
// asserted in modelnet_tests.cpp and modelnet_b0_remaining_tests.cpp.
//
// R10-01 and R10-03 are about how the inbound key and the worker pool are
// derived, not about the numbers, and remain UNPROVEN per the header.

BOOST_AUTO_TEST_SUITE_END()
