// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_p2_transcript_binding.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <utility>

namespace matmul::v4::rc::stage3_p2_transcript_binding {
namespace {

namespace ah = alg_hash;

bool Fail(std::string* why, const std::string& message)
{
    if (why != nullptr) {
        *why = "stage3:p2_transcript_binding:" + message;
    }
    return false;
}

void AppendLE32(std::vector<unsigned char>& out, uint32_t value)
{
    for (uint32_t byte = 0; byte < 4; ++byte) {
        out.push_back(static_cast<unsigned char>(value >> (8 * byte)));
    }
}

void AppendLE64(std::vector<unsigned char>& out, uint64_t value)
{
    for (uint32_t byte = 0; byte < 8; ++byte) {
        out.push_back(static_cast<unsigned char>(value >> (8 * byte)));
    }
}

void AppendFp3(std::vector<unsigned char>& out, const gf::Fp3& value)
{
    AppendLE64(out, gf::Canonical(value.c0));
    AppendLE64(out, gf::Canonical(value.c1));
    AppendLE64(out, gf::Canonical(value.c2));
}

void AppendDigest(
    std::vector<unsigned char>& out,
    const Fri3AlgDigest& digest)
{
    const uint256 encoded = Fri3AlgDigestToUint256(digest);
    out.insert(out.end(), encoded.begin(), encoded.end());
}

void AppendStringLanes(
    std::vector<gf::Fp>& lanes,
    const std::string& value)
{
    lanes.push_back(gf::FromU64(
        static_cast<uint32_t>(value.size())));
    for (size_t offset = 0; offset < value.size(); offset += 4) {
        uint32_t word = 0;
        for (size_t byte = 0;
             byte < 4 && offset + byte < value.size();
             ++byte) {
            word |= static_cast<uint32_t>(
                        static_cast<unsigned char>(
                            value[offset + byte]))
                    << (8 * byte);
        }
        lanes.push_back(gf::FromU64(word));
    }
}

void AppendBytesLanes(
    std::vector<gf::Fp>& lanes,
    const std::vector<unsigned char>& value)
{
    lanes.push_back(gf::FromU64(
        static_cast<uint32_t>(value.size())));
    for (size_t offset = 0; offset < value.size(); offset += 4) {
        uint32_t word = 0;
        for (size_t byte = 0;
             byte < 4 && offset + byte < value.size();
             ++byte) {
            word |= static_cast<uint32_t>(value[offset + byte])
                    << (8 * byte);
        }
        lanes.push_back(gf::FromU64(word));
    }
}

void AppendFp3Lanes(
    std::vector<gf::Fp>& lanes,
    const gf::Fp3& value)
{
    lanes.push_back(gf::Canonical(value.c0));
    lanes.push_back(gf::Canonical(value.c1));
    lanes.push_back(gf::Canonical(value.c2));
}

bool HasExtensionCoordinate(const gf::Fp3& value)
{
    return gf::Canonical(value.c1) != 0 ||
           gf::Canonical(value.c2) != 0;
}

bool SameFp3(const gf::Fp3& lhs, const gf::Fp3& rhs)
{
    return gf::Eq(lhs, rhs);
}

bool SameEvent(
    const ProofOwnedEvent& lhs,
    const ProofOwnedEvent& rhs)
{
    return lhs.kind == rhs.kind &&
           lhs.semantic_index == rhs.semantic_index &&
           lhs.draw_index == rhs.draw_index &&
           lhs.label == rhs.label &&
           lhs.fs_prefix == rhs.fs_prefix &&
           SameFp3(lhs.challenge, rhs.challenge) &&
           lhs.query_index == rhs.query_index &&
           lhs.is_query == rhs.is_query;
}

bool SameCell(
    const ConsumerCellMapEntry& lhs,
    const ConsumerCellMapEntry& rhs)
{
    return lhs.event_ordinal == rhs.event_ordinal &&
           lhs.kind == rhs.kind &&
           lhs.semantic_index == rhs.semantic_index &&
           lhs.family == rhs.family &&
           lhs.consumer_index == rhs.consumer_index &&
           lhs.width == rhs.width &&
           SameFp3(lhs.fp3_value, rhs.fp3_value) &&
           lhs.index_value == rhs.index_value &&
           lhs.value_available == rhs.value_available;
}

bool SamePrefixScheduleEntry(
    const PrefixScheduleEntry& lhs,
    const PrefixScheduleEntry& rhs)
{
    return lhs.ordinal == rhs.ordinal &&
           lhs.source_kind == rhs.source_kind &&
           lhs.semantic_index == rhs.semantic_index &&
           lhs.first_event_ordinal ==
               rhs.first_event_ordinal &&
           lhs.event_count == rhs.event_count &&
           lhs.fs_prefix == rhs.fs_prefix &&
           lhs.proof_owned == rhs.proof_owned;
}

std::vector<unsigned char> InitialV10FsPrefix(
    const Fri3AlgBatchProof& proof,
    const uint256& fs_seed)
{
    std::vector<unsigned char> out;
    const char* domain =
        kRCFri3AlgP2Q192K2DomainTagV10;
    out.insert(
        out.end(),
        reinterpret_cast<const unsigned char*>(domain),
        reinterpret_cast<const unsigned char*>(domain) +
            std::strlen(domain));
    out.insert(out.end(), fs_seed.begin(), fs_seed.end());
    AppendLE64(out, proof.pow_grind_nonce);
    AppendLE32(out, proof.blowup);
    AppendLE32(out, proof.n_coeffs);
    AppendLE32(out, proof.version);
    AppendLE32(
        out,
        static_cast<uint32_t>(proof.column_len.size()));
    AppendDigest(
        out,
        Fri3AlgShapeCommit(
            proof.n_coeffs, proof.column_len));
    AppendDigest(out, proof.row_commit.root);
    return out;
}

ProofOwnedEvent Fp3Event(
    p2tx::EventKind kind,
    uint32_t semantic_index,
    uint32_t draw_index,
    const char* label,
    const std::vector<unsigned char>& prefix,
    const gf::Fp3& challenge)
{
    ProofOwnedEvent out;
    out.kind = kind;
    out.semantic_index = semantic_index;
    out.draw_index = draw_index;
    out.label = label;
    out.fs_prefix = prefix;
    out.challenge = challenge;
    return out;
}

bool ReconstructActiveEvents(
    const Fri3AlgBatchProof& proof,
    std::vector<unsigned char>& initial_prefix,
    std::vector<ProofOwnedEvent>& events,
    std::string* why)
{
    events.clear();
    std::vector<unsigned char> fs = initial_prefix;

    const gf::Fp3 lambda =
        Fri3AlgP2SqueezeChallengeFp3(
            fs, "fra3_lambda", 0);
    if (!SameFp3(lambda, proof.lambda)) {
        return Fail(why, "lambda_replay_mismatch");
    }
    events.push_back(Fp3Event(
        p2tx::EventKind::FriLambda, 0, 0,
        "fra3_lambda", fs, lambda));
    AppendFp3(fs, proof.lambda);

    uint32_t draw = 0;
    gf::Fp3 selected_z1{};
    bool found_z1 = false;
    for (; draw <
           kRCFri3AlgP2Q192K2OodCandidatesV10;
         ++draw) {
        const gf::Fp3 candidate =
            Fri3AlgP2SqueezeChallengeFp3(
                fs, "fra3_z", draw);
        if (!HasExtensionCoordinate(candidate)) continue;
        selected_z1 = candidate;
        events.push_back(Fp3Event(
            p2tx::EventKind::OodZ1, 0, draw,
            "fra3_z", fs, candidate));
        found_z1 = true;
        break;
    }
    if (!found_z1 || !SameFp3(selected_z1, proof.z1)) {
        return Fail(why, "z1_replay_mismatch");
    }

    draw = kRCFri3AlgP2Q192K2OodCandidatesV10;
    gf::Fp3 selected_z2{};
    bool found_z2 = false;
    for (;
         draw <
         2 * kRCFri3AlgP2Q192K2OodCandidatesV10;
         ++draw) {
        const gf::Fp3 candidate =
            Fri3AlgP2SqueezeChallengeFp3(
                fs, "fra3_z", draw);
        if (!HasExtensionCoordinate(candidate) ||
            SameFp3(candidate, selected_z1)) {
            continue;
        }
        selected_z2 = candidate;
        events.push_back(Fp3Event(
            p2tx::EventKind::OodZ2, 1, draw,
            "fra3_z", fs, candidate));
        found_z2 = true;
        break;
    }
    if (!found_z2 || !SameFp3(selected_z2, proof.z2)) {
        return Fail(why, "z2_replay_mismatch");
    }
    AppendFp3(fs, proof.z1);
    AppendFp3(fs, proof.z2);
    AppendDigest(
        fs,
        Fri3AlgOodEvalCommit(
            proof.z1, proof.z2,
            proof.evals_z1, proof.evals_z2));

    const gf::Fp3 w1 =
        Fri3AlgP2SqueezeChallengeFp3(
            fs, "fra3_w", 0);
    const gf::Fp3 w2 =
        Fri3AlgP2SqueezeChallengeFp3(
            fs, "fra3_w", 1);
    if (!SameFp3(w1, proof.w1) ||
        !SameFp3(w2, proof.w2)) {
        return Fail(why, "weight_replay_mismatch");
    }
    events.push_back(Fp3Event(
        p2tx::EventKind::DeepW1, 0, 0,
        "fra3_w", fs, w1));
    events.push_back(Fp3Event(
        p2tx::EventKind::DeepW2, 1, 1,
        "fra3_w", fs, w2));
    AppendFp3(fs, proof.w1);
    AppendFp3(fs, proof.w2);

    if (proof.fold_layers.size() !=
        proof.fold_challenges.size() + 1) {
        return Fail(why, "fold_shape");
    }
    for (size_t fold = 0;
         fold < proof.fold_layers.size();
         ++fold) {
        AppendDigest(fs, proof.fold_layers[fold].root);
        if (fold == proof.fold_challenges.size()) break;
        const gf::Fp3 beta =
            Fri3AlgP2SqueezeChallengeFp3(
                fs, "fra3_fold",
                static_cast<uint32_t>(fold));
        if (!SameFp3(
                beta, proof.fold_challenges[fold])) {
            return Fail(
                why,
                "fold_replay_mismatch_" +
                    std::to_string(fold));
        }
        events.push_back(Fp3Event(
            p2tx::EventKind::Fold,
            static_cast<uint32_t>(fold),
            static_cast<uint32_t>(fold),
            "fra3_fold", fs, beta));
    }

    if (proof.queries.size() != kRCFri3AlgNumQueries) {
        return Fail(why, "query_count");
    }
    const uint64_t n_lde64 =
        static_cast<uint64_t>(proof.n_coeffs) *
        proof.blowup;
    if (n_lde64 == 0 ||
        n_lde64 >
            std::numeric_limits<uint32_t>::max()) {
        return Fail(why, "query_modulus_overflow");
    }
    const uint32_t n_lde =
        static_cast<uint32_t>(n_lde64);
    for (uint32_t query = 0;
         query < kRCFri3AlgNumQueries;
         ++query) {
        const gf::Fp3 challenge =
            Fri3AlgP2SqueezeChallengeFp3(
                fs, "fra3_query", query);
        const unsigned __int128 wide =
            (static_cast<unsigned __int128>(
                 gf::Canonical(challenge.c1))
             << 64) |
            gf::Canonical(challenge.c0);
        const uint32_t index =
            static_cast<uint32_t>(wide % n_lde);
        if (index != proof.queries[query].index) {
            return Fail(
                why,
                "query_replay_mismatch_" +
                    std::to_string(query));
        }
        ProofOwnedEvent event = Fp3Event(
            p2tx::EventKind::Query,
            query, query, "fra3_query",
            fs, challenge);
        event.is_query = true;
        event.query_index = index;
        events.push_back(std::move(event));
    }
    return true;
}

std::vector<PrefixScheduleEntry> BuildPrefixSchedule(
    const std::vector<ProofOwnedEvent>& events)
{
    std::vector<PrefixScheduleEntry> out;
    if (events.size() <
        5 + kRCFri3AlgNumQueries) {
        return out;
    }
    const auto append =
        [&](PrefixSourceKind kind,
            uint32_t semantic_index,
            uint32_t first_event,
            uint32_t count,
            const std::vector<unsigned char>& prefix,
            bool proof_owned) {
            PrefixScheduleEntry entry;
            entry.ordinal =
                static_cast<uint32_t>(out.size());
            entry.source_kind = kind;
            entry.semantic_index = semantic_index;
            entry.first_event_ordinal = first_event;
            entry.event_count = count;
            entry.fs_prefix = prefix;
            entry.proof_owned = proof_owned;
            out.push_back(std::move(entry));
        };

    // There is no Fri3Alg byte prefix for the AIR-quotient lambda.
    append(
        PrefixSourceKind::MissingAirqTranscript,
        0, std::numeric_limits<uint32_t>::max(),
        0, {}, false);
    // Local event ordinal 0 is FRI lambda.
    append(
        PrefixSourceKind::FriInitialLambda,
        0, 0, 1, events[0].fs_prefix, true);
    // Local event ordinals 1,2 are z1,z2. Both use the post-lambda
    // prefix; V10 reserves the fixed candidate windows {0,1}/{2,3}.
    append(
        PrefixSourceKind::FriPostLambdaOod,
        0, 1, 2, events[1].fs_prefix, true);
    // Local event ordinals 3,4 are w1,w2 and share one post-claim prefix.
    append(
        PrefixSourceKind::FriPostZClaimWeights,
        0, 3, 2, events[3].fs_prefix, true);

    size_t cursor = 5;
    uint32_t local_ordinal = 5;
    while (cursor < events.size() &&
           events[cursor].kind ==
               p2tx::EventKind::Fold) {
        append(
            PrefixSourceKind::FriPostFoldRoot,
            events[cursor].semantic_index,
            local_ordinal, 1,
            events[cursor].fs_prefix, true);
        ++cursor;
        ++local_ordinal;
    }
    if (cursor >= events.size() ||
        events[cursor].kind !=
            p2tx::EventKind::Query ||
        events.size() - cursor !=
            kRCFri3AlgNumQueries) {
        return {};
    }
    append(
        PrefixSourceKind::FriTerminalQueries,
        0, local_ordinal,
        kRCFri3AlgNumQueries,
        events[cursor].fs_prefix, true);
    return out;
}

Fri3AlgDigest CommitSource(
    const BindingResult& binding)
{
    std::vector<gf::Fp> lanes;
    AppendStringLanes(lanes, kBindingDomainTag);
    lanes.push_back(gf::FromU64(kBindingVersion));
    lanes.push_back(gf::FromU64(binding.source_proof_version));
    AppendStringLanes(
        lanes, binding.source_protocol_domain);
    lanes.push_back(gf::FromU64(
        binding.target_proof_version));
    AppendStringLanes(
        lanes, binding.target_protocol_domain);
    std::vector<unsigned char> statement_commitment;
    std::string ignored;
    if (!p2tx::CanonicalStatementPrefix(
            binding.statement,
            statement_commitment, &ignored)) {
        return {};
    }
    AppendBytesLanes(lanes, statement_commitment);
    lanes.push_back(gf::FromU64(
        static_cast<uint32_t>(
            binding.source_events.size())));
    for (const ProofOwnedEvent& event :
         binding.source_events) {
        lanes.push_back(gf::FromU64(
            static_cast<uint32_t>(event.kind)));
        lanes.push_back(gf::FromU64(
            event.semantic_index));
        lanes.push_back(gf::FromU64(
            event.draw_index));
        AppendStringLanes(lanes, event.label);
        AppendBytesLanes(lanes, event.fs_prefix);
        AppendFp3Lanes(lanes, event.challenge);
        lanes.push_back(gf::FromU64(
            event.query_index));
        lanes.push_back(gf::FromU64(
            event.is_query ? 1 : 0));
    }
    lanes.push_back(gf::FromU64(
        static_cast<uint32_t>(
            binding.prefix_schedule.size())));
    for (const PrefixScheduleEntry& entry :
         binding.prefix_schedule) {
        lanes.push_back(gf::FromU64(entry.ordinal));
        lanes.push_back(gf::FromU64(
            static_cast<uint32_t>(
                entry.source_kind)));
        lanes.push_back(gf::FromU64(
            entry.semantic_index));
        lanes.push_back(gf::FromU64(
            entry.first_event_ordinal));
        lanes.push_back(gf::FromU64(
            entry.event_count));
        AppendBytesLanes(lanes, entry.fs_prefix);
        lanes.push_back(gf::FromU64(
            entry.proof_owned ? 1 : 0));
    }
    return ah::SpongeHashFp(lanes);
}

Fri3AlgDigest CommitConsumerManifest(
    const ConsumerMappingManifest& manifest)
{
    std::vector<gf::Fp> lanes;
    AppendStringLanes(lanes, kBindingDomainTag);
    lanes.push_back(gf::FromU64(kBindingVersion));
    lanes.push_back(gf::FromU64(
        static_cast<uint32_t>(
            manifest.entries.size())));
    for (const ConsumerCellMapEntry& entry :
         manifest.entries) {
        lanes.push_back(gf::FromU64(entry.event_ordinal));
        lanes.push_back(gf::FromU64(
            static_cast<uint32_t>(entry.kind)));
        lanes.push_back(gf::FromU64(
            entry.semantic_index));
        lanes.push_back(gf::FromU64(
            static_cast<uint32_t>(entry.family)));
        lanes.push_back(gf::FromU64(
            entry.consumer_index));
        lanes.push_back(gf::FromU64(entry.width));
        AppendFp3Lanes(lanes, entry.fp3_value);
        lanes.push_back(gf::FromU64(
            entry.index_value));
        lanes.push_back(gf::FromU64(
            entry.value_available ? 1 : 0));
    }
    return ah::SpongeHashFp(lanes);
}

ConsumerMappingManifest BuildConsumerManifest(
    const p2tx::Statement& statement,
    const Fri3AlgBatchProof& proof,
    std::string* why)
{
    ConsumerMappingManifest out;
    std::vector<p2tx::EventDescriptor> events;
    if (!p2tx::CanonicalEventManifest(
            statement, events, why)) {
        return out;
    }
    out.entries.reserve(events.size());
    for (const auto& event : events) {
        ConsumerCellMapEntry entry;
        entry.event_ordinal = event.ordinal;
        entry.kind = event.kind;
        entry.semantic_index = event.semantic_index;
        entry.consumer_index = event.semantic_index;
        switch (event.kind) {
        case p2tx::EventKind::FriLambda:
            entry.family = ConsumerFamily::ProofLambda;
            entry.width = 3;
            entry.fp3_value = proof.lambda;
            entry.value_available = true;
            break;
        case p2tx::EventKind::OodZ1:
            entry.family = ConsumerFamily::ProofZ1;
            entry.width = 3;
            entry.fp3_value = proof.z1;
            entry.value_available = true;
            break;
        case p2tx::EventKind::OodZ2:
            entry.family = ConsumerFamily::ProofZ2;
            entry.width = 3;
            entry.fp3_value = proof.z2;
            entry.value_available = true;
            break;
        case p2tx::EventKind::DeepW1:
            entry.family = ConsumerFamily::ProofW1;
            entry.width = 3;
            entry.fp3_value = proof.w1;
            entry.value_available = true;
            break;
        case p2tx::EventKind::DeepW2:
            entry.family = ConsumerFamily::ProofW2;
            entry.width = 3;
            entry.fp3_value = proof.w2;
            entry.value_available = true;
            break;
        case p2tx::EventKind::Fold:
            if (event.semantic_index >=
                proof.fold_challenges.size()) {
                Fail(why, "consumer_fold_oob");
                return {};
            }
            entry.family =
                ConsumerFamily::ProofFoldChallenge;
            entry.width = 3;
            entry.fp3_value =
                proof.fold_challenges[
                    event.semantic_index];
            entry.value_available = true;
            break;
        case p2tx::EventKind::Query:
            if (event.semantic_index >=
                proof.queries.size()) {
                Fail(why, "consumer_query_oob");
                return {};
            }
            entry.family =
                ConsumerFamily::ProofQueryIndex;
            entry.width = 1;
            entry.index_value =
                proof.queries[event.semantic_index].index;
            entry.value_available = true;
            break;
        }
        out.entries.push_back(std::move(entry));
    }
    out.commitment = CommitConsumerManifest(out);
    out.canonical = true;
    return out;
}

bool SameDigest(
    const Fri3AlgDigest& lhs,
    const Fri3AlgDigest& rhs)
{
    return lhs == rhs;
}

} // namespace

BindingResult BuildProofOwnedTranscriptBindingV10(
    const Fri3AlgBatchProof& proof,
    const uint256& fs_seed)
{
    BindingResult out;
    out.source_proof_version = proof.version;
    out.source_protocol_domain =
        kRCFri3AlgP2Q192K2DomainTagV10;

    if (proof.version !=
            kRCFri3AlgP2Q192K2ProofVersionV10) {
        out.note =
            "stage3:p2_transcript_binding:"
            "source_not_v10_k2_p2";
        return out;
    }

    std::vector<unsigned char> encoded;
    const size_t encoded_size =
        SerializeFri3AlgBatchProof(proof, encoded);
    const auto decoded =
        DeserializeFri3AlgP2Q192K2V10BatchProof(
            encoded);
    std::vector<unsigned char> roundtrip;
    size_t roundtrip_size = 0;
    if (decoded.has_value()) {
        // Capture before comparing: evaluating Serialize(...) and
        // roundtrip.size() as opposite operands of one expression has
        // unspecified evaluation order in C++.
        roundtrip_size =
            SerializeFri3AlgBatchProof(
                *decoded, roundtrip);
    }
    if (encoded_size == 0 ||
        encoded_size != encoded.size() ||
        !decoded.has_value() ||
        roundtrip_size != roundtrip.size() ||
        roundtrip != encoded) {
        out.note =
            "stage3:p2_transcript_binding:"
            "noncanonical_proof_codec";
        return out;
    }
    out.canonical_proof_bytes = std::move(encoded);
    out.canonical_proof_codec = true;

    std::string verify_why;
    if (!Fri3AlgP2Q192K2V10BatchVerify(
            proof, fs_seed, &verify_why)) {
        out.note =
            "stage3:p2_transcript_binding:"
            "native_verify:" + verify_why;
        return out;
    }
    out.native_proof_verified = true;

    std::vector<unsigned char> initial =
        InitialV10FsPrefix(proof, fs_seed);
    if (initial.empty() ||
        !ReconstructActiveEvents(
            proof, initial,
            out.source_events, &verify_why)) {
        out.note = verify_why.empty()
            ? "stage3:p2_transcript_binding:"
              "source_replay"
            : verify_why;
        return out;
    }
    out.proof_owned_prefix_reconstructed = true;
    out.exact_active_transcript_replayed = true;
    out.prefix_schedule =
        BuildPrefixSchedule(out.source_events);
    if (out.prefix_schedule.empty()) {
        out.note =
            "stage3:p2_transcript_binding:"
            "prefix_schedule";
        return out;
    }
    out.compact_prefix_schedule_canonical = true;

    out.statement.version = p2tx::kArtifactVersion;
    out.statement.queries = p2tx::kQueries;
    out.statement.ood_candidates =
        p2tx::kOodCandidates;
    out.statement.n_folds =
        static_cast<uint32_t>(
            proof.fold_challenges.size());
    const uint64_t n_lde64 =
        static_cast<uint64_t>(proof.n_coeffs) *
        proof.blowup;
    if (n_lde64 < 2 ||
        n_lde64 >
            std::numeric_limits<uint32_t>::max()) {
        out.note =
            "stage3:p2_transcript_binding:"
            "bad_query_modulus";
        return out;
    }
    out.statement.query_modulus =
        static_cast<uint32_t>(n_lde64);
    out.statement.event_prefixes.reserve(
        out.source_events.size());
    for (const ProofOwnedEvent& event :
         out.source_events) {
        p2tx::EventPrefix prefix;
        prefix.kind = event.kind;
        prefix.semantic_index =
            event.semantic_index;
        prefix.bytes = event.fs_prefix;
        out.statement.event_prefixes.push_back(
            std::move(prefix));
    }

    std::vector<p2tx::EventDescriptor> canonical;
    if (!p2tx::CanonicalEventManifest(
            out.statement, canonical, &verify_why)) {
        out.note = verify_why;
        return out;
    }
    if (canonical.size() !=
        out.source_events.size()) {
        out.note =
            "stage3:p2_transcript_binding:"
            "source_event_count";
        return out;
    }
    for (size_t index = 0;
         index < out.source_events.size();
         ++index) {
        const auto& expected = canonical[index];
        const auto& actual = out.source_events[index];
        if (expected.kind != actual.kind ||
            expected.semantic_index !=
                actual.semantic_index ||
            expected.label != actual.label) {
            out.note =
                "stage3:p2_transcript_binding:"
                "source_event_order_" +
                std::to_string(index);
            return out;
        }
    }
    out.source_event_order_complete = true;

    out.consumer_manifest =
        BuildConsumerManifest(
            out.statement, proof, &verify_why);
    if (!out.consumer_manifest.canonical) {
        out.note = verify_why;
        return out;
    }
    out.consumer_mapping_canonical = true;
    out.source_commitment = CommitSource(out);
    out.proof_owned_source_cells_bound = true;

    // These are genuine residuals, not TODO constants that may be flipped.
    out.local_air_event_prefixes_match_active_protocol = true;
    out.v10_k2_protocol_producer_executable = true;
    out.recursive_consumer_cells_bound = false;
    out.recursive_authority = false;
    out.valid =
        out.canonical_proof_codec &&
        out.native_proof_verified &&
        out.proof_owned_prefix_reconstructed &&
        out.compact_prefix_schedule_canonical &&
        out.exact_active_transcript_replayed &&
        out.source_event_order_complete &&
        out.consumer_mapping_canonical &&
        out.proof_owned_source_cells_bound &&
        out.local_air_event_prefixes_match_active_protocol &&
        out.v10_k2_protocol_producer_executable &&
        !out.recursive_consumer_cells_bound &&
        !out.recursive_authority;
    out.note =
        out.valid
            ? "proof-owned fixed-K=2 V10 transcript, event-prefix AIR "
              "schedule, and canonical consumer layout execute; AIRQ is "
              "separate and same-parent consumer equalities remain open"
            : "stage3:p2_transcript_binding:incomplete_foundation";
    return out;
}

bool ValidateProofOwnedTranscriptBindingV10(
    const BindingResult& binding,
    const Fri3AlgBatchProof& proof,
    const uint256& fs_seed,
    std::string* why)
{
    if (binding.version != kBindingVersion ||
        binding.domain_tag != kBindingDomainTag) {
        return Fail(why, "binding_domain_or_version");
    }
    const BindingResult expected =
        BuildProofOwnedTranscriptBindingV10(
            proof, fs_seed);
    if (!expected.valid) {
        return Fail(why, "rebuild:" + expected.note);
    }
    if (!binding.valid ||
        binding.source_proof_version !=
            expected.source_proof_version ||
        binding.source_protocol_domain !=
            expected.source_protocol_domain ||
        binding.target_proof_version !=
            expected.target_proof_version ||
        binding.target_protocol_domain !=
            expected.target_protocol_domain ||
        binding.statement.version !=
            expected.statement.version ||
        binding.statement.queries !=
            expected.statement.queries ||
        binding.statement.ood_candidates !=
            expected.statement.ood_candidates ||
        binding.statement.n_folds !=
            expected.statement.n_folds ||
        binding.statement.query_modulus !=
            expected.statement.query_modulus ||
        binding.statement.event_prefixes.size() !=
            expected.statement.event_prefixes.size() ||
        binding.canonical_proof_bytes !=
            expected.canonical_proof_bytes ||
        binding.source_events.size() !=
            expected.source_events.size() ||
        binding.prefix_schedule.size() !=
            expected.prefix_schedule.size() ||
        binding.consumer_manifest.version !=
            expected.consumer_manifest.version ||
        binding.consumer_manifest.domain_tag !=
            expected.consumer_manifest.domain_tag ||
        binding.consumer_manifest.entries.size() !=
            expected.consumer_manifest.entries.size() ||
        !SameDigest(
            binding.source_commitment,
            expected.source_commitment) ||
        !SameDigest(
            binding.consumer_manifest.commitment,
            expected.consumer_manifest.commitment)) {
        return Fail(why, "binding_header_or_commitment");
    }
    for (size_t index = 0;
         index <
             expected.statement.event_prefixes.size();
         ++index) {
        const auto& lhs =
            binding.statement.event_prefixes[index];
        const auto& rhs =
            expected.statement.event_prefixes[index];
        if (lhs.kind != rhs.kind ||
            lhs.semantic_index != rhs.semantic_index ||
            lhs.bytes != rhs.bytes) {
            return Fail(
                why,
                "statement_event_prefix_" +
                    std::to_string(index));
        }
    }
    for (size_t index = 0;
         index < expected.source_events.size();
         ++index) {
        if (!SameEvent(
                binding.source_events[index],
                expected.source_events[index])) {
            return Fail(
                why,
                "source_event_" +
                    std::to_string(index));
        }
    }
    for (size_t index = 0;
         index < expected.prefix_schedule.size();
         ++index) {
        if (!SamePrefixScheduleEntry(
                binding.prefix_schedule[index],
                expected.prefix_schedule[index])) {
            return Fail(
                why,
                "prefix_schedule_" +
                    std::to_string(index));
        }
    }
    for (size_t index = 0;
         index <
             expected.consumer_manifest.entries.size();
         ++index) {
        if (!SameCell(
                binding.consumer_manifest.entries[index],
                expected.consumer_manifest.entries[index])) {
            return Fail(
                why,
                "consumer_cell_" +
                    std::to_string(index));
        }
    }
    if (!binding.canonical_proof_codec ||
        !binding.native_proof_verified ||
        !binding.proof_owned_prefix_reconstructed ||
        !binding.compact_prefix_schedule_canonical ||
        !binding.exact_active_transcript_replayed ||
        !binding.source_event_order_complete ||
        !binding.consumer_mapping_canonical ||
        !binding.proof_owned_source_cells_bound ||
        !binding.local_air_event_prefixes_match_active_protocol ||
        !binding.v10_k2_protocol_producer_executable ||
        binding.recursive_consumer_cells_bound ||
        binding.recursive_authority ||
        !binding.consumer_manifest.canonical ||
        !binding.consumer_manifest.appendable_layout_only ||
        binding.consumer_manifest.same_parent_cells_bound) {
        return Fail(why, "predicate_overclaim_or_loss");
    }
    return true;
}

bool AssessLocalAirConsumerEqualityV10(
    const BindingResult& binding,
    const p2tx::BuildResult& air,
    std::vector<uint32_t>& mismatching_ordinals,
    std::string* why)
{
    mismatching_ordinals.clear();
    if (!binding.valid ||
        !binding.consumer_manifest.canonical ||
        !air.valid ||
        !p2tx::IsCanonicalEventManifest(
            binding.statement,
            air.manifest, why) ||
        air.event_challenges.size() !=
            binding.consumer_manifest.entries.size()) {
        return Fail(why, "bad_binding_or_air");
    }
    size_t query_cursor = 0;
    for (const ConsumerCellMapEntry& entry :
         binding.consumer_manifest.entries) {
        bool matches = entry.value_available;
        if (entry.kind == p2tx::EventKind::Query) {
            if (query_cursor >=
                air.query_indices.size()) {
                matches = false;
            } else {
                matches =
                    entry.value_available &&
                    air.query_indices[query_cursor] ==
                        entry.index_value;
            }
            ++query_cursor;
        } else {
            matches =
                entry.value_available &&
                SameFp3(
                    air.event_challenges[
                        entry.event_ordinal],
                    entry.fp3_value);
        }
        if (!matches) {
            mismatching_ordinals.push_back(
                entry.event_ordinal);
        }
    }
    if (query_cursor != air.query_indices.size()) {
        return Fail(why, "query_schedule_size");
    }
    if (!mismatching_ordinals.empty()) {
        return Fail(
            why,
            "air_consumer_value_mismatch");
    }
    // All values now agree with the genuine V10 producer, but comparison in
    // this host function is not an AIR equality constraint. The recursive
    // parent must export these cells and constrain the row-tagged map before
    // this can become an authority predicate.
    return Fail(why, "same_parent_cells_not_exported");
}

} // namespace matmul::v4::rc::stage3_p2_transcript_binding
