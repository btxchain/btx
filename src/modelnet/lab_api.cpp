// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/lab_api.h>

#include <modelnet/action_authority.h>
#include <modelnet/admission_routes.h>
#include <modelnet/canonical_codec.h>
#include <modelnet/git_snapshot.h>
#include <modelnet/guard_machine.h>
#include <modelnet/identity.h>
#include <modelnet/lab_ancestry.h>
#include <modelnet/lab_disk.h>
#include <modelnet/lab_exchange.h>
#include <modelnet/lab_peer.h>
#include <modelnet/lab_guard_client.h>
#include <modelnet/model_admission.h>
#include <modelnet/piece_store.h>
#include <modelnet/pq_delegation.h>
#include <modelnet/realm_channel.h>
#include <modelnet/research_graph.h>
#include <modelnet/research_views.h>
#include <modelnet/training_integer.h>
#include <modelnet/training_launch.h>
#include <modelnet/workspace_journal.h>
#include <crypto/sha384.h>
#include <span.h>
#include <support/cleanse.h>
#include <sync.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/strencodings.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace modelnet {
namespace {

bool DecodePieceLine(const std::string& line, std::string& digest, size_t& index, std::string& chunk, std::string& err);
bool ParseDec(const std::string& s, int64_t& out);
bool Fail(std::string& err, const char* code);

GlobalMutex g_lab_mutex;

enum class LabKind {
    INFO, RECORD_GET, RECORD_IMPORT, RECORD_VERIFY, IDENTITY_INSPECT, IDENTITY_CREATE,
    IDENTITY_SIGN, IDENTITY_MUTATE, IDENTITY_REFRESH, GRANT, SUBSCRIBE, UNSUBSCRIBE,
    EVENTS, PUBLISH, OP_GET, OP_CANCEL, ADMIT, HOST, UNHOST, PREPARE, EXECUTE, PAUSE,
    RESUME, REALM_CREATE, REALM_STATUS, CHANNEL_GET, CHANNEL_PUBLISH, ROLLOUT_STATUS,
    ROLLOUT_PAUSE, ROLLOUT_ENDPOINTS, MIG_PLAN, MIG_VERIFY, ECONOMY, STATE_GET, AUDIT,
    QUERY, OP_START, RECORD,
};

struct LabMethod {
    const char* name;
    const char* required;
    const char* nullable;
    const char* types;
    LabKind kind;
};

#include <modelnet/lab_methods.inc>

struct Operation {
    std::string state{"RUNNING"};
    std::string physical{"STILL_IN_FLIGHT"};
    uint64_t generation{1};
};

struct IssuedPermit {
    std::string effect;
    uint64_t generation{1};
    std::string fingerprint;
    int64_t not_after_ms{0};
};

struct TrainKept {
    std::string profile;
    IntegerState state;
    LaunchCheckpoint launch;
    std::vector<Interval> intervals;
    std::string author;
};

/** Bearer that authorizes one snapshot export of one repository. */
struct FetchTicket {
    std::string repository_id;
    std::string operation;
    int64_t max_bytes{0};
    int64_t not_after_ms{0};
    bool consumed{false};
};

int64_t NowMs()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

struct Store {
    Store() : gate(std::make_unique<ActionGate>()) {}
    std::unique_ptr<ActionGate> gate;
    IdentityChain chain;
    RealmRollout rollout;
    ResearchBook research;
    WorkspaceBook workspaces;
    struct IdemRow {
        std::string caller;
        std::string key;
        std::string digest;
        std::string result;
        bool retired{false};
    };
    std::vector<IdemRow> idempotency;
    std::map<std::string, std::string> admission_subject;
    bool recovery_required{false};
    uint64_t commit_generation{1};
    std::map<std::string, std::string> records;
    std::map<std::string, std::string> identities;
    std::map<std::string, std::vector<unsigned char>> identity_pk;
    std::map<std::string, std::vector<unsigned char>> identity_sk;
    std::string active_root;
    std::map<std::string, Operation> operations;
    std::map<std::string, std::string> admissions;
    std::set<std::string> hosted;
    std::set<std::string> paused_bindings;
    std::map<std::string, IssuedPermit> permit_rows;
    std::map<std::string, std::string> grants;
    std::map<std::string, uint64_t> subscription_cursor;
    std::vector<std::string> published;
    std::set<std::string> repos;
    std::map<std::string, std::string> repo_commit;
    /** Genesis commit stored at repository create. First null old_target may replace it. */
    std::map<std::string, std::string> repo_genesis;
    /** Repositories that already accepted a GitRefUpdate. */
    std::set<std::string> repo_ref_published;
    std::set<std::string> snapshots;
    std::map<std::string, std::string> checkpoints;
    std::map<std::string, std::string> realms;
    std::map<std::string, std::string> plans;
    std::map<std::string, uint64_t> pause_epoch;
    std::map<std::string, std::string> workspace_backend;
    std::map<std::string, std::string> lineage;
    std::map<std::string, std::string> bindings;
    std::set<std::string> migrations;
    std::set<std::string> migration_plans;
    std::map<std::string, std::string> tokens;
    std::string token_subject;
    GuardTable guards;
    std::map<std::string, TrainKept> trains;
    /** Artifact digest to canonical INTEGER_MODEL bytes. */
    std::map<std::string, std::string> models;
    /** Pieces of those bytes, in order. Empty means the whole object is the only copy. */
    std::map<std::string, std::vector<std::string>> model_pieces;
    /** Rings that rehashed and reached ACTIVE, keyed by plan id. */
    std::map<std::string, std::set<std::string>> verified_rings;
    std::vector<ResearchObservation> observations;
    std::map<std::string, std::vector<ExchangeObject>> repo_objects;
    std::map<std::string, FetchTicket> fetch_tickets;
    std::vector<std::string> endpoint_receipts;
};

std::string HexBytes(const std::vector<unsigned char>& bytes)
{
    static const char* digits = "0123456789abcdef";
    std::string out(bytes.size() * 2, '\0');
    for (size_t i = 0; i < bytes.size(); ++i) {
        out[i * 2] = digits[bytes[i] >> 4];
        out[i * 2 + 1] = digits[bytes[i] & 0x0f];
    }
    return out;
}

bool BytesFromHex(const std::string& hex, std::vector<unsigned char>& out)
{
    if (hex.size() % 2 != 0) return false;
    out.clear();
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            return -1;
        };
        const int hi = nibble(hex[i]);
        const int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return true;
}

void ImageFromStore(const Store& store, LabDiskImage& image)
{
    image = LabDiskImage{};
    image.records = store.records;
    image.observations = store.observations;
    for (const auto& entry : store.repo_objects) {
        std::vector<LabDiskObject> objects;
        objects.reserve(entry.second.size());
        for (const ExchangeObject& object : entry.second) {
            LabDiskObject row;
            row.kind = object.kind;
            row.digest = object.digest;
            row.content = object.content;
            objects.push_back(std::move(row));
        }
        image.repo_objects.emplace(entry.first, std::move(objects));
    }
    image.repos = store.repos;
    image.repo_commit = store.repo_commit;
    image.repo_genesis = store.repo_genesis;
    image.repo_ref_published = store.repo_ref_published;
    image.snapshots = store.snapshots;
    image.realms = store.realms;
    image.lineage = store.lineage;
    image.plans = store.plans;
    image.admissions = store.admissions;
    for (const auto& item : store.identity_pk) {
        image.identity_pk.emplace(item.first, HexStr(item.second));
    }
    for (const auto& item : store.trains) {
        if (item.second.profile == LAUNCH_PROFILE) {
            image.launch_trains.emplace(item.first, item.second.launch);
            if (!item.second.author.empty()) image.launch_authors.emplace(item.first, item.second.author);
            continue;
        }
        image.trains.emplace(item.first, item.second.state);
        if (!item.second.author.empty()) image.train_authors.emplace(item.first, item.second.author);
    }
    for (const RealmRollout::SavedRealm& saved : store.rollout.SavedRealms()) {
        LabDiskImage::RolloutRow row;
        row.key = saved.key;
        row.policy = saved.policy;
        row.threshold = saved.threshold;
        row.pins = saved.pins;
        row.revoked = saved.revoked;
        row.has_channel = saved.has_channel;
        row.sequence = saved.sequence;
        row.body = saved.body;
        image.rollout.push_back(std::move(row));
    }
    image.hosted = store.hosted;
    image.verified_rings = store.verified_rings;
    for (const auto& item : store.rollout.SavedFleet()) image.fleet.emplace(item.first, item.second);
    for (const auto& item : store.rollout.SavedEndpoints()) image.endpoints.emplace(item.first, item.second);
    for (const auto& item : store.pause_epoch) image.pause_epochs.emplace(item.first, std::to_string(item.second));
    image.checkpoints = store.checkpoints;
    image.migrations = store.migrations;
    image.migration_plans = store.migration_plans;
    for (const auto& item : store.operations) {
        LabDiskImage::OperationRow row;
        row.state = item.second.state;
        row.physical = item.second.physical;
        row.generation = std::to_string(item.second.generation);
        image.operations.emplace(item.first, std::move(row));
    }
    image.generations = store.rollout.StagedGenerations();
    image.active_generation = store.rollout.ActiveGeneration();
    image.previous_generation = store.rollout.PreviousGeneration();
    image.grants = store.grants;
    image.bindings = store.bindings;
    for (const std::string& name : store.workspaces.TreeNames()) {
        WorkspaceBook::TreeImage tree;
        if (!store.workspaces.ExportTree(name, tree)) continue;
        LabDiskImage::WorkspaceRow row;
        const auto backend = store.workspace_backend.find(name);
        row.backend = backend == store.workspace_backend.end() ? "OPERATION_JOURNAL" : backend->second;
        row.generation = std::to_string(tree.generation);
        row.next_publication = std::to_string(tree.next_publication);
        for (const auto& file : tree.live) row.live.emplace(file.first, HexBytes(file.second));
        for (const auto& gen : tree.closed) {
            std::map<std::string, std::string> files;
            for (const auto& file : gen.second) files.emplace(file.first, HexBytes(file.second));
            row.closed.emplace(std::to_string(gen.first), std::move(files));
        }
        for (uint64_t publication : tree.publication_ids) row.publications.push_back(std::to_string(publication));
        row.cancelled = tree.cancelled;
        row.completed = tree.completed;
        image.workspaces.emplace(name, std::move(row));
    }
    image.active_root = store.active_root;
    image.admission_subject = store.admission_subject;
    for (const Store::IdemRow& saved : store.idempotency) {
        LabDiskImage::IdempotencyRow row;
        row.caller = saved.caller;
        row.key = saved.key;
        row.digest = saved.digest;
        row.result = saved.result;
        row.retired = saved.retired;
        image.idempotency.push_back(std::move(row));
    }
    std::vector<LabDiskObject> model_rows;
    for (const auto& item : store.models) {
        LabDiskObject row;
        row.kind = "model";
        row.digest = item.first;
        row.content = item.second;
        model_rows.push_back(std::move(row));
        const auto pieces = store.model_pieces.find(item.first);
        if (pieces == store.model_pieces.end()) continue;
        for (size_t i = 0; i < pieces->second.size(); ++i) {
            LabDiskObject piece;
            piece.kind = "piece";
            piece.digest = item.first;
            piece.content = std::to_string(i) + ":" + pieces->second[i];
            model_rows.push_back(std::move(piece));
        }
    }
    if (!model_rows.empty()) image.repo_objects["model-bytes"] = std::move(model_rows);
}

TrainKept MaterializeTrain(const IntegerState& state)
{
    TrainKept kept;
    kept.state = state;
    std::string check_err;
    if (!IntegerTrainer::CheckState(state, check_err)) return kept;
    IntegerTrainer trainer;
    if (!trainer.Run(state.step, check_err)) return kept;
    kept.intervals = trainer.Intervals();
    return kept;
}

TrainKept MaterializeLaunch(const LaunchCheckpoint& checkpoint)
{
    TrainKept kept;
    kept.profile = LAUNCH_PROFILE;
    kept.launch = checkpoint;
    kept.state.step = checkpoint.step;
    kept.state.cursor = checkpoint.cursor;
    kept.state.state_hash = checkpoint.state_hash;
    std::string err;
    LaunchTrainer trainer;
    if (!trainer.Run(checkpoint.step, err)) return kept;
    const LaunchCheckpoint& got = trainer.Checkpoint();
    if (got.state_hash != checkpoint.state_hash || got.weight_hash != checkpoint.weight_hash || got.cursor != checkpoint.cursor) {
        return kept;
    }
    kept.intervals = trainer.Intervals();
    kept.launch.hits = got.hits;
    kept.launch.miss_mass = got.miss_mass;
    return kept;
}

bool TrainMatches(const TrainKept& kept, std::string& err)
{
    if (kept.profile == LAUNCH_PROFILE) return LaunchTrainer::CheckState(kept.launch, err);
    return IntegerTrainer::CheckState(kept.state, err);
}

void RestorePublished(Store& store)
{
    store.published.clear();
    for (const ResearchObservation& observation : store.observations) {
        if (observation.is_private || observation.record_id.empty()) continue;
        store.published.push_back(observation.record_id);
    }
}

/** Decimal piece index below MODEL_MAX_PIECES. The loop stops at the bound, so a long index cannot wrap. */
bool ParsePieceIndex(const std::string& text, size_t& index, std::string& err)
{
    if (text.empty()) return Fail(err, "BTX035_SCHEMA");
    for (char c : text) {
        if (c < '0' || c > '9') return Fail(err, "BTX035_SCHEMA");
    }
    index = 0;
    for (char c : text) {
        index = index * 10 + static_cast<size_t>(c - '0');
        if (index >= MODEL_MAX_PIECES) return Fail(err, "BTX035_LIMIT_EXCEEDED");
    }
    err.clear();
    return true;
}

/** Store one piece. Pieces arrive in index order, so an index past the next free slot is a gap. */
bool PutModelPiece(std::map<std::string, std::vector<std::string>>& model_pieces, const std::string& digest, size_t index,
                   std::string chunk, std::string& err)
{
    if (index >= MODEL_MAX_PIECES) return Fail(err, "BTX035_LIMIT_EXCEEDED");
    const auto found = model_pieces.find(digest);
    const size_t have = found == model_pieces.end() ? 0 : found->second.size();
    if (index > have) return Fail(err, "BTX035_GAP");
    std::vector<std::string>& pieces = found == model_pieces.end() ? model_pieces[digest] : found->second;
    if (index == have) {
        pieces.push_back(std::move(chunk));
    } else {
        pieces[index] = std::move(chunk);
    }
    err.clear();
    return true;
}

void ImageToStore(const LabDiskImage& image, Store& store)
{
    store.records = image.records;
    store.observations = image.observations;
    store.repo_objects.clear();
    for (const auto& entry : image.repo_objects) {
        std::vector<ExchangeObject> objects;
        objects.reserve(entry.second.size());
        for (const LabDiskObject& row : entry.second) {
            ExchangeObject object;
            object.kind = row.kind;
            object.digest = row.digest;
            object.content = row.content;
            objects.push_back(std::move(object));
        }
        store.repo_objects.emplace(entry.first, std::move(objects));
    }
    store.repos = image.repos;
    store.repo_commit = image.repo_commit;
    store.repo_genesis = image.repo_genesis;
    store.repo_ref_published = image.repo_ref_published;
    store.snapshots = image.snapshots;
    store.realms = image.realms;
    store.lineage = image.lineage;
    store.plans = image.plans;
    store.admissions = image.admissions;
    store.identity_pk.clear();
    for (const auto& item : image.identity_pk) {
        store.identity_pk.emplace(item.first, ParseHex(item.second));
    }
    store.active_root = image.active_root;
    store.admission_subject = image.admission_subject;
    store.idempotency.clear();
    for (const LabDiskImage::IdempotencyRow& saved : image.idempotency) {
        Store::IdemRow row;
        row.caller = saved.caller;
        row.key = saved.key;
        row.digest = saved.digest;
        row.result = saved.result;
        row.retired = saved.retired;
        store.idempotency.push_back(std::move(row));
    }
    store.trains.clear();
    for (const auto& item : image.trains) {
        store.trains.emplace(item.first, MaterializeTrain(item.second));
    }
    for (auto& item : store.trains) {
        const auto author = image.train_authors.find(item.first);
        if (author == image.train_authors.end() || author->second.empty()) continue;
        item.second.author = author->second;
        for (Interval& interval : item.second.intervals) interval.ancestry = item.second.author;
    }
    for (const auto& item : image.launch_trains) {
        TrainKept kept = MaterializeLaunch(item.second);
        const auto author = image.launch_authors.find(item.first);
        if (author != image.launch_authors.end() && !author->second.empty()) {
            kept.author = author->second;
            for (Interval& interval : kept.intervals) interval.ancestry = kept.author;
        }
        store.trains.insert_or_assign(item.first, std::move(kept));
    }
    store.models.clear();
    store.model_pieces.clear();
    for (const auto& entry : store.repo_objects) {
        for (const ExchangeObject& object : entry.second) {
            if (object.kind == "model") {
                std::string digest;
                std::string digest_err;
                const std::vector<unsigned char> bytes(object.content.begin(), object.content.end());
                if (!GitObjectDigest("model", Span<const unsigned char>{bytes.data(), bytes.size()}, digest, digest_err)) continue;
                if (digest != object.digest) continue;
                store.models[digest] = object.content;
            } else if (object.kind == "piece") {
                if (object.content.rfind("v1|", 0) == 0) {
                    std::string digest;
                    size_t index = 0;
                    std::string chunk;
                    std::string piece_err;
                    // A row past the cap or after a gap is skipped, like any other bad row.
                    if (!DecodePieceLine(object.content, digest, index, chunk, piece_err)) continue;
                    (void)PutModelPiece(store.model_pieces, digest, index, std::move(chunk), piece_err);
                    continue;
                }
                const auto colon = object.content.find(':');
                if (colon == std::string::npos) continue;
                size_t index = 0;
                std::string index_err;
                if (!ParsePieceIndex(object.content.substr(0, colon), index, index_err)) continue;
                (void)PutModelPiece(store.model_pieces, object.digest, index, object.content.substr(colon + 1), index_err);
            }
        }
    }
    RestorePublished(store);
    for (const LabDiskImage::RolloutRow& row : image.rollout) {
        RealmRollout::SavedRealm saved;
        saved.key = row.key;
        saved.policy = row.policy;
        saved.threshold = row.threshold;
        saved.pins = row.pins;
        saved.revoked = row.revoked;
        saved.has_channel = row.has_channel;
        saved.sequence = row.sequence;
        saved.body = row.body;
        std::string restore_err;
        if (!store.rollout.RestoreRealm(saved, restore_err)) continue;
    }
    for (const auto& item : image.fleet) {
        std::string restore_err;
        store.rollout.Observe(item.first, item.second, restore_err);
    }
    for (const auto& item : image.endpoints) {
        std::string restore_err;
        store.rollout.ObserveEndpoint(item.first, item.second, restore_err);
    }
    store.hosted = image.hosted;
    store.verified_rings = image.verified_rings;
    for (const auto& item : image.pause_epochs) {
        int64_t epoch = 0;
        if (!ParseDec(item.second, epoch) || epoch < 0) continue;
        store.pause_epoch[item.first] = static_cast<uint64_t>(epoch);
    }
    store.checkpoints = image.checkpoints;
    store.migrations = image.migrations;
    store.migration_plans = image.migration_plans;
    for (const auto& item : image.operations) {
        int64_t generation = 0;
        if (!ParseDec(item.second.generation, generation) || generation < 0) continue;
        Operation op;
        op.state = item.second.state;
        op.physical = item.second.physical;
        op.generation = static_cast<uint64_t>(generation);
        store.operations.emplace(item.first, op);
    }
    if (!image.generations.empty() || !image.active_generation.empty() || !image.previous_generation.empty()) {
        std::string restore_err;
        store.rollout.RestoreGenerations(image.generations, image.active_generation, image.previous_generation, restore_err);
    }
    store.grants = image.grants;
    store.bindings = image.bindings;
    for (const auto& item : image.workspaces) {
        int64_t generation = 0;
        int64_t next_publication = 0;
        if (!ParseDec(item.second.generation, generation) || generation <= 0 ||
            !ParseDec(item.second.next_publication, next_publication) || next_publication <= 0) {
            continue;
        }
        WorkspaceBook::TreeImage tree;
        tree.generation = static_cast<uint64_t>(generation);
        tree.next_publication = static_cast<uint64_t>(next_publication);
        bool files_ok = true;
        for (const auto& file : item.second.live) {
            std::vector<unsigned char> bytes;
            if (!BytesFromHex(file.second, bytes)) files_ok = false;
            else tree.live.emplace(file.first, std::move(bytes));
        }
        for (const auto& gen : item.second.closed) {
            int64_t closed_generation = 0;
            if (!ParseDec(gen.first, closed_generation) || closed_generation <= 0) files_ok = false;
            std::map<std::string, std::vector<unsigned char>> files;
            for (const auto& file : gen.second) {
                std::vector<unsigned char> bytes;
                if (!BytesFromHex(file.second, bytes)) files_ok = false;
                else files.emplace(file.first, std::move(bytes));
            }
            if (closed_generation > 0) tree.closed.emplace(static_cast<uint64_t>(closed_generation), std::move(files));
        }
        for (const std::string& publication : item.second.publications) {
            int64_t id = 0;
            if (!ParseDec(publication, id) || id <= 0) files_ok = false;
            else tree.publication_ids.push_back(static_cast<uint64_t>(id));
        }
        tree.cancelled = item.second.cancelled;
        tree.completed = item.second.completed;
        std::string restore_err;
        if (!files_ok || !store.workspaces.ImportTree(item.first, tree, restore_err)) continue;
        store.workspace_backend[item.first] = item.second.backend;
    }
}

bool& DiskLoadedOnce()
{
    static bool loaded = false;
    return loaded;
}

void CheckPieceStore(Store& store);

void LoadDiskInto(Store& store)
{
    store.recovery_required = false;
    const fs::path dir = LabDiskDirectory();
    if (dir.empty()) return;
    const fs::path file = dir / "lab.json";
    bool present = false;
    try {
        present = fs::exists(file);
    } catch (const std::filesystem::filesystem_error&) {
        store.recovery_required = true;
        return;
    }
    if (!present) return;
    LabDiskImage image;
    std::string err;
    if (!LoadLabDisk(image, err)) {
        store.recovery_required = true;
        return;
    }
    ImageToStore(image, store);
    CheckPieceStore(store);
}

Store& State()
{
    static Store store;
    if (!DiskLoadedOnce()) {
        DiskLoadedOnce() = true;
        LoadDiskInto(store);
    }
    return store;
}

bool SaveModelPieces(const Store& store, std::string& err)
{
    const fs::path root = LabDiskDirectory();
    if (root.empty() || store.models.empty()) {
        err.clear();
        return true;
    }
    const fs::path piece_root = root / "pieces";
    fs::create_directories(piece_root);
    LocalPieceStore pieces(piece_root, 64ull * 1024ull * 1024ull);
    for (const auto& item : store.models) {
        Digest48 artifact;
        if (!Digest48::FromHex(item.first, artifact, err)) return false;
        const auto found = store.model_pieces.find(item.first);
        if (found == store.model_pieces.end()) continue;
        for (size_t i = 0; i < found->second.size(); ++i) {
            const std::string& chunk = found->second[i];
            const std::vector<unsigned char> raw(chunk.begin(), chunk.end());
            const Span<const unsigned char> span{raw.data(), raw.size()};
            if (!pieces.PutVerifiedPiece(artifact, 0, static_cast<uint32_t>(i), span, ChunkLeaf(static_cast<uint64_t>(i), span), err)) {
                return false;
            }
        }
    }
    err.clear();
    return true;
}

void CheckPieceStore(Store& store)
{
    const fs::path root = LabDiskDirectory();
    if (root.empty()) return;
    const fs::path piece_root = root / "pieces";
    if (!fs::exists(piece_root)) return;
    LocalPieceStore pieces(piece_root, 64ull * 1024ull * 1024ull);
    for (const auto& item : store.models) {
        Digest48 artifact;
        std::string err;
        if (!Digest48::FromHex(item.first, artifact, err)) {
            store.recovery_required = true;
            return;
        }
        std::vector<uint32_t> indexes;
        if (!pieces.EnumerateCommittedPieces(artifact, 0, indexes) || indexes.empty()) continue;
        std::sort(indexes.begin(), indexes.end());
        std::vector<std::string> chunks(indexes.size());
        bool dense = true;
        for (size_t i = 0; i < indexes.size(); ++i) {
            if (indexes[i] != static_cast<uint32_t>(i)) dense = false;
            std::vector<unsigned char> raw;
            if (!pieces.GetPiece(artifact, 0, indexes[i], raw, err)) dense = false;
            else chunks[i].assign(raw.begin(), raw.end());
        }
        std::string joined;
        if (!dense || !JoinModelPieces(chunks, joined, err) || joined != item.second) {
            store.recovery_required = true;
            return;
        }
        store.model_pieces[item.first] = std::move(chunks);
    }
}

bool PersistDurable(std::string& err)
{
    if (LabDiskDirectory().empty()) {
        err.clear();
        return true;
    }
    LabDiskImage image;
    ImageFromStore(State(), image);
    if (!SaveLabDisk(image, err)) return false;
    return SaveModelPieces(State(), err);
}

void RevertStore(LabDiskImage prior, std::map<std::string, std::vector<unsigned char>> secrets, bool recovery, uint64_t generation)
{
    Store& store = State();
    for (auto& item : store.identity_sk) memory_cleanse(item.second.data(), item.second.size());
    store = Store{};
    ImageToStore(prior, store);
    for (const auto& item : store.identity_pk) {
        Digest48 root;
        std::string chain_err;
        (void)store.chain.CreateRoot(Span<const unsigned char>{item.second.data(), item.second.size()}, root, chain_err);
    }
    for (auto& item : secrets) {
        if (store.identity_pk.count(item.first) == 0) {
            memory_cleanse(item.second.data(), item.second.size());
            continue;
        }
        store.identity_sk[item.first] = std::move(item.second);
    }
    store.recovery_required = recovery;
    store.commit_generation = generation;
}

void WipeMemory()
{
    Store& store = State();
    for (auto& item : store.identity_sk) {
        memory_cleanse(item.second.data(), item.second.size());
    }
    store = Store{};
}

bool Fail(std::string& err, const char* code)
{
    err = code;
    return false;
}

bool SignedModelTrustAttestation(const UniValue& attestation, const std::string& promotion_id, const std::string& destination)
{
    if (!attestation.exists("body") || !attestation["body"].isObject() ||
        !attestation.exists("signature_hex")) {
        return false;
    }
    const UniValue& body = attestation["body"];
    if (!body.exists("record_type") || !body["record_type"].isStr() ||
        body["record_type"].get_str() != "ModelTrustAttestation" ||
        !body.exists("payload") || !body["payload"].isObject()) {
        return false;
    }
    const UniValue& payload = body["payload"];
    if (!payload.exists("promotion_id") || !payload["promotion_id"].isStr() ||
        payload["promotion_id"].get_str() != promotion_id ||
        !payload.exists("destination_realm_id") || !payload["destination_realm_id"].isStr() ||
        payload["destination_realm_id"].get_str() != destination) {
        return false;
    }
    std::string verify_err;
    return VerifySignedEnvelopeV11(attestation, verify_err);
}

std::string Id96(const std::string& material)
{
    CSHA384 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(material.data()), material.size());
    unsigned char out[CSHA384::OUTPUT_SIZE];
    hasher.Finalize(out);
    return HexStr(out);
}

std::string Id64(const std::string& material)
{
    return Id96(material).substr(0, 64);
}

bool Listed(const std::string& csv, const std::string& key)
{
    std::stringstream ss(csv);
    std::string item;
    while (std::getline(ss, item, ',')) {
        if (item == key) return true;
    }
    return false;
}

bool KnownField(const std::string& types, const std::string& key)
{
    std::stringstream ss(types);
    std::string item;
    const std::string prefix = key + ":";
    while (std::getline(ss, item, ',')) {
        if (item.rfind(prefix, 0) == 0) return true;
    }
    return false;
}

std::string FieldType(const std::string& types, const std::string& key)
{
    std::stringstream ss(types);
    std::string item;
    const std::string prefix = key + ":";
    while (std::getline(ss, item, ',')) {
        if (item.rfind(prefix, 0) == 0) return item.substr(prefix.size());
    }
    return "string";
}

bool TypeOk(const UniValue& value, const std::string& type)
{
    if (type == "object") return value.isObject();
    if (type == "array") return value.isArray();
    if (type == "boolean") return value.isBool();
    if (type == "integer" || type == "number") return value.isNum();
    return value.isStr();
}

bool CheckRequest(const LabMethod& method, const UniValue& req, std::string& err)
{
    if (ResearchMaySpendWallet()) return Fail(err, "BTX035_SCOPE_DENIED");
    if (req.exists("automatic_spend_atoms")) {
        if (!req["automatic_spend_atoms"].isStr() || req["automatic_spend_atoms"].get_str() != "0") {
            return Fail(err, "BTX035_SCOPE_DENIED");
        }
    }
    if (req.exists("auto_pay")) {
        if (!req["auto_pay"].isBool()) return Fail(err, "BTX035_INVALID_SCHEMA");
        if (req["auto_pay"].isTrue()) return Fail(err, "BTX035_SCOPE_DENIED");
    }
    std::map<std::string, UniValue> supplied;
    req.getObjMap(supplied);
    for (const auto& item : supplied) {
        if (item.first == "auto_pay" || item.first == "automatic_spend_atoms") continue;
        if (!KnownField(method.types, item.first)) return Fail(err, "BTX035_SCHEMA");
    }
    if (method.required[0] == '\0') return true;
    std::stringstream ss(method.required);
    std::string key;
    while (std::getline(ss, key, ',')) {
        if (!req.exists(key)) return Fail(err, "BTX035_SCHEMA");
        if (req[key].isNull()) {
            if (!Listed(method.nullable, key)) return Fail(err, "BTX035_SCHEMA");
            continue;
        }
        if (!TypeOk(req[key], FieldType(method.types, key))) return Fail(err, "BTX035_SCHEMA");
    }
    if (req.exists("idempotency_key") && req["idempotency_key"].isStr() && req["idempotency_key"].get_str().size() < 16) {
        return Fail(err, "BTX035_SCHEMA");
    }
    return true;
}

constexpr size_t kMaxIdempotency = 64;
/** Keys past the live cap keep a digest-only tombstone so a retry cannot mint a second result. */
constexpr size_t kMaxRetiredIdempotency = 256;

std::string IdemCaller(const Store& store)
{
    return store.active_root.empty() ? std::string("local") : store.active_root;
}

bool Replay(const UniValue& req, const std::string& digest, std::string& response, std::string& err)
{
    if (!req.exists("idempotency_key") || !req["idempotency_key"].isStr()) return true;
    const std::string key = req["idempotency_key"].get_str();
    const std::string caller = IdemCaller(State());
    for (const Store::IdemRow& row : State().idempotency) {
        if (row.caller != caller || row.key != key) continue;
        if (row.digest != digest) return Fail(err, "BTX035_IDEMPOTENCY");
        if (row.retired) return Fail(err, "BTX035_IDEMPOTENCY_EXPIRED");
        response = row.result;
        return true;
    }
    return true;
}

void Remember(const UniValue& req, const std::string& digest, const std::string& response)
{
    if (!req.exists("idempotency_key") || !req["idempotency_key"].isStr()) return;
    Store& store = State();
    const std::string key = req["idempotency_key"].get_str();
    const std::string caller = IdemCaller(store);
    for (Store::IdemRow& row : store.idempotency) {
        if (row.caller != caller || row.key != key) continue;
        // A dropped result cannot be rebuilt. Leave the tombstone in place.
        if (row.retired) return;
        row.digest = digest;
        row.result = response;
        return;
    }
    Store::IdemRow row;
    row.caller = caller;
    row.key = key;
    row.digest = digest;
    row.result = response;
    store.idempotency.push_back(std::move(row));
    size_t live = 0;
    for (const Store::IdemRow& saved : store.idempotency) {
        if (!saved.retired) ++live;
    }
    for (Store::IdemRow& saved : store.idempotency) {
        if (live <= kMaxIdempotency) break;
        if (saved.retired) continue;
        saved.retired = true;
        saved.result.clear();
        --live;
    }
    size_t retired = 0;
    for (const Store::IdemRow& saved : store.idempotency) {
        if (saved.retired) ++retired;
    }
    while (retired > kMaxRetiredIdempotency && !store.idempotency.empty() && store.idempotency.front().retired) {
        store.idempotency.erase(store.idempotency.begin());
        --retired;
    }
}

UniValue EnvelopeResponse(const std::string& request_id, const UniValue& result)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("request_id", request_id);
    out.pushKV("result", result);
    out.pushKV("automatic_spend_atoms", "0");
    out.pushKV("state_token", Id96("state|" + request_id));
    return out;
}

UniValue Coverage(const std::string& scope)
{
    UniValue coverage(UniValue::VOBJ);
    coverage.pushKV("view_id", Id96("coverage|" + scope));
    coverage.pushKV("complete", false);
    coverage.pushKV("scope", scope == "REALM" || scope == "PEERS" ? scope : "LOCAL");
    coverage.pushKV("observed_records", "0");
    coverage.pushKV("queried_peers", "0");
    coverage.pushKV("truncated", false);
    coverage.pushKV("omissions", UniValue(UniValue::VARR));
    return coverage;
}

UniValue Counts(uint64_t total, uint64_t unknown)
{
    UniValue counts(UniValue::VOBJ);
    counts.pushKV("total_targets", std::to_string(total));
    counts.pushKV("healthy", "0");
    counts.pushKV("failed", "0");
    counts.pushKV("unknown", std::to_string(unknown));
    counts.pushKV("pending", "0");
    counts.pushKV("paused", "0");
    counts.pushKV("acknowledged", "0");
    counts.pushKV("unacknowledged", "0");
    return counts;
}

std::string RequireStr(const UniValue& req, const char* key)
{
    if (!req.exists(key) || !req[key].isStr()) return "";
    return req[key].get_str();
}

bool FailStr(std::string& err, const std::string& code)
{
    err = code.empty() ? std::string("BTX035_SCHEMA") : code;
    return false;
}

bool HexN(const std::string& hex, size_t n)
{
    if (hex.size() != n) return false;
    for (unsigned char c : hex) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

bool ChannelWindowOpen(const UniValue& payload, std::string& err)
{
    if (!payload.isObject() || !payload.exists("valid_until_ms") || !payload["valid_until_ms"].isStr()) return Fail(err, "BTX035_SCHEMA");
    int64_t until = 0;
    if (!ParseDec(payload["valid_until_ms"].get_str(), until)) return Fail(err, "BTX035_SCHEMA");
    if (until <= NowMs()) return Fail(err, "BTX035_EXPIRED");
    err.clear();
    return true;
}

bool ParseDec(const std::string& s, int64_t& out)
{
    if (s.empty() || s.size() > 18) return false;
    if (s.size() > 1 && s[0] == '0') return false;
    int64_t n = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
        n = n * 10 + (c - '0');
    }
    out = n;
    return true;
}

/** A JSON number read as an int. A fraction, an exponent or a value outside int is false; this never throws. */
bool ReadIntParam(const UniValue& value, int& out)
{
    if (!value.isNum()) return false;
    const std::optional<int> parsed = ToIntegral<int>(value.getValStr());
    if (!parsed) return false;
    out = *parsed;
    return true;
}

bool Expect(Store& store, const UniValue& req, const std::string& subject, std::string& err)
{
    store.token_subject = subject;
    if (!req.exists("expected_state") || req["expected_state"].isNull()) return true;
    if (!req["expected_state"].isStr() || !HexN(req["expected_state"].get_str(), 96)) return Fail(err, "BTX035_SCHEMA");
    const auto it = store.tokens.find(subject);
    if (it == store.tokens.end() || it->second != req["expected_state"].get_str()) return Fail(err, "BTX035_STATE");
    return true;
}

bool Rec(UniValue& result, const std::string& id, const char* state)
{
    result.pushKV("record_id", id);
    result.pushKV("state", state);
    return true;
}

bool OpOut(Store& store, UniValue& result, const std::string& id, const char* state, const char* physical)
{
    Operation op;
    op.state = state;
    op.physical = physical;
    store.operations[id] = op;
    result.pushKV("operation_id", id);
    result.pushKV("state", state);
    return true;
}

UniValue RefOf(const char* kind, const std::string& digest)
{
    UniValue ref(UniValue::VOBJ);
    ref.pushKV("kind", kind);
    ref.pushKV("digest48", digest);
    return ref;
}

bool LoadEnvelope(Store& store, const std::string& id, UniValue& envelope, std::string& err)
{
    const auto it = store.records.find(id);
    if (it == store.records.end()) return Fail(err, "BTX035_NOT_FOUND");
    if (!envelope.read(it->second) || !envelope.isObject()) return Fail(err, "BTX035_ENVELOPE");
    std::string verify_err;
    if (!VerifySignedEnvelopeV11(envelope, verify_err)) return FailStr(err, verify_err);
    return true;
}

bool OwnerActivation(Store& store, const UniValue& payload, const std::string& rollout_id)
{
    if (!payload["activation_authorization_id"].isStr()) return false;
    const std::string auth = payload["activation_authorization_id"].get_str();
    if (!HexN(auth, 96)) return false;
    UniValue envelope;
    std::string load_err;
    if (!LoadEnvelope(store, auth, envelope, load_err)) return false;
    const UniValue& body = envelope["body"];
    if (!body["record_type"].isStr() || body["record_type"].get_str() != "GovernanceApproval") return false;
    const UniValue& approval = body["payload"];
    return approval.isObject() && approval["decision"].isStr() && approval["decision"].get_str() == "APPROVE" &&
           approval["decision_context"].isStr() && approval["decision_context"].get_str() == rollout_id;
}

fs::path BundleDir()
{
    if (const char* env = std::getenv("BTX035_BUNDLE_DIR")) return fs::path(env);
    return fs::path("lab-bundles");
}

bool SafeSegment(const std::string& name)
{
    if (name.empty() || name.size() > 80 || name == "." || name == "..") return false;
    for (unsigned char c : name) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
        if (!ok) return false;
    }
    return true;
}

bool EnsureBundleDir(std::string& err)
{
    if (std::filesystem::is_directory(BundleDir())) return true;
    if (!fs::create_directories(BundleDir())) return Fail(err, "BTX035_BUNDLE");
    return true;
}

bool SignRequest(Store& store, const UniValue& req, UniValue& envelope, std::string& err)
{
    if (store.active_root.empty() || !store.identity_sk.count(store.active_root)) return Fail(err, "BTX035_NOT_FOUND");
    const auto identity = store.identities.find(store.active_root);
    if (identity != store.identities.end() && identity->second == "REVOKED") return Fail(err, "BTX035_IDENTITY_REVOKED");
    const std::vector<unsigned char>& pk = store.identity_pk.at(store.active_root);
    const std::vector<unsigned char>& sk = store.identity_sk.at(store.active_root);
    const std::string signer = ResearchIdentityId(Span<const unsigned char>{pk.data(), pk.size()}).Hex();
    UniValue body(UniValue::VOBJ);
    body.pushKV("envelope_version", 2);
    body.pushKV("contract_revision", "1.1.0");
    body.pushKV("record_type", req["record_type"].get_str());
    body.pushKV("network_id", Id64("BTX/035/network"));
    body.pushKV("realm_id", req["realm_id"].get_str());
    body.pushKV("principal_id", signer);
    body.pushKV("signer_id", signer);
    body.pushKV("key_epoch", "0");
    body.pushKV("public_key_hex", HexStr(pk));
    body.pushKV("delegation_id", req["delegation_id"].isNull() ? UniValue() : req["delegation_id"]);
    body.pushKV("created_ms", "1");
    body.pushKV("expires_ms", req["expires_ms"].get_str());
    body.pushKV("critical_extensions", UniValue(UniValue::VARR));
    body.pushKV("payload", req["payload"]);
    Digest48 id;
    if (!RecordIdV11(body, id, err)) return false;
    std::vector<unsigned char> pre;
    if (!RecordPreimageV11(body, pre, err)) return false;
    std::vector<unsigned char> sig;
    if (!SignMlDsa44(Span<const unsigned char>{sk.data(), sk.size()},
                    Span<const unsigned char>{pre.data(), pre.size()}, sig, err)) {
        return false;
    }
    envelope.pushKV("record_id", id.Hex());
    envelope.pushKV("body", body);
    envelope.pushKV("signature_hex", HexStr(sig));
    std::string verify_err;
    if (!VerifySignedEnvelopeV11(envelope, verify_err)) return FailStr(err, verify_err);
    return true;
}

void QueryOut(UniValue& result, const std::vector<std::string>& ids, const std::string& salt)
{
    UniValue arr(UniValue::VARR);
    for (const std::string& id : ids) {
        if (HexN(id, 96)) arr.push_back(id);
    }
    result.pushKV("record_ids", arr);
    result.pushKV("next_cursor", UniValue());
    UniValue coverage = Coverage("LOCAL");
    coverage.pushKV("view_id", Id96("coverage|" + salt));
    coverage.pushKV("observed_records", std::to_string(arr.size()));
    result.pushKV("coverage", coverage);
    result.pushKV("snapshot_id", Id96("snapshot|" + salt));
    result.pushKV("policy_id", UniValue());
    result.pushKV("truncated_by_bytes", false);
}

void FillOp(UniValue& result, const Operation& op)
{
    result.pushKV("state", op.state);
    result.pushKV("progress", UniValue(UniValue::VARR));
    result.pushKV("result_ref", UniValue());
    result.pushKV("error", UniValue());
    result.pushKV("physical_disposition", op.physical);
    result.pushKV("generation", std::to_string(op.generation));
    result.pushKV("lease_count", "0");
    result.pushKV("quiescence_evidence_id", UniValue());
    result.pushKV("completion_result", UniValue());
}

// Canonical research snapshot line, one line with no raw CR or LF:
//   v1|<record_id>|<topic_id>|<author_id>|<content_hash>|<0|1>|<sequence>|<reproduction_count>|<contest_count>
// Field escapes: \\ -> \, \p -> |, \n -> newline, \r -> CR. Private rows are omitted.
// A decoded row is public.

std::string EscapeResearchField(const std::string& text)
{
    std::string out;
    out.reserve(text.size());
    for (unsigned char c : text) {
        if (c == '\\') out += "\\\\";
        else if (c == '|') out += "\\p";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else out.push_back(static_cast<char>(c));
    }
    return out;
}

bool UnescapeResearchField(const std::string& text, std::string& out)
{
    out.clear();
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] != '\\') {
            out.push_back(text[i]);
            continue;
        }
        if (i + 1 >= text.size()) return false;
        const char next = text[++i];
        if (next == '\\') out.push_back('\\');
        else if (next == 'p') out.push_back('|');
        else if (next == 'n') out.push_back('\n');
        else if (next == 'r') out.push_back('\r');
        else return false;
    }
    return true;
}

bool ParseResearchU64(const std::string& text, uint64_t& out)
{
    if (text.empty() || text.size() > 20) return false;
    if (text.size() > 1 && text[0] == '0') return false;
    uint64_t value = 0;
    for (char c : text) {
        if (c < '0' || c > '9') return false;
        const uint64_t digit = static_cast<uint64_t>(c - '0');
        if (value > (UINT64_MAX - digit) / 10) return false;
        value = value * 10 + digit;
    }
    out = value;
    return true;
}

bool EncodeResearchLine(const ResearchObservation& row, std::string& line, std::string& err)
{
    if (row.record_id.empty()) return Fail(err, "BTX035_SCHEMA");
    line = "v1|" + EscapeResearchField(row.record_id) + "|" + EscapeResearchField(row.topic_id) + "|" +
           EscapeResearchField(row.author_id) + "|" + EscapeResearchField(row.content_hash) + "|" +
           (row.negative ? "1" : "0") + "|" + std::to_string(row.sequence) + "|" +
           std::to_string(row.reproduction_count) + "|" + std::to_string(row.contest_count);
    if (line.find('\n') != std::string::npos || line.find('\r') != std::string::npos) return Fail(err, "BTX035_SCHEMA");
    err.clear();
    return true;
}

bool DecodeResearchLine(const std::string& line, ResearchObservation& row, std::string& err)
{
    if (line.empty() || line.find('\n') != std::string::npos || line.find('\r') != std::string::npos) {
        return Fail(err, "BTX035_SCHEMA");
    }
    std::vector<std::string> parts;
    std::string current;
    for (char c : line) {
        if (c == '|') {
            parts.push_back(current);
            current.clear();
        } else {
            current.push_back(c);
        }
    }
    parts.push_back(current);
    if (parts.size() != 9 || parts[0] != "v1") return Fail(err, "BTX035_SCHEMA");
    ResearchObservation decoded;
    if (!UnescapeResearchField(parts[1], decoded.record_id) || decoded.record_id.empty() ||
        !UnescapeResearchField(parts[2], decoded.topic_id) ||
        !UnescapeResearchField(parts[3], decoded.author_id) ||
        !UnescapeResearchField(parts[4], decoded.content_hash)) {
        return Fail(err, "BTX035_SCHEMA");
    }
    if (parts[5] != "0" && parts[5] != "1") return Fail(err, "BTX035_SCHEMA");
    uint64_t sequence = 0;
    uint64_t reproduction = 0;
    uint64_t contest = 0;
    if (!ParseResearchU64(parts[6], sequence) || !ParseResearchU64(parts[7], reproduction) ||
        !ParseResearchU64(parts[8], contest) || reproduction > UINT32_MAX || contest > UINT32_MAX) {
        return Fail(err, "BTX035_SCHEMA");
    }
    decoded.negative = parts[5] == "1";
    decoded.is_private = false;
    decoded.sequence = sequence;
    decoded.reproduction_count = static_cast<uint32_t>(reproduction);
    decoded.contest_count = static_cast<uint32_t>(contest);
    row = std::move(decoded);
    err.clear();
    return true;
}

bool AppendPublicResearch(const std::vector<ResearchObservation>& rows, std::vector<ExchangeObject>& objects, std::string& err)
{
    for (const ResearchObservation& row : rows) {
        if (row.is_private) continue;
        ExchangeObject object;
        object.kind = "research";
        if (!EncodeResearchLine(row, object.content, err)) return false;
        const std::vector<unsigned char> bytes(object.content.begin(), object.content.end());
        if (!GitObjectDigest("research", Span<const unsigned char>{bytes.data(), bytes.size()}, object.digest, err)) return false;
        objects.push_back(std::move(object));
    }
    err.clear();
    return true;
}

// Canonical INTEGER_LINEAR snapshot line, one line with no raw CR or LF:
//   v1|<trajectory_id>|<weight>|<bias>|<momentum_w>|<momentum_b>|<cursor>|<step>|<state_hash>
// trajectory_id and state_hash use the research field escapes. Integers are
// canonical decimal (optional leading minus, no leading zeros).

bool ParseTrainI64(const std::string& text, int64_t& out)
{
    if (text.empty() || text.size() > 20) return false;
    size_t i = 0;
    bool neg = false;
    if (text[0] == '-') {
        neg = true;
        i = 1;
        if (i == text.size()) return false;
    }
    if (text[i] == '0' && i + 1 != text.size()) return false;
    uint64_t mag = 0;
    for (; i < text.size(); ++i) {
        if (text[i] < '0' || text[i] > '9') return false;
        const uint64_t digit = static_cast<uint64_t>(text[i] - '0');
        if (mag > (UINT64_MAX - digit) / 10) return false;
        mag = mag * 10 + digit;
    }
    if (!neg) {
        if (mag > static_cast<uint64_t>(INT64_MAX)) return false;
        out = static_cast<int64_t>(mag);
        return true;
    }
    if (mag > static_cast<uint64_t>(INT64_MAX) + 1) return false;
    if (mag == static_cast<uint64_t>(INT64_MAX) + 1) {
        out = INT64_MIN;
        return true;
    }
    out = -static_cast<int64_t>(mag);
    return true;
}

bool EncodeTrainLine(const std::string& trajectory_id, const IntegerState& state, std::string& line, std::string& err)
{
    if (!HexN(trajectory_id, 96) || !HexN(state.state_hash, 96)) return Fail(err, "BTX035_SCHEMA");
    line = "v1|" + EscapeResearchField(trajectory_id) + "|" + std::to_string(state.weight) + "|" +
           std::to_string(state.bias) + "|" + std::to_string(state.momentum_w) + "|" +
           std::to_string(state.momentum_b) + "|" + std::to_string(state.cursor) + "|" +
           std::to_string(state.step) + "|" + EscapeResearchField(state.state_hash);
    if (line.find('\n') != std::string::npos || line.find('\r') != std::string::npos) return Fail(err, "BTX035_SCHEMA");
    err.clear();
    return true;
}

bool DecodeTrainLine(const std::string& line, std::string& trajectory_id, IntegerState& state, std::string& err)
{
    if (line.empty() || line.find('\n') != std::string::npos || line.find('\r') != std::string::npos) {
        return Fail(err, "BTX035_SCHEMA");
    }
    std::vector<std::string> parts;
    std::string current;
    for (char c : line) {
        if (c == '|') {
            parts.push_back(current);
            current.clear();
        } else {
            current.push_back(c);
        }
    }
    parts.push_back(current);
    if (parts.size() != 9 || parts[0] != "v1") return Fail(err, "BTX035_SCHEMA");
    std::string hash;
    if (!UnescapeResearchField(parts[1], trajectory_id) || !HexN(trajectory_id, 96) ||
        !ParseTrainI64(parts[2], state.weight) || !ParseTrainI64(parts[3], state.bias) ||
        !ParseTrainI64(parts[4], state.momentum_w) || !ParseTrainI64(parts[5], state.momentum_b) ||
        !ParseResearchU64(parts[6], state.cursor) || !ParseResearchU64(parts[7], state.step) ||
        !UnescapeResearchField(parts[8], hash) || !HexN(hash, 96)) {
        return Fail(err, "BTX035_SCHEMA");
    }
    if (state.step > INTEGER_MAX_STEPS) return Fail(err, "BTX035_LIMIT_EXCEEDED");
    state.state_hash = std::move(hash);
    err.clear();
    return true;
}

bool EncodeReplayLine(const std::string& trajectory_id, const std::string& author, std::string& line, std::string& err)
{
    if (!HexN(trajectory_id, 96) || !HexN(author, 96)) return Fail(err, "BTX035_SCHEMA");
    line = "v1|" + trajectory_id + "|" + author;
    err.clear();
    return true;
}

bool DecodeReplayLine(const std::string& line, std::string& trajectory_id, std::string& author, std::string& err)
{
    const auto p1 = line.find('|');
    const auto p2 = p1 == std::string::npos ? std::string::npos : line.find('|', p1 + 1);
    if (p1 == std::string::npos || p2 == std::string::npos || line.find('|', p2 + 1) != std::string::npos) {
        return Fail(err, "BTX035_SCHEMA");
    }
    if (line.substr(0, p1) != "v1") return Fail(err, "BTX035_SCHEMA");
    trajectory_id = line.substr(p1 + 1, p2 - p1 - 1);
    author = line.substr(p2 + 1);
    if (!HexN(trajectory_id, 96) || !HexN(author, 96)) return Fail(err, "BTX035_SCHEMA");
    err.clear();
    return true;
}

bool AppendTrains(const std::map<std::string, TrainKept>& trains, std::vector<ExchangeObject>& objects, std::string& err)
{
    for (const auto& item : trains) {
        ExchangeObject object;
        object.kind = "train";
        if (item.second.profile == LAUNCH_PROFILE) {
            if (!EncodeLaunchLine(item.first, item.second.launch, object.content, err)) return false;
        } else if (!EncodeTrainLine(item.first, item.second.state, object.content, err)) {
            return false;
        }
        const std::vector<unsigned char> bytes(object.content.begin(), object.content.end());
        if (!GitObjectDigest("train", Span<const unsigned char>{bytes.data(), bytes.size()}, object.digest, err)) return false;
        objects.push_back(std::move(object));
        if (item.second.author.empty()) continue;
        ExchangeObject replay;
        replay.kind = "replay";
        if (!EncodeReplayLine(item.first, item.second.author, replay.content, err)) return false;
        const std::vector<unsigned char> replay_bytes(replay.content.begin(), replay.content.end());
        if (!GitObjectDigest("replay", Span<const unsigned char>{replay_bytes.data(), replay_bytes.size()}, replay.digest, err)) return false;
        objects.push_back(std::move(replay));
    }
    err.clear();
    return true;
}

bool ApplyReplayAuthors(Store& store, const std::vector<ExchangeObject>& objects, std::string& err)
{
    std::set<std::string> seen;
    for (const ExchangeObject& object : objects) {
        if (object.kind != "replay") continue;
        std::string trajectory_id;
        std::string author;
        if (!DecodeReplayLine(object.content, trajectory_id, author, err)) return false;
        std::string digest;
        const std::vector<unsigned char> bytes(object.content.begin(), object.content.end());
        if (!GitObjectDigest("replay", Span<const unsigned char>{bytes.data(), bytes.size()}, digest, err)) return false;
        if (digest != object.digest) return Fail(err, "BTX035_ID_MISMATCH");
        if (!seen.insert(trajectory_id).second) return Fail(err, "BTX035_SCHEMA");
        const auto train = store.trains.find(trajectory_id);
        if (train == store.trains.end()) return Fail(err, "BTX035_NOT_FOUND");
        train->second.author = author;
        for (Interval& interval : train->second.intervals) interval.ancestry = author;
    }
    err.clear();
    return true;
}

bool CollectTrains(const std::vector<ExchangeObject>& objects, std::map<std::string, IntegerState>& out,
                  std::map<std::string, LaunchCheckpoint>& launch_out, std::string& err)
{
    out.clear();
    launch_out.clear();
    for (const ExchangeObject& object : objects) {
        if (object.kind != "train") continue;
        std::string trajectory_id;
        if (object.content.rfind("v2|", 0) == 0) {
            LaunchCheckpoint state;
            if (!DecodeLaunchLine(object.content, trajectory_id, state, err)) return false;
            if (out.count(trajectory_id) != 0 || !launch_out.emplace(trajectory_id, std::move(state)).second) {
                return Fail(err, "BTX035_SCHEMA");
            }
            continue;
        }
        IntegerState state;
        if (!DecodeTrainLine(object.content, trajectory_id, state, err)) return false;
        if (!out.emplace(trajectory_id, std::move(state)).second || launch_out.count(trajectory_id) != 0) {
            return Fail(err, "BTX035_SCHEMA");
        }
    }
    err.clear();
    return true;
}

void RestoreTrains(Store& store, const std::map<std::string, IntegerState>& trains)
{
    for (const auto& item : trains) {
        store.trains[item.first] = MaterializeTrain(item.second);
    }
}

void RestoreLaunch(Store& store, const std::map<std::string, LaunchCheckpoint>& trains)
{
    for (const auto& item : trains) {
        store.trains[item.first] = MaterializeLaunch(item.second);
    }
}

bool AcceptBlob(Store& store, const ExchangeObject& object, std::string& err)
{
    if (object.kind != "blob") return true;
    std::string digest;
    const std::vector<unsigned char> raw(object.content.begin(), object.content.end());
    if (!GitObjectDigest("blob", Span<const unsigned char>{raw.data(), raw.size()}, digest, err)) return false;
    if (digest != object.digest) return Fail(err, "BTX035_ID_MISMATCH");
    store.records[digest] = object.content;
    err.clear();
    return true;
}

bool EncodePieceLine(const std::string& digest, size_t index, const std::string& chunk, std::string& line, std::string& err)
{
    if (!HexN(digest, 96) || chunk.empty()) return Fail(err, "BTX035_SCHEMA");
    const std::vector<unsigned char> raw(chunk.begin(), chunk.end());
    line = "v1|" + digest + "|" + std::to_string(index) + "|" + HexStr(Span<const unsigned char>{raw.data(), raw.size()});
    if (line.find('\n') != std::string::npos || line.find('\r') != std::string::npos) return Fail(err, "BTX035_SCHEMA");
    err.clear();
    return true;
}

bool DecodePieceLine(const std::string& line, std::string& digest, size_t& index, std::string& chunk, std::string& err)
{
    const auto p1 = line.find('|');
    const auto p2 = p1 == std::string::npos ? std::string::npos : line.find('|', p1 + 1);
    const auto p3 = p2 == std::string::npos ? std::string::npos : line.find('|', p2 + 1);
    if (p1 == std::string::npos || p2 == std::string::npos || p3 == std::string::npos) return Fail(err, "BTX035_SCHEMA");
    if (line.substr(0, p1) != "v1") return Fail(err, "BTX035_SCHEMA");
    digest = line.substr(p1 + 1, p2 - p1 - 1);
    if (!HexN(digest, 96)) return Fail(err, "BTX035_SCHEMA");
    const std::string index_text = line.substr(p2 + 1, p3 - p2 - 1);
    if (index_text.empty() || (index_text.size() > 1 && index_text[0] == '0')) return Fail(err, "BTX035_SCHEMA");
    if (!ParsePieceIndex(index_text, index, err)) return false;
    const std::vector<unsigned char> raw = ParseHex(line.substr(p3 + 1));
    if (raw.empty()) return Fail(err, "BTX035_SCHEMA");
    chunk.assign(raw.begin(), raw.end());
    err.clear();
    return true;
}

bool ModelBytesMatch(const Store& store, const std::string& digest, std::string& err)
{
    const auto it = store.models.find(digest);
    if (it == store.models.end()) return Fail(err, "BTX035_NOT_FOUND");
    std::string got;
    const std::vector<unsigned char> bytes(it->second.begin(), it->second.end());
    if (!GitObjectDigest("model", Span<const unsigned char>{bytes.data(), bytes.size()}, got, err)) return false;
    if (got != digest) return Fail(err, "BTX035_ID_MISMATCH");
    const auto pieces = store.model_pieces.find(digest);
    if (pieces == store.model_pieces.end() || pieces->second.empty()) {
        err.clear();
        return true;
    }
    std::string joined;
    if (!JoinModelPieces(pieces->second, joined, err)) return false;
    if (joined != it->second) return Fail(err, "BTX035_ID_MISMATCH");
    err.clear();
    return true;
}

bool AppendModels(const Store& store, std::vector<ExchangeObject>& objects, std::string& err)
{
    for (const auto& item : store.models) {
        if (!ModelBytesMatch(store, item.first, err)) return false;
        ExchangeObject object;
        object.kind = "model";
        object.digest = item.first;
        object.content = item.second;
        objects.push_back(object);
        const auto pieces = store.model_pieces.find(item.first);
        if (pieces == store.model_pieces.end()) continue;
        for (size_t i = 0; i < pieces->second.size(); ++i) {
            ExchangeObject piece;
            piece.kind = "piece";
            if (!EncodePieceLine(item.first, i, pieces->second[i], piece.content, err)) return false;
            const std::vector<unsigned char> bytes(piece.content.begin(), piece.content.end());
            if (!GitObjectDigest("piece", Span<const unsigned char>{bytes.data(), bytes.size()}, piece.digest, err)) return false;
            objects.push_back(std::move(piece));
        }
    }
    err.clear();
    return true;
}

bool AcceptModelObject(Store& store, const ExchangeObject& object, std::string& err)
{
    if (object.kind == "model") {
        std::string digest;
        const std::vector<unsigned char> bytes(object.content.begin(), object.content.end());
        if (!GitObjectDigest("model", Span<const unsigned char>{bytes.data(), bytes.size()}, digest, err)) return false;
        if (digest != object.digest) return Fail(err, "BTX035_ID_MISMATCH");
        store.models[digest] = object.content;
        return true;
    }
    if (object.kind != "piece") return true;
    std::string digest;
    size_t index = 0;
    std::string chunk;
    if (!DecodePieceLine(object.content, digest, index, chunk, err)) return false;
    std::string piece_digest;
    const std::vector<unsigned char> bytes(object.content.begin(), object.content.end());
    if (!GitObjectDigest("piece", Span<const unsigned char>{bytes.data(), bytes.size()}, piece_digest, err)) return false;
    if (piece_digest != object.digest) return Fail(err, "BTX035_ID_MISMATCH");
    return PutModelPiece(store.model_pieces, digest, index, std::move(chunk), err);
}

bool CollectResearch(const std::vector<ExchangeObject>& objects, std::vector<ResearchObservation>& out, std::string& err)
{
    out.clear();
    for (const ExchangeObject& object : objects) {
        if (object.kind != "research") continue;
        ResearchObservation row;
        if (!DecodeResearchLine(object.content, row, err)) return false;
        row.is_private = false;
        out.push_back(std::move(row));
    }
    err.clear();
    return true;
}

bool ContributionKindOk(const std::string& kind)
{
    return kind == "HYPOTHESIS" || kind == "EXPERIMENT" || kind == "NEGATIVE_RESULT" || kind == "REPRODUCTION" ||
           kind == "CRITIQUE" || kind == "SYNTHESIS" || kind == "TOOL_IMPROVEMENT";
}

bool ReadIdVector(const UniValue& payload, const char* key, const std::string& self, std::vector<std::string>& out, std::string& err)
{
    out.clear();
    if (!payload.exists(key) || !payload[key].isArray()) return Fail(err, "BTX035_SCHEMA");
    std::set<std::string> seen;
    for (size_t i = 0; i < payload[key].size(); ++i) {
        if (!payload[key][i].isStr()) return Fail(err, "BTX035_SCHEMA");
        const std::string id = payload[key][i].get_str();
        if (!HexN(id, 96) || id == self || !seen.insert(id).second) return Fail(err, "BTX035_SCHEMA");
        out.push_back(id);
    }
    err.clear();
    return true;
}

bool ReadContributionPayload(const UniValue& envelope, const std::string& self, ResearchObservation& observation, std::string& err)
{
    if (!envelope.exists("body") || !envelope["body"].isObject()) return Fail(err, "BTX035_SCHEMA");
    const UniValue& body = envelope["body"];
    if (!body.exists("payload") || !body["payload"].isObject()) return Fail(err, "BTX035_SCHEMA");
    const UniValue& payload = body["payload"];
    if (!payload.exists("kind") || !payload["kind"].isStr()) return Fail(err, "BTX035_SCHEMA");
    const std::string kind = payload["kind"].get_str();
    if (!ContributionKindOk(kind)) return Fail(err, "BTX035_SCHEMA");
    std::vector<std::string> physical;
    std::vector<std::string> informed;
    if (!ReadIdVector(payload, "physical_parent_ids", self, physical, err)) return false;
    if (!ReadIdVector(payload, "informed_by", self, informed, err)) return false;
    observation.kind = kind;
    observation.physical_parent_ids = std::move(physical);
    observation.informed_by = std::move(informed);
    err.clear();
    return true;
}

bool StoredRecordType(const Store& store, const std::string& record_id, UniValue& envelope, std::string& record_type)
{
    record_type.clear();
    const auto it = store.records.find(record_id);
    if (it == store.records.end()) return false;
    if (!envelope.read(it->second) || !envelope.isObject()) return false;
    if (!envelope.exists("body") || !envelope["body"].isObject()) return false;
    const UniValue& body = envelope["body"];
    if (!body.exists("record_type") || !body["record_type"].isStr()) return false;
    record_type = body["record_type"].get_str();
    return true;
}

// Replace this row's link. Do not append its parents onto another contribution.
void PutObservationLink(std::map<std::string, ContributionLink>& links, const ResearchObservation& observation)
{
    if (observation.record_id.empty()) return;
    ContributionLink link;
    link.record_id = observation.record_id;
    link.kind = observation.kind;
    link.physical_parent_ids = observation.physical_parent_ids;
    link.informed_by = observation.informed_by;
    link.announcement = false;
    links[observation.record_id] = std::move(link);
}

void LinksFromObservations(const std::vector<ResearchObservation>& observations, std::map<std::string, ContributionLink>& links)
{
    links.clear();
    for (const ResearchObservation& observation : observations) PutObservationLink(links, observation);
}

std::string JoinComma(const std::vector<std::string>& ids)
{
    std::string out;
    for (size_t i = 0; i < ids.size(); ++i) {
        if (i != 0) out.push_back(',');
        out += ids[i];
    }
    return out;
}

bool ParseCsvIds(const std::string& field, const std::string& self, std::vector<std::string>& out, std::string& err)
{
    out.clear();
    if (field.empty()) {
        err.clear();
        return true;
    }
    std::set<std::string> seen;
    size_t begin = 0;
    for (;;) {
        const size_t comma = field.find(',', begin);
        const std::string id = field.substr(begin, comma == std::string::npos ? std::string::npos : comma - begin);
        if (!HexN(id, 96) || id == self || !seen.insert(id).second) return Fail(err, "BTX035_SCHEMA");
        out.push_back(id);
        if (comma == std::string::npos) break;
        begin = comma + 1;
        if (begin >= field.size()) return Fail(err, "BTX035_SCHEMA");
    }
    err.clear();
    return true;
}

void SplitPipes(const std::string& line, std::vector<std::string>& parts)
{
    parts.clear();
    std::string current;
    for (char c : line) {
        if (c == '|') {
            parts.push_back(current);
            current.clear();
        } else {
            current.push_back(c);
        }
    }
    parts.push_back(current);
}

// Canonical lineage snapshot line, one line with no spaces and no raw CR or LF:
//   v1|<record_id>|<kind>|<physical ids joined by comma>|<informed_by ids joined by comma>
// An empty id list is an empty field. Private rows are omitted.

bool DecodeLineageLine(const std::string& line, std::string& record_id, std::string& kind, std::vector<std::string>& physical,
                       std::vector<std::string>& informed, std::string& err)
{
    if (line.empty() || line.find('\n') != std::string::npos || line.find('\r') != std::string::npos ||
        line.find(' ') != std::string::npos) {
        return Fail(err, "BTX035_SCHEMA");
    }
    std::vector<std::string> parts;
    SplitPipes(line, parts);
    if (parts.size() != 5 || parts[0] != "v1") return Fail(err, "BTX035_SCHEMA");
    if (!HexN(parts[1], 96)) return Fail(err, "BTX035_SCHEMA");
    if (!parts[2].empty() && !ContributionKindOk(parts[2])) return Fail(err, "BTX035_SCHEMA");
    if (!ParseCsvIds(parts[3], parts[1], physical, err) || !ParseCsvIds(parts[4], parts[1], informed, err)) return false;
    record_id = parts[1];
    kind = parts[2];
    err.clear();
    return true;
}

bool EncodeLineageLine(const ResearchObservation& row, std::string& line, std::string& err)
{
    if (!HexN(row.record_id, 96)) return Fail(err, "BTX035_SCHEMA");
    if (!row.kind.empty() && !ContributionKindOk(row.kind)) return Fail(err, "BTX035_SCHEMA");
    std::vector<std::string> checked;
    if (!ParseCsvIds(JoinComma(row.physical_parent_ids), row.record_id, checked, err)) return false;
    if (!ParseCsvIds(JoinComma(row.informed_by), row.record_id, checked, err)) return false;
    line = "v1|" + row.record_id + "|" + row.kind + "|" + JoinComma(row.physical_parent_ids) + "|" + JoinComma(row.informed_by);
    if (line.find('\n') != std::string::npos || line.find('\r') != std::string::npos || line.find(' ') != std::string::npos) {
        return Fail(err, "BTX035_SCHEMA");
    }
    err.clear();
    return true;
}

bool AppendLineage(const std::vector<ResearchObservation>& rows, std::vector<ExchangeObject>& objects, std::string& err)
{
    for (const ResearchObservation& row : rows) {
        if (row.is_private) continue;
        if (row.kind.empty() && row.physical_parent_ids.empty() && row.informed_by.empty()) continue;
        ExchangeObject object;
        object.kind = "lineage";
        if (!EncodeLineageLine(row, object.content, err)) return false;
        const std::vector<unsigned char> bytes(object.content.begin(), object.content.end());
        if (!GitObjectDigest("lineage", Span<const unsigned char>{bytes.data(), bytes.size()}, object.digest, err)) return false;
        objects.push_back(std::move(object));
    }
    err.clear();
    return true;
}

bool AttachLineage(const std::vector<ExchangeObject>& objects, std::vector<ResearchObservation>& rows, std::string& err)
{
    std::map<std::string, size_t> index;
    for (size_t i = 0; i < rows.size(); ++i) index.emplace(rows[i].record_id, i);
    std::set<std::string> attached;
    for (const ExchangeObject& object : objects) {
        if (object.kind != "lineage") continue;
        std::string record_id;
        std::string kind;
        std::vector<std::string> physical;
        std::vector<std::string> informed;
        if (!DecodeLineageLine(object.content, record_id, kind, physical, informed, err)) return false;
        const auto found = index.find(record_id);
        if (found == index.end()) continue;
        if (!attached.insert(record_id).second) return Fail(err, "BTX035_SCHEMA");
        ResearchObservation& row = rows[found->second];
        row.kind = std::move(kind);
        row.physical_parent_ids = std::move(physical);
        row.informed_by = std::move(informed);
    }
    err.clear();
    return true;
}

enum class GuardRoute { Local, Remote, Invalid };

GuardRoute GuardRouteForCall(uint16_t& port, std::string& err)
{
    port = 0;
    const char* env = std::getenv("BTX_GUARD_PORT");
    if (env == nullptr || env[0] == '\0' || (env[0] == '0' && env[1] == '\0')) return GuardRoute::Local;
    int64_t value = 0;
    if (!ParseDec(env, value) || value <= 0 || value > 65535) {
        err = "BTX035_SCHEMA";
        return GuardRoute::Invalid;
    }
    port = static_cast<uint16_t>(value);
    return GuardRoute::Remote;
}

bool DurableRead(const std::string& method)
{
    return method == "lab.info" || method == "lab.record_get" || method == "lab.record_verify" ||
           method == "lab.identity_inspect" || method == "lab.grant_evaluate" || method == "lab.research_events" ||
           method == "lab.research_frontier" || method == "lab.research_query" || method == "lab.git_refs" ||
           method == "lab.agent_lineage" || method == "lab.research_context" || method == "lab.source_query" ||
           method == "lab.operation_get" || method == "lab.journal_proof" || method == "lab.channel_get" ||
           method == "lab.rollout_status" || method == "lab.rollout_endpoints" || method == "lab.migration_verify" ||
           method == "lab.economy_refs" || method == "lab.capsule_resolve" || method == "lab.state_get" ||
           method == "lab.audit_coverage" || method == "lab.realm_status";
}

bool GenerationHeld(const Store& store, uint64_t generation, std::string& err)
{
    if (store.commit_generation != generation) return Fail(err, "BTX035_GENERATION");
    return true;
}

bool Apply(const std::string& method, const UniValue& req, UniValue& result, std::string& err, UniqueLock<GlobalMutex>& api_lock)
{
    Store& store = State();
    store.token_subject.clear();
    const std::string id = Id96(method + "|" + req.write());

    if (method == "lab.info") {
        if (store.recovery_required) result.pushKV("recovery_required", "BTX035_RECOVERY_REQUIRED");
        result.pushKV("release", "0.35.0rc1");
        result.pushKV("network_id", Id64("BTX/035/network"));
        result.pushKV("realm_id", Id96("BTX/035/PublicRealm/v1"));
        UniValue protocols(UniValue::VARR);
        protocols.push_back("3");
        result.pushKV("protocols", protocols);
        UniValue capabilities(UniValue::VARR);
        capabilities.push_back("lab");
        capabilities.push_back("git");
        capabilities.push_back("research");
        result.pushKV("capabilities", capabilities);
        result.pushKV("baseline_commit", "0f36daafd42b4b921696df9d4f3de4baeff437c8");
        return true;
    }
    if (method == "lab.record_get") {
        UniValue envelope;
        if (!LoadEnvelope(store, RequireStr(req, "record_id"), envelope, err)) return false;
        result.pushKV("envelope", envelope);
        result.pushKV("signature_valid", true);
        result.pushKV("authority_state", "VALID");
        result.pushKV("source", "LOCAL");
        return true;
    }
    if (method == "lab.record_verify") {
        std::string verify_err;
        const bool valid = VerifySignedEnvelopeV11(req["envelope"], verify_err);
        result.pushKV("valid", valid);
        UniValue reasons(UniValue::VARR);
        if (!valid && !verify_err.empty()) reasons.push_back(verify_err);
        result.pushKV("reason_codes", reasons);
        return true;
    }
    if (method == "lab.record_import") {
        if (!Expect(store, req, "import|" + RequireStr(req, "idempotency_key"), err)) return false;
        std::string verify_err;
        if (!VerifySignedEnvelopeV11(req["envelope"], verify_err)) return FailStr(err, verify_err);
        const std::string record_id = req["envelope"]["record_id"].get_str();
        store.records[record_id] = req["envelope"].write();
        return Rec(result, record_id, req["publish"].isTrue() ? "PUBLISHED" : "STORED");
    }
    if (method == "lab.identity_create") {
        if (!Expect(store, req, "identity|" + RequireStr(req, "label"), err)) return false;
        std::vector<unsigned char> pk, sk;
        if (!GenerateMlDsa44(pk, sk, err)) return false;
        Digest48 root;
        if (!store.chain.CreateRoot(Span<const unsigned char>{pk.data(), pk.size()}, root, err)) {
            memory_cleanse(sk.data(), sk.size());
            return false;
        }
        const std::string root_id = root.Hex();
        store.identity_pk[root_id] = std::move(pk);
        store.identity_sk[root_id] = std::move(sk);
        store.active_root = root_id;
        store.identities[root_id] = "ACTIVE";
        return Rec(result, root_id, "ACTIVE");
    }
    if (method == "lab.identity_inspect") {
        const std::string principal = RequireStr(req, "principal_id");
        if (!HexN(principal, 96)) return Fail(err, "BTX035_SCHEMA");
        result.pushKV("principal_id", principal);
        Digest48 root;
        uint64_t epoch = 0;
        std::string ignored;
        if (!Digest48::FromHex(principal, root, ignored) || !store.chain.CurrentEpoch(root, epoch, ignored)) {
            result.pushKV("active_key_id", UniValue());
            result.pushKV("epoch", UniValue());
            result.pushKV("state", "UNKNOWN");
            result.pushKV("chain_ids", UniValue(UniValue::VARR));
            return true;
        }
        std::vector<unsigned char> pk;
        std::string key_err;
        UniValue chains(UniValue::VARR);
        chains.push_back(principal);
        result.pushKV("chain_ids", chains);
        if (store.chain.CurrentPublicKey(root, pk, key_err)) {
            result.pushKV("active_key_id", IdentityKeyId(Span<const unsigned char>{pk.data(), pk.size()}).Hex());
        } else {
            result.pushKV("active_key_id", UniValue());
        }
        result.pushKV("epoch", std::to_string(epoch));
        const auto it = store.identities.find(principal);
        result.pushKV("state", it == store.identities.end() ? "ACTIVE" : it->second);
        return true;
    }
    if (method == "lab.identity_sign") {
        if (!Expect(store, req, "sign|" + store.active_root, err)) return false;
        UniValue envelope(UniValue::VOBJ);
        if (!SignRequest(store, req, envelope, err)) return false;
        result.pushKV("envelope", envelope);
        return true;
    }
    if (method == "lab.identity_transition" || method == "lab.identity_revoke") {
        if (!Expect(store, req, method, err)) return false;
        const std::string proof_id = method == "lab.identity_revoke" ? RequireStr(req, "revocation_id") : RequireStr(req, "new_key_proof_id");
        UniValue envelope;
        if (!LoadEnvelope(store, proof_id, envelope, err)) return false;
        const UniValue& body = envelope["body"];
        if (method == "lab.identity_revoke") {
            if (body["record_type"].get_str() != "Revocation") return Fail(err, "BTX035_RECORD_TYPE");
            Digest48 root;
            Digest48 key;
            if (!Digest48::FromHex(body["principal_id"].get_str(), root, err)) return false;
            if (!Digest48::FromHex(body["signer_id"].get_str(), key, err)) return false;
            if (!store.chain.RevokeKey(root, key, 1, err)) return false;
            store.identities[root.Hex()] = "REVOKED";
            return Rec(result, proof_id, "REVOKED");
        }
        if (body["record_type"].get_str() != "NewKeyProof") return Fail(err, "BTX035_RECORD_TYPE");
        const UniValue& payload = body["payload"];
        if (!payload.isObject() || !payload.exists("root_id") || !payload["root_id"].isStr() ||
            !payload.exists("new_epoch") || !payload["new_epoch"].isStr() ||
            !payload.exists("new_public_key_hex") || !payload["new_public_key_hex"].isStr()) {
            return Fail(err, "BTX035_SCHEMA");
        }
        Digest48 root;
        int64_t new_epoch = 0;
        if (!Digest48::FromHex(payload["root_id"].get_str(), root, err)) return false;
        if (!ParseDec(payload["new_epoch"].get_str(), new_epoch)) return Fail(err, "BTX035_SCHEMA");
        const std::vector<unsigned char> npk = ParseHex(payload["new_public_key_hex"].get_str());
        const std::vector<unsigned char> sig = ParseHex(envelope["signature_hex"].get_str());
        if (!store.chain.AdvanceEpoch(root, npk, static_cast<uint64_t>(new_epoch), sig, err)) return false;
        store.identities[root.Hex()] = "ACTIVE";
        return Rec(result, proof_id, "ACTIVE");
    }
    if (method == "lab.identity_refresh") {
        if (!Expect(store, req, "refresh|" + RequireStr(req, "principal_id"), err)) return false;
        Digest48 root;
        uint64_t epoch = 0;
        if (!Digest48::FromHex(RequireStr(req, "principal_id"), root, err) || !store.chain.CurrentEpoch(root, epoch, err)) {
            return Fail(err, "BTX035_NOT_FOUND");
        }
        result.pushKV("identity_state_id", Id96(root.Hex() + "|" + std::to_string(epoch)));
        return true;
    }
    if (method == "lab.grant_evaluate") {
        const std::string grant = RequireStr(req, "grant_id");
        const bool allow = store.grants.count(grant) != 0;
        result.pushKV("decision", allow ? "ALLOW" : "DENY");
        result.pushKV("effective_limits", UniValue(UniValue::VARR));
        UniValue reasons(UniValue::VARR);
        if (!allow) reasons.push_back("BTX035_PERMIT");
        result.pushKV("reason_codes", reasons);
        return true;
    }
    if (method == "lab.research_subscribe") {
        if (!Expect(store, req, "sub|" + RequireStr(req, "idempotency_key"), err)) return false;
        const std::string sub = Id96("sub|" + req.write());
        store.subscription_cursor[sub] = store.published.size();
        result.pushKV("subscription_id", sub);
        return true;
    }
    if (method == "lab.research_unsubscribe") {
        if (!Expect(store, req, "unsub|" + RequireStr(req, "subscription_id"), err)) return false;
        const std::string sub = RequireStr(req, "subscription_id");
        if (!store.subscription_cursor.count(sub)) return Fail(err, "BTX035_NOT_FOUND");
        store.subscription_cursor.erase(sub);
        result.pushKV("stopped", true);
        return true;
    }
    if (method == "lab.research_events") {
        const std::string sub = RequireStr(req, "subscription_id");
        if (!store.subscription_cursor.count(sub)) return Fail(err, "BTX035_NOT_FOUND");
        int64_t after = 0;
        if (!ParseDec(RequireStr(req, "after_sequence"), after)) return Fail(err, "BTX035_SCHEMA");
        UniValue events(UniValue::VARR);
        bool gap = false;
        if (after > static_cast<int64_t>(store.published.size())) gap = true;
        else {
            for (size_t i = static_cast<size_t>(after); i < store.published.size() && events.size() < 100; ++i) {
                events.push_back(store.published[i]);
            }
        }
        result.pushKV("events", events);
        result.pushKV("next_sequence", std::to_string(store.published.size()));
        result.pushKV("gap", gap);
        return true;
    }
    if (method == "lab.research_publish") {
        if (!Expect(store, req, "publish|" + RequireStr(req, "record_id"), err)) return false;
        if (store.active_root.empty()) return Fail(err, "BTX035_NOT_FOUND");
        if (!req["topic_ids"].isArray() || req["topic_ids"].empty()) return Fail(err, "BTX035_SCHEMA");
        const std::string record_id = RequireStr(req, "record_id");
        const std::string topic_hex = req["topic_ids"][0].isStr() ? req["topic_ids"][0].get_str() : "";
        if (!HexN(record_id, 96) || !HexN(topic_hex, 96)) return Fail(err, "BTX035_SCHEMA");
        Digest48 topic, cid, author;
        if (!Digest48::FromHex(topic_hex, topic, err) || !Digest48::FromHex(record_id, cid, err) ||
            !Digest48::FromHex(store.active_root, author, err)) {
            return false;
        }
        const std::string visibility = RequireStr(req, "visibility");
        UniValue envelope;
        std::string record_type;
        const bool stored_envelope = StoredRecordType(store, record_id, envelope, record_type);
        if (stored_envelope && envelope["body"]["payload"].isObject() && envelope["body"]["payload"].exists("summary") &&
            envelope["body"]["payload"]["summary"].isStr()) {
            std::string lower;
            const std::string& summary = envelope["body"]["payload"]["summary"].get_str();
            lower.reserve(summary.size());
            for (unsigned char c : summary) lower.push_back(static_cast<char>(std::tolower(c)));
            if (lower.find("wallet") != std::string::npos && lower.find("spend") != std::string::npos) {
                return Fail(err, "BTX035_PERMIT");
            }
        }
        if (stored_envelope && record_type == "ActivityAnnouncement") {
            store.published.push_back(record_id);
            return Rec(result, record_id, "PUBLISHED");
        }
        const bool contribution = stored_envelope && record_type == "ResearchContribution";
        ResearchObservation observation;
        observation.record_id = record_id;
        observation.topic_id = topic_hex;
        observation.author_id = store.active_root;
        observation.content_hash = record_id;
        observation.is_private = visibility == "PRIVATE";
        observation.reproduction_count = visibility == "REPRODUCED" ? 1 : 0;
        observation.contest_count = visibility == "CONTESTED" ? 1 : 0;
        bool negative = visibility == "NEGATIVE";
        if (contribution) {
            if (!ReadContributionPayload(envelope, record_id, observation, err)) return false;
            if (observation.kind == "NEGATIVE_RESULT") negative = true;
            std::map<std::string, ContributionLink> links;
            LinksFromObservations(store.observations, links);
            PutObservationLink(links, observation);
            AncestryReport report;
            if (!WalkAncestry(record_id, links, report, err)) return false;
        }
        observation.negative = negative;
        if (!store.research.Publish(topic, cid, author, negative, record_id, err)) return false;
        store.published.push_back(record_id);
        if (!contribution) store.records[record_id] = req.write();
        observation.sequence = store.published.size();
        store.observations.push_back(std::move(observation));
        return Rec(result, record_id, "PUBLISHED");
    }
    if (method == "lab.research_frontier") {
        ResearchView view;
        if (!ParseResearchView(RequireStr(req, "view"), view, err)) return false;
        std::vector<std::string> ids;
        if (!SortResearchView(view, store.observations, true, ids, err)) return false;
        int limit = 100;
        if (req.exists("limit") && req["limit"].isNum() && !ReadIntParam(req["limit"], limit)) return Fail(err, "BTX035_SCHEMA");
        if (limit < 1) limit = 1;
        if (static_cast<int>(ids.size()) > limit) ids.resize(static_cast<size_t>(limit));
        QueryOut(result, ids, method + req.write());
        return true;
    }
    if (method == "lab.research_query" || method == "lab.git_refs" || method == "lab.agent_lineage") {
        std::set<std::string> hidden;
        if (method == "lab.research_query") {
            for (const ResearchObservation& observation : store.observations) {
                if (observation.is_private && !observation.record_id.empty()) hidden.insert(observation.record_id);
            }
        }
        std::vector<std::string> ids;
        ids.reserve(store.published.size());
        for (const std::string& id : store.published) {
            if (hidden.count(id)) continue;
            ids.push_back(id);
        }
        std::string peer_omission;
        int queried_peers = 0;
        if (method == "lab.research_query" && RequireStr(req, "scope") == "PEERS") {
            ids.clear();
            for (const ResearchObservation& observation : store.observations) {
                if (observation.is_private) continue;
                ids.push_back(observation.record_id);
            }
            std::vector<LoopbackPeer> peers;
            bool configured = false;
            if (!LoopbackPeers(peers, configured, err)) return false;
            if (!configured) {
                peer_omission = "BTX035_SCOPE_DENIED";
            } else {
                UniValue inner(UniValue::VOBJ);
                inner.pushKV("scope", "LOCAL");
                inner.pushKV("topics", req["topics"]);
                inner.pushKV("kinds", req["kinds"]);
                inner.pushKV("after_cursor", req["after_cursor"]);
                inner.pushKV("limit", req["limit"]);
                bool any = false;
                for (const LoopbackPeer& peer : peers) {
                    std::string remote_json;
                    std::string call_err;
                    const uint64_t generation = store.commit_generation;
                    const std::string subject = store.token_subject;
                    bool called = false;
                    {
                        REVERSE_LOCK(api_lock);
                        called = LabCallLoopback(peer.host, peer.port, peer.user, peer.password, "lab.research_query", inner.write(), remote_json, call_err);
                    }
                    store.token_subject = subject;
                    if (!GenerationHeld(store, generation, err)) return false;
                    if (!called) {
                        if (call_err != "BTX035_TRANSPORT") return Fail(err, call_err.c_str());
                        continue;
                    }
                    UniValue remote;
                    if (!remote.read(remote_json) || !remote.isObject() || !remote.exists("record_ids") || !remote["record_ids"].isArray()) {
                        return Fail(err, "BTX035_SCHEMA");
                    }
                    for (size_t i = 0; i < remote["record_ids"].size(); ++i) {
                        if (!remote["record_ids"][i].isStr()) continue;
                        const std::string remote_id = remote["record_ids"][i].get_str();
                        if (hidden.count(remote_id)) continue;
                        ids.push_back(remote_id);
                    }
                    any = true;
                    ++queried_peers;
                }
                if (!any) return Fail(err, "BTX035_TRANSPORT");
            }
        }
        if (method == "lab.agent_lineage") {
            ids.clear();
            const std::string release = RequireStr(req, "release_id");
            if (store.lineage.count(release)) ids.push_back(store.lineage[release]);
        }
        if (method == "lab.git_refs") {
            ids.clear();
            const auto it = store.repo_commit.find(RequireStr(req, "repository_id"));
            if (it != store.repo_commit.end() && HexN(it->second, 96)) ids.push_back(it->second);
        }
        QueryOut(result, ids, method + req.write());
        if (method == "lab.research_query" && RequireStr(req, "scope") == "PEERS") {
            UniValue coverage = result["coverage"];
            coverage.pushKV("scope", "PEERS");
            coverage.pushKV("complete", false);
            coverage.pushKV("queried_peers", std::to_string(queried_peers));
            UniValue omissions(UniValue::VARR);
            if (!peer_omission.empty()) omissions.push_back(peer_omission);
            coverage.pushKV("omissions", omissions);
            result.pushKV("coverage", coverage);
        }
        return true;
    }
    if (method == "lab.research_context") {
        std::vector<std::string> ids;
        std::set<std::string> roots;
        if (req["root_ids"].isArray()) {
            for (size_t i = 0; i < req["root_ids"].size(); ++i) {
                if (req["root_ids"][i].isStr()) roots.insert(req["root_ids"][i].get_str());
            }
        }
        int max_records = 0;
        if (req.exists("max_records") && req["max_records"].isNum() && !ReadIntParam(req["max_records"], max_records)) {
            return Fail(err, "BTX035_SCHEMA");
        }
        std::map<std::string, ContributionLink> links;
        LinksFromObservations(store.observations, links);
        std::set<std::string> seen;
        uint64_t physical_edges = 0;
        uint64_t informed_edges = 0;
        for (const ResearchObservation& observation : store.observations) {
            if (!roots.count(observation.record_id) && !roots.count(observation.topic_id) && !roots.count(observation.author_id)) continue;
            if (seen.insert(observation.record_id).second) {
                if (max_records > 0 && static_cast<int>(ids.size()) >= max_records) break;
                ids.push_back(observation.record_id);
            }
            if (links.count(observation.record_id) == 0) continue;
            AncestryReport report;
            if (!WalkAncestry(observation.record_id, links, report, err)) return false;
            physical_edges += report.physical_edges;
            informed_edges += report.informed_edges;
            for (const std::string& ancestor : report.record_ids) {
                if (!seen.insert(ancestor).second) continue;
                if (max_records > 0 && static_cast<int>(ids.size()) >= max_records) break;
                ids.push_back(ancestor);
            }
            if (max_records > 0 && static_cast<int>(ids.size()) >= max_records) break;
        }
        QueryOut(result, ids, method + req.write());
        UniValue coverage = result["coverage"];
        coverage.pushKV("physical_edges", std::to_string(physical_edges));
        coverage.pushKV("informed_edges", std::to_string(informed_edges));
        coverage.pushKV("selection_is_proof", false);
        result.pushKV("coverage", coverage);
        return true;
    }
    if (method == "lab.source_query") {
        const std::string query = RequireStr(req, "query");
        int limit = 0;
        if (req.exists("limit") && req["limit"].isNum() && !ReadIntParam(req["limit"], limit)) return Fail(err, "BTX035_SCHEMA");
        if (limit < 0) return Fail(err, "BTX035_SCHEMA");
        std::set<std::string> wanted;
        if (req["snapshot_ids"].isArray()) {
            for (size_t i = 0; i < req["snapshot_ids"].size(); ++i) {
                if (req["snapshot_ids"][i].isStr()) wanted.insert(req["snapshot_ids"][i].get_str());
            }
        }
        UniValue matches(UniValue::VARR);
        UniValue roots(UniValue::VARR);
        for (const auto& entry : store.repo_objects) {
            bool used = false;
            for (const ExchangeObject& object : entry.second) {
                if (!wanted.empty() && !wanted.count(entry.first) && !wanted.count(object.digest)) continue;
                if (!query.empty() && object.content.find(query) == std::string::npos) continue;
                if (!HexN(object.digest, 96)) continue;
                matches.push_back(object.digest);
                used = true;
                if (limit > 0 && static_cast<int>(matches.size()) >= limit) break;
            }
            if (used && HexN(entry.first, 96)) roots.push_back(entry.first);
            if (limit > 0 && static_cast<int>(matches.size()) >= limit) break;
        }
        result.pushKV("matches", matches);
        result.pushKV("index_source_roots", roots);
        UniValue coverage = Coverage("LOCAL");
        coverage.pushKV("complete", true);
        coverage.pushKV("observed_records", std::to_string(matches.size()));
        result.pushKV("coverage", coverage);
        return true;
    }
    if (method == "lab.research_execute") {
        if (!Expect(store, req, method + "|" + RequireStr(req, "idempotency_key"), err)) return false;
        if (!store.grants.count(RequireStr(req, "local_capability_grant_id"))) {
            return OpOut(store, result, id, "FAILED", "STOPPED_QUIESCENT");
        }
        const std::string recipe = RequireStr(req, "recipe_id");
        if (recipe == LAUNCH_PROFILE) {
            LaunchTrainer trainer;
            const std::string capsule = RequireStr(req, "input_capsule_id");
            const auto prior = store.trains.find(capsule);
            if (prior != store.trains.end() && prior->second.profile == LAUNCH_PROFILE) {
                if (!trainer.Resume(prior->second.launch, err)) return false;
                if (!trainer.Run(LAUNCH_CONTINUE_STEPS, err)) return false;
            } else if (!trainer.Run(LAUNCH_STEPS, err)) {
                return false;
            }
            TrainKept kept;
            kept.profile = LAUNCH_PROFILE;
            kept.launch = trainer.Checkpoint();
            kept.intervals = trainer.Intervals();
            kept.state.step = kept.launch.step;
            kept.state.cursor = kept.launch.cursor;
            kept.state.state_hash = kept.launch.state_hash;
            kept.author = store.active_root;
            for (Interval& interval : kept.intervals) interval.ancestry = kept.author;
            store.trains[id] = kept;
            store.records[id] = kept.launch.state_hash;
            std::string bytes;
            if (!EncodeLaunchArtifact(kept.launch, trainer.Weights(), bytes, err)) return false;
            std::string digest;
            const std::vector<unsigned char> raw(bytes.begin(), bytes.end());
            if (!GitObjectDigest("model", Span<const unsigned char>{raw.data(), raw.size()}, digest, err)) return false;
            std::vector<std::string> pieces;
            if (!SplitModelPieces(bytes, pieces, err)) return false;
            store.models[digest] = bytes;
            store.model_pieces[digest] = std::move(pieces);
            if (!ModelBytesMatch(store, digest, err)) return false;
            std::string dataset;
            std::string tokenizer;
            if (!LaunchDatasetDigest(dataset, err) || !LaunchTokenizerDigest(tokenizer, err)) return false;
            store.records[dataset] = LaunchCorpusBytes();
            store.records[tokenizer] = LaunchTokenizerBytes();
            const std::string initial = kept.intervals.empty() ? std::string() : kept.intervals.front().start_state;
            result.pushKV("artifact_digest", digest);
            result.pushKV("state_hash", kept.launch.state_hash);
            result.pushKV("previous_state", kept.launch.inherited_state.empty() ? initial : kept.launch.inherited_state);
            result.pushKV("next_byte_hits", std::to_string(kept.launch.hits));
            result.pushKV("miss_mass", std::to_string(kept.launch.miss_mass));
            result.pushKV("tokenizer_digest", tokenizer);
            result.pushKV("dataset_digest", dataset);
            result.pushKV("profile", LAUNCH_PROFILE);
            return OpOut(store, result, id, "COMPLETE", "STOPPED_QUIESCENT");
        }
        if (recipe != INTEGER_PROFILE && recipe != INTEGER_MODEL_PROFILE) return Fail(err, "BTX035_PROFILE");
        IntegerTrainer trainer;
        if (!trainer.Run(IntegerDataset().size(), err)) return false;
        TrainKept kept;
        kept.state = trainer.State();
        kept.intervals = trainer.Intervals();
        kept.author = store.active_root;
        for (Interval& interval : kept.intervals) interval.ancestry = kept.author;
        store.trains[id] = kept;
        store.records[id] = kept.state.state_hash;
        if (recipe == INTEGER_MODEL_PROFILE) {
            std::string bytes;
            if (!EncodeModelArtifact(kept.state, bytes, err)) return false;
            std::string digest;
            const std::vector<unsigned char> raw(bytes.begin(), bytes.end());
            if (!GitObjectDigest("model", Span<const unsigned char>{raw.data(), raw.size()}, digest, err)) return false;
            std::vector<std::string> pieces;
            if (!SplitModelPieces(bytes, pieces, err)) return false;
            store.models[digest] = bytes;
            store.model_pieces[digest] = std::move(pieces);
            if (!ModelBytesMatch(store, digest, err)) return false;
            result.pushKV("artifact_digest", digest);
        }
        return OpOut(store, result, id, "COMPLETE", "STOPPED_QUIESCENT");
    }
    if (method == "lab.artifact_acquire") {
        if (!Expect(store, req, method + "|" + RequireStr(req, "idempotency_key"), err)) return false;
        int64_t max_bytes = 0;
        if (!ParseDec(RequireStr(req, "max_bytes"), max_bytes) || max_bytes < 0) return Fail(err, "BTX035_SCHEMA");
        const UniValue& resource = req["resource"];
        const std::string digest = resource.isObject() && resource.exists("digest") && resource["digest"].isStr() ? resource["digest"].get_str() : "";
        auto remember = [&](const std::string& bytes) {
            store.records[id] = bytes;
            result.pushKV("artifact_digest", digest);
            result.pushKV("byte_size", std::to_string(bytes.size()));
        };
        std::string match_err;
        if (!digest.empty() && ModelBytesMatch(store, digest, match_err)) {
            if (static_cast<int64_t>(store.models[digest].size()) > max_bytes) {
                return OpOut(store, result, id, "FAILED", "STOPPED_QUIESCENT");
            }
            remember(store.models[digest]);
            return OpOut(store, result, id, "COMPLETE", "STOPPED_QUIESCENT");
        }
        if (!digest.empty() && match_err == "BTX035_ID_MISMATCH") return Fail(err, "BTX035_ID_MISMATCH");
        std::string content;
        bool found = false;
        if (!digest.empty()) {
            for (const auto& entry : store.repo_objects) {
                for (const ExchangeObject& object : entry.second) {
                    if (object.kind == "model" || object.kind == "piece") continue;
                    if (object.digest != digest) continue;
                    content = object.content;
                    found = true;
                    break;
                }
                if (found) break;
            }
        }
        if (!found && !digest.empty() && resource.isObject() && resource.exists("repository_id") && resource["repository_id"].isStr()) {
            std::vector<LoopbackPeer> peers;
            bool configured = false;
            if (!LoopbackPeers(peers, configured, err)) return false;
            if (configured) {
                bool pulled = false;
                for (const LoopbackPeer& peer : peers) {
                    std::vector<std::string> chunks;
                    std::string piece_err;
                    bool saw_piece = false;
                    bool piece_bad = false;
                    const uint64_t piece_generation = store.commit_generation;
                    const std::string piece_subject = store.token_subject;
                    {
                        REVERSE_LOCK(api_lock);
                        for (uint64_t index = 0; index < MODEL_MAX_PIECES; ++index) {
                            UniValue resource_ref(UniValue::VOBJ);
                            resource_ref.pushKV("kind", "MODEL");
                            resource_ref.pushKV("digest48", digest);
                            UniValue piece_req(UniValue::VOBJ);
                            piece_req.pushKV("resource", resource_ref);
                            piece_req.pushKV("manifest_id", digest);
                            piece_req.pushKV("piece_index", std::to_string(index));
                            piece_req.pushKV("maximum_bytes", std::to_string(max_bytes));
                            std::string piece_json;
                            if (!PeerRouteLoopback(peer.host, peer.port, peer.user, peer.password, "artifacts/piece", piece_req.write(), piece_json, piece_err)) {
                                if (piece_err == "BTX035_NOT_FOUND" || piece_err == "BTX035_TRANSPORT") break;
                                piece_bad = true;
                                break;
                            }
                            UniValue piece;
                            if (!piece.read(piece_json) || !piece.isObject() || !piece["content_hex"].isStr()) {
                                piece_err = "BTX035_SCHEMA";
                                piece_bad = true;
                                break;
                            }
                            std::vector<unsigned char> raw;
                            if (!BytesFromHex(piece["content_hex"].get_str(), raw) || raw.empty()) {
                                piece_err = "BTX035_SCHEMA";
                                piece_bad = true;
                                break;
                            }
                            chunks.emplace_back(raw.begin(), raw.end());
                            saw_piece = true;
                            if (raw.size() != 32) break;
                        }
                    }
                    store.token_subject = piece_subject;
                    if (!GenerationHeld(store, piece_generation, err)) return false;
                    if (piece_bad) return Fail(err, piece_err.c_str());
                    if (saw_piece) {
                        std::string joined;
                        if (!JoinModelPieces(chunks, joined, err)) return false;
                        std::string got;
                        const std::vector<unsigned char> raw_joined(joined.begin(), joined.end());
                        if (!GitObjectDigest("model", Span<const unsigned char>{raw_joined.data(), raw_joined.size()}, got, err)) return false;
                        if (got != digest) return Fail(err, "BTX035_ID_MISMATCH");
                        store.models[digest] = joined;
                        store.model_pieces[digest] = std::move(chunks);
                        if (static_cast<int64_t>(joined.size()) > max_bytes) {
                            return OpOut(store, result, id, "FAILED", "STOPPED_QUIESCENT");
                        }
                        remember(store.models[digest]);
                        return OpOut(store, result, id, "COMPLETE", "STOPPED_QUIESCENT");
                    }
                    if (!piece_err.empty() && piece_err != "BTX035_NOT_FOUND" && piece_err != "BTX035_TRANSPORT") {
                        return Fail(err, piece_err.c_str());
                    }
                    std::string manifest;
                    std::string call_err;
                    const uint64_t pull_generation = store.commit_generation;
                    const std::string pull_subject = store.token_subject;
                    bool pulled_manifest = false;
                    {
                        REVERSE_LOCK(api_lock);
                        pulled_manifest = PullExchangeLoopback(peer.host, peer.port, peer.user, peer.password, resource["repository_id"].get_str(), manifest, call_err);
                    }
                    store.token_subject = pull_subject;
                    if (!GenerationHeld(store, pull_generation, err)) return false;
                    if (!pulled_manifest) {
                        if (call_err != "BTX035_TRANSPORT") return Fail(err, call_err.c_str());
                        continue;
                    }
                    std::vector<ExchangeObject> objects;
                    if (!VerifyExchangeManifest(manifest, objects, err)) return false;
                    for (const ExchangeObject& object : objects) {
                        if (object.kind == "piece" && static_cast<int64_t>(object.content.size()) > max_bytes) {
                            return Fail(err, "BTX035_LIMIT_EXCEEDED");
                        }
                    }
                    for (const ExchangeObject& object : objects) {
                        if (!AcceptModelObject(store, object, err)) return false;
                    }
                    pulled = true;
                    if (ModelBytesMatch(store, digest, err)) {
                        if (static_cast<int64_t>(store.models[digest].size()) > max_bytes) {
                            return OpOut(store, result, id, "FAILED", "STOPPED_QUIESCENT");
                        }
                        remember(store.models[digest]);
                        return OpOut(store, result, id, "COMPLETE", "STOPPED_QUIESCENT");
                    }
                    if (err == "BTX035_ID_MISMATCH") return false;
                    err.clear();
                }
                if (!pulled) return Fail(err, "BTX035_TRANSPORT");
            }
        }
        if (!found || static_cast<int64_t>(content.size()) > max_bytes) {
            return OpOut(store, result, id, "FAILED", "STOPPED_QUIESCENT");
        }
        remember(content);
        return OpOut(store, result, id, "COMPLETE", "STOPPED_QUIESCENT");
    }
    if (method == "lab.agent_adopt" || method == "lab.promotion_verify" ||
        method == "lab.workspace_hydrate" || method == "lab.workspace_restore") {
        if (!Expect(store, req, method + "|" + RequireStr(req, "idempotency_key"), err)) return false;
        const char* physical = "STOPPED_QUIESCENT";
        const char* state = "FAILED";
        if (method == "lab.agent_adopt") {
            bool ready = store.grants.count(RequireStr(req, "grant_id")) != 0 && req["evaluation_ids"].isArray() && !req["evaluation_ids"].empty();
            if (ready) {
                for (size_t i = 0; i < req["evaluation_ids"].size(); ++i) {
                    if (!req["evaluation_ids"][i].isStr() || !store.records.count(req["evaluation_ids"][i].get_str())) ready = false;
                }
            }
            const std::string release = RequireStr(req, "release_id");
            const std::string prior = RequireStr(req, "prior_release_id");
            const std::string grant = RequireStr(req, "grant_id");
            if (ready && (!prior.empty() && prior == release)) ready = false;
            if (ready && store.identity_sk.count(grant)) ready = false;
            if (!ready) {
                state = "FAILED";
                physical = "STOPPED_QUIESCENT";
            } else {
                if (store.lineage.count(release)) store.records["previous|" + release] = store.lineage[release];
                store.lineage[release] = prior;
                state = "COMPLETE";
                physical = "STOPPED_QUIESCENT";
            }
        }
        if (method == "lab.promotion_verify") {
            bool ready = store.records.count(RequireStr(req, "promotion_id")) != 0 && req["attestation_ids"].isArray() && !req["attestation_ids"].empty();
            const std::string promotion_id = RequireStr(req, "promotion_id");
            std::string destination_realm;
            {
                UniValue prepared;
                const auto prepared_record = store.records.find(promotion_id);
                if (prepared_record != store.records.end() && prepared.read(prepared_record->second) && prepared.isObject() &&
                    prepared.exists("destination_realm_id") && prepared["destination_realm_id"].isStr()) {
                    destination_realm = prepared["destination_realm_id"].get_str();
                }
            }
            std::set<std::string> unique_pins;
            if (ready) {
                for (size_t i = 0; i < req["attestation_ids"].size(); ++i) {
                    if (!req["attestation_ids"][i].isStr()) {
                        ready = false;
                        continue;
                    }
                    const std::string pin = req["attestation_ids"][i].get_str();
                    if (!unique_pins.insert(pin).second) {
                        ready = false;
                        continue;
                    }
                    const auto record = store.records.find(pin);
                    if (record == store.records.end()) {
                        ready = false;
                        continue;
                    }
                    UniValue attestation;
                    if (!attestation.read(record->second) || !attestation.isObject()) {
                        ready = false;
                        continue;
                    }
                    bool matches = false;
                    if (attestation.exists("promotion_id") && attestation["promotion_id"].isStr()) {
                        matches = attestation["promotion_id"].get_str() == promotion_id;
                    } else if (!destination_realm.empty()) {
                        matches = SignedModelTrustAttestation(attestation, promotion_id, destination_realm);
                    }
                    if (!matches) ready = false;
                }
            }
            state = ready ? "COMPLETE" : "FAILED";
            physical = "STOPPED_QUIESCENT";
            if (ready) {
                UniValue stored;
                if (stored.read(store.records[RequireStr(req, "promotion_id")]) && stored.isObject() &&
                    stored.exists("destination_realm_id") && stored["destination_realm_id"].isStr()) {
                    std::vector<std::string> pins(unique_pins.begin(), unique_pins.end());
                    if (!store.rollout.SetPolicy(stored["destination_realm_id"].get_str(), static_cast<int>(pins.size()), pins, err)) {
                        return false;
                    }
                    result.pushKV("threshold", std::to_string(pins.size()));
                }
            }
        }
        if (method == "lab.workspace_hydrate") {
            const std::string ws = RequireStr(req, "workspace_id");
            if (!store.workspace_backend.count(ws)) return Fail(err, "BTX035_NOT_FOUND");
            int64_t want = 0;
            if (!ParseDec(RequireStr(req, "generation"), want) || want < 0) return Fail(err, "BTX035_SCHEMA");
            if (static_cast<uint64_t>(want) == store.workspaces.Generation(ws)) {
                state = "COMPLETE";
                physical = "STOPPED_QUIESCENT";
            }
        }
        if (method == "lab.workspace_restore") {
            if (!store.checkpoints.count(RequireStr(req, "checkpoint_id"))) return Fail(err, "BTX035_NOT_FOUND");
            const std::string ws = store.checkpoints[RequireStr(req, "checkpoint_id")];
            if (!store.workspaces.Undo(ws, err)) return false;
            state = "COMPLETE";
            physical = "STOPPED_QUIESCENT";
        }
        return OpOut(store, result, id, state, physical);
    }
    if (method == "lab.git_register" || method == "lab.git_snapshot") {
        if (!Expect(store, req, method + "|" + RequireStr(req, "repository_id"), err)) return false;
        const std::string repo = RequireStr(req, "repository_id");
        if (!store.repos.count(repo)) return Fail(err, "BTX035_NOT_FOUND");
        if (method == "lab.git_register") {
            store.repo_commit[repo] = RequireStr(req, "required_commit");
            return OpOut(store, result, id, "COMPLETE", "STOPPED_QUIESCENT");
        }
        std::string commit;
        if (req["commit"].isStr()) commit = req["commit"].get_str();
        else if (req["commit"].isObject() || req["commit"].isArray()) commit = req["commit"].write();
        else return Fail(err, "BTX035_SCHEMA");
        const std::vector<unsigned char> bytes(commit.begin(), commit.end());
        std::string digest;
        if (!GitObjectDigest("commit", Span<const unsigned char>{bytes.data(), bytes.size()}, digest, err)) return false;
        ExchangeObject object;
        object.kind = "commit";
        object.digest = digest;
        object.content = commit;
        store.repo_objects[repo].push_back(object);
        store.records[Id96(digest)] = digest;
        if (req["history_required"].isTrue()) return OpOut(store, result, id, "FAILED", "STOPPED_QUIESCENT");
        store.snapshots.insert(id);
        return OpOut(store, result, id, "COMPLETE", "STOPPED_QUIESCENT");
    }
    if (method == "lab.git_fetch_ticket") {
        if (!Expect(store, req, "ticket|" + RequireStr(req, "repository_id"), err)) return false;
        const std::string repo = RequireStr(req, "repository_id");
        if (!store.repos.count(repo)) return Fail(err, "BTX035_NOT_FOUND");
        const std::string operation = RequireStr(req, "operation");
        if (operation.empty()) return Fail(err, "BTX035_SCHEMA");
        int64_t max_bytes = 0;
        if (!ParseDec(RequireStr(req, "max_bytes"), max_bytes) || max_bytes < 0) return Fail(err, "BTX035_SCHEMA");
        const std::string ticket = GuardRandomHex();
        if (ticket.size() != 64 || store.fetch_tickets.count(ticket)) return Fail(err, "BTX035_PERMIT");
        FetchTicket row;
        row.repository_id = repo;
        row.operation = operation;
        row.max_bytes = max_bytes;
        row.not_after_ms = NowMs() + GuardTable::kPermitTtlMs;
        store.fetch_tickets.emplace(ticket, row);
        const auto objects = store.repo_objects.find(repo);
        result.pushKV("ticket", ticket);
        result.pushKV("expires_ms", std::to_string(row.not_after_ms));
        result.pushKV("repository_id", repo);
        result.pushKV("object_count", static_cast<int>(objects == store.repo_objects.end() ? 0 : objects->second.size()));
        result.pushKV("transport", "lab.snapshot_export");
        return true;
    }
    if (method == "lab.git_attest") {
        if (!Expect(store, req, "attest|" + RequireStr(req, "snapshot_id"), err)) return false;
        const std::string snapshot = RequireStr(req, "snapshot_id");
        if (!store.snapshots.count(snapshot)) return Fail(err, "BTX035_NOT_FOUND");
        const std::string purpose = RequireStr(req, "purpose");
        if (purpose.empty()) return Fail(err, "BTX035_SCHEMA");
        std::string closure;
        if (req.exists("build_closure_id") && req["build_closure_id"].isStr()) closure = req["build_closure_id"].get_str();
        if (!closure.empty()) {
            if (!HexN(closure, 96)) return Fail(err, "BTX035_SCHEMA");
            std::string match_err;
            const bool bytes_ok = ModelBytesMatch(store, closure, match_err);
            if (!bytes_ok && match_err == "BTX035_ID_MISMATCH") return Fail(err, "BTX035_ID_MISMATCH");
            if (!bytes_ok && !store.records.count(closure) && !store.snapshots.count(closure)) return Fail(err, "BTX035_NOT_FOUND");
        }
        const std::string attestation = Id96("attest|" + snapshot + "|" + purpose + "|" + closure);
        store.records[attestation] = snapshot + "\n" + purpose + "\n" + closure;
        return Rec(result, attestation, "ATTESTED");
    }
    if (method == "lab.git_publish_ref") {
        if (!Expect(store, req, "ref|" + RequireStr(req, "update_id"), err)) return false;
        UniValue envelope;
        if (!LoadEnvelope(store, RequireStr(req, "update_id"), envelope, err)) return false;
        if (envelope["body"]["record_type"].get_str() != "GitRefUpdate") return Fail(err, "BTX035_RECORD_TYPE");
        const UniValue& payload = envelope["body"]["payload"];
        if (!payload.isObject()) return Fail(err, "BTX035_SCHEMA");
        if (payload.exists("repository_id") && payload["repository_id"].isStr()) {
            const std::string repository = payload["repository_id"].get_str();
            const auto current = store.repo_commit.find(repository);
            if (current != store.repo_commit.end()) {
                const bool old_null = payload.exists("old_target") && payload["old_target"].isNull();
                const bool old_str = payload.exists("old_target") && payload["old_target"].isStr();
                if (old_str && payload["old_target"].get_str() != current->second) return Fail(err, "BTX035_STALE");
                if (old_null) {
                    const auto genesis = store.repo_genesis.find(repository);
                    const bool at_genesis = genesis != store.repo_genesis.end() && current->second == genesis->second;
                    const bool first = !store.repo_ref_published.count(repository);
                    if (!at_genesis && !first) return Fail(err, "BTX035_STALE");
                }
            }
            if (payload.exists("new_target") && payload["new_target"].isStr() && !payload["new_target"].get_str().empty()) {
                store.repo_commit[repository] = payload["new_target"].get_str();
            }
            store.repo_ref_published.insert(repository);
        }
        return Rec(result, RequireStr(req, "update_id"), "PUBLISHED");
    }
    if (method == "lab.git_push_authorize") {
        if (!Expect(store, req, "push|" + RequireStr(req, "batch_id"), err)) return false;
        const std::string batch = RequireStr(req, "batch_id");
        if (!HexN(batch, 96)) return Fail(err, "BTX035_SCHEMA");
        if (!store.records.count(batch) && !store.repos.count(batch)) return Fail(err, "BTX035_NOT_FOUND");
        result.pushKV("transaction_id", Id96("tx|" + batch));
        result.pushKV("state", "PREPARED");
        return true;
    }
    if (method == "lab.repository_create") {
        if (!Expect(store, req, "repo|" + RequireStr(req, "label"), err)) return false;
        const std::string repo = Id96("repo|" + RequireStr(req, "label") + "|" + RequireStr(req, "nonce"));
        const std::string genesis = HexN(RequireStr(req, "project_genesis_id"), 96) ? RequireStr(req, "project_genesis_id") : Id96("genesis|" + repo);
        store.repos.insert(repo);
        store.repo_commit[repo] = genesis;
        store.repo_genesis[repo] = genesis;
        result.pushKV("repository_id", repo);
        result.pushKV("repository_genesis_id", genesis);
        return true;
    }
    if (method == "lab.workspace_create") {
        if (!Expect(store, req, "ws|" + RequireStr(req, "snapshot_id"), err)) return false;
        const std::string backend = RequireStr(req, "backend");
        if (backend == "EXTERNAL_ADAPTER") return Fail(err, "BTX035_WORKSPACE");
        if (backend != "PLAIN_GIT" && backend != "OPERATION_JOURNAL") return Fail(err, "BTX035_SCHEMA");
        const std::string ws = Id96("ws|" + RequireStr(req, "snapshot_id") + "|" + backend);
        if (!store.workspaces.OpenTree(ws, err)) return false;
        store.workspace_backend[ws] = backend;
        result.pushKV("workspace_id", ws);
        result.pushKV("generation", std::to_string(store.workspaces.Generation(ws)));
        result.pushKV("path", "ws/" + ws);
        return true;
    }
    if (method == "lab.workspace_operation") {
        if (!Expect(store, req, "wsop|" + RequireStr(req, "workspace_id"), err)) return false;
        const std::string ws = RequireStr(req, "workspace_id");
        if (!store.workspace_backend.count(ws)) return Fail(err, "BTX035_NOT_FOUND");
        if (req["event"].isObject() && req["event"].exists("hook")) return Fail(err, "BTX035_SCOPE_DENIED");
        const uint64_t gen = store.workspaces.Generation(ws);
        const std::string raw = req["event"].write();
        const std::vector<unsigned char> bytes(raw.begin(), raw.end());
        if (!store.workspaces.Put(ws, gen, "event", bytes, err)) return false;
        if (!store.workspaces.Publish(ws, gen, false, false, err)) return false;
        result.pushKV("sequence", std::to_string(gen));
        result.pushKV("journal_state", Id96(ws + "|" + std::to_string(gen)));
        return true;
    }
    if (method == "lab.workspace_snapshot") {
        if (!Expect(store, req, "wssnap|" + RequireStr(req, "workspace_id"), err)) return false;
        const std::string ws = RequireStr(req, "workspace_id");
        if (!store.workspace_backend.count(ws)) return Fail(err, "BTX035_NOT_FOUND");
        int64_t want = 0;
        if (!ParseDec(RequireStr(req, "generation"), want)) return Fail(err, "BTX035_SCHEMA");
        const uint64_t gen = store.workspaces.Generation(ws);
        if (static_cast<uint64_t>(want) != gen) return Fail(err, "BTX035_GENERATION");
        if (!store.workspaces.Publish(ws, gen, false, req["publishable"].isTrue(), err)) return false;
        const std::string cp = Id96(ws + "|snap|" + std::to_string(gen));
        store.checkpoints[cp] = ws;
        return Rec(result, cp, "SNAPSHOT");
    }
    if (method == "lab.workspace_reconcile") {
        if (!Expect(store, req, "wsrec|" + RequireStr(req, "workspace_id"), err)) return false;
        if (!store.workspace_backend.count(RequireStr(req, "workspace_id"))) return Fail(err, "BTX035_NOT_FOUND");
        bool ready = req["parent_checkpoint_ids"].isArray() && !req["parent_checkpoint_ids"].empty();
        if (ready) {
            for (size_t i = 0; i < req["parent_checkpoint_ids"].size(); ++i) {
                if (!req["parent_checkpoint_ids"][i].isStr() || !store.checkpoints.count(req["parent_checkpoint_ids"][i].get_str())) ready = false;
            }
        }
        return Rec(result, id, ready ? "RECONCILED" : "CONFLICT");
    }
    if (method == "lab.operation_get") {
        const auto it = store.operations.find(RequireStr(req, "operation_id"));
        if (it == store.operations.end()) return Fail(err, "BTX035_NOT_FOUND");
        FillOp(result, it->second);
        return true;
    }
    if (method == "lab.operation_cancel") {
        if (!Expect(store, req, "cancel|" + RequireStr(req, "operation_id"), err)) return false;
        const std::string op_id = RequireStr(req, "operation_id");
        auto it = store.operations.find(op_id);
        if (it == store.operations.end()) return Fail(err, "BTX035_NOT_FOUND");
        store.gate->CancelLogical(op_id);
        it->second.state = "CANCELLED";
        result.pushKV("state", "CANCELLED");
        result.pushKV("physical_disposition", it->second.physical);
        result.pushKV("generation", std::to_string(it->second.generation));
        result.pushKV("lease_count", "0");
        result.pushKV("quiescence_evidence_id", UniValue());
        return true;
    }
    if (method == "lab.admission_evaluate") {
        if (!Expect(store, req, "admit|" + RequireStr(req, "model_ref"), err)) return false;
        std::vector<std::string> evidence_ids;
        if (req["evidence_ids"].isArray()) {
            for (size_t i = 0; i < req["evidence_ids"].size(); ++i) {
                if (req["evidence_ids"][i].isStr()) evidence_ids.push_back(req["evidence_ids"][i].get_str());
            }
        }
        std::vector<Interval> intervals;
        std::vector<std::string> roots;
        std::string start_state;
        std::string final_state;
        uint64_t total = 0;
        bool hash_ok = !evidence_ids.empty();
        for (const std::string& evidence : evidence_ids) {
            const auto train = store.trains.find(evidence);
            if (train == store.trains.end()) {
                hash_ok = false;
                continue;
            }
            std::string check_err;
            if (!TrainMatches(train->second, check_err)) hash_ok = false;
            if (start_state.empty() && !train->second.intervals.empty()) start_state = train->second.intervals.front().start_state;
            if (!train->second.intervals.empty()) final_state = train->second.intervals.back().end_state;
            if (train->second.state.step > total) total = train->second.state.step;
            intervals.insert(intervals.end(), train->second.intervals.begin(), train->second.intervals.end());
            if (!train->second.author.empty()) roots.push_back(train->second.author);
        }
        if (req["model_ref"].isObject() && req["model_ref"].exists("digest") && req["model_ref"]["digest"].isStr()) {
            std::string byte_err;
            if (!ModelBytesMatch(store, req["model_ref"]["digest"].get_str(), byte_err)) hash_ok = false;
        }
        const AdmissionResult decision = Admit(Assurance::PUBLIC_STRICT, hash_ok, intervals, total, start_state, final_state, roots, false);
        store.admissions[id] = decision.admitted ? "ADMITTED" : decision.code;
        if (req["model_ref"].isObject()) {
            const UniValue& ref = req["model_ref"];
            const std::string digest = ref.exists("digest") && ref["digest"].isStr() ? ref["digest"].get_str() : "";
            const std::string model_id = ref.exists("model_id") && ref["model_id"].isStr() && !ref["model_id"].get_str().empty()
                                              ? ref["model_id"].get_str()
                                              : digest;
            if (!model_id.empty()) store.admission_subject[id] = model_id + "\n" + digest;
        }
        return OpOut(store, result, id, decision.admitted ? "COMPLETE" : "FAILED", "STOPPED_QUIESCENT");
    }
    if (method == "lab.model_host") {
        if (!Expect(store, req, "host|" + RequireStr(req, "model_ref"), err)) return false;
        const std::string admission = RequireStr(req, "admission_id");
        const auto it = store.admissions.find(admission);
        if (it == store.admissions.end() || it->second != "ADMITTED") return Fail(err, "BTX035_ADMISSION");
        const auto subject = store.admission_subject.find(admission);
        if (subject != store.admission_subject.end()) {
            const auto split = subject->second.find('\n');
            const std::string bound_id = split == std::string::npos ? subject->second : subject->second.substr(0, split);
            const std::string bound_digest = split == std::string::npos ? std::string() : subject->second.substr(split + 1);
            std::string host_id;
            std::string host_digest;
            if (req["model_ref"].isObject()) {
                const UniValue& ref = req["model_ref"];
                if (ref.exists("model_id") && ref["model_id"].isStr()) host_id = ref["model_id"].get_str();
                if (ref.exists("digest") && ref["digest"].isStr()) host_digest = ref["digest"].get_str();
                if (host_id.empty()) host_id = host_digest;
            } else if (req["model_ref"].isStr()) {
                host_id = req["model_ref"].get_str();
                host_digest = host_id;
            }
            if (host_id != bound_id || (!bound_digest.empty() && host_digest != bound_digest)) return Fail(err, "BTX035_ADMISSION");
        }
        std::string hosted_id;
        if (req["model_ref"].isObject() && req["model_ref"].exists("digest") && req["model_ref"]["digest"].isStr()) {
            hosted_id = req["model_ref"]["digest"].get_str();
            if (!ModelBytesMatch(store, hosted_id, err)) return false;
        } else if (req["model_ref"].isStr()) {
            hosted_id = req["model_ref"].get_str();
        } else {
            return Fail(err, "BTX035_SCHEMA");
        }
        store.hosted.insert(hosted_id);
        result.pushKV("hosted", true);
        result.pushKV("admission_id", admission);
        return true;
    }
    if (method == "lab.model_unhost") {
        if (!Expect(store, req, "unhost|" + RequireStr(req, "model_ref"), err)) return false;
        result.pushKV("unhosted", store.hosted.erase(RequireStr(req, "model_ref")) > 0);
        return true;
    }
    if (method == "lab.action_prepare") {
        if (!Expect(store, req, "prepare|" + RequireStr(req, "intent_id"), err)) return false;
        const std::string intent = RequireStr(req, "intent_id");
        if (!HexN(intent, 96)) return Fail(err, "BTX035_SCHEMA");
        uint16_t guard_port = 0;
        const GuardRoute route = GuardRouteForCall(guard_port, err);
        if (route == GuardRoute::Invalid) return false;
        const int64_t now = NowMs();
        const std::string fingerprint = Id96("fp|" + intent);
        GuardPermit issued;
        if (route == GuardRoute::Remote) {
            if (!GuardClientPrepare("127.0.0.1", guard_port, "research.run", fingerprint, 1, issued, err)) return false;
        } else if (!store.guards.Prepare("research.run", fingerprint, 1, now, issued, err)) {
            return false;
        }
        ActionPermit permit;
        permit.permit_id = issued.commitment;
        permit.grant_id = intent;
        permit.generation = issued.generation;
        permit.effect = issued.effect;
        permit.not_after_ms = issued.not_after_ms;
        permit.parameter_fingerprint = issued.fingerprint;
        if (!store.gate->Issue(permit, err)) return false;
        IssuedPermit row;
        row.effect = permit.effect;
        row.generation = permit.generation;
        row.fingerprint = permit.parameter_fingerprint;
        row.not_after_ms = permit.not_after_ms;
        store.permit_rows[issued.secret] = row;
        store.grants[intent] = "ALLOW";
        result.pushKV("one_use_permit", issued.secret);
        result.pushKV("permit_commitment", issued.commitment);
        return Rec(result, issued.commitment, "PREPARED");
    }
    if (method == "lab.action_execute") {
        if (!Expect(store, req, "exec|" + RequireStr(req, "one_use_permit"), err)) return false;
        const std::string secret = RequireStr(req, "one_use_permit");
        const auto it = store.permit_rows.find(secret);
        if (it == store.permit_rows.end()) return Fail(err, "BTX035_PERMIT");
        const IssuedPermit row = it->second;
        uint16_t guard_port = 0;
        const GuardRoute route = GuardRouteForCall(guard_port, err);
        if (route == GuardRoute::Invalid) return false;
        const int64_t now = NowMs();
        std::string receipt;
        if (route == GuardRoute::Remote) {
            if (!GuardClientExecute("127.0.0.1", guard_port, secret, receipt, err)) return false;
        } else if (!store.guards.Execute(secret, now, receipt, err)) {
            return false;
        }
        if (!store.gate->Consume(GuardCommitment(secret), row.effect, row.generation, now, row.fingerprint, err)) return false;
        result.pushKV("physical_disposition", "NOT_DISPATCHED");
        result.pushKV("permit_consumed", true);
        return Rec(result, receipt, "PERMIT_CONSUMED");
    }
    if (method == "lab.runtime_bind") {
        if (!Expect(store, req, "bind|" + RequireStr(req, "release_id"), err)) return false;
        const std::string assurance = RequireStr(req, "assurance");
        if (assurance == "SOFTWARE_ISOLATED" || assurance == "VM_ISOLATED" || assurance == "HARDWARE_ATTESTED") {
            if (std::getenv("BTX_GUARD_PORT") == nullptr) return Fail(err, "BTX035_SCOPE_DENIED");
        }
        const std::string binding = Id96("bind|" + RequireStr(req, "release_id") + "|" + RequireStr(req, "environment_ref"));
        store.bindings[binding] = assurance;
        return Rec(result, binding, "BOUND");
    }
    if (method == "lab.runtime_pause") {
        if (!Expect(store, req, "pause|" + RequireStr(req, "runtime_binding_id"), err)) return false;
        const std::string binding = RequireStr(req, "runtime_binding_id");
        if (!store.bindings.count(binding)) return Fail(err, "BTX035_NOT_FOUND");
        uint16_t guard_port = 0;
        const GuardRoute route = GuardRouteForCall(guard_port, err);
        if (route == GuardRoute::Invalid) return false;
        if (route == GuardRoute::Remote) {
            if (!GuardClientPause("127.0.0.1", guard_port, err)) return false;
        } else {
            store.guards.Pause();
        }
        store.gate->Pause();
        store.paused_bindings.insert(binding);
        result.pushKV("state", "PAUSED");
        result.pushKV("receipt_id", Id96("pause|" + binding));
        return true;
    }
    if (method == "lab.runtime_resume") {
        if (!Expect(store, req, "resume|" + RequireStr(req, "runtime_binding_id"), err)) return false;
        const std::string binding = RequireStr(req, "runtime_binding_id");
        if (!store.paused_bindings.count(binding)) return Fail(err, "BTX035_NOT_FOUND");
        if (!store.grants.count(RequireStr(req, "new_grant_id"))) return Fail(err, "BTX035_PERMIT");
        uint16_t guard_port = 0;
        const GuardRoute route = GuardRouteForCall(guard_port, err);
        if (route == GuardRoute::Invalid) return false;
        store.paused_bindings.erase(binding);
        if (store.paused_bindings.empty()) {
            if (route == GuardRoute::Remote) {
                if (!GuardClientResume("127.0.0.1", guard_port, err)) {
                    store.paused_bindings.insert(binding);
                    return false;
                }
            } else {
                store.guards.Resume();
            }
            store.gate->Resume();
        }
        return Rec(result, Id96("resume|" + binding), "RESUMED");
    }
    if (method == "lab.journal_checkpoint") {
        if (!Expect(store, req, "cp|" + RequireStr(req, "stream_id"), err)) return false;
        const std::string cp = Id96("cp|" + RequireStr(req, "stream_id") + "|" + RequireStr(req, "through_sequence"));
        store.checkpoints[cp] = RequireStr(req, "stream_id");
        store.records["witness|" + cp] = req.write();
        return Rec(result, cp, "CHECKPOINT");
    }
    if (method == "lab.journal_proof") {
        const std::string cp = RequireStr(req, "checkpoint_id");
        const auto checkpoint = store.checkpoints.find(cp);
        if (checkpoint == store.checkpoints.end()) return Fail(err, "BTX035_NOT_FOUND");
        result.pushKV("proof_ref", RefOf("POLICY_BUNDLE", cp));
        result.pushKV("event_ref", RefOf("POLICY_BUNDLE", checkpoint->second));
        return true;
    }
    if (method == "lab.journal_witness") {
        if (!Expect(store, req, "wit|" + RequireStr(req, "checkpoint_id"), err)) return false;
        const std::string checkpoint = RequireStr(req, "checkpoint_id");
        if (!store.checkpoints.count(checkpoint)) return Fail(err, "BTX035_NOT_FOUND");
        const std::string witness = "witness|" + checkpoint;
        if (!store.records.count(witness)) return Fail(err, "BTX035_WITNESS");
        return Rec(result, Id96("wit|" + checkpoint), "WITNESSED");
    }
    if (method == "lab.incident_publish") {
        if (!Expect(store, req, "inc|" + RequireStr(req, "incident_id"), err)) return false;
        if (!HexN(RequireStr(req, "incident_id"), 96)) return Fail(err, "BTX035_SCHEMA");
        store.records[RequireStr(req, "incident_id")] = req.write();
        return Rec(result, RequireStr(req, "incident_id"), "PUBLISHED");
    }
    if (method == "lab.realm_create") {
        if (!Expect(store, req, "realm|" + RequireStr(req, "name"), err)) return false;
        const std::string realm = Id96("realm|" + RequireStr(req, "name") + "|" + RequireStr(req, "nonce"));
        const std::string policy = Id96("policy|" + realm);
        store.realms[realm] = policy;
        result.pushKV("realm_id", realm);
        result.pushKV("policy_id", policy);
        return true;
    }
    if (method == "lab.realm_policy_apply") {
        if (!Expect(store, req, "policy|" + RequireStr(req, "policy_id"), err)) return false;
        bool known = false;
        for (const auto& item : store.realms) {
            if (item.second == RequireStr(req, "policy_id")) known = true;
        }
        if (!known) return Fail(err, "BTX035_NOT_FOUND");
        return Rec(result, RequireStr(req, "policy_id"), "APPLIED");
    }
    if (method == "lab.realm_status") {
        const std::string realm = RequireStr(req, "realm_id");
        const auto it = store.realms.find(realm);
        if (it == store.realms.end()) return Fail(err, "BTX035_NOT_FOUND");
        result.pushKV("policy_id", it->second);
        result.pushKV("epoch", std::to_string(store.rollout.RingGeneration(realm)));
        result.pushKV("threshold", std::to_string(store.rollout.Threshold(realm)));
        result.pushKV("public_connectivity", "DISABLED");
        result.pushKV("revocation_age_ms", "0");
        result.pushKV("authority_state", "LOCAL");
        return true;
    }
    if (method == "lab.promotion_prepare") {
        if (!Expect(store, req, "promo|" + RequireStr(req, "source_realm_id"), err)) return false;
        if (!store.realms.count(RequireStr(req, "source_realm_id")) || !store.realms.count(RequireStr(req, "destination_realm_id"))) {
            return Fail(err, "BTX035_REALM");
        }
        store.records[id] = req.write();
        return Rec(result, id, "PREPARED");
    }
    if (method == "lab.promotion_attest") {
        if (!Expect(store, req, "promo-att|" + RequireStr(req, "promotion_id"), err)) return false;
        const std::string promotion = RequireStr(req, "promotion_id");
        if (!store.records.count(promotion)) return Fail(err, "BTX035_NOT_FOUND");
        if (!req["checks_ref"].isObject() || req["checks_ref"].getKeys().empty()) return Fail(err, "BTX035_SCHEMA");
        UniValue prepared;
        if (!prepared.read(store.records[promotion]) || !prepared.isObject() || !prepared["destination_realm_id"].isStr()) {
            return Fail(err, "BTX035_SCHEMA");
        }
        const std::string destination = prepared["destination_realm_id"].get_str();
        if (!req["checks_ref"].exists("realm_id") || !req["checks_ref"]["realm_id"].isStr() ||
            req["checks_ref"]["realm_id"].get_str() != destination) {
            return Fail(err, "BTX035_REALM");
        }
        if (req["checks_ref"].exists("revoke_attestor") && req["checks_ref"]["revoke_attestor"].isStr()) {
            const std::string realm = destination;
            const std::string attestor = req["checks_ref"]["revoke_attestor"].get_str();
            const int before = store.rollout.Threshold(realm);
            if (before < 1) return Fail(err, "BTX035_REALM");
            if (!store.rollout.RevokeAttestor(realm, attestor, err)) return false;
            if (store.rollout.Threshold(realm) != before) return Fail(err, "BTX035_THRESHOLD");
            result.pushKV("threshold", std::to_string(before));
            return Rec(result, Id96("revoke|" + realm + "|" + attestor), "REVOKED");
        }
        const std::string idem = RequireStr(req, "idempotency_key");
        if (idem.size() < 16) return Fail(err, "BTX035_SCHEMA");
        const std::string attestation = Id96("patt|" + promotion + "|" + idem);
        store.records[attestation] = req.write();
        return Rec(result, attestation, "ATTESTED");
    }
    if (method == "lab.channel_publish") {
        if (!Expect(store, req, "chan|" + RequireStr(req, "update_id"), err)) return false;
        UniValue envelope;
        if (!LoadEnvelope(store, RequireStr(req, "update_id"), envelope, err)) return false;
        const UniValue& body = envelope["body"];
        if (body["record_type"].get_str() != "ChannelUpdate") return Fail(err, "BTX035_RECORD_TYPE");
        const UniValue& payload = body["payload"];
        if (!payload.isObject() || !payload.exists("realm_id") || !payload["realm_id"].isStr() ||
            !payload.exists("channel") || !payload["channel"].isStr() ||
            !payload.exists("sequence") || !payload["sequence"].isStr()) {
            return Fail(err, "BTX035_SCHEMA");
        }
        int64_t sequence = 0;
        if (!ParseDec(payload["sequence"].get_str(), sequence)) return Fail(err, "BTX035_SCHEMA");
        if (!ChannelWindowOpen(payload, err)) return false;
        const std::string key = payload["realm_id"].get_str() + "\n" + payload["channel"].get_str();
        if (!store.rollout.PublishChannel(key, sequence, RequireStr(req, "update_id"), err)) return false;
        return Rec(result, RequireStr(req, "update_id"), "PUBLISHED");
    }
    if (method == "lab.channel_get") {
        const std::string key = RequireStr(req, "realm_id") + "\n" + RequireStr(req, "channel");
        const int64_t sequence = store.rollout.ChannelSequence(key);
        const std::string body = store.rollout.ChannelBody(key);
        if (sequence < 0 || body.empty()) {
            result.pushKV("update_id", UniValue());
            result.pushKV("sequence", "0");
            result.pushKV("state", "UNKNOWN");
            return true;
        }
        result.pushKV("update_id", body);
        result.pushKV("sequence", std::to_string(sequence));
        result.pushKV("state", "CURRENT");
        return true;
    }
    if (method == "lab.rollout_start" || method == "lab.rollout_rollback") {
        if (!Expect(store, req, "roll|" + RequireStr(req, "plan_id"), err)) return false;
        const std::string plan = RequireStr(req, "plan_id");
        if (!HexN(plan, 96)) return Fail(err, "BTX035_SCHEMA");
        if (method == "lab.rollout_start") {
            UniValue envelope;
            std::string load_err;
            if (LoadEnvelope(store, plan, envelope, load_err) && envelope["body"]["record_type"].isStr() &&
                envelope["body"]["record_type"].get_str() == "RolloutPlan") {
                const UniValue& rings = envelope["body"]["payload"]["rings"];
                if (!rings.isArray() || rings.size() < 2) return Fail(err, "BTX035_SCHEMA");
                store.plans[plan] = "STAGED";
                store.verified_rings[plan].clear();
            } else {
                store.plans[plan] = "PLANNED";
            }
            return OpOut(store, result, id, "COMPLETE", "STOPPED_QUIESCENT");
        }
        if (!store.plans.count(plan)) return OpOut(store, result, id, "FAILED", "STOPPED_QUIESCENT");
        const std::string update_id = RequireStr(req, "new_channel_update_id");
        UniValue envelope;
        std::string load_err;
        if (!LoadEnvelope(store, update_id, envelope, load_err) || !envelope["body"]["record_type"].isStr() ||
            envelope["body"]["record_type"].get_str() != "ChannelUpdate") {
            return OpOut(store, result, id, "FAILED", "STOPPED_QUIESCENT");
        }
        const UniValue& payload = envelope["body"]["payload"];
        int64_t sequence = 0;
        if (!payload.isObject() || !payload["sequence"].isStr() || !ParseDec(payload["sequence"].get_str(), sequence) ||
            !payload["realm_id"].isStr() || !payload["channel"].isStr()) {
            return Fail(err, "BTX035_SCHEMA");
        }
        if (!ChannelWindowOpen(payload, err)) return false;
        const std::string key = payload["realm_id"].get_str() + "\n" + payload["channel"].get_str();
        const int64_t current = store.rollout.ChannelSequence(key);
        if (current < 0 || sequence <= current) return Fail(err, "BTX035_ROLLBACK");
        if (!store.rollout.PublishChannel(key, sequence, update_id, err)) return false;
        store.plans[plan] = "ROLLED_BACK";
        return OpOut(store, result, id, "COMPLETE", "STOPPED_QUIESCENT");
    }
    if (method == "lab.rollout_pause") {
        if (!Expect(store, req, "rpause|" + RequireStr(req, "plan_id"), err)) return false;
        const std::string plan = RequireStr(req, "plan_id");
        if (!store.plans.count(plan)) return Fail(err, "BTX035_NOT_FOUND");
        store.plans[plan] = "PAUSED";
        const uint64_t epoch = ++store.pause_epoch[plan];
        result.pushKV("paused", true);
        result.pushKV("pause_epoch", std::to_string(epoch));
        UniValue counts = Counts(0, 0);
        counts.pushKV("paused", "1");
        result.pushKV("counts", counts);
        result.pushKV("snapshot_id", Id96("roll|" + plan + "|" + std::to_string(epoch)));
        result.pushKV("endpoint_query_method", "lab.rollout_endpoints");
        return true;
    }
    if (method == "lab.rollout_status" || method == "lab.rollout_endpoints") {
        const std::string plan = RequireStr(req, "plan_id");
        if (!store.plans.count(plan)) return Fail(err, "BTX035_NOT_FOUND");
        const FleetCounts fleet = store.rollout.FleetStatus();
        UniValue counts = Counts(static_cast<uint64_t>(fleet.healthy + fleet.unhealthy + fleet.unknown), static_cast<uint64_t>(fleet.unknown));
        counts.pushKV("healthy", std::to_string(fleet.healthy));
        counts.pushKV("failed", std::to_string(fleet.unhealthy));
        if (store.plans[plan] == "PAUSED") counts.pushKV("paused", "1");
        if (method == "lab.rollout_endpoints") {
            UniValue endpoints(UniValue::VARR);
            for (const std::string& receipt : store.endpoint_receipts) endpoints.push_back(receipt);
            result.pushKV("endpoints", endpoints);
            result.pushKV("counts", counts);
            result.pushKV("target_set_root", Id96("targets|" + plan));
            result.pushKV("snapshot_id", Id96("ends|" + plan));
            result.pushKV("observed_ms", "0");
            result.pushKV("next_cursor", UniValue());
            return true;
        }
        result.pushKV("state", store.plans[plan]);
        result.pushKV("counts", counts);
        result.pushKV("target_set_root", Id96("targets|" + plan));
        result.pushKV("snapshot_id", Id96("status|" + plan));
        result.pushKV("observed_ms", "0");
        result.pushKV("freshness_limit_ms", "10000");
        result.pushKV("pause_epoch", std::to_string(store.pause_epoch[plan]));
        result.pushKV("active_generation", store.rollout.ActiveGeneration());
        result.pushKV("previous_generation", store.rollout.PreviousGeneration());
        result.pushKV("endpoint_query_method", "lab.rollout_endpoints");
        return true;
    }
    if (method == "lab.deployment_observe") {
        if (!Expect(store, req, "obs|" + RequireStr(req, "receipt_id"), err)) return false;
        const std::string receipt = RequireStr(req, "receipt_id");
        if (!HexN(receipt, 96)) return Fail(err, "BTX035_SCHEMA");
        UniValue envelope;
        std::string load_err;
        if (LoadEnvelope(store, receipt, envelope, load_err) && envelope["body"]["record_type"].isStr() &&
            envelope["body"]["record_type"].get_str() == "DeploymentReceipt") {
            const UniValue& payload = envelope["body"]["payload"];
            if (!payload.isObject() || !payload["state"].isStr() || !payload["device_id"].isStr() || !payload["ring_id"].isStr() ||
                !payload["rollout_id"].isStr()) {
                return Fail(err, "BTX035_SCHEMA");
            }
            const std::string state = payload["state"].get_str();
            const std::string device = payload["device_id"].get_str();
            const std::string ring = payload["ring_id"].get_str();
            const std::string rollout_id = payload["rollout_id"].get_str();
            if (state == "ACTIVE") {
                UniValue channel_env;
                std::string channel_err;
                const std::string update_id = payload["channel_update_id"].isStr() ? payload["channel_update_id"].get_str() : "";
                if (!LoadEnvelope(store, update_id, channel_env, channel_err) || !channel_env["body"]["record_type"].isStr() ||
                    channel_env["body"]["record_type"].get_str() != "ChannelUpdate") {
                    return Fail(err, "BTX035_NOT_FOUND");
                }
                if (!ChannelWindowOpen(channel_env["body"]["payload"], err)) {
                    std::string observe_err;
                    store.rollout.Observe(device, "UNKNOWN", observe_err);
                    store.rollout.ObserveEndpoint(device, "UNKNOWN", observe_err);
                    return false;
                }
                const std::string closure = payload["observed_closure_root"].isStr() ? payload["observed_closure_root"].get_str() : "";
                if (!ModelBytesMatch(store, closure, err)) {
                    std::string observe_err;
                    store.rollout.Observe(device, "UNKNOWN", observe_err);
                    store.rollout.ObserveEndpoint(device, "UNKNOWN", observe_err);
                    return false;
                }
                if (!store.rollout.Observe(device, "HEALTHY", err)) return false;
                if (!store.rollout.ObserveEndpoint(device, "ACTIVE", err)) return false;
                store.verified_rings[rollout_id].insert(ring);
                if (!store.rollout.StageGeneration(rollout_id, {}, err)) return false;
                const bool owner_ok = OwnerActivation(store, payload, rollout_id);
                if (store.verified_rings[rollout_id].size() >= 2 && owner_ok) {
                    if (!store.rollout.ActivateGeneration(rollout_id, true, true, err)) return false;
                }
                if (store.plans.count(rollout_id)) {
                    const bool active = store.verified_rings[rollout_id].size() >= 2 && owner_ok;
                    store.plans[rollout_id] = active ? "ACTIVE" : "CANARY";
                }
            } else if (state == "UNKNOWN") {
                if (!store.rollout.Observe(device, "UNKNOWN", err)) return false;
                if (!store.rollout.ObserveEndpoint(device, "UNKNOWN", err)) return false;
            } else if (state == "FAILED") {
                if (!store.rollout.Observe(device, "UNHEALTHY", err)) return false;
                if (!store.rollout.ObserveEndpoint(device, "FAILED", err)) return false;
            } else {
                if (!store.rollout.Observe(device, "UNKNOWN", err)) return false;
                if (!store.rollout.ObserveEndpoint(device, state, err)) return false;
            }
            store.endpoint_receipts.push_back(receipt);
            result.pushKV("endpoint_state", store.rollout.EndpointState(device));
            return Rec(result, receipt, "OBSERVED");
        }
        store.records[receipt] = req.write();
        store.endpoint_receipts.push_back(receipt);
        std::string observe_err;
        store.rollout.Observe(receipt, "UNKNOWN", observe_err);
        return Rec(result, receipt, "OBSERVED");
    }
    if (method == "lab.trust_reconcile") {
        if (!Expect(store, req, "trust|" + RequireStr(req, "owner_approval_id"), err)) return false;
        bool ready = req["anchor_record_ids"].isArray() && !req["anchor_record_ids"].empty();
        std::string joined;
        if (ready) {
            for (size_t i = 0; i < req["anchor_record_ids"].size(); ++i) {
                if (!req["anchor_record_ids"][i].isStr() || !store.records.count(req["anchor_record_ids"][i].get_str())) ready = false;
                else joined += req["anchor_record_ids"][i].get_str();
            }
        }
        result.pushKV("state", ready ? "RECONCILED" : "RECOVERY_REQUIRED");
        result.pushKV("reconciled_anchor_root", ready ? UniValue(Id96(joined)) : UniValue());
        return true;
    }
    if (method == "lab.bundle_export") {
        if (!Expect(store, req, "bex|" + RequireStr(req, "bundle_id"), err)) return false;
        const std::string name = RequireStr(req, "local_destination");
        if (!SafeSegment(name)) return Fail(err, "BTX035_PATH_UNSAFE");
        const std::string realm = RequireStr(req, "bundle_id");
        if (!store.realms.count(realm)) return OpOut(store, result, id, "FAILED", "STOPPED_QUIESCENT");
        if (!EnsureBundleDir(err)) return false;
        const fs::path path = BundleDir() / name.c_str();
        if (!store.rollout.WriteOfflineBundle(path, realm, err)) return false;
        return OpOut(store, result, id, "COMPLETE", "STOPPED_QUIESCENT");
    }
    if (method == "lab.bundle_import") {
        if (!Expect(store, req, "bim|" + RequireStr(req, "local_source"), err)) return false;
        const std::string name = RequireStr(req, "local_source");
        if (!SafeSegment(name)) return Fail(err, "BTX035_PATH_UNSAFE");
        int64_t minimum = 0;
        if (!ParseDec(RequireStr(req, "minimum_policy_epoch"), minimum)) return Fail(err, "BTX035_SCHEMA");
        const std::string realm = RequireStr(req, "destination_realm_id");
        if (store.rollout.RingGeneration(realm) < minimum) return Fail(err, "BTX035_POLICY");
        const fs::path path = BundleDir() / name.c_str();
        if (!store.rollout.ReadOfflineBundle(path, realm, err)) return false;
        return OpOut(store, result, id, "COMPLETE", "STOPPED_QUIESCENT");
    }
    if (method == "lab.migration_plan") {
        const std::string plan = Id96("plan|" + RequireStr(req, "target_version"));
        store.migration_plans.insert(plan);
        store.records[plan] = req.write();
        result.pushKV("plan_ref", RefOf("RELEASE", plan));
        result.pushKV("legacy_model_count", "0");
        result.pushKV("requires_stop", false);
        return true;
    }
    if (method == "lab.migration_apply") {
        if (!Expect(store, req, "mig|" + RequireStr(req, "idempotency_key"), err)) return false;
        if (!req["plan_ref"].isObject() || !req["backup_ref"].isObject()) return Fail(err, "BTX035_SCHEMA");
        const std::string plan = req["plan_ref"].exists("digest48") && req["plan_ref"]["digest48"].isStr() ? req["plan_ref"]["digest48"].get_str() : "";
        if (!store.migration_plans.count(plan) || !store.records.count(plan)) {
            return OpOut(store, result, id, "FAILED", "STOPPED_QUIESCENT");
        }
        const UniValue& backup = req["backup_ref"];
        if (backup.exists("sequence") && backup["sequence"].isStr() && backup.exists("realm_id") && backup["realm_id"].isStr() &&
            backup.exists("channel") && backup["channel"].isStr()) {
            int64_t backup_sequence = 0;
            if (!ParseDec(backup["sequence"].get_str(), backup_sequence)) return Fail(err, "BTX035_SCHEMA");
            const std::string key = backup["realm_id"].get_str() + "\n" + backup["channel"].get_str();
            const int64_t current = store.rollout.ChannelSequence(key);
            if (current >= 0 && backup_sequence < current) return Fail(err, "BTX035_ROLLBACK");
        }
        store.migrations.insert(id);
        store.records[id] = req.write();
        return OpOut(store, result, id, "COMPLETE", "STOPPED_QUIESCENT");
    }
    if (method == "lab.migration_verify") {
        const std::string mig = RequireStr(req, "migration_id");
        const bool done = store.migrations.count(mig) != 0;
        result.pushKV("state", done ? "COMPLETE" : "INCOMPLETE");
        result.pushKV("money_unchanged", true);
        result.pushKV("source_map_ref", RefOf("RELEASE", Id96("src|" + mig)));
        return true;
    }
    if (method == "lab.economy_refs") {
        if (ResearchMaySpendWallet()) return Fail(err, "BTX035_SCOPE_DENIED");
        result.pushKV("bounty_ids", UniValue(UniValue::VARR));
        result.pushKV("agreement_ids", UniValue(UniValue::VARR));
        result.pushKV("spend_authorized", false);
        return true;
    }
    if (method == "lab.capsule_resolve") {
        const std::string capsule = RequireStr(req, "capsule_id");
        const std::string purpose = RequireStr(req, "purpose");
        if (!HexN(capsule, 96) || (purpose != "INSPECT" && purpose != "REPLAY" && purpose != "EXTEND" && purpose != "DEPLOY")) {
            return Fail(err, "BTX035_SCHEMA");
        }
        int64_t max_bytes = 0;
        if (!ParseDec(RequireStr(req, "max_bytes"), max_bytes) || max_bytes < 0) return Fail(err, "BTX035_SCHEMA");
        result.pushKV("plan_id", Id96("plan|" + capsule));
        std::string retained;
        if (store.models.count(capsule)) retained = store.models[capsule];
        else if (store.records.count(capsule)) retained = store.records[capsule];
        UniValue missing(UniValue::VARR);
        if (retained.empty() || static_cast<int64_t>(retained.size()) > max_bytes) {
            UniValue ref = RefOf("RECORD", HexN(capsule, 96) ? capsule : Id96(capsule));
            ref.pushKV("record_type", "ResearchCapsule");
            missing.push_back(ref);
        }
        result.pushKV("missing_refs", missing);
        result.pushKV("untrusted_refs", UniValue(UniValue::VARR));
        result.pushKV("estimated_bytes", std::to_string(retained.size()));
        return true;
    }
    if (method == "lab.state_get") {
        const std::string key = RequireStr(req, "target_key");
        if (!HexN(key, 96)) return Fail(err, "BTX035_SCHEMA");
        const bool exists = store.records.count(key) || store.operations.count(key) || store.identities.count(key) ||
                            store.repos.count(key) || store.realms.count(key) || store.workspace_backend.count(key) ||
                            store.plans.count(key) || store.snapshots.count(key) || store.checkpoints.count(key) ||
                            store.grants.count(key) || store.bindings.count(key) || store.workspace_backend.count(key);
        result.pushKV("target_kind", RequireStr(req, "target_kind"));
        result.pushKV("target_key", key);
        result.pushKV("exists", exists);
        result.pushKV("generation", exists ? "1" : "0");
        result.pushKV("value_id", exists ? UniValue(key) : UniValue());
        result.pushKV("policy_epoch", "0");
        result.pushKV("state_token", UniValue());
        return true;
    }
    if (method == "lab.audit_coverage") {
        const auto train = store.trains.find(RequireStr(req, "trajectory_id"));
        UniValue gaps(UniValue::VARR);
        UniValue accepted(UniValue::VARR);
        bool complete = false;
        if (train == store.trains.end()) {
            gaps.push_back("BTX035_NOT_FOUND");
        } else {
            std::string check_err;
            const bool retained = !train->second.state.state_hash.empty() && train->second.state.step > 0;
            const bool state_ok = TrainMatches(train->second, check_err);
            const bool path_ok = retained && !train->second.intervals.empty() &&
                                 FullReplayCoverage(train->second.state.step, train->second.intervals.front().start_state,
                                                    train->second.state.state_hash, train->second.intervals);
            complete = retained && state_ok && path_ok;
            if (!complete) gaps.push_back(check_err.empty() ? "BTX035_REPLAY" : check_err);
            else if (!train->second.author.empty()) accepted.push_back(train->second.author);
        }
        result.pushKV("complete_path", complete);
        result.pushKV("accepted_attestation_ids", accepted);
        result.pushKV("gaps", gaps);
        result.pushKV("mode", "LOCAL_REPLAY");
        return true;
    }
    if (method == "lab.snapshot_export") {
        if (!Expect(store, req, "snapex|" + RequireStr(req, "repository_id"), err)) return false;
        const std::string repo = RequireStr(req, "repository_id");
        const auto it = store.repo_objects.find(repo);
        if (it == store.repo_objects.end()) return Fail(err, "BTX035_NOT_FOUND");
        const bool ticketed = req.exists("fetch_ticket") && req["fetch_ticket"].isStr() && !req["fetch_ticket"].get_str().empty();
        if (ticketed) {
            const std::string ticket = req["fetch_ticket"].get_str();
            const auto auth = store.fetch_tickets.find(ticket);
            if (auth == store.fetch_tickets.end()) return Fail(err, "BTX035_PERMIT");
            if (auth->second.consumed) return Fail(err, "BTX035_REPLAY");
            if (auth->second.repository_id != repo) return Fail(err, "BTX035_ID_MISMATCH");
            if (NowMs() > auth->second.not_after_ms) return Fail(err, "BTX035_EXPIRED");
        }
        std::vector<ExchangeObject> exported;
        for (const ExchangeObject& object : it->second) {
            if (object.kind == "research" || object.kind == "train" || object.kind == "lineage" || object.kind == "model" ||
                object.kind == "piece" || object.kind == "replay" || object.kind == "blob") {
                continue;
            }
            exported.push_back(object);
        }
        if (!AppendPublicResearch(store.observations, exported, err)) return false;
        if (!AppendTrains(store.trains, exported, err)) return false;
        if (!AppendModels(store, exported, err)) return false;
        {
            std::string dataset;
            std::string tokenizer;
            if (!LaunchDatasetDigest(dataset, err) || !LaunchTokenizerDigest(tokenizer, err)) return false;
            for (const std::string& blob_id : {dataset, tokenizer}) {
                const auto found = store.records.find(blob_id);
                if (found == store.records.end()) continue;
                ExchangeObject object;
                object.kind = "blob";
                object.content = found->second;
                const std::vector<unsigned char> raw(object.content.begin(), object.content.end());
                if (!GitObjectDigest("blob", Span<const unsigned char>{raw.data(), raw.size()}, object.digest, err)) return false;
                if (object.digest != blob_id) return Fail(err, "BTX035_ID_MISMATCH");
                exported.push_back(std::move(object));
            }
        }
        if (!AppendLineage(store.observations, exported, err)) return false;
        if (ticketed) {
            const auto auth = store.fetch_tickets.find(req["fetch_ticket"].get_str());
            if (auth == store.fetch_tickets.end()) return Fail(err, "BTX035_PERMIT");
            int64_t bytes = 0;
            for (const ExchangeObject& object : exported) bytes += static_cast<int64_t>(object.content.size());
            if (bytes > auth->second.max_bytes) return Fail(err, "BTX035_POLICY");
        }
        std::string manifest;
        if (!WriteExchangeManifest(exported, manifest, err)) return false;
        if (ticketed) store.fetch_tickets[req["fetch_ticket"].get_str()].consumed = true;
        result.pushKV("manifest", manifest);
        result.pushKV("object_count", static_cast<int>(exported.size()));
        return true;
    }
    if (method == "lab.snapshot_import") {
        if (!Expect(store, req, "snapim|" + RequireStr(req, "idempotency_key"), err)) return false;
        std::vector<ExchangeObject> objects;
        if (!VerifyExchangeManifest(RequireStr(req, "manifest"), objects, err)) return false;
        std::vector<ResearchObservation> observed;
        if (!CollectResearch(objects, observed, err)) return false;
        std::map<std::string, IntegerState> trains;
        std::map<std::string, LaunchCheckpoint> launch_trains;
        if (!CollectTrains(objects, trains, launch_trains, err)) return false;
        if (!AttachLineage(objects, observed, err)) return false;
        const std::string repo = Id96(RequireStr(req, "manifest"));
        store.repos.insert(repo);
        store.repo_objects[repo] = objects;
        store.snapshots.insert(repo);
        store.observations = std::move(observed);
        RestorePublished(store);
        RestoreTrains(store, trains);
        RestoreLaunch(store, launch_trains);
        if (!ApplyReplayAuthors(store, objects, err)) return false;
        for (const ExchangeObject& object : objects) {
            if (object.kind != "model" && object.kind != "piece") continue;
            if (!AcceptModelObject(store, object, err)) return false;
        }
        for (const ExchangeObject& object : objects) {
            if (!AcceptBlob(store, object, err)) return false;
        }
        for (const ExchangeObject& object : objects) {
            if (object.kind != "model") continue;
            if (!ModelBytesMatch(store, object.digest, err)) return false;
        }
        result.pushKV("repository_id", repo);
        result.pushKV("object_count", static_cast<int>(objects.size()));
        return true;
    }
    if (method == "lab.snapshot_pull") {
        if (!Expect(store, req, "snappull|" + RequireStr(req, "idempotency_key"), err)) return false;
        int port_num = 0;
        if (!req.exists("port") || !ReadIntParam(req["port"], port_num)) return Fail(err, "BTX035_SCHEMA");
        if (port_num <= 0 || port_num > 65535) return Fail(err, "BTX035_SCHEMA");
        std::string manifest;
        const uint64_t generation = store.commit_generation;
        const std::string subject = store.token_subject;
        bool pulled = false;
        {
            REVERSE_LOCK(api_lock);
            pulled = PullExchangeLoopback(RequireStr(req, "host"), static_cast<uint16_t>(port_num), RequireStr(req, "rpc_user"),
                                          RequireStr(req, "rpc_password"), RequireStr(req, "repository_id"), manifest, err);
        }
        store.token_subject = subject;
        if (!GenerationHeld(store, generation, err)) return false;
        if (!pulled) return false;
        std::vector<ExchangeObject> objects;
        if (!VerifyExchangeManifest(manifest, objects, err)) return false;
        std::vector<ResearchObservation> observed;
        if (!CollectResearch(objects, observed, err)) return false;
        std::map<std::string, IntegerState> trains;
        std::map<std::string, LaunchCheckpoint> launch_trains;
        if (!CollectTrains(objects, trains, launch_trains, err)) return false;
        if (!AttachLineage(objects, observed, err)) return false;
        const std::string repo = RequireStr(req, "repository_id");
        for (const ExchangeObject& object : objects) {
            if (object.kind != "model" && object.kind != "piece") continue;
            if (!AcceptModelObject(store, object, err)) return false;
        }
        for (const ExchangeObject& object : objects) {
            if (!AcceptBlob(store, object, err)) return false;
        }
        for (const ExchangeObject& object : objects) {
            if (object.kind != "model") continue;
            if (!ModelBytesMatch(store, object.digest, err)) return false;
        }
        store.repos.insert(repo);
        store.repo_objects[repo] = std::move(objects);
        store.observations = std::move(observed);
        RestorePublished(store);
        RestoreTrains(store, trains);
        RestoreLaunch(store, launch_trains);
        if (!ApplyReplayAuthors(store, store.repo_objects[repo], err)) return false;
        result.pushKV("manifest", manifest);
        result.pushKV("repository_id", repo);
        return true;
    }
    return Fail(err, "BTX035_NOT_IMPLEMENTED");
}

class LabStoreView : public PeerView {
    const Store& store;
public:
    explicit LabStoreView(const Store& in) : store(in) {}
    bool Record(const std::string& id, PeerRecord& out) const override
    {
        out = PeerRecord{};
        for (const ResearchObservation& observation : store.observations) {
            if (observation.record_id == id && observation.is_private) {
                out.exists = true;
                out.is_private = true;
                return true;
            }
        }
        const auto record = store.records.find(id);
        if (record != store.records.end()) {
            out.exists = true;
            out.body = record->second;
            return true;
        }
        const auto model = store.models.find(id);
        if (model != store.models.end()) {
            out.exists = true;
            out.body = model->second;
            return true;
        }
        return false;
    }
    bool Piece(const std::string& model_digest, uint64_t index, std::string& bytes) const override
    {
        const auto found = store.model_pieces.find(model_digest);
        if (found == store.model_pieces.end() || index >= found->second.size() || found->second[index].empty()) return false;
        bytes = found->second[index];
        return true;
    }
    bool Channel(const std::string& realm_id, const std::string& channel, int64_t& sequence, std::string& update_id) const override
    {
        const std::string key = realm_id + "\n" + channel;
        sequence = store.rollout.ChannelSequence(key);
        update_id = store.rollout.ChannelBody(key);
        return sequence >= 0 && !update_id.empty();
    }
    bool Realm(const std::string& realm_id, std::string& policy_id, int& threshold) const override
    {
        const auto found = store.realms.find(realm_id);
        if (found == store.realms.end()) return false;
        policy_id = found->second;
        threshold = store.rollout.Threshold(realm_id);
        return true;
    }
    void PublicResearch(std::vector<std::string>& ids) const override
    {
        ids.clear();
        for (const ResearchObservation& observation : store.observations) {
            if (!observation.is_private && !observation.record_id.empty()) ids.push_back(observation.record_id);
        }
    }
    bool Ticket(const std::string& ticket_id) const override
    {
        const auto found = store.fetch_tickets.find(ticket_id);
        return found != store.fetch_tickets.end() && !found->second.consumed && NowMs() <= found->second.not_after_ms;
    }
    bool VerifySession(const std::string& message, const std::string& signature_hex) const override
    {
        std::vector<unsigned char> digest;
        const std::vector<unsigned char> sig = ParseHex(signature_hex);
        if (!BytesFromHex(message, digest) || sig.empty()) return false;
        for (const auto& item : store.identity_pk) {
            if (VerifyMlDsa44(Span<const unsigned char>{item.second.data(), item.second.size()},
                              Span<const unsigned char>{digest.data(), digest.size()},
                              Span<const unsigned char>{sig.data(), sig.size()})) {
                return true;
            }
        }
        return false;
    }
};

const LabMethod* FindMethod(const std::string& method)
{
    for (const LabMethod& item : kLabMethods) {
        if (method == item.name) return &item;
    }
    return nullptr;
}

} // namespace

void ResetLabApi()
{
    LOCK(g_lab_mutex);
    WipeMemory();
}

void ReloadLabFromDisk()
{
    LOCK(g_lab_mutex);
    WipeMemory();
    LoadDiskInto(State());
}

bool ServeLabPeer(const std::string& route, const std::string& request_json, std::string& response_json, std::string& err)
{
    LOCK(g_lab_mutex);
    const LabStoreView view(State());
    return DispatchPeerRoute(route, request_json, view, response_json, err);
}

bool PublishAdmission(const std::string& method, const UniValue& req, std::string& err)
{
    if (method != "lab.admission_evaluate") return true;
    const std::string op = Id96(method + "|" + req.write());
    const Store& store = State();
    const auto subject = store.admission_subject.find(op);
    if (subject == store.admission_subject.end()) return true;
    const auto split = subject->second.find('\n');
    const std::string model_id = split == std::string::npos ? subject->second : subject->second.substr(0, split);
    const std::string digest = split == std::string::npos ? std::string() : subject->second.substr(split + 1);
    const auto decision = store.admissions.find(op);
    if (model_id.empty() || decision == store.admissions.end() || decision->second.empty()) return true;
    return RecordModelAdmission(model_id, digest, decision->second, err);
}

struct SecretCopy {
    std::map<std::string, std::vector<unsigned char>> keys;
    ~SecretCopy()
    {
        for (auto& item : keys) memory_cleanse(item.second.data(), item.second.size());
    }
};

bool DispatchLabApi(const std::string& method, const std::string& request_json, std::string& response_json, std::string& err)
{
    UniqueLock<GlobalMutex> api_lock(g_lab_mutex, "g_lab_mutex", __FILE__, __LINE__);
    response_json.clear();
    const LabMethod* spec = FindMethod(method);
    if (!spec) return Fail(err, "BTX035_NOT_IMPLEMENTED");
    UniValue req;
    if (!req.read(request_json) || !req.isObject()) return Fail(err, "BTX035_INVALID_SCHEMA");
    if (!CheckRequest(*spec, req, err)) return false;
    if (State().recovery_required && !DurableRead(method)) return Fail(err, "BTX035_RECOVERY_REQUIRED");
    const std::string digest = Id96(method + "\n" + req.write());
    std::string replayed;
    if (!Replay(req, digest, replayed, err)) return false;
    if (!replayed.empty()) {
        response_json = replayed;
        err.clear();
        return true;
    }
    LabDiskImage prior_image;
    SecretCopy prior_secrets;
    // Only a durable write can roll back, so a read does not copy the store.
    if (!DurableRead(method)) {
        ImageFromStore(State(), prior_image);
        prior_secrets.keys = State().identity_sk;
    }
    const bool prior_recovery = State().recovery_required;
    const uint64_t prior_generation = State().commit_generation;
    UniValue result(UniValue::VOBJ);
    if (!Apply(method, req, result, err, api_lock)) return false;
    if (result.empty()) return Fail(err, "BTX035_INVALID_SCHEMA");
    const std::string request_id = Id96(method + "|" + req.write()).substr(0, 32);
    const UniValue envelope = EnvelopeResponse(request_id, result);
    response_json = envelope.write();
    if (!State().token_subject.empty() && envelope.exists("state_token") && envelope["state_token"].isStr()) {
        State().tokens[State().token_subject] = envelope["state_token"].get_str();
    }
    Remember(req, digest, response_json);
    if (!DurableRead(method)) {
        bool persisted = false;
        try {
            persisted = PersistDurable(err);
        } catch (const std::filesystem::filesystem_error&) {
            err = "BTX035_RECOVERY_REQUIRED";
        }
        if (!persisted) {
            bool recovery = prior_recovery;
            if (!recovery && err == "BTX035_RECOVERY_REQUIRED") {
                // A failed write leaves lab.json untouched, or it is put back below. Block writes only when it cannot be read.
                LabDiskImage on_disk;
                std::string read_err;
                recovery = !LoadLabDisk(on_disk, read_err);
            }
            if (!recovery) {
                std::string rollback_err;
                (void)SaveLabDisk(prior_image, rollback_err);
            }
            RevertStore(std::move(prior_image), std::move(prior_secrets.keys), recovery, prior_generation);
            response_json.clear();
            return false;
        }
        bool published = false;
        try {
            published = PublishAdmission(method, req, err);
        } catch (const std::filesystem::filesystem_error&) {
            err = "BTX035_RECOVERY_REQUIRED";
        }
        if (!published) {
            std::string rollback_err;
            const bool rolled_back = SaveLabDisk(prior_image, rollback_err);
            RevertStore(std::move(prior_image), std::move(prior_secrets.keys), !rolled_back, prior_generation);
            response_json.clear();
            if (!rolled_back) err = "BTX035_RECOVERY_REQUIRED";
            return false;
        }
        State().commit_generation += 1;
    }
    err.clear();
    return true;
}

} // namespace modelnet
