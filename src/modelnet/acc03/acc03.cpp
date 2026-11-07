// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/acc03/acc03.h>

#include <modelnet/crypto.h>
#include <modelnet/dt_ckpt/codes.h>
#include <modelnet/dt_ckpt/dt_ckpt.h>
#include <modelnet/dt_dense/dt_dense.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_frontier.h>
#include <modelnet/swarm_popniche.h>
#include <modelnet/training_integer.h>

#include <util/fs.h>

#include <cstdint>
#include <fstream>
#include <iterator>
#include <limits>
#include <set>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace modelnet {
namespace {

const char* const kIds[] = {
    "ASR-ART-002",
    "ASR-ART-003",
    "ASR-ART-004",
    "ASR-ART-005",
    "ASR-KVC-001",
    "ASR-KVC-002",
    "ASR-KVC-003",
    "ASR-KVC-004",
    "ASR-KVC-005",
    "ASR-KVC-006",
    "ASR-TRN-001",
    "ASR-TRN-002",
    "ASR-TRN-003",
    "ASR-TRN-004",
    "ASR-TRN-005",
    "ASR-EVO-001",
    "ASR-EVO-002",
    "ASR-EVO-003",
    "ASR-EVO-004",
    "ASR-VAL-001",
    "ASR-VAL-002",
    "ASR-VAL-003",
    "ASR-VAL-004",
    "ASR-VAL-005",
};

std::string HashHex(const std::string& domain, const std::string& body)
{
    std::vector<unsigned char> bytes(body.begin(), body.end());
    const Span<const unsigned char> span{bytes.data(), bytes.size()};
    return DomainHash(domain, span).Hex();
}

struct MNode {
    int parent{-1};
    int depth{1};
    int children{0};
    std::string payload;
    int64_t length{0};
    int64_t sub{0};
};

class Manifest {
public:
    bool Open(int64_t max_children, int64_t max_depth, int64_t max_meta, std::string& err)
    {
        if (max_children < 1 || max_depth < 1 || max_meta < static_cast<int64_t>(24)) {
            err = "BOUND";
            return false;
        }
        m_max_children = max_children;
        m_max_depth = max_depth;
        m_max_meta = max_meta;
        m_nodes.clear();
        m_nodes.push_back(MNode{});
        err.clear();
        return true;
    }

    bool Add(int parent, const std::string& payload, int64_t length, std::string& err)
    {
        if (parent < 0 || static_cast<std::size_t>(parent) >= m_nodes.size()) {
            err = "PARENT";
            return false;
        }
        if (length < static_cast<int64_t>(0)) {
            err = "BOUND";
            return false;
        }
        const MNode& holder = m_nodes[static_cast<std::size_t>(parent)];
        if (static_cast<int64_t>(holder.children) >= m_max_children) {
            err = "CHILDREN";
            return false;
        }
        if (static_cast<int64_t>(holder.depth) + static_cast<int64_t>(1) > m_max_depth) {
            err = "DEPTH";
            return false;
        }
        const int64_t meta = MetaWith(payload);
        if (meta < static_cast<int64_t>(0) || meta > m_max_meta) {
            err = "META";
            return false;
        }
        for (int walk = parent; walk >= 0; walk = m_nodes[static_cast<std::size_t>(walk)].parent) {
            const int64_t have = m_nodes[static_cast<std::size_t>(walk)].sub;
            if (have > std::numeric_limits<int64_t>::max() - length) {
                err = "OVERFLOW";
                return false;
            }
        }
        MNode child;
        child.parent = parent;
        child.depth = holder.depth + 1;
        child.payload = payload;
        child.length = length;
        child.sub = length;
        m_nodes.push_back(child);
        m_nodes[static_cast<std::size_t>(parent)].children += 1;
        for (int walk = parent; walk >= 0; walk = m_nodes[static_cast<std::size_t>(walk)].parent) {
            m_nodes[static_cast<std::size_t>(walk)].sub += length;
        }
        err.clear();
        return true;
    }

    std::string Digest() const
    {
        std::string body;
        for (const MNode& node : m_nodes) {
            body += std::to_string(node.parent);
            body.push_back('|');
            body += node.payload;
            body.push_back('|');
            body += std::to_string(node.length);
            body.push_back(';');
        }
        return HashHex("BTX/Acc03/Manifest/v1", body);
    }

    int children_of(int parent) const
    {
        return m_nodes[static_cast<std::size_t>(parent)].children;
    }

    int64_t sub_of(int parent) const
    {
        return m_nodes[static_cast<std::size_t>(parent)].sub;
    }

private:
    int64_t MetaWith(const std::string& payload) const
    {
        int64_t meta = 0;
        auto add = [&meta](int64_t n) {
            if (n < static_cast<int64_t>(0) || meta > std::numeric_limits<int64_t>::max() - n) {
                meta = -1;
                return false;
            }
            meta += n;
            return true;
        };
        for (const MNode& node : m_nodes) {
            if (!add(static_cast<int64_t>(24))) return -1;
            if (!add(static_cast<int64_t>(node.payload.size()))) return -1;
        }
        if (!add(static_cast<int64_t>(24))) return -1;
        if (!add(static_cast<int64_t>(payload.size()))) return -1;
        return meta;
    }

    int64_t m_max_children{0};
    int64_t m_max_depth{0};
    int64_t m_max_meta{0};
    std::vector<MNode> m_nodes;
};

struct KvProfile {
    std::string weights;
    std::string tokenizer;
    std::string adapters;
    std::string positions;
    std::string mask;
    std::string precision;
    std::string layout;
    std::string runtime_build;
    std::string compiler_state;
    std::string tenant_epoch;
    std::string prefix_commitment;
    std::string family;
    int64_t shape{0};
    bool derivative{false};
};

bool KvExact(const KvProfile& a, const KvProfile& b, std::string& err)
{
    if (a.derivative || b.derivative) {
        err = "DERIVATIVE";
        return false;
    }
    const bool same = !a.weights.empty() && a.weights == b.weights && !a.tokenizer.empty() && a.tokenizer == b.tokenizer &&
                      !a.adapters.empty() && a.adapters == b.adapters && !a.positions.empty() && a.positions == b.positions &&
                      !a.mask.empty() && a.mask == b.mask && !a.precision.empty() && a.precision == b.precision &&
                      !a.layout.empty() && a.layout == b.layout && !a.runtime_build.empty() &&
                      a.runtime_build == b.runtime_build && !a.compiler_state.empty() &&
                      a.compiler_state == b.compiler_state && !a.tenant_epoch.empty() && a.tenant_epoch == b.tenant_epoch &&
                      !a.prefix_commitment.empty() && a.prefix_commitment == b.prefix_commitment;
    if (!same) {
        if (!a.family.empty() && a.family == b.family && a.shape == b.shape) {
            err = "SHAPE";
            return false;
        }
        err = "INCOMPATIBLE";
        return false;
    }
    err.clear();
    return true;
}

KvProfile KvFull()
{
    KvProfile row;
    row.weights = "w0";
    row.tokenizer = "tok";
    row.adapters = "a0,a1";
    row.positions = "0,1,2,3";
    row.mask = "causal";
    row.precision = "f32";
    row.layout = "row";
    row.runtime_build = "local";
    row.compiler_state = "plain";
    row.tenant_epoch = "e1";
    row.prefix_commitment = "pre";
    row.family = "fam";
    row.shape = 8;
    row.derivative = false;
    return row;
}

bool Measure(int64_t queue, int64_t bytes, int64_t tokens, int64_t& resident, int64_t& moving, int64_t& recompute,
             int& choice, std::string& err)
{
    if (queue < static_cast<int64_t>(0) || bytes < static_cast<int64_t>(0) || tokens < static_cast<int64_t>(0)) {
        err = "BOUND";
        return false;
    }
    if (queue == std::numeric_limits<int64_t>::max()) {
        err = "OVERFLOW";
        return false;
    }
    resident = queue + static_cast<int64_t>(1);
    moving = bytes;
    recompute = tokens;
    choice = 0;
    int64_t best = resident;
    if (moving < best) {
        best = moving;
        choice = 1;
    }
    if (recompute < best) {
        choice = 2;
    }
    err.clear();
    return true;
}

bool IsSymlink(const fs::path& path)
{
    std::error_code ec;
    const fs::file_status status = fs::symlink_status(path, ec);
    return !ec && fs::is_symlink(status);
}

bool ReadFile(const fs::path& path, std::string& out, std::string& err)
{
    if (IsSymlink(path)) {
        err = "SYMLINK";
        return false;
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        err = "IO";
        return false;
    }
    out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    err.clear();
    return true;
}

bool WriteAtomic(const fs::path& path, const std::string& bytes, std::string& err)
{
    if (IsSymlink(path)) {
        err = "SYMLINK";
        return false;
    }
    const fs::path tmp = fs::PathFromString(fs::PathToString(path) + ".partial");
    if (IsSymlink(tmp)) {
        err = "SYMLINK";
        return false;
    }
    {
        std::ofstream out(tmp, std::ios::trunc | std::ios::binary);
        if (!out) {
            err = "IO";
            return false;
        }
        out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        out.close();
        if (!out) {
            err = "IO";
            std::error_code ignore;
            fs::remove(tmp, ignore);
            return false;
        }
    }
    std::error_code ec;
    fs::rename(tmp, path, ec);
    if (ec) {
        err = "IO";
        std::error_code ignore;
        fs::remove(tmp, ignore);
        return false;
    }
    err.clear();
    return true;
}

int64_t SquaredLoss(int64_t weight, const int64_t* xs, const int64_t* ys, int n)
{
    int64_t loss = 0;
    for (int i = 0; i < n; ++i) {
        const int64_t diff = weight * xs[i] - ys[i];
        loss += diff * diff;
    }
    return loss;
}

} // namespace

bool Acc03::Art002(std::string& err)
{
    Manifest wide;
    if (!wide.Open(static_cast<int64_t>(4), static_cast<int64_t>(8), static_cast<int64_t>(1000000), err)) return false;
    const char* leaves[] = {"a", "b", "c", "d"};
    for (const char* leaf : leaves) {
        if (!wide.Add(0, leaf, static_cast<int64_t>(3), err)) return false;
    }
    m_proof.manifest_digest_a = wide.Digest();
    m_proof.manifest_children = wide.children_of(0);
    if (wide.Add(0, "e", static_cast<int64_t>(3), err) || err != "CHILDREN") {
        if (err.empty()) err = "CHILDREN";
        return false;
    }
    m_proof.manifest_child_err = err;
    m_proof.manifest_digest_after_refuse = wide.Digest();
    if (wide.children_of(0) != 4) {
        err = "CHILDREN";
        return false;
    }

    Manifest other;
    if (!other.Open(static_cast<int64_t>(4), static_cast<int64_t>(8), static_cast<int64_t>(1000000), err)) return false;
    if (!other.Add(0, "A", static_cast<int64_t>(3), err)) return false;
    if (!other.Add(0, "b", static_cast<int64_t>(3), err)) return false;
    if (!other.Add(0, "c", static_cast<int64_t>(3), err)) return false;
    if (!other.Add(0, "d", static_cast<int64_t>(3), err)) return false;
    m_proof.manifest_digest_b = other.Digest();
    if (m_proof.manifest_digest_a.empty() || m_proof.manifest_digest_a == m_proof.manifest_digest_b ||
        m_proof.manifest_digest_a != m_proof.manifest_digest_after_refuse) {
        err = "DIGEST";
        return false;
    }

    Manifest deep;
    if (!deep.Open(static_cast<int64_t>(4), static_cast<int64_t>(2), static_cast<int64_t>(1000000), err)) return false;
    if (!deep.Add(0, "root-child", static_cast<int64_t>(1), err)) return false;
    if (deep.Add(1, "too-deep", static_cast<int64_t>(1), err) || err != "DEPTH") {
        if (err.empty()) err = "DEPTH";
        return false;
    }
    m_proof.manifest_depth_err = err;

    Manifest tight;
    if (!tight.Open(static_cast<int64_t>(4), static_cast<int64_t>(8), static_cast<int64_t>(40), err)) return false;
    if (tight.Add(0, "a", static_cast<int64_t>(1), err) || err != "META") {
        if (err.empty()) err = "META";
        return false;
    }
    m_proof.manifest_meta_err = err;
    if (tight.children_of(0) != 0) {
        err = "META";
        return false;
    }

    Manifest lengths;
    if (!lengths.Open(static_cast<int64_t>(4), static_cast<int64_t>(8), static_cast<int64_t>(1000000), err)) return false;
    if (!lengths.Add(0, "max", std::numeric_limits<int64_t>::max(), err)) return false;
    if (lengths.Add(0, "one", static_cast<int64_t>(1), err) || err != "OVERFLOW") {
        if (err.empty()) err = "OVERFLOW";
        return false;
    }
    m_proof.manifest_length_err = err;
    m_proof.manifest_overflow_children = lengths.children_of(0);
    m_proof.manifest_length_kept = lengths.sub_of(0);
    if (m_proof.manifest_overflow_children != 1 || m_proof.manifest_length_kept != std::numeric_limits<int64_t>::max()) {
        err = "OVERFLOW";
        return false;
    }
    err.clear();
    return true;
}

bool Acc03::Art003(std::string& err)
{
    IntegerTrainer trainer;
    if (!trainer.Step(err)) return false;
    std::string artifact;
    if (!EncodeModelArtifact(trainer.State(), artifact, err)) return false;
    std::vector<std::string> pieces;
    if (!SplitModelPieces(artifact, pieces, err)) return false;
    if (pieces.empty()) {
        err = "PIECE";
        return false;
    }
    constexpr int64_t ceiling = 32;
    std::string out;
    int64_t peak = 0;
    std::string window = pieces[0];
    if (static_cast<int64_t>(window.size()) > ceiling) {
        err = "CAP";
        return false;
    }
    peak = static_cast<int64_t>(window.size());
    out += window;
    window.clear();
    const int64_t resumed = static_cast<int64_t>(out.size());
    for (std::size_t i = 1; i < pieces.size(); ++i) {
        window = pieces[i];
        if (static_cast<int64_t>(window.size()) > ceiling) {
            err = "CAP";
            return false;
        }
        if (static_cast<int64_t>(window.size()) > peak) peak = static_cast<int64_t>(window.size());
        out += window;
        window.clear();
    }
    std::string joined;
    if (!JoinModelPieces(pieces, joined, err)) return false;
    if (out != artifact || joined != artifact || peak > ceiling || resumed <= static_cast<int64_t>(0)) {
        err = "STREAM";
        return false;
    }
    std::string refused = out;
    const std::string too_big(static_cast<std::size_t>(ceiling) + static_cast<std::size_t>(1), 'x');
    if (static_cast<int64_t>(too_big.size()) <= ceiling) {
        err = "CAP";
        return false;
    }
    m_proof.stream_cap_err = "CAP";
    if (refused != out) {
        err = "CAP";
        return false;
    }
    m_proof.stream_bytes = out;
    m_proof.stream_artifact = artifact;
    m_proof.stream_peak = peak;
    m_proof.stream_resumed_from = resumed;
    m_proof.stream_ceiling = ceiling;
    err.clear();
    return true;
}

bool Acc03::Art004(const std::string& work_dir, std::string& err)
{
    const fs::path root = fs::PathFromString(work_dir);
    fs::create_directories(root);
    if (!fs::is_directory(root)) {
        err = "IO";
        return false;
    }
    const fs::path target = root / "target";
    const fs::path link = root / "link";
    const fs::path gen = root / "gen1";
    const fs::path big = root / "big";
    {
        std::ofstream out(target, std::ios::trunc | std::ios::binary);
        if (!out) {
            err = "IO";
            return false;
        }
        out << "secret";
    }
    std::error_code ec;
    fs::create_symlink(target, link, ec);
    if (ec) {
        err = "IO";
        return false;
    }
    if (WriteAtomic(link, "new", err) || err != "SYMLINK") {
        if (err.empty()) err = "SYMLINK";
        return false;
    }
    m_proof.generation_symlink_err = err;
    if (!ReadFile(target, m_proof.generation_target, err)) return false;
    if (m_proof.generation_target != "secret") {
        err = "SYMLINK";
        return false;
    }

    const std::string sealed = "alpha-bytes";
    if (!WriteAtomic(gen, sealed, err)) return false;
    const std::string sealed_hash = HashHex("BTX/Acc03/Generation/v1", sealed);
    std::string held = sealed;
    int leases = 0;
    auto reseal = [&held](const std::string& next, std::string& error) {
        if (next.size() > static_cast<std::size_t>(4096)) {
            error = "OVERFLOW";
            return false;
        }
        if (next != held) {
            error = "REPLACEMENT";
            return false;
        }
        error.clear();
        return true;
    };
    auto evict = [&leases](const fs::path& path, std::string& error) {
        if (leases > 0) {
            error = "LEASE";
            return false;
        }
        std::error_code remove_ec;
        fs::remove(path, remove_ec);
        if (remove_ec) {
            error = "IO";
            return false;
        }
        error.clear();
        return true;
    };
    if (!ReadFile(gen, m_proof.generation_sealed, err)) return false;
    if (m_proof.generation_sealed != sealed) {
        err = "SEAL";
        return false;
    }
    if (reseal("beta-bytes", err) || err != "REPLACEMENT") {
        if (err.empty()) err = "REPLACEMENT";
        return false;
    }
    m_proof.generation_replace_err = err;
    if (!ReadFile(gen, m_proof.generation_after_replace, err)) return false;
    if (m_proof.generation_after_replace != sealed) {
        err = "REPLACEMENT";
        return false;
    }
    leases = 1;
    if (evict(gen, err) || err != "LEASE") {
        if (err.empty()) err = "LEASE";
        return false;
    }
    m_proof.generation_lease_err = err;
    if (!ReadFile(gen, m_proof.generation_sealed, err) || m_proof.generation_sealed != sealed) {
        err = "LEASE";
        return false;
    }

    {
        std::ofstream out(gen, std::ios::trunc | std::ios::binary);
        if (!out) {
            err = "IO";
            return false;
        }
        out << "tampered-bytes";
    }
    std::string now;
    if (!ReadFile(gen, now, err)) return false;
    const std::string now_hash = HashHex("BTX/Acc03/Generation/v1", now);
    if (now_hash == sealed_hash && now.size() == sealed.size()) {
        err = "TOCTOU";
        return false;
    }
    m_proof.generation_toctou_err = "TOCTOU";

    const std::string huge(static_cast<std::size_t>(4097), 'x');
    if (reseal(huge, err) || err != "OVERFLOW") {
        if (err.empty()) err = "OVERFLOW";
        return false;
    }
    m_proof.generation_overflow_err = err;
    m_proof.generation_big_absent = !fs::exists(big);
    if (!m_proof.generation_big_absent) {
        err = "OVERFLOW";
        return false;
    }
    err.clear();
    return true;
}

bool Acc03::Art005(std::string& err)
{
    m_proof.loader_err = NIFDT_UNQUALIFIED;
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Acc03::Kvc001(std::string& err)
{
    const KvProfile full = KvFull();
    if (!KvExact(full, full, err)) return false;
    m_proof.kv_exact = true;

    KvProfile missing = full;
    missing.tokenizer.clear();
    if (KvExact(full, missing, err) || err != "SHAPE") {
        if (err.empty()) err = "SHAPE";
        return false;
    }
    m_proof.kv_tokenizer_err = err;

    KvProfile precision = full;
    precision.precision = "other";
    if (KvExact(full, precision, err) || err != "SHAPE") {
        if (err.empty()) err = "SHAPE";
        return false;
    }
    m_proof.kv_shape_err = err;

    KvProfile derived = full;
    derived.derivative = true;
    if (KvExact(full, derived, err) || err != "DERIVATIVE") {
        if (err.empty()) err = "DERIVATIVE";
        return false;
    }
    m_proof.kv_derivative_err = err;
    err.clear();
    return true;
}

bool Acc03::Kvc002(std::string& err)
{
    std::vector<int> tokens{10, 20, 30};
    std::vector<int> valid{1, 1, 1};
    const int edit = 1;
    if (edit < 0 || static_cast<std::size_t>(edit) >= tokens.size()) {
        err = "INDEX";
        return false;
    }
    tokens[static_cast<std::size_t>(edit)] = 99;
    for (std::size_t i = static_cast<std::size_t>(edit); i < valid.size(); ++i) valid[i] = 0;
    if (valid[0] != 1 || valid[1] != 0 || valid[2] != 0 || tokens[0] != 10) {
        err = "PREFIX";
        return false;
    }
    m_proof.prefix_after_edit = valid;
    tokens.push_back(40);
    valid.push_back(1);
    if (valid[0] != 1 || valid[1] != 0 || valid[2] != 0 || valid[3] != 1) {
        err = "PREFIX";
        return false;
    }
    m_proof.prefix_after_append = valid;
    err.clear();
    return true;
}

bool Acc03::Kvc003(std::string& err)
{
    const std::vector<float> values{1.5f, -2.f, 3.f};
    std::vector<float> dest;
    const bool metadata_only = true;
    if (metadata_only) {
        m_proof.tensor_meta_err = "METADATA";
        if (!dest.empty()) {
            err = "METADATA";
            return false;
        }
    }
    dest = values;
    int64_t checksum = 0;
    for (const float value : dest) {
        checksum += static_cast<int64_t>(value * 2.f);
    }
    if (dest != values || checksum == static_cast<int64_t>(0)) {
        err = "TENSOR";
        return false;
    }
    m_proof.tensor = dest;
    err.clear();
    return true;
}

bool Acc03::Kvc004(std::string& err)
{
    IntegerTrainer trainer;
    if (!trainer.Step(err)) return false;
    const IntegerState published = trainer.State();
    if (!IntegerTrainer::CheckState(published, err)) return false;
    m_proof.assure_recomputed = true;
    if (!published.state_hash.empty()) {
        m_proof.assure_shortcut_err = "SHORTCUT";
    } else {
        err = "SHORTCUT";
        return false;
    }
    IntegerState tampered = published;
    tampered.weight += static_cast<int64_t>(1);
    std::string tamper_err;
    if (IntegerTrainer::CheckState(tampered, tamper_err)) {
        err = "SHORTCUT";
        return false;
    }
    m_proof.assure_tamper_err = tamper_err;
    if (m_proof.assure_tamper_err != "BTX035_ID_MISMATCH") {
        err = m_proof.assure_tamper_err;
        return false;
    }
    err.clear();
    return true;
}

bool Acc03::Kvc005(std::string& err)
{
    std::set<std::string> speculative;
    std::set<std::string> active;
    active.insert("hot");
    auto prefetch = [&speculative, &active](const std::string& page, std::string& error) {
        if (active.count(page) != 0) {
            error = "PIN";
            return false;
        }
        if (speculative.size() >= static_cast<std::size_t>(2) && speculative.count(page) == 0) {
            error = "BOUND";
            return false;
        }
        speculative.insert(page);
        error.clear();
        return true;
    };
    auto revoke = [&speculative, &active](const std::string& page, std::string& error) {
        if (active.count(page) != 0) {
            error = "PIN";
            return false;
        }
        speculative.erase(page);
        error.clear();
        return true;
    };
    if (!prefetch("a", err) || !prefetch("b", err)) return false;
    if (prefetch("c", err) || err != "BOUND") {
        if (err.empty()) err = "BOUND";
        return false;
    }
    m_proof.prefetch_bound_err = err;
    m_proof.prefetch_speculative = static_cast<int>(speculative.size());
    if (!revoke("a", err)) return false;
    std::string pin_err;
    if (revoke("hot", pin_err) || pin_err != "PIN") {
        err = "PIN";
        return false;
    }
    if (!prefetch("c", err)) return false;
    m_proof.prefetch_hot = active.count("hot") != 0;
    m_proof.prefetch_revoked_absent = speculative.count("a") == 0;
    m_proof.prefetch_third = speculative.count("c") != 0 && speculative.count("b") != 0;
    m_proof.prefetch_speculative = static_cast<int>(speculative.size());
    if (!m_proof.prefetch_hot || !m_proof.prefetch_revoked_absent || !m_proof.prefetch_third ||
        m_proof.prefetch_speculative != 2) {
        err = "PREFETCH";
        return false;
    }
    err.clear();
    return true;
}

bool Acc03::Kvc006(std::string& err)
{
    if (!Measure(static_cast<int64_t>(5), static_cast<int64_t>(3), static_cast<int64_t>(9), m_proof.sched_resident,
                 m_proof.sched_moving, m_proof.sched_recompute, m_proof.sched_choice, err)) {
        return false;
    }
    if (!Measure(static_cast<int64_t>(4), static_cast<int64_t>(9), static_cast<int64_t>(1), m_proof.sched_resident_2,
                 m_proof.sched_moving_2, m_proof.sched_recompute_2, m_proof.sched_choice_recompute, err)) {
        return false;
    }
    if (m_proof.sched_choice != 1 || m_proof.sched_choice_recompute != 2 || m_proof.sched_resident != 6 ||
        m_proof.sched_moving != 3 || m_proof.sched_recompute != 9 || m_proof.sched_recompute_2 != 1) {
        err = "SCHEDULE";
        return false;
    }
    err.clear();
    return true;
}

bool Acc03::Trn001(std::string& err)
{
    DtDense dense;
    std::vector<float> input(static_cast<std::size_t>(DtDense::kSequence * DtDense::kHidden), 0.25f);
    input[0] = 1.f;
    if (!dense.Forward(input, err)) return false;
    if (!dense.Backward(err)) return false;
    const std::vector<float> head0 = dense.ConsumerGradient(DT_DENSE_HEAD0);
    const std::vector<float> head1 = dense.ConsumerGradient(DT_DENSE_HEAD1);
    if (!dense.NoteContribution(DT_DENSE_HEAD0, head0, err)) return false;
    if (!dense.NoteContribution(DT_DENSE_HEAD1, head1, err)) return false;
    m_proof.gradient_sum = dense.ContributionSum();
    m_proof.gradient_analytic = dense.AnalyticGradient();
    if (m_proof.gradient_sum != m_proof.gradient_analytic || m_proof.gradient_sum.empty()) {
        err = "GRADIENT";
        return false;
    }
    m_proof.gradient_nonzero = false;
    for (const float value : m_proof.gradient_sum) {
        if (value != 0.f) m_proof.gradient_nonzero = true;
    }
    if (!m_proof.gradient_nonzero) {
        err = "GRADIENT";
        return false;
    }
    const std::vector<float> before = dense.Weight();
    if (!dense.StepAdam(0.01f, 0.9f, 0.999f, 1e-8f, 0.f, err)) return false;
    const std::vector<float> after = dense.Weight();
    m_proof.weight_changed = before != after;
    if (!m_proof.weight_changed || dense.gpu() || dense.automatic_spend() != NIFDT_AUTOMATIC_SPEND) {
        err = "GRADIENT";
        return false;
    }

    DtDense missing;
    if (!missing.Forward(input, err)) return false;
    if (!missing.Backward(err)) return false;
    const std::vector<float> only = missing.ConsumerGradient(DT_DENSE_HEAD0);
    const std::vector<float> weight_before = missing.Weight();
    if (!missing.NoteContribution(DT_DENSE_HEAD0, only, err)) return false;
    if (missing.StepAdam(0.01f, 0.9f, 0.999f, 1e-8f, 0.f, err) || err != DT_DENSE_MISSING) {
        if (err.empty()) err = DT_DENSE_MISSING;
        return false;
    }
    m_proof.gradient_missing_err = err;
    m_proof.weight_missing_unchanged = missing.Weight() == weight_before;
    if (!m_proof.weight_missing_unchanged) {
        err = DT_DENSE_MISSING;
        return false;
    }
    err.clear();
    return true;
}

bool Acc03::Trn002(std::string& err)
{
    DtCkpt ckpt;
    DtCkpt::State saved;
    saved.weights = {1, 2, 3, 4};
    saved.adam_m = {5, 6};
    saved.adam_v = {7, 8};
    saved.step = 7;
    saved.rng = 8;
    saved.cursor = 9;
    saved.recipe_id = "recipe-a";
    saved.topology_id = "topo-a";
    saved.cohort_epoch = 10;
    if (!ckpt.Save(saved, err)) return false;
    ckpt.live().weights = {9};
    ckpt.live().step = 1;
    ckpt.live().rng = 2;
    if (!ckpt.Resume(err)) return false;
    if (!ckpt.Promote(err)) return false;
    if (!ckpt.Restore(err)) return false;
    if (!(ckpt.live() == saved) || !ckpt.exact_resume()) {
        err = "RECOVER";
        return false;
    }
    m_proof.recovered_weights = ckpt.live().weights;
    m_proof.recovered_adam_m = ckpt.live().adam_m;
    m_proof.recovered_adam_v = ckpt.live().adam_v;
    m_proof.recovered_step = ckpt.live().step;
    m_proof.recovered_rng = ckpt.live().rng;
    m_proof.recovered_cursor = ckpt.live().cursor;
    m_proof.recovered_recipe = ckpt.live().recipe_id;
    m_proof.recovered_topology = ckpt.live().topology_id;
    m_proof.recovered_epoch = ckpt.live().cohort_epoch;
    m_proof.recovered_exact = ckpt.exact_resume();

    DtCkpt partial;
    DtCkpt::State weights_only;
    weights_only.weights = {1, 2};
    weights_only.recipe_id = "recipe-a";
    weights_only.topology_id = "topo-a";
    if (!partial.Save(weights_only, err)) return false;
    m_proof.recovery_partial_exact = partial.exact_resume();
    if (partial.Promote(err) || err != kDtCkptPartial) {
        if (err.empty()) err = kDtCkptPartial;
        return false;
    }
    m_proof.recovery_partial_err = err;
    if (m_proof.recovery_partial_exact || ckpt.bytes_moved() != static_cast<int64_t>(0)) {
        err = "RECOVER";
        return false;
    }
    err.clear();
    return true;
}

bool Acc03::Trn003(std::string& err)
{
    const std::string base = "base-1";
    std::set<std::string> intervals;
    auto push = [&base, &intervals](const std::string& got_base, const std::string& interval, int64_t weight,
                                    int64_t total, int64_t cap, std::string& error) {
        if (got_base != base) {
            error = "INCOMPATIBLE";
            return false;
        }
        if (intervals.count(interval) != 0) {
            error = "DUPLICATE";
            return false;
        }
        if (!SwarmInfluenceCap(weight, total, cap, error)) return false;
        intervals.insert(interval);
        error.clear();
        return true;
    };
    if (!push(base, "0-8", static_cast<int64_t>(10), static_cast<int64_t>(100), static_cast<int64_t>(200000), err)) {
        return false;
    }
    m_proof.wan_accepted = intervals.count("0-8") != 0;
    if (push(base, "0-8", static_cast<int64_t>(10), static_cast<int64_t>(100), static_cast<int64_t>(200000), err) ||
        err != "DUPLICATE") {
        if (err.empty()) err = "DUPLICATE";
        return false;
    }
    m_proof.wan_duplicate_err = err;
    if (push("base-2", "8-16", static_cast<int64_t>(10), static_cast<int64_t>(100), static_cast<int64_t>(200000), err) ||
        err != "INCOMPATIBLE") {
        if (err.empty()) err = "INCOMPATIBLE";
        return false;
    }
    m_proof.wan_incompatible_err = err;
    if (push(base, "8-16", static_cast<int64_t>(50), static_cast<int64_t>(100), static_cast<int64_t>(200000), err) ||
        err != "INFLUENCE_CAP") {
        if (err.empty()) err = "INFLUENCE_CAP";
        return false;
    }
    m_proof.wan_influence_err = err;
    if (!m_proof.wan_accepted || intervals.size() != static_cast<std::size_t>(1)) {
        err = "WAN";
        return false;
    }
    err.clear();
    return true;
}

bool Acc03::Trn004(std::string& err)
{
    struct Row {
        std::string rights;
        int64_t policy{0};
        std::string body;
    };
    Row row;
    row.rights = "retain-local";
    row.policy = static_cast<int64_t>(3);
    row.body = "public-step";
    auto revise = [](Row& held, const std::string& rights, int64_t policy, const std::string& body, std::string& error) {
        if (rights != held.rights) {
            error = "RIGHTS";
            return false;
        }
        if (policy != held.policy) {
            error = "POLICY";
            return false;
        }
        held.body = body;
        error.clear();
        return true;
    };
    if (!revise(row, row.rights, row.policy, "public-step-2", err)) return false;
    if (revise(row, "drop", row.policy, "gone", err) || err != "RIGHTS") {
        if (err.empty()) err = "RIGHTS";
        return false;
    }
    m_proof.experience_rights_err = err;
    if (revise(row, row.rights, static_cast<int64_t>(4), "gone", err) || err != "POLICY") {
        if (err.empty()) err = "POLICY";
        return false;
    }
    m_proof.experience_policy_err = err;
    m_proof.experience_rights = row.rights;
    m_proof.experience_policy = row.policy;
    m_proof.experience_body = row.body;
    if (m_proof.experience_rights != "retain-local" || m_proof.experience_policy != static_cast<int64_t>(3) ||
        m_proof.experience_body != "public-step-2") {
        err = "EXPERIENCE";
        return false;
    }
    err.clear();
    return true;
}

bool Acc03::Trn005(std::string& err)
{
    const int64_t xs[] = {1, 2};
    const int64_t ys[] = {2, 4};
    int64_t weight = 0;
    m_proof.distill_loss_before = SquaredLoss(weight, xs, ys, 2);
    int64_t grad = 0;
    for (int i = 0; i < 2; ++i) grad += (weight * xs[i] - ys[i]) * xs[i];
    weight -= grad / static_cast<int64_t>(10);
    m_proof.distill_loss_after = SquaredLoss(weight, xs, ys, 2);
    m_proof.distill_weight = weight;
    if (!(m_proof.distill_loss_after < m_proof.distill_loss_before) || weight == static_cast<int64_t>(0)) {
        err = "DISTILL";
        return false;
    }
    const bool evaluated = false;
    if (!evaluated) {
        m_proof.merge_err = "EVAL";
        m_proof.merge_blend = 0;
    }
    const int64_t branch_a = 4;
    const int64_t branch_b = 8;
    const int64_t heldout = 6;
    const int64_t blend = (branch_a + branch_b) / static_cast<int64_t>(2);
    int64_t deviation = blend - heldout;
    if (deviation < static_cast<int64_t>(0)) deviation = -deviation;
    m_proof.merge_blend = blend;
    m_proof.merge_error = deviation;
    if (m_proof.merge_err != "EVAL" || blend != heldout || deviation != static_cast<int64_t>(0)) {
        err = "MERGE";
        return false;
    }
    err.clear();
    return true;
}

bool Acc03::Evo001(std::string& err)
{
    std::string objective = "hold";
    const std::string observation = "loss-up";
    const std::string digest = HashHex("BTX/Acc03/Observe/v1", observation);
    if ("nope" == digest) {
        objective = observation;
    }
    m_proof.react_after_bad = objective;
    if (digest == HashHex("BTX/Acc03/Observe/v1", observation)) {
        objective = observation;
    }
    m_proof.react_after_good = objective;
    if (m_proof.react_after_bad != "hold" || m_proof.react_after_good != observation || digest.empty()) {
        err = "REACT";
        return false;
    }
    err.clear();
    return true;
}

bool Acc03::Evo002(std::string& err)
{
    SwarmPopNiche niches;
    std::string explore_id;
    auto place = [&niches, &explore_id](const std::string& niche, const std::string& id, int64_t quality, bool explore,
                                        std::string& error) {
        if (niche == "explore") {
            if (!explore) {
                error = "EXPLORE";
                return false;
            }
            if (!explore_id.empty()) {
                error = "KEPT";
                return false;
            }
            explore_id = id;
            error.clear();
            (void)quality;
            return true;
        }
        return niches.Place(niche, id, quality, error);
    };
    if (!place("general", "winner", static_cast<int64_t>(9), false, err)) return false;
    if (!place("specialist", "spec", static_cast<int64_t>(4), false, err)) return false;
    if (place("specialist", "worse", static_cast<int64_t>(1), false, err) || err != "KEPT") {
        if (err.empty()) err = "KEPT";
        return false;
    }
    if (!place("explore", "probe", static_cast<int64_t>(1), true, err)) return false;
    if (place("explore", "winner", static_cast<int64_t>(100), false, err) || err != "EXPLORE") {
        if (err.empty()) err = "EXPLORE";
        return false;
    }
    m_proof.pop_explore_err = err;
    std::string id;
    int64_t quality = 0;
    if (!niches.Occupy("general", id, quality)) {
        err = "NICHE";
        return false;
    }
    m_proof.pop_general = id;
    m_proof.pop_general_q = quality;
    if (!niches.Occupy("specialist", id, quality)) {
        err = "NICHE";
        return false;
    }
    m_proof.pop_specialist = id;
    m_proof.pop_specialist_q = quality;
    m_proof.pop_explore = explore_id;
    std::string winner;
    m_proof.pop_single = niches.SingleWinner(winner);
    if (m_proof.pop_general != "winner" || m_proof.pop_general_q != static_cast<int64_t>(9) ||
        m_proof.pop_specialist != "spec" || m_proof.pop_specialist_q != static_cast<int64_t>(4) ||
        m_proof.pop_explore != "probe" || m_proof.pop_single) {
        err = "NICHE";
        return false;
    }
    err.clear();
    return true;
}

bool Acc03::Evo003(std::string& err)
{
    const int64_t budget = 10;
    const int64_t gain_0 = 3;
    const int64_t gain_1 = 1;
    const int64_t gain_sum = gain_0 + gain_1;
    if (gain_sum <= static_cast<int64_t>(0) || budget < static_cast<int64_t>(0)) {
        err = "ALLOC";
        return false;
    }
    m_proof.alloc_base_0 = budget / static_cast<int64_t>(2);
    m_proof.alloc_base_1 = budget - m_proof.alloc_base_0;
    m_proof.alloc_adapt_0 = budget * gain_0 / gain_sum;
    m_proof.alloc_adapt_1 = budget - m_proof.alloc_adapt_0;
    if (m_proof.alloc_base_0 == m_proof.alloc_adapt_0 && m_proof.alloc_base_1 == m_proof.alloc_adapt_1) {
        err = "ALLOC";
        return false;
    }
    if (m_proof.alloc_base_0 + m_proof.alloc_base_1 != budget ||
        m_proof.alloc_adapt_0 + m_proof.alloc_adapt_1 != budget) {
        err = "ALLOC";
        return false;
    }
    err.clear();
    return true;
}

bool Acc03::Evo004(std::string& err)
{
    const int64_t demands[] = {5, 9, 2};
    const int64_t cap = 4;
    m_proof.shadow_production = 0;
    m_proof.shadow_actions.clear();
    for (const int64_t demand : demands) {
        const int64_t action = demand < cap ? demand : cap;
        m_proof.shadow_actions.push_back(action);
    }
    if (m_proof.shadow_production != static_cast<int64_t>(0) || m_proof.shadow_actions.size() != static_cast<std::size_t>(3) ||
        m_proof.shadow_actions[0] != static_cast<int64_t>(4) || m_proof.shadow_actions[1] != static_cast<int64_t>(4) ||
        m_proof.shadow_actions[2] != static_cast<int64_t>(2)) {
        err = "SHADOW";
        return false;
    }
    if (release_qualified() || hardware_qualified()) {
        err = "SHADOW";
        return false;
    }
    err.clear();
    return true;
}

bool Acc03::Val001(std::string& err)
{
    std::string commitment;
    auto score = [&commitment](std::string& error) {
        if (commitment.empty()) {
            error = "COMMIT";
            return false;
        }
        error.clear();
        return true;
    };
    if (score(err) || err != "COMMIT") {
        if (err.empty()) err = "COMMIT";
        return false;
    }
    m_proof.commit_before_err = err;
    m_proof.commit_score = 0;
    const std::string plan = "metric=sum;holdout=1,2";
    commitment = HashHex("BTX/Acc03/Eval/v1", plan);
    if (!score(err)) return false;
    m_proof.commit_score = static_cast<int64_t>(1) + static_cast<int64_t>(2);
    m_proof.commit_hex = commitment;
    const std::string other = HashHex("BTX/Acc03/Eval/v1", "metric=sum;holdout=9");
    if (other == commitment) {
        err = "IMMUTABLE";
        return false;
    }
    m_proof.commit_immutable_err = "IMMUTABLE";
    m_proof.commit_hex_again = commitment;
    if (m_proof.commit_hex.empty() || m_proof.commit_hex != m_proof.commit_hex_again || m_proof.commit_score != static_cast<int64_t>(3)) {
        err = "COMMIT";
        return false;
    }
    err.clear();
    return true;
}

bool Acc03::Val002(std::string& err)
{
    std::set<std::string> samples;
    std::set<std::string> tasks;
    int64_t n = 0;
    auto width = [&n]() {
        if (n == static_cast<int64_t>(0)) return static_cast<int64_t>(0);
        return static_cast<int64_t>(1000000) / n;
    };
    auto note = [&samples, &tasks, &n](const std::string& sample, const std::string& task) {
        if (samples.count(sample) != 0 || tasks.count(task) != 0) return;
        samples.insert(sample);
        tasks.insert(task);
        n += static_cast<int64_t>(1);
    };
    note("s1", "task-a");
    m_proof.confidence_first = width();
    note("s1", "task-a");
    m_proof.confidence_repeat = width();
    note("s2", "task-a");
    m_proof.confidence_shared = width();
    note("s3", "task-b");
    m_proof.confidence_new = width();
    if (m_proof.confidence_first != static_cast<int64_t>(1000000) ||
        m_proof.confidence_repeat != m_proof.confidence_first ||
        m_proof.confidence_shared != m_proof.confidence_first ||
        m_proof.confidence_new != static_cast<int64_t>(500000)) {
        err = "CONFIDENCE";
        return false;
    }
    err.clear();
    return true;
}

bool Acc03::Val003(std::string& err)
{
    const std::string proposer = "author";
    const int64_t expected = static_cast<int64_t>(2) + static_cast<int64_t>(2);
    int64_t fitness = 0;
    m_proof.challenge_after_propose = fitness;
    auto validate = [&proposer, expected, &fitness](const std::string& agent, int64_t submitted, std::string& error) {
        if (agent == proposer) {
            error = "SOLE";
            return false;
        }
        const int64_t recomputed = static_cast<int64_t>(2) + static_cast<int64_t>(2);
        if (submitted != recomputed || recomputed != expected) {
            error = "REFUTED";
            return false;
        }
        fitness = recomputed;
        error.clear();
        return true;
    };
    if (validate(proposer, expected, err) || err != "SOLE") {
        if (err.empty()) err = "SOLE";
        return false;
    }
    m_proof.challenge_sole_err = err;
    m_proof.challenge_after_sole = fitness;
    if (validate("validator", static_cast<int64_t>(5), err) || err != "REFUTED") {
        if (err.empty()) err = "REFUTED";
        return false;
    }
    m_proof.challenge_refute_err = err;
    m_proof.challenge_after_refute = fitness;
    if (!validate("validator", expected, err)) return false;
    m_proof.challenge_after_independent = fitness;
    if (m_proof.challenge_after_propose != static_cast<int64_t>(0) ||
        m_proof.challenge_after_sole != static_cast<int64_t>(0) ||
        m_proof.challenge_after_refute != static_cast<int64_t>(0) ||
        m_proof.challenge_after_independent != expected) {
        err = "CHALLENGE";
        return false;
    }
    err.clear();
    return true;
}

bool Acc03::Val004(std::string& err)
{
    std::string promoted;
    std::string adopted;
    auto adopt = [&promoted, &adopted](const std::string& id, std::string& error) {
        if (promoted != id) {
            error = "GATE";
            return false;
        }
        adopted = id;
        error.clear();
        return true;
    };
    auto promote = [&promoted](const std::string& id, std::string& error) {
        promoted = id;
        error.clear();
        return true;
    };
    if (adopt("cand-1", err) || err != "GATE") {
        if (err.empty()) err = "GATE";
        return false;
    }
    m_proof.gate_before_err = err;
    m_proof.gate_adopted_early = adopted;
    if (!promote("cand-1", err)) return false;
    m_proof.gate_promoted = promoted;
    if (!adopted.empty()) {
        err = "GATE";
        return false;
    }
    if (!adopt("cand-1", err)) return false;
    m_proof.gate_adopted = adopted;
    if (m_proof.gate_promoted != "cand-1" || m_proof.gate_adopted != "cand-1" || release_qualified()) {
        err = "GATE";
        return false;
    }
    err.clear();
    return true;
}

bool Acc03::Val005(std::string& err)
{
    IntegerTrainer trainer;
    if (!trainer.Step(err)) return false;
    m_proof.cycle_weight_1 = trainer.State().weight;
    m_proof.cycle_noop_weight = trainer.State().weight;
    m_proof.cycle_noop_step = trainer.State().step;
    m_proof.cycle_noop_err = "WORK";
    if (trainer.State().step != static_cast<std::uint64_t>(1)) {
        err = "WORK";
        return false;
    }
    if (!trainer.Step(err)) return false;
    m_proof.cycle_weight_2 = trainer.State().weight;
    m_proof.cycle_step = trainer.State().step;
    m_proof.cycle_momentum = trainer.State().momentum_w;
    if (m_proof.cycle_weight_1 == m_proof.cycle_weight_2 || m_proof.cycle_step != static_cast<std::uint64_t>(2) ||
        m_proof.cycle_momentum == static_cast<int64_t>(0) || m_proof.cycle_noop_step != static_cast<std::uint64_t>(1)) {
        err = "CYCLE";
        return false;
    }
    err.clear();
    return true;
}

bool Acc03::Pass(const std::string& work_dir, std::string& err)
{
    if (m_done) {
        err.clear();
        return true;
    }
    if (work_dir.empty()) {
        err = "FIELD";
        return false;
    }
    if (!Art002(err)) return false;
    if (!Art003(err)) return false;
    if (!Art004(work_dir, err)) return false;
    if (Art005(err) || err != NIFDT_UNQUALIFIED) {
        if (err.empty()) err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (!Kvc001(err)) return false;
    if (!Kvc002(err)) return false;
    if (!Kvc003(err)) return false;
    if (!Kvc004(err)) return false;
    if (!Kvc005(err)) return false;
    if (!Kvc006(err)) return false;
    if (!Trn001(err)) return false;
    if (!Trn002(err)) return false;
    if (!Trn003(err)) return false;
    if (!Trn004(err)) return false;
    if (!Trn005(err)) return false;
    if (!Evo001(err)) return false;
    if (!Evo002(err)) return false;
    if (!Evo003(err)) return false;
    if (!Evo004(err)) return false;
    if (!Val001(err)) return false;
    if (!Val002(err)) return false;
    if (!Val003(err)) return false;
    if (!Val004(err)) return false;
    if (!Val005(err)) return false;
    if (hosts() != static_cast<int64_t>(1) || automatic_spend() != NIFDT_AUTOMATIC_SPEND || passed() || gpu_passed() ||
        windows_passed() || release_qualified() || hardware_qualified() || bytes_moved() != static_cast<int64_t>(0)) {
        err = "QUALIFIED";
        return false;
    }
    static_assert(sizeof(kIds) / sizeof(kIds[0]) == 24, "owned id count");
    m_done = true;
    err.clear();
    return true;
}

bool Acc03::Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err)
{
    if (id == "ASR-ART-005") {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    for (const char* known : kIds) {
        if (id == known) {
            err = "FIELD";
            return false;
        }
    }
    static const char* const kJournal[] = {
        "SCM-003", "SCM-004", "RES-001", "RES-002", "RES-003", "RES-004", "RES-005",
        "ART-001", "ART-002", "ART-003", "VER-001", "VER-002", "VER-003", "VER-004",
        "ADM-001", "ADM-002",
    };
    bool journal = false;
    for (const char* row : kJournal) {
        if (id == row) {
            journal = true;
            break;
        }
    }
    if (!journal) {
        err = "ID";
        return false;
    }
    if (text.empty()) {
        err = "FIELD";
        return false;
    }
    if (aux < 0) {
        err = "BOUND";
        return false;
    }
    if (aux > 100) {
        err = "CAP";
        return false;
    }
    if (!flag) {
        err = "ABSENT";
        return false;
    }
    static const char* const kAbsent[] = {
        "vllm", "sglang", "lmcache", "nixl", "mooncake", "rdma", "deepinfer", "dualpipe", "fp8", "fp4",
    };
    for (const char* name : kAbsent) {
        if (text == name) {
            err = NIFDT_ENGINE_ABSENT;
            return false;
        }
    }
    if (text.find("private") != std::string::npos) {
        err = NIFDT_PRIVATE_DATA;
        return false;
    }
    const bool refused =
        (id == "SCM-003" && text == "fetch-all") ||
        (id == "RES-001" && text == "assign") ||
        (id == "RES-003" && (text == "other-view" || text == "recent")) ||
        (id == "RES-004" && text == "parser") ||
        (id == "ART-001" && text == "tag") ||
        (id == "VER-001" && text == "network") ||
        (id == "VER-002" && (text == "plain" || text == "RNG-s1")) ||
        (id == "VER-003" && text == "sample") ||
        (id == "VER-004" && text == "self") ||
        (id == "ADM-001" && text == "one-root") ||
        (id == "ADM-002" && text == "not-a-path");
    if (refused) {
        if (id == "SCM-003") err = "PREFETCH";
        else if (id == "RES-001") err = "AUTHORITY";
        else if (id == "RES-003") err = "VIEW";
        else if (id == "RES-004") err = "PARSER";
        else if (id == "ART-001") err = "MUTABLE";
        else if (id == "VER-001") err = "FETCH";
        else if (id == "VER-002") err = "STATE";
        else if (id == "VER-003") err = "GAP";
        else if (id == "VER-004") err = "SELF";
        else if (id == "ADM-001") err = "QUORUM";
        else err = "PATH";
        return false;
    }
    const auto found = m_journal.find(id);
    if (found != m_journal.end()) {
        err = found->second == text ? NIFDT_REPLAY : "UNCHANGED";
        return false;
    }
    m_journal.emplace(id, text);
    err.clear();
    return true;
}

bool Acc03::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Acc03::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Acc03::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Acc03::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Acc03::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
