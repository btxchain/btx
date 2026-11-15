// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_verify.h>

#include <fstream>
#include <system_error>

namespace modelnet {
namespace {

bool WriteAtomic(const fs::path& final_path, const std::string& body, std::string& err)
{
    const fs::path tmp = fs::u8path(final_path.utf8string() + ".tmp");
    {
        std::ofstream file(tmp, std::ios::trunc);
        if (!file) {
            err = "WRITE";
            return false;
        }
        file << body;
        if (!file) {
            err = "WRITE";
            return false;
        }
    }
    std::error_code ec;
    fs::rename(tmp, final_path, ec);
    if (ec) {
        err = "RENAME";
        return false;
    }
    err.clear();
    return true;
}

} // namespace

const char* SwarmVerifyStateName(SwarmVerifyState state)
{
    switch (state) {
    case SwarmVerifyState::Discovered: return "DISCOVERED";
    case SwarmVerifyState::Fetching: return "FETCHING";
    case SwarmVerifyState::Incomplete: return "INCOMPLETE";
    case SwarmVerifyState::Verified: return "VERIFIED";
    case SwarmVerifyState::Admitted: return "ADMITTED";
    }
    return "INCOMPLETE";
}

bool SwarmVerifyBook::Discover(const std::string& root, int64_t total_length, const std::vector<std::string>& digests,
                               const std::vector<int64_t>& lengths, std::string& err)
{
    if (root.empty() || digests.empty() || digests.size() != lengths.size() || total_length <= 0) {
        err = "MANIFEST";
        return false;
    }
    int64_t sum = 0;
    for (int64_t length : lengths) {
        if (length <= 0) {
            err = "LENGTH";
            return false;
        }
        sum += length;
    }
    if (sum != total_length) {
        err = "LENGTH";
        return false;
    }
    m_root = root;
    m_total = total_length;
    m_pieces.clear();
    for (std::size_t i = 0; i < digests.size(); ++i) {
        if (digests[i].empty()) {
            err = "DIGEST";
            return false;
        }
        Piece piece;
        piece.order = static_cast<int>(i);
        piece.digest = digests[i];
        piece.length = lengths[i];
        m_pieces.push_back(piece);
    }
    m_state = SwarmVerifyState::Discovered;
    m_discovered = true;
    err.clear();
    return true;
}

bool SwarmVerifyBook::BeginFetch(std::string& err)
{
    if (!m_discovered || m_state == SwarmVerifyState::Admitted) {
        err = "GATE";
        return false;
    }
    m_state = SwarmVerifyState::Fetching;
    err.clear();
    return true;
}

bool SwarmVerifyBook::Submit(int order, const std::string& digest, int64_t length, std::string& err)
{
    if (m_state != SwarmVerifyState::Fetching && m_state != SwarmVerifyState::Incomplete) {
        err = "GATE";
        return false;
    }
    if (order < 0 || static_cast<std::size_t>(order) >= m_pieces.size()) {
        m_state = SwarmVerifyState::Incomplete;
        err = "REORDER";
        return false;
    }
    Piece& piece = m_pieces[static_cast<std::size_t>(order)];
    if (piece.present && piece.got_digest == digest && piece.got_length == length) {
        err.clear();
        return true;
    }
    if (piece.present) {
        m_state = SwarmVerifyState::Incomplete;
        err = "DUPLICATE";
        return false;
    }
    piece.present = true;
    piece.got_digest = digest;
    piece.got_length = length;
    if (digest != piece.digest) {
        m_state = SwarmVerifyState::Incomplete;
        err = "DIGEST";
        return false;
    }
    if (length != piece.length) {
        m_state = SwarmVerifyState::Incomplete;
        err = "LENGTH";
        return false;
    }
    err.clear();
    return true;
}

bool SwarmVerifyBook::NotePeerGone(std::string& err)
{
    if (m_state == SwarmVerifyState::Verified || m_state == SwarmVerifyState::Admitted) {
        err = "GATE";
        return false;
    }
    m_state = SwarmVerifyState::Incomplete;
    err = "PEER";
    return false;
}

bool SwarmVerifyBook::Finish(const std::string& root, std::string& err)
{
    if (!m_discovered || m_state == SwarmVerifyState::Admitted) {
        err = "GATE";
        return false;
    }
    if (root != m_root) {
        m_state = SwarmVerifyState::Incomplete;
        err = "ROOT";
        return false;
    }
    int64_t sum = 0;
    for (const Piece& piece : m_pieces) {
        if (!piece.present || piece.got_digest != piece.digest || piece.got_length != piece.length) {
            m_state = SwarmVerifyState::Incomplete;
            err = "MISSING";
            return false;
        }
        sum += piece.got_length;
    }
    if (sum != m_total) {
        m_state = SwarmVerifyState::Incomplete;
        err = "LENGTH";
        return false;
    }
    m_state = SwarmVerifyState::Verified;
    err.clear();
    return true;
}

bool SwarmVerifyBook::Activate(std::string& err)
{
    if (m_state != SwarmVerifyState::Verified) {
        err = "GATE";
        return false;
    }
    m_state = SwarmVerifyState::Admitted;
    err.clear();
    return true;
}

bool SwarmVerifyBook::Persist(const fs::path& modeldir, std::string& err)
{
    if (modeldir.empty()) {
        err = "MODELDIR";
        return false;
    }
    fs::path dir = modeldir / "swarm";
    fs::create_directories(dir);
    if (!fs::exists(dir)) {
        err = "SWARM_DIR";
        return false;
    }
    std::string body = std::string("state ") + SwarmVerifyStateName(m_state) + "\nroot " + m_root + "\ntotal " +
                       std::to_string(m_total) + "\n";
    for (const Piece& piece : m_pieces) {
        body += "piece " + std::to_string(piece.order) + " " + piece.digest + " " + std::to_string(piece.length) + " " +
                (piece.present ? "1" : "0") + " " + std::to_string(piece.got_length) + " " +
                (piece.got_digest.empty() ? "-" : piece.got_digest) + "\n";
    }
    return WriteAtomic(dir / "verify-state.txt", body, err);
}

bool SwarmVerifyBook::Load(const fs::path& modeldir, std::string& err)
{
    std::ifstream in(modeldir / "swarm" / "verify-state.txt");
    if (!in) {
        err = "READ";
        return false;
    }
    std::string tag;
    std::string state;
    if (!(in >> tag >> state) || tag != "state") {
        err = "READ";
        return false;
    }
    if (state == "DISCOVERED") m_state = SwarmVerifyState::Discovered;
    else if (state == "FETCHING") m_state = SwarmVerifyState::Fetching;
    else if (state == "INCOMPLETE") m_state = SwarmVerifyState::Incomplete;
    else if (state == "VERIFIED") m_state = SwarmVerifyState::Verified;
    else if (state == "ADMITTED") m_state = SwarmVerifyState::Admitted;
    else {
        err = "READ";
        return false;
    }
    if (!(in >> tag >> m_root) || tag != "root" || !(in >> tag >> m_total) || tag != "total") {
        err = "READ";
        return false;
    }
    m_pieces.clear();
    while (in >> tag) {
        if (tag != "piece") {
            err = "READ";
            return false;
        }
        Piece piece;
        int present = 0;
        if (!(in >> piece.order >> piece.digest >> piece.length >> present >> piece.got_length >> piece.got_digest)) {
            err = "READ";
            return false;
        }
        piece.present = present != 0;
        if (piece.got_digest == "-") piece.got_digest.clear();
        m_pieces.push_back(piece);
    }
    m_discovered = true;
    err.clear();
    return true;
}

} // namespace modelnet
