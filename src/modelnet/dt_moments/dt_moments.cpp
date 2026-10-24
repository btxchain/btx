// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_moments/dt_moments.h>

#include <modelnet/nifdt_contract/contract.h>
#include <util/fs.h>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <system_error>

namespace modelnet {
namespace {

bool NonFiniteText(const std::string& text)
{
    return text.find("nan") != std::string::npos || text.find("inf") != std::string::npos;
}

bool ReadFive(const fs::path& path, std::string& master, std::string& moment, std::string& scale,
              std::string& rng, std::string& scheduler)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    std::string raw;
    raw.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    if (!in && !in.eof()) return false;

    std::string lines[5];
    std::size_t pos = 0;
    for (int i = 0; i < 5; ++i) {
        const std::size_t nl = raw.find('\n', pos);
        if (nl == std::string::npos) return false;
        lines[i].assign(raw, pos, nl - pos);
        if (lines[i].empty()) return false;
        pos = nl + 1;
    }
    if (pos != raw.size()) return false;

    master = std::move(lines[0]);
    moment = std::move(lines[1]);
    scale = std::move(lines[2]);
    rng = std::move(lines[3]);
    scheduler = std::move(lines[4]);
    return true;
}

bool Publish(const fs::path& directory, const fs::path& final, const std::string& body, std::string& err)
{
    const fs::path tmp = directory / "moments.journal.tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) {
            err = DT_MOMENTS_JOURNAL;
            std::error_code ignore;
            fs::remove(tmp, ignore);
            return false;
        }
        out.write(body.data(), static_cast<std::streamsize>(body.size()));
        out.close();
        if (!out) {
            err = DT_MOMENTS_JOURNAL;
            std::error_code ignore;
            fs::remove(tmp, ignore);
            return false;
        }
    }
    std::error_code ec;
    fs::rename(tmp, final, ec);
    if (ec) {
        err = DT_MOMENTS_JOURNAL;
        std::error_code ignore;
        fs::remove(tmp, ignore);
        return false;
    }
    err.clear();
    return true;
}

} // namespace

bool DtMoments::Commit(const fs::path& dir, const std::string& master, const std::string& moment,
                       const std::string& scale, const std::string& rng, const std::string& scheduler,
                       bool journal_ok, std::string& err)
{
    // fs::path::string() is deleted. utf8string() is the path text.
    const std::string utf8 = dir.utf8string();
    if (utf8.empty()) {
        err = DT_MOMENTS_DIR;
        return false;
    }
    if (master.empty() || moment.empty() || scale.empty() || rng.empty() || scheduler.empty()) {
        err = DT_MOMENTS_STATE;
        return false;
    }
    if (NonFiniteText(master) || NonFiniteText(moment) || NonFiniteText(scale) || NonFiniteText(rng) ||
        NonFiniteText(scheduler)) {
        err = DT_MOMENTS_FINITE;
        return false;
    }
    if (!journal_ok) {
        err = DT_MOMENTS_JOURNAL;
        return false;
    }
    if (m_moment == moment) {
        err = NIFDT_REPLAY;
        return false;
    }

    const fs::path directory = fs::u8path(utf8);
    const fs::path final = directory / DT_MOMENTS_JOURNAL_NAME;
    if (fs::exists(final)) {
        std::string stored_master;
        std::string stored_moment;
        std::string stored_scale;
        std::string stored_rng;
        std::string stored_scheduler;
        if (ReadFive(final, stored_master, stored_moment, stored_scale, stored_rng, stored_scheduler) &&
            stored_moment == moment) {
            err = NIFDT_REPLAY;
            return false;
        }
    }

    try {
        fs::create_directories(directory);
    } catch (const std::filesystem::filesystem_error&) {
        err = DT_MOMENTS_JOURNAL;
        return false;
    }
    if (!fs::exists(directory)) {
        err = DT_MOMENTS_JOURNAL;
        return false;
    }

    const std::string body = master + "\n" + moment + "\n" + scale + "\n" + rng + "\n" + scheduler + "\n";
    if (!Publish(directory, final, body, err)) return false;

    m_master = master;
    m_moment = moment;
    m_scale = scale;
    m_rng = rng;
    m_scheduler = scheduler;
    err.clear();
    return true;
}

bool DtMoments::Reload(const fs::path& dir, std::string& err)
{
    const std::string utf8 = dir.utf8string();
    if (utf8.empty()) {
        err = DT_MOMENTS_DIR;
        return false;
    }
    const fs::path final = fs::u8path(utf8) / DT_MOMENTS_JOURNAL_NAME;
    if (!fs::exists(final)) {
        err = DT_MOMENTS_JOURNAL;
        return false;
    }
    std::string master;
    std::string moment;
    std::string scale;
    std::string rng;
    std::string scheduler;
    if (!ReadFive(final, master, moment, scale, rng, scheduler)) {
        err = DT_MOMENTS_JOURNAL;
        return false;
    }
    if (NonFiniteText(master) || NonFiniteText(moment) || NonFiniteText(scale) || NonFiniteText(rng) ||
        NonFiniteText(scheduler)) {
        err = DT_MOMENTS_FINITE;
        return false;
    }
    m_master = std::move(master);
    m_moment = std::move(moment);
    m_scale = std::move(scale);
    m_rng = std::move(rng);
    m_scheduler = std::move(scheduler);
    err.clear();
    return true;
}

bool DtMoments::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

} // namespace modelnet
