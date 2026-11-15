// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_appointment.h>

#include <univalue.h>

#include <fstream>
#include <system_error>

namespace modelnet {
namespace {

bool EnsureDir(const fs::path& modeldir, fs::path& swarm_dir, std::string& err)
{
    if (modeldir.empty()) {
        err = "MODELDIR";
        return false;
    }
    swarm_dir = modeldir / "swarm";
    fs::create_directories(swarm_dir);
    if (!fs::exists(swarm_dir)) {
        err = "SWARM_DIR";
        return false;
    }
    return true;
}

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

bool ReadRaw(const fs::path& path, std::string& raw)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    raw.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return true;
}

bool AllowedAction(const std::string& action)
{
    return action == "HASHLOCK_REMEDY" || action == "STALE_STATE_ALERT" || action == "DRAIN_AND_NOTIFY";
}

} // namespace

bool SwarmWriteAppointment(const fs::path& modeldir, const SwarmAppointment& appointment, std::string& err)
{
    if (appointment.channel_id.empty() || appointment.sequence < 0) {
        err = "APPOINTMENT";
        return false;
    }
    // 160 is the minimum close margin. It is not a claim that the window is production-qualified.
    if (appointment.contest_blocks < 160) {
        err = "CONTEST_WINDOW";
        return false;
    }
    if (!AllowedAction(appointment.action)) {
        err = "APPOINTMENT";
        return false;
    }
    if (appointment.native_remedy_available) {
        err = "NATIVE_REMEDY";
        return false;
    }
    if (appointment.secp_penalty) {
        err = "SECP_PENALTY";
        return false;
    }
    fs::path swarm_dir;
    if (!EnsureDir(modeldir, swarm_dir, err)) return false;
    UniValue root(UniValue::VOBJ);
    root.pushKV("channel_id", appointment.channel_id);
    root.pushKV("sequence", appointment.sequence);
    root.pushKV("contest_blocks", appointment.contest_blocks);
    root.pushKV("native_remedy_available", false);
    root.pushKV("secp_penalty", false);
    root.pushKV("action", appointment.action);
    root.pushKV("automatic_spend_atoms", "0");
    return WriteAtomic(swarm_dir / "appointment.json", root.write(0, 0) + "\n", err);
}

bool SwarmReadAppointment(const fs::path& modeldir, SwarmAppointment& appointment, std::string& err)
{
    std::string raw;
    UniValue root;
    if (!ReadRaw(modeldir / "swarm" / "appointment.json", raw) || !root.read(raw) || !root.isObject() ||
        !root.exists("channel_id") || !root["channel_id"].isStr() || !root.exists("sequence") || !root["sequence"].isNum() ||
        !root.exists("contest_blocks") || !root["contest_blocks"].isNum() || !root.exists("native_remedy_available") ||
        !root["native_remedy_available"].isBool() || !root.exists("secp_penalty") || !root["secp_penalty"].isBool() ||
        !root.exists("action") || !root["action"].isStr() || !root.exists("automatic_spend_atoms") ||
        !root["automatic_spend_atoms"].isStr() || root["automatic_spend_atoms"].get_str() != "0") {
        err = "APPOINTMENT_READ";
        return false;
    }
    appointment.channel_id = root["channel_id"].get_str();
    appointment.sequence = root["sequence"].getInt<int64_t>();
    appointment.contest_blocks = root["contest_blocks"].getInt<int>();
    appointment.native_remedy_available = root["native_remedy_available"].get_bool();
    appointment.secp_penalty = root["secp_penalty"].get_bool();
    appointment.action = root["action"].get_str();
    err.clear();
    return true;
}

} // namespace modelnet
