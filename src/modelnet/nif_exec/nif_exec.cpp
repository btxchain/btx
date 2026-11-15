// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_exec/nif_exec.h>

namespace modelnet {

NifExec::Item* NifExec::Find(const std::string& id)
{
    for (Item& item : m_items) {
        if (item.id == id) return &item;
    }
    return nullptr;
}

const NifExec::Item* NifExec::Find(const std::string& id) const
{
    for (const Item& item : m_items) {
        if (item.id == id) return &item;
    }
    return nullptr;
}

bool NifExec::Enqueue(const std::string& id, NifPrivacy privacy, const std::string& prompt, const std::string& engine, std::string& err)
{
    if (id.empty()) {
        err = "REQUEST";
        return false;
    }
    if (Find(id) != nullptr) {
        err = NIFDT_REPLAY;
        return false;
    }
    if (m_items.size() >= 4) {
        err = "QUEUE";
        return false;
    }
    Item item;
    item.id = id;
    item.privacy = privacy;
    item.prompt = prompt;
    item.engine = engine;
    item.decode = std::make_unique<SwarmDecodeRun>();
    m_items.push_back(std::move(item));
    err.clear();
    return true;
}

bool NifExec::Tick(std::string& err)
{
    NifPrivacy scope = NifPrivacy::LocalOnly;
    bool any = false;
    for (const Item& item : m_items) {
        if (item.cancelled || item.absent) continue;
        scope = item.privacy;
        any = true;
        break;
    }
    if (!any) {
        err = "EMPTY";
        return false;
    }
    bool pulled = false;
    for (Item& item : m_items) {
        if (item.cancelled || item.absent || item.privacy != scope) continue;
        if (!NifDtEngineLinked(item.engine) || item.engine != "memory") {
            item.absent = true;
            err = NIFDT_ENGINE_ABSENT;
            return false;
        }
        if (!item.opened) {
            if (!item.decode->Open(item.id, "memory", err)) return false;
            if (!item.decode->Prompt(item.id, item.prompt, false, err)) return false;
            item.opened = true;
        }
        if (!item.decode->Pull(item.id, err)) {
            if (err == "DONE") continue;
            return false;
        }
        item.held = item.decode->text();
        m_accepted += 1;
        pulled = true;
    }
    if (!pulled) {
        err = "DONE";
        return false;
    }
    err.clear();
    return true;
}

bool NifExec::Cancel(const std::string& id, std::string& err)
{
    Item* item = Find(id);
    if (item == nullptr) {
        err = "REQUEST";
        return false;
    }
    item->cancelled = true;
    err.clear();
    return true;
}

std::string NifExec::held(const std::string& id) const
{
    const Item* item = Find(id);
    if (item == nullptr) return {};
    return item->held;
}

} // namespace modelnet
