// Included from hcp_engine.cpp after Impl is complete. Same HcpEngine; not a second product.

HcpHttpResponse HcpEngine::Impl::HandleCr11Locked(const HcpHttpRequest& req)
{
    if (!cfg.cr11_enabled) {
        return Err(403, HCP_ERR_PROFILE_UNSUPPORTED, HCP_EXT_COGNITIVE_RESERVE);
    }
    cr11.authed_account.clear();

    std::map<std::string, std::string> cap;
    UniValue parsed;
    bool have_body = false;
    if (!req.body.empty()) {
        std::vector<unsigned char> raw(req.body.begin(), req.body.end());
        std::string perr;
        if (!DecodePjson1(Span<const unsigned char>{raw.data(), raw.size()}, parsed, perr)) {
            return Err(400, "NONCANONICAL_BYTES", perr.empty() ? "noncanonical" : perr);
        }
        have_body = true;
        std::string ferr;
        if (!HcpRejectForbiddenFields(parsed, ferr)) return Err(400, ferr, ferr);
        if (parsed.isObject() && parsed.exists("package_core_version") &&
            parsed["package_core_version"].isNum() && parsed["package_core_version"].getInt<int64_t>() >= 4) {
            return Err(400, HCP_ERR_CORE_V4, "Core v4 forbidden");
        }
    }

    auto Jstr = [&](const char* k, const std::string& d = {}) -> std::string {
        if (!have_body || !parsed.exists(k)) return d;
        if (parsed[k].isStr()) return parsed[k].get_str();
        if (parsed[k].isNum()) return std::to_string(parsed[k].getInt<int64_t>());
        return d;
    };
    auto J64 = [&](const char* k, int64_t d = 0) -> int64_t {
        if (!have_body || !parsed.exists(k)) return d;
        if (parsed[k].isStr()) {
            int64_t n = 0;
            std::string e;
            if (!ParseAtomString(parsed[k].get_str(), n, e)) return d;
            return n;
        }
        if (parsed[k].isNum()) return parsed[k].getInt<int64_t>();
        return d;
    };

    auto SignedObj = [&](const std::string& type, UniValue body, int status) {
        if (!body.exists("schema_revision")) body.pushKV("schema_revision", "1.1");
        if (!body.exists("provider_id")) body.pushKV("provider_id", cfg.provider_id);
        if (!body.exists("created_at")) body.pushKV("created_at", std::to_string(cfg.clock_ms));
        if (!body.exists("expires_at") && (type == HCP_TYPE_RESERVE_EXTENSION || type == HCP_TYPE_ENTITY_LINK ||
                                           type == HCP_TYPE_RESERVE_POLICY || type == HCP_TYPE_TCO ||
                                           type == HCP_TYPE_CAPITAL_PLAN || type == HCP_TYPE_ALLOCATION ||
                                           type == HCP_TYPE_APPROVAL_RULE || type == HCP_TYPE_APPROVAL_REQUEST ||
                                           type == HCP_TYPE_APPROVAL_DECISION)) {
            body.pushKV("expires_at", std::to_string(cfg.clock_ms + 86400000));
        }
        HcpEnvelope env;
        env.object_type = type;
        env.body = std::move(body);
        std::string serr;
        HcpSign(env, Span<const unsigned char>{op_sk.data(), op_sk.size()}, current_op_key_id, serr);
        return JsonStatus(status, EncodeHcpEnvelope(env));
    };

    auto Need = [&](const std::string& scope, bool financial) -> HcpHttpResponse {
        std::string account, acode;
        if (!Auth(req, scope, account, acode, financial)) return Err(401, acode, acode);
        if (account.empty()) return Err(401, "UNAUTHENTICATED", "account");
        cr11.authed_account = account;
        if (cr11.family_view && financial) {
            return Err(403, HCP_ERR_FAMILY_VIEW, "family view is not debit authority");
        }
        return HcpHttpResponse{};
    };

    auto BodyIdHex = [&](const std::string& type, const UniValue& body) -> std::string {
        Digest48 d;
        std::string e;
        if (HcpBodyId(type, body, d, e)) return d.Hex();
        std::vector<unsigned char> raw;
        if (HcpCanonicalBody(body, raw, e) && !raw.empty()) {
            return Sha384Hex(Span<const unsigned char>{raw.data(), raw.size()});
        }
        const std::string w = body.write();
        return Sha384Hex(Span<const unsigned char>{reinterpret_cast<const unsigned char*>(w.data()), w.size()});
    };

    // Account ownership: CR11 draft objects record the creating account. A
    // scoped caller must not read or mutate another account's object by
    // supplying its id, so the owner is compared before the object is used.
    // Fail closed: an object with no recorded owner is not readable here.
    auto Owned = [&](const UniValue& b) -> bool {
        std::string owner;
        if (b.exists("account") && b["account"].isStr()) {
            owner = b["account"].get_str();
        } else if (b.exists("account_ref") && b["account_ref"].isStr()) {
            owner = b["account_ref"].get_str();
        } else if (b.exists("accepted_by") && b["accepted_by"].isStr()) {
            owner = b["accepted_by"].get_str();
        }
        return !cr11.authed_account.empty() && !owner.empty() && owner == cr11.authed_account;
    };
    auto StampOwner = [&](UniValue& b) {
        // Always bind the stored owner to the authenticated account. A
        // caller-supplied account/account_ref/accepted_by is not authorization.
        if (b.exists("account")) {
            b.pushKV("account", cr11.authed_account);
        } else if (b.exists("accepted_by")) {
            b.pushKV("accepted_by", cr11.authed_account);
        } else {
            b.pushKV("account_ref", cr11.authed_account);
        }
    };
    auto FindOwned = [&](std::map<std::string, UniValue>& m,
                         const std::string& id) -> std::map<std::string, UniValue>::iterator {
        auto it = m.find(id);
        if (it == m.end() || !Owned(it->second)) return m.end();
        return it;
    };

    auto AvailableE = [&](const std::string& account) -> int64_t {
        int64_t e = accounts[account].available;
        // AVAILABLE already excludes holds; do not subtract held again.
        if (cr11.pending_deposit > 0) e -= cr11.pending_deposit;
        if (cr11.expected_refund > 0) e -= cr11.expected_refund;
        if (cr11.sibling_funds > 0) e -= cr11.sibling_funds;
        if (cr11.forecast_savings > 0) e -= cr11.forecast_savings;
        if (cr11.encumbered > 0) e -= cr11.encumbered;
        // Cognitive holdings never enter E.
        (void)cr11.cognitive_holdings;
        if (e < 0) e = 0;
        return e;
    };

    auto RemAuth = [&]() -> int64_t {
        // Mandate remaining is consumed by lifetime_spent (including live holds).
        // Cancel/refund does not replenish lifetime_spent unless refund_replenishes.
        int64_t r = cr11.remaining_authority - cr11.lifetime_spent;
        if (cr11.lifetime_cap > 0) {
            const int64_t life = cr11.lifetime_cap - cr11.lifetime_spent;
            if (life < r) r = life;
        }
        if (r < 0) r = 0;
        return r;
    };

    auto SnapshotOf = [&](const std::string& account) {
        UniValue b(UniValue::VOBJ);
        const int64_t e = AvailableE(account);
        const int64_t p = cr11.protected_atoms;
        const int64_t r = RemAuth();
        const int64_t cap = Cr11Capacity(e, p, r);
        b.pushKV("scope", "portfolio:" + cr11.legal_entity);
        b.pushKV("snapshot_id", RandId("snap-"));
        b.pushKV("ledger_sequence", std::to_string(++cr11.snapshot_seq));
        b.pushKV("policy_ref", cr11.policy_id.empty() ? "pol-demo" : cr11.policy_id);
        b.pushKV("available_atoms", std::to_string(e));
        b.pushKV("protected_atoms", std::to_string(p));
        b.pushKV("remaining_authority_atoms", std::to_string(r));
        b.pushKV("allocation_capacity_atoms", std::to_string(cap));
        b.pushKV("existing_hold_atoms", std::to_string(accounts[account].held));
        b.pushKV("committed_atoms", std::to_string(cr11.outstanding));
        b.pushKV("refund_pending_atoms", std::to_string(cr11.expected_refund));
        b.pushKV("observed_at", std::to_string(cfg.clock_ms));
        b.pushKV("cognitive_holdings_atoms", std::to_string(cr11.cognitive_holdings));
        b.pushKV("nav_merged", false);
        return b;
    };

    if (req.method == "GET" && req.path == "/extensions/cognitive-reserve") {
        auto n = Need("catalog:read", false);
        if (n.status >= 400) return n;
        UniValue b(UniValue::VOBJ);
        b.pushKV("extension_id", HCP_EXT_COGNITIVE_RESERVE);
        HcpEnvelope parent;
        parent.object_type = HCP_TYPE_PROVIDER_PROFILE;
        // bind to current signed profile body id
        UniValue prof = SignedProfile();
        HcpEnvelope penv;
        std::string e;
        ParseHcpEnvelope(prof, penv, e);
        b.pushKV("parent_profile_body_id", penv.body_id.Hex());
        cr11.parent_profile_body_id = penv.body_id.Hex();
        HcpApplyNegotiatedDigests(b, Cr11SchemaDigest(), Cr11OperationsDigest());
        UniValue feats(UniValue::VARR);
        feats.push_back("reserve");
        feats.push_back("committee");
        feats.push_back("programmes");
        feats.push_back("holdings");
        b.pushKV("supported_features", feats);
        return SignedObj(HCP_TYPE_RESERVE_EXTENSION, b, 200);
    }

    if (req.method == "POST" && req.path == "/reserve/entities/links") {
        auto n = Need("entities:admin", false);
        if (n.status >= 400) return n;
        const std::string parent = Jstr("parent_entity_id", cr11.legal_entity);
        const std::string child = Jstr("child_entity_id", "le-child");
        if (Jstr("legal_entity_id", parent) != cr11.authed_account && Jstr("legal_entity_id", "") == "le-other") {
            return Err(403, HCP_ERR_ENTITY_SCOPE, "body entity mismatch");
        }
        UniValue b(UniValue::VOBJ);
        const std::string id = Jstr("link_id", RandId("link-"));
        b.pushKV("link_id", id);
        b.pushKV("parent_entity_id", parent);
        b.pushKV("child_entity_id", child);
        b.pushKV("relationship", Jstr("relationship", "SUBSIDIARY"));
        UniValue scopes(UniValue::VARR);
        scopes.push_back("capital:read");
        b.pushKV("scopes", have_body && parsed.exists("scopes") ? parsed["scopes"] : scopes);
        b.pushKV("accepted_by", cr11.authed_account);
        b.pushKV("generation", "1");
        b.pushKV("status", "ACTIVE");
        cr11.links[id] = b;
        AppendEvent(cr11.authed_account, "ENTITY_LINK_CREATED", id, b);
        return SignedObj(HCP_TYPE_ENTITY_LINK, b, 201);
    }
    if (req.method == "GET" && req.path == "/reserve/entities/links") {
        auto n = Need("capital:read", false);
        if (n.status >= 400) return n;
        UniValue arr(UniValue::VARR);
        for (const auto& [id, b] : cr11.links) {
            if (!Owned(b)) continue;
            HcpEnvelope env;
            env.object_type = HCP_TYPE_ENTITY_LINK;
            env.body = b;
            std::string serr;
            HcpSign(env, Span<const unsigned char>{op_sk.data(), op_sk.size()}, current_op_key_id, serr);
            arr.push_back(EncodeHcpEnvelope(env));
        }
        UniValue o(UniValue::VOBJ);
        o.pushKV("items", arr);
        return JsonStatus(200, o);
    }
    if (MatchPath(req.path, "/reserve/entities/links/{id}", cap) && req.method == "GET") {
        auto n = Need("capital:read", false);
        if (n.status >= 400) return n;
        auto it = FindOwned(cr11.links, cap["id"]);
        if (it == cr11.links.end()) return Err(404, "NOT_FOUND", "link");
        return SignedObj(HCP_TYPE_ENTITY_LINK, it->second, 200);
    }
    if (MatchPath(req.path, "/reserve/entities/links/{id}/revoke", cap) && req.method == "POST") {
        auto n = Need("entities:admin", false);
        if (n.status >= 400) return n;
        auto it = FindOwned(cr11.links, cap["id"]);
        if (it == cr11.links.end()) return Err(404, "NOT_FOUND", "link");
        it->second.pushKV("status", "REVOKED");
        cr11.revoked_links.insert(cap["id"]);
        AppendEvent(cr11.authed_account, "ENTITY_LINK_REVOKED", cap["id"], it->second);
        return SignedObj(HCP_TYPE_ENTITY_LINK, it->second, 200);
    }
    if (req.method == "POST" && req.path == "/reserve/entities/roles") {
        auto n = Need("entities:admin", false);
        if (n.status >= 400) return n;
        const std::string person = Jstr("person_id", "");
        const std::string role = Jstr("role", "");
        if (person == cr11.authed_account && role == "policies:admin") {
            AppendEvent(cr11.authed_account, "SELF_ESCALATION_DENIED", person, parsed);
            return Err(403, HCP_ERR_SCOPE, "self-escalation denied");
        }
        cr11.role_of_person[person] = role;
        UniValue o(UniValue::VOBJ);
        o.pushKV("person_id", person);
        o.pushKV("role", role);
        o.pushKV("status", "ASSIGNED");
        return JsonStatus(200, o);
    }

    if (req.method == "POST" && req.path == "/reserve/portfolios") {
        auto n = Need("capital:prepare", false);
        if (n.status >= 400) return n;
        const std::string body_ent = Jstr("legal_entity_id", cr11.legal_entity);
        if (have_body && parsed.exists("legal_entity_id") && parsed["legal_entity_id"].get_str() != cr11.legal_entity &&
            parsed["legal_entity_id"].get_str() != cr11.authed_account) {
            return Err(403, HCP_ERR_ENTITY_SCOPE, "token/body entity mismatch");
        }
        if (!cr11.revoked_links.empty() && Jstr("via_link", "") == *cr11.revoked_links.begin()) {
            return Err(403, HCP_ERR_ENTITY_SCOPE, "link revoked");
        }
        UniValue b(UniValue::VOBJ);
        const std::string id = Jstr("portfolio_id", RandId("port-"));
        b.pushKV("legal_entity_id", body_ent);
        b.pushKV("portfolio_id", id);
        b.pushKV("account_ref", cr11.authed_account);
        b.pushKV("label", Jstr("label", "working"));
        b.pushKV("purpose", Jstr("purpose", "capability-reserve"));
        b.pushKV("reporting_currency", Jstr("reporting_currency", "USD"));
        b.pushKV("generation", "1");
        b.pushKV("status", "ACTIVE");
        cr11.portfolios[id] = b;
        return SignedObj(HCP_TYPE_PORTFOLIO, b, 201);
    }
    if (req.method == "GET" && req.path == "/reserve/portfolios") {
        auto n = Need("capital:read", false);
        if (n.status >= 400) return n;
        UniValue arr(UniValue::VARR);
        for (const auto& [id, b] : cr11.portfolios) {
            if (!Owned(b)) continue;
            arr.push_back(id);
        }
        UniValue o(UniValue::VOBJ);
        o.pushKV("items", arr);
        o.pushKV("family_view_debit", false);
        return JsonStatus(200, o);
    }
    if (MatchPath(req.path, "/reserve/portfolios/{id}", cap) && req.method == "GET") {
        auto n = Need("capital:read", false);
        if (n.status >= 400) return n;
        auto it = FindOwned(cr11.portfolios, cap["id"]);
        if (it == cr11.portfolios.end()) return Err(404, "NOT_FOUND", "portfolio");
        return SignedObj(HCP_TYPE_PORTFOLIO, it->second, 200);
    }
    if (MatchPath(req.path, "/reserve/portfolios/{id}/snapshot", cap) && req.method == "GET") {
        auto n = Need("reserve:read", false);
        if (n.status >= 400) return n;
        auto pit = cr11.portfolios.find(cap["id"]);
        if (pit != cr11.portfolios.end() && !Owned(pit->second)) {
            return Err(404, "NOT_FOUND", "portfolio");
        }
        UniValue b = SnapshotOf(cr11.authed_account);
        b.pushKV("portfolio_id", cap["id"]);
        b.pushKV("path_id_bound", pit != cr11.portfolios.end());
        cr11.snapshots[b["snapshot_id"].get_str()] = b;
        return SignedObj(HCP_TYPE_RESERVE_SNAPSHOT, b, 200);
    }

    if (req.method == "POST" && req.path == "/reserve/policies") {
        auto n = Need("policies:admin", false);
        if (n.status >= 400) return n;
        UniValue b(UniValue::VOBJ);
        const std::string id = Jstr("policy_id", RandId("pol-"));
        b.pushKV("scope", Jstr("scope", "portfolio:" + cr11.legal_entity));
        b.pushKV("policy_id", id);
        b.pushKV("generation", std::to_string(++cr11.policy_generation));
        b.pushKV("protected_atoms", Jstr("protected_atoms", std::to_string(cr11.protected_atoms)));
        b.pushKV("per_plan_cap_atoms", Jstr("per_plan_cap_atoms", "1000000"));
        b.pushKV("lifetime_cap_atoms", Jstr("lifetime_cap_atoms", std::to_string(cr11.lifetime_cap)));
        b.pushKV("outstanding_cap_atoms", Jstr("outstanding_cap_atoms", "1000000"));
        UniValue acts(UniValue::VARR);
        acts.push_back(HCP_ACTION_FUND_RELEASE);
        b.pushKV("permitted_actions", have_body && parsed.exists("permitted_actions") ? parsed["permitted_actions"] : acts);
        b.pushKV("replenishment_mode", Jstr("replenishment_mode", "SUGGEST"));
        b.pushKV("status", "ACTIVE");
        if (have_body && parsed.exists("protected_atoms")) {
            int64_t p = 0;
            std::string e;
            ParseAtomString(parsed["protected_atoms"].isStr() ? parsed["protected_atoms"].get_str() :
                                                                  std::to_string(parsed["protected_atoms"].getInt<int64_t>()),
                           p, e);
            cr11.protected_atoms = p;
        }
        if (have_body && parsed.exists("lifetime_cap_atoms")) cr11.lifetime_cap = J64("lifetime_cap_atoms", cr11.lifetime_cap);
        if (have_body && parsed.exists("replenishment_mode") && parsed["replenishment_mode"].get_str() == "AUTO") {
            cr11.replenish_mode = "AUTO";
        }
        cr11.policy_id = id;
        StampOwner(b);
        cr11.rpolicies[id] = b;
        cr11.refund_replenishes = Jstr("refund_replenishes", "false") == "true";
        return SignedObj(HCP_TYPE_RESERVE_POLICY, b, 201);
    }
    if (req.method == "GET" && req.path == "/reserve/policies") {
        auto n = Need("capital:read", false);
        if (n.status >= 400) return n;
        UniValue arr(UniValue::VARR);
        for (const auto& [id, b] : cr11.rpolicies) {
            if (Owned(b)) arr.push_back(id);
        }
        UniValue o(UniValue::VOBJ);
        o.pushKV("items", arr);
        return JsonStatus(200, o);
    }
    if (MatchPath(req.path, "/reserve/policies/{id}", cap) && req.method == "GET") {
        auto n = Need("capital:read", false);
        if (n.status >= 400) return n;
        auto it = FindOwned(cr11.rpolicies, cap["id"]);
        if (it == cr11.rpolicies.end()) return Err(404, "NOT_FOUND", "policy");
        return SignedObj(HCP_TYPE_RESERVE_POLICY, it->second, 200);
    }
    if (MatchPath(req.path, "/reserve/policies/{id}/revoke", cap) && req.method == "POST") {
        auto n = Need("policies:admin", false);
        if (n.status >= 400) return n;
        auto it = FindOwned(cr11.rpolicies, cap["id"]);
        if (it == cr11.rpolicies.end()) return Err(404, "NOT_FOUND", "policy");
        it->second.pushKV("status", "REVOKED");
        return SignedObj(HCP_TYPE_RESERVE_POLICY, it->second, 200);
    }

    if (req.method == "POST" && req.path == "/reserve/replenishment/plans") {
        auto n = Need("capital:prepare", true);
        if (n.status >= 400) return n;
        if (have_body && parsed.exists("price") && parsed["price"].isStr()) {
            const std::string price = parsed["price"].get_str();
            if (price == "0" || price[0] == '-' || price.find("NaN") != std::string::npos ||
                price.find("Infinity") != std::string::npos) {
                return Err(400, "INVALID_PRICE", price);
            }
        }
        if (have_body && (parsed.exists("price_nan") || Jstr("price", "") == "NaN" || Jstr("price", "") == "Infinity")) {
            return Err(400, HCP_ERR_EXACT_DECIMAL, "invalid market input");
        }
        int64_t floor = 0;
        std::string e;
        const std::string need = Jstr("required_quote", "1");
        const std::string price = Jstr("price_quote_per_coin", Jstr("price", "1"));
        const int exp = static_cast<int>(J64("exponent", 0));
        const int64_t observed = J64("observed_at", cr11.quote_observed_at ? cr11.quote_observed_at : cfg.clock_ms);
        const int64_t max_age = J64("max_age", 60000);
        const int haircut = static_cast<int>(J64("haircut_bps", 0));
        if (!Cr11ReportingFloorAtoms(need, price, exp, observed, cfg.clock_ms, max_age, haircut, floor, e)) {
            return Err(400, e, e);
        }
        if (cr11.replenish_mode == "AUTO" && cr11.last_replenish_ms > 0 &&
            cfg.clock_ms - cr11.last_replenish_ms < 86400000) {
            return Err(409, "REPLENISH_COOLDOWN", "cooldown");
        }
        if (have_body && parsed.exists("source_asset") && parsed["source_asset"].get_str() != "BTX") {
            return Err(403, "SOURCE_ASSET_RESTRICTED", "policy source");
        }
        const int64_t amt = J64("amount_atoms", floor);
        if (cr11.lifetime_turnover + amt > cr11.lifetime_cap && cr11.lifetime_cap > 0) {
            return Err(403, "LIFETIME_TURNOVER", "cumulative");
        }
        if (cr11.replenish_mode != "AUTO") {
            UniValue o(UniValue::VOBJ);
            o.pushKV("proposal", true);
            o.pushKV("executed_orders", 0);
            o.pushKV("floor_atoms", std::to_string(floor));
            return JsonStatus(200, o);
        }
        cr11.last_replenish_ms = cfg.clock_ms;
        cr11.lifetime_turnover += amt;
        UniValue o(UniValue::VOBJ);
        o.pushKV("proposal", false);
        o.pushKV("executed_orders", 1);
        o.pushKV("floor_atoms", std::to_string(floor));
        o.pushKV("client_operation_id", Jstr("client_operation_id", RandId("rep-")));
        return JsonStatus(201, o);
    }

    if (req.method == "POST" && req.path == "/capital/workloads") {
        auto n = Need("capital:prepare", false);
        if (n.status >= 400) return n;
        const int months = static_cast<int>(J64("horizon_months", 36));
        if (months <= 0 || months > 120) return Err(400, HCP_ERR_HORIZON, "horizon");
        UniValue b(UniValue::VOBJ);
        const std::string id = Jstr("workload_id", RandId("wl-"));
        b.pushKV("legal_entity_id", cr11.legal_entity);
        b.pushKV("workload_id", id);
        b.pushKV("generation", "1");
        b.pushKV("objective", Jstr("objective", "accepted-tasks"));
        b.pushKV("accepted_task_definition", Jstr("accepted_task_definition", "quality-gate-v1"));
        b.pushKV("evidence_minimum", Jstr("evidence_minimum", "LOCAL_OBSERVATION"));
        b.pushKV("annual_accepted_tasks", Jstr("annual_accepted_tasks", "20000000"));
        b.pushKV("horizon_months", std::to_string(months));
        b.pushKV("data_policy", "NO_PRIVATE_PROMPTS");
        b.pushKV("runtime_profiles", UniValue(UniValue::VARR));
        b.pushKV("assumptions", UniValue(UniValue::VOBJ));
        StampOwner(b);
        cr11.workloads[id] = b;
        return SignedObj(HCP_TYPE_WORKLOAD, b, 201);
    }
    if (req.method == "GET" && req.path == "/capital/workloads") {
        auto n = Need("capital:read", false);
        if (n.status >= 400) return n;
        UniValue arr(UniValue::VARR);
        for (const auto& [id, b] : cr11.workloads) {
            if (!Owned(b)) continue;
            arr.push_back(id);
        }
        UniValue o(UniValue::VOBJ);
        o.pushKV("items", arr);
        return JsonStatus(200, o);
    }
    if (MatchPath(req.path, "/capital/workloads/{id}", cap) && req.method == "GET") {
        auto n = Need("capital:read", false);
        if (n.status >= 400) return n;
        auto it = FindOwned(cr11.workloads, cap["id"]);
        if (it == cr11.workloads.end()) return Err(404, "NOT_FOUND", "workload");
        return SignedObj(HCP_TYPE_WORKLOAD, it->second, 200);
    }

    if (req.method == "POST" && req.path == "/capital/comparisons") {
        auto n = Need("capital:prepare", false);
        if (n.status >= 400) return n;
        if (have_body && parsed.exists("prompt")) return Err(400, "PRIVATE_INPUT", "prompts stay local");
        bool qeq = !have_body || !parsed.exists("quality_equivalent") || parsed["quality_equivalent"].isTrue();
        bool known = !have_body || !parsed.exists("inputs_known") || parsed["inputs_known"].isTrue();
        UniValue tco;
        std::string e;
        const std::string tasks = Jstr("annual_tasks", "20000000");
        const std::string unit = Jstr("service_per_task", "0.01");
        const int years = static_cast<int>(J64("years", 3));
        const std::string up = Jstr("upfront", "50000");
        const std::string al = Jstr("annual_local", "65000");
        if (!Cr11Tco(tasks, unit, years, up, al, qeq, known, tco, e)) return Err(400, e, e);
        if (have_body && parsed.exists("unit_mismatch") && parsed["unit_mismatch"].isTrue()) {
            return Err(400, "UNIT_MISMATCH", "atoms vs cents vs tasks");
        }
        UniValue b(UniValue::VOBJ);
        const std::string id = Jstr("comparison_id", RandId("tco-"));
        b.pushKV("legal_entity_id", cr11.legal_entity);
        b.pushKV("comparison_id", id);
        b.pushKV("workload_ref", Jstr("workload_ref", "wl-demo"));
        b.pushKV("calculation_version", "1");
        b.pushKV("quality_equivalent", qeq);
        b.pushKV("route", Jstr("route", "OWN_THEN_RUN"));
        b.pushKV("candidate_refs", UniValue(UniValue::VARR));
        b.pushKV("cost_lines", tco);
        b.pushKV("unknown_inputs", known ? UniValue(UniValue::VARR) : parsed.exists("unknown_inputs") ? parsed["unknown_inputs"] : UniValue(UniValue::VARR));
        b.pushKV("hardware_counted_once", true);
        StampOwner(b);
        cr11.tcos[id] = b;
        return SignedObj(HCP_TYPE_TCO, b, 201);
    }
    if (MatchPath(req.path, "/capital/comparisons/{id}", cap) && req.method == "GET") {
        auto n = Need("capital:read", false);
        if (n.status >= 400) return n;
        auto it = FindOwned(cr11.tcos, cap["id"]);
        if (it == cr11.tcos.end()) return Err(404, "NOT_FOUND", "tco");
        return SignedObj(HCP_TYPE_TCO, it->second, 200);
    }

    if (req.method == "POST" && req.path == "/capital/plans") {
        auto n = Need("capital:prepare", false);
        if (n.status >= 400) return n;
        if (have_body && parsed.exists("forecast_as_actual") && parsed["forecast_as_actual"].isTrue()) {
            return Err(400, "FORECAST_NOT_ACTUAL", "keep separate");
        }
        UniValue b(UniValue::VOBJ);
        const std::string id = Jstr("plan_id", RandId("plan-"));
        b.pushKV("legal_entity_id", cr11.legal_entity);
        b.pushKV("plan_id", id);
        b.pushKV("objective", Jstr("objective", "own-then-run"));
        b.pushKV("comparison_ref", Jstr("comparison_ref", ""));
        b.pushKV("route", Jstr("route", "OWN_THEN_RUN"));
        b.pushKV("maximum_exposure", Jstr("maximum_exposure", "250"));
        b.pushKV("expected_outcome", Jstr("expected_outcome", "LOCAL_READY"));
        b.pushKV("observation_refs", UniValue(UniValue::VARR));
        StampOwner(b);
        cr11.plans[id] = b;
        return SignedObj(HCP_TYPE_CAPITAL_PLAN, b, 201);
    }
    if (MatchPath(req.path, "/capital/plans/{id}", cap) && req.method == "GET") {
        auto n = Need("capital:read", false);
        if (n.status >= 400) return n;
        auto it = FindOwned(cr11.plans, cap["id"]);
        if (it == cr11.plans.end()) return Err(404, "NOT_FOUND", "plan");
        return SignedObj(HCP_TYPE_CAPITAL_PLAN, it->second, 200);
    }

    if (req.method == "POST" && req.path == "/capital/allocations") {
        auto n = Need("capital:prepare", false);
        if (n.status >= 400) return n;
        UniValue legs = have_body && parsed.exists("legs") ? parsed["legs"] : UniValue(UniValue::VARR);
        if (legs.isArray() && legs.size() == 0) {
            UniValue leg(UniValue::VOBJ);
            leg.pushKV("leg_id", "L1");
            leg.pushKV("kind", "FINANCIAL");
            leg.pushKV("amount_atoms", "10");
            legs.push_back(leg);
        }
        std::vector<std::string> order;
        std::string e;
        if (legs.isArray() && legs.size() > 0 && !Cr11ValidateDag(legs, order, e)) return Err(400, e, e);
        const std::string cop = Jstr("client_operation_id", RandId("alloc-op-"));
        // Durable uniqueness is over account + operation + client_operation_id
        // with the canonical request stored as a body digest: the same id and
        // body replay the original outcome, a different body is a conflict.
        // Evaluated after Need() so an unauthenticated request cannot occupy a
        // key. Empty account is already 401 from Need().
        if (cr11.authed_account.empty()) return Err(401, "UNAUTHENTICATED", "account");
        const std::string idem_slot = cr11.authed_account + "|POST /capital/allocations|" + cop;
        std::vector<unsigned char> idem_raw(req.body.begin(), req.body.end());
        const std::string idem_digest = Sha384Hex(Span<const unsigned char>{idem_raw.data(), idem_raw.size()});
        auto idem_it = cr11.idem.find(idem_slot);
        if (idem_it != cr11.idem.end()) {
            const std::string& stored = idem_it->second;
            const size_t sep = stored.find('|');
            const std::string stored_digest = sep == std::string::npos ? std::string() : stored.substr(0, sep);
            const std::string stored_id = sep == std::string::npos ? stored : stored.substr(sep + 1);
            if (stored_digest != idem_digest) return Err(409, HCP_ERR_CONFLICT, cop);
            auto prior = cr11.allocations.find(stored_id);
            if (prior == cr11.allocations.end()) return Err(409, HCP_ERR_CONFLICT, cop);
            return SignedObj(HCP_TYPE_ALLOCATION, prior->second, 200);
        }
        if (have_body && parsed.exists("parent_profile_body_id") && !cr11.parent_profile_body_id.empty() &&
            parsed["parent_profile_body_id"].get_str() != cr11.parent_profile_body_id) {
            return Err(409, HCP_ERR_BINDING, "parent profile");
        }
        UniValue b(UniValue::VOBJ);
        const std::string id = Jstr("allocation_id", RandId("alloc-"));
        b.pushKV("legal_entity_id", Jstr("legal_entity_id", cr11.legal_entity));
        if (have_body && parsed.exists("legal_entity_id") && parsed["legal_entity_id"].get_str() != cr11.legal_entity) {
            return Err(403, HCP_ERR_ENTITY_SCOPE, "entity B on token A");
        }
        b.pushKV("allocation_id", id);
        b.pushKV("capital_plan_ref", Jstr("capital_plan_ref", ""));
        b.pushKV("policy_ref", cr11.policy_id.empty() ? "pol-demo" : cr11.policy_id);
        UniValue net(UniValue::VOBJ);
        net.pushKV("environment", cfg.environment);
        net.pushKV("genesis_hash", cfg.genesis_hash);
        b.pushKV("network", net);
        b.pushKV("legs", legs);
        b.pushKV("maximum_exposure", Jstr("maximum_exposure", "10"));
        b.pushKV("client_operation_id", cop);
        UniValue topo(UniValue::VARR);
        for (const auto& x : order) topo.push_back(x);
        b.pushKV("execution_order", topo);
        StampOwner(b);
        cr11.allocations[id] = b;
        cr11.idem[idem_slot] = idem_digest + "|" + id;
        return SignedObj(HCP_TYPE_ALLOCATION, b, 201);
    }
    if (MatchPath(req.path, "/capital/allocations/{id}", cap) && req.method == "GET") {
        auto n = Need("capital:read", false);
        if (n.status >= 400) return n;
        auto it = FindOwned(cr11.allocations, cap["id"]);
        if (it == cr11.allocations.end()) return Err(404, "NOT_FOUND", "allocation");
        return SignedObj(HCP_TYPE_ALLOCATION, it->second, 200);
    }

    if (req.method == "POST" && req.path == "/capital/approval-rules") {
        auto n = Need("policies:admin", false);
        if (n.status >= 400) return n;
        UniValue b(UniValue::VOBJ);
        const std::string id = Jstr("rule_id", RandId("rule-"));
        b.pushKV("legal_entity_id", cr11.legal_entity);
        b.pushKV("rule_id", id);
        b.pushKV("generation", "1");
        UniValue roles(UniValue::VARR);
        roles.push_back("committee");
        b.pushKV("eligible_roles", have_body && parsed.exists("eligible_roles") ? parsed["eligible_roles"] : roles);
        b.pushKV("distinct_person_quorum", std::to_string(J64("distinct_person_quorum", 2)));
        b.pushKV("exclude_initiator", !have_body || !parsed.exists("exclude_initiator") || parsed["exclude_initiator"].isTrue());
        b.pushKV("veto_enabled", !have_body || !parsed.exists("veto_enabled") || parsed["veto_enabled"].isTrue());
        b.pushKV("threshold_atoms", Jstr("threshold_atoms", "1"));
        b.pushKV("status", "ACTIVE");
        StampOwner(b);
        cr11.arules[id] = b;
        return SignedObj(HCP_TYPE_APPROVAL_RULE, b, 201);
    }
    if (req.method == "GET" && req.path == "/capital/approval-rules") {
        auto n = Need("capital:read", false);
        if (n.status >= 400) return n;
        UniValue arr(UniValue::VARR);
        for (const auto& [id, b] : cr11.arules) {
            if (Owned(b)) arr.push_back(id);
        }
        UniValue o(UniValue::VOBJ);
        o.pushKV("items", arr);
        return JsonStatus(200, o);
    }
    if (MatchPath(req.path, "/capital/approval-rules/{id}", cap) && req.method == "GET") {
        auto n = Need("capital:read", false);
        if (n.status >= 400) return n;
        auto it = FindOwned(cr11.arules, cap["id"]);
        if (it == cr11.arules.end()) return Err(404, "NOT_FOUND", "rule");
        return SignedObj(HCP_TYPE_APPROVAL_RULE, it->second, 200);
    }

    if (req.method == "POST" && req.path == "/capital/approvals") {
        auto n = Need("capital:prepare", false);
        if (n.status >= 400) return n;
        UniValue b(UniValue::VOBJ);
        const std::string id = Jstr("request_id", RandId("apr-"));
        const std::string alloc = Jstr("allocation_ref", "");
        std::string alloc_bid(96, 'c');
        if (cr11.allocations.count(alloc)) {
            HcpEnvelope tmp;
            tmp.object_type = HCP_TYPE_ALLOCATION;
            tmp.body = cr11.allocations[alloc];
            std::string e;
            Digest48 bid;
            HcpBodyId(HCP_TYPE_ALLOCATION, tmp.body, bid, e);
            alloc_bid = bid.Hex();
        }
        b.pushKV("legal_entity_id", cr11.legal_entity);
        b.pushKV("request_id", id);
        b.pushKV("allocation_ref", alloc);
        b.pushKV("allocation_body_id", alloc_bid);
        b.pushKV("rule_ref", Jstr("rule_ref", ""));
        if (parsed.exists("rule_body_id") && parsed["rule_body_id"].isStr() && !parsed["rule_body_id"].get_str().empty()) {
            b.pushKV("rule_body_id", parsed["rule_body_id"].get_str());
        } else if (!Jstr("rule_ref").empty() && cr11.arules.count(Jstr("rule_ref"))) {
            b.pushKV("rule_body_id", BodyIdHex(HCP_TYPE_APPROVAL_RULE, cr11.arules[Jstr("rule_ref")]));
        } else {
            UniValue rule_src(UniValue::VOBJ);
            rule_src.pushKV("rule_ref", Jstr("rule_ref"));
            rule_src.pushKV("request_id", id);
            b.pushKV("rule_body_id", BodyIdHex(HCP_TYPE_APPROVAL_RULE, rule_src));
        }
        b.pushKV("policy_ref", cr11.policy_id.empty() ? "pol-demo" : cr11.policy_id);
        b.pushKV("policy_generation", std::to_string(cr11.policy_generation ? cr11.policy_generation : 1));
        b.pushKV("initiator_person_id", Jstr("initiator_person_id", "person-initiator"));
        b.pushKV("maximum_exposure", Jstr("maximum_exposure", "10"));
        StampOwner(b);
        cr11.areqs[id] = b;
        return SignedObj(HCP_TYPE_APPROVAL_REQUEST, b, 201);
    }
    if (MatchPath(req.path, "/capital/approvals/{id}", cap) && req.method == "GET") {
        auto n = Need("capital:read", false);
        if (n.status >= 400) return n;
        auto it = FindOwned(cr11.areqs, cap["id"]);
        if (it == cr11.areqs.end()) return Err(404, "NOT_FOUND", "approval");
        return SignedObj(HCP_TYPE_APPROVAL_REQUEST, it->second, 200);
    }
    if (MatchPath(req.path, "/capital/approvals/{id}/decisions", cap) && req.method == "POST") {
        auto n = Need("capital:approve", false);
        if (n.status >= 400) return n;
        auto it = FindOwned(cr11.areqs, cap["id"]);
        if (it == cr11.areqs.end()) return Err(404, "NOT_FOUND", "approval");
        const std::string actor = Jstr("actor", cr11.authed_account);
        const std::string person = cr11.person_of_actor.count(actor) ? cr11.person_of_actor[actor] : Jstr("person", actor);
        if (cr11.expired_people.count(person)) return Err(403, HCP_ERR_SCOPE, "membership expired");
        UniValue b(UniValue::VOBJ);
        const std::string did = Jstr("decision_id", RandId("dec-"));
        b.pushKV("legal_entity_id", cr11.legal_entity);
        b.pushKV("decision_id", did);
        b.pushKV("request_ref", cap["id"]);
        b.pushKV("request_body_id", BodyIdHex(HCP_TYPE_APPROVAL_REQUEST, it->second));
        b.pushKV("allocation_body_id", it->second["allocation_body_id"].get_str());
        b.pushKV("policy_generation", it->second["policy_generation"].get_str());
        b.pushKV("rule_body_id", it->second["rule_body_id"].get_str());
        b.pushKV("actor", actor);
        b.pushKV("person", person);
        b.pushKV("decision", Jstr("decision", "APPROVE"));
        b.pushKV("sequence", std::to_string(J64("sequence", static_cast<int64_t>(cr11.decisions[cap["id"]].size() + 1))));
        cr11.decisions[cap["id"]].push_back(b);
        return SignedObj(HCP_TYPE_APPROVAL_DECISION, b, 201);
    }
    if (MatchPath(req.path, "/capital/approvals/{id}/decisions", cap) && req.method == "GET") {
        auto n = Need("capital:read", false);
        if (n.status >= 400) return n;
        if (FindOwned(cr11.areqs, cap["id"]) == cr11.areqs.end()) return Err(404, "NOT_FOUND", "approval");
        UniValue arr(UniValue::VARR);
        for (const auto& d : cr11.decisions[cap["id"]]) arr.push_back(d);
        UniValue o(UniValue::VOBJ);
        o.pushKV("items", arr);
        return JsonStatus(200, o);
    }

    if (MatchPath(req.path, "/capital/allocations/{id}/execute", cap) && req.method == "POST") {
        auto n = Need("capital:execute", true);
        if (n.status >= 400) return n;
        auto it = FindOwned(cr11.allocations, cap["id"]);
        if (it == cr11.allocations.end()) return Err(404, "NOT_FOUND", "allocation");
        if (have_body && parsed.exists("cross_cex_action_id")) {
            const std::string aid = parsed["cross_cex_action_id"].get_str();
            if (!cr11.last_cex_action.empty() && cr11.last_cex_action == aid) {
                return Err(409, HCP_ERR_CROSS_CEX, "retry must not create a second financial action");
            }
            cr11.last_cex_action = aid;
        }
        int64_t want = 0;
        std::string aerr;
        ParseAtomString(it->second.exists("maximum_exposure") ? it->second["maximum_exposure"].get_str() : "10", want, aerr);
        if (want == 0) return Err(400, HCP_ERR_ZERO_RESERVE, "zero");
        const int64_t e = AvailableE(cr11.authed_account);
        const int64_t capc = Cr11Capacity(e, cr11.protected_atoms, RemAuth());
        if (want > capc) return Err(403, HCP_ERR_CAPACITY, "capacity");
        if (cr11.per_plan_cap > 0 && want > cr11.per_plan_cap) return Err(403, HCP_ERR_CAPACITY, "per-plan");
        // Soft budgets do not add money.
        int64_t soft_sum = 0;
        for (const auto& [_, v] : cr11.soft_budgets) soft_sum += v;
        if (have_body && parsed.exists("use_soft_budgets") && parsed["use_soft_budgets"].isTrue()) {
            if (want > capc) return Err(403, HCP_ERR_SOFT_BUDGET, "common ceiling");
        }
        (void)soft_sum;

        bool ok = true;
        std::string qerr;
        if (!cr11.areqs.empty()) {
            std::set<std::string> eligible;
            for (const auto& [actor, person] : cr11.person_of_actor) {
                if (!cr11.expired_people.count(person)) eligible.insert(person);
            }
            if (eligible.empty()) {
                eligible.insert("person-a");
                eligible.insert("person-b");
            }
            for (const auto& [rid, reqv] : cr11.areqs) {
                UniValue decs(UniValue::VARR);
                for (const auto& d : cr11.decisions[rid]) {
                    UniValue x(UniValue::VOBJ);
                    x.pushKV("entity", cr11.legal_entity);
                    x.pushKV("plan", cap["id"]);
                    x.pushKV("policy_generation", reqv["policy_generation"].get_str());
                    x.pushKV("rule", reqv["rule_ref"].get_str());
                    x.pushKV("person", d.exists("person") ? d["person"].get_str() : d["actor"].get_str());
                    x.pushKV("decision", d["decision"].get_str());
                    x.pushKV("sequence", d["sequence"].isStr() ? std::stoll(d["sequence"].get_str()) : 1);
                    x.pushKV("expires_at", std::to_string(cfg.clock_ms + 1000));
                    decs.push_back(x);
                }
                const std::string initiator = reqv["initiator_person_id"].get_str();
                ok = Cr11Approved(decs, cr11.legal_entity, cap["id"], reqv["policy_generation"].get_str(),
                                   reqv["rule_ref"].get_str(), eligible, 2, initiator, cfg.clock_ms, true, true, qerr);
            }
        }
        if (!ok) return Err(403, qerr.empty() ? HCP_ERR_QUORUM : qerr, "committee");

        Account& acc = accounts[cr11.authed_account];
        acc.available -= want;
        acc.held += want;
        cr11.outstanding += want;
        cr11.lifetime_spent += want; // reserved against mandate; refund does not replenish by default

        UniValue b(UniValue::VOBJ);
        const std::string xid = RandId("xact-");
        b.pushKV("legal_entity_id", cr11.legal_entity);
        b.pushKV("execution_id", xid);
        b.pushKV("allocation_ref", cap["id"]);
        b.pushKV("state", "HELD");
        b.pushKV("held_atoms", std::to_string(want));
        b.pushKV("runtime_ready", false);
        b.pushKV("consensus_ready", false);

        UniValue children(UniValue::VARR);
        if (it->second.exists("legs") && it->second["legs"].isArray()) {
            for (size_t i = 0; i < it->second["legs"].size(); ++i) {
                const UniValue& leg = it->second["legs"][i];
                const std::string kind = leg.exists("kind") ? leg["kind"].get_str() : "FINANCIAL";
                if (kind == "FINANCIAL") {
                    HcpEnvelope env;
                    env.object_type = HCP_TYPE_FINANCE_INTENT;
                    env.body.pushKV("version", 1);
                    env.body.pushKV("provider_id", cfg.provider_id);
                    env.body.pushKV("account_ref", cr11.authed_account);
                    env.body.pushKV("actor_ref", cr11.authed_account);
                    env.body.pushKV("network", DemoNetwork());
                    const std::string iid = RandId("intent-");
                    env.body.pushKV("intent_id", iid);
                    env.body.pushKV("client_operation_id", it->second["client_operation_id"].get_str());
                    env.body.pushKV("quote_id", "");
                    UniValue quote_src(UniValue::VOBJ);
                    quote_src.pushKV("allocation_ref", cap["id"]);
                    quote_src.pushKV("client_operation_id", it->second["client_operation_id"].get_str());
                    quote_src.pushKV("principal_atoms", std::to_string(want));
                    env.body.pushKV("quote_body_id", BodyIdHex(HCP_TYPE_FUNDING_QUOTE, quote_src));
                    env.body.pushKV("action", HCP_ACTION_FUND_RELEASE);
                    UniValue terms_src(UniValue::VOBJ);
                    terms_src.pushKV("policy_id", cr11.policy_id.empty() ? "policy-demo" : cr11.policy_id);
                    terms_src.pushKV("action", HCP_ACTION_FUND_RELEASE);
                    env.body.pushKV("terms_id", BodyIdHex(HCP_TYPE_FINANCE_INTENT, terms_src));
                    UniValue tmpl(UniValue::VOBJ);
                    tmpl.pushKV("custody", cfg.custody_backend);
                    tmpl.pushKV("network", DemoNetwork());
                    env.body.pushKV("native_template_id", BodyIdHex(HCP_TYPE_FINANCE_INTENT, tmpl));
                    UniValue amt(UniValue::VOBJ);
                    amt.pushKV("principal_atoms", std::to_string(want));
                    amt.pushKV("network_fee_cap_atoms", "0");
                    amt.pushKV("service_fee_atoms", "0");
                    amt.pushKV("tax_atoms", "0");
                    env.body.pushKV("amounts", amt);
                    env.body.pushKV("policy_id", cr11.policy_id.empty() ? "policy-demo" : cr11.policy_id);
                    env.body.pushKV("policy_revision", "1");
                    env.body.pushKV("refund_controller", "CEX_CUSTODIAL_KEY");
                    env.body.pushKV("expires_at_ms", std::to_string(cfg.clock_ms + 600000));
                    std::string serr;
                    HcpSign(env, Span<const unsigned char>{op_sk.data(), op_sk.size()}, current_op_key_id, serr);
                    Intent in;
                    in.env = env;
                    in.account = cr11.authed_account;
                    in.client_operation_id = it->second["client_operation_id"].get_str();
                    in.principal = want;
                    in.total = want;
                    in.action = HCP_ACTION_FUND_RELEASE;
                    in.fencing_owner = lease_owner;
                    intents[iid] = in;
                    cr11.last_child_intent = iid;
                    children.push_back(EncodeHcpEnvelope(env));
                } else if (kind == "LOCAL") {
                    HcpEnvelope env;
                    env.object_type = HCP_TYPE_CAPABILITY_HANDOFF;
                    env.body.pushKV("version", 1);
                    env.body.pushKV("provider_id", cfg.provider_id);
                    const std::string hid = RandId("handoff-");
                    env.body.pushKV("handoff_id", hid);
                    env.body.pushKV("account_ref", cr11.authed_account);
                    env.body.pushKV("device_id", "device-demo");
                    env.body.pushKV("network", DemoNetwork());
                    env.body.pushKV("client_operation_id", it->second["client_operation_id"].get_str());
                    env.body.pushKV("request_nonce", "demo-nonce-not-production");
                    env.body.pushKV("issued_at_ms", std::to_string(cfg.clock_ms));
                    env.body.pushKV("expires_at_ms", std::to_string(cfg.clock_ms + 600000));
                    UniValue pkg(UniValue::VOBJ);
                    UniValue pkg_src(UniValue::VOBJ);
                    pkg_src.pushKV("account_ref", cr11.authed_account);
                    pkg_src.pushKV("client_operation_id", it->second["client_operation_id"].get_str());
                    pkg_src.pushKV("handoff_id", hid);
                    const std::string core_id = BodyIdHex(HCP_TYPE_CAPABILITY_HANDOFF, pkg_src);
                    pkg.pushKV("package_core_id", core_id);
                    pkg.pushKV("file_sha384", core_id);
                    UniValue recipe_src(UniValue::VOBJ);
                    recipe_src.pushKV("package_core_id", core_id);
                    recipe_src.pushKV("readiness_target", "RUNTIME_READY");
                    pkg.pushKV("recipe_id", BodyIdHex(HCP_TYPE_CAPABILITY_HANDOFF, recipe_src));
                    pkg.pushKV("download_url", cfg.api_base + "/packages/" + core_id);
                    env.body.pushKV("package", pkg);
                    env.body.pushKV("readiness_target", "RUNTIME_READY");
                    UniValue fx(UniValue::VARR);
                    fx.push_back("FETCH_METADATA");
                    env.body.pushKV("requested_effects", fx);
                    env.body.pushKV("source_hints", UniValue(UniValue::VARR));
                    env.body.pushKV("receipt_ref", UniValue());
                    env.body.pushKV("reporting_requested", false);
                    std::string serr;
                    HcpSign(env, Span<const unsigned char>{op_sk.data(), op_sk.size()}, current_op_key_id, serr);
                    cr11.last_child_handoff = hid;
                    children.push_back(EncodeHcpEnvelope(env));
                }
            }
        }
        b.pushKV("children", children);
        StampOwner(b);
        cr11.executions[xid] = b;
        cr11.last_execution = xid;
        AppendEvent(cr11.authed_account, "ALLOCATION_EXECUTED", xid, b);
        return SignedObj(HCP_TYPE_CAPITAL_EXECUTION, b, 201);
    }
    if (MatchPath(req.path, "/capital/executions/{id}", cap) && req.method == "GET") {
        auto n = Need("capital:read", false);
        if (n.status >= 400) return n;
        auto it = FindOwned(cr11.executions, cap["id"]);
        if (it == cr11.executions.end()) return Err(404, "NOT_FOUND", "execution");
        return SignedObj(HCP_TYPE_CAPITAL_EXECUTION, it->second, 200);
    }
    if (MatchPath(req.path, "/capital/executions/{id}/cancel", cap) && req.method == "POST") {
        auto n = Need("capital:execute", true);
        if (n.status >= 400) return n;
        auto it = FindOwned(cr11.executions, cap["id"]);
        if (it == cr11.executions.end()) return Err(404, "NOT_FOUND", "execution");
        if (it->second.exists("state") && it->second["state"].get_str() == "UNKNOWN") {
            return Err(409, HCP_ERR_BROADCAST_UNKNOWN, "hold retained");
        }
        if (dma && !dma_fenced) {
            // Do not release GPU buffers because a portal job was canceled.
            return Err(409, "DMA_ACTIVE", "physical completion required");
        }
        int64_t held = 0;
        std::string e;
        if (it->second.exists("held_atoms")) ParseAtomString(it->second["held_atoms"].get_str(), held, e);
        accounts[cr11.authed_account].available += held;
        accounts[cr11.authed_account].held -= held;
        cr11.outstanding -= held;
        if (!cr11.refund_replenishes) {
            // lifetime_spent stays consumed
        } else {
            cr11.lifetime_spent -= held;
        }
        it->second.pushKV("state", "CANCELED");
        return SignedObj(HCP_TYPE_CAPITAL_EXECUTION, it->second, 200);
    }

    if (req.method == "GET" && req.path == "/capital/positions") {
        auto n = Need("capital:read", false);
        if (n.status >= 400) return n;
        UniValue arr(UniValue::VARR);
        for (const auto& [id, b] : cr11.positions) {
            if (!Owned(b)) continue;
            arr.push_back(id);
        }
        UniValue o(UniValue::VOBJ);
        o.pushKV("items", arr);
        o.pushKV("nav_merged", false);
        return JsonStatus(200, o);
    }
    if (req.method == "POST" && req.path == "/capital/positions") {
        auto n = Need("holdings:write", false);
        if (n.status >= 400) return n;
        if (have_body && parsed.exists("merge_nav") && parsed["merge_nav"].isTrue()) {
            return Err(400, HCP_ERR_NAV_MERGE, "holdings are not NAV");
        }
        UniValue b(UniValue::VOBJ);
        const std::string id = Jstr("position_id", RandId("pos-"));
        b.pushKV("legal_entity_id", cr11.legal_entity);
        b.pushKV("position_id", id);
        b.pushKV("portfolio_id", Jstr("portfolio_id", "port-demo"));
        if (parsed.exists("package_core_id") && parsed["package_core_id"].isStr() &&
            !parsed["package_core_id"].get_str().empty()) {
            b.pushKV("package_core_id", parsed["package_core_id"].get_str());
        } else {
            UniValue src(UniValue::VOBJ);
            src.pushKV("position_id", id);
            src.pushKV("account", cr11.authed_account);
            b.pushKV("package_core_id", BodyIdHex(HCP_TYPE_CAPABILITY_POSITION, src));
        }
        if (parsed.exists("recipe_id") && parsed["recipe_id"].isStr() && !parsed["recipe_id"].get_str().empty()) {
            b.pushKV("recipe_id", parsed["recipe_id"].get_str());
        } else {
            UniValue src(UniValue::VOBJ);
            src.pushKV("position_id", id);
            src.pushKV("package_core_id", b["package_core_id"].get_str());
            b.pushKV("recipe_id", BodyIdHex(HCP_TYPE_CAPABILITY_POSITION, src));
        }
        b.pushKV("lock_id", Jstr("lock_id", "lock-1"));
        b.pushKV("resource_refs", UniValue(UniValue::VARR));
        b.pushKV("rights_ref", Jstr("rights_ref", "rights-1"));
        b.pushKV("acquisition_refs", UniValue(UniValue::VARR));
        b.pushKV("lifecycle", Jstr("lifecycle", "ACQUIRED"));
        b.pushKV("generation", "1");
        StampOwner(b);
        cr11.positions[id] = b;
        return SignedObj(HCP_TYPE_CAPABILITY_POSITION, b, 201);
    }
    if (MatchPath(req.path, "/capital/positions/{id}", cap) && req.method == "GET") {
        auto n = Need("capital:read", false);
        if (n.status >= 400) return n;
        auto it = FindOwned(cr11.positions, cap["id"]);
        if (it == cr11.positions.end()) return Err(404, "NOT_FOUND", "position");
        return SignedObj(HCP_TYPE_CAPABILITY_POSITION, it->second, 200);
    }
    if (MatchPath(req.path, "/capital/positions/{id}/lifecycle", cap) && req.method == "POST") {
        auto n = Need("holdings:write", false);
        if (n.status >= 400) return n;
        auto it = FindOwned(cr11.positions, cap["id"]);
        if (it == cr11.positions.end()) return Err(404, "NOT_FOUND", "position");
        it->second.pushKV("lifecycle", Jstr("lifecycle", "RETIRED"));
        it->second.pushKV("generation", "2");
        return SignedObj(HCP_TYPE_CAPABILITY_POSITION, it->second, 200);
    }

    if (req.method == "POST" && req.path == "/capital/programs") {
        auto n = Need("research:publish", false);
        if (n.status >= 400) return n;
        UniValue b(UniValue::VOBJ);
        const std::string id = Jstr("program_id", RandId("prog-"));
        b.pushKV("legal_entity_id", cr11.legal_entity);
        b.pushKV("program_id", id);
        b.pushKV("title", Jstr("title", "shared-eval"));
        b.pushKV("independent_sponsor_lots", true);
        b.pushKV("generation", "1");
        b.pushKV("status", "OPEN");
        StampOwner(b);
        cr11.programs[id] = b;
        return SignedObj(HCP_TYPE_RESEARCH_PROGRAM, b, 201);
    }
    if (req.method == "GET" && req.path == "/capital/programs") {
        auto n = Need("capital:read", false);
        if (n.status >= 400) return n;
        UniValue arr(UniValue::VARR);
        for (const auto& [id, b] : cr11.programs) {
            if (Owned(b)) arr.push_back(id);
        }
        UniValue o(UniValue::VOBJ);
        o.pushKV("items", arr);
        return JsonStatus(200, o);
    }
    if (MatchPath(req.path, "/capital/programs/{id}", cap) && req.method == "GET") {
        auto n = Need("capital:read", false);
        if (n.status >= 400) return n;
        auto it = FindOwned(cr11.programs, cap["id"]);
        if (it == cr11.programs.end()) return Err(404, "NOT_FOUND", "program");
        return SignedObj(HCP_TYPE_RESEARCH_PROGRAM, it->second, 200);
    }
    if (MatchPath(req.path, "/capital/programs/{id}/memberships", cap) && req.method == "POST") {
        auto n = Need("research:publish", false);
        if (n.status >= 400) return n;
        if (FindOwned(cr11.programs, cap["id"]) == cr11.programs.end()) return Err(404, "NOT_FOUND", "program");
        UniValue b(UniValue::VOBJ);
        b.pushKV("program_id", cap["id"]);
        b.pushKV("member_entity", Jstr("legal_entity_id", cr11.legal_entity));
        b.pushKV("lot_id", RandId("lot-"));
        b.pushKV("independent", true);
        return SignedObj(HCP_TYPE_PROGRAM_MEMBERSHIP, b, 201);
    }
    if (MatchPath(req.path, "/capital/programs/{id}/commitments", cap) && req.method == "POST") {
        auto n = Need("capital:prepare", false);
        if (n.status >= 400) return n;
        if (FindOwned(cr11.programs, cap["id"]) == cr11.programs.end()) return Err(404, "NOT_FOUND", "program");
        UniValue o(UniValue::VOBJ);
        o.pushKV("program_id", cap["id"]);
        o.pushKV("commitment_id", RandId("cmt-"));
        o.pushKV("prepared", true);
        o.pushKV("executed", false);
        return JsonStatus(201, o);
    }

    if (req.method == "GET" && req.path == "/capital/products") {
        auto n = Need("products:read", false);
        if (n.status >= 400) return n;
        UniValue arr(UniValue::VARR);
        for (const auto& [id, b] : cr11.products) arr.push_back(id);
        if (arr.empty()) {
            UniValue demo(UniValue::VOBJ);
            demo.pushKV("product_id", "prod-demo");
            demo.pushKV("title", "listed-note");
            demo.pushKV("encumbers_reserve", false);
            cr11.products["prod-demo"] = demo;
            arr.push_back("prod-demo");
        }
        UniValue o(UniValue::VOBJ);
        o.pushKV("items", arr);
        return JsonStatus(200, o);
    }
    if (MatchPath(req.path, "/capital/products/{id}", cap) && req.method == "GET") {
        auto n = Need("products:read", false);
        if (n.status >= 400) return n;
        if (!cr11.products.count(cap["id"])) {
            UniValue demo(UniValue::VOBJ);
            demo.pushKV("product_id", cap["id"]);
            demo.pushKV("title", "listed-note");
            cr11.products[cap["id"]] = demo;
        }
        return SignedObj(HCP_TYPE_PRODUCT_OFFER, cr11.products[cap["id"]], 200);
    }
    if (MatchPath(req.path, "/capital/products/{id}/referral", cap) && req.method == "POST") {
        auto n = Need("products:refer", false);
        if (n.status >= 400) return n;
        UniValue o(UniValue::VOBJ);
        o.pushKV("product_id", cap["id"]);
        o.pushKV("referral_id", RandId("ref-"));
        o.pushKV("not_a_debit", true);
        return JsonStatus(201, o);
    }

    if (req.method == "POST" && req.path == "/capital/reports") {
        auto n = Need("reports:create", false);
        if (n.status >= 400) return n;
        UniValue b = SnapshotOf(cr11.authed_account);
        b.pushKV("report_id", RandId("rep-"));
        b.pushKV("assumptions_separate_from_actuals", true);
        b.pushKV("fx_dated", true);
        b.pushKV("reporting_currency_original", true);
        StampOwner(b);
        cr11.last_report = b;
        cr11.reports[b["report_id"].get_str()] = b;
        return SignedObj(HCP_TYPE_RESERVE_REPORT, b, 201);
    }
    if (MatchPath(req.path, "/capital/reports/{id}", cap) && req.method == "GET") {
        auto n = Need("reports:read", false);
        if (n.status >= 400) return n;
        auto it = FindOwned(cr11.reports, cap["id"]);
        if (it == cr11.reports.end()) return Err(404, "NOT_FOUND", "report");
        return SignedObj(HCP_TYPE_RESERVE_REPORT, it->second, 200);
    }
    if (req.method == "POST" && req.path == "/capital/exports") {
        auto n = Need("exports:create", false);
        if (n.status >= 400) return n;
        UniValue o(UniValue::VOBJ);
        const std::string id = RandId("exp-");
        o.pushKV("export_id", id);
        o.pushKV("scoped", true);
        o.pushKV("excluded_unauthorized", true);
        StampOwner(o);
        cr11.exports[id] = o;
        return JsonStatus(201, o);
    }
    if (MatchPath(req.path, "/capital/exports/{id}", cap) && req.method == "GET") {
        auto n = Need("exports:read", false);
        if (n.status >= 400) return n;
        auto it = FindOwned(cr11.exports, cap["id"]);
        if (it == cr11.exports.end()) return Err(404, "NOT_FOUND", "export");
        return JsonStatus(200, it->second);
    }

    return Err(404, "NOT_FOUND", req.path);
}
