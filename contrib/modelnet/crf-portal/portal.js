/* BTX Cognitive Reserve v1.1 portal.
 * Catalogue / reserve / committee shell. Not a wallet.
 * No custody keys, no native wallet RPC, no token in URI,
 * automatic_spend_atoms stays 0, family view is not debit authority.
 * HTTP 202 / lost broadcast → reconciliation; never retry-new-payment.
 */
(function () {
  "use strict";

  var TOKEN_NEEDLES = [
    "access_token",
    "refresh_token",
    "id_token",
    "dpop",
    "authorization",
    "bearer",
    "client_secret",
    "client_assertion",
  ];
  var LAB_API_BASE = "https://exchange.example/btx/hcp/v1";
  var LAB_VERIFIER = "pkce-verifier-demo-aaaa";
  var DRAFT_KEY = "cr11_draft_ids";
  var ORIGIN_KEY = "cr11_base";

  var ENTITIES = {
    company: { label: "Example Operating Co.", id: "le-company" },
    trust: { label: "Example Family Trust", id: "le-trust" },
    foundation: { label: "Example Research Foundation", id: "le-foundation" },
  };

  var FIXTURE_SNAPSHOT = {
    scope: "portfolio:le-demo",
    snapshot_id: "snap-fixture",
    available_atoms: "45000",
    protected_atoms: "20000",
    remaining_authority_atoms: "10000",
    allocation_capacity_atoms: "10000",
    existing_hold_atoms: "0",
    committed_atoms: "8500",
    refund_pending_atoms: "0",
    cognitive_holdings_atoms: "24",
    nav_merged: false,
    family_view_debit: false,
  };

  var state = {
    view: "overview",
    lastClientOp: "op-cr11-portal-01",
    last202: false,
    executing: false,
    financial: false,
    local: false,
    planned: false,
    jkt: "",
    available: 45000,
    familyView: false,
    planOpener: null,
    draft: {
      workload_id: "",
      comparison_id: "",
      plan_id: "",
      allocation_id: "",
      approval_id: "",
      execution_id: "",
      program_id: "",
      maximum_exposure: "10",
    },
  };

  function $(id) {
    return document.getElementById(id);
  }

  function announce(t) {
    $("announcement").textContent = t;
  }

  function pretty(v) {
    return JSON.stringify(v, null, 2);
  }

  function log(msg) {
    var el = $("log");
    if (el) el.textContent = msg;
  }

  function canonicalJSON(value) {
    if (value === null) return "null";
    var t = typeof value;
    if (t === "number") {
      if (!Number.isInteger(value)) throw new Error("floats prohibited");
      return String(value);
    }
    if (t === "boolean") return value ? "true" : "false";
    if (t === "string") return JSON.stringify(value);
    if (Array.isArray(value)) {
      return "[" + value.map(canonicalJSON).join(",") + "]";
    }
    if (t === "object") {
      var keys = Object.keys(value).sort();
      var parts = [];
      for (var i = 0; i < keys.length; i++) {
        var k = keys[i];
        if (value[k] === undefined) continue;
        parts.push(JSON.stringify(k) + ":" + canonicalJSON(value[k]));
      }
      return "{" + parts.join(",") + "}";
    }
    throw new Error("unsupported JSON type");
  }

  function uriContainsToken(uri) {
    var lower = String(uri).toLowerCase();
    for (var i = 0; i < TOKEN_NEEDLES.length; i++) {
      if (lower.indexOf(TOKEN_NEEDLES[i]) !== -1) return TOKEN_NEEDLES[i];
    }
    return null;
  }

  function stripTokenFromLocation() {
    var href = String(location.href || "");
    var hit = uriContainsToken(href);
    if (!hit) return;
    var note = $("uri-strip");
    note.hidden = false;
    note.textContent =
      "Refused token-in-URI: found " +
      hit +
      " on this page URL. Tokens were dropped from the address bar. Use the gateway header field only.";
    if (history && history.replaceState) {
      history.replaceState(null, "", location.pathname + (location.hash || ""));
    }
    $("token").value = "";
    announce("Token removed from the address bar");
  }

  function localeTag() {
    return $("locale").value === "ja" ? "ja-JP" : "en-US";
  }

  function fmtDisplay(n) {
    var num = typeof n === "number" ? n : Number(String(n).replace(/,/g, ""));
    if (!isFinite(num)) return String(n);
    return new Intl.NumberFormat(localeTag(), { maximumFractionDigits: 0 }).format(num);
  }

  function atomsOf(el) {
    return String(el.value || "").trim();
  }

  function entityMeta() {
    return ENTITIES[$("entity").value] || ENTITIES.company;
  }

  function portfolioId() {
    return ($("portfolio").value || "demo").trim();
  }

  function isAdviser() {
    return $("persona").value === "adviser";
  }

  function canDebit() {
    return !isAdviser() && !state.familyView && !state.last202 && !state.executing;
  }

  function requireOk(rec, step) {
    if (!rec || rec.status >= 400) {
      throw new Error(step + " HTTP " + (rec ? rec.status : "n/a"));
    }
    return rec;
  }

  function baseUrl() {
    var v = ($("base").value || "").trim().replace(/\/$/, "");
    if (!v) v = "http://127.0.0.1:18781";
    try {
      localStorage.setItem(ORIGIN_KEY, v);
    } catch (e) {}
    return v;
  }

  function accessToken() {
    return ($("token").value || "").trim();
  }

  function saveDraft() {
    try {
      sessionStorage.setItem(
        DRAFT_KEY,
        JSON.stringify({
          draft: state.draft,
          lastClientOp: state.lastClientOp,
          planned: state.planned,
          financial: state.financial,
          local: state.local,
          entity: $("entity").value,
          portfolio: portfolioId(),
        })
      );
    } catch (e) {}
  }

  function loadDraft() {
    try {
      var raw = sessionStorage.getItem(DRAFT_KEY);
      if (!raw) return;
      var o = JSON.parse(raw);
      if (o.draft) state.draft = Object.assign(state.draft, o.draft);
      if (o.lastClientOp) state.lastClientOp = o.lastClientOp;
      if (o.entity && ENTITIES[o.entity]) $("entity").value = o.entity;
      if (o.portfolio) {
        ensurePortfolioOption(o.portfolio);
        $("portfolio").value = o.portfolio;
      }
      state.planned = !!o.planned;
      state.financial = !!o.financial;
      state.local = !!o.local;
    } catch (e) {}
  }

  function ensurePortfolioOption(id) {
    var sel = $("portfolio");
    for (var i = 0; i < sel.options.length; i++) {
      if (sel.options[i].value === id) return;
    }
    var opt = document.createElement("option");
    opt.value = id;
    opt.textContent = id;
    sel.appendChild(opt);
  }

  function sha256hex(str) {
    var data = new TextEncoder().encode(str);
    return crypto.subtle.digest("SHA-256", data).then(function (buf) {
      var bytes = new Uint8Array(buf);
      var hex = "";
      for (var i = 0; i < bytes.length; i++) {
        hex += bytes[i].toString(16).padStart(2, "0");
      }
      return hex;
    });
  }

  function dpopProof(method, path) {
    var tok = accessToken();
    var htu = LAB_API_BASE + path;
    var proof = {
      htm: method,
      htu: htu,
      iat: String(Date.now()),
      jti: "jti-" + Math.random().toString(16).slice(2) + Date.now().toString(16),
      lab_only: true,
    };
    if (state.jkt) proof.jkt = state.jkt;
    if (!tok) return Promise.resolve(proof);
    return sha256hex(tok).then(function (ath) {
      proof.ath = ath;
      return proof;
    });
  }

  function unwrap(rec) {
    var p = rec && rec.body;
    if (p && p.body && typeof p.body === "object" && !Array.isArray(p.body)) return p.body;
    return p || {};
  }

  function itemsOf(rec) {
    var b = rec && rec.body;
    if (b && Array.isArray(b.items)) return b.items;
    var u = unwrap(rec);
    if (u && Array.isArray(u.items)) return u.items;
    return [];
  }

  function isUnknown(rec) {
    if (!rec) return false;
    if (rec.status === 202 || rec.unknown) return true;
    var b = unwrap(rec);
    var st = String(b.state || b.code || "");
    return (
      st === "UNKNOWN" ||
      st === "BROADCAST_UNKNOWN" ||
      st === "RECONCILIATION_REQUIRED"
    );
  }

  function showUnknown(rec) {
    state.last202 = true;
    $("unknown-banner").hidden = false;
    $("execute").disabled = true;
    $("finance-timeline").innerHTML =
      'Capital plan: <span class="status">Transaction outcome is being reconciled. Hold retained.</span>';
    $("activity-out").textContent = pretty({
      unknown: true,
      http_202_is_unknown: true,
      retry_new_payment: false,
      safe_next_action: "View existing operation",
      record: rec || { fixture: true, state: "BROADCAST_UNKNOWN" },
    });
    announce("Broadcast outcome unknown. Reconcile the existing operation. No new payment.");
  }

  /**
   * Typed CR11/HCP fetch against btx-hcpd origin.
   * Paths are /reserve, /capital, /health, /lab, /capabilities — never token in URI.
   */
  function cr11Request(method, path, bodyObj) {
    var url = baseUrl() + path;
    var hit = uriContainsToken(url);
    if (hit) return Promise.reject(new Error("Refused: " + hit + " must not appear in the request URI"));
    var headers = { Accept: "application/json" };
    var init = { method: method, headers: headers, credentials: "omit", cache: "no-store", redirect: "error" };
    var tok = accessToken();
    if (tok) headers.Authorization = "Bearer " + tok;
    var needDpop = tok && (method === "POST" || method === "PUT" || method === "PATCH");
    var bodyP = Promise.resolve();
    if (bodyObj !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = canonicalJSON(bodyObj);
    }
    var dpopP = needDpop ? dpopProof(method, path) : Promise.resolve(null);
    return dpopP.then(function (proof) {
      if (proof) headers.DPoP = canonicalJSON(proof);
      return fetch(url, init).then(function (res) {
        return res.text().then(function (text) {
          var parsed = null;
          try {
            parsed = text ? JSON.parse(text) : {};
          } catch (e) {
            parsed = { raw: text };
          }
          var rec = {
            status: res.status,
            unknown: res.status === 202,
            body: parsed,
            path: path,
            method: method,
          };
          log(method + " " + path + " → HTTP " + res.status + "\n" + pretty(parsed));
          if (res.status === 401) {
            $("session-note").hidden = false;
            $("session-note").textContent =
              "Session expired or unauthenticated. Draft identifiers are retained. Re-authenticate, then the current plan and permissions will be rechecked. Tokens stay out of the URL.";
            announce("Re-authentication required. Draft retained.");
          }
          if (isUnknown(rec)) showUnknown(rec);
          return rec;
        });
      });
    });
  }

  function catchHttp(err) {
    var msg = String(err && err.message ? err.message : err);
    log(msg);
    announce(msg);
  }

  function show(id) {
    var sections = document.querySelectorAll("section.view");
    for (var i = 0; i < sections.length; i++) {
      sections[i].hidden = sections[i].id !== id;
    }
    var buttons = document.querySelectorAll("[data-page]");
    for (var j = 0; j < buttons.length; j++) {
      if (buttons[j].getAttribute("data-page") === id) {
        buttons[j].setAttribute("aria-current", "page");
      } else {
        buttons[j].removeAttribute("aria-current");
      }
    }
    state.view = id;
    if (location.hash !== "#" + id && history && history.replaceState) {
      history.replaceState(null, "", "#" + id);
    }
    var h1 = document.querySelector("#" + id + " h1");
    if (h1) h1.focus();
    announce(id + " view opened");
  }

  function syncPayerCopy() {
    var label = entityMeta().label;
    document.querySelectorAll(".entity-label").forEach(function (el) {
      el.textContent = label;
    });
    var pLabel = $("portfolio").selectedOptions[0]
      ? $("portfolio").selectedOptions[0].text
      : portfolioId();
    $("portfolio-label").textContent = pLabel;
    $("pkt-portfolio").textContent = pLabel;
    $("dialog-portfolio").textContent = pLabel;
    $("family-debit-flag").textContent = "false";
  }

  function applySnapshot(snap, source) {
    var avail = snap.available_atoms != null ? snap.available_atoms : String(state.available);
    var prot = snap.protected_atoms != null ? snap.protected_atoms : atomsOf($("floor"));
    var rem = snap.remaining_authority_atoms != null ? snap.remaining_authority_atoms : atomsOf($("authority"));
    var cap = snap.allocation_capacity_atoms;
    var committed = snap.committed_atoms != null ? snap.committed_atoms : "8500";
    var holdings = snap.cognitive_holdings_atoms != null ? snap.cognitive_holdings_atoms : "24";
    state.available = Number(avail) || state.available;
    $("floor").value = String(prot);
    $("authority").value = String(rem);
    $("ov-available-canon").textContent = String(avail);
    $("ov-available").textContent = fmtDisplay(avail) + " BTX";
    $("ov-committed").textContent = fmtDisplay(committed) + " BTX";
    $("ov-holdings").textContent = fmtDisplay(holdings) + " recipes";
    document.querySelectorAll(".floor-label").forEach(function (x) {
      x.textContent = fmtDisplay(prot);
    });
    var capN =
      cap != null
        ? Number(cap)
        : Math.max(0, Math.min(state.available - Number(prot || 0), Number(rem || 0)));
    $("capacity").textContent = fmtDisplay(capN) + " BTX";
    $("capacity-sentence").textContent =
      "This portfolio can allocate up to " +
      fmtDisplay(capN) +
      " BTX while retaining its protected reserve. Source: " +
      source +
      ".";
    $("pkt-remaining").textContent = String(rem);
    if (snap.family_view_debit === true) {
      $("family-debit-flag").textContent = "true (gateway error — this portal treats family view as non-debit)";
    }
    refreshApprovals();
  }

  function localCapacity() {
    var floor = Math.max(0, Number(atomsOf($("floor"))) || 0);
    var a = Math.max(0, Number(atomsOf($("authority"))) || 0);
    var cap = Math.max(0, Math.min(state.available - floor, a));
    $("capacity").textContent = fmtDisplay(cap) + " BTX";
    document.querySelectorAll(".floor-label").forEach(function (x) {
      x.textContent = fmtDisplay(floor);
    });
    $("capacity-sentence").textContent =
      "This portfolio can allocate up to " +
      fmtDisplay(cap) +
      " BTX while retaining its protected reserve.";
    return cap;
  }

  function compare() {
    var tasks = Number($("tasks").value) || 0;
    var price = Number($("service-price").value) || 0;
    var up = Number($("upfront").value) || 0;
    var an = Number($("annual").value) || 0;
    $("service-total").textContent = "$" + fmtDisplay(tasks * price * 3);
    $("local-total").textContent = "$" + fmtDisplay(up + an * 3);
  }

  function refreshApprovals() {
    var adviser = isAdviser();
    var family = state.familyView;
    $("financial-approve").disabled = !state.planned || adviser || family || state.financial;
    $("local-approve").disabled = !state.planned || state.local;
    $("execute").disabled =
      !state.planned ||
      !state.financial ||
      !state.local ||
      adviser ||
      family ||
      state.last202 ||
      state.executing;
    var parts = [];
    parts.push(state.financial ? "Financial review recorded." : "Financial review pending.");
    parts.push(state.local ? "Local permission recorded." : "Local permission pending.");
    if (adviser) parts.push("Adviser role cannot debit or execute.");
    if (family) parts.push("Group view is not debit authority.");
    if (state.last202) parts.push("UNKNOWN broadcast: reconcile existing operation; no new payment.");
    $("approval-status").textContent = parts.join(" ");
    $("pkt-cop").textContent = state.lastClientOp;
    $("pkt-exposure").textContent = state.draft.maximum_exposure || "—";
  }

  function resetPacket(reason) {
    state.planned = false;
    state.financial = false;
    state.local = false;
    state.executing = false;
    $("approval-title").textContent = "No plan awaiting review";
    $("approval-description").textContent =
      reason || "Create a capital plan to populate the decision packet.";
    $("pkt-objective").textContent = "—";
    refreshApprovals();
    saveDraft();
  }

  function fillPacketFromDraft() {
    var payer = entityMeta().label;
    $("approval-title").textContent = "Document-workload capital plan";
    $("approval-description").textContent =
      "One decision packet for " +
      payer +
      " / " +
      portfolioId() +
      ". Financial exposure, conversion and native terms require exact production records; local effects require independent permission.";
    $("pkt-objective").textContent = "own-then-run · accepted tasks";
    $("pkt-exposure").textContent = state.draft.maximum_exposure;
    $("pkt-cop").textContent = state.lastClientOp;
    refreshApprovals();
  }

  function openPlan() {
    state.planOpener = document.activeElement;
    compare();
    $("plan-dialog").showModal();
    $("tasks").focus();
  }

  function closePlan() {
    $("plan-dialog").close();
    if (state.planOpener && typeof state.planOpener.focus === "function") {
      state.planOpener.focus();
    }
  }

  function createPacketLive() {
    var cop = state.lastClientOp;
    var exposure = state.draft.maximum_exposure || "10";
    return cr11Request("POST", "/capital/workloads", {
      objective: "accepted-tasks",
      annual_accepted_tasks: atomsOf($("tasks")),
      horizon_months: 36,
    })
      .then(function (wl) {
        requireOk(wl, "POST /capital/workloads");
        var b = unwrap(wl);
        if (b.workload_id) state.draft.workload_id = b.workload_id;
        return cr11Request("POST", "/capital/comparisons", {
          annual_tasks: atomsOf($("tasks")),
          service_per_task: atomsOf($("service-price")),
          years: 3,
          upfront: atomsOf($("upfront")),
          annual_local: atomsOf($("annual")),
          quality_equivalent: true,
          inputs_known: true,
        });
      })
      .then(function (tco) {
        requireOk(tco, "POST /capital/comparisons");
        var b = unwrap(tco);
        if (b.comparison_id) state.draft.comparison_id = b.comparison_id;
        return cr11Request("POST", "/capital/plans", {
          objective: "own-then-run",
          comparison_ref: state.draft.comparison_id,
          route: "OWN_THEN_RUN",
          maximum_exposure: exposure,
          expected_outcome: "LOCAL_READY",
        });
      })
      .then(function (plan) {
        requireOk(plan, "POST /capital/plans");
        var b = unwrap(plan);
        if (b.plan_id) state.draft.plan_id = b.plan_id;
        return cr11Request("POST", "/capital/allocations", {
          client_operation_id: cop,
          capital_plan_ref: state.draft.plan_id,
          maximum_exposure: exposure,
        });
      })
      .then(function (alloc) {
        requireOk(alloc, "POST /capital/allocations");
        var b = unwrap(alloc);
        if (b.allocation_id) state.draft.allocation_id = b.allocation_id;
        if (b.client_operation_id) state.lastClientOp = b.client_operation_id;
        return alloc;
      });
  }

  function afterPacketCreated(source) {
    state.planned = true;
    state.financial = false;
    state.local = false;
    fillPacketFromDraft();
    saveDraft();
    closePlan();
    show("approvals");
    announce("Review packet created from " + source);
  }

  function bindDialogFocusTrap() {
    var dlg = $("plan-dialog");
    dlg.addEventListener("keydown", function (ev) {
      if (ev.key !== "Tab") return;
      var focusable = dlg.querySelectorAll("button, input, select, textarea, [href]");
      if (!focusable.length) return;
      var first = focusable[0];
      var last = focusable[focusable.length - 1];
      if (ev.shiftKey && document.activeElement === first) {
        ev.preventDefault();
        last.focus();
      } else if (!ev.shiftKey && document.activeElement === last) {
        ev.preventDefault();
        first.focus();
      }
    });
  }

  function renderLinks(items) {
    var box = $("entity-links");
    if (!items || !items.length) {
      box.textContent = "No entity links. Group visibility never pools funds.";
      return;
    }
    box.textContent = "";
    items.forEach(function (it) {
      var body = it && it.body ? it.body : it;
      var p = document.createElement("p");
      p.className = "small";
      p.textContent =
        (body.parent_entity_id || "") +
        " → " +
        (body.child_entity_id || body) +
        " (" +
        (body.relationship || "link") +
        ") status=" +
        (body.status || "listed") +
        " — visibility only";
      box.appendChild(p);
    });
  }

  function bind() {
    stripTokenFromLocation();
    try {
      var saved = localStorage.getItem(ORIGIN_KEY);
      if (saved) $("base").value = saved;
    } catch (e) {}
    loadDraft();
    syncPayerCopy();
    applySnapshot(FIXTURE_SNAPSHOT, "offline fixture");
    if (state.planned) fillPacketFromDraft();
    refreshApprovals();
    bindDialogFocusTrap();

    var hash = (location.hash || "").replace(/^#/, "");
    if (hash && document.getElementById(hash)) show(hash);
    window.addEventListener("hashchange", function () {
      var h = (location.hash || "").replace(/^#/, "");
      if (h && document.getElementById(h) && h !== state.view) show(h);
    });

    document.querySelectorAll("[data-page]").forEach(function (b) {
      b.addEventListener("click", function () {
        show(b.getAttribute("data-page"));
      });
    });
    document.querySelectorAll("[data-go]").forEach(function (b) {
      b.addEventListener("click", function () {
        show(b.getAttribute("data-go"));
      });
    });
    document.querySelectorAll("[data-start]").forEach(function (b) {
      b.addEventListener("click", openPlan);
    });
    document.querySelectorAll("[data-base]").forEach(function (b) {
      b.addEventListener("click", function () {
        $("base").value = b.getAttribute("data-base");
        baseUrl();
        announce("Gateway origin set to " + $("base").value);
      });
    });

    $("entity").addEventListener("change", function () {
      syncPayerCopy();
      resetPacket("Legal payer changed; previous review cleared. The new packet will name this payer and portfolio.");
      announce("Legal payer changed; previous review cleared");
    });
    $("portfolio").addEventListener("change", function () {
      syncPayerCopy();
      resetPacket("Portfolio changed; previous review cleared.");
    });
    $("persona").addEventListener("change", refreshApprovals);
    $("locale").addEventListener("change", function () {
      document.documentElement.lang = $("locale").value === "ja" ? "ja" : "en";
      localCapacity();
      compare();
      applySnapshot(
        {
          available_atoms: $("ov-available-canon").textContent,
          protected_atoms: atomsOf($("floor")),
          remaining_authority_atoms: atomsOf($("authority")),
          committed_atoms: "8500",
          cognitive_holdings_atoms: "24",
        },
        "locale display only; canonical atoms unchanged"
      );
    });
    $("family-view").addEventListener("change", function () {
      state.familyView = $("family-view").checked;
      $("family-banner").hidden = !state.familyView;
      refreshApprovals();
      announce(
        state.familyView
          ? "Group overview enabled. This view cannot debit."
          : "Acting as the selected legal payer."
      );
    });
    $("floor").addEventListener("input", localCapacity);
    $("authority").addEventListener("input", localCapacity);
    ["tasks", "service-price", "upfront", "annual"].forEach(function (id) {
      $(id).addEventListener("input", compare);
    });

    $("policy-preview").addEventListener("click", function () {
      localCapacity();
      var body = {
        protected_atoms: atomsOf($("floor")),
        replenishment_mode: "SUGGEST",
        required_quote: "1",
        price_quote_per_coin: "1",
        observed_at: Date.now(),
        max_age: 100000,
      };
      $("policy-status").textContent =
        "Preview created. SUGGEST mode executes 0 orders. This demonstration does not change an accepted policy or execute a trade.";
      announce("Reserve policy preview created");
      cr11Request("POST", "/reserve/replenishment/plans", body)
        .then(function (rec) {
          var b = rec.body || {};
          $("policy-status").textContent =
            "Live replenishment plan: executed_orders=" +
            String(b.executed_orders != null ? b.executed_orders : unwrap(rec).executed_orders) +
            ". SUGGEST must stay 0. No trade executed by preview.";
        })
        .catch(function () {
          $("policy-status").textContent =
            "Gateway unreachable or unauthenticated. Offline preview only — no trade executed.";
        });
    });

    $("create-policy").addEventListener("click", function () {
      cr11Request("POST", "/reserve/policies", {
        protected_atoms: atomsOf($("floor")),
        replenishment_mode: "SUGGEST",
      })
        .then(function (rec) {
          $("policy-status").textContent = "Policy POST HTTP " + rec.status + " · " + pretty(unwrap(rec));
        })
        .catch(catchHttp);
    });

    $("load-snapshot").addEventListener("click", function () {
      cr11Request("GET", "/reserve/portfolios/" + encodeURIComponent(portfolioId()) + "/snapshot")
        .then(function (rec) {
          var b = unwrap(rec);
          if (rec.status >= 400) {
            applySnapshot(FIXTURE_SNAPSHOT, "fixture (live snapshot HTTP " + rec.status + ")");
            return;
          }
          applySnapshot(b, "GET /reserve/portfolios/{id}/snapshot");
        })
        .catch(function (err) {
          applySnapshot(FIXTURE_SNAPSHOT, "fixture (live fetch failed)");
          catchHttp(err);
        });
    });
    $("refresh-overview").addEventListener("click", function () {
      $("load-snapshot").click();
      cr11Request("GET", "/reserve/entities/links")
        .then(function (rec) {
          renderLinks(itemsOf(rec));
        })
        .catch(function () {
          renderLinks([]);
        });
      cr11Request("GET", "/reserve/portfolios")
        .then(function (rec) {
          var items = itemsOf(rec);
          items.forEach(function (it) {
            var id = typeof it === "string" ? it : it.portfolio_id || (it.body && it.body.portfolio_id);
            if (id) ensurePortfolioOption(id);
          });
          if (rec.body && rec.body.family_view_debit) {
            $("family-debit-flag").textContent = "gateway claimed debit — portal still refuses";
          }
        })
        .catch(function () {});
    });

    $("list-products").addEventListener("click", function () {
      cr11Request("GET", "/capital/products")
        .then(function (rec) {
          $("products-out").textContent = pretty(rec.body);
        })
        .catch(catchHttp);
    });
    $("product-referral").addEventListener("click", function () {
      cr11Request("POST", "/capital/products/prod-demo/referral", {
        client_operation_id: "ref-" + state.lastClientOp,
      })
        .then(function (rec) {
          $("products-out").textContent = pretty({
            referral: rec.body,
            not_a_debit: true,
            not_a_loan: true,
          });
        })
        .catch(catchHttp);
    });

    $("free-acquire").addEventListener("click", function () {
      $("free-status").textContent =
        "Public capability prepared for a finite local grant. No exchange payment, new wallet, or forced subscription is required. The local client verifies the package. automatic_spend_atoms stays 0.";
      announce("Free local handoff prepared. No CEX payment.");
      cr11Request("POST", "/capabilities/search", { q: "document.extraction" })
        .then(function (rec) {
          $("free-status").textContent =
            "Catalogue HTTP " +
            rec.status +
            ". Public acquisition does not require a monetary wallet, CEX toll, or subscription. Hits may be empty (incomplete=true).";
        })
        .catch(function () {
          $("free-status").textContent =
            "Gateway unreachable. Offline public journey still requires no CEX payment, new wallet, or subscription. Prepare on the local client under its existing finite grant.";
        });
    });
    $("search-public").addEventListener("click", function () {
      cr11Request("POST", "/capabilities/search", { q: "document.classification" })
        .then(function (rec) {
          $("free-status").textContent = pretty({
            search: rec.body,
            compulsory_cex_payment: false,
            new_wallet: false,
            forced_subscription: false,
          });
        })
        .catch(catchHttp);
    });
    $("list-positions").addEventListener("click", function () {
      cr11Request("GET", "/capital/positions")
        .then(function (rec) {
          $("positions-out").textContent = pretty(rec.body);
        })
        .catch(catchHttp);
    });

    $("list-programs").addEventListener("click", function () {
      cr11Request("GET", "/capital/programs")
        .then(function (rec) {
          $("program-out").textContent = pretty(rec.body);
        })
        .catch(catchHttp);
    });
    $("create-program").addEventListener("click", function () {
      cr11Request("POST", "/capital/programs", { title: "foundation" })
        .then(function (rec) {
          var b = unwrap(rec);
          if (b.program_id) state.draft.program_id = b.program_id;
          $("program-out").textContent = pretty(rec.body);
          saveDraft();
        })
        .catch(catchHttp);
    });
    $("join-program").addEventListener("click", function () {
      var pid = state.draft.program_id || "prog-demo";
      cr11Request("POST", "/capital/programs/" + encodeURIComponent(pid) + "/memberships", {})
        .then(function (rec) {
          $("program-out").textContent = pretty({
            membership: rec.body,
            debit_authorized: false,
            independent_lots: true,
          });
        })
        .catch(catchHttp);
    });
    $("prepare-commitment").addEventListener("click", function () {
      var pid = state.draft.program_id || "prog-demo";
      cr11Request("POST", "/capital/programs/" + encodeURIComponent(pid) + "/commitments", {})
        .then(function (rec) {
          $("program-out").textContent = pretty({
            commitment: rec.body,
            executed: false,
            note: "Proposal only. Execute still requires the one decision packet.",
          });
        })
        .catch(catchHttp);
    });

    $("plan-form").addEventListener("submit", function (ev) {
      var val = ev.submitter && ev.submitter.value;
      if (val === "cancel") return;
      ev.preventDefault();
      state.lastClientOp = "op-cr11-" + Date.now().toString(16);
      state.draft.maximum_exposure = "10";
      createPacketLive()
        .then(function () {
          afterPacketCreated("live /capital routes");
        })
        .catch(function (err) {
          afterPacketCreated("offline fixture (live packet failed: " + String(err && err.message ? err.message : err) + ")");
        });
    });

    $("financial-approve").addEventListener("click", function () {
      if (!state.planned) return;
      if (isAdviser() || state.familyView) {
        announce("This role or group view cannot record financial debit authority.");
        refreshApprovals();
        return;
      }
      var done = function () {
        state.financial = true;
        refreshApprovals();
        saveDraft();
        announce("Financial approval recorded. Local permission is still separate.");
      };
      if (state.draft.approval_id && accessToken()) {
        cr11Request("POST", "/capital/approvals/" + encodeURIComponent(state.draft.approval_id) + "/decisions", {
          decision: "APPROVE",
        })
          .then(function (rec) {
            if (rec.status >= 400) {
              $("approval-status").textContent = "Financial decision HTTP " + rec.status + ". " + pretty(rec.body);
              return;
            }
            done();
          })
          .catch(function (err) {
            catchHttp(err);
            done();
          });
      } else {
        done();
      }
    });

    $("local-approve").addEventListener("click", function () {
      state.local = true;
      refreshApprovals();
      saveDraft();
      announce("Local permission recorded separately from financial approval.");
    });

    $("execute").addEventListener("click", function () {
      if ($("execute").disabled || state.executing) return;
      if (!canDebit()) {
        announce("Execute refused: family view, adviser role, or UNKNOWN broadcast.");
        return;
      }
      state.executing = true;
      $("execute").disabled = true;
      var aid = state.draft.allocation_id;
      var finishOk = function (rec) {
        state.executing = false;
        if (isUnknown(rec)) {
          show("activity");
          return;
        }
        $("finance-timeline").innerHTML =
          'Capital plan: <span class="status">Authorized workflow dispatched · reuse ' +
          state.lastClientOp +
          "</span>";
        $("local-timeline").innerHTML =
          "Capability: <span class=\"status\">Handoff issued if present · runtime not inferred from receipt</span>";
        if (rec && rec.body) $("activity-out").textContent = pretty(rec.body);
        show("activity");
        state.planned = false;
        refreshApprovals();
        saveDraft();
      };
      if (aid && accessToken()) {
        cr11Request("POST", "/capital/allocations/" + encodeURIComponent(aid) + "/execute", {
          client_operation_id: state.lastClientOp,
        })
          .then(function (rec) {
            var b = unwrap(rec);
            if (b.execution_id) state.draft.execution_id = b.execution_id;
            if (rec.status === 403) {
              state.executing = false;
              $("approval-status").textContent =
                "Execute refused HTTP 403 (" +
                ((rec.body && rec.body.error && rec.body.error.code) || "forbidden") +
                "). Family view is not debit authority.";
              refreshApprovals();
              return;
            }
            finishOk(rec);
          })
          .catch(function (err) {
            state.executing = false;
            catchHttp(err);
            refreshApprovals();
          });
      } else {
        finishOk({ status: 201, body: { fixture: true, client_operation_id: state.lastClientOp, runtime_ready: false } });
      }
    });

    $("view-operation").addEventListener("click", function () {
      var xid = state.draft.execution_id;
      var alloc = state.draft.allocation_id;
      var path = xid
        ? "/capital/executions/" + encodeURIComponent(xid)
        : alloc
          ? "/capital/allocations/" + encodeURIComponent(alloc)
          : "";
      if (!path) {
        $("activity-out").textContent = pretty({
          note: "No execution id yet. Reuse client_operation_id; do not mint a new payment.",
          client_operation_id: state.lastClientOp,
          retry_new_payment: false,
        });
        announce("No existing execution to view. Do not start a new payment.");
        return;
      }
      cr11Request("GET", path)
        .then(function (rec) {
          $("activity-out").textContent = pretty({
            existing_operation: rec,
            retry_new_payment: false,
            http_202_is_unknown: isUnknown(rec),
          });
        })
        .catch(catchHttp);
    });

    $("simulate-unknown").addEventListener("click", function () {
      showUnknown({
        status: 202,
        unknown: true,
        body: {
          state: "BROADCAST_UNKNOWN",
          client_operation_id: state.lastClientOp,
          safe_next_action: "RETAIN_HOLD_AND_RECONCILE",
        },
      });
      show("activity");
    });

    $("create-report").addEventListener("click", function () {
      cr11Request("POST", "/capital/reports", {})
        .then(function (rec) {
          $("report-out").textContent = pretty(rec.body);
        })
        .catch(catchHttp);
    });
    $("create-export").addEventListener("click", function () {
      cr11Request("POST", "/capital/exports", { include_secrets: false })
        .then(function (rec) {
          $("report-out").textContent = pretty(rec.body);
        })
        .catch(catchHttp);
    });

    $("ping-health").addEventListener("click", function () {
      cr11Request("GET", "/health")
        .then(function (rec) {
          var b = rec.body || {};
          $("spend-chip").textContent =
            "automatic_spend_atoms = " + String(b.automatic_spend_atoms != null ? b.automatic_spend_atoms : 0);
          if (b.automatic_spend_atoms && Number(b.automatic_spend_atoms) !== 0) {
            log("Refusing non-zero automatic_spend_atoms from gateway health");
            announce("Gateway advertised non-zero automatic spend. This portal will not auto-spend.");
          }
          return cr11Request("GET", "/extensions/cognitive-reserve");
        })
        .then(function (ext) {
          log($("log").textContent + "\nGET /extensions/cognitive-reserve → HTTP " + ext.status);
        })
        .catch(catchHttp);
    });

    $("lab-session").addEventListener("click", function () {
      var ver = LAB_VERIFIER;
      cr11Request("GET", "/lab/pkce?verifier=" + encodeURIComponent(ver))
        .then(function (pkce) {
          var challenge = (pkce.body && pkce.body.challenge) || "";
          var q =
            "/lab/authorize?account=" +
            encodeURIComponent("account-demo") +
            "&client_id=client-demo&redirect=" +
            encodeURIComponent("https://app.example/cb") +
            "&state=state-1&challenge=" +
            encodeURIComponent(challenge);
          return cr11Request("GET", q);
        })
        .then(function (auth) {
          var code = auth.body && auth.body.code;
          var tq =
            "/lab/token?code=" +
            encodeURIComponent(code || "") +
            "&verifier=" +
            encodeURIComponent(ver) +
            "&redirect=" +
            encodeURIComponent("https://app.example/cb");
          var hit = uriContainsToken(tq);
          if (hit) throw new Error("Refused lab token URL containing " + hit);
          return cr11Request("GET", tq);
        })
        .then(function (tok) {
          var b = tok.body || {};
          if (b.access_token) $("token").value = b.access_token;
          if (b.jkt) state.jkt = b.jkt;
          $("session-note").hidden = false;
          $("session-note").textContent =
            "Lab session stored in the header field only. Draft identifiers were retained. Recheck the current plan before executing. Token is not in the URL.";
          announce("Lab session established. Token stays in the header field.");
          if (state.draft.plan_id) {
            return cr11Request("GET", "/capital/plans/" + encodeURIComponent(state.draft.plan_id));
          }
        })
        .catch(catchHttp);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bind);
  } else {
    bind();
  }
})();
