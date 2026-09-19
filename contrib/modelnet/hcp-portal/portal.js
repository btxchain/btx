/* BTX HCP reference portal (0.34.8-dev).
 * Browser catalogue/pairing shell. Not a wallet.
 * No custody keys, no native wallet RPC, no token in URI, no auto-submit on 202.
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

  var FIXTURE_OFFER = {
    object_type: "CapabilityOffer",
    body: {
      version: 1,
      provider_id: "provider-demo",
      offer_id: "offer-demo",
      sponsored: true,
      availability_scope: "LOCAL_OBSERVATION",
      observed_provider_count: null,
      economic_status: "PUBLIC",
      package: {
        package_core_id:
          "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
        file_sha384:
          "222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222",
        recipe_id:
          "333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333",
      },
    },
    body_id:
      "e758c20ee5a4032e511f18a2dbfb7729f65f65627d3c75e6b922f46ac30543de5a48f7ebb99b83a23db2cf0695135bb8",
    signer_key_id: "unsigned-demo",
    signature: null,
  };

  var FIXTURE_POLICY = {
    policy_id: "policy-demo",
    revision: "1",
    allowed_actions: ["FUND_RELEASE"],
    allowed_terms_ids: [
      "555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555",
    ],
    per_action_principal_atoms: "5000",
    lifetime_principal_atoms: "10000",
    lifetime_fee_atoms: "1000",
    outstanding_exposure_atoms: "12000",
    max_actions: 20,
    max_concurrent: 4,
    expires_at_ms: "1790000600000",
    revoked: false,
    refund_replenishes_lifetime: false,
  };

  var FIXTURE_QUOTE = {
    object_type: "FundingQuote",
    body: {
      quote_id: "quote-demo",
      quote_kind: "FIRM",
      action: "FUND_RELEASE",
      terms_id:
        "555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555",
      amounts: {
        principal_atoms: "1000",
        network_fee_cap_atoms: "30",
        service_fee_atoms: "20",
        tax_atoms: "0",
        max_total_debit_atoms: "1050",
      },
      refund_controller: "CEX_CUSTODIAL_KEY",
      required_confirmations: 6,
    },
    body_id:
      "218705dd2e377b731b199b9bb12dbe337538baf70edd5a1f4ae20e92f2c046a877d94043b10b95b0f9d0538707e1ff15",
    signer_key_id: "unsigned-demo",
    signature: null,
  };

  var FIXTURE_EXPORT = {
    export_id: "export-demo",
    account_ref: "account-demo",
    include_secrets: false,
    custody_controller: "CEX_CUSTODIAL_KEY",
    self_custody_claimed: false,
    unresolved_intents: false,
    unresolved_provider: false,
    secrets_omitted: true,
    note: "Lab fixture. Not a proof of assets, liabilities, or title.",
  };

  var state = {
    lastClientOp: "op-portal-demo-01",
    last202: false,
    readyFromReport: false,
    fundedReceipt: false,
  };

  function $(id) {
    return document.getElementById(id);
  }

  function log(msg) {
    $("log").textContent = msg;
  }

  function pretty(v) {
    return JSON.stringify(v, null, 2);
  }

  /** BTX-PJSON1-ish: sorted keys, no extra space. Integers stay integers. */
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

  function assertNoTokenInUri(uri) {
    var hit = uriContainsToken(uri);
    if (hit) {
      throw new Error("Refused: " + hit + " must not appear in a pairing URI or the URL bar");
    }
    return uri;
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
      " on this page URL. Tokens were dropped from the address bar. Use the header field only.";
    if (history && history.replaceState) {
      history.replaceState(null, "", location.pathname + location.hash);
    }
    $("token").value = "";
  }

  function baseUrl() {
    var v = ($("base").value || "").trim().replace(/\/$/, "");
    if (!v) v = "http://127.0.0.1:18780";
    try {
      localStorage.setItem("hcp_base", v);
    } catch (e) {}
    return v;
  }

  function accessToken() {
    return ($("token").value || "").trim();
  }

  /**
   * Typed HCP fetch. Never writes tokens onto the URI.
   * HTTP 202 is returned as {status:202, unknown:true, body} and does not submit.
   */
  function hcpRequest(method, path, bodyObj) {
    var url = baseUrl() + path;
    assertNoTokenInUri(url);
    var headers = { Accept: "application/json" };
    var init = { method: method, headers: headers, credentials: "omit", cache: "no-store" };
    var tok = accessToken();
    if (tok) headers.Authorization = "Bearer " + tok;
    if (bodyObj !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = canonicalJSON(bodyObj);
    }
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
        if (res.status === 202) {
          state.last202 = true;
          $("submit-intent").disabled = true;
          $("treasury-unknown").hidden = false;
        }
        log(method + " " + path + " → HTTP " + res.status + "\n" + pretty(parsed));
        return rec;
      });
    });
  }

  function protocolFactsFromOffer(hit) {
    var env = hit && hit.offer ? hit.offer : hit;
    var body = env && env.body ? env.body : {};
    var pkg = body.package || {};
    return {
      kind: "protocol_facts",
      object_type: env && env.object_type,
      body_id: env && env.body_id,
      package_core_id: pkg.package_core_id,
      file_sha384: pkg.file_sha384,
      recipe_id: pkg.recipe_id,
      signature_status: hit && hit.signature_status,
    };
  }

  function annotationsFromHit(hit) {
    return {
      kind: "catalogue_annotation_not_protocol_fact",
      sponsored: !!(hit && hit.sponsored),
      quality_claim: hit ? hit.quality_claim : null,
      observed_availability: hit ? hit.observed_availability : null,
      memory_compatible: hit ? hit.memory_compatible : null,
      evidence_complete: hit ? hit.evidence_complete : false,
      ranking_copy:
        "Sponsored / trending / rank are product observations. They do not become package identity, terms_id, funding authority, or LocalCapabilityGrant.",
    };
  }

  function renderHits(payload, sourceLabel) {
    var box = $("hits");
    box.innerHTML = "";
    var intro = document.createElement("p");
    intro.className = "note";
    intro.textContent =
      sourceLabel +
      " — split below: protocol facts vs catalogue annotations. incomplete=" +
      String(payload && payload.incomplete) +
      " query_budget=" +
      String(payload && payload.query_budget);
    box.appendChild(intro);
    var hits = (payload && payload.hits) || [];
    if (!hits.length) {
      var empty = document.createElement("p");
      empty.className = "note";
      empty.textContent =
        "No offers in this gateway’s catalogue. Empty hits are still a valid search; do not invent capacity.";
      box.appendChild(empty);
      return;
    }
    hits.forEach(function (hit) {
      var el = document.createElement("article");
      el.className = "hit";
      var badge = "";
      if (hit.sponsored) {
        badge =
          '<span class="badge">sponsored — catalogue annotation, not a protocol fact</span>';
      }
      el.innerHTML =
        badge +
        "<div class='split'>" +
        "<div><h3 class='fact-label'>Protocol facts</h3><pre></pre></div>" +
        "<div><h3 class='ann-label'>Catalogue annotations</h3><pre></pre></div>" +
        "</div>";
      var pres = el.querySelectorAll("pre");
      pres[0].textContent = pretty(protocolFactsFromOffer(hit));
      pres[1].textContent = pretty(annotationsFromHit(hit));
      box.appendChild(el);
    });
  }

  function showQuote(rec, source) {
    var body = rec && rec.body && rec.body.body ? rec.body.body : rec && rec.body ? rec.body : rec;
    $("terms-facts").textContent = pretty({
      source: source,
      terms_id: body && body.terms_id,
      quote_id: body && body.quote_id,
      quote_kind: body && body.quote_kind,
      native_template_id: body && body.native_template_id,
      amounts: body && body.amounts,
      body_id: rec && rec.body && rec.body.body_id,
      refund_controller: body && body.refund_controller,
    });
    $("terms-ann").textContent = pretty({
      kind: "catalogue_annotation_not_protocol_fact",
      dated_observation: body && body.dated_observation,
      percent_funded_label: body && body.percent_funded_label,
      observation_basis: (body && body.observation_basis) || "HOSTED_ATTESTED",
      note: "Economy percents and ranking are observations. Finance still requires the current terms_id.",
    });
    $("terms-raw").textContent = pretty(rec);
  }

  function setStages(map) {
    var items = $("stages").querySelectorAll("li");
    var keys = [
      "FETCH_METADATA",
      "ACQUIRE_MODEL",
      "PLAN_LOCAL_RUN",
      "Authorized device report",
      "RUNTIME_READY (not inferred from receipt)",
    ];
    for (var i = 0; i < items.length; i++) {
      items[i].dataset.state = map[keys[i]] || "blocked";
    }
  }

  function pairingUri(deviceId, challenge) {
    var uri =
      "btx-hcp-pair://device/enroll?device_id=" +
      encodeURIComponent(deviceId) +
      "&challenge=" +
      encodeURIComponent(challenge);
    return assertNoTokenInUri(uri);
  }

  function showView(name) {
    var views = document.querySelectorAll("section.view");
    for (var i = 0; i < views.length; i++) {
      views[i].classList.toggle("active", views[i].id === "view-" + name);
    }
    var buttons = document.querySelectorAll("nav button");
    for (var j = 0; j < buttons.length; j++) {
      if (buttons[j].getAttribute("data-view") === name) {
        buttons[j].setAttribute("aria-current", "page");
      } else {
        buttons[j].removeAttribute("aria-current");
      }
    }
  }

  function catchHttp(err) {
    log(String(err && err.message ? err.message : err));
  }

  function bind() {
    stripTokenFromLocation();
    try {
      var saved = localStorage.getItem("hcp_base");
      if (saved) $("base").value = saved;
    } catch (e) {}

    $("policy-digest").textContent = pretty({
      note: "Finite policy. Natural-language urgency cannot widen these limits.",
      policy: FIXTURE_POLICY,
    });
    $("expected-body").value = FIXTURE_QUOTE.body_id;

    document.querySelectorAll("nav button").forEach(function (btn) {
      btn.addEventListener("click", function () {
        showView(btn.getAttribute("data-view"));
      });
    });
    document.querySelectorAll("button[data-base]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        $("base").value = btn.getAttribute("data-base");
        baseUrl();
      });
    });

    $("search-live").addEventListener("click", function () {
      var q = ($("q").value || "").trim();
      var body = q ? { q: q } : {};
      hcpRequest("POST", "/capabilities/search", body)
        .then(function (rec) {
          renderHits(rec.body, "Live loopback");
        })
        .catch(catchHttp);
    });
    $("search-fixture").addEventListener("click", function () {
      var payload = {
        hits: [
          {
            offer: FIXTURE_OFFER,
            sponsored: true,
            signature_status: "UNSIGNED_FIXTURE",
            quality_claim: null,
            observed_availability: "LOCAL_OBSERVATION",
            memory_compatible: null,
            evidence_complete: false,
          },
        ],
        incomplete: true,
        query_budget: 100,
      };
      renderHits(payload, "Lab fixture (not production evidence)");
      log("Fixture catalogue. Ranking badge is a catalogue annotation, not a protocol fact.");
    });

    $("economy-live").addEventListener("click", function () {
      var id = encodeURIComponent(($("target").value || "target-demo").trim());
      hcpRequest("GET", "/economy/" + id)
        .then(function (rec) {
          showQuote(rec, "GET /economy");
        })
        .catch(catchHttp);
    });
    $("quote-live").addEventListener("click", function () {
      hcpRequest("POST", "/finance/quotes", {})
        .then(function (rec) {
          showQuote(rec, "POST /finance/quotes");
        })
        .catch(catchHttp);
    });
    $("quote-fixture").addEventListener("click", function () {
      showQuote({ body: FIXTURE_QUOTE, status: "fixture" }, "unsigned fixture");
      log("Quote fixture. Amounts are decimal atom strings. Unsigned — no settlement.");
    });

    $("authorize").addEventListener("click", function () {
      var iid = ($("intent-id").value || "").trim();
      hcpRequest("POST", "/finance/intents/" + encodeURIComponent(iid) + "/authorize", {
        expected_body_id: ($("expected-body").value || "").trim(),
        policy_id: FIXTURE_POLICY.policy_id,
        policy_revision: ($("policy-rev").value || "").trim(),
      })
        .then(function (rec) {
          $("approvals-out").textContent = pretty(rec);
        })
        .catch(catchHttp);
    });

    $("balances").addEventListener("click", function () {
      hcpRequest("GET", "/treasury/balances")
        .then(function (rec) {
          $("treasury-bal").textContent = pretty(rec);
        })
        .catch(catchHttp);
    });
    $("prepare-intent").addEventListener("click", function () {
      hcpRequest("POST", "/finance/intents", {
        client_operation_id: state.lastClientOp,
        quote_id: "quote-demo",
        terms_id: FIXTURE_QUOTE.body.terms_id,
        amounts: FIXTURE_QUOTE.body.amounts,
      })
        .then(function (rec) {
          $("treasury-act").textContent = pretty({
            prepared: rec,
            auto_submit: false,
            reuse_client_operation_id: state.lastClientOp,
          });
          if (rec.unknown) {
            $("submit-intent").disabled = true;
          }
        })
        .catch(catchHttp);
    });
    $("poll-op").addEventListener("click", function () {
      hcpRequest("GET", "/operations/" + encodeURIComponent(state.lastClientOp))
        .then(function (rec) {
          $("treasury-act").textContent = pretty({
            poll: rec,
            http_202_is_unknown: true,
            auto_submit: false,
          });
        })
        .catch(catchHttp);
    });
    $("submit-intent").addEventListener("click", function () {
      log("Submit remains an explicit human action and is disabled on 202 / timeout. No auto-submit.");
    });

    $("make-pair-uri").addEventListener("click", function () {
      try {
        var uri = pairingUri($("device-id").value.trim(), $("device-challenge").value.trim());
        $("pair-uri").textContent = uri;
        $("devices-out").textContent = pretty({
          pairing_uri: uri,
          outbound_only: true,
          inbound_execution_port: false,
          token_in_uri: false,
          custody_key_in_browser: false,
        });
      } catch (e) {
        catchHttp(e);
      }
    });
    $("refuse-token-uri").addEventListener("click", function () {
      var bad =
        pairingUri($("device-id").value.trim(), $("device-challenge").value.trim()) +
        "&access_token=lab-not-a-credential";
      try {
        assertNoTokenInUri(bad);
        $("devices-out").textContent = "BUG: token URI was accepted";
      } catch (e) {
        $("devices-out").textContent = pretty({
          refused: true,
          reason: e.message,
          attempted: bad,
        });
        log(e.message);
      }
    });
    $("enroll").addEventListener("click", function () {
      hcpRequest("POST", "/devices/enroll", {
        client_operation_id: "op-pair-demo",
        device_id: $("device-id").value.trim(),
        device_public_key_ref: "device-demo-pub-not-custody",
        challenge: $("device-challenge").value.trim(),
      })
        .then(function (rec) {
          $("devices-out").textContent = pretty(rec);
          if (rec.body && rec.body.challenge) $("device-challenge").value = rec.body.challenge;
          if (rec.body && rec.body.device_id) $("device-id").value = rec.body.device_id;
        })
        .catch(catchHttp);
    });
    $("confirm").addEventListener("click", function () {
      var did = encodeURIComponent($("device-id").value.trim());
      hcpRequest("POST", "/devices/" + did + "/confirm", {
        challenge: $("device-challenge").value.trim(),
        expected_device_key_id: "device-demo-pub-not-custody",
      })
        .then(function (rec) {
          $("devices-out").textContent = pretty(rec);
        })
        .catch(catchHttp);
    });
    $("poll-handoffs").addEventListener("click", function () {
      var did = encodeURIComponent($("device-id").value.trim());
      hcpRequest("GET", "/devices/" + did + "/handoffs")
        .then(function (rec) {
          $("devices-out").textContent = pretty({
            outbound_poll: rec,
            inbound_execution_port: false,
          });
        })
        .catch(catchHttp);
    });
    $("revoke").addEventListener("click", function () {
      var did = encodeURIComponent($("device-id").value.trim());
      hcpRequest("POST", "/devices/" + did + "/revoke", {})
        .then(function (rec) {
          $("devices-out").textContent = pretty(rec);
          state.readyFromReport = false;
        })
        .catch(catchHttp);
    });

    $("progress-live").addEventListener("click", function () {
      var id = ($("progress-id").value || "").trim();
      Promise.all([
        hcpRequest("GET", "/handoffs/" + encodeURIComponent(id)).catch(function (e) {
          return { error: String(e) };
        }),
        hcpRequest("GET", "/operations/" + encodeURIComponent(id)).catch(function (e) {
          return { error: String(e) };
        }),
      ]).then(function (pair) {
        var handoff = pair[0];
        var op = pair[1];
        state.fundedReceipt = false;
        var report = state.readyFromReport;
        setStages({
          FETCH_METADATA: handoff && handoff.status === 200 ? "done" : "blocked",
          ACQUIRE_MODEL: "blocked",
          PLAN_LOCAL_RUN: "blocked",
          "Authorized device report": report ? "done" : "blocked",
          "RUNTIME_READY (not inferred from receipt)": report ? "done" : "blocked",
        });
        $("progress-out").textContent = pretty({
          handoff: handoff,
          operation: op,
          ready_inferred_from_receipt: false,
          ready_requires_authorized_device_report: true,
          http_202_is_unknown: !!(op && op.unknown),
        });
      });
    });
    $("progress-fixture").addEventListener("click", function () {
      state.fundedReceipt = true;
      state.readyFromReport = false;
      setStages({
        FETCH_METADATA: "done",
        ACQUIRE_MODEL: "done",
        PLAN_LOCAL_RUN: "done",
        "Authorized device report": "blocked",
        "RUNTIME_READY (not inferred from receipt)": "blocked",
      });
      $("progress-out").textContent = pretty({
        fixture: true,
        financial_receipt: "HOSTED_ATTESTED PREPARED (not consensus-ready)",
        download_count: 1,
        live_socket: false,
        runtime_ready: false,
        reason: "No authorized LocalReadinessReport. Receipt/download/socket do not imply Ready.",
      });
      log("Fixture progress: funded/downloaded but not Ready.");
    });

    $("export-live").addEventListener("click", function () {
      hcpRequest("POST", "/exports", {
        client_operation_id: "op-export-demo",
        include: ["PACKAGES", "INTENTS", "RECEIPTS", "POLICIES", "CUSTODY_OBLIGATIONS"],
        include_secrets: false,
      })
        .then(function (rec) {
          $("export-out").textContent = pretty(rec);
          if (rec.body && rec.body.export_id) {
            return hcpRequest("GET", "/exports/" + encodeURIComponent(rec.body.export_id));
          }
        })
        .catch(catchHttp);
    });
    $("export-fixture").addEventListener("click", function () {
      $("export-out").textContent = pretty(FIXTURE_EXPORT);
      log("Export fixture. HTTP 202 would stay UNKNOWN; secrets omitted.");
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bind);
  } else {
    bind();
  }
})();
