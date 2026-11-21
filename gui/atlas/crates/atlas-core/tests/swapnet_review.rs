use atlas_core::{
    operations::Request,
    swapnet::{self, TradePreview},
    Error,
};
use serde_json::{json, Value};

fn record() -> Value {
    json!({"preview_id":"3".repeat(64),"quote_id":"2".repeat(64),"principal":"owner:cookie","wallet":"wallet A","provider":"maker",
      "sell_asset":"btx:input:0:native","buy_asset":"btc:output:0:native","sell_atoms":"9007199254740993","buy_atoms":"18014398509481985",
      "maximum_send_atoms":"9130656043753338","minimum_receive_atoms":"18014398509481979","net_receive_floor_atoms":"18014398509481979",
      "max_local_fee_atoms":"123456789012345","refund_fee_atoms":"5","claim_fee_atoms":"4","maker_fee_atoms":"2","max_receive_network_fee_atoms":"4",
      "expires_at":1,"quote_expires_at":2})
}
#[test]
fn final_review_shows_exact_stored_terms_and_expiry_without_extending_it() {
    let r = record();
    let shown = TradePreview::from_node(&r, &"3".repeat(64), Some("wallet A"))
        .unwrap()
        .summary()
        .unwrap();
    for text in [
        "wallet A",
        "btx:input:0:native",
        "btc:output:0:native",
        "9007199254740993",
        "18014398509481979",
        "123456789012345",
        "Preview deadline (Unix seconds): 1",
        "Quote expiry (Unix seconds): 2",
    ] {
        assert!(shown.contains(text), "missing {text}");
    }
    assert!(shown.contains("already-started"));
    // The old generic summary establishes the reproduced opaque-ID contrast.
    let request = Request {
        method: "confirmswap".into(),
        params_json: json!([{"preview_id":"3".repeat(64)}]).to_string(),
        wallet: Some("wallet A".into()),
    };
    assert!(!request.summary().unwrap().contains("9007199254740993"));
}
#[test]
fn wrong_identity_wallet_missing_or_malformed_amount_refuses_review() {
    assert!(TradePreview::from_node(&record(), &"4".repeat(64), Some("wallet A")).is_err());
    assert!(TradePreview::from_node(&record(), &"3".repeat(64), Some("wallet B")).is_err());
    for bad in [
        json!(9007199254740993u64),
        json!("1e8"),
        json!("01"),
        json!("-1"),
        json!("1".repeat(79)),
    ] {
        let mut r = record();
        r["sell_atoms"] = bad;
        assert!(TradePreview::from_node(&r, &"3".repeat(64), None).is_err());
    }
    let mut r = record();
    r.as_object_mut().unwrap().remove("refund_fee_atoms");
    assert!(TradePreview::from_node(&r, &"3".repeat(64), None).is_err());
}
#[test]
fn immutable_comparison_detects_financial_changes_but_not_progress() {
    let first = TradePreview::from_node(&record(), &"3".repeat(64), None).unwrap();
    for key in [
        "sell_atoms",
        "max_local_fee_atoms",
        "minimum_receive_atoms",
        "refund_fee_atoms",
        "claim_fee_atoms",
    ] {
        let mut r = record();
        r[key] = json!("6");
        assert_ne!(
            first,
            TradePreview::from_node(&r, &"3".repeat(64), None).unwrap()
        );
    }
    let mut r = record();
    r["stage"] = json!("funded");
    r["browser_summary"] = json!("untrusted fabricated amounts");
    assert_eq!(
        first,
        TradePreview::from_node(&r, &"3".repeat(64), None).unwrap()
    );
    assert!(!first.summary().unwrap().contains("fabricated"));
}
#[test]
fn only_exact_request_shapes_select_the_preview() {
    let id = "3".repeat(64);
    assert_eq!(
        swapnet::preview_id(&json!([{"preview_id":id}])).unwrap(),
        id
    );
    assert_eq!(
        swapnet::preview_id(&json!({"request":{"preview_id":id}})).unwrap(),
        id
    );
    for bad in [
        json!([]),
        json!([{"preview_id":id,"amount":"1"}]),
        json!({"preview_id":id}),
        json!([{"preview_id":"bad"}]),
        json!([{}, {}]),
    ] {
        assert!(swapnet::preview_id(&bad).is_err());
    }
}
#[test]
fn lookup_timeouts_are_not_mutation_unknown() {
    let e = swapnet::lookup_error(Error::unknown("transport timeout"));
    assert!(!e.outcome_unknown);
    assert!(e.message.contains("not submitted"));
    assert!(Error::unknown("actual mutation transport failure").outcome_unknown);
}

#[derive(Default, Debug)]
struct Observed {
    events: Vec<String>,
    checks: usize,
    reads: usize,
    mutations: usize,
    summary: String,
}
fn orchestrate(fault: &str) -> (atlas_core::Result<Value>, Observed) {
    use std::{cell::RefCell, rc::Rc};
    let state = Rc::new(RefCell::new(Observed::default()));
    let (checks, calls, ui, audit) = (state.clone(), state.clone(), state.clone(), state.clone());
    let request = Request {
        method: "confirmswap".into(),
        params_json: json!([{"preview_id":"3".repeat(64)}]).to_string(),
        wallet: Some("wallet A".into()),
    };
    let result = swapnet::execute_reviewed_trade(
        &request,
        || {
            let mut s = checks.borrow_mut();
            s.checks += 1;
            let i = s.checks;
            s.events.push(format!("check{i}"));
            if fault == format!("check{i}") {
                return Err(Error::unknown("readonly genesis timeout"));
            }
            if fault == "connection" && i == 2 {
                return Err(Error::new("CONNECTION_CHANGED", "Changed"));
            }
            Ok(())
        },
        |method, params, timeout| {
            let mut s = calls.borrow_mut();
            s.events.push(method.into());
            if method == "getswaptradepreview" {
                assert_eq!(timeout, 20);
                assert_eq!(params, &json!([{"preview_id":"3".repeat(64)}]));
                s.reads += 1;
                if fault == format!("lookup{}", s.reads) {
                    return Err(Error::unknown("readonly lookup timeout"));
                }
                let mut r = record();
                if fault == "changed" && s.reads == 2 {
                    r["max_local_fee_atoms"] = json!("99");
                }
                return Ok(r);
            }
            assert_eq!(method, "confirmswap");
            assert_eq!(timeout, 180);
            assert_eq!(params, &json!([{"preview_id":"3".repeat(64)}]));
            s.mutations += 1;
            match fault {
                "mutation_unknown" => Err(Error::unknown("actual mutation timeout")),
                "mutation_refused" => Err(Error::new("RPC_-1", "MODE_DISABLED")),
                _ => Ok(json!({"swap_id":"4".repeat(64)})),
            }
        },
        |summary| {
            let mut s = ui.borrow_mut();
            s.events.push("approve".into());
            s.summary = summary;
            if fault == "cancel" {
                Err(Error::new("CANCELLED", "Cancelled"))
            } else {
                Ok(())
            }
        },
        |phase| {
            let mut s = audit.borrow_mut();
            s.events.push(phase.into());
            if fault == "audit_result" && phase == "SUCCEEDED" {
                Err(Error::new("IO", "journal"))
            } else {
                Ok(())
            }
        },
    );
    drop((checks, calls, ui, audit));
    let observed = Rc::try_unwrap(state).unwrap().into_inner();
    (result, observed)
}
#[test]
fn orchestration_uses_trusted_summary_rechecks_then_submits_original_once() {
    let (result, s) = orchestrate("");
    assert!(result.is_ok());
    assert_eq!(s.mutations, 1);
    assert!(s.summary.contains("9007199254740993"));
    assert!(s.summary.contains("123456789012345"));
    assert_eq!(
        s.events,
        [
            "check1",
            "getswaptradepreview",
            "approve",
            "check2",
            "getswaptradepreview",
            "check3",
            "SUBMITTED",
            "confirmswap",
            "SUCCEEDED"
        ]
    );
}
#[test]
fn orchestration_preflight_timeouts_never_dispatch_or_claim_unknown() {
    for fault in ["check1", "check2", "check3", "lookup1", "lookup2"] {
        let (result, s) = orchestrate(fault);
        let e = result.unwrap_err();
        assert!(!e.outcome_unknown, "{fault}");
        assert!(e.message.contains("not submitted"));
        assert_eq!(s.mutations, 0);
        assert!(!s.events.iter().any(|x| x == "SUBMITTED"));
    }
    let (result, s) = orchestrate("connection");
    assert_eq!(result.unwrap_err().code, "CONNECTION_CHANGED");
    assert_eq!(s.mutations, 0);
}
#[test]
fn orchestration_cancel_and_changed_terms_do_not_submit() {
    let (result, s) = orchestrate("cancel");
    assert_eq!(result.unwrap_err().code, "CANCELLED");
    assert_eq!(s.reads, 1);
    assert_eq!(s.mutations, 0);
    let (result, s) = orchestrate("changed");
    assert_eq!(result.unwrap_err().code, "TRADE_REVIEW_CHANGED");
    assert_eq!(s.mutations, 0);
}
#[test]
fn orchestration_real_mutation_failure_keeps_its_outcome_and_no_retry() {
    for fault in ["mutation_unknown", "mutation_refused", "audit_result"] {
        let (result, s) = orchestrate(fault);
        let e = result.unwrap_err();
        assert_eq!(s.mutations, 1);
        assert_eq!(e.outcome_unknown, fault != "mutation_refused");
        assert_eq!(
            s.events.last().map(String::as_str),
            Some(match fault {
                "mutation_unknown" => "UNKNOWN",
                "mutation_refused" => "REJECTED",
                _ => "SUCCEEDED",
            })
        );
    }
}
