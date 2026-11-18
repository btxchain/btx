//! Trusted, read-only trade-preview material for the final native approval.
//! Financial authorization and expiry/retry policy remain in the node.
use crate::{operations::Request, Error, Result};
use serde_json::{json, Map, Value};

fn invalid() -> Error {
    Error::new("TRADE_REVIEW", "Stored trade preview is unavailable or inconsistent; this confirmation attempt was not submitted")
}
fn hex_id(value: &Value) -> Result<&str> {
    value
        .as_str()
        .filter(|s| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .ok_or_else(invalid)
}
/// Only shapes supported by the node's single `request` argument are accepted.
pub fn preview_id(params: &Value) -> Result<String> {
    let request = match params {
        Value::Array(a) if a.len() == 1 => &a[0],
        Value::Object(o) if o.len() == 1 => o.get("request").ok_or_else(invalid)?,
        _ => return Err(invalid()),
    };
    let object = request
        .as_object()
        .filter(|o| o.len() == 1)
        .ok_or_else(invalid)?;
    Ok(hex_id(object.get("preview_id").ok_or_else(invalid)?)?.to_owned())
}

#[derive(Clone, Debug, PartialEq)]
pub struct TradePreview {
    // Only immutable allowlisted terms are compared; no live stage/progress.
    terms: Map<String, Value>,
}
impl TradePreview {
    pub fn from_node(value: &Value, id: &str, requested_wallet: Option<&str>) -> Result<Self> {
        let source = value.as_object().ok_or_else(invalid)?;
        if source.get("preview_id").and_then(Value::as_str) != Some(id) {
            return Err(invalid());
        }
        let mut terms = Map::new();
        for name in ["preview_id", "quote_id"] {
            let v = source.get(name).ok_or_else(invalid)?;
            hex_id(v)?;
            terms.insert(name.into(), v.clone());
        }
        for name in ["principal", "wallet", "provider", "sell_asset", "buy_asset"] {
            let v = source.get(name).ok_or_else(invalid)?;
            let s = v
                .as_str()
                .filter(|s| {
                    s.len() <= 512
                        && !s.chars().any(char::is_control)
                        && (name == "wallet" || !s.is_empty())
                })
                .ok_or_else(invalid)?;
            if name == "wallet" && requested_wallet.is_some_and(|w| w != s) {
                return Err(invalid());
            }
            terms.insert(name.into(), v.clone());
        }
        const MAX_ATOMS: &str =
            "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        for name in [
            "sell_atoms",
            "buy_atoms",
            "maximum_send_atoms",
            "minimum_receive_atoms",
            "net_receive_floor_atoms",
            "max_local_fee_atoms",
            "refund_fee_atoms",
            "claim_fee_atoms",
            "maker_fee_atoms",
            "max_receive_network_fee_atoms",
        ] {
            let v = source.get(name).ok_or_else(invalid)?;
            let s = v.as_str().ok_or_else(invalid)?;
            if s.is_empty()
                || !s.bytes().all(|b| b.is_ascii_digit())
                || (s.len() > 1 && s.starts_with('0'))
                || s.len() > MAX_ATOMS.len()
                || (s.len() == MAX_ATOMS.len() && s > MAX_ATOMS)
            {
                return Err(invalid());
            }
            terms.insert(name.into(), v.clone());
        }
        for name in ["expires_at", "quote_expires_at"] {
            let v = source
                .get(name)
                .filter(|v| v.as_u64().is_some())
                .ok_or_else(invalid)?;
            terms.insert(name.into(), v.clone());
        }
        Ok(Self { terms })
    }
    pub fn summary(&self) -> Result<String> {
        let s = |key: &str| self.terms[key].as_str().unwrap_or("");
        let text = format!(
            "Method: confirmswap\nPrincipal: {:?}\nRPC wallet: {:?}\nPreview ID: {}\nQuote ID: {}\nProvider: {:?}\n\nSell/input asset: {}\nInput: {} atoms\nMaximum send including local fees: {} input-asset atoms\nLocal network fee cap: {} input-asset atoms\nRefund fee budget: {} input-asset atoms\n\nBuy/output asset: {}\nGross receive: {} atoms\nRequested minimum receive: {} output-asset atoms\nQuoted net receive floor: {} output-asset atoms\nMaker fee: {} output-asset atoms\nRecipient network fee cap: {} output-asset atoms\nClaim fee budget: {} output-asset atoms\n\nPreview deadline (Unix seconds): {}\nQuote expiry (Unix seconds): {}\n\nTerms read from the connected node's stored preview. An empty RPC wallet uses node binding. The node still enforces expiry, wallet, fee and mode checks. An expired preview can only recover an already-started trade if the node permits it.",
            s("principal"), s("wallet"), s("preview_id"), s("quote_id"), s("provider"), s("sell_asset"), s("sell_atoms"), s("maximum_send_atoms"), s("max_local_fee_atoms"), s("refund_fee_atoms"), s("buy_asset"), s("buy_atoms"), s("minimum_receive_atoms"), s("net_receive_floor_atoms"), s("maker_fee_atoms"), s("max_receive_network_fee_atoms"), s("claim_fee_atoms"), self.terms["expires_at"], self.terms["quote_expires_at"]);
        if text.len() > 16000 {
            return Err(invalid());
        }
        Ok(text)
    }
}

/// A failure in a read-only lookup does not make this mutation's outcome unknown.
pub fn lookup_error(_error: Error) -> Error {
    Error::new("TRADE_REVIEW_UNAVAILABLE", "Could not verify the stored trade preview; this confirmation attempt was not submitted. A prior trade may already exist; inspect its status before retrying")
}
pub fn lookup_params(id: &str) -> Value {
    json!([{"preview_id": id}])
}

fn preflight_error(error: Error) -> Error {
    if error.outcome_unknown {
        lookup_error(error)
    } else {
        error
    }
}

/// Broker sequence shared by the Tauri entry point and its no-spend tests.
/// Origin, gate and immutable approval consumption remain in the entry point.
pub fn execute_reviewed_trade<C, R, U, A>(
    request: &Request,
    mut recheck: C,
    mut rpc: R,
    mut approve: U,
    mut audit: A,
) -> Result<Value>
where
    C: FnMut() -> Result<()>,
    R: FnMut(&str, &Value, u64) -> Result<Value>,
    U: FnMut(String) -> Result<()>,
    A: FnMut(&str) -> Result<()>,
{
    if request.method != "confirmswap" {
        return Err(invalid());
    }
    let params = request.parse()?;
    let id = preview_id(&params)?;
    recheck().map_err(preflight_error)?;
    let shown = TradePreview::from_node(
        &rpc("getswaptradepreview", &lookup_params(&id), 20).map_err(lookup_error)?,
        &id,
        request.wallet.as_deref(),
    )?;
    approve(shown.summary()?)?;
    recheck().map_err(preflight_error)?;
    let current = TradePreview::from_node(
        &rpc("getswaptradepreview", &lookup_params(&id), 20).map_err(lookup_error)?,
        &id,
        request.wallet.as_deref(),
    )?;
    if current != shown {
        return Err(Error::new(
            "TRADE_REVIEW_CHANGED",
            "Stored trade terms changed after review; this confirmation attempt was not submitted",
        ));
    }
    recheck().map_err(preflight_error)?;
    audit("SUBMITTED")?;
    match rpc("confirmswap", &params, 180) {
        Ok(result) => {
            audit("SUCCEEDED").map_err(|_| Error::unknown("Node replied, but durable result journaling failed. Do not repeat the operation."))?;
            Ok(result)
        }
        Err(error) => {
            let _ = audit(if error.outcome_unknown {
                "UNKNOWN"
            } else {
                "REJECTED"
            });
            Err(error)
        }
    }
}
