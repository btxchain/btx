//! Deliberately consequential REGTEST-ONLY qualification driver. Never mainnet.
//! The caller must supply a freshly funded disposable test wallet and destination.
use atlas_core::{
    auth::CookieSource,
    money::{Money, Recipient, SendDraft},
    rpc::Rpc,
};
use serde_json::json;
use std::{collections::HashMap, path::PathBuf};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() % 2 != 0 {
        return Err("Use key/value arguments".into());
    }
    let m: HashMap<_, _> = args
        .chunks(2)
        .map(|x| (x[0].as_str(), x[1].as_str()))
        .collect();
    let required = |k| m.get(k).copied().ok_or_else(|| format!("Missing {k}"));
    if required("--accept-disposable-regtest")? != "yes" {
        return Err("Explicit disposable regtest consent required".into());
    }
    let rpc = Rpc::new(
        required("--endpoint")?,
        CookieSource::new(PathBuf::from(required("--cookie")?))?,
    )?;
    let chain = rpc.call("getblockchaininfo", &json!([]), None, 20)?;
    if chain["chain"] != "regtest" {
        return Err("REFUSED: not regtest".into());
    }
    let wallet = required("--wallet")?.to_owned();
    if !wallet.starts_with("atlas-qualification-") {
        return Err("Refused non-qualification wallet".into());
    }
    let draft = SendDraft {
        wallet: wallet.clone(),
        recipients: vec![Recipient {
            address: required("--recipient")?.into(),
            amount: "0.10000001".into(),
        }],
        inputs: vec![],
        maximum_fee: "0.01".into(),
        fee_rate: "2".into(),
        replaceable: true,
    };
    let mut money = Money::default();
    let plan = money.create(&rpc, draft, 1)?;
    assert_eq!(plan.state, "UNSIGNED");
    let signed = money.sign(&rpc, &plan.id, 1)?;
    assert_eq!(signed.state, "SIGNED_NOT_BROADCAST");
    assert!(money.sign(&rpc, &plan.id, 1).is_err());
    let sent = money.broadcast(&rpc, &plan.id, 1)?;
    assert_eq!(sent.state, "BROADCAST_SUBMITTED_NOT_CONFIRMED");
    assert!(money.broadcast(&rpc, &plan.id, 1).is_err());
    let txid = sent.txid.ok_or("No transaction ID")?;
    let tx = rpc.call("gettransaction", &json!([txid]), Some(&wallet), 20)?;
    println!(
        "{}",
        json!({"schema":"btx.atlas.native-wallet-qualification/1","chain":"regtest","txid":txid,"plan":plan,"signed_state":signed.state,"observed_transaction":tx,"scope":"Core Money and Rpc implementation only; OS confirmation, packaged WebView and hardware signers not tested"})
    );
    Ok(())
}
