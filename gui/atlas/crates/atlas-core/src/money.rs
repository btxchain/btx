//! Wallet ownership stays in btxd. Atlas freezes exact unsigned transaction semantics,
//! checks recipients/change/fees, then requires separate native sign and broadcast review.
use crate::{amount::Amount, now_ms, random_id, rpc::Rpc, Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use zeroize::Zeroize;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Recipient {
    pub address: String,
    pub amount: String,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendDraft {
    pub wallet: String,
    pub recipients: Vec<Recipient>,
    #[serde(default)]
    pub inputs: Vec<Input>,
    pub maximum_fee: String,
    #[serde(default = "default_rate")]
    pub fee_rate: String,
    #[serde(default = "yes")]
    pub replaceable: bool,
}
fn default_rate() -> String {
    "2".into()
}
fn yes() -> bool {
    true
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub txid: String,
    pub vout: u32,
}
#[derive(Clone, Serialize)]
pub struct PlanView {
    pub id: String,
    pub wallet: String,
    pub recipients: Vec<Recipient>,
    pub fee: String,
    pub change: String,
    pub input_count: usize,
    pub unsigned_digest: String,
    pub state: String,
    pub expires_at_ms: u64,
    pub txid: Option<String>,
}
struct Plan {
    view: PlanView,
    psbt: String,
    raw: Option<String>,
    skeleton: Value,
    epoch: u64,
    created: u64,
}
impl Drop for Plan {
    fn drop(&mut self) {
        self.psbt.zeroize();
        if let Some(h) = self.raw.as_mut() {
            h.zeroize();
        }
    }
}
#[derive(Default)]
pub struct Money {
    plans: HashMap<String, Plan>,
}
impl SendDraft {
    pub fn validate(&self) -> Result<()> {
        if self.wallet.is_empty()
            || self.wallet.len() > 256
            || self.wallet.chars().any(char::is_control)
        {
            return Err(Error::new("WALLET", "Choose a wallet"));
        }
        if self.recipients.is_empty() || self.recipients.len() > 32 || self.inputs.len() > 512 {
            return Err(Error::new(
                "SEND_SIZE",
                "Use 1–32 recipients and at most 512 explicit inputs",
            ));
        }
        let mut total = Amount::from_atoms(0)?;
        let mut addresses = std::collections::HashSet::new();
        for r in &self.recipients {
            if r.address.len() > 256
                || r.address.is_empty()
                || !r.address.bytes().all(|x| x.is_ascii_alphanumeric())
                || !addresses.insert(&r.address)
            {
                return Err(Error::new("RECIPIENT", "Invalid or duplicate recipient"));
            }
            let amount = Amount::parse(&r.amount)?;
            if amount.atoms() == 0 {
                return Err(Error::new("AMOUNT", "A recipient amount must be positive"));
            }
            total = total.checked_add(amount)?;
        }
        let ceiling = Amount::parse(&self.maximum_fee)?;
        let _ = total.checked_add(ceiling)?;
        let rate: serde_json::Number = self
            .fee_rate
            .parse()
            .map_err(|_| Error::new("FEE_RATE", "Invalid exact fee rate"))?;
        let r = rate.to_string();
        if r.contains(['e', 'E', '-', '+'])
            || r.len() > 16
            || Amount::parse(&r)?.atoms() > Amount::parse("10000")?.atoms()
        {
            return Err(Error::new(
                "FEE_RATE",
                "Fee rate must be a decimal between 0 and 10000 atoms/vB",
            ));
        }
        let mut inputs = std::collections::HashSet::new();
        for i in &self.inputs {
            if i.txid.len() != 64
                || !i.txid.bytes().all(|b| b.is_ascii_hexdigit())
                || !inputs.insert((i.txid.to_ascii_lowercase(), i.vout))
            {
                return Err(Error::new(
                    "INPUT",
                    "Invalid or duplicate coin-control input",
                ));
            }
        }
        Ok(())
    }
    pub fn summary(&self) -> Result<String> {
        self.validate()?;
        Ok(format!("Wallet: {}\n{}\n\nMaximum fee: {} BTX\nFee rate: {} atoms/vB\nExplicit inputs: {}\nReplaceable: {}\n\nCreates an unsigned PSBT. No signing or broadcast. The wallet may reserve a new change address.",self.wallet,self.recipients.iter().map(|r|format!("{} BTX → {}",r.amount,r.address)).collect::<Vec<_>>().join("\n"),self.maximum_fee,self.fee_rate,self.inputs.len(),self.replaceable))
    }
}
impl Money {
    pub fn clear(&mut self) {
        self.plans.clear();
    }
    pub fn create(&mut self, rpc: &Rpc, draft: SendDraft, epoch: u64) -> Result<PlanView> {
        draft.validate()?;
        self.plans
            .retain(|_, p| now_ms().saturating_sub(p.created) < 600_000);
        if self.plans.len() >= 8 {
            return Err(Error::new(
                "QUEUE_FULL",
                "At most eight unsigned transaction plans",
            ));
        }
        let mut expected: BTreeMap<String, i64> = BTreeMap::new();
        let mut outputs = Vec::new();
        for r in &draft.recipients {
            let valid = rpc.call("validateaddress", &json!([r.address]), None, 20)?;
            if valid.get("isvalid") != Some(&Value::Bool(true)) {
                return Err(Error::new("ADDRESS", "Node rejected a destination"));
            }
            let script = valid
                .get("scriptPubKey")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    Error::new("ADDRESS", "Node did not return an exact destination script")
                })?;
            let amount = Amount::parse(&r.amount)?;
            *expected.entry(script.into()).or_default() += amount.atoms();
            let mut map = serde_json::Map::new();
            map.insert(r.address.clone(), amount.json()?);
            outputs.push(Value::Object(map));
        }
        let rate: serde_json::Number = draft
            .fee_rate
            .parse()
            .map_err(|_| Error::new("FEE_RATE", "Invalid fee rate"))?;
        let options = json!({"add_inputs":draft.inputs.is_empty(),"lockUnspents":false,"replaceable":draft.replaceable,"fee_rate":rate});
        let reply = rpc.call(
            "walletcreatefundedpsbt",
            &json!([draft.inputs, outputs, 0, options, true]),
            Some(&draft.wallet),
            60,
        )?;
        let fee = Amount::from_value(
            reply
                .get("fee")
                .ok_or_else(|| Error::new("PSBT", "Missing fee"))?,
        )?;
        if fee > Amount::parse(&draft.maximum_fee)? {
            return Err(Error::new(
                "FEE_CEILING",
                "Prepared fee exceeds the approved maximum. Nothing signed.",
            ));
        }
        let psbt = reply
            .get("psbt")
            .and_then(Value::as_str)
            .filter(|p| p.len() <= 1_048_576)
            .ok_or_else(|| Error::new("PSBT", "Missing/oversized PSBT"))?
            .to_owned();
        let decoded = rpc.call("decodepsbt", &json!([psbt]), None, 20)?;
        let tx = decoded
            .get("tx")
            .ok_or_else(|| Error::new("PSBT", "Missing unsigned transaction"))?;
        let change_pos = reply
            .get("changepos")
            .and_then(Value::as_i64)
            .ok_or_else(|| Error::new("PSBT", "Missing change position"))?;
        let vout = tx
            .get("vout")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::new("PSBT", "Missing outputs"))?;
        if change_pos < -1 || change_pos >= vout.len() as i64 {
            return Err(Error::new("CHANGE", "Invalid change position"));
        }
        let mut change = Amount::from_atoms(0)?;
        for (i, o) in vout.iter().enumerate() {
            let amount = Amount::from_value(
                o.get("value")
                    .ok_or_else(|| Error::new("OUTPUT", "Missing output amount"))?,
            )?;
            let script = o
                .pointer("/scriptPubKey/hex")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::new("OUTPUT", "Missing output script"))?;
            if i as i64 == change_pos {
                let address = o
                    .pointer("/scriptPubKey/address")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        Error::new("CHANGE", "Cannot establish change address ownership")
                    })?;
                let owned =
                    rpc.call("getaddressinfo", &json!([address]), Some(&draft.wallet), 20)?;
                if owned.get("ismine") != Some(&Value::Bool(true))
                    && owned.get("iswatchonly") != Some(&Value::Bool(true))
                {
                    return Err(Error::new(
                        "CHANGE",
                        "Change output is not owned or watched by the selected wallet",
                    ));
                }
                change = amount;
            } else {
                match expected.remove(script) {
                    Some(n) if n == amount.atoms() => {}
                    _ => {
                        return Err(Error::new(
                            "OUTPUT_CHANGED",
                            "Unsigned transaction does not exactly match approved recipients",
                        ))
                    }
                }
            }
        }
        if !expected.is_empty() {
            return Err(Error::new(
                "OUTPUT_MISSING",
                "An approved recipient is absent",
            ));
        }
        let skeleton = transaction_skeleton(tx)?;
        let input_count = skeleton["vin"].as_array().map_or(0, Vec::len);
        if !draft.inputs.is_empty() {
            let got: std::collections::BTreeSet<_> = skeleton["vin"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| {
                    (
                        v["txid"].as_str().unwrap_or("").to_owned(),
                        v["vout"].as_u64().unwrap_or(u64::MAX),
                    )
                })
                .collect();
            let wanted: std::collections::BTreeSet<_> = draft
                .inputs
                .iter()
                .map(|i| (i.txid.to_lowercase(), u64::from(i.vout)))
                .collect();
            if got != wanted {
                return Err(Error::new("INPUT_CHANGED", "Coin-control inputs changed"));
            }
        }
        let id = random_id()?;
        let now = now_ms();
        let view = PlanView {
            id: id.clone(),
            wallet: draft.wallet,
            recipients: draft.recipients,
            fee: fee.decimal(),
            change: change.decimal(),
            input_count,
            unsigned_digest: crate::hash(skeleton.to_string().as_bytes()),
            state: "UNSIGNED".into(),
            expires_at_ms: now + 600_000,
            txid: None,
        };
        self.plans.insert(
            id,
            Plan {
                view: view.clone(),
                psbt,
                raw: None,
                skeleton,
                epoch,
                created: now,
            },
        );
        Ok(view)
    }
    pub fn view(&self, id: &str, epoch: u64) -> Result<PlanView> {
        Ok(self.plan(id, epoch)?.view.clone())
    }
    fn plan(&self, id: &str, epoch: u64) -> Result<&Plan> {
        let p = self
            .plans
            .get(id)
            .ok_or_else(|| Error::new("PLAN", "Unknown transaction plan"))?;
        if p.epoch != epoch || now_ms().saturating_sub(p.created) >= 600_000 {
            return Err(Error::new(
                "PLAN_EXPIRED",
                "Transaction plan expired or connection changed",
            ));
        }
        Ok(p)
    }
    pub fn summary(&self, id: &str, epoch: u64) -> Result<String> {
        let v = &self.plan(id, epoch)?.view;
        Ok(format!("Wallet: {}\n{}\n\nFee: {} BTX\nChange: {} BTX\nInputs: {}\nUnsigned digest: {}\nStatus: {}\n\nApprovals apply only to this exact transaction.",v.wallet,v.recipients.iter().map(|r|format!("{} BTX → {}",r.amount,r.address)).collect::<Vec<_>>().join("\n"),v.fee,v.change,v.input_count,v.unsigned_digest,v.state))
    }
    pub fn psbt(&self, id: &str, epoch: u64) -> Result<String> {
        Ok(self.plan(id, epoch)?.psbt.clone())
    }
    pub fn sign(&mut self, rpc: &Rpc, id: &str, epoch: u64) -> Result<PlanView> {
        self.plan(id, epoch)?;
        let p = self.plans.get_mut(id).unwrap();
        if p.view.state != "UNSIGNED" {
            return Err(Error::new(
                "PLAN_STATE",
                "Plan is not unsigned; never repeat an uncertain signing operation",
            ));
        }
        p.view.state = "SIGNING_UNKNOWN".into();
        let signed = rpc.call(
            "walletprocesspsbt",
            &json!([p.psbt, true, "ALL", true]),
            Some(&p.view.wallet),
            120,
        )?;
        let psbt = signed
            .get("psbt")
            .and_then(Value::as_str)
            .filter(|x| x.len() <= 1_048_576)
            .ok_or_else(|| Error::new("PSBT", "Signed PSBT missing"))?;
        let decoded = rpc.call("decodepsbt", &json!([psbt]), None, 20)?;
        if transaction_skeleton(&decoded["tx"])? != p.skeleton {
            return Err(Error::new(
                "TX_CHANGED",
                "Signing changed transaction semantics",
            ));
        }
        p.psbt.zeroize();
        p.psbt = psbt.to_owned();
        let final_tx = rpc.call("finalizepsbt", &json!([p.psbt]), None, 20)?;
        if final_tx.get("complete") != Some(&Value::Bool(true)) {
            p.view.state = "PARTIALLY_SIGNED".into();
            return Ok(p.view.clone());
        }
        let raw = final_tx
            .get("hex")
            .and_then(Value::as_str)
            .filter(|s| s.len() <= 2_000_000)
            .ok_or_else(|| Error::new("TX", "Final transaction missing"))?;
        let decoded = rpc.call("decoderawtransaction", &json!([raw]), None, 20)?;
        if transaction_skeleton(&decoded)? != p.skeleton {
            return Err(Error::new(
                "TX_CHANGED",
                "Final transaction changed approved outputs, inputs, or locktime",
            ));
        }
        p.raw = Some(raw.into());
        p.view.txid = decoded
            .get("txid")
            .and_then(Value::as_str)
            .map(str::to_owned);
        p.view.state = "SIGNED_NOT_BROADCAST".into();
        Ok(p.view.clone())
    }
    pub fn broadcast(&mut self, rpc: &Rpc, id: &str, epoch: u64) -> Result<PlanView> {
        self.plan(id, epoch)?;
        let p = self.plans.get_mut(id).unwrap();
        if p.view.state != "SIGNED_NOT_BROADCAST" {
            return Err(Error::new(
                "PLAN_STATE",
                "Transaction is not ready for a first broadcast",
            ));
        }
        let raw = p
            .raw
            .as_ref()
            .ok_or_else(|| Error::new("TX", "Missing signed transaction"))?;
        // Unknown is latched before network I/O. No second send follows a timeout.
        p.view.state = "BROADCAST_UNKNOWN".into();
        let result = rpc.call("sendrawtransaction", &json!([raw]), None, 60)?;
        if result.as_str() != p.view.txid.as_deref() {
            return Err(Error::unknown(
                "Broadcast result does not match the reviewed transaction ID",
            ));
        }
        p.view.state = "BROADCAST_SUBMITTED_NOT_CONFIRMED".into();
        Ok(p.view.clone())
    }
    pub fn discard(&mut self, id: &str) {
        self.plans.remove(id);
    }
}
pub fn transaction_skeleton(tx: &Value) -> Result<Value> {
    let integer = |key: &str| {
        tx.get(key)
            .filter(|v| v.is_i64() || v.is_u64())
            .cloned()
            .ok_or_else(|| Error::new("TX", format!("Missing integer {key}")))
    };
    let ins = tx
        .get("vin")
        .and_then(Value::as_array)
        .filter(|x| !x.is_empty() && x.len() <= 512)
        .ok_or_else(|| Error::new("TX", "Invalid input count"))?;
    let outs = tx
        .get("vout")
        .and_then(Value::as_array)
        .filter(|x| !x.is_empty() && x.len() <= 128)
        .ok_or_else(|| Error::new("TX", "Invalid output count"))?;
    let mut vin = Vec::new();
    for i in ins {
        let id = i
            .get("txid")
            .and_then(Value::as_str)
            .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or_else(|| Error::new("TX", "Invalid input identity"))?;
        let out = i
            .get("vout")
            .and_then(Value::as_u64)
            .ok_or_else(|| Error::new("TX", "Invalid input index"))?;
        let seq = i
            .get("sequence")
            .and_then(Value::as_u64)
            .ok_or_else(|| Error::new("TX", "Invalid input sequence"))?;
        vin.push(json!({"txid":id.to_lowercase(),"vout":out,"sequence":seq}));
    }
    let mut vout = Vec::new();
    for o in outs {
        let amount = Amount::from_value(&o["value"])?;
        let script = o
            .pointer("/scriptPubKey/hex")
            .and_then(Value::as_str)
            .filter(|s| {
                s.len() <= 20000 && s.len() % 2 == 0 && s.bytes().all(|b| b.is_ascii_hexdigit())
            })
            .ok_or_else(|| Error::new("TX", "Invalid output script"))?;
        vout.push(json!({"atoms":amount.atoms().to_string(),"script":script.to_lowercase()}));
    }
    Ok(json!({"version":integer("version")?,"locktime":integer("locktime")?,"vin":vin,"vout":vout}))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn draft_rejects_float_and_duplicates() {
        let mut d = SendDraft {
            wallet: "test".into(),
            recipients: vec![Recipient {
                address: "btx1qtest".into(),
                amount: "0.00000001".into(),
            }],
            inputs: vec![],
            maximum_fee: "0.001".into(),
            fee_rate: "2".into(),
            replaceable: true,
        };
        assert!(d.validate().is_ok());
        d.recipients.push(d.recipients[0].clone());
        assert!(d.validate().is_err());
    }
    #[test]
    fn skeleton_excludes_witness_not_outputs() {
        let mut tx = json!({"version":2,"locktime":0,"vin":[{"txid":"a".repeat(64),"vout":0,"sequence":4294967293u64}],"vout":[{"value":"1.00000001","scriptPubKey":{"hex":"0014aabb"}}]});
        let a = transaction_skeleton(&tx).unwrap();
        tx["vin"][0]["txinwitness"] = json!(["abc"]);
        assert_eq!(a, transaction_skeleton(&tx).unwrap());
        tx["vout"][0]["value"] = json!("1.00000002");
        assert_ne!(a, transaction_skeleton(&tx).unwrap());
    }
}
