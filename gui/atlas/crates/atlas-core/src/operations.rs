use crate::{hash, now_ms, random_id, strict_json, Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use zeroize::Zeroize;

// openbtxuri, openmodelshare, decoderesource, and decoderesourceuri read a local file
// when the argument is a filesystem path, so they are not silent reads. They stay
// available through the prepared approval path. They do not spend and do not start inference.
const READ_METHODS: &[&str] = &[
    "getblockchaininfo",
    "getnetworkinfo",
    "getpeerinfo",
    "getnettotals",
    "getmempoolinfo",
    "getmininginfo",
    "getsetupstatus",
    "uptime",
    "listbanned",
    "listwallets",
    "listwalletdir",
    "getmemoryinfo",
    "getrpcinfo",
    "getblockhash",
    "getblock",
    "getrawmempool",
    "getrawtransaction",
    "gettxout",
    "help",
    "validateaddress",
    "estimatesmartfee",
    "getwalletinfo",
    "getbalances",
    "listaddressgroupings",
    "listlockunspent",
    "listtransactions",
    "listunspent",
    "gettransaction",
    "getaddressinfo",
    "listreceivedbyaddress",
    "listlabels",
    "getaddressesbylabel",
    "decodepsbt",
    "analyzepsbt",
    "decoderawtransaction",
    "verifymessage",
    "getbalancewatch",
    "getbalanceatheight",
    "getmodelnetworkinfo",
    "getmodelcryptoinfo",
    "checkmodelsetup",
    "getmodeltransfers",
    "listmodels",
    "getmodelwatchstatus",
    "getmodelhostprofile",
    "getmodelpolicy",
    "getmodelpeers",
    "listmodelidentities",
    "listmodelrules",
    "getmodelreciprocity",
    "getmodelaliases",
    "listbountydrafts",
    "getmodelfeed",
    "getrecentreleases",
    "getfundablemodels",
    "getrecentlyunlockedmodels",
    "getreleasefeed",
    "showmodel",
    "getmodelsharecard",
    "getmodelmanifest",
    "getmodelrelease",
    "getmodeljob",
    "getbounty",
    "getbountyeconomy",
    "getbountyterms",
    "getbountydraft",
    "searchmodels",
    "searchbounties",
    "getbountycapabilities",
    "getbtxruntimecapabilities",
    "getbtxttctrace",
    "getcloudstorageinfo",
    "getmodeldirectoryentry",
    "getmodeleconomyentry",
    "getmodeleventsequence",
    "getmodelfeedsequence",
    "getmodelprofile",
    "getmodelreleaseeconomics",
    "getresourcegovernorinfo",
    "getsearchstatus",
    "listmodelwatches",
    "searchcollections",
    "searchpublishers",
];
const AGENT_READS: &[&str] = &[
    "getblockchaininfo",
    "getmodelnetworkinfo",
    "getmodelhostprofile",
    "getsetupstatus",
    "getmininginfo",
    "listmodels",
    "getmodeltransfers",
];
const SECRET_METHODS: &[&str] = &[
    "walletpassphrase",
    "walletpassphrasechange",
    "encryptwallet",
    "createwallet",
    "migratewallet",
    "dumpprivkey",
    "dumpwallet",
    "importprivkey",
    "importwallet",
    "signmessage",
    "walletprocesspsbt",
    "signrawtransactionwithkey",
    "listdescriptors",
    "signmessagewithprivkey",
    "sweepprivkeys",
    "sethdseed",
    "exportwalletbundle",
    "restorewalletbundle",
    "restorewalletbundlearchive",
];
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub method: String,
    pub params_json: String,
    #[serde(default)]
    pub wallet: Option<String>,
}
impl Drop for Request {
    fn drop(&mut self) {
        self.params_json.zeroize();
    }
}
impl Request {
    pub fn parse(&self) -> Result<Value> {
        if self.method.is_empty()
            || self.method.len() > 96
            || !self
                .method
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(Error::new("METHOD", "Invalid RPC method name"));
        }
        if self
            .wallet
            .as_ref()
            .is_some_and(|w| w.len() > 512 || w.chars().any(char::is_control))
        {
            return Err(Error::new("WALLET", "Invalid wallet name"));
        }
        let p = strict_json::parse(self.params_json.as_bytes(), strict_json::MAX_REQUEST)?;
        if !p.is_array() && !p.is_object() {
            return Err(Error::new(
                "PARAMETERS",
                "RPC params must be an array or object",
            ));
        }
        Ok(p)
    }
    pub fn sensitive(&self) -> bool {
        SECRET_METHODS.contains(&self.method.as_str())
    }
    pub fn digest(&self) -> Result<String> {
        let p = self.parse()?;
        Ok(hash(
            serde_json::to_string(&json!({"method":self.method,"wallet":self.wallet,"params":p}))
                .map_err(|_| Error::new("JSON", "Cannot hash request"))?
                .as_bytes(),
        ))
    }
    pub fn summary(&self) -> Result<String> {
        let p = self.parse()?;
        let body = if self.method == "importdescriptors" {
            "Descriptor import. Descriptor material is hidden from this dialog. Approval still covers the exact submitted bytes.".to_owned()
        } else {
            // Redact credential fields, not the operation's non-secret semantics. The
            // native dialog still shows wallet, timeout, destination/message and switches.
            let mut shown = p.clone();
            let positions: &[usize] = match self.method.as_str() {
                "walletpassphrase"
                | "encryptwallet"
                | "importprivkey"
                | "signmessagewithprivkey" => &[0],
                "walletpassphrasechange" => &[0, 1],
                "createwallet" => &[3],
                "migratewallet" | "sethdseed" | "exportwalletbundle" => &[1],
                "signrawtransactionwithkey" => &[1],
                "restorewalletbundle" => &[4],
                "restorewalletbundlearchive" => &[2],
                _ => &[],
            };
            // Named credentials are hidden at every depth: sweepprivkeys takes them
            // inside its first positional object, and options objects nest them too.
            const CREDENTIAL_NAMES: &[&str] = &[
                "passphrase",
                "oldpassphrase",
                "newpassphrase",
                "wallet_passphrase",
                "archive_passphrase",
                "private_keys",
                "privkeys",
                "privkey",
                "privatekey",
                "seed",
            ];
            fn hide_names(value: &mut Value) {
                match value {
                    Value::Object(o) => {
                        for (name, v) in o.iter_mut() {
                            if CREDENTIAL_NAMES.contains(&name.as_str()) {
                                *v = json!("[credential hidden]");
                            } else {
                                hide_names(v);
                            }
                        }
                    }
                    Value::Array(a) => a.iter_mut().for_each(hide_names),
                    _ => {}
                }
            }
            // The node turns an object key "args" into the positional array
            // (transformNamedArguments). Hide the same indexes there.
            fn hide_positions(values: &mut [Value], positions: &[usize]) {
                for i in positions {
                    if let Some(v) = values.get_mut(*i) {
                        *v = json!("[credential hidden]");
                    }
                }
            }
            if let Some(a) = shown.as_array_mut() {
                hide_positions(a, positions);
            }
            if let Some(o) = shown.as_object_mut() {
                if let Some(args) = o.get_mut("args").and_then(Value::as_array_mut) {
                    hide_positions(args, positions);
                }
            }
            hide_names(&mut shown);
            let body = serde_json::to_string_pretty(&shown)
                .map_err(|_| Error::new("JSON", "Cannot show request"))?;
            if body.len() > 12000 {
                return Err(Error::new(
                    "REVIEW_SIZE",
                    "Request too large for complete native review. Use the PSBT or file workflow.",
                ));
            }
            body
        };
        Ok(format!(
            "Method: {}\nWallet: {}\n\n{}",
            self.method,
            self.wallet.as_deref().unwrap_or("node / none"),
            body
        ))
    }
}
pub fn read_allowed(method: &str, params: &Value) -> bool {
    if !READ_METHODS.contains(&method) {
        return false;
    }
    if matches!(
        method,
        "searchmodels" | "searchbounties" | "searchcollections" | "searchpublishers"
    ) {
        return search_stays_local(params);
    }
    true
}
fn search_stays_local(params: &Value) -> bool {
    let query = if params.is_array() {
        match params.get(0) {
            Some(v) => v,
            None => return true,
        }
    } else if params.is_object() {
        params.get("query").unwrap_or(params)
    } else {
        return false;
    };
    match query {
        Value::Object(o) => match o.get("scope") {
            Some(Value::String(s)) => s.eq_ignore_ascii_case("local"),
            Some(_) => false,
            None => !o.contains_key("text") && !o.contains_key("query"),
        },
        _ => false,
    }
}
fn private_flag(params: &Value) -> bool {
    // Positional form, plus params["args"] when it is the array the node
    // substitutes for positional parameters. A sibling "private" key still counts.
    // gethdkeys names its object "options"; only a JSON bool true at
    // options.private exports the seed. The same check runs on args arrays.
    fn on(params: &Value) -> bool {
        params == &Value::Bool(true)
            || params.get(0) == Some(&Value::Bool(true))
            || params.get("private") == Some(&Value::Bool(true))
            || params.get(0).and_then(|v| v.get("private")) == Some(&Value::Bool(true))
            || params.get("options").and_then(|v| v.get("private")) == Some(&Value::Bool(true))
            || params
                .get(0)
                .and_then(|v| v.get("options"))
                .and_then(|v| v.get("private"))
                == Some(&Value::Bool(true))
    }
    on(params)
        || params
            .get("args")
            .filter(|args| args.is_array())
            .is_some_and(on)
}
pub fn agent_read_allowed(method: &str) -> bool {
    AGENT_READS.contains(&method)
}
pub fn verify_zero_spend(method: &str, p: &Value) -> Result<()> {
    if matches!(
        method,
        "setmodelpolicy"
            | "getmodel"
            | "ensurebtxcapability"
            | "planbtxcapability"
            | "planbtxcapabilityupdate"
            | "prefetchbtxcapability"
            | "releasebtxcapability"
            | "sleepbtxcapability"
            | "switchbtxcapability"
            | "wakebtxcapability"
    ) {
        fn walk(v: &Value) -> bool {
            match v {
                Value::Object(m) => m.iter().all(|(k, v)| match k.as_str() {
                    "automatic_spend_atoms" => v == "0" || v == &json!(0),
                    "auto_pay" => v == &Value::Bool(false),
                    "mode" | "retrieval_mode" => v == "FREE_ONLY",
                    _ => walk(v),
                }),
                Value::Array(a) => a.iter().all(walk),
                _ => true,
            }
        }
        if !walk(p) {
            return Err(Error::new(
                "AUTO_SPEND_DENIED",
                "Atlas does not widen the current zero-spend/free-only policy",
            ));
        }
    }
    Ok(())
}
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Phase {
    Prepared,
    Approved,
    Submitted,
    Succeeded,
    Rejected,
    Unknown,
    Cancelled,
    Expired,
}
#[derive(Debug, Copy, Clone)]
pub enum Event {
    Approve,
    Submit,
    Succeed,
    Reject,
    Indeterminate,
    Cancel,
    Expire,
}
pub fn transition(state: Phase, event: Event) -> Result<Phase> {
    use Event::*;
    use Phase::*;
    match (state, event) {
        (Prepared, Approve) => Ok(Approved),
        (Approved, Submit) => Ok(Submitted),
        (Submitted, Succeed) => Ok(Succeeded),
        (Submitted, Reject) => Ok(Rejected),
        (Submitted, Indeterminate) => Ok(Unknown),
        (Prepared, Cancel) | (Approved, Cancel) => Ok(Cancelled),
        (Prepared, Expire) | (Approved, Expire) => Ok(Expired),
        _ => Err(Error::new("STATE", "Illegal operation state transition")),
    }
}
struct Prepared {
    request: Request,
    epoch: u64,
    created_ms: u64,
    digest: String,
}
#[derive(Default)]
pub struct PreparedStore {
    entries: HashMap<String, Prepared>,
}
#[derive(Serialize)]
pub struct PreparedView {
    pub id: String,
    pub method: String,
    pub wallet: Option<String>,
    pub digest: String,
    pub expires_at_ms: u64,
    pub sensitive: bool,
}
impl PreparedStore {
    pub fn prepare(&mut self, request: Request, epoch: u64) -> Result<PreparedView> {
        let now = now_ms();
        self.entries
            .retain(|_, p| now.saturating_sub(p.created_ms) < 120_000);
        if self.entries.len() >= 16 {
            return Err(Error::new(
                "QUEUE_FULL",
                "At most sixteen pending approvals",
            ));
        }
        let p = request.parse()?;
        if matches!(
            request.method.as_str(),
            "dumpprivkey"
                | "dumpwallet"
                | "backupwallet"
                | "backupwalletbundle"
                | "backupwalletbundlearchive"
        ) || (matches!(request.method.as_str(), "listdescriptors" | "gethdkeys")
            && private_flag(&p))
        {
            return Err(Error::new(
                "KEY_EXPORT_DENIED",
                "Private key, seed, and wallet-file export are excluded from Atlas.",
            ));
        }
        verify_zero_spend(&request.method, &p)?;
        let digest = request.digest()?;
        let id = random_id()?;
        let view = PreparedView {
            id: id.clone(),
            method: request.method.clone(),
            wallet: request.wallet.clone(),
            digest: digest.clone(),
            expires_at_ms: now + 120000,
            sensitive: request.sensitive(),
        };
        self.entries.insert(
            id,
            Prepared {
                request,
                epoch,
                created_ms: now,
                digest,
            },
        );
        Ok(view)
    }
    /// Consume before showing the native dialog. A second submission cannot reuse it.
    pub fn consume(&mut self, id: &str, epoch: u64) -> Result<Request> {
        let p = self
            .entries
            .remove(id)
            .ok_or_else(|| Error::new("APPROVAL", "Unknown or already consumed approval"))?;
        if p.epoch != epoch {
            return Err(Error::new(
                "CONNECTION_CHANGED",
                "Approval belongs to another connection",
            ));
        }
        if now_ms().saturating_sub(p.created_ms) >= 120000 {
            return Err(Error::new("APPROVAL_EXPIRED", "Approval expired"));
        }
        if p.request.digest()? != p.digest {
            return Err(Error::new("APPROVAL_CHANGED", "Prepared command changed"));
        }
        Ok(p.request)
    }
    pub fn clear(&mut self) {
        self.entries.clear();
    }
    pub fn cancel(&mut self, id: &str) {
        self.entries.remove(id);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn no_agent_writes() {
        for m in [
            "sendtoaddress",
            "stop",
            "generatemodel",
            "walletprocesspsbt",
            "setmodelpolicy",
            "help",
        ] {
            assert!(!agent_read_allowed(m));
        }
    }
    #[test]
    fn read_is_not_prefix() {
        assert!(!read_allowed("getnewaddress", &json!([])));
        assert!(!read_allowed("getmodel", &json!([])));
        assert!(!read_allowed("getdangerous", &json!([])));
    }
    #[test]
    fn network_queries() {
        for method in [
            "searchmodels",
            "searchbounties",
            "searchcollections",
            "searchpublishers",
        ] {
            assert!(read_allowed(method, &json!([{"scope":"LOCAL"}])));
            assert!(read_allowed(method, &json!([{"scope":"local"}])));
            assert!(read_allowed(method, &json!([])));
            assert!(!read_allowed(method, &json!(["text"])));
            assert!(!read_allowed(
                method,
                &json!({"query":"text","scope":"NETWORK"})
            ));
            assert!(!read_allowed(method, &json!(["text", {"scope":"NETWORK"}])));
            assert!(!read_allowed(method, &json!([{"text":"x"}])));
            assert!(!read_allowed(method, &json!([{"scope":"NETWORK"}])));
            assert!(!read_allowed(method, &json!([{"scope":"PEERS"}])));
            assert!(!read_allowed(method, &json!([{"scope":"ALL"}])));
            assert!(!read_allowed(method, &json!([{"scope":""}])));
        }
    }
    #[test]
    fn path_reads_need_approval() {
        for method in [
            "openbtxuri",
            "openmodelshare",
            "decoderesource",
            "decoderesourceuri",
        ] {
            assert!(!read_allowed(method, &json!(["/tmp/x"])));
        }
    }
    #[test]
    fn key_export_denied() {
        let mut s = PreparedStore::default();
        match s.prepare(
            Request {
                method: "backupwallet".into(),
                params_json: "[]".into(),
                wallet: None,
            },
            1,
        ) {
            Err(e) => assert_eq!(e.code, "KEY_EXPORT_DENIED"),
            Ok(_) => panic!("backupwallet was prepared"),
        }
        match s.prepare(
            Request {
                method: "gethdkeys".into(),
                params_json: "[true]".into(),
                wallet: None,
            },
            1,
        ) {
            Err(e) => assert_eq!(e.code, "KEY_EXPORT_DENIED"),
            Ok(_) => panic!("private gethdkeys was prepared"),
        }
        match s.prepare(
            Request {
                method: "gethdkeys".into(),
                params_json: r#"[{"private":true}]"#.into(),
                wallet: None,
            },
            1,
        ) {
            Err(e) => assert_eq!(e.code, "KEY_EXPORT_DENIED"),
            Ok(_) => panic!("private gethdkeys was prepared"),
        }
        assert!(s
            .prepare(
                Request {
                    method: "gethdkeys".into(),
                    params_json: "[false]".into(),
                    wallet: None,
                },
                1,
            )
            .is_ok());
    }
    #[test]
    fn args_key_export_denied() {
        let mut s = PreparedStore::default();
        match s.prepare(
            Request {
                method: "listdescriptors".into(),
                params_json: r#"{"args":[true]}"#.into(),
                wallet: None,
            },
            1,
        ) {
            Err(e) => assert_eq!(e.code, "KEY_EXPORT_DENIED"),
            Ok(_) => panic!("private listdescriptors was prepared"),
        }
        match s.prepare(
            Request {
                method: "gethdkeys".into(),
                params_json: r#"{"args":[{"private":true}]}"#.into(),
                wallet: None,
            },
            1,
        ) {
            Err(e) => assert_eq!(e.code, "KEY_EXPORT_DENIED"),
            Ok(_) => panic!("private gethdkeys was prepared"),
        }
        match s.prepare(
            Request {
                method: "listdescriptors".into(),
                params_json: r#"{"args":[false],"private":true}"#.into(),
                wallet: None,
            },
            1,
        ) {
            Err(e) => assert_eq!(e.code, "KEY_EXPORT_DENIED"),
            Ok(_) => panic!("named private listdescriptors was prepared"),
        }
        assert!(s
            .prepare(
                Request {
                    method: "listdescriptors".into(),
                    params_json: r#"{"args":[false]}"#.into(),
                    wallet: None,
                },
                1,
            )
            .is_ok());
        assert!(s
            .prepare(
                Request {
                    method: "gethdkeys".into(),
                    params_json: r#"{"args":[{"private":false}]}"#.into(),
                    wallet: None,
                },
                1,
            )
            .is_ok());
    }
    #[test]
    fn options_private_key_export_denied() {
        let mut s = PreparedStore::default();
        for params_json in [
            r#"{"options":{"private":true}}"#,
            r#"{"options":{"private":true,"active_only":true}}"#,
            r#"[{"options":{"private":true}}]"#,
            r#"{"args":[{"options":{"private":true}}]}"#,
            r#"{"args":[{"private":true}]}"#,
        ] {
            match s.prepare(
                Request {
                    method: "gethdkeys".into(),
                    params_json: params_json.into(),
                    wallet: None,
                },
                1,
            ) {
                Err(e) => assert_eq!(e.code, "KEY_EXPORT_DENIED"),
                Ok(_) => panic!("private gethdkeys was prepared: {params_json}"),
            }
        }
        for params_json in [
            r#"{"options":{"private":false}}"#,
            r#"{"options":{"active_only":true}}"#,
            r#"{"options":{"private":"true"}}"#,
        ] {
            assert!(
                s.prepare(
                    Request {
                        method: "gethdkeys".into(),
                        params_json: params_json.into(),
                        wallet: None,
                    },
                    1,
                )
                .is_ok(),
                "gethdkeys should prepare: {params_json}"
            );
        }
    }
    #[test]
    fn importdescriptors_summary_hides_material() {
        let descriptor = "wpkh(xprv9s21ZrQH143KSECRETDESCRIPTOR/0/*)";
        let summary = Request {
            method: "importdescriptors".into(),
            params_json: json!([{"desc": descriptor}]).to_string(),
            wallet: None,
        }
        .summary()
        .unwrap();
        assert!(!summary.contains(descriptor));
        assert!(summary.contains(
            "Descriptor import. Descriptor material is hidden from this dialog. Approval still covers the exact submitted bytes."
        ));
    }
    #[test]
    fn walletpassphrase_args_summary_hides_passphrase() {
        let summary = Request {
            method: "walletpassphrase".into(),
            params_json: r#"{"args":["secret-passphrase",60]}"#.into(),
            wallet: None,
        }
        .summary()
        .unwrap();
        assert!(!summary.contains("secret-passphrase"));
        assert!(summary.contains("[credential hidden]"));
        assert!(summary.contains("60"));
    }
    #[test]
    fn bundle_and_key_credentials_hidden_in_summary() {
        let secret = "secret-credential-value";
        let cases = [
            ("exportwalletbundle", json!(["/tmp/w.btxwallet", secret])),
            (
                "restorewalletbundle",
                json!(["w", "/tmp/w.btxwallet", null, null, secret]),
            ),
            (
                "restorewalletbundlearchive",
                json!(["w", "/tmp/w.archive", secret]),
            ),
            ("restorewalletbundle", json!({"wallet_passphrase": secret})),
            (
                "restorewalletbundlearchive",
                json!({"args": ["w", "/tmp/w.archive", secret]}),
            ),
            ("signmessagewithprivkey", json!([secret, "message"])),
            ("sethdseed", json!([true, secret])),
            (
                "sweepprivkeys",
                json!([{"privkeys": [secret], "label": "x"}]),
            ),
            ("sweepprivkeys", json!({"options": {"privkeys": [secret]}})),
        ];
        for (method, params) in cases {
            let request = Request {
                method: method.into(),
                params_json: params.to_string(),
                wallet: None,
            };
            let summary = request.summary().unwrap();
            assert!(
                !summary.contains(secret),
                "{method} {params} shows the credential"
            );
            assert!(summary.contains("[credential hidden]"), "{method} {params}");
            assert!(request.sensitive(), "{method} is not marked sensitive");
        }
    }
    #[test]
    fn state() {
        assert!(transition(Phase::Prepared, Event::Submit).is_err());
        assert!(transition(Phase::Unknown, Event::Submit).is_err());
        assert_eq!(
            transition(Phase::Approved, Event::Submit).unwrap(),
            Phase::Submitted
        );
    }
    #[test]
    fn single_use() {
        let mut s = PreparedStore::default();
        let v = s
            .prepare(
                Request {
                    method: "walletlock".into(),
                    params_json: "[]".into(),
                    wallet: Some("w".into()),
                },
                3,
            )
            .unwrap();
        assert!(s.consume(&v.id, 3).is_ok());
        assert!(s.consume(&v.id, 3).is_err());
    }
    #[test]
    fn epoch() {
        let mut s = PreparedStore::default();
        let v = s
            .prepare(
                Request {
                    method: "stop".into(),
                    params_json: "[]".into(),
                    wallet: None,
                },
                1,
            )
            .unwrap();
        assert!(s.consume(&v.id, 2).is_err());
    }
    #[test]
    fn zero_spend() {
        assert!(
            verify_zero_spend("setmodelpolicy", &json!([{"automatic_spend_atoms":"1"}])).is_err()
        );
        assert!(verify_zero_spend("getmodel", &json!(["m",{"mode":"PAID"}])).is_err());
        assert!(verify_zero_spend(
            "planbtxcapability",
            &json!([{"grant":{"automatic_spend_atoms":"1"}}])
        )
        .is_err());
        assert!(verify_zero_spend(
            "wakebtxcapability",
            &json!([{"automatic_spend_atoms":"0","remap_only":false}])
        )
        .is_ok());
    }
}
