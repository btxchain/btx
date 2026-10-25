use atlas_core::{
    agent::Agent, auth::CookieSource, journal::Journal, money::Money, operations::PreparedStore,
    rpc::Rpc, Error, Result,
};
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, MutexGuard,
    },
};
use tauri::{AppHandle, WebviewWindow};
#[derive(Clone)]
pub struct Connection {
    pub rpc: Rpc,
    pub epoch: u64,
    pub genesis: String,
    pub chain: String,
}
pub struct Host {
    pub connection: Mutex<Option<Connection>>,
    pub epoch: AtomicUsize,
    pub gate: Mutex<()>,
    pub approvals: Mutex<PreparedStore>,
    pub money: Mutex<Money>,
    pub agent: Mutex<Agent>,
    pub journal: Mutex<Journal>,
    pub config: Mutex<Option<PathBuf>>,
    pub links: Mutex<Vec<String>>,
    pub reads: AtomicUsize,
    pub clipboard: Mutex<Option<arboard::Clipboard>>,
}
pub fn lock<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>> {
    mutex.lock().map_err(|_| {
        Error::new(
            "HOST_STATE",
            "Native state lock was poisoned; restart the client",
        )
    })
}
impl Host {
    pub fn new(path: PathBuf) -> Result<Self> {
        Ok(Self {
            connection: Mutex::new(None),
            epoch: AtomicUsize::new(0),
            gate: Mutex::new(()),
            approvals: Mutex::new(PreparedStore::default()),
            money: Mutex::new(Money::default()),
            agent: Mutex::new(Agent::default()),
            journal: Mutex::new(Journal::open(path)?),
            config: Mutex::new(None),
            links: Mutex::new(Vec::new()),
            reads: AtomicUsize::new(0),
            clipboard: Mutex::new(None),
        })
    }
    pub fn connected(&self) -> Result<Connection> {
        lock(&self.connection)?.clone().ok_or_else(|| {
            Error::new(
                "DISCONNECTED",
                "Connect to a locally running BTX node first",
            )
        })
    }
    pub fn recheck(&self, c: &Connection) -> Result<()> {
        let current = self.connected()?;
        if current.epoch != c.epoch || current.genesis != c.genesis {
            return Err(Error::new(
                "CONNECTION_CHANGED",
                "Connection changed during operation",
            ));
        }
        let genesis = c.rpc.call("getblockhash", &json!([0]), None, 20)?;
        if genesis.as_str() != Some(&c.genesis) {
            return Err(Error::new(
                "CHAIN_CHANGED",
                "Connected chain no longer matches approved genesis",
            ));
        }
        Ok(())
    }
    pub fn envelope(&self, c: &Connection, result: Value) -> Result<Value> {
        if self.connected()?.epoch != c.epoch {
            return Err(Error::new(
                "STALE_RESULT",
                "Discarded response from the previous connection",
            ));
        }
        Ok(
            json!({"ok":true,"observed_at":atlas_core::now_ms(),"epoch":c.epoch,"chain":c.chain,"result":atlas_core::strict_json::for_ui(result),"consistency":"LOCAL_NONATOMIC","complete":false}),
        )
    }
    pub fn audit(&self, id: &str, method: &str, phase: &str) -> Result<()> {
        lock(&self.journal)?.append(id, method, phase)?;
        Ok(())
    }
    pub fn receive_link(&self, value: &str) {
        if value.len() <= 4096
            && (value.starts_with("btx:") || value.starts_with("btx-p2p:"))
            && !value.chars().any(char::is_control)
        {
            if let Ok(mut links) = self.links.lock() {
                if links.len() < 8 {
                    links.push(value.into());
                }
            }
        }
    }
}
pub fn authorize(window: &WebviewWindow) -> Result<()> {
    let url = window
        .url()
        .map_err(|_| Error::new("ORIGIN", "Cannot establish native window origin"))?;
    let trusted = url.scheme() == "tauri" && url.host_str() == Some("localhost")
        || matches!(url.scheme(), "http" | "https") && url.host_str() == Some("tauri.localhost");
    if window.label() != "main" || !trusted {
        return Err(Error::new(
            "ORIGIN",
            "Only the packaged main window may invoke native commands",
        ));
    }
    Ok(())
}
pub async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|_| {
        Error::new(
            "HOST_TASK",
            "Native task stopped unexpectedly; inspect the journal before retrying",
        )
    })?
}
pub fn main_thread<T: Send + 'static>(
    app: &AppHandle,
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T> {
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    app.run_on_main_thread(move || {
        let _ = tx.send(f());
    })
    .map_err(|_| Error::new("NATIVE_UI", "Cannot open trusted native control"))?;
    rx.recv()
        .map_err(|_| Error::new("NATIVE_UI", "Native control closed unexpectedly"))
}
pub fn confirm(app: &AppHandle, title: &str, message: String) -> Result<()> {
    if message.len() > 20000 {
        return Err(Error::new(
            "REVIEW_SIZE",
            "Native review exceeds its complete-display budget",
        ));
    }
    let title = format!("BTX ATLAS • {title}");
    let ok = main_thread(app, move || {
        rfd::MessageDialog::new()
            .set_title(title)
            .set_description(message)
            .set_buttons(rfd::MessageButtons::OkCancel)
            .set_level(rfd::MessageLevel::Warning)
            .show()
            == rfd::MessageDialogResult::Ok
    })?;
    if !ok {
        return Err(Error::new(
            "CANCELLED",
            "Cancelled in the native confirmation dialog",
        ));
    }
    Ok(())
}
pub fn pick(app: &AppHandle, save: bool, title: &str) -> Result<PathBuf> {
    let title = title.to_owned();
    main_thread(app, move || {
        let d = rfd::FileDialog::new().set_title(title);
        if save {
            d.save_file()
        } else {
            d.pick_file()
        }
    })?
    .ok_or_else(|| Error::new("CANCELLED", "No file selected"))
}
pub fn pick_folder(app: &AppHandle, title: &str) -> Result<PathBuf> {
    let title = title.to_owned();
    main_thread(app, move || {
        rfd::FileDialog::new().set_title(title).pick_folder()
    })?
    .ok_or_else(|| Error::new("CANCELLED", "No directory selected"))
}
pub struct ReadSlot {
    host: Arc<Host>,
}
impl ReadSlot {
    pub fn acquire(host: Arc<Host>) -> Result<Self> {
        let previous = host.reads.fetch_add(1, Ordering::SeqCst);
        if previous >= 4 {
            host.reads.fetch_sub(1, Ordering::SeqCst);
            return Err(Error::new(
                "BUSY",
                "At most four concurrent observation requests",
            ));
        }
        Ok(Self { host })
    }
}
impl Drop for ReadSlot {
    fn drop(&mut self) {
        self.host.reads.fetch_sub(1, Ordering::SeqCst);
    }
}
pub fn connect(app: &AppHandle, host: &Host, endpoint: String) -> Result<Value> {
    let _gate = lock(&host.gate)?;
    let cookie = pick(
        app,
        false,
        "Choose this BTX node's RPC .cookie file (never shown to the page)",
    )?;
    let rpc = Rpc::new(&endpoint, CookieSource::new(cookie)?)?;
    let chain = rpc.call("getblockchaininfo", &json!([]), None, 20)?;
    let genesis = rpc.call("getblockhash", &json!([0]), None, 20)?;
    let chain_name = chain
        .get("chain")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new("CHAIN", "Node has no chain identity"))?
        .to_owned();
    let genesis = genesis
        .as_str()
        .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| Error::new("CHAIN", "Invalid genesis identity"))?
        .to_owned();
    confirm(app,"Connect to local node",format!("Endpoint: {endpoint}\nChain: {chain_name}\nGenesis: {genesis}\n\nAtlas will observe this node. Every write still requires native confirmation. Wallet keys remain with btxd. A compromised same-user process is outside this boundary."))?;
    let epoch = host.epoch.fetch_add(1, Ordering::SeqCst) as u64 + 1;
    let c = Connection {
        rpc,
        epoch,
        genesis,
        chain: chain_name,
    };
    *lock(&host.connection)? = Some(c.clone());
    lock(&host.approvals)?.clear();
    lock(&host.money)?.clear();
    lock(&host.agent)?.revoke();
    host.envelope(&c, chain)
}
