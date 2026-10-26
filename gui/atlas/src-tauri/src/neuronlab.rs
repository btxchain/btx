//! Private, bounded research-worker bridge. No browser RPC cookie or wallet key.
//! Native compilation/platform qualification is tracked separately in the report.
use crate::host::{authorize, blocking, confirm, lock, pick, pick_folder, Host};
use atlas_core::{files, strict_json, Error, Result};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::{Duration, Instant},
};
use tauri::{AppHandle, Emitter, Manager, State, WebviewWindow};

const INPUT_LIMIT: usize = 262_144;
const OUTPUT_LIMIT: usize = 8_388_608;
const READS: &[&str] = &[
    "status",
    "list",
    "models",
    "profile",
    "events",
    "receipts",
    "binding",
    "router_preview",
    "adapter_catalog",
    "embeddings_list",
    "embeddings_page",
    "session_list",
    "session_get",
    "session_operation",
    "trace_get",
    "qualification_list",
    "annotation_get",
    "sweep_get",
];
const COMPUTE: &[&str] = &[
    "compare",
    "generate",
    "study_run",
    "direction",
    "lens",
    "run_router",
    "embeddings_import",
    "embeddings_capture",
    "embeddings_neighbors",
    "session_turn",
    "trace_chunk",
    "trace_path",
    "trace_interaction",
    "model_qualify",
    "activation_scan",
    "measured_lens",
    "connection_cone",
    "sweep_chunk",
];
const ACTIONS: &[&str] = &[
    "status",
    "list",
    "models",
    "profile",
    "events",
    "receipts",
    "binding",
    "router_preview",
    "initialize",
    "register",
    "create",
    "import",
    "export",
    "trust",
    "revoke",
    "activate",
    "deactivate",
    "compare",
    "generate",
    "direction",
    "lens",
    "study_plan",
    "study_run",
    "evaluate",
    "save_router",
    "run_router",
    "import_evidence",
    "adapter_catalog",
    "embeddings_list",
    "embeddings_page",
    "session_list",
    "session_get",
    "session_operation",
    "trace_get",
    "qualification_list",
    "annotation_get",
    "sweep_get",
    "embeddings_import",
    "embeddings_capture",
    "embeddings_neighbors",
    "session_turn",
    "trace_chunk",
    "trace_path",
    "trace_interaction",
    "model_qualify",
    "activation_scan",
    "measured_lens",
    "connection_cone",
    "sweep_chunk",
    "session_create",
    "session_fork",
    "session_recover",
    "trace_plan",
    "annotation_set",
    "sweep_plan",
];
static CANCEL: AtomicU64 = AtomicU64::new(0);
static PROCESSES: AtomicUsize = AtomicUsize::new(0);
static HEAVY: AtomicUsize = AtomicUsize::new(0);
static CONFIG: OnceLock<Mutex<Option<Runner>>> = OnceLock::new();
#[derive(Clone)]
struct Runner {
    python: PathBuf,
    entry: PathBuf,
    store: PathBuf,
    python_hash: String,
    manifest_hash: String,
}
struct Slot {
    heavy: bool,
}
impl Slot {
    fn acquire(heavy: bool) -> Result<Self> {
        if PROCESSES.fetch_add(1, Ordering::SeqCst) >= 3 {
            PROCESSES.fetch_sub(1, Ordering::SeqCst);
            return Err(Error::new(
                "LAB_BUSY",
                "At most three research operations may run",
            ));
        }
        if heavy && HEAVY.fetch_add(1, Ordering::SeqCst) >= 1 {
            HEAVY.fetch_sub(1, Ordering::SeqCst);
            PROCESSES.fetch_sub(1, Ordering::SeqCst);
            return Err(Error::new(
                "LAB_COMPUTE_BUSY",
                "Only one local scientific compute request may run",
            ));
        }
        Ok(Self { heavy })
    }
}
impl Drop for Slot {
    fn drop(&mut self) {
        PROCESSES.fetch_sub(1, Ordering::SeqCst);
        if self.heavy {
            HEAVY.fetch_sub(1, Ordering::SeqCst);
        }
    }
}
fn config() -> &'static Mutex<Option<Runner>> {
    CONFIG.get_or_init(|| Mutex::new(None))
}
fn err(code: &str, msg: &str) -> Error {
    Error::new(code, msg)
}
fn string<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v.get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| err("LAB_SCHEMA", "Missing text field"))
}
fn digest(value: &str) -> Result<()> {
    if value.len() != 96
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(err("LAB_ID", "Expected 96 lowercase hex characters"));
    }
    Ok(())
}
fn only_keys(p: &Value, allowed: &[&str]) -> Result<()> {
    let o = p
        .as_object()
        .ok_or_else(|| err("LAB_SCHEMA", "Object payload required"))?;
    if o.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err(err("LAB_SCHEMA", "Unknown payload field"));
    }
    Ok(())
}
fn source_manifest(entry: &Path) -> Result<(String, Value)> {
    if entry.file_name().and_then(|s| s.to_str()) != Some("worker.py") {
        return Err(err(
            "LAB_RUNNER",
            "Select the installed worker.py entry point",
        ));
    }
    let parent = entry
        .parent()
        .ok_or_else(|| err("LAB_RUNNER", "No source root"))?;
    let manifest = files::read_bounded(&parent.join("code-manifest.json"), 131072)?;
    let parsed = strict_json::parse(&manifest, 131072)?;
    if parsed.get("schema").and_then(Value::as_str) != Some("btx.neuronlab.code-manifest/1") {
        return Err(err("LAB_MANIFEST", "Unknown source-manifest schema"));
    }
    Ok((atlas_core::hash(&manifest), parsed))
}
fn verify_sources(r: &Runner) -> Result<()> {
    if atlas_core::hash(&files::read_bounded(&r.python, 268_435_456)?) != r.python_hash {
        return Err(err(
            "LAB_INTERPRETER_CHANGED",
            "Research interpreter changed; configure again",
        ));
    }
    let (hash, m) = source_manifest(&r.entry)?;
    if hash != r.manifest_hash {
        return Err(err(
            "LAB_SOURCE_CHANGED",
            "Research source manifest changed; configure again",
        ));
    }
    let root = r
        .entry
        .parent()
        .ok_or_else(|| err("LAB_RUNNER", "No source root"))?;
    let entries = m
        .get("files")
        .and_then(Value::as_object)
        .ok_or_else(|| err("LAB_MANIFEST", "Missing source file hashes"))?;
    if entries.is_empty() || entries.len() > 128 {
        return Err(err("LAB_MANIFEST", "Invalid source count"));
    }
    let mut allowed = BTreeSet::new();
    for (name, value) in entries {
        if name.contains("..")
            || name.contains('\\')
            || name.starts_with('/')
            || !name.ends_with(".py")
        {
            return Err(err("LAB_MANIFEST", "Unsafe source path"));
        }
        let path = root.join(name);
        let metadata =
            std::fs::symlink_metadata(&path).map_err(|_| err("LAB_SOURCE", "Source missing"))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(err("LAB_SOURCE", "Only regular source files are accepted"));
        }
        if Some(atlas_core::hash(&files::read_bounded(&path, 1_048_576)?).as_str())
            != value.as_str()
        {
            return Err(err("LAB_SOURCE_CHANGED", "Research module hash mismatch"));
        }
        allowed.insert(name.clone());
    }
    // Prevent a .so/.pyc or unlisted .py shadowing a reviewed package module.
    for entry in std::fs::read_dir(root.join("btx_neuronlab"))
        .map_err(|_| err("LAB_SOURCE", "Package directory unavailable"))?
    {
        let e = entry.map_err(|_| err("LAB_SOURCE", "Cannot enumerate installed package"))?;
        let name = format!("btx_neuronlab/{}", e.file_name().to_string_lossy());
        if !allowed.contains(&name) {
            return Err(err(
                "LAB_SOURCE_UNREVIEWED",
                "Unlisted files or bytecode in the package; use a clean reviewed installation",
            ));
        }
    }
    Ok(())
}
fn spawn_reader<T: Read + Send + 'static>(
    reader: T,
    max: usize,
) -> std::sync::mpsc::Receiver<std::io::Result<Vec<u8>>> {
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut out = Vec::new();
        let result = reader
            .take((max + 1) as u64)
            .read_to_end(&mut out)
            .map(|_| out);
        let _ = tx.send(result);
    });
    rx
}
// Streaming frames are private, bounded display data, never commands. Only the
// authorized main window receives them. The final result still has a release fence.
fn spawn_frames<T: Read + Send + 'static>(
    reader: T,
    app: Option<AppHandle>,
    operation: String,
    epoch: u64,
) -> std::sync::mpsc::Receiver<std::io::Result<Vec<u8>>> {
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = (|| -> std::io::Result<Vec<u8>> {
            let mut input = BufReader::new(reader);
            let mut final_frame: Option<Vec<u8>> = None;
            let mut events = 0usize;
            loop {
                let mut line = Vec::new();
                loop {
                    let buf = input.fill_buf()?;
                    if buf.is_empty() {
                        break;
                    }
                    let take = buf
                        .iter()
                        .position(|b| *b == b'\n')
                        .map(|i| i + 1)
                        .unwrap_or(buf.len());
                    if line.len() + take > OUTPUT_LIMIT + 1 {
                        return Err(std::io::Error::other("research frame size exceeded"));
                    }
                    let ended = buf[take - 1] == b'\n';
                    line.extend_from_slice(&buf[..take]);
                    input.consume(take);
                    if ended {
                        break;
                    }
                }
                if line.is_empty() {
                    break;
                }
                if final_frame.is_some() {
                    return Err(std::io::Error::other("frame after final response"));
                }
                let v = strict_json::parse(&line, OUTPUT_LIMIT)
                    .map_err(|_| std::io::Error::other("invalid research frame"))?;
                if let Some(event) = v.get("event") {
                    if line.len() > 65536
                        || v.as_object().map(|o| o.len()) != Some(2)
                        || v.get("operation_id").and_then(Value::as_str) != Some(operation.as_str())
                        || !event.is_object()
                    {
                        return Err(std::io::Error::other("invalid progress envelope"));
                    }
                    events += line.len();
                    if events > 4_194_304 {
                        return Err(std::io::Error::other("progress budget exceeded"));
                    }
                    if CANCEL.load(Ordering::SeqCst) != epoch {
                        return Err(std::io::Error::other("progress cancelled"));
                    }
                    if let Some(ref host) = app {
                        host.emit_to(
                            "main",
                            "neuronlab-progress",
                            json!({"operation_id":operation,"event":event}),
                        )
                        .map_err(|_| std::io::Error::other("progress delivery failed"))?;
                    }
                } else {
                    if v.get("ok").and_then(Value::as_bool).is_none() {
                        return Err(std::io::Error::other("missing final status"));
                    }
                    final_frame = Some(line);
                }
            }
            final_frame.ok_or_else(|| std::io::Error::other("missing final research response"))
        })();
        let _ = tx.send(result);
    });
    rx
}
fn run(r: &Runner, action: &str, payload: Value, operation_id: &str) -> Result<Value> {
    run_stream(r, action, payload, operation_id, None)
}
fn run_stream(
    r: &Runner,
    action: &str,
    payload: Value,
    operation_id: &str,
    app: Option<AppHandle>,
) -> Result<Value> {
    let _slot = Slot::acquire(COMPUTE.contains(&action))?;
    verify_sources(r)?;
    let start_epoch = CANCEL.load(Ordering::SeqCst);
    let mut raw =
        serde_json::to_vec(&json!({"action":action,"payload":payload,"operation_id":operation_id}))
            .map_err(|_| err("LAB_JSON", "Cannot serialize research request"))?;
    if raw.len() > INPUT_LIMIT {
        return Err(err("LAB_SIZE", "Research request exceeds 256 KiB"));
    }
    raw.push(b'\n');
    let mut cmd = Command::new(&r.python);
    cmd.arg("-I")
        .arg("-B")
        .arg(&r.entry)
        .arg("--store")
        .arg(&r.store)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear();
    for k in [
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "SystemRoot",
        "WINDIR",
        "PATH",
        "TMPDIR",
        "TEMP",
        "TMP",
    ] {
        if let Some(v) = std::env::var_os(k) {
            cmd.env(k, v);
        }
    }
    if app.is_some() {
        cmd.arg("--stream");
    }
    cmd.env("HF_HUB_OFFLINE", "1")
        .env("TRANSFORMERS_OFFLINE", "1")
        .env("OMP_NUM_THREADS", "2");
    let mut child = cmd.spawn().map_err(|_| {
        err(
            "LAB_LAUNCH",
            "Cannot start the approved research interpreter",
        )
    })?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| err("LAB_PIPE", "Missing private stdin"))?;
    let stdout = spawn_frames(
        child
            .stdout
            .take()
            .ok_or_else(|| err("LAB_PIPE", "Missing private stdout"))?,
        app,
        operation_id.to_owned(),
        start_epoch,
    );
    let stderr = spawn_reader(
        child
            .stderr
            .take()
            .ok_or_else(|| err("LAB_PIPE", "Missing private stderr"))?,
        65536,
    );
    let (tx, writer) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = stdin.write_all(&raw);
        drop(stdin);
        let _ = tx.send(result);
    });
    let deadline =
        Instant::now() + Duration::from_secs(if COMPUTE.contains(&action) { 900 } else { 60 });
    let exit = loop {
        if CANCEL.load(Ordering::SeqCst) != start_epoch || Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::unknown("Research job stopped or timed out; inspect its operation ID before retrying a mutation"));
        }
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Error::unknown("Research worker state is unknown"));
            }
        }
    };
    writer
        .recv_timeout(Duration::from_secs(2))
        .map_err(|_| Error::unknown("Worker input completion unknown"))?
        .map_err(|_| Error::unknown("Worker request delivery failed"))?;
    let out = stdout
        .recv_timeout(Duration::from_secs(2))
        .map_err(|_| Error::unknown("Worker output did not close"))?
        .map_err(|_| err("LAB_OUTPUT", "Cannot read worker result"))?;
    let diagnostics = stderr
        .recv_timeout(Duration::from_secs(2))
        .map_err(|_| err("LAB_OUTPUT", "Worker diagnostics did not close"))?
        .map_err(|_| err("LAB_OUTPUT", "Cannot read diagnostics"))?;
    if out.len() > OUTPUT_LIMIT || diagnostics.len() > 65536 {
        return Err(err("LAB_OUTPUT_LIMIT", "Worker output exceeded its bounds"));
    }
    if CANCEL.load(Ordering::SeqCst) != start_epoch {
        return Err(err("LAB_REVOKED", "Result release cancelled"));
    }
    let response = strict_json::parse(&out, OUTPUT_LIMIT)?;
    if response.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(Error::new(
            response
                .pointer("/error/code")
                .and_then(Value::as_str)
                .unwrap_or("LAB_FAILURE"),
            atlas_core::safe_text(
                response
                    .pointer("/error/message")
                    .and_then(Value::as_str)
                    .unwrap_or("Research worker refused request"),
                1024,
            ),
        ));
    }
    if !exit.success() {
        return Err(err("LAB_EXIT", "Worker exited unsuccessfully"));
    }
    response
        .get("result")
        .cloned()
        .ok_or_else(|| err("LAB_RESULT", "Worker result missing"))
}
fn uri(p: &Value) -> Result<String> {
    let s = string(p, "uri")?;
    if s.len() > 4096
        || !s.starts_with("btx://")
        || (s.contains('?') || s.contains('#'))
        || s.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(err("LAB_URI", "Expected canonical BTX resource URI"));
    }
    Ok(s.to_owned())
}

#[tauri::command]
pub fn atlas_neuronlab_cancel(window: WebviewWindow) -> Result<Value> {
    authorize(&window)?;
    let epoch = CANCEL.fetch_add(1, Ordering::SeqCst) + 1;
    Ok(json!({"cancel_epoch":epoch,"scope":"research-worker-only; monetary node untouched"}))
}

#[tauri::command]
pub async fn atlas_neuronlab(
    window: WebviewWindow,
    app: AppHandle,
    state: State<'_, Arc<Host>>,
    action: String,
    payload_json: String,
    operation_id: String,
) -> Result<Value> {
    authorize(&window)?;
    if operation_id.len() > 96
        || operation_id.is_empty()
        || !operation_id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        return Err(err("LAB_OPERATION_ID", "Invalid operation ID"));
    }
    let mut p = strict_json::parse(payload_json.as_bytes(), INPUT_LIMIT)?;
    if !p.is_object() {
        return Err(err("LAB_SCHEMA", "Object payload required"));
    }
    let h = state.inner().clone();
    blocking(move||{
  if action=="configure"{
   only_keys(&p,&[])?;
   let python=pick(&app,false,"Choose a trusted Python 3.11+ interpreter for scientific work")?.canonicalize().map_err(|_|err("LAB_PYTHON","Cannot resolve interpreter"))?;
   let entry=pick(&app,false,"Choose installed contrib/atlas/neuronlab/worker.py")?.canonicalize().map_err(|_|err("LAB_RUNNER","Cannot resolve worker entry"))?;
   let(hash,_)=source_manifest(&entry)?;
   let python_hash=atlas_core::hash(&files::read_bounded(&python,268_435_456)?);
   let store=app.path().app_local_data_dir().map_err(|_|err("LAB_STORE","No local application directory"))?.join("neuronlab");
   let r=Runner{python,entry,store,python_hash,manifest_hash:hash};verify_sources(&r)?;
   confirm(&app,"Install local scientific worker",format!("Interpreter: {}\nSHA-256: {}\nWorker: {}\nSource manifest SHA-256: {}\nStore: {}\n\nThis explicitly trusts installed code and its scientific dependencies. It does NOT grant wallet keys or peer activation. OS sandbox and native platform qualification remain separate gates.",r.python.display(),r.python_hash,r.entry.display(),r.manifest_hash,r.store.display()))?;
   CANCEL.fetch_add(1,Ordering::SeqCst);*lock(config())?=Some(r.clone());return run(&r,"status",json!({}),&operation_id);
  }
  let r=lock(config())?.clone().ok_or_else(||err("LAB_NOT_CONFIGURED","Configure an approved local research worker first"))?;
  if action=="publish"{
   only_keys(&p,&["profile_id"])?;let id=string(&p,"profile_id")?;digest(id)?;
   let plan=run(&r,"publish_plan",p.clone(),&format!("{operation_id}-plan"))?;
   // Reconstruct native parameters; never proxy worker-supplied RPC or arguments.
   let path=r.store.join("capsules").join(format!("{id}.safetensors"));
   confirm(&app,"Serve public intervention data",format!("Profile: {id}\nCapsule SHA-384: {}\n\nServe this PUBLIC data-only SafeTensors capsule using the connected BTX node. It is not a model checkpoint, execution grant, or spend. Search-card publication is disabled; share the resulting BTX resource URI explicitly.",plan.get("capsule_sha384").and_then(Value::as_str).unwrap_or("unknown")))?;
   let c=h.connected()?;h.recheck(&c)?;h.audit(&operation_id,"neuronlab.publish","SUBMITTED")?;
   let result=c.rpc.call("hostmodel",&json!([path.to_string_lossy(),{"pin":true,"publish":false}]),None,180)?;
   h.recheck(&c)?;h.audit(&operation_id,"neuronlab.publish","SUCCEEDED")?;
   return Ok(json!({"profile_id":id,"native_result":result,"activation_authorized":false,"automatic_spend_atoms":"0"}));
  }
  if action=="acquire"{
   only_keys(&p,&["uri"])?;let resource=uri(&p)?;
   confirm(&app,"Retrieve intervention bytes",format!("Resource: {resource}\n\nUse FREE_ONLY retrieval. This may acquire and serve bytes under your existing node storage policy. Downloading does not trust a publisher or apply neuron settings."))?;
   let c=h.connected()?;h.recheck(&c)?;h.audit(&operation_id,"neuronlab.acquire","SUBMITTED")?;
   let result=c.rpc.call("getmodel",&json!([resource,{"mode":"FREE_ONLY"}]),None,180)?;
   h.recheck(&c)?;h.audit(&operation_id,"neuronlab.acquire","ACCEPTED_NOT_COMPLETED")?;
   return Ok(json!({"native_result":result,"complete":"CHECK_NATIVE_JOB","activation_authorized":false}));
  }
  if action=="finish_acquire"{
   only_keys(&p,&["uri","profile_id"])?;let resource=uri(&p)?;let id=string(&p,"profile_id")?.to_owned();digest(&id)?;
   confirm(&app,"Verify completed intervention checkout",format!("Resource: {resource}\nExpected profile: {id}\n\nAsk the native node for its verified checkout, then verify the capsule signature and exact profile identity. Do not import incomplete or wrong bytes. No activation follows."))?;
   let c=h.connected()?;h.recheck(&c)?;let result=c.rpc.call("exportmodelpath",&json!([resource]),None,180)?;h.recheck(&c)?;
   let path=result.get("usable_runtime_root").or_else(||result.get("path")).and_then(Value::as_str).ok_or_else(||err("LAB_CHECKOUT","Native response lacks a verified checkout root"))?;
   return run(&r,"import_checkout",json!({"path":path,"profile_id":id}),&operation_id);
  }
  if !ACTIONS.contains(&action.as_str()){return Err(err("LAB_ACTION","Unknown research action"));}
  // File paths are selected here, never accepted from a generated panel or profile.
  if action=="register"{only_keys(&p,&[])?;let path=pick_folder(&app,"Select exact local SafeTensors model directory; no download or code execution")?;p=json!({"path":path.to_string_lossy()});}
  if action=="import"||action=="import_evidence"{only_keys(&p,&[])?;let path=pick(&app,false,"Select a signed research capsule/evidence file to inspect")?;p=json!({"path":path.to_string_lossy()});}
  if action=="embeddings_import"{
   only_keys(&p,&["title","method","seed"])?;
   let path=pick(&app,false,"Select a local numeric .npy embedding matrix (no pickle, no archive)")?;
   p["path"]=json!(path.to_string_lossy());
  }
  if action=="export"{only_keys(&p,&["profile_id"])?;digest(string(&p,"profile_id")?)?;let path=pick(&app,true,"Save capsule to a NEW .safetensors file")?;p["path"]=json!(path.to_string_lossy());}
  if !READS.contains(&action.as_str()){
   let mut review=format!("Research action: {action}\nOperation ID: {operation_id}\n\n{}\n\nNo wallet/host-tool authority is added. Profile signatures do not certify model behavior.",serde_json::to_string_pretty(&p).map_err(|_|err("LAB_JSON","Review serialization failed"))?);
   if ["compare","generate","activate"].contains(&action.as_str()){
    if let Some(id)=p.get("profile_id").and_then(Value::as_str){let actual=run(&r,"profile",json!({"profile_id":id}),&format!("{operation_id}-inspect"))?;
     review.push_str(&format!("\n\nExact signed operators:\n{}",serde_json::to_string_pretty(&actual.pointer("/profile/operations")).unwrap_or_default()));}
   }
   confirm(&app,"Review local model intervention",review)?;
   if action=="revoke"||action=="deactivate"{CANCEL.fetch_add(1,Ordering::SeqCst);}
   h.audit(&operation_id,&format!("neuronlab.{action}"),"SUBMITTED")?;
  }
  let result=run_stream(&r,&action,p,&operation_id,Some(app.clone()))?;
  if !READS.contains(&action.as_str()){h.audit(&operation_id,&format!("neuronlab.{action}"),"SUCCEEDED")?;}
  Ok(result)
 }).await
}
