use crate::host::*;
use atlas_core::{
    files,
    money::SendDraft,
    operations::{self, Request},
    settings, Error, Result,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::{
    process::{Command, Stdio},
    sync::Arc,
};
use tauri::{AppHandle, State, WebviewWindow};
type Shared = Arc<Host>;

#[tauri::command]
pub fn atlas_status(window: WebviewWindow, state: State<'_, Shared>) -> Result<Value> {
    authorize(&window)?;
    let c = lock(&state.connection)?;
    Ok(
        json!({"application":"BTX Atlas","version":env!("CARGO_PKG_VERSION"),"base":"18ea826ee3d82edf65a274c00316bd118ed731d2","connected":c.is_some(),"chain":c.as_ref().map(|x|&x.chain),"epoch":c.as_ref().map(|x|x.epoch),"qualification":"SOURCE_CANDIDATE_NOT_RELEASE_QUALIFIED","assistant":lock(&state.agent)?.view()}),
    )
}
#[tauri::command]
pub async fn atlas_connect(
    window: WebviewWindow,
    app: AppHandle,
    state: State<'_, Shared>,
    endpoint: String,
) -> Result<Value> {
    authorize(&window)?;
    let h = state.inner().clone();
    blocking(move || connect(&app, &h, endpoint)).await
}
#[tauri::command]
pub async fn atlas_read(
    window: WebviewWindow,
    state: State<'_, Shared>,
    request: Request,
) -> Result<Value> {
    authorize(&window)?;
    let h = state.inner().clone();
    let slot = ReadSlot::acquire(h.clone())?;
    blocking(move || {
        let _slot = slot;
        let c = h.connected()?;
        let params = request.parse()?;
        if !operations::read_allowed(&request.method, &params) {
            return Err(Error::new(
                "READ_DENIED",
                "This method/scope needs a prepared operation and native human approval",
            ));
        }
        let result = c
            .rpc
            .call(&request.method, &params, request.wallet.as_deref(), 20)?;
        h.envelope(&c, result)
    })
    .await
}
#[tauri::command]
pub fn atlas_prepare(
    window: WebviewWindow,
    state: State<'_, Shared>,
    request: Request,
) -> Result<Value> {
    authorize(&window)?;
    let c = state.connected()?;
    let prepared = lock(&state.approvals)?.prepare(request, c.epoch)?;
    serde_json::to_value(prepared).map_err(|_| Error::new("JSON", "Cannot encode approval"))
}
#[tauri::command]
pub fn atlas_cancel(window: WebviewWindow, state: State<'_, Shared>, id: String) -> Result<()> {
    authorize(&window)?;
    lock(&state.approvals)?.cancel(&id);
    Ok(())
}
#[tauri::command]
pub async fn atlas_execute(
    window: WebviewWindow,
    app: AppHandle,
    state: State<'_, Shared>,
    id: String,
) -> Result<Value> {
    authorize(&window)?;
    let h = state.inner().clone();
    blocking(move||{
  let _gate=lock(&h.gate)?;let c=h.connected()?;let request=lock(&h.approvals)?.consume(&id,c.epoch)?;let params=request.parse()?;
  h.recheck(&c)?;let mut summary=request.summary()?;
  if request.method=="walletprocesspsbt"{
   let p=params.get(0).or_else(||params.get("psbt")).and_then(Value::as_str).ok_or_else(||Error::new("PSBT","Missing PSBT"))?;
   let decoded=c.rpc.call("decodepsbt",&json!([p]),None,20)?;
   summary=format!("Method: walletprocesspsbt\nWallet: {}\nPSBT SHA-256: {}\n\n{}",request.wallet.as_deref().unwrap_or("NONE"),atlas_core::hash(p.as_bytes()),serde_json::to_string_pretty(&atlas_core::money::transaction_skeleton(&decoded["tx"])?) .map_err(|_|Error::new("PSBT","Cannot show decoded transaction"))?);
  }
  confirm(&app,"Authorize exact operation",format!("Chain: {}\nGenesis: {}\n\n{}\n\nThis is a native approval, not a model recommendation. A timeout after submission is UNKNOWN and will NOT be retried automatically.",c.chain,c.genesis,summary))?;
  h.recheck(&c)?;h.audit(&id,&request.method,"SUBMITTED")?;
  let reply=c.rpc.call(&request.method,&params,request.wallet.as_deref(),180);
  match reply{
   Ok(result)=>{h.audit(&id,&request.method,"SUCCEEDED").map_err(|_|Error::unknown("Node replied, but durable result journaling failed. Do not repeat the operation."))?;h.envelope(&c,result)},
   Err(e)=>{let phase=if e.outcome_unknown{"UNKNOWN"}else{"REJECTED"};let _=h.audit(&id,&request.method,phase);Err(e)}
  }
 }).await
}
#[tauri::command]
pub async fn atlas_money(
    window: WebviewWindow,
    app: AppHandle,
    state: State<'_, Shared>,
    action: String,
    id: Option<String>,
    draft: Option<SendDraft>,
) -> Result<Value> {
    authorize(&window)?;
    let h = state.inner().clone();
    blocking(move||{
  let _gate=lock(&h.gate)?;let c=h.connected()?;h.recheck(&c)?;let mut money=lock(&h.money)?;
  match action.as_str(){
   "prepare"=>{let d=draft.ok_or_else(||Error::new("DRAFT","Missing payment draft"))?;confirm(&app,"Prepare unsigned transaction",format!("Chain: {}\n\n{}",c.chain,d.summary()?))?;let op=atlas_core::random_id()?;h.audit(&op,"walletcreatefundedpsbt","SUBMITTED")?;
    let result=money.create(&c.rpc,d,c.epoch);let _=h.audit(&op,"walletcreatefundedpsbt",if result.is_ok(){"SUCCEEDED"}else{"UNKNOWN"});serde_json::to_value(result?).map_err(|_|Error::new("JSON","Plan serialization failed"))},
   "sign"|"broadcast"=>{let id=id.ok_or_else(||Error::new("PLAN","Missing plan ID"))?;let summary=money.summary(&id,c.epoch)?;
    confirm(&app,if action=="sign"{"Sign exact transaction"}else{"Broadcast exact transaction"},format!("Chain: {}\n\n{}\n\n{}",c.chain,summary,if action=="broadcast"{"Broadcast can transfer money irreversibly. Signing approval did not authorize this step."}else{"Signing is not broadcasting. Recheck every destination and the complete fee."}))?;
    h.recheck(&c)?;let method=if action=="sign"{"walletprocesspsbt"}else{"sendrawtransaction"};h.audit(&id,method,"SUBMITTED")?;
    let result=if action=="sign"{money.sign(&c.rpc,&id,c.epoch)}else{money.broadcast(&c.rpc,&id,c.epoch)};
    let _=h.audit(&id,method,if result.is_ok(){"SUCCEEDED"}else{"UNKNOWN"});serde_json::to_value(result?).map_err(|_|Error::new("JSON","Plan serialization failed"))},
   "inspect"=>serde_json::to_value(money.view(id.as_deref().unwrap_or(""),c.epoch)?).map_err(|_|Error::new("JSON","Plan serialization failed")),
   "export"=>{let psbt=money.psbt(id.as_deref().unwrap_or(""),c.epoch)?;let path=pick(&app,true,"Save PSBT to a NEW file")?;files::write_new(&path,psbt.as_bytes())?;Ok(json!({"saved":true}))},
   "discard"=>{money.discard(id.as_deref().unwrap_or(""));Ok(json!({"discarded":true}))},
   _=>Err(Error::new("MONEY_ACTION","Unknown wallet workflow action"))
  }
 }).await
}
#[tauri::command]
pub async fn atlas_agent(
    window: WebviewWindow,
    app: AppHandle,
    state: State<'_, Shared>,
    action: String,
    model: Option<String>,
    question: Option<String>,
) -> Result<Value> {
    authorize(&window)?;
    let h = state.inner().clone();
    blocking(move||{
  let _gate=lock(&h.gate)?;let c=h.connected()?;let mut agent=lock(&h.agent)?;
  match action.as_str(){
   "grant"=>{let model=model.ok_or_else(||Error::new("MODEL","Select a local model"))?;confirm(&app,"Local assistant session",format!("Model: {}\nChain: {}\n\nAllow up to 32 questions for one hour on this exact connection. Each question may run at most two local generations (512 tokens each) plus bounded redacted read-only observations. This consumes local compute. No wallet, private paths, external provider, shell, signing, or write tools. Revoke in the assistant panel.",atlas_core::safe_text(&model,256),c.chain))?;serde_json::to_value(agent.grant(&c.rpc,&model,c.epoch)?).map_err(|_|Error::new("JSON","Cannot encode grant"))},
   "ask"=>{let op=atlas_core::random_id()?;h.audit(&op,"assistant.local_generate","SUBMITTED")?;let a=agent.ask(&c.rpc,&question.unwrap_or_default(),c.epoch);let _=h.audit(&op,"assistant.local_generate",if a.is_ok(){"SUCCEEDED"}else{"UNKNOWN"});serde_json::to_value(a?).map_err(|_|Error::new("JSON","Cannot encode assistant result"))},
   "revoke"=>{agent.revoke();Ok(json!({"revoked":true,"note":"Stops future turns; an already running node generation is not retroactively cancelled."}))},
   "status"=>serde_json::to_value(agent.view()).map_err(|_|Error::new("JSON","Cannot encode assistant grant")),
   _=>Err(Error::new("AGENT_ACTION","Unknown assistant action"))
  }
 }).await
}
#[tauri::command]
pub async fn atlas_document(
    window: WebviewWindow,
    app: AppHandle,
    action: String,
    text: Option<String>,
) -> Result<Value> {
    authorize(&window)?;
    blocking(move||match action.as_str(){
  "psbt_import"=>{let path=pick(&app,false,"Open binary or base64 PSBT")?;let b=files::read_bounded(&path,1_048_576)?;let text=if b.starts_with(b"psbt\xff"){STANDARD.encode(&b)}else{String::from_utf8(b).map_err(|_|Error::new("PSBT","Expected binary PSBT magic or UTF-8 base64"))?.trim().to_owned()};if text.len()>1_400_000{return Err(Error::new("PSBT","PSBT exceeds import budget"));}Ok(json!({"text":text,"trust":"UNTRUSTED_PSBT_NOT_SIGNED"}))},
  "import"=>{let path=pick(&app,false,"Open a local evidence, workflow, surface, resource, or PSBT document")?;let b=files::read_bounded(&path,1_048_576)?;let text=String::from_utf8(b).map_err(|_|Error::new("TEXT","Document is not UTF-8"))?;Ok(json!({"text":text,"digest":atlas_core::hash(text.as_bytes()),"trust":"UNTRUSTED_LOCAL_DOCUMENT"}))},
  "export"=>{let text=text.ok_or_else(||Error::new("EXPORT","Missing export text"))?;if text.len()>4_194_304{return Err(Error::new("EXPORT_SIZE","Export exceeds 4 MiB"));}let path=pick(&app,true,"Export to a NEW file; existing files are not overwritten")?;files::write_new(&path,text.as_bytes())?;Ok(json!({"saved":true}))},
  "source_path"=>{let path=pick(&app,false,"Choose a model or native source file")?;Ok(json!({"path":path.to_string_lossy()}))},
  "folder_path"=>{let path=pick_folder(&app,"Choose model/source folder")?;Ok(json!({"path":path.to_string_lossy()}))},
  "destination_path"=>{let path=pick(&app,true,"Choose destination for the separately reviewed native operation")?;Ok(json!({"path":path.to_string_lossy()}))},
  "tensor_header"=>{let path=pick(&app,false,"Inspect a SafeTensors header (no model execution)")?;files::inspect_safetensors(&path)},
  _=>Err(Error::new("DOCUMENT_ACTION","Unknown document action"))
 }).await
}
#[tauri::command]
pub fn atlas_qr(window: WebviewWindow, text: String) -> Result<Value> {
    authorize(&window)?;
    files::qr_matrix(&text)
}
#[tauri::command]
pub async fn atlas_config(
    window: WebviewWindow,
    app: AppHandle,
    state: State<'_, Shared>,
    action: String,
    section: String,
    edit: Option<String>,
) -> Result<Value> {
    authorize(&window)?;
    let h = state.inner().clone();
    blocking(move||{
  let _gate=lock(&h.gate)?;
  if action=="open"{let path=pick(&app,false,"Choose node configuration to inspect; credentials are omitted")?;let s=settings::inspect(&path,&section)?;*lock(&h.config)?=Some(path);return serde_json::to_value(s).map_err(|_|Error::new("JSON","Cannot show settings"));}
  let path=lock(&h.config)?.clone().ok_or_else(||Error::new("CONFIG","Select a node configuration first"))?;
  if action=="read"{return serde_json::to_value(settings::inspect(&path,&section)?).map_err(|_|Error::new("JSON","Cannot show settings"));}
  if action!="apply"{return Err(Error::new("CONFIG_ACTION","Unknown configuration action"));}
  let edit=settings::parse_edit(&edit.unwrap_or_default())?;
  confirm(&app,"Change node configuration",format!("File: {}\nSection: {}\nExpected digest: {}\n\n{}\n\nNode restart is required. This edits only the selected file. It does not override command-line settings or start/stop the node. External signer paths can cause code execution by btxd.",path.display(),edit.section,edit.expected_hash,edit.values.iter().map(|(k,v)|format!("{k}={v}")).collect::<Vec<_>>().join("\n")))?;
  serde_json::to_value(settings::apply(&path,&edit)?).map_err(|_|Error::new("JSON","Cannot show settings"))
 }).await
}
#[tauri::command]
pub async fn atlas_launch(
    window: WebviewWindow,
    app: AppHandle,
    state: State<'_, Shared>,
    chain: String,
) -> Result<Value> {
    authorize(&window)?;
    let h = state.inner().clone();
    blocking(move||{
  let _gate=lock(&h.gate)?;if !["main","test","testnet4","signet","regtest"].contains(&chain.as_str()){return Err(Error::new("CHAIN","Invalid chain"));}
  let binary=pick(&app,false,"Choose a trusted btxd executable")?;let datadir=pick_folder(&app,"Choose an existing BTX data directory")?;
  let bytes=files::read_bounded(&binary,268_435_456)?;let digest=atlas_core::hash(&bytes);drop(bytes);
  confirm(&app,"Start native BTX daemon",format!("Executable: {}\nSHA-256: {}\nData directory: {}\nChain: {}\n\nThis runs the selected executable as your OS user. Verify its signature independently. No shell is used. btxd retains its existing wallet and helper authority. Closing Atlas will NOT terminate this node.",binary.display(),digest,datadir.display(),chain))?;
  if atlas_core::hash(&files::read_bounded(&binary,268_435_456)?)!=digest{return Err(Error::new("EXECUTABLE_CHANGED","Executable changed during review"));}
  let id=atlas_core::random_id()?;h.audit(&id,"native.launch_btxd","SUBMITTED")?;
  let mut command=Command::new(&binary);command.arg(format!("-datadir={}",datadir.display())).arg(format!("-chain={chain}")).arg("-server=1").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).env_clear();
  for key in ["HOME","USERPROFILE","APPDATA","LOCALAPPDATA","SystemRoot","WINDIR","PATH","TMPDIR","TEMP","TMP"]{if let Some(v)=std::env::var_os(key){command.env(key,v);}}
  let child=command.spawn().map_err(|_|Error::new("LAUNCH","Failed to launch selected executable"))?;let pid=child.id();
  // A waiter reaps the process without owning a kill-on-drop handle. GUI exit does not send kill.
  std::thread::spawn(move||{let mut child=child;let _=child.wait();});h.audit(&id,"native.launch_btxd","SUCCEEDED")?;
  Ok(json!({"pid":pid,"started":true,"readiness":"NOT_YET_OBSERVED","helpers":"owned by btxd"}))
 }).await
}
#[tauri::command]
pub fn atlas_activity(window: WebviewWindow, state: State<'_, Shared>) -> Result<Value> {
    authorize(&window)?;
    let j = lock(&state.journal)?;
    Ok(
        json!({"entries":j.tail(512),"unresolved":j.unresolved(),"checkpoint":j.checkpoint(),"scope":"LOCAL_GUI_JOURNAL_NOT_NATIVE_SWARM_LEDGER"}),
    )
}
#[tauri::command]
pub fn atlas_pending_links(window: WebviewWindow, state: State<'_, Shared>) -> Result<Vec<String>> {
    authorize(&window)?;
    Ok(std::mem::take(&mut *lock(&state.links)?))
}

// Clipboard ownership is retained for Linux. No clipboard read authority is exposed.
#[tauri::command]
pub async fn atlas_copy(
    window: WebviewWindow,
    app: AppHandle,
    state: State<'_, Shared>,
    text: String,
) -> Result<()> {
    authorize(&window)?;
    if text.len() > 65536 {
        return Err(Error::new(
            "CLIPBOARD_SIZE",
            "Clipboard text exceeds 64 KiB",
        ));
    }
    let h = state.inner().clone();
    blocking(move || {
        main_thread(&app, move || {
            let mut c = lock(&h.clipboard)?;
            if c.is_none() {
                *c = Some(
                    arboard::Clipboard::new()
                        .map_err(|_| Error::new("CLIPBOARD", "OS clipboard is unavailable"))?,
                );
            }
            c.as_mut()
                .ok_or_else(|| Error::new("CLIPBOARD", "Clipboard owner unavailable"))?
                .set_text(text)
                .map_err(|_| Error::new("CLIPBOARD", "OS clipboard write failed"))
        })?
    })
    .await
}
#[tauri::command]
pub async fn atlas_desktop(
    window: WebviewWindow,
    app: AppHandle,
    state: State<'_, Shared>,
    action: String,
) -> Result<Value> {
    authorize(&window)?;
    let h = state.inner().clone();
    blocking(move||{
  use tauri_plugin_autostart::ManagerExt;
  if action=="status"{return Ok(json!({"autostart":app.autolaunch().is_enabled().map_err(|_|Error::new("AUTOSTART","Cannot observe OS autostart state"))?}));}
  let _gate=lock(&h.gate)?;
  match action.as_str(){
   "enable_autostart"|"disable_autostart"=>{
    let enable=action=="enable_autostart";confirm(&app,"Change login launch",format!("{} BTX Atlas at OS login. This does not start btxd, unlock a wallet, or grant an agent authority.",if enable{"Enable"}else{"Disable"}))?;
    let op=atlas_core::random_id()?;h.audit(&op,"desktop.autostart","SUBMITTED")?;
    let result=if enable{app.autolaunch().enable()}else{app.autolaunch().disable()};
    result.map_err(|_|Error::new("AUTOSTART","OS autostart update failed; recheck its current state"))?;
    h.audit(&op,"desktop.autostart","SUCCEEDED")?;Ok(json!({"autostart":enable}))
   },
   _=>Err(Error::new("DESKTOP_ACTION","Unsupported desktop operation"))
  }
 }).await
}
