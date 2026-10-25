import {encodeJson} from './json.js';
import {BY_METHOD} from './catalog.js';
import {demoReply, demoGraphSources} from '../fixtures/demo.js';
export const isNative=!!globalThis.__TAURI__?.core?.invoke;
export class Bridge{
 constructor(){this.mode=isNative?'native':'disconnected';this.connected=false;this.epoch=0;this.available=null;}
 async invoke(command,args={}){if(!isNative)throw Object.assign(Error('This operation requires the native BTX Atlas application. Browser mode never connects to RPC.'),{code:'NATIVE_REQUIRED'});try{return await globalThis.__TAURI__.core.invoke(command,args);}catch(e){if(typeof e==='object')throw Object.assign(Error(e.message||e.code||'Native request failed'),e);throw Error(String(e));}}
 demo(){if(isNative)throw Error('Synthetic data is excluded from the native connected application');this.mode='demo';this.connected=true;this.epoch++;this.available=new Set(BY_METHOD.keys());return demoGraphSources();}
 async copy(text){if(new TextEncoder().encode(text).length>65536)throw Error("Clipboard text exceeds 64 KiB");if(isNative)return this.invoke("atlas_copy",{text});return navigator.clipboard.writeText(text);}
 async status(){if(!isNative)return{connected:this.connected,mode:this.mode};const s=await this.invoke('atlas_status');this.connected=s.connected;this.epoch=s.epoch??0;return s;}
 async connect(endpoint){const e=await this.invoke('atlas_connect',{endpoint});this.mode='native';this.connected=true;this.epoch=e.epoch;this.available=null;return e;}
 async read(method,params=[],wallet=null){
  if(this.mode==='demo')return{ok:true,observed_at:Date.now(),epoch:this.epoch,result:demoReply(method,params),complete:false,synthetic:true};
  return this.invoke('atlas_read',{request:{method,params_json:typeof params==='string'?params:encodeJson(params),wallet:wallet||null}});
 }
 async discover(){const e=await this.read('help');this.available=new Set(String(e.result||'').split('\n').map(x=>x.trim().match(/^([a-z][a-z0-9_]*)\b/)?.[1]).filter(Boolean));return this.available;}
 async help(method){return(await this.read('help',[method])).result;}
 supported(method){return this.available===null?null:this.available.has(method);}
 async prepare(method,params,wallet=null){if(this.mode==='demo')throw Error('Demo mode cannot prepare, sign, execute, or spend');return this.invoke('atlas_prepare',{request:{method,params_json:typeof params==='string'?params:encodeJson(params),wallet:wallet||null}});}
 async execute(id){return this.invoke('atlas_execute',{id});}
 async cancel(id){return this.invoke('atlas_cancel',{id});}
 async money(action,{id=null,draft=null}={}){return this.invoke('atlas_money',{action,id,draft});}
 async agent(action,{model=null,question=null}={}){return this.invoke('atlas_agent',{action,model,question});}
 async document(action,text=null){return this.invoke('atlas_document',{action,text});}
 async config(action,section='',edit=null){return this.invoke('atlas_config',{action,section,edit:edit===null?null:JSON.stringify(edit)});}
 async activity(){if(this.mode==='demo')return {entries:[],unresolved:[],scope:'DEMO: no native audit journal'};return this.invoke('atlas_activity');}
 async export(text,filename='atlas-export.json'){
  if(isNative)return this.document('export',text);
  if(new TextEncoder().encode(text).length>4*1024*1024)throw Error('Export exceeds 4 MiB');
  const url=URL.createObjectURL(new Blob([text],{type:'application/json'})),a=document.createElement('a');a.href=url;a.download=filename;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);return{saved:true};
 }
}
