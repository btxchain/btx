const KINDS=new Set(['stack','text','metric','table','sparkline','button']);
const ACTIONS=new Set(['navigate','focus','compare']);
const VIEWS=new Set(['atlas','models','swarms','work','research','economy','compute','mining','wallet','activity','tools','settings']);
const FORBIDDEN=new Set(['__proto__','prototype','constructor']);
const SOURCE_ALLOW=new Set(['getblockchaininfo','getnetworkinfo','getmodelnetworkinfo','getmodelhostprofile','getmininginfo','getsetupstatus','listmodels','getmodeltransfers']);
export function resolveRef(root,path){
  if(typeof path!=='string'||path.length>256)throw Error('Bad data reference');
  const parts=path.split('.');if(parts.length>12||parts.some(p=>!p||FORBIDDEN.has(p)||!/^[a-zA-Z0-9_-]+$/.test(p)))throw Error('Unsafe data reference');
  let result=root;for(const p of parts){if(!result||typeof result!=='object'||!Object.hasOwn(result,p))return undefined;result=result[p];}
  return result;
}
export function validateSurface(doc){
  const encoded=JSON.stringify(doc);if(!encoded||new TextEncoder().encode(encoded).length>65536)throw Error('Surface exceeds 64 KiB');
  const allowedTop=new Set(['schema','id','revision','title','sources','root','origin']);
  if(!doc||Array.isArray(doc)||Object.keys(doc).some(k=>!allowedTop.has(k)))throw Error('Unknown surface field');
  if(doc.schema!=='btx.atlas.surface/1'||!/^[a-z0-9._-]{1,64}$/.test(doc.id)||!Number.isSafeInteger(doc.revision)||doc.revision<1)throw Error('Invalid surface identity/version');
  if(typeof doc.title!=='string'||doc.title.length>96)throw Error('Invalid title');
  if(!Array.isArray(doc.sources)||doc.sources.length>8||new Set(doc.sources).size!==doc.sources.length||doc.sources.some(x=>!SOURCE_ALLOW.has(x)))throw Error('Unapproved surface source');
  let count=0;
  function check(node,depth){
    if(depth>12||++count>256||!node||typeof node!=='object'||Array.isArray(node)||!KINDS.has(node.type))throw Error('Surface structural limit/type');
    const allowed={stack:['type','children'],text:['type','text','tone'],metric:['type','title','ref','unit'],table:['type','ref','columns'],sparkline:['type','ref'],button:['type','label','action','target']}[node.type];
    if(Object.keys(node).some(k=>!allowed.includes(k)))throw Error('Unknown component field');
    for(const k of ['text','title','unit','label'])if(k in node&&(typeof node[k]!=='string'||node[k].length>1024))throw Error('Text limit');
    if(['metric','table','sparkline'].includes(node.type)&&typeof node.ref!=='string')throw Error('Missing data binding');
    if(node.ref){if(typeof node.ref!=='string'||!doc.sources.includes(node.ref.split('.')[0]))throw Error('Unbound data source');resolveRef({},node.ref);}
    if(node.type==='stack'){if(!Array.isArray(node.children)||node.children.length>64)throw Error('Children limit');node.children.forEach(x=>check(x,depth+1));}
    if(node.type==='table'&&(!Array.isArray(node.columns)||node.columns.length>12||node.columns.some(c=>typeof c!=='string'||c.length>64||FORBIDDEN.has(c))))throw Error('Invalid columns');
    if(node.type==='button'){
      if(!ACTIONS.has(node.action)||typeof node.target!=='string'||node.target.length>192)throw Error('Action not allowed');
      if(node.action==='navigate'&&!VIEWS.has(node.target))throw Error('Unknown workspace');
      if(node.action!=='navigate'&&!/^[a-zA-Z0-9:._/-]+$/.test(node.target))throw Error('Unsafe object target');
    }
    if(node.tone&&!['primary','muted','warning'].includes(node.tone))throw Error('Unknown tone');
  }
  check(doc.root,0);return doc;
}
export async function surfaceDigest(doc){validateSurface(doc);const bytes=new TextEncoder().encode(JSON.stringify(doc));return [...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(x=>x.toString(16).padStart(2,'0')).join('');}
export function redactAgentContext(sources){
  // Small, explicitly selected facts only. No wallet, IP, filesystem, raw prompt, auth, or history.
  const result={schema:'btx.atlas.agent-context/1',scope:'local_observations',authorizes:[]};
  const chain=sources.getblockchaininfo?.result;
  if(chain)result.chain={chain:chain.chain,blocks:String(chain.blocks??''),initialblockdownload:chain.initialblockdownload};
  const net=sources.getmodelnetworkinfo?.result;
  if(net)result.modelnet={enabled:net.enabled,helper_ready:net.helper_ready,pq1_ready:net.pq1_ready,automatic_spend_atoms:String(net.automatic_spend_atoms??'unknown'),release_qualified:net.native_participation?.release_qualified===true};
  const models=sources.listmodels?.result;
  const rows=Array.isArray(models)?models:models?.models||models?.items||[];
  result.models=rows.slice(0,32).map(m=>({id:String(m.model_id||m.id||'').slice(0,192),bytes_verified:m.bytes_verified===true,incomplete:m.incomplete!==false,format:String(m.format||'').slice(0,24)}));
  result.models_omitted=Math.max(0,rows.length-32);return result;
}
