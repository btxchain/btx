import {numeric} from './json.js';
export const GRAPH_LIMIT=100000, EDGE_LIMIT=200000;
export function hash32(text){let h=2166136261;for(let i=0;i<text.length;i++){h^=text.charCodeAt(i);h=Math.imul(h,16777619);}return h>>>0;}
export function stablePosition(id,group=0){
  const a=hash32(id),b=hash32(id+'|b');
  return [(a%1000-500)/65,(group-2)*3.2,(b%1000-500)/65];
}
export function sourceRows(source, keys=['models','items','records','rows','peers','transfers']) {
  if(!source)return [];
  const value=source.result??source;
  if(Array.isArray(value))return value;
  for(const k of keys)if(Array.isArray(value?.[k]))return value[k];
  return [];
}
export function buildGraph(sources,{now=Date.now(),privacy=true,maxNodes=GRAPH_LIMIT}={}) {
  const nodes=[],edges=[],ids=new Set();let omitted=0;
  function add(n){if(ids.has(n.id))return;if(nodes.length>=maxNodes){omitted++;return;}ids.add(n.id);nodes.push(n);}
  const chain=sources.getblockchaininfo?.result?.chain||'unknown';
  add({id:'local:node',kind:'node',label:'This node',group:0,state:sources.getblockchaininfo?.ok?'observed':'unavailable',source:'getblockchaininfo',observed_at:sources.getblockchaininfo?.observed_at??null,detail:{chain}});
  for(const p of sourceRows(sources.getpeerinfo,[])) {
    const id=`money-peer:${p.id??hash32(String(p.addr??''))}`;
    add({id,kind:'peer',network:'money',group:1,label:privacy?`Money peer ${p.id??'? '}`:p.addr||id,state:'observed',source:'getpeerinfo',detail:privacy?{id:p.id,subver:p.subver,inbound:p.inbound,connection_type:p.connection_type,network:'money'}:p});
    edges.push({from:'local:node',to:id,kind:'OBSERVED_MONETARY_PEER',source:'getpeerinfo'});
  }
  const modelnet=sources.getmodelnetworkinfo?.result||{};
  const native=modelnet.native_participation||sources.getmodelpeers?.result?.native_participation||{};
  for(const p of native.peer_observations||sourceRows(sources.getmodelpeers)){
    if(!p||typeof p!=='object')continue;
    const identity=String(p.transport_pin||p.node_id||p.id||p.endpoint||'unknown');
    const id=`model-peer:${identity}`;
    const expiry=numeric(p.expires_at_ms??p.expires_ms);
    const state=expiry!==null&&expiry<now?'stale':p.authenticated===true||p.transport_pin?'observed':'unverified';
    add({id,kind:'peer',network:'models',group:2,label:privacy?`Model peer ${hash32(identity).toString(16).slice(0,6)}`:p.endpoint||identity.slice(0,18),state,source:'getmodelnetworkinfo',detail:privacy?{network:'models',transport_observed:!!p.transport_pin,compute_authorized:p.compute_authorized===true,expires_at_ms:expiry}:p});
    edges.push({from:'local:node',to:id,kind:'OBSERVED_MODEL_PEER',source:'native_participation'});
  }
  for(const m of sourceRows(sources.listmodels)){
    const nativeId=m.model_id||m.id||m.uri||m.share?.uri;
    if(typeof nativeId!=='string'||!nativeId)continue; // Never invent lineage or artifact identity from the name.
    const id=`model:${nativeId}`;
    const verified=m.bytes_verified===true&&m.incomplete===false;
    add({id,nativeId,kind:'model',group:3,label:String(m.name||m.display_name||m.aliases?.[0]||nativeId.slice(0,14)),state:verified?'verified_bytes':m.incomplete?'incomplete':'observed',source:'listmodels',detail:m});
    edges.push({from:'local:node',to:id,kind:verified?'HAS_VERIFIED_REPLICA':'HAS_CATALOG_ENTRY',source:'listmodels'});
    if(typeof m.lineage_id==='string'&&m.lineage_verified===true){
      const lineage=`lineage:${m.lineage_id}`;add({id:lineage,kind:'lineage',group:4,label:m.lineage_name||m.lineage_id.slice(0,16),state:'observed',source:'listmodels',detail:{lineage_id:m.lineage_id}});
      edges.push({from:id,to:lineage,kind:'MAPS_TO_LINEAGE',source:'listmodels'});
    }
  }
  for(const n of nodes)n.position=stablePosition(n.id,n.group);
  const validEdges=edges.filter(e=>ids.has(e.from)&&ids.has(e.to)).slice(0,EDGE_LIMIT);
  return {nodes,edges:validEdges,omitted,complete:false,note:'Local observations, not a global directory. Edges are not grants.'};
}
export function layoutGraph(graph,{plane=false}={}){
  if(graph.nodes.length>GRAPH_LIMIT||graph.edges.length>EDGE_LIMIT)throw Error('Graph budget exceeded');
  const positions=new Float32Array(graph.nodes.length*3),indices=new Map();
  graph.nodes.forEach((n,i)=>{indices.set(n.id,i);const p=stablePosition(n.id,n.group??0);positions.set(plane?[p[0],p[2],0]:p,i*3);});
  const edgeIndices=[];
  for(const e of graph.edges){const a=indices.get(e.from),b=indices.get(e.to);if(a!==undefined&&b!==undefined)edgeIndices.push(a,b);}
  return {positions,edgeIndices:new Uint32Array(edgeIndices)};
}
export function adjacency(graph){const out=new Map(graph.nodes.map(n=>[n.id,[]]));for(const e of graph.edges)if(out.has(e.from)&&out.has(e.to))out.get(e.from).push(e.to);return out;}
export function descendants(graph,id,max=10000){if(!Number.isSafeInteger(max)||max<1||max>GRAPH_LIMIT)throw Error('Traversal budget');const adj=adjacency(graph),seen=new Set([id]),queue=[id];for(let i=0;i<queue.length&&seen.size<max;i++){for(const v of adj.get(queue[i])||[]){if(!seen.has(v)){seen.add(v);queue.push(v);if(seen.size>=max)break;}}}return seen;}
export function topological(nodes,edges){
  const indegree=new Map(nodes.map(n=>[n.id,0])),adj=new Map(nodes.map(n=>[n.id,[]]));
  if(indegree.size!==nodes.length)throw Error('Duplicate node ID');
  for(const e of edges){if(!indegree.has(e.from)||!indegree.has(e.to))throw Error('Dangling edge');indegree.set(e.to,indegree.get(e.to)+1);adj.get(e.from).push(e.to);}
  const q=[...indegree].filter(([,d])=>d===0).map(([id])=>id).sort(),order=[];
  for(let i=0;i<q.length;i++){const n=q[i];order.push(n);for(const to of adj.get(n)){indegree.set(to,indegree.get(to)-1);if(!indegree.get(to))q.push(to);}}
  if(order.length!==nodes.length)throw Error('Cycle in workflow or ancestry');return order;
}
