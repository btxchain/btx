import {topological} from './graph.js';
const TYPES=new Set(['input','model','evaluate','compare','artifact','guard','output']);
export function validateWorkflow(doc){
  if(!doc||doc.schema!=='btx.atlas.workflow/1'||!Array.isArray(doc.nodes)||!Array.isArray(doc.edges)||doc.nodes.length>256||doc.edges.length>1024)throw Error('Invalid workflow contract');
  for(const n of doc.nodes){if(!n||!/^[a-zA-Z0-9_-]{1,64}$/.test(n.id)||!TYPES.has(n.kind)||typeof n.label!=='string'||n.label.length>160)throw Error('Invalid workflow node');if(n.position&&(!Array.isArray(n.position)||n.position.length!==2||n.position.some(x=>!Number.isFinite(x)||Math.abs(x)>100000)))throw Error('Invalid node coordinate');}
  for(const e of doc.edges)if(!e||typeof e.from!=='string'||typeof e.to!=='string')throw Error('Invalid workflow edge');
  topological(doc.nodes,doc.edges);return doc;
}
export function createWorkflow(){return{schema:'btx.atlas.workflow/1',id:crypto.randomUUID(),status:'LOCAL_DRAFT_NOT_AUTHORIZED',nodes:[],edges:[]};}
export function addEdge(doc,from,to){const next={...doc,edges:[...doc.edges,{from,to}]};validateWorkflow(next);return next;}
export function compareEvaluations(a,b){
  const rows=[];for(const key of new Set([...Object.keys(a||{}),...Object.keys(b||{})])){
    const x=a?.[key],y=b?.[key];if(typeof x==='object'||typeof y==='object')continue;
    const nx=Number(x),ny=Number(y),measured=x!==undefined&&y!==undefined&&Number.isFinite(nx)&&Number.isFinite(ny);
    rows.push({metric:key,parent:x??'unavailable',candidate:y??'unavailable',difference:measured?ny-nx:null,qualification:'Reported values; not independently verified'});
  }return rows;
}
