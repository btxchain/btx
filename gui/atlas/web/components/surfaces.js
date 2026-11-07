import {el,button,note,metric,table} from './ui.js';
import {validateSurface,resolveRef,surfaceDigest} from '../core/surface.js';
export function renderSurface(doc,sources,navigate,focus){
 validateSurface(doc);const bindings=Object.fromEntries(doc.sources.map(m=>[m,sources[m]?.ok?sources[m].result:undefined]));
 const root=el('section',{class:'surface-document','aria-label':`Generated read-only view: ${doc.title}`});
 root.append(el('h2',{},doc.title),note('Generated read-only view · No execution or signing authority.'));
 function node(n){switch(n.type){
  case 'stack':return el('div',{class:'surface-stack'},...n.children.map(node));
  case 'text':return el('p',{class:n.tone||''},n.text||'');
  case 'metric':{const v=resolveRef(bindings,n.ref);return metric(n.title||'Metric',v===undefined?'Unavailable':String(v),n.unit||'');}
  case 'table':{const v=resolveRef(bindings,n.ref);return Array.isArray(v)?table(v.slice(0,200),n.columns,{pageSize:25}):note('Bound source unavailable; no cached value substituted.','warning');}
  case 'sparkline':{const v=resolveRef(bindings,n.ref);if(!Array.isArray(v)||v.length>512||v.some(x=>!Number.isFinite(Number(x))))return note('Numeric series unavailable.');const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');svg.setAttribute('viewBox','0 0 400 90');svg.setAttribute('role','img');svg.setAttribute('aria-label','Bound numerical time series');const p=document.createElementNS(svg.namespaceURI,'polyline'),a=v.map(Number),min=Math.min(...a),max=Math.max(...a),range=max-min||1;p.setAttribute('points',a.map((x,i)=>`${i*400/Math.max(a.length-1,1)},${85-(x-min)*80/range}`).join(' '));p.setAttribute('fill','none');p.setAttribute('stroke','currentColor');p.setAttribute('stroke-width','2');svg.append(p);return svg;}
  case 'button':return button(n.label||'Open',()=>n.action==='navigate'?navigate(n.target):focus(n.target),'subtle');
 }}
 root.append(node(doc.root));return root;
}
export async function saveSurface(doc){validateSurface(doc);const digest=await surfaceDigest(doc);const all=loadSurfaces().filter(s=>!(s.doc.id===doc.id&&s.doc.revision===doc.revision));all.push({doc,digest,savedAt:Date.now()});const trimmed=all.slice(-12);if(new TextEncoder().encode(JSON.stringify(trimmed)).length>1024*1024)throw Error('Surface history storage budget exceeded');localStorage.setItem('atlas.surfaces.v1',JSON.stringify(trimmed));return digest;}
export function loadSurfaces(){try{const raw=localStorage.getItem('atlas.surfaces.v1');if(!raw||raw.length>1024*1024)return[];return JSON.parse(raw).slice(-12).filter(x=>{try{validateSurface(x.doc);return true;}catch{return false;}});}catch{return[];}}
export function deleteSurface(id,revision){const a=loadSurfaces().filter(x=>x.doc.id!==id||x.doc.revision!==revision);localStorage.setItem('atlas.surfaces.v1',JSON.stringify(a));}
