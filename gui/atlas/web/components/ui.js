export function el(tag,attrs={},...children){
 const node=document.createElement(tag);
 for(const [key,value]of Object.entries(attrs||{})){
  if(value===null||value===undefined||value===false)continue;
  if(key==='class')node.className=value;
  else if(key==='text')node.textContent=String(value);
  else if(key==='dataset'){for(const [k,v]of Object.entries(value))node.dataset[k]=String(v);}
  else if(key.startsWith('on')&&typeof value==='function')node.addEventListener(key.slice(2).toLowerCase(),value);
  else if(['value','checked','disabled','selected','hidden','readOnly'].includes(key))node[key]=value;
  else node.setAttribute(key,value===true?'':String(value));
 }
 for(const c of children.flat(Infinity)){if(c===null||c===undefined||c===false)continue;node.append(c instanceof Node?c:document.createTextNode(String(c)));}
 return node;
}
export const button=(text,onClick,kind='',attrs={})=>el('button',{type:'button',class:`button ${kind}`,onClick,...attrs},text);
export const badge=(text,tone='')=>el('span',{class:`badge ${tone}`},text);
export const note=(text,tone='')=>el('div',{class:`note ${tone}`,role:tone==='danger'?'alert':'note'},text);
export const heading=(title,subtitle)=>el('div',{class:'section-heading'},el('h1',{},title),subtitle&&el('p',{},subtitle));
export function field(label,input,help=''){return el('label',{class:'field'},el('span',{},label),input,help&&el('small',{},help));}
export function jsonView(value,{open=false,title='Exact source result'}={}){const str=typeof value==='string'?value:JSON.stringify(value,null,2);return el('details',{class:'json',open},el('summary',{},title),el('pre',{},str.length>262144?str.slice(0,262144)+'\n[display capped; export for full bounded result]':str));}
export function short(value,max=100){if(value===undefined||value===null)return '—';const s=typeof value==='object'?JSON.stringify(value):String(value);return s.length>max?s.slice(0,max)+'…':s;}
export function humanBytes(value){const n=Number(value);if(!Number.isFinite(n)||n<0)return'—';if(n<1024)return `${n} B`;const units=['KiB','MiB','GiB','TiB'];let v=n/1024,i=0;while(v>=1024&&i<units.length-1){v/=1024;i++;}return `${v.toFixed(1)} ${units[i]}`;}
export function metric(label,value,detail=''){return el('div',{class:'metric'},el('span',{class:'label'},label),el('strong',{},value??'—'),el('small',{},detail));}
export function toast(message,tone=''){const host=document.querySelector('#notifications');if(!host)return;const n=el('div',{class:`toast ${tone}`,role:'status'},message);host.append(n);while(host.children.length>4)host.firstChild.remove();setTimeout(()=>n.remove(),7000);}
export async function busy(control,fn){const prev=control.disabled;control.disabled=true;control.setAttribute('aria-busy','true');try{return await fn();}catch(e){toast(e.message||String(e),'danger');throw e;}finally{if(control.isConnected){control.disabled=prev;control.removeAttribute('aria-busy');}}}
export function dialog(title,body,{actions=[]}={}){
 const d=el('dialog',{class:'dialog'}),close=()=>{d.close();d.remove();};
 d.append(el('header',{},el('h2',{},title),button('×',close,'icon',{'aria-label':'Close dialog'})),el('div',{class:'dialog-body'},body),el('footer',{},...actions.map(a=>button(a.label,()=>a.action(close),a.kind||'')),button('Close',close)));
 document.body.append(d);d.addEventListener('cancel',e=>{e.preventDefault();close();});d.showModal();return{element:d,close};
}
export function table(rows,columns,{onSelect,pageSize=100,empty='No observed records.',search=true}={}){
 const header=c=>typeof c==='string'?c:(c.label??c.key??'');
 const root=el('div',{class:'data-table'}),filter=el('input',{type:'search',placeholder:'Filter these records…','aria-label':'Filter table'}),body=el('tbody'),table=el('table',{},el('thead',{},el('tr',{},...columns.map(c=>el('th',{scope:'col'},header(c))))),body),count=el('span',{class:'muted'});let page=0,sortKey=null,reverse=false;
 const selected=()=>{const needle=filter.value.toLowerCase();let a=rows.filter(r=>!needle||JSON.stringify(r).toLowerCase().includes(needle));if(sortKey)a=[...a].sort((a,b)=>String(a[sortKey]??'').localeCompare(String(b[sortKey]??''),undefined,{numeric:true})*(reverse?-1:1));return a;};
 const render=()=>{const all=selected();page=Math.max(0,Math.min(page,Math.ceil(all.length/pageSize)-1));const start=page*pageSize;body.replaceChildren();for(const row of all.slice(start,start+pageSize)){const tr=el('tr',{tabindex:onSelect?0:null,onClick:onSelect?()=>onSelect(row):null,onKeydown:onSelect?e=>{if(e.key==='Enter')onSelect(row);}:null});for(const c of columns){const k=typeof c==='string'?c:c.key,v=row[k];tr.append(el('td',{title:short(v,400)},typeof c==='object'&&c.render?c.render(v,row):short(v)));}body.append(tr);}if(!all.length)body.append(el('tr',{},el('td',{colspan:columns.length,class:'empty'},empty)));count.textContent=`${all.length?start+1:0}–${Math.min(start+pageSize,all.length)} of ${all.length.toLocaleString()} shown within the loaded scope`;};
 filter.addEventListener('input',()=>{page=0;render();});[...table.querySelectorAll('th')].forEach((th,i)=>{const c=columns[i],k=typeof c==='string'?c:c.key;th.replaceChildren(button(header(c),()=>{reverse=sortKey===k?!reverse:false;sortKey=k;render();},'table-sort'));});
 if(search)root.append(filter);root.append(el('div',{class:'table-scroll'},table),el('div',{class:'pager'},count,button('Previous',()=>{page--;render();}),button('Next',()=>{page++;render();})));render();return root;
}
export function mountError(root,error){root.append(note(`${error.code?error.code+' · ':''}${error.message||error}`, 'danger'));}
export function downloadCSV(rows,columns){const quote=v=>'"'+String(v??'').replace(/"/g,'""').replace(/^[=+@-]/,"'$&")+'"';return[columns.map(quote).join(','),...rows.slice(0,10000).map(r=>columns.map(k=>quote(typeof r[k]==='object'?JSON.stringify(r[k]):r[k])).join(','))].join('\r\n');}
