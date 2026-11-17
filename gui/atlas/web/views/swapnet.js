import {el,button,heading,note,metric,jsonView} from '../components/ui.js';
import {presentObservation} from '../core/observe.js';
import {operationDialog} from './operations.js';

const STATUS=['getswapnetworkinfo','getswapbootstrapinfo','getswapvalidationinfo','getswaphealth','listswapassets','getswapcapabilities'];
const LOOKUP=['listswaps','listswapproviders','searchswaps','listswapmarkets','getswaprouteinfo','getswapevents','listswapmandates','getswaprecoveryinfo'];
const REVIEW=['requestswapquote','acceptswapquote','cancelswap','refundswap','resumeswap','bumpswapfee','createswapmandate','revokeswapmandate','publishswapprovider','withdrawswapprovider','setswapmarket','setswapassetpolicy','getswapwalletinfo','exportswaprecovery'];

export function swapnetView(app){
 const root=el('div',{class:'page'},heading('SwapNet','Route, bootstrap, and health from this node. A quote, accept, refund, fee bump, mandate, or recovery export opens native review. Atlas does not spend.'));
 const host=el('div',{class:'surface-stack'});
 const refresh=button('Refresh',()=>load(),'primary');
 async function load(){
  refresh.disabled=true;
  host.replaceChildren(note('Reading this node…'));
  const blocks=[];
  try{
   for(const method of STATUS){
    const box=el('section',{class:'panel'});
    try{
     const envelope=await app.bridge.read(method,[]);
     const result=envelope&&Object.prototype.hasOwnProperty.call(envelope,'result')?envelope.result:envelope;
     const shown=presentObservation(method,result);
     box.append(el('div',{class:'row'},el('h2',{},shown.title),el('small',{class:'mono'},method)));
     if(shown.metrics.length)box.append(el('div',{class:'metrics'},...shown.metrics.map(item=>metric(item.label,item.value))));
     box.append(jsonView(result,{open:false,title:'Native record'}));
    }catch(e){
     box.append(el('h2',{},method),note(e.message,'warning'));
    }
    blocks.push(box);
   }
   host.replaceChildren(...blocks,note('automatic_spend_atoms stays 0. source_version and client_version are not release qualification. Awaiting a compatible peer is a reported state. No hub is compiled in.'));
  }finally{refresh.disabled=false;}
 }
 root.append(el('div',{class:'row'},refresh),host,el('h2',{},'Look up'),el('div',{class:'actions'},...LOOKUP.map(method=>button(method,()=>operationDialog(app,method)))),el('h2',{},'Native review'),note('These change a route, a mandate, or funds. The form is prepared for review. It is not sent from this page.'),el('div',{class:'actions'},...REVIEW.map(method=>button(method,()=>operationDialog(app,method)))));
 load();
 return root;
}
