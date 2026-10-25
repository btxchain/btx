// SYNTHETIC visual fixtures only. Never imported by native authority code or used as
// a fallback for unavailable live facts. Native mode cannot enter demo().
import {OPERATIONS} from '../core/catalog.js';
const families=['Logic / general','Code / repair','Language / local','Vision / research'];
const models=Array.from({length:36},(_,i)=>({model_id:`demo-${i.toString(16).padStart(4,'0')}`,name:`${families[i%4]} · ${Math.floor(i/4)+1}`,format:i%3?'SafeTensors':'GGUF',bytes_verified:i%9!==0,incomplete:i%9===0,size_bytes:String((2+i%5)*1024**3),lineage_id:`demo-family-${i%4}`,lineage_name:families[i%4],lineage_verified:true,source:'SYNTHETIC',qualification:'NOT_EVIDENCE'}));
export function demoReply(method,params=[]){const now=Date.now();switch(method){
 case 'help':return params.length?`${params[0]}\nSYNTHETIC help placeholder. Consult the connected node for the exact signature.`:OPERATIONS.map(x=>x.method+' (arguments)').join('\n');
 case 'getblockchaininfo':return{chain:'regtest · DEMO',blocks:'420000',headers:'420000',initialblockdownload:false,verificationprogress:'1',bestblockhash:'d'.repeat(64),source:'SYNTHETIC'};
 case 'getnetworkinfo':return{version:'350000',subversion:'/BTX:0.35.0rc1 DEMO/',connections:'18',networkactive:true,localaddresses:[],warnings:[]};
 case 'getmodelnetworkinfo':return{enabled:true,helper_ready:true,pq1_ready:true,automatic_spend_atoms:'0',quota_bytes:String(128*1024**3),used_bytes:String(36*1024**3),native_participation:{release_qualified:false,automatic_spend_atoms:'0',authenticated_peers:'12',peer_observations:Array.from({length:12},(_,i)=>({id:`demo-model-peer-${i}`,transport_pin:`DEMO${i}`,endpoint:'REDACTED SYNTHETIC',compute_authorized:false,expires_at_ms:String(now+60000)}))}};
 case 'getpeerinfo':return Array.from({length:18},(_,i)=>({id:String(i),addr:`demo-peer-${i}`,inbound:!!(i%2),subver:'/BTX:DEMO/',pingtime:String((i+4)/1000),bytessent:String(1000+i*733),bytesrecv:String(1500+i*1391)}));
 case 'getmodelpeers':return{peers:[],note:'See synthetic native_participation'};
 case 'listmodels':return{models,coverage:{complete:false},synthetic:true};
 case 'searchmodels':return{models:models.filter(m=>m.name.toLowerCase().includes(String(params[0]?.text||'').toLowerCase())),coverage:{complete:false}};
 case 'showmodel':return models.find(m=>m.model_id===params[0])||{unavailable:true};
 case 'getmodeltransfers':return{transfers:models.slice(0,4).map((m,i)=>({model_id:m.model_id,name:m.name,state:i?'SEEDING':'DOWNLOADING',percent:String(28+i*22),bytes_per_sec:String((i+1)*1024**2),job_id:`demo-job-${i}`}))};
 case 'getmodelhostprofile':return{local_generate:true,trust_remote_code:false,cuda_smoke_is_not_generate:true,backend:'DEMO / not a running engine'};
 case 'getsetupstatus':return{one_liner:'Synthetic fixture. No node, model runtime, or wallet is connected.',money:{ready_to_mine:false},modelnet:{ready_to_host:false}};
 case 'getmininginfo':return{blocks:'420000',chain:'DEMO',pooledtx:'62',first_run:{ready_to_mine:false,one_liner:'No synthetic mining performance is reported.'}};
 case 'getmempoolinfo':return{size:'62',bytes:'27155',usage:'145408',loaded:true};
 case 'getnettotals':return{totalbytesrecv:'48234496',totalbytessent:'20971520',timemillis:String(now)};
 case 'listwallets':return[];
 case 'getmodelpolicy':return{seed:'auto',automatic_spend_atoms:'0',retrieval_mode:'FREE_ONLY'};
 case 'getmodelfeed':case 'getrecentreleases':case 'getfundablemodels':case 'searchbounties':return{items:[],coverage:{complete:false}};
 case 'getmemoryinfo':return{note:'No measured native process memory in demo mode'};
 case 'getmodelwatchstatus':return{configured:false};
 default:return{unavailable:true,source:'SYNTHETIC',note:'This fixture deliberately contains no fabricated result for this method.'};
}}
export function demoGraphSources(){return Object.fromEntries(['getblockchaininfo','getnetworkinfo','getmodelnetworkinfo','getpeerinfo','listmodels','getmodeltransfers','getmodelhostprofile','getmininginfo','getmempoolinfo','getsetupstatus','getnettotals'].map(m=>[m,{ok:true,observed_at:Date.now(),synthetic:true,result:demoReply(m)}]));}
