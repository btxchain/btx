import {lasso,MAX_POINTS} from './embedding-data.js';
let xy=null,count=0,generation=0,visibility=null;
self.onmessage=e=>{const m=e.data;try{
 if(m.type==='dataset'){if(!(m.xy instanceof Float32Array)||!Number.isInteger(m.count)||m.count<0||m.count>MAX_POINTS||m.xy.length<m.count*2)throw Error('Invalid worker dataset');xy=m.xy;count=m.count;generation=m.generation;visibility=null;self.postMessage({type:'ready',generation});}
 else if(m.type==='visibility'&&m.generation===generation){if(!(m.mask instanceof Uint8Array)||m.mask.length!==count)throw Error('Invalid visibility');visibility=m.mask;}
 else if(m.type==='lasso'&&xy&&m.generation===generation){const result=lasso(xy,count,m.polygon,10000,visibility);self.postMessage({type:'selection',generation,request:m.request,...result},[result.slots.buffer]);}
 else if(m.type==='clear'){xy=null;count=0;generation++;}
}catch(err){self.postMessage({type:'error',generation,request:m.request,message:String(err.message).slice(0,256)});}};
