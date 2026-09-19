/** Neutral CRL transport. Supply real enrolled auth and native verification. */
export type Json = null | boolean | number | string | Json[] | {[key:string]:Json};
export type Operation = {operation_id:string; method:"GET"|"POST"; path:string;
  request_schema:string|null; response_schema:string; effect:string; scope:string};
export type HeaderFactory = (method:string,url:string,body:Uint8Array)=>Promise<Record<string,string>>;
export type Verifier = (statement:Record<string,Json>)=>Promise<void>;
export class CrlClient {
  private readonly ops:Map<string,Operation>;
  private readonly base:string;
  constructor(base:string, operations:Operation[], private headers:HeaderFactory,
              private verify:Verifier, private timeoutMs=30000) {
    const u=new URL(base);
    if(u.protocol!=="https:"||u.username||u.password||u.search||u.hash) throw new Error("ENROLLED_HTTPS_REQUIRED");
    this.base=base.replace(/\/$/,"");this.ops=new Map(operations.map(o=>[o.operation_id,o]));
  }
  async call(id:string, options:{path?:Record<string,string>;query?:Record<string,string>;
       body?:Json;idempotencyKey?:string}={}):Promise<Json> {
    const op=this.ops.get(id);if(!op)throw new Error("UNKNOWN_OPERATION");
    if(op.request_schema==="BINARY"||op.response_schema==="BINARY")throw new Error("USE_BOUNDED_BINARY_TRANSPORT");
    const path=options.path??{};let route=op.path.replace(/^\/btx\/hcp\/v1/,"");
    const keys=[...route.matchAll(/\{([^}]+)\}/g)].map(x=>x[1]);
    if(keys.sort().join()!==Object.keys(path).sort().join())throw new Error("PATH_MISMATCH");
    for(const k of keys){const v=path[k];if(!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(v))throw new Error("INVALID_ID");route=route.replace(`{${k}}`,encodeURIComponent(v));}
    const url=this.base+route+(options.query?"?"+new URLSearchParams(options.query).toString():"");
    if(op.method==="POST"&&!options.idempotencyKey)throw new Error("IDEMPOTENCY_REQUIRED");
    const text=options.body===undefined?"":JSON.stringify(options.body);
    const bytes=new TextEncoder().encode(text);if(bytes.byteLength>1048576)throw new Error("BODY_TOO_LARGE");
    const h=await this.headers(op.method,url,bytes);h["Accept"]="application/json";h["Content-Type"]="application/json";
    if(options.idempotencyKey)h["Idempotency-Key"]=options.idempotencyKey;
    const c=new AbortController();const timer=setTimeout(()=>c.abort(),this.timeoutMs);
    try {
      const r=await fetch(url,{method:op.method,headers:h,body:op.method==="POST"?text:undefined,redirect:"error",signal:c.signal});
      const reader=r.body?.getReader();if(!reader)throw new Error("EMPTY_RESPONSE");
      const parts:Uint8Array[]=[];let size=0;
      for(;;){const x=await reader.read();if(x.done)break;size+=x.value.byteLength;if(size>1048576){await reader.cancel();throw new Error("RESPONSE_TOO_LARGE");}parts.push(x.value);}
      const all=new Uint8Array(size);let at=0;for(const x of parts){all.set(x,at);at+=x.length;}
      const data=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(all)) as Json;
      if(!r.ok)throw new Error(`HTTP_${r.status}: ${JSON.stringify(data)}`);
      if(data&&typeof data==="object"&&!Array.isArray(data)&&"object_type" in data)await this.verify(data);
      return data;
    } finally {clearTimeout(timer);}
  }
}
