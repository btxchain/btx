export class Store {
  #state; #listeners = new Set(); #sequence = 0;
  constructor(initial = {}) { this.#state = Object.freeze({...initial}); }
  get state() { return this.#state; }
  get sequence() { return this.#sequence; }
  update(patch) {
    const change = typeof patch === 'function' ? patch(this.#state) : patch;
    this.#state = Object.freeze({...this.#state,...change}); this.#sequence++;
    for (const fn of [...this.#listeners]) fn(this.#state,change);
  }
  subscribe(fn) { this.#listeners.add(fn); return ()=>this.#listeners.delete(fn); }
  get listenerCount() { return this.#listeners.size; }
}
export class ByteCache {
  #entries = new Map(); #bytes = 0;
  constructor(limit = 16*1024*1024, count = 64) { if(!Number.isSafeInteger(limit)||limit<1||!Number.isSafeInteger(count)||count<1)throw Error('Cache budgets must be positive integers');this.limit=limit; this.count=count; }
  set(key,value,bytes) {
    if (!Number.isSafeInteger(bytes) || bytes<0 || bytes>this.limit) throw new Error('Cache entry exceeds budget');
    this.delete(key);
    while (this.#entries.size>=this.count || this.#bytes+bytes>this.limit) this.delete(this.#entries.keys().next().value);
    this.#entries.set(key,{value,bytes}); this.#bytes+=bytes;
  }
  get(key) { const x=this.#entries.get(key); if(!x)return undefined; this.#entries.delete(key); this.#entries.set(key,x); return x.value; }
  delete(key) { const x=this.#entries.get(key); if(x){this.#bytes-=x.bytes;this.#entries.delete(key);} }
  clear(){this.#entries.clear();this.#bytes=0;}
  get size(){return this.#entries.size;} get bytes(){return this.#bytes;}
}
export class Ring {
  constructor(capacity=512){if(capacity<1)throw Error('capacity');this.capacity=capacity;this.items=[];this.start=0;}
  push(value){if(this.items.length<this.capacity)this.items.push(value);else{this.items[this.start]=value;this.start=(this.start+1)%this.capacity;}}
  values(){return [...this.items.slice(this.start),...this.items.slice(0,this.start)];}
  clear(){this.items=[];this.start=0;}
}
export class Poller {
  #running=false; #timer=null; #epoch=0;
  constructor(fn,{interval=5000,onError=()=>{}}={}){this.fn=fn;this.interval=interval;this.onError=onError;}
  start(){if(this.#running)return;this.#running=true;const epoch=++this.#epoch;this.#tick(epoch);}
  stop(){this.#running=false;this.#epoch++;clearTimeout(this.#timer);this.#timer=null;}
  async #tick(epoch){
    try{await this.fn(()=>this.#running&&epoch===this.#epoch);}catch(e){if(epoch===this.#epoch)this.onError(e);}
    if(this.#running&&epoch===this.#epoch)this.#timer=setTimeout(()=>this.#tick(epoch),this.interval);
  }
  get running(){return this.#running;}
}
export async function boundedMap(items, concurrency, fn) {
  if(!Number.isSafeInteger(concurrency)||concurrency<1||concurrency>64)throw Error('Invalid concurrency');
  const results=new Array(items.length);let next=0;
  await Promise.all(Array.from({length:Math.min(concurrency,items.length)},async()=>{
    while(next<items.length){const i=next++;try{results[i]=await fn(items[i],i);}catch(e){results[i]={ok:false,error:String(e?.message||e)};}}
  }));return results;
}
