// All geometry is derived display state, never native identity/permission state.
export const MAX_POINTS=1_000_000, PAGE_LIMIT=32768;
const id=v=>typeof v==='string'&&/^[a-f0-9]{96}$/.test(v);
const integer=(n,a,b)=>Number.isSafeInteger(n)&&n>=a&&n<=b;
function assert(ok,message){if(!ok)throw Error(message);}
function bytes(s,length){assert(typeof s==='string'&&s.length<=Math.ceil(length/3)*4+4,'Oversized binary page');let raw;try{raw=atob(s);}catch{throw Error('Invalid binary page encoding');}assert(raw.length===length,'Wrong binary page length');return Uint8Array.from(raw,c=>c.charCodeAt(0));}
export function decodePage(p,expected){
 assert(p?.schema==='btx.neuronlab.embedding-page/2'&&id(p.dataset_id)&&p.dataset_id===expected,'Wrong embedding dataset');
 assert(integer(p.count,0,PAGE_LIMIT)&&integer(p.total_rows,2,MAX_POINTS)&&integer(p.stride,1,MAX_POINTS),'Invalid embedding bounds');
 const xyRaw=bytes(p.coordinates_f32_le,p.count*8),catRaw=bytes(p.categories_u32_le,p.count*16),idRaw=bytes(p.row_ids_u32_le,p.count*4);
 const xy=new Float32Array(p.count*2),categories=new Uint32Array(p.count*4),ids=new Uint32Array(p.count);
 let dv=new DataView(xyRaw.buffer);for(let i=0;i<xy.length;i++){const v=dv.getFloat32(i*4,true);assert(Number.isFinite(v)&&Math.abs(v)<1e12,'Nonfinite/extreme coordinate');xy[i]=v;}
 dv=new DataView(catRaw.buffer);for(let i=0;i<categories.length;i++)categories[i]=dv.getUint32(i*4,true);
 dv=new DataView(idRaw.buffer);for(let i=0;i<ids.length;i++){ids[i]=dv.getUint32(i*4,true);assert(ids[i]<p.total_rows&&(!i||ids[i]-ids[i-1]===p.stride),'Disordered or duplicate row IDs');}
 assert(p.next_offset===null||integer(p.next_offset,0,p.total_rows),'Invalid page cursor');
 return {xy,categories,ids,count:p.count,total:p.total_rows,stride:p.stride,next:p.next_offset};
}
export class PointStore{
 constructor(dataset,stride=1){assert(id(dataset.id)&&integer(dataset.rows,2,MAX_POINTS),'Invalid dataset summary');assert(integer(stride,1,MAX_POINTS),'Invalid stride');this.id=dataset.id;this.total=dataset.rows;this.stride=stride;this.capacity=Math.ceil(this.total/stride);this.xy=new Float32Array(this.capacity*2);this.categories=new Uint32Array(this.capacity*4);this.ids=new Uint32Array(this.capacity);this.count=0;this.next=0;this.complete=false;}
 append(page){const p=decodePage(page,this.id);assert(p.total===this.total&&p.stride===this.stride&&this.count+p.count<=this.capacity,'Embedding page changed dimensions');assert(p.count>0&&p.ids[0]===this.next,'Missing/duplicated/out-of-order page');const expected=p.ids[p.ids.length-1]+this.stride;assert(p.next===(expected<this.total?expected:null),'Inconsistent continuation');this.xy.set(p.xy,this.count*2);this.categories.set(p.categories,this.count*4);this.ids.set(p.ids,this.count);this.count+=p.count;this.next=p.next;this.complete=this.next===null&&this.stride===1;return this;}
 bounds(){let minX=Infinity,minY=Infinity,maxX=-Infinity,maxY=-Infinity;for(let i=0;i<this.count;i++){const x=this.xy[i*2],y=this.xy[i*2+1];minX=Math.min(minX,x);minY=Math.min(minY,y);maxX=Math.max(maxX,x);maxY=Math.max(maxY,y);}return this.count?[minX,minY,maxX,maxY]:[-1,-1,1,1];}
 memoryBytes(){return this.xy.byteLength+this.categories.byteLength+this.ids.byteLength;}
 row(slot){assert(integer(slot,0,this.count-1),'Invalid point selection');return{row:this.ids[slot],x:this.xy[slot*2],y:this.xy[slot*2+1],neuron:this.categories[slot*4],prompt:this.categories[slot*4+1],dose:this.categories[slot*4+2],kind:this.categories[slot*4+3]};}
 dispose(){this.xy=new Float32Array(0);this.categories=new Uint32Array(0);this.ids=new Uint32Array(0);this.count=0;}
}
export function insidePolygon(x,y,polygon){let hit=false;for(let i=0,j=polygon.length-1;i<polygon.length;j=i++){const a=polygon[i],b=polygon[j];if(((a[1]>y)!==(b[1]>y))&&(x<(b[0]-a[0])*(y-a[1])/(b[1]-a[1])+a[0]))hit=!hit;}return hit;}
export function lasso(xy,count,polygon,limit=10000,visibility=null){assert(integer(count,0,MAX_POINTS)&&xy.length>=count*2,'Invalid point buffer');assert(integer(limit,1,10000),'Invalid selection cap');assert(visibility===null||(visibility instanceof Uint8Array&&visibility.length>=count),'Invalid visibility mask');assert(Array.isArray(polygon)&&polygon.length>=3&&polygon.length<=128&&polygon.every(p=>Array.isArray(p)&&p.length===2&&p.every(Number.isFinite)),'Invalid lasso');const xs=polygon.map(p=>p[0]),ys=polygon.map(p=>p[1]);const x0=Math.min(...xs),x1=Math.max(...xs),y0=Math.min(...ys),y1=Math.max(...ys);const selected=[];let total=0;for(let i=0;i<count;i++){if(visibility&&!visibility[i])continue;const x=xy[2*i],y=xy[2*i+1];if(x>=x0&&x<=x1&&y>=y0&&y<=y1&&insidePolygon(x,y,polygon)){total++;if(selected.length<limit)selected.push(i);}}return{slots:new Uint32Array(selected),total,truncated:total>selected.length};}
// Packed uniform grid; bounded typed-array index, no per-point DOM/JS objects.
export class SpatialIndex{
 constructor(xy,count,bounds,size=64){assert(integer(count,0,MAX_POINTS),'Index too large');this.xy=xy;this.count=count;this.bounds=bounds;this.size=size;this.starts=new Uint32Array(size*size+1);this.order=new Uint32Array(count);for(let i=0;i<count;i++)this.starts[this.bin(xy[2*i],xy[2*i+1])+1]++;for(let i=1;i<this.starts.length;i++)this.starts[i]+=this.starts[i-1];const cursor=this.starts.slice();for(let i=0;i<count;i++)this.order[cursor[this.bin(xy[2*i],xy[2*i+1])]++]=i;}
 axis(v,lo,hi){return Math.max(0,Math.min(this.size-1,Math.floor((v-lo)/Math.max(hi-lo,1e-12)*this.size)));}
 bin(x,y){return this.axis(y,this.bounds[1],this.bounds[3])*this.size+this.axis(x,this.bounds[0],this.bounds[2]);}
 nearest(x,y,radius,filter=()=>true){let best=-1,distance=radius*radius;const [x0,y0,x1,y1]=this.bounds;const ax=this.axis(x-radius,x0,x1),bx=this.axis(x+radius,x0,x1),ay=this.axis(y-radius,y0,y1),by=this.axis(y+radius,y0,y1);for(let row=ay;row<=by;row++)for(let col=ax;col<=bx;col++){const k=row*this.size+col;for(let p=this.starts[k];p<this.starts[k+1];p++){const i=this.order[p];if(!filter(i))continue;const dx=this.xy[2*i]-x,dy=this.xy[2*i+1]-y,d=dx*dx+dy*dy;if(d<=distance){distance=d;best=i;}}}return best;}
}
