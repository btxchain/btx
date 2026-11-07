// Bounded, event-driven 2.5D layer atlas. Unmeasured cells remain structural bins.
import {captureValues} from './contract.js';
export class NeuronScene{
 constructor(canvas,{onSelect=()=>{}}={}){
  this.canvas=canvas;this.ctx=canvas.getContext('2d');this.onSelect=onSelect;this.binding=null;this.capture=null;this.cells=[];this.yaw=-0.45;this.zoom=1;this.raf=0;this.alive=true;this.selected={layer:0,unit:0};this.flat=false;this.drag=null;
  this.handlers={pointerdown:e=>{this.drag={x:e.clientX,y:e.clientY,start:e.clientX};canvas.setPointerCapture(e.pointerId);},pointermove:e=>{if(this.drag){this.yaw+=(e.clientX-this.drag.x)*.005;this.drag.x=e.clientX;this.invalidate();}},pointerup:e=>{if(this.drag&&Math.abs(e.clientX-this.drag.start)<5){const r=canvas.getBoundingClientRect(),x=e.clientX-r.left,y=e.clientY-r.top;let best=null,dist=100;for(const c of this.cells){const d=(x-c.x)**2+(y-c.y)**2;if(d<dist){best=c;dist=d;}}if(best){this.selected={layer:best.layer,unit:best.first};this.onSelect({...best,aggregated:best.last>best.first});this.invalidate();}}this.drag=null;},wheel:e=>{e.preventDefault();this.zoom=Math.max(.4,Math.min(2.2,this.zoom*Math.exp(-e.deltaY*.001)));this.invalidate();},keydown:e=>{if(e.key==='Home'){this.yaw=-.45;this.zoom=1;this.invalidate();}if(e.key==='ArrowLeft'||e.key==='ArrowRight'){this.yaw+=(e.key==='ArrowLeft'?-.08:.08);this.invalidate();}}};
  for(const[k,v]of Object.entries(this.handlers))canvas.addEventListener(k,v,k==='wheel'?{passive:false}:undefined);
  this.resize=new ResizeObserver(()=>this.invalidate());this.resize.observe(canvas);this.invalidate();
 }
 setData(binding,capture=null){this.binding=binding;this.capture=capture;this.invalidate();}
 setSelected(layer,unit){this.selected={layer,unit};this.invalidate();}
 invalidate(){if(!this.raf&&this.alive)this.raf=requestAnimationFrame(()=>{this.raf=0;this.draw();});}
 draw(){
  const c=this.canvas,ctx=this.ctx;if(!ctx)return;const box=c.getBoundingClientRect(),w=Math.max(1,box.width),h=Math.max(1,box.height),dpr=Math.min(devicePixelRatio||1,2);
  if(c.width!==Math.round(w*dpr)||c.height!==Math.round(h*dpr)){c.width=Math.round(w*dpr);c.height=Math.round(h*dpr);}ctx.setTransform(dpr,0,0,dpr,0,0);ctx.clearRect(0,0,w,h);ctx.fillStyle='#050608';ctx.fillRect(0,0,w,h);this.cells=[];
  if(!this.binding){ctx.fillStyle='#96a0aa';ctx.font='14px system-ui';ctx.fillText('Select a registered checkpoint to inspect its actual layer dimensions.',24,h/2);return;}
  const b=this.binding,layers=Math.min(b.layers,48),bins=Math.min(b.intermediate_size,96),stride=Math.ceil(b.intermediate_size/bins);
  const extent=Math.min(w*.62,h*.75)*this.zoom,step=extent/Math.max(3,layers),tile=Math.min(210,extent*.55);
  const project=(layer,u,v)=>{const x=(layer-(layers-1)/2)*step,y=u*tile,z=v*tile;return{x:w*.49+x*Math.cos(this.yaw)+z*Math.sin(this.yaw),y:h*.54+y+(this.flat?0:x*.33-z*.4)};};
  ctx.font='11px ui-monospace,monospace';
  for(let layer=0;layer<layers;layer++){
   const corners=[[-.6,-.55],[-.6,.55],[.6,.55],[.6,-.55]].map(([u,v])=>project(layer,u,v));
   ctx.beginPath();corners.forEach((p,i)=>i?ctx.lineTo(p.x,p.y):ctx.moveTo(p.x,p.y));ctx.closePath();ctx.fillStyle='rgba(100,125,150,.025)';ctx.fill();ctx.strokeStyle=layer===this.selected.layer?'#536779':'#202933';ctx.stroke();
   const label=project(layer,.76,0);ctx.fillStyle=layer===this.selected.layer?'#dce4ec':'#7b8793';ctx.fillText(`L${layer}`,label.x-8,label.y+12);
   const{values}=captureValues(this.capture,layer);
   for(let n=0;n<bins;n++){
    const first=n*stride;if(first>=b.intermediate_size)break;const last=Math.min(b.intermediate_size-1,first+stride-1),p=project(layer,((n%8)/7-.5),((Math.floor(n/8))/Math.max(1,Math.ceil(bins/8)-1)-.5));let val=null;
    for(const[unit,v]of values)if(unit>=first&&unit<=last&&(val===null||Math.abs(v)>Math.abs(val)))val=v;
    const selected=layer===this.selected.layer&&this.selected.unit>=first&&this.selected.unit<=last;
    ctx.beginPath();ctx.arc(p.x,p.y,selected?4:val===null?1.2:2.8,0,Math.PI*2);
    ctx.fillStyle=selected?'#fff':val===null?'#3b4652':val>=0?'#efb86f':'#df90c7';ctx.fill();
    if(selected){ctx.beginPath();ctx.arc(p.x,p.y,7,0,Math.PI*2);ctx.strokeStyle='#63c9e8';ctx.stroke();}
    this.cells.push({...p,layer,first,last,value:val});
   }
  }
  ctx.fillStyle='#96a0aa';ctx.fillText(`${layers}/${b.layers} layers · ${bins} bounded coordinate bins/layer · ${this.capture?'measured selected coordinates':'structure only, no activations'}`,16,24);
  ctx.fillText('Drag to orbit · scroll to zoom · Home to reset · exact coordinates in the inspector',16,h-18);
 }
 dispose(){this.alive=false;if(this.raf)cancelAnimationFrame(this.raf);this.resize.disconnect();for(const[k,v]of Object.entries(this.handlers))this.canvas.removeEventListener(k,v);this.cells=[];this.capture=null;}
}
