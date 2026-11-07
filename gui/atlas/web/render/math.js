export const identity=()=>new Float32Array([1,0,0,0,0,1,0,0,0,0,1,0,0,0,0,1]);
export function multiply(a,b){const out=new Float32Array(16);for(let c=0;c<4;c++)for(let r=0;r<4;r++)for(let k=0;k<4;k++)out[c*4+r]+=a[k*4+r]*b[c*4+k];return out;}
export function perspective(fovy,aspect,near,far){const f=1/Math.tan(fovy/2),nf=1/(near-far);return new Float32Array([f/aspect,0,0,0,0,f,0,0,0,0,(far+near)*nf,-1,0,0,2*far*near*nf,0]);}
export function ortho(left,right,bottom,top,near,far){return new Float32Array([2/(right-left),0,0,0,0,2/(top-bottom),0,0,0,0,-2/(far-near),0,-(right+left)/(right-left),-(top+bottom)/(top-bottom),-(far+near)/(far-near),1]);}
const normalize=v=>{const n=Math.hypot(...v)||1;return v.map(x=>x/n);};const cross=(a,b)=>[a[1]*b[2]-a[2]*b[1],a[2]*b[0]-a[0]*b[2],a[0]*b[1]-a[1]*b[0]],dot=(a,b)=>a.reduce((s,x,i)=>s+x*b[i],0);
export function lookAt(eye,target,up=[0,1,0]){const z=normalize(eye.map((x,i)=>x-target[i])),x=normalize(cross(up,z)),y=cross(z,x);return new Float32Array([x[0],y[0],z[0],0,x[1],y[1],z[1],0,x[2],y[2],z[2],0,-dot(x,eye),-dot(y,eye),-dot(z,eye),1]);}
export function project(m,p,w,h){const v=[p[0],p[1],p[2],1],out=[0,0,0,0];for(let r=0;r<4;r++)for(let k=0;k<4;k++)out[r]+=m[k*4+r]*v[k];if(out[3]<=0)return null;return[(out[0]/out[3]+1)*w/2,(1-out[1]/out[3])*h/2,out[2]/out[3]];}
export class Camera{
 constructor(saved={}){this.yaw=Number.isFinite(saved.yaw)?saved.yaw:.65;this.pitch=Number.isFinite(saved.pitch)?saved.pitch:.38;this.distance=Number.isFinite(saved.distance)?Math.max(5,Math.min(100,saved.distance)):31;this.target=[0,0,0];this.flat=false;}
 matrix(aspect){const eye=this.flat?[this.target[0],this.target[1],this.distance]:[this.target[0]+Math.sin(this.yaw)*Math.cos(this.pitch)*this.distance,this.target[1]+Math.sin(this.pitch)*this.distance,this.target[2]+Math.cos(this.yaw)*Math.cos(this.pitch)*this.distance];const p=this.flat?ortho(-this.distance*aspect/2,this.distance*aspect/2,-this.distance/2,this.distance/2,.1,1000):perspective(.72,aspect,.1,1000);return multiply(p,lookAt(eye,this.target));}
 orbit(dx,dy){this.yaw+=dx*.007;this.pitch=Math.max(-1.25,Math.min(1.25,this.pitch+dy*.007));}
 pan(dx,dy){this.target[0]-=dx*this.distance/1000;this.target[1]+=dy*this.distance/1000;}
 zoom(delta){this.distance=Math.max(5,Math.min(100,this.distance*Math.exp(delta*.001)));}
 save(){return{yaw:this.yaw,pitch:this.pitch,distance:this.distance};}
}
