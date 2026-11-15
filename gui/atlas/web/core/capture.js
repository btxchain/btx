const SAFE=/^[A-Za-z0-9._:/-]{1,256}$/;
export function validateCapture(doc){
 if(!doc||doc.schema!=='btx.atlas.capture/1'||!doc.provenance||typeof doc.provenance.model_id!=='string'||!SAFE.test(doc.provenance.model_id)||typeof doc.provenance.runtime!=='string'||doc.provenance.runtime.length>128)throw Error('Capture needs exact model identity and runtime provenance');
 if(!Array.isArray(doc.layers)||doc.layers.length>512)throw Error('Capture exceeds 512 measured layers');let points=0;
 const ids=new Set();for(const layer of doc.layers){if(!layer||typeof layer.id!=='string'||!SAFE.test(layer.id)||ids.has(layer.id)||!Array.isArray(layer.units)||layer.units.length>4096)throw Error('Invalid or duplicated measured layer');ids.add(layer.id);for(const unit of layer.units){if(!Number.isSafeInteger(unit.index)||unit.index<0||!Number.isFinite(unit.value)||Math.abs(unit.value)>1e30)throw Error('Invalid measured activation');}points+=layer.units.length;}
 if(points>100000)throw Error('Capture exceeds 100,000 retained measurements');
 return doc;
}
export function captureGraph(doc){validateCapture(doc);const nodes=[],edges=[];for(const [i,l]of doc.layers.entries()){const layerId=`layer:${l.id}`;nodes.push({id:layerId,label:l.id,kind:'layer',group:i,state:'imported_measurement',source:doc.provenance.runtime,detail:{...doc.provenance,layer:l.id,units:l.units.length,trust:'Imported record; signature and runtime not independently verified'}});for(const u of l.units){const id=`unit:${l.id}:${u.index}`;nodes.push({id,label:`${l.id} / ${u.index}`,kind:'tensor',group:i,state:'reported',source:doc.provenance.runtime,detail:{unit:u.index,value:u.value,metric:l.metric,source:doc.provenance}});edges.push({from:layerId,to:id,kind:'CAPTURED_IN_LAYER'});}}
 return{nodes,edges,complete:false};
}
