import {layoutGraph} from '../core/graph.js';
self.onmessage=event=>{const {generation,graph,plane}=event.data;try{const data=layoutGraph(graph,{plane});self.postMessage({generation,...data},[data.positions.buffer,data.edgeIndices.buffer]);}catch(e){self.postMessage({generation,error:String(e.message)});}};
