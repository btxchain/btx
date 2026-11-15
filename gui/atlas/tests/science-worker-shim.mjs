// Test adapter only: runs the unchanged browser-worker module in a Node worker.
import {parentPort} from 'node:worker_threads';
globalThis.self={postMessage:(message,transfer)=>parentPort.postMessage(message,transfer)};
await import('../web/neuronlab/science/scatter-worker.js');
parentPort.on('message',data=>self.onmessage({data}));
