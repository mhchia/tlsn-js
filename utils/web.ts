import { prove } from '../src';

// In KB. Only support 1, 4, 8, 16 KB now.
const DATA_SIZE = 1;
// Loop 10 times to get average runtime.
const NUM_LOOPS = 10;
// In bytes. This must match the value used in notary-server.
const MAX_TRANSCRIPT_SIZE = 49152;

(async function runTest() {
  const runtimes: number[] = []
  for (let i = 0; i < NUM_LOOPS; i++) {
    const start = performance.now();
    const proof = await prove(`https://test-server.io/formats/json?size=${DATA_SIZE}`, {
      method: 'GET',
      maxTranscriptSize: MAX_TRANSCRIPT_SIZE,
      // NOTE: Still use https since it failed
      notaryUrl: 'https://localhost:7047',
      websocketProxyUrl: 'ws://localhost:55688?token=local',
    });
    console.log("!@# proof=", proof)
    const end = performance.now();
    runtimes.push(end - start);
  }
  console.log("!@# runtimes          =", runtimes.map(x => x / 1000))
  const avgRuntime = runtimes.reduce((a, b) => a + b, 0) / runtimes.length;
  console.log("!@# average prove time=", avgRuntime / 1000);
})();