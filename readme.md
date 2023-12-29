# Benchmark with tlsn-server-fixture

## Setup
Notary <-> Prover <-> Websockify <-> Test Server (tlsn-server-fixture)

## Configurations
In [utils/web.ts](./utils/web.ts)
- `DATA_SIZE`: size of the data to be notarized in KB. Now the fixture only supports 1, 4, 8, and 16 KB.
- `NUM_LOOPS`: notarize for this many times and take the average.
- `MAX_TRANSCRIPT_SIZE`: maximum size of the transcript in KB. Note that
    - This number should be large enough for a larger dataset.
    - This value `max-transcript-size` must be the same one used by notary-server. Otherwise the notary server will reject the transcript.

## Steps to run
### 1. Start tlsn-server-fixture server
At the root level of tlsn repository, run
```sh
cd tlsn/tlsn-server-fixture
PORT=22655 cargo run --release
```
to start the server on port `22655`.

### 2. Start the notary server
First, change the `notarization.max-transcript-size` in `notary-server/config/config.yaml` to be `49152`.

Then, run the following command under `notary-server` folder:
```sh
cd ../notary-server
cargo run --release
```

### 3. Build and run a websocket proxy
Build the websockify proxy docker image
```sh
git clone https://github.com/novnc/websockify && cd websockify
./docker/build.sh

Go back to tlsn-extension repository root and run the websockify proxy
```sh
cd tlsn-extension
docker run -it --rm -p 55688:80 -v $(pwd):/app novnc/websockify 80 --target-config /app/websockify_target_cfg
```

### 4. Build the wasm and run web server
```sh
npm run build:wasm
npm run dev
```

#### Note
1. You will need to change the path of [tlsn](https://github.com/tlsnotary/tlsn) if it is not under the same directory as this repo, in order to make it build. This is required since we're using `tls_core::anchors::RootCertStore`, which is not able to import directly through github link. Also, make sure to check out tlsn to the commit to be benchmarked.

2. If an error like the following one occurs, it might be because your cargo doesn't support wasm32-unknown-unknown target. [This](https://github.com/tlsnotary/tlsn-extension/issues/29#issuecomment-1855186942) could be a possible solution if you're using macOS.

```sh
Error: Compiling your crate to WebAssembly failed
Caused by: Compiling your crate to WebAssembly failed
Caused by: failed to execute `cargo build`: exited with exit status: 101
  full command: "cargo" "build" "--lib" "--release" "--target" "wasm32-unknown-unknown"
```

### 5. Run the prover
Open the page and you can see the prover running in the console

```sh
open localhost:3001
```
