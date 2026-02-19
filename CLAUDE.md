# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Does

**Ligetron** is a zero-knowledge proof system that takes WebAssembly (WASM) programs as input and generates proofs that a computation executed correctly. It uses the Ligero polynomial commitment scheme and GPU acceleration via WebGPU (Dawn on native, Emscripten on web).

## Build Commands

### Native Prover/Verifier
```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
ctest  # run all tests
```

### Web Version (requires Emscripten + prebuilt wasm-libs)
```bash
mkdir -p build-web && cd build-web
emcmake cmake -DCMAKE_BUILD_TYPE=Web -DCMAKE_PREFIX_PATH=<path-to-wasm-libs> ..
emmake make
emrun --browser chrome webgpu_prover.html  # CORS prevents direct file open
```

### C++ SDK
```bash
cd sdk/cpp && mkdir build && cd build
emcmake cmake ..
make -j
```

### Rust SDK
```bash
cd sdk/rust
cargo build --target wasm32-wasip1 --release
# Build examples:
cargo build --examples --target wasm32-wasip1 --release
```

## Running the Prover/Verifier

Both executables take a single JSON string argument:
```bash
./webgpu_prover '{"program":"app.wasm","shader-path":"../shader","packing":8192,"private-indices":[1],"args":[{"str":"hello"},{"i64":42},{"hex":"0xdeadbeef"}]}'
./webgpu_verifier '<same JSON but private args can be obscured with same-length placeholder>'
```

Key JSON fields: `program` (required), `gpu-threads`, `shader-path` (default `"./shader"`), `packing` (default `8192`, affects proof size), `private-indices` (1-indexed), `args` (array of `{"str":...}`, `{"i64":...}`, or `{"hex":...}` objects).

## Architecture

### Execution Pipeline
1. **Transpiler** ([include/transpiler.hpp](include/transpiler.hpp)) — parses WASM via WABT and converts to internal instruction format
2. **Interpreter** ([include/interpreter.hpp](include/interpreter.hpp), [include/interpreter_impl.hpp](include/interpreter_impl.hpp)) — executes WASM opcodes and collects witness/execution trace
3. **Witness Manager** ([include/zkp/backend/witness_manager.hpp](include/zkp/backend/witness_manager.hpp)) — manages the execution trace needed for proof generation
4. **Ligero Backend** ([include/zkp/backend/ligero.hpp](include/zkp/backend/ligero.hpp)) — generates the ZK proof using Merkle tree commitments and polynomial operations
5. **WebGPU Engine** ([src/webgpu/engine.cpp](src/webgpu/engine.cpp)) — offloads heavy polynomial/field arithmetic to the GPU via WGSL shaders

### Key Module Groups

- **WASM VM** (`include/interpreter*.hpp`, `include/transpiler.hpp`, `include/runtime.hpp`, `include/opcode.hpp`) — the core VM that runs guest WASM programs
- **Host Modules** (`include/host_modules/`) — cryptographic functions exposed to guest WASM: BN254 field arithmetic (`bn254fr.hpp`), vectorized ops (`vbn254fr.hpp`), uint256 (`uint256.hpp`), WASI (`wasi_preview1.hpp`)
- **ZKP Backend** (`include/zkp/`) — Ligero proving scheme, finite field arithmetic (GMP-based BN254), Merkle trees, Rescue Prime hash, random challenge generation
- **WebGPU** (`src/webgpu/`, `include/wgpu.hpp`, `shader/`) — GPU device management and WGSL shaders for BigNum arithmetic and SHA256
- **SDKs** (`sdk/cpp/`, `sdk/rust/`) — cryptographic libraries for writing guest WASM applications (elliptic curves, hash functions, signatures)

### GPU Shaders
- [shader/bignum.wgsl](shader/bignum.wgsl) — BigNum/polynomial arithmetic on GPU (FFT, field ops)
- [shader/sha256.wgsl](shader/sha256.wgsl) — SHA-256 on GPU

### Tests
Tests are `.wat` (WebAssembly text format) files in [tests/](tests/) covering WASM instruction families (i32/i64 arithmetic, bitwise, memory, control flow). They are registered in CMake and run via `ctest`.

## Key Dependencies

- **Dawn** (WebGPU): must be built from source and installed before building Ligetron
- **WABT**: WebAssembly Binary Toolkit for parsing `.wasm`/`.wat` files
- **GMP/MPFR**: arbitrary-precision arithmetic for field operations
- **Boost**: logging, serialization, program_options, iostreams
- **nlohmann JSON 3.11.3**: JSON parsing (fetched by CMake)
- **Emscripten**: required only for web/SDK builds targeting WASM

## Hardware Requirements

Requires DX12/Vulkan/Metal GPU support. No iOS support. On Linux with Chrome:
```bash
google-chrome --enable-unsafe-webgpu --enable-features=Vulkan
```
