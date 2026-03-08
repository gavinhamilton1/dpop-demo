# Rust WASM AI Detection Setup Guide

## Overview

The AI detection has been migrated from AssemblyScript to **Rust** using `wasm-pack`. Rust provides better tooling, more mature ecosystem, and excellent WASM support.

## Quick Start

### 1. Install Prerequisites

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Install wasm-pack
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

# Verify
cargo --version
wasm-pack --version
```

### 2. Build WASM Module

```bash
cd wasm-rs
./build.sh
```

This will:
- Generate/load secret
- Build WASM module
- Copy to `../public/wasm/`

### 3. Set Server Secret

```bash
# Match the secret used in WASM build
export AI_DETECTION_SECRET="AI_DETECT_SECRET_v1_<your-secret>"
```

### 4. Integrate JavaScript

See `wasm-rs/INTEGRATION_EXAMPLE.js` for complete integration example.

## Project Structure

```
wasm-rs/
├── src/
│   └── lib.rs              # Rust source code
├── Cargo.toml              # Rust dependencies
├── build.sh                # Build script
├── .gitignore              # Git ignore rules
├── README.md               # Detailed README
└── INTEGRATION_EXAMPLE.js  # JS integration example

public/wasm/
├── ai-detection.wasm       # Compiled WASM binary
├── ai-detection.js         # JavaScript bindings
└── ai-detection.d.ts       # TypeScript definitions
```

## Features

✅ **Rust-based**: Better tooling and ecosystem  
✅ **SHA-256**: Proper cryptographic hashing for proof generation  
✅ **Type-safe**: Full TypeScript definitions  
✅ **Optimized**: Release build optimized for size  
✅ **Call-home**: Embedded secret with server verification  
✅ **Well-documented**: Complete docs and examples  

## Build Process

1. **Secret Management**: Build script handles secret generation/loading
2. **Compilation**: `wasm-pack` compiles Rust to WASM
3. **Optimization**: Release build optimized for size
4. **Binding Generation**: Auto-generates JS bindings
5. **Deployment**: Files copied to `public/wasm/`

## Integration

The WASM module exposes:

- `detect_ai(browserData)` - Run detection
- `generate_proof(sessionId, timestamp)` - Generate call-home proof
- `verify_proof(proof, sessionId, timestamp)` - Verify proof (client-side)
- `get_embedded_secret()` - Get secret (debugging only)

See `wasm-rs/INTEGRATION_EXAMPLE.js` for complete usage.

## Security

- Secret embedded at compile time
- Proof uses SHA-256 hashing
- Server validates proof and timestamp
- Detection logic hidden in WASM binary

## Troubleshooting

See `wasm-rs/README.md` for detailed troubleshooting guide.

## Migration from AssemblyScript

If you had started with AssemblyScript:
- Old code is in `wasm/` directory (can be removed)
- New Rust code is in `wasm-rs/` directory
- Same call-home endpoint works with both
- JavaScript integration is similar but uses wasm-pack bindings

