# WASM AI Detection Build Instructions

## Overview

This guide explains how to build the AI detection WASM module with embedded secret and call-home verification.

## Prerequisites

```bash
npm install -g assemblyscript
cd wasm
npm install
```

## Build Process

### 1. Set the Secret

The secret is embedded at build time. You can set it via:

**Option A: Environment Variable**
```bash
export AI_DETECTION_SECRET="AI_DETECT_SECRET_v1_$(openssl rand -hex 16)"
npm run asbuild
```

**Option B: Build Script**
```bash
# Build script will prompt for secret or use env var
./build-with-secret.sh
```

**Option C: Configuration File** (not in git)
```bash
# Create wasm/.secret file (gitignored)
echo "AI_DETECT_SECRET_v1_<your-secret>" > wasm/.secret
npm run asbuild
```

### 2. Build WASM Module

```bash
cd wasm
npm run asbuild:release
```

This produces:
- `../public/wasm/ai-detection.wasm` - Compiled binary
- `../public/wasm/ai-detection.wat` - Text format (for debugging)

### 3. Set Server Secret

The server needs the same secret to verify proofs:

```bash
# Development
export AI_DETECTION_SECRET="AI_DETECT_SECRET_v1_<same-secret>"

# Production (in render.yaml or deployment config)
# Set environment variable: AI_DETECTION_SECRET
```

### 4. Verify Build

```bash
# Check WASM file exists
ls -lh public/wasm/ai-detection.wasm

# Verify it's valid WASM
wasm-validate public/wasm/ai-detection.wasm
```

## Secret Management

### Security Best Practices

1. **Never commit secrets to git**
   - Add `wasm/.secret` to `.gitignore`
   - Use environment variables or secrets manager

2. **Use different secrets per environment**
   - Development: `AI_DETECT_SECRET_v1_dev_<random>`
   - Production: `AI_DETECT_SECRET_v1_prod_<random>`

3. **Rotate secrets periodically**
   - Update WASM binary with new secret
   - Update server environment variable
   - Deploy both simultaneously

4. **Keep secrets synchronized**
   - WASM secret must match server secret
   - Use same secret source for both builds

## Deployment Checklist

- [ ] Secret set in build environment
- [ ] WASM module compiled successfully
- [ ] WASM file deployed to `public/wasm/`
- [ ] Server `AI_DETECTION_SECRET` environment variable set
- [ ] Secrets match between WASM and server
- [ ] Test call-home verification works
- [ ] Monitor verification failures in logs

## Troubleshooting

### Build fails
- Check AssemblyScript is installed: `npx asc --version`
- Verify TypeScript syntax is valid
- Check for missing dependencies

### Verification fails
- Ensure WASM secret matches server secret
- Check timestamp is recent (within 10 seconds)
- Verify session ID is valid
- Check server logs for error details

### WASM won't load
- Verify WASM file is served correctly
- Check browser console for errors
- Ensure WASM module exports match JS expectations
- Verify CORS headers allow WASM loading

