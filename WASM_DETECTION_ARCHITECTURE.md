# WASM AI Detection Architecture with Call-Home Verification

## Overview

This architecture implements AI browser detection using WebAssembly (WASM) with an embedded secret and call-home verification to ensure the WASM module actually executed.

## Architecture Components

### 1. WebAssembly Module (AssemblyScript)
- **Location**: `wasm/ai-detection.ts` (source) → compiled to `public/wasm/ai-detection.wasm`
- **Contains**:
  - All detection algorithms
  - Embedded secret (compiled into binary)
  - Call-home proof generation function
  - Pattern matching logic
  - Fingerprinting calculations

### 2. JavaScript Glue Code
- **Location**: `public/js/services/AIDetectionService.js` (updated)
- **Responsibilities**:
  - Load WASM module
  - Collect browser API data
  - Pass data to WASM functions
  - Execute call-home verification
  - Handle detection results

### 3. Server Verification Endpoint
- **Location**: `server/core/app.py`
- **Endpoint**: `POST /ai-detection/verify`
- **Responsibilities**:
  - Verify call-home proof token
  - Validate embedded secret
  - Track WASM execution
  - Return verification status

## Call-Home Mechanism

### Secret Embedding
The secret is embedded at compile time in the WASM binary:

```typescript
// In WASM source
const EMBEDDED_SECRET = "your-secret-here"; // Compile-time constant
```

### Proof Generation
When WASM executes, it generates a proof token:

```typescript
function generateProof(sessionId: string, timestamp: number): string {
    // Combine secret + sessionId + timestamp
    const proofData = `${EMBEDDED_SECRET}:${sessionId}:${timestamp}`;
    // Generate hash (SHA-256 in WASM)
    return hash(proofData);
}
```

### Verification Flow

```
┌─────────────┐
│   Client    │
│   Browser   │
└──────┬──────┘
       │
       │ 1. Load WASM module
       ▼
┌─────────────────────┐
│  WASM Module        │
│  (ai-detection.wasm)│
│                     │
│  - Run detection    │
│  - Generate proof   │
│  - Return results   │
└──────┬──────────────┘
       │
       │ 2. Call detection + generate proof
       ▼
┌─────────────────────┐
│  JS Glue Code       │
│                     │
│  - Collect browser  │
│    properties       │
│  - Call WASM        │
│  - Get proof token  │
└──────┬──────────────┘
       │
       │ 3. POST /ai-detection/verify
       │    { sessionId, proof, timestamp, detectionResults }
       ▼
┌─────────────────────┐
│  Server             │
│  /ai-detection/     │
│  verify             │
│                     │
│  - Validate proof   │
│  - Check secret     │
│  - Verify timestamp │
│  - Track execution  │
└──────┬──────────────┘
       │
       │ 4. Return { verified: true/false }
       ▼
┌─────────────────────┐
│  Client             │
│                     │
│  - If verified: OK  │
│  - If not: Block    │
└─────────────────────┘
```

## Security Model

### What This Prevents

1. **Simple Bypass**: Can't just skip calling detection code
2. **Code Injection**: Harder to modify detection logic (binary format)
3. **Static Analysis**: Detection algorithms hidden in WASM binary
4. **Execution Skipping**: Call-home proves WASM actually ran

### What It Doesn't Prevent

1. **Advanced Reverse Engineering**: WASM can still be analyzed (just harder)
2. **Proxy/Man-in-the-Middle**: Could intercept call-home request
3. **WASM Module Replacement**: Could replace the WASM file
4. **Proof Token Replay**: Need timestamp/rate limiting on server

### Additional Hardening

1. **Time-based Verification**: Proof includes timestamp (prevent replay)
2. **Session Binding**: Proof bound to session ID
3. **Rate Limiting**: Limit verification attempts per session
4. **WASM Hash Verification**: Verify WASM file integrity (optional)
5. **Obfuscated JS**: Obfuscate glue code

## Implementation Details

### WASM Module Structure

```typescript
// wasm/ai-detection.ts

// Embedded secret (compiled into binary)
const EMBEDDED_SECRET: string = "AI_DETECT_SECRET_v1_<random>";

// Export functions
export function detectAI(browserData: BrowserData): DetectionResult {
    // Run all detection checks
    // Return detection results
}

export function generateProof(sessionId: string, timestamp: i64): string {
    // Generate proof using embedded secret
    const proofData = `${EMBEDDED_SECRET}:${sessionId}:${timestamp}`;
    return sha256(proofData);
}

export function getSecret(): string {
    // Never export this - just for internal use
    return EMBEDDED_SECRET;
}
```

### Server Endpoint

```python
@app.post("/ai-detection/verify")
async def verify_ai_detection(request: Request):
    """
    Verify that WASM module executed with correct secret.
    
    Request body:
    {
        "sessionId": "session-id",
        "proof": "proof-token-hash",
        "timestamp": 1234567890,
        "detectionResults": {...}
    }
    
    Response:
    {
        "verified": true/false,
        "message": "..."
    }
    """
    # 1. Verify proof token matches expected hash
    # 2. Check timestamp is recent (within 5 seconds)
    # 3. Verify session exists
    # 4. Track execution
    # 5. Return verification status
```

### JavaScript Integration

```javascript
// Load WASM module
const wasmModule = await loadWASM('/public/wasm/ai-detection.wasm');

// Collect browser data
const browserData = collectBrowserData();

// Call WASM detection
const detectionResult = wasmModule.detectAI(browserData);

// Generate proof
const timestamp = Date.now();
const sessionId = getSessionId();
const proof = wasmModule.generateProof(sessionId, timestamp);

// Call home to verify
const verified = await fetch('/ai-detection/verify', {
    method: 'POST',
    body: JSON.stringify({
        sessionId,
        proof,
        timestamp,
        detectionResults: detectionResult
    })
});

if (!verified.ok || !verified.verified) {
    blockApplication(['WASM verification failed']);
}

if (detectionResult.detected) {
    blockApplication(detectionResult.reasons);
}
```

## Build Process

### 1. Install AssemblyScript
```bash
npm install --save-dev assemblyscript
npx asinit .
```

### 2. Compile WASM
```bash
npm run asbuild
# Output: build/release.wasm
```

### 3. Embed Secret
- Secret can be:
  - Environment variable at build time
  - Configuration file (not in git)
  - Generated during build

### 4. Deploy
- WASM binary included in public assets
- Server endpoint deployed
- JS glue code updated

## Deployment Considerations

1. **Secret Management**: 
   - Use environment variable for secret
   - Different secret per environment (dev/prod)
   - Rotate secrets periodically

2. **WASM Versioning**:
   - Version WASM module (in filename or hash)
   - Support multiple versions during migration

3. **Fallback Strategy**:
   - If WASM fails to load, block application
   - If verification fails, block application
   - Log all failures for monitoring

4. **Performance**:
   - WASM loads once per session
   - Verification is async (don't block UI)
   - Cache verification result for session

## Monitoring

Track:
- WASM load failures
- Verification failures
- Detection results
- Execution times
- False positives/negatives

## Future Enhancements

1. **Multiple Secrets**: Rotate between multiple embedded secrets
2. **Server-Side Challenge**: Server sends challenge, WASM responds
3. **WASM Integrity**: Verify WASM file hasn't been tampered with
4. **Behavioral Analysis**: Track detection patterns over time
5. **Machine Learning**: Use ML to identify new automation patterns

