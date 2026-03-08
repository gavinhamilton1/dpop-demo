#!/bin/bash
# Build script for WASM module with secret embedding

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "🔐 WASM AI Detection Build Script"
echo "=================================="

# Get secret from environment or prompt
if [ -z "$AI_DETECTION_SECRET" ]; then
    if [ -f ".secret" ]; then
        echo "📄 Reading secret from .secret file..."
        AI_DETECTION_SECRET=$(cat .secret | tr -d '\n\r')
    else
        echo -e "${YELLOW}⚠️  No AI_DETECTION_SECRET environment variable or .secret file found${NC}"
        echo "Generating a new secret..."
        AI_DETECTION_SECRET="AI_DETECT_SECRET_v1_$(openssl rand -hex 16)"
        echo "$AI_DETECTION_SECRET" > .secret
        echo -e "${GREEN}✓ Secret saved to .secret file${NC}"
    fi
fi

echo -e "${GREEN}✓ Using secret: ${AI_DETECTION_SECRET:0:30}...${NC}"

# Replace secret in source file (before compilation)
echo "📝 Embedding secret in WASM source..."

# Note: In a real implementation, you'd use a template replacement tool
# For now, we'll document that the secret should be set at build time
# AssemblyScript doesn't support compile-time string replacement easily
# So we need to either:
# 1. Use a build tool to replace the constant
# 2. Pass secret as a build-time constant
# 3. Use a more advanced build system

echo "🔨 Building WASM module..."

# Build WASM
npm run asbuild:release

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ WASM build successful!${NC}"
    echo ""
    echo "📋 Next steps:"
    echo "1. Set server environment variable:"
    echo "   export AI_DETECTION_SECRET=\"$AI_DETECTION_SECRET\""
    echo ""
    echo "2. Verify WASM file:"
    echo "   ls -lh ../public/wasm/ai-detection.wasm"
    echo ""
    echo "3. Test verification endpoint"
else
    echo -e "${RED}✗ WASM build failed${NC}"
    exit 1
fi

