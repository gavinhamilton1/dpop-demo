#!/bin/bash
# Build script for Rust WASM module with secret embedding

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔐 Rust WASM AI Detection Build Script${NC}"
echo "=============================================="

# Check if wasm-pack is installed
if ! command -v wasm-pack &> /dev/null; then
    echo -e "${RED}✗ wasm-pack not found${NC}"
    echo "Install it with: curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh"
    exit 1
fi

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo -e "${RED}✗ Rust/Cargo not found${NC}"
    echo "Install Rust from: https://rustup.rs/"
    exit 1
fi

# Get secret from environment or prompt
if [ -z "$AI_DETECTION_SECRET" ]; then
    if [ -f ".secret" ]; then
        echo -e "${BLUE}📄 Reading secret from .secret file...${NC}"
        export AI_DETECTION_SECRET=$(cat .secret | tr -d '\n\r')
    else
        echo -e "${YELLOW}⚠️  No AI_DETECTION_SECRET environment variable or .secret file found${NC}"
        echo "Generating a new secret..."
        export AI_DETECTION_SECRET="AI_DETECT_SECRET_v1_$(openssl rand -hex 16)"
        echo "$AI_DETECTION_SECRET" > .secret
        echo -e "${GREEN}✓ Secret saved to .secret file${NC}"
    fi
fi

echo -e "${GREEN}✓ Using secret: ${AI_DETECTION_SECRET:0:30}...${NC}"

# Build with wasm-pack
echo -e "${BLUE}🔨 Building WASM module with wasm-pack...${NC}"

# Build for web target (outputs to pkg/)
# Pass the secret as an environment variable that Rust can access via env!
AI_DETECTION_SECRET="$AI_DETECTION_SECRET" wasm-pack build --target web --release --out-dir pkg

if [ $? -ne 0 ]; then
    echo -e "${RED}✗ WASM build failed${NC}"
    exit 1
fi

# Copy to public directory
echo -e "${BLUE}📦 Copying WASM files to public directory...${NC}"
mkdir -p ../public/wasm
cp pkg/ai_detection_wasm_bg.wasm ../public/wasm/ai-detection.wasm
cp pkg/ai_detection_wasm.js ../public/wasm/ai-detection.js
cp pkg/ai_detection_wasm.d.ts ../public/wasm/ai-detection.d.ts

echo -e "${GREEN}✓ WASM build successful!${NC}"
echo ""
echo -e "${BLUE}📋 Next steps:${NC}"
echo "1. Set server environment variable:"
echo "   ${GREEN}export AI_DETECTION_SECRET=\"$AI_DETECTION_SECRET\"${NC}"
echo ""
echo "2. Verify WASM files:"
echo "   ${GREEN}ls -lh ../public/wasm/ai-detection.*${NC}"
echo ""
echo "3. Update JavaScript to load WASM module"
echo ""
echo -e "${GREEN}✓ Build complete!${NC}"

