#!/bin/bash

# Deployment script for Render.com
echo "🚀 Deploying DPoP Demo to Render..."

# Check if we're in the right directory
if [ ! -f "requirements.txt" ]; then
    echo "❌ Error: requirements.txt not found. Are you in the project root?"
    exit 1
fi

# Build Docker image locally (optional, for testing)
if [ "$1" = "--local-test" ]; then
    echo "🔨 Building Docker image locally..."
    docker build -t dpop-demo .
    echo "✅ Docker image built successfully"
    echo "🧪 To test locally: docker run -p 8000:10000 dpop-demo"
fi

echo "📋 Deployment checklist:"
echo "✅ Dockerfile created"
echo "✅ render.yaml configured"
echo "✅ Production config created"
echo "✅ Requirements.txt updated"

echo ""
echo "🎯 Next steps for Render deployment:"
echo "1. Push this code to your Git repository"
echo "2. Connect your repo to Render"
echo "3. Render will automatically build and deploy using the Dockerfile"
echo "4. Update the external_origin in stronghold.prod.yaml with your actual Render URL"

echo ""
echo "🔧 Render service configuration:"
echo "- Type: Web Service"
echo "- Environment: Docker"
echo "- Plan: Standard (your paid tier)"
echo "- Build Command: (auto-detected from Dockerfile)"
echo "- Start Command: (auto-detected from Dockerfile)"

echo ""
echo "📊 Expected performance:"
echo "- Model download: ~2-3 minutes on first build"
echo "- Cold start: ~30-60 seconds"
echo "- Warm requests: <1 second"
echo "- Memory usage: ~500MB-1GB"

echo ""
echo "🎉 Ready for deployment!"
