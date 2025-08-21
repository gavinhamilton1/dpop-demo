#!/bin/bash

# Test runner script for Device Identity & DPoP Security Reference Implementation

echo "🧪 Running Device Identity & DPoP Security Tests"
echo "=================================================="

# Check if we're in the right directory
if [ ! -f "package.json" ] || [ ! -f "requirements.txt" ]; then
    echo "❌ Error: Please run this script from the project root directory"
    exit 1
fi

# Function to run client tests
run_client_tests() {
    echo ""
    echo "🔧 Running Client-Side Tests (Jest)"
    echo "-----------------------------------"
    
    if command -v npm &> /dev/null; then
        npm test
        CLIENT_EXIT_CODE=$?
    else
        echo "❌ npm not found. Please install Node.js and npm"
        CLIENT_EXIT_CODE=1
    fi
}

# Function to run server tests
run_server_tests() {
    echo ""
    echo "🐍 Running Server-Side Tests (pytest)"
    echo "-------------------------------------"
    
    if command -v pytest &> /dev/null; then
        pytest test_server.py -v
        SERVER_EXIT_CODE=$?
    else
        echo "❌ pytest not found. Installing dependencies..."
        pip install pytest pytest-asyncio httpx
        pytest test_server.py -v
        SERVER_EXIT_CODE=$?
    fi
}

# Function to run all tests with coverage
run_coverage_tests() {
    echo ""
    echo "📊 Running Tests with Coverage"
    echo "------------------------------"
    
    if command -v pytest &> /dev/null; then
        pip install pytest-cov
        pytest test_server.py --cov=server --cov-report=html --cov-report=term -v
        COVERAGE_EXIT_CODE=$?
    else
        echo "❌ pytest not found. Please install pytest first"
        COVERAGE_EXIT_CODE=1
    fi
}

# Parse command line arguments
case "${1:-all}" in
    "client")
        run_client_tests
        exit $CLIENT_EXIT_CODE
        ;;
    "server")
        run_server_tests
        exit $SERVER_EXIT_CODE
        ;;
    "coverage")
        run_coverage_tests
        exit $COVERAGE_EXIT_CODE
        ;;
    "all")
        run_client_tests
        run_server_tests
        
        echo ""
        echo "📋 Test Summary"
        echo "==============="
        
        if [ $CLIENT_EXIT_CODE -eq 0 ]; then
            echo "✅ Client tests passed"
        else
            echo "❌ Client tests failed"
        fi
        
        if [ $SERVER_EXIT_CODE -eq 0 ]; then
            echo "✅ Server tests passed"
        else
            echo "❌ Server tests failed"
        fi
        
        if [ $CLIENT_EXIT_CODE -eq 0 ] && [ $SERVER_EXIT_CODE -eq 0 ]; then
            echo ""
            echo "🎉 All tests passed!"
            exit 0
        else
            echo ""
            echo "💥 Some tests failed. Check the output above for details."
            exit 1
        fi
        ;;
    *)
        echo "Usage: $0 [client|server|coverage|all]"
        echo ""
        echo "Options:"
        echo "  client    - Run only client-side tests (Jest)"
        echo "  server    - Run only server-side tests (pytest)"
        echo "  coverage  - Run server tests with coverage report"
        echo "  all       - Run all tests (default)"
        exit 1
        ;;
esac
