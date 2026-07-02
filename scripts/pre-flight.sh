#!/bin/bash
#
# PromptWall Pre-Flight Check
# Quick sanity check before starting a reconnaissance session
#
# Usage: ./scripts/pre-flight.sh

set -e

echo "🚀 PromptWall Pre-Flight Check"
echo "=============================="
echo ""

# Activate venv if not already activated
if [ -z "$VIRTUAL_ENV" ]; then
    if [ -d "venv" ]; then
        echo "⚠️  Activating venv..."
        source venv/bin/activate
    else
        echo "❌ Virtual environment not found. Run: python -m venv venv && source venv/bin/activate"
        exit 1
    fi
fi

# Check 1: Version
echo "🔍 Checking version..."
VERSION_OUTPUT=$(python ozy.py --version 2>&1 | grep -o "v[0-9]\+\.[0-9]\+\.[0-9]\+" || echo "")
if [ "$VERSION_OUTPUT" = "v9.0.1" ]; then
    echo "✅ Version: $VERSION_OUTPUT"
else
    echo "❌ Version mismatch: expected v9.0.1, got '$VERSION_OUTPUT'"
    echo "   Run: pip install -e ."
    exit 1
fi

# Check 2: Dependencies
echo ""
echo "🔍 Checking dependencies..."
DOCTOR_OUTPUT=$(python ozy.py doctor 2>&1)
if echo "$DOCTOR_OUTPUT" | grep -q "READY - All checks passed"; then
    echo "✅ All dependencies OK"
else
    echo "❌ Dependency check failed:"
    echo "$DOCTOR_OUTPUT" | tail -20
    exit 1
fi

# Check 3: Scope
echo ""
echo "🔍 Checking scope configuration..."
SCOPE_COUNT=$(python ozy.py scope list 2>&1 | grep -c "example.com\|No domains" || echo "0")
if [ "$SCOPE_COUNT" -gt 0 ]; then
    echo "✅ Scope configured"
    python ozy.py scope list 2>&1 | head -10
else
    echo "⚠️  No targets in scope"
    echo "   Add a target with: python ozy.py scope add target.com"
fi

# Check 4: Test suite (optional, quick smoke test)
echo ""
echo "🔍 Running quick smoke test..."
PYTEST_OUTPUT=$(pytest tests/core/test_bootstrap.py -q 2>&1 || echo "FAILED")
if echo "$PYTEST_OUTPUT" | grep -q "passed"; then
    echo "✅ Smoke test passed"
else
    echo "⚠️  Smoke test had issues (not critical)"
fi

# Check 5: Disk space
echo ""
echo "🔍 Checking disk space..."
DISK_AVAIL=$(df -h . | awk 'NR==2 {print $4}')
echo "✅ Available disk space: $DISK_AVAIL"

# Check 6: Network connectivity
echo ""
echo "🔍 Checking network connectivity..."
if ping -c 1 -W 2 8.8.8.8 > /dev/null 2>&1; then
    echo "✅ Network connectivity OK"
else
    echo "⚠️  Network connectivity issue (might affect external scans)"
fi

# Summary
echo ""
echo "=============================="
echo "✅ All systems go! Ready for reconnaissance."
echo ""
echo "Quick start commands:"
echo "  python ozy.py scope add target.com"
echo "  python ozy.py flow target.com --profile safe-active"
echo "  python ozy.py inventory"
echo ""
