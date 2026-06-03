#!/bin/bash
# Automated test runner for connect event tracking

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  AMON CONNECT EVENT TEST"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check if test binary exists
if [ ! -f "$SCRIPT_DIR/test_connect" ]; then
    echo "❌ test_connect binary not found"
    echo "   Compiling..."
    gcc -o "$SCRIPT_DIR/test_connect" "$SCRIPT_DIR/test_connect.c"
    echo "✅ Compiled successfully"
    echo ""
fi

# Check if test_connect is in config
if ! grep -q "test_connect" ~/.amon/config.yaml 2>/dev/null; then
    echo "⚠️  test_connect not in config.yaml"
    echo "   Adding it now..."

    if [ ! -f ~/.amon/config.yaml ]; then
        echo "❌ Config file not found: ~/.amon/config.yaml"
        exit 1
    fi

    # Add to tracked_commands section
    sed -i '/^tracked_commands:/a\  - test_connect' ~/.amon/config.yaml
    echo "✅ Added to config"
    echo ""
fi

# Check if Amon is running
if ! pgrep -f "bin/amon" > /dev/null; then
    echo "⚠️  Amon is not running"
    echo "   Starting Amon..."

    cd "$PROJECT_ROOT"
    sudo bin/amon &
    sleep 2

    if pgrep -f "bin/amon" > /dev/null; then
        echo "✅ Amon started"
    else
        echo "❌ Failed to start Amon"
        exit 1
    fi
    echo ""
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  RUNNING TEST"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Clean up old reports
rm -f ~/.amon/crashes/test_connect_*.txt
rm -f ~/.amon/crashes/test_connect_*.jsonl

# Run the test
"$SCRIPT_DIR/test_connect"

# Wait a moment for report to be written
sleep 1

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  VERIFICATION"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Find the report
REPORT=$(ls -t ~/.amon/crashes/test_connect_*.txt 2>/dev/null | head -1)

if [ -z "$REPORT" ]; then
    echo "❌ FAILED: No crash report generated"
    echo ""
    echo "Troubleshooting:"
    echo "  1. Check if Amon is running: ps aux | grep amon"
    echo "  2. Check logs: tail -50 ~/.amon/amon.log"
    echo "  3. Check config: cat ~/.amon/config.yaml"
    exit 1
fi

echo "✅ Crash report generated: $(basename "$REPORT")"
echo ""

# Verification checks
PASS=0
FAIL=0

# Check 1: Connect events captured
CONNECT_COUNT=$(grep -c "CONNECT" "$REPORT" || true)
if [ "$CONNECT_COUNT" -ge 8 ]; then
    echo "✅ Connect events captured: $CONNECT_COUNT (expected: 8-10)"
    ((PASS++))
else
    echo "❌ Connect events: $CONNECT_COUNT (expected: 8-10)"
    ((FAIL++))
fi

# Check 2: Error count
ERROR_COUNT=$(grep "Errors:" "$REPORT" | awk '{print $2}')
if [ "$ERROR_COUNT" -eq 6 ]; then
    echo "✅ Error count: $ERROR_COUNT (expected: 6)"
    ((PASS++))
else
    echo "❌ Error count: $ERROR_COUNT (expected: 6)"
    ((FAIL++))
fi

# Check 3: Slow ops count
SLOW_COUNT=$(grep "Slow Ops:" "$REPORT" | awk '{print $3}')
if [ "$SLOW_COUNT" -eq 1 ]; then
    echo "✅ Slow ops count: $SLOW_COUNT (expected: 1)"
    ((PASS++))
else
    echo "❌ Slow ops count: $SLOW_COUNT (expected: 1)"
    ((FAIL++))
fi

# Check 4: EINPROGRESS handled correctly (should NOT have error marker)
if grep -q "async (EINPROGRESS)" "$REPORT"; then
    # Check if it has error marker (should not)
    if grep "async (EINPROGRESS)" "$REPORT" | grep -q "❌"; then
        echo "❌ EINPROGRESS incorrectly marked as error"
        ((FAIL++))
    else
        echo "✅ EINPROGRESS handled correctly (not marked as error)"
        ((PASS++))
    fi
else
    echo "⚠️  EINPROGRESS event not found (non-blocking may have succeeded immediately)"
    ((PASS++))
fi

# Check 5: IP addresses present
if grep -q "8.8.8.8" "$REPORT" && grep -q "127.0.0.1" "$REPORT"; then
    echo "✅ IP addresses captured correctly"
    ((PASS++))
else
    echo "❌ IP addresses missing or incorrect"
    ((FAIL++))
fi

# Check 6: Error markers present
ERROR_MARKERS=$(grep -c "❌  CONNECT" "$REPORT" || true)
if [ "$ERROR_MARKERS" -ge 5 ]; then
    echo "✅ Error markers present: $ERROR_MARKERS"
    ((PASS++))
else
    echo "❌ Error markers: $ERROR_MARKERS (expected: ~6)"
    ((FAIL++))
fi

# Check 7: Slow marker present
if grep -q "⚠ SLOW" "$REPORT"; then
    echo "✅ Slow operation marker present"
    ((PASS++))
else
    echo "❌ Slow operation marker missing"
    ((FAIL++))
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  RESULTS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Passed: $PASS"
echo "Failed: $FAIL"
echo ""

if [ "$FAIL" -eq 0 ]; then
    echo "🎉 ALL TESTS PASSED!"
    echo ""
    echo "Report location: $REPORT"
    exit 0
else
    echo "❌ SOME TESTS FAILED"
    echo ""
    echo "Report location: $REPORT"
    echo "Log file: ~/.amon/amon.log"
    exit 1
fi
