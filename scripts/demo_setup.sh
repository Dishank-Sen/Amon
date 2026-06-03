#!/bin/bash
# Demo setup script for Amon project submission
# Helps create impressive crash reports with real applications

set -e

echo "═══════════════════════════════════════════════════════════════"
echo "              AMON PROJECT DEMO SETUP"
echo "═══════════════════════════════════════════════════════════════"
echo ""

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Clean old reports
echo "🧹 Cleaning old crash reports..."
rm -f ~/.amon/crashes/*.txt
rm -f ~/.amon/crashes/*.jsonl
echo "✅ Old reports cleaned"
echo ""

# Check if Amon is built
if [ ! -f "$PROJECT_ROOT/bin/amon" ]; then
    echo "⚠️  Amon binary not found. Building..."
    cd "$PROJECT_ROOT"
    make build
    echo "✅ Build complete"
else
    echo "✅ Amon binary found"
fi
echo ""

# Setup config
echo "⚙️  Setting up config..."
mkdir -p ~/.amon

cat > ~/.amon/config.yaml << 'EOF'
tracked_commands:
  - nginx
  - python
  - node
  - test_connect
  - crash_test_1
  - crash_with_erro

ignored_commands:
  - systemd
  - dbus-daemon
  - git

events_threshold: 1000
EOF

echo "✅ Config created at ~/.amon/config.yaml"
echo ""

# Show available demo applications
echo "═══════════════════════════════════════════════════════════════"
echo "              DEMO APPLICATION OPTIONS"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "1. test_connect       - Network connection test (READY)"
echo "   • Tests 8-10 connect scenarios"
echo "   • ECONNREFUSED, ETIMEDOUT, EINPROGRESS"
echo "   • ~35 filtered events in report"
echo ""
echo "2. crash_test_1       - Simple file + crash (READY)"
echo "   • Opens 2 files then crashes"
echo "   • Minimal but clean report"
echo ""
echo "3. crash_with_errors  - File operations with errors (READY)"
echo "   • 100 successful + 5 failed operations"
echo "   • Demonstrates signal vs noise filtering"
echo ""
echo "4. nginx              - Real web server (if installed)"
echo "   • Most impressive for demo"
echo "   • Need to trigger crash manually"
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Check what's available
echo "📋 Checking available test programs..."
echo ""

if [ -f "$PROJECT_ROOT/tests/C/test_connect" ]; then
    echo "✅ test_connect available"
else
    echo "⚠️  test_connect not compiled"
fi

if [ -f "$PROJECT_ROOT/tests/C/crash_test_1" ]; then
    echo "✅ crash_test_1 available"
else
    echo "⚠️  crash_test_1 not found"
fi

if [ -f "$PROJECT_ROOT/tests/C/crash_with_errors" ]; then
    echo "✅ crash_with_errors available"
else
    echo "⚠️  crash_with_errors not compiled"
fi

if command -v nginx &> /dev/null; then
    echo "✅ nginx installed"
else
    echo "⚠️  nginx not installed (sudo apt install nginx)"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "              RECOMMENDED DEMO FLOW"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Terminal 1 (this one):"
echo "  $ sudo $PROJECT_ROOT/bin/amon"
echo ""
echo "Terminal 2:"
echo "  $ $PROJECT_ROOT/tests/C/test_connect"
echo ""
echo "Then check report:"
echo "  $ ls -lh ~/.amon/crashes/"
echo "  $ cat ~/.amon/crashes/test_connect_*.txt"
echo ""
echo "Expected impressive features in report:"
echo "  ✅ Network connection tracking"
echo "  ✅ Error detection (ECONNREFUSED, ETIMEDOUT)"
echo "  ✅ EINPROGRESS handled correctly (not error)"
echo "  ✅ Slow operation detection (>100ms)"
echo "  ✅ Signal vs noise filtering (1500 → 35 events)"
echo "  ✅ IP addresses and ports captured"
echo "  ✅ Latency measurements"
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo ""

read -p "Start Amon now? (y/n) " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "🚀 Starting Amon..."
    echo ""
    cd "$PROJECT_ROOT"
    sudo bin/amon
fi
