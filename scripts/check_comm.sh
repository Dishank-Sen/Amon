#!/bin/bash
# Helper script to check what comm name the kernel will use for a binary
# Usage: ./check_comm.sh /path/to/binary

if [ $# -eq 0 ]; then
    echo "Usage: $0 <binary-path>"
    echo "Example: $0 /usr/local/bin/crash_with_errors"
    exit 1
fi

BINARY="$1"

if [ ! -f "$BINARY" ]; then
    echo "Error: Binary not found: $BINARY"
    exit 1
fi

if [ ! -x "$BINARY" ]; then
    echo "Error: Binary is not executable: $BINARY"
    exit 1
fi

echo "Checking comm name for: $BINARY"
echo ""

# Run the binary in background and quickly check its comm
"$BINARY" > /dev/null 2>&1 &
PID=$!
sleep 0.1

if [ -d "/proc/$PID" ]; then
    COMM=$(cat /proc/$PID/comm 2>/dev/null)
    kill $PID 2>/dev/null
    wait $PID 2>/dev/null

    echo "Process comm name: '$COMM'"
    echo "Length: ${#COMM} characters (max 15)"
    echo ""
    echo "Add this to config.yaml:"
    echo "  - $COMM"
else
    echo "Error: Process exited too quickly or failed to start"
    exit 1
fi
