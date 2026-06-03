# Amon - eBPF Crash Forensics Tool

Amon is an eBPF-based crash forensics tool that automatically captures **stack traces**, **fault addresses**, and **syscall context** when processes crash, providing root cause analysis with zero configuration.

## Key Features

### 🔍 Crash Forensics
- **User-Space Stack Traces**: Captures complete call stack at crash time with symbol resolution
- **Fault Address Capture**: Pinpoints exact memory address that caused SIGSEGV/SIGBUS
- **Root Cause Analysis**: Automatic detection of NULL pointer dereference, use-after-free, stack overflow, heap corruption
- **Memory Classification**: Determines if crash occurred in heap, stack, library, or unmapped memory
- **Smart Recommendations**: Actionable debugging advice based on crash pattern

### 📊 Event Intelligence
- **Priority Storage**: Captures errors, slow operations (>100ms), and relevant context
- **Noise Filtering**: Removes benign startup probes (pyvenv.cfg, ._pth, etc.)
- **Network Tracking**: connect() calls with IP, port, and status (SUCCESS, ECONNREFUSED, ETIMEDOUT)
- **Relative Timestamps**: Events shown as offset from process start (+0.5s, +104ms)

### 📄 Dual Format Reports
- **Human-readable TXT**: Crash analysis first, then stack trace and timeline
- **Machine-queryable JSONL**: For automated processing

## Why Use Amon?

**Typical crash debugging workflow:**
```
1. Program crashes in production
2. Add logging, redeploy, wait for crash
3. Still don't know exact location
4. Add more logging, redeploy again...
⏱️  Time: Hours to days
```

**With Amon:**
```
1. Program crashes
2. Check Amon report
3. See exact function, call chain, and fault address
4. Fix the bug
⏱️  Time: Seconds to minutes
```

**What Amon tells you instantly:**
- ✅ **WHERE:** Which function crashed (`crash_function+0x31`)
- ✅ **HOW:** Complete call chain (main → level_1 → ... → crash)
- ✅ **WHAT:** Memory address accessed (0x0 = NULL pointer)
- ✅ **WHY:** Root cause (NULL dereference, use-after-free, etc.)
- ✅ **FIX:** Actionable recommendations

## Installation

### Prerequisites

- **Linux kernel >= 5.10** (with eBPF support)
- **clang** - For compiling eBPF programs
- **libbpf-dev** - BPF library headers
- **golang >= 1.18** - For building the application

```bash
# Check kernel version
uname -r

# Install dependencies (Ubuntu/Debian)
sudo apt update
sudo apt install clang libbpf-dev golang-go make

# Install dependencies (Fedora/RHEL)
sudo dnf install clang libbpf-devel golang make
```

### Clone and Build

```bash
# Clone repository
git clone https://github.com/Dishank-Sen/Amon.git
cd Amon

# Compile eBPF programs
make gen

# Build Go binary
make build
```

The compiled binary will be at `bin/amon`.

### Configuration

Create configuration file at `~/.amon/config.yaml`:

```bash
mkdir -p ~/.amon
cat > ~/.amon/config.yaml << 'EOF'
tracked_commands:
  - nginx
  - python3
  - your_program    # Add programs to monitor
  # Note: Linux kernel truncates process names to 15 chars

ignored_commands:
  - systemd         # Processes to ignore
  - dbus-daemon

events_threshold: 1000  # Circular buffer size
EOF
```

**Important:** Linux truncates process names to 15 characters. If your program is named `my_long_program_name`, use `my_long_progra` in the config.

## Usage

### Basic Usage

```bash
# Terminal 1: Start Amon (requires root for eBPF)
sudo ./bin/amon

# Terminal 2: Run your application
./your_program

# When it crashes, check the report
cat ~/.amon/crashes/*.txt
```

### Testing with Examples

```bash
# Test 1: C program with full stack trace (RECOMMENDED)
./tests/C/stack_trace_test

# Test 2: Network + crash test
./tests/C/test_connect

# Test 3: Python example (shows interpreter limitations)
python3 tests/python/network_crash_test.py

# View latest crash report
cat ~/.amon/crashes/stack_trace_te_*.txt
```

### Stopping Amon

Press `Ctrl+C` in the terminal running Amon, or:

```bash
sudo pkill amon
```

## Report Example

```
═══════════════════════════════════════════════════════════════════
                    AMON CRASH REPORT
                    Forensic Analysis
═══════════════════════════════════════════════════════════════════

CRASH ANALYSIS
───────────────────────────────────────────────────────────────────
  Signal:         SIGSEGV (11)
  Fault Address:  0x0 (NULL)
  Memory Type:    null

  Likely Cause:
    NULL pointer dereference

  Recommendation:
    Check for uninitialized pointers or missing null checks

STACK TRACE (at crash time)
───────────────────────────────────────────────────────────────────
  #0  crash_function+0x31
      stack_trace_test
  #1  level_3+0x22
      stack_trace_test
  #2  level_2+0x22
      stack_trace_test
  #3  level_1+0x22
      stack_trace_test
  #4  main+0x71
      stack_trace_test

PROCESS INFORMATION
───────────────────────────────────────────────────────────────────
  Process:        stack_trace_te
  PID:            12345
  Lifetime:       0.8 seconds
  Crash Time:     2026-06-04T01:45:00+05:30

EVENT STATISTICS
───────────────────────────────────────────────────────────────────
  Total Events:   15
  Errors:         0
  Slow Ops:       0 (>100ms)
  Shown Below:    8 (errors + slow + context)

DETAILED EVENTS (chronological, filtered for relevance)
═══════════════════════════════════════════════════════════════════

[   1]     OPENAT
       Time:      +0 ms
       File:      /etc/ld.so.cache
       Return:    3

[   2]     OPENAT
       Time:      +5 ms
       File:      /lib/x86_64-linux-gnu/libc.so.6
       Return:    3

... (more events)
```

## Testing

### Recommended: C Native Stack Trace
```bash
./tests/C/stack_trace_test
```
**Shows:** Complete call chain with all function names (best demonstration)

### Network + Crash Test
```bash
./tests/C/test_connect
```
**Shows:** Network connections + crash analysis

### Python (Interpreter Limitation)
```bash
python3 tests/python/network_crash_test.py
```
**Shows:** Network activity + crash (stack shows interpreter internals only)

**Note:** Python stack traces show interpreter/C-extension stack, not Python functions (inherent limitation of interpreted languages). Use C tests to see full native stack traces.

## Architecture

```
┌────────────────────────────────────────────────┐
│           eBPF Programs (Kernel)               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐      │
│  │ kprobe   │  │tracepoint│  │tracepoint│      │
│  │force_sig │  │signal_   │  │sys_enter │      │
│  │_fault    │  │deliver   │  │_openat   │      │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘      │
│       │ fault       │ stack       │ events     │
│       │ address     │ trace       │            │
│       └─────────────┴─────────────┘            │
│                     │                          │
│            ┌────────▼────────┐                 │
│            │  Ring Buffer +  │                 │
│            │   Stack Map     │                 │
│            └────────┬────────┘                 │
└─────────────────────┼──────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────┐
│        Userspace (Go Application)              │
│  ┌──────────────┐       ┌──────────────┐       │
│  │ Event Parser │─────▶│   Circular   │       │
│  │ Symbol       │       │   Buffers    │       │
│  │ Resolver     │       │ (per-process)│       │
│  └──────────────┘       └───────┬──────┘       │
│                                 │              │
│                         ┌───────▼──────┐       │
│                         │   Crash      │       │
│                         │  Detection   │       │
│                         └───────┬──────┘       │
│                                 │              │
│                     ┌───────────▼───────────┐  │
│                     │   Report Generation   │  │
│                     │  • Stack trace        │  │
│                     │  • Root cause         │  │
│                     │  • Timeline           │  │
│                     └───────────────────────┘  │
└────────────────────────────────────────────────┘
```

## How It Works

### 1. Signal Generation (Kprobe)
When a crash occurs, kernel calls `force_sig_fault()`:
- **Captures:** Fault address (e.g., 0x0 for NULL)
- **Stores:** In temporary map for later retrieval

### 2. Signal Delivery (Tracepoint)
When signal is delivered to process:
- **Captures:** User-space stack trace via `bpf_get_stackid()`
- **Retrieves:** Fault address from temporary map
- **Emits:** Combined event with both pieces

### 3. Symbol Resolution (Userspace)
- Parse `/proc/pid/maps` to find which binary each address belongs to
- Read ELF symbol tables
- Match instruction pointers to function names
- Build human-readable stack trace

### 4. Report Generation
- Analyze crash pattern (NULL deref, use-after-free, etc.)
- Display stack trace showing call chain
- Show syscall timeline with relative timestamps
- Provide recommendations

## Key Design Decisions

### Two-Stage Capture
- **Kprobe at fault generation:** Captures fault address (only available here)
- **Tracepoint at signal delivery:** Captures stack trace (stack still intact)
- **Bridge via map:** Combines both into one coherent report

### Symbol Resolution
- Handles ASLR (Address Space Layout Randomization)
- Calculates correct ELF file offsets
- Filters for function symbols only
- Caches results for performance

### Language Support
| Language | Stack Trace | Notes |
|----------|-------------|-------|
| C/C++ | ✅ Perfect | Native code, full symbols |
| Rust | ✅ Perfect | Native code, full symbols |
| Go | ✅ Perfect | Native code (symbols may look unusual) |
| Python | ⚠️ Limited | Shows interpreter + C extensions only |

### Noise Filtering
- Startup probes: pyvenv.cfg, ._pth, __pycache__
- Only filters ENOENT errors from known patterns
- Report shows filtered count

### Relative Timestamps
- Events shown as offset from process start
- Format: +0ms, +510ms, +1.2s
- Makes timeline immediately readable

## Output Locations

```
~/.amon/
├── crashes/
│   ├── stack_trace_te_12345_2026-06-04T01:45:00.txt
│   ├── stack_trace_te_12345_2026-06-04T01:45:00.jsonl
│   └── ...
├── amon.log       # Operational logs
└── config.yaml    # Configuration
```

## Performance

- **Normal operation:** Zero overhead (hooks only fire on crashes)
- **Stack capture:** ~1-2 microseconds
- **Symbol resolution:** ~10 milliseconds (after crash)
- **Memory:** 160 KB for stack map + circular buffers

## Troubleshooting

### "Permission denied" when starting Amon
Amon requires root privileges to load eBPF programs:
```bash
sudo ./bin/amon  # Use sudo
```

### "No crash report generated"
**Check 1:** Is the process name in `tracked_commands`?
```bash
cat ~/.amon/config.yaml  # Verify configuration
```

**Check 2:** Linux truncates process names to 15 characters.
```bash
# If your program is "stack_trace_test", use:
tracked_commands:
  - stack_trace_te  # Only 15 chars allowed
```

**Check 3:** Is Amon running?
```bash
ps aux | grep amon
```

### Python/interpreted languages don't show function names
**This is expected.** Python is interpreted - the native stack only shows:
- Python interpreter internals
- C extensions (ctypes, numpy, etc.)
- System libraries

For full function-level stack traces, use compiled languages (C/C++/Rust/Go).

See "Language Support" section for details.

### Stack trace shows only addresses (0x1234...)
**Cause:** Binary is stripped of symbols.

**Solution:** Compile with debug symbols:
```bash
gcc -g program.c -o program  # Add -g flag
```

Most system libraries already have symbols, so this mainly affects your own programs.

### "Failed to load eBPF: permission denied"
**Cause:** Kernel lockdown or missing privileges.

**Solutions:**
1. Run with sudo: `sudo ./bin/amon`
2. Check kernel lockdown: `cat /sys/kernel/security/lockdown`
3. If "integrity" mode, may need to disable secure boot

### Build errors: "clang: not found"
Install missing dependencies:
```bash
# Ubuntu/Debian
sudo apt install clang libbpf-dev golang-go

# Fedora/RHEL
sudo dnf install clang libbpf-devel golang
```

### Report location issues
Reports are saved to the home directory of the user running Amon:
- If run with `sudo`, reports go to `/root/.amon/crashes/`
- For user reports, check `~/.amon/crashes/` or `/home/USERNAME/.amon/crashes/`

## Comparison to Other Tools

| Tool | Auto-capture | Stack trace | Fault addr | Syscalls | Root cause | Zero config |
|------|-------------|-------------|------------|----------|------------|-------------|
| **Amon** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| gdb/coredump | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ |
| strace | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |
| bpftrace | ❌ | ⚠️ | ⚠️ | ✅ | ❌ | ❌ |
| perf | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |

## What You Get

Amon answers the critical debugging questions:

1. **WHERE did it crash?** → Stack trace shows exact function
2. **WHAT memory was accessed?** → Fault address (0x0, 0xdeadbeef, etc.)
3. **WHY did it crash?** → Root cause analysis (NULL deref, use-after-free)
4. **HOW did execution get there?** → Complete call chain
5. **WHAT was it doing?** → Syscall timeline before crash

**Time to debug: Seconds instead of hours.**

## License

MIT License

---