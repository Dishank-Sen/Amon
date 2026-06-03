# Amon - eBPF Crash Analysis Tool

Amon is an eBPF-based crash detection and analysis tool that captures syscall activity leading up to process crashes, helping developers debug production failures by preserving the context that caused the crash.

## Features

- **Intelligent Event Filtering**: Captures errors and slow operations, filters out noise (50,000 successful operations → 35 meaningful events)
- **Crash Detection**: Detects fatal signals (SIGSEGV, SIGABRT, SIGBUS, SIGILL, SIGFPE)
- **Multiple Event Types**: Tracks file operations (openat), network connections (connect), and process lifecycle
- **Smart Error Handling**: Distinguishes real errors from async operations (EINPROGRESS)
- **Dual Report Format**: Human-readable TXT and machine-queryable JSONL
- **Circular Buffers**: Per-process buffers keep recent history without unbounded memory

## Quick Start

### Prerequisites

```bash
# Linux kernel >= 5.10
uname -r

# Required tools
sudo apt install clang libbpf-dev golang-go
```

### Build

```bash
make gen    # Compile eBPF programs
make build  # Build Go binary
```

### Configure

Edit `~/.amon/config.yaml`:

```yaml
tracked_commands:
  - nginx
  - python
  - node

ignored_commands:
  - systemd
  - dbus-daemon

events_threshold: 1000
```

### Run

```bash
sudo bin/amon
```

## Architecture

```
┌────────────────────────────────────────────────┐
│              eBPF Programs (Kernel)            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐      │
│  │ sys_enter│  │sys_enter │  │  sched   │      │
│  │  openat  │  │ connect  │  │process_  │      │
│  │          │  │          │  │  exit    │      │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘      │
│       │             │             │            │
│       └─────────────┴─────────────┘            │
│                     │                          │
│            ┌────────▼────────┐                 │
│            │  Unified Ring   │                 │
│            │     Buffer      │                 │
│            └────────┬────────┘                 │
└─────────────────────┼──────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────┐
│           Userspace (Go Application)           │
│  ┌──────────────┐       ┌──────────────┐       │
│  │ Event Parser │─────▶│   Circular   │       │
│  │  (by type)   │       │   Buffers    │       │
│  └──────────────┘       │ (per-process)│       │
│                         └───────┬──────┘       │
│                                 │              │
│                         ┌───────▼──────┐       │
│                         │   Crash      │       │
│                         │  Detection   │       │
│                         └───────┬──────┘       │
│                                 │              │
│                     ┌───────────▼───────────┐  │
│                     │   Report Generation   │  │
│                     │  • TXT (human)        │  │
│                     │  • JSONL (machine)    │  │
│                     └───────────────────────┘  │
└────────────────────────────────────────────────┘
```

## Report Example

```
═══════════════════════════════════════════════════
                AMON CRASH REPORT
═══════════════════════════════════════════════════

PROCESS INFORMATION
  Process:        nginx
  PID:            12345
  Parent PID:     1
  Start Time:     1234567890 ns

CRASH DETAILS
  Time:           2024-06-03T16:45:00-07:00
  Signal:         SIGSEGV (11)
  Exit Code:      0

STATISTICS
  Total Events:   1520
  Events Saved:   42 (filtered)
  Errors:         8
  Slow Ops:       2 (>100ms)

EVENTS LEADING TO CRASH

[   1] ❌  CONNECT
       Latency:   3001.00 ms ⚠ SLOW
       Return:    -110 ❌ ERROR
       Dest IP:   10.0.0.5
       Port:      5432

[   2] ❌  OPENAT
       Return:    -2 ❌ ERROR
       File:      /var/log/nginx/access.log

[   3]     CONNECT
       Return:    async (EINPROGRESS)
       Dest IP:   10.0.0.9
       Port:      6379

... (context events)
```

## Testing

```bash
# Run connect event test
./tests/C/run_connect_test.sh

# Run crash test
./tests/C/crash_test_1

# Check reports
ls -lh ~/.amon/crashes/
cat ~/.amon/crashes/*.txt
```

## Key Design Decisions

### Signal vs Noise Filtering
Only errors, slow operations (>100ms), and recent context are saved. 50,000 successful reads are filtered out, keeping reports focused on the signal.

### EINPROGRESS Handling
Non-blocking connect() returns EINPROGRESS (-115), which is NOT an error. Amon correctly excludes it from error counts.

### Packed Structs
All eBPF event structs use `__attribute__((packed))` to avoid alignment issues between C and Go.

### Process Name Truncation
Linux truncates comm names to 15 characters. Amon validates and warns about this.

## Output Locations

```
~/.amon/
├── crashes/
│   ├── nginx_12345_2024-06-03T16:45:00.txt
│   ├── nginx_12345_2024-06-03T16:45:00.jsonl
│   └── ...
├── amon.log       # Operational logs
└── config.yaml    # Configuration
```

## License

MIT License
