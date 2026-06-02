# Crash Reporting System

## Overview

Amon now generates comprehensive crash reports in two formats:
- **Human-readable TXT** - for developers debugging crashes
- **JSONL format** - for tooling, querying, and analysis

## Directory Structure

```
~/.amon/
├── crashes/
│   ├── crash_test_1_210681_2024-06-03T14:32:05.txt
│   ├── crash_test_1_210681_2024-06-03T14:32:05.jsonl
│   ├── nginx_4821_2024-06-03T15:20:13.txt
│   └── nginx_4821_2024-06-03T15:20:13.jsonl
└── amon.log
```

## Report Formats

### TXT Report (Human-Readable)

The TXT report includes:

1. **Process Information**
   - Process name, PID, parent PID
   - Start time (nanoseconds since boot)

2. **Crash Details**
   - Timestamp (ISO 8601 format)
   - Signal that caused the crash (SIGSEGV, SIGABRT, etc.)
   - Exit code

3. **Statistics**
   - Total events captured
   - Number of events saved in circular buffer
   - Error count (syscalls that returned < 0)
   - Slow operations count (>100ms)

4. **Events Leading to Crash**
   - Chronologically ordered (oldest → newest)
   - Each event shows:
     - Event type (OPENAT, CONNECT, etc.)
     - PID, timestamp
     - Latency (if available)
     - Return value (marked with ❌ if error)
     - Event-specific data:
       - Files: path, flags, file descriptor
       - Network: destination IP, port, socket FD
       - Process: child PID, command, binary path

**Example TXT Output:**

```
═══════════════════════════════════════════════════════════════════
                    AMON CRASH REPORT
═══════════════════════════════════════════════════════════════════

PROCESS INFORMATION
───────────────────────────────────────────────────────────────────
  Process:        crash_test_1
  PID:            210681
  Parent PID:     84394
  Start Time:     1234567890 ns (boot time)

CRASH DETAILS
───────────────────────────────────────────────────────────────────
  Time:           2024-06-03T14:32:05-07:00
  Signal:         SIGSEGV (11)
  Exit Code:      0

STATISTICS
───────────────────────────────────────────────────────────────────
  Total Events:   42
  Events Saved:   42 (circular buffer)
  Errors:         0
  Slow Ops:       0 (>100ms)

EVENTS LEADING TO CRASH (oldest → newest)
═══════════════════════════════════════════════════════════════════

[   1] OPENAT
       PID:       210681
       Timestamp: 1717445525123456789 ns
       File:      /etc/hostname

[   2] OPENAT
       PID:       210681
       Timestamp: 1717445525123567890 ns
       File:      /etc/passwd

═══════════════════════════════════════════════════════════════════
End of report
```

### JSONL Report (Machine-Readable)

Each line is a valid JSON object. First line contains metadata, subsequent lines are events.

**Metadata Line:**
```json
{"_type":"crash_metadata","process":{"pid":210681,"ppid":84394,"comm":"crash_test_1","start_time_ns":1234567890},"crash":{"timestamp_ns":1717445525234567890,"timestamp_iso":"2024-06-03T14:32:05-07:00","exit_code":0,"signal":11,"signal_name":"SIGSEGV"},"stats":{"total_events":42,"error_count":0,"slow_count":0}}
```

**Event Lines:**
```json
{"_type":"event","type":"openat","pid":210681,"timestamp":1717445525123456789,"latency":0,"ret":0,"file":{"Filename":"/etc/hostname","Flags":0,"FD":0}}
{"_type":"event","type":"openat","pid":210681,"timestamp":1717445525123567890,"latency":0,"ret":0,"file":{"Filename":"/etc/passwd","Flags":0,"FD":0}}
```

### Operational Log (amon.log)

Located at `~/.amon/amon.log`, this logs daemon lifecycle events:

```
[2024-06-03 14:30:00] INFO  Amon daemon starting...
[2024-06-03 14:30:00] DEBUG Loaded eBPF collection from internal/bpf/trace.o
[2024-06-03 14:30:00] DEBUG eBPF programs loaded successfully
[2024-06-03 14:30:00] INFO  Config loaded: tracking 1 commands, ignoring 5 commands
[2024-06-03 14:30:01] INFO  All tracepoints attached successfully
[2024-06-03 14:30:01] INFO  Amon daemon started - monitoring processes...
[2024-06-03 14:32:05] CRASH Process crashed: PID=210681 COMM=crash_test_1 SIGNAL=11
[2024-06-03 14:35:22] INFO  Received shutdown signal - stopping daemon...
[2024-06-03 14:35:22] INFO  Amon daemon stopped
```

## Querying JSONL Reports

The JSONL format makes it easy to query with standard tools:

```bash
# Extract all file operations from a crash
jq 'select(._type == "event" and .file != null)' crash_test_1_210681_2024-06-03T14:32:05.jsonl

# Find all errors (ret < 0)
jq 'select(._type == "event" and .ret < 0)' crash_test_1_210681_2024-06-03T14:32:05.jsonl

# Get crash signal from metadata
jq 'select(._type == "crash_metadata") | .crash.signal_name' crash_test_1_210681_2024-06-03T14:32:05.jsonl

# Find all events accessing a specific file
jq 'select(._type == "event" and .file.Filename | contains("passwd"))' crash_test_1_210681_2024-06-03T14:32:05.jsonl

# Extract timeline of events with timestamps
jq 'select(._type == "event") | {timestamp, type, file: .file.Filename}' crash_test_1_210681_2024-06-03T14:32:05.jsonl
```

## Implementation Details

### Packages

- **`internal/reports/reports.go`** - Generates TXT and JSONL reports
- **`internal/logger/logger.go`** - Operational logging to console and file
- **`internal/circular_buffer/`** - Per-process event buffers

### Report Generation Flow

1. Process crashes (SIGSEGV, SIGABRT, SIGBUS, SIGILL, SIGFPE)
2. `handleExitEvent` detects the crash
3. Circular buffer for crashed PID is retrieved
4. `reports.GenerateCrashReport()` creates both TXT and JSONL files
5. Report paths are logged to console and amon.log
6. Buffer is cleaned up

### Circular Buffer

- Each monitored process gets its own circular buffer (1000 events)
- Events are stored chronologically
- When full, oldest events are overwritten
- On crash, buffer is drained in chronological order (oldest → newest)
- Statistics maintained: total events, errors, slow ops

## Testing

Run the crash test:

```bash
make build
sudo bin/amon &
./tests/C/crash_test_1
sudo pkill amon

# Check reports
ls -lh ~/.amon/crashes/
cat ~/.amon/crashes/*.txt
cat ~/.amon/amon.log
```

## Future Enhancements

- [ ] Capture syscall arguments (flags, file descriptors, return values)
- [ ] Calculate accurate latencies (need exit tracepoint integration)
- [ ] Add network event capture (connect, bind, listen)
- [ ] Add process event capture (fork, exec)
- [ ] Report retention policy (auto-cleanup old reports)
- [ ] Compression for old reports
- [ ] Report uploading/shipping to central logging
