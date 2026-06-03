package circularbuffer

import (
	"sync"
	"github.com/Dishank-Sen/Amon/types"
)

type CircularBuffer struct {
    // the actual storage - circular buffer for recent events
    events []types.SyscallEvent
    head   int        // next write position
    count  int        // total events stored, capped at BufferSize
    mu     sync.Mutex
	size   int

	// priority storage - errors and anomalies we always want to keep
	// these are kept separately so they don't get overwritten by successful ops
	errorEvents []types.SyscallEvent  // all errors (ret < 0)
	slowEvents  []types.SyscallEvent  // slow operations (latency > threshold)
	maxErrors   int                    // cap for error events
	maxSlow     int                    // cap for slow events

	// process metadata
    // stored here so report has context even after process dies
    PID       uint32
    PPID      uint32
    Comm      string
    StartTime uint64   // from task_struct.start_time — nanoseconds since boot

    // stats — useful for report summary section
    TotalEvents   uint64   // every event ever pushed, including overwritten ones
    ErrorCount    uint64   // events where Ret < 0
    SlowCount     uint64   // events where Latency > threshold
}

func (cb *CircularBuffer) Push(e types.SyscallEvent) {
    cb.mu.Lock()
    defer cb.mu.Unlock()

    const EINPROGRESS = 115

    // EINPROGRESS is not an error for connect syscalls
    isError := e.Ret < 0 && e.Ret != -EINPROGRESS
    // Don't mark EINPROGRESS as slow either
    isSlow := e.Latency > 100_000_000 && e.Ret != -EINPROGRESS // 100ms threshold

    // Always keep errors and slow operations in priority storage
    if isError && len(cb.errorEvents) < cb.maxErrors {
        cb.errorEvents = append(cb.errorEvents, e)
    }
    if isSlow && len(cb.slowEvents) < cb.maxSlow {
        cb.slowEvents = append(cb.slowEvents, e)
    }

    // Also store in circular buffer (for context around errors)
    cb.events[cb.head] = e
    cb.head = (cb.head + 1) % cb.size

    if cb.count < cb.size {
        cb.count++
    }

    // maintain stats
    cb.TotalEvents++
    if isError {
        cb.ErrorCount++
    }
    if isSlow {
        cb.SlowCount++
    }
}

// Drain returns priority events (errors + slow ops) plus recent context
// This gives you signal (failed operations) without noise (50k successful reads)
func (cb *CircularBuffer) Drain() []types.SyscallEvent {
    cb.mu.Lock()
    defer cb.mu.Unlock()

    // Strategy: Return errors/slow ops + surrounding context from circular buffer
    // If there are errors, we want to see what happened around them

    if len(cb.errorEvents) == 0 && len(cb.slowEvents) == 0 {
        // No errors or slow ops - return recent events (last ~50 for context)
        contextSize := 50
        if cb.count < contextSize {
            contextSize = cb.count
        }

        result := make([]types.SyscallEvent, 0, contextSize)

        if cb.count < cb.size {
            // buffer not full
            start := cb.count - contextSize
            if start < 0 {
                start = 0
            }
            result = append(result, cb.events[start:cb.count]...)
        } else {
            // buffer full - get last N events
            startIdx := (cb.head - contextSize + cb.size) % cb.size
            for i := 0; i < contextSize; i++ {
                idx := (startIdx + i) % cb.size
                result = append(result, cb.events[idx])
            }
        }
        return result
    }

    // We have errors/slow ops - merge them with surrounding context
    result := make([]types.SyscallEvent, 0)

    // Add all priority events (errors and slow ops)
    result = append(result, cb.errorEvents...)
    result = append(result, cb.slowEvents...)

    // Add recent context (last 20-30 events) to see what led to the problems
    contextSize := 30
    if cb.count < contextSize {
        contextSize = cb.count
    }

    if cb.count < cb.size {
        // buffer not full
        start := cb.count - contextSize
        if start < 0 {
            start = 0
        }
        result = append(result, cb.events[start:cb.count]...)
    } else {
        // buffer full - get last N events
        startIdx := (cb.head - contextSize + cb.size) % cb.size
        for i := 0; i < contextSize; i++ {
            idx := (startIdx + i) % cb.size
            result = append(result, cb.events[idx])
        }
    }

    // Sort by timestamp to present chronologically
    // (errors might be scattered in time)
    return sortByTimestamp(result)
}

// sortByTimestamp sorts events chronologically
func sortByTimestamp(events []types.SyscallEvent) []types.SyscallEvent {
    // Simple insertion sort - good enough for small arrays
    for i := 1; i < len(events); i++ {
        key := events[i]
        j := i - 1
        for j >= 0 && events[j].Timestamp > key.Timestamp {
            events[j+1] = events[j]
            j--
        }
        events[j+1] = key
    }
    return events
}