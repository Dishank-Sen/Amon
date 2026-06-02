package circularbuffer

import (
	"sync"
	"github.com/Dishank-Sen/Amon/types"
)

type CircularBuffer struct {
    // the actual storage
    events []types.SyscallEvent
    head   int        // next write position
    count  int        // total events stored, capped at BufferSize
    mu     sync.Mutex
	size   int
    
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

    cb.events[cb.head] = e
    cb.head = (cb.head + 1) % cb.size

    if cb.count < cb.size {
        cb.count++
    }

    // maintain stats
    cb.TotalEvents++
    if e.Ret < 0 {
        cb.ErrorCount++
    }
    if e.Latency > 100_000_000 { // 100ms threshold
        cb.SlowCount++
    }
}

// Drain returns all stored events in chronological order oldest → newest
func (cb *CircularBuffer) Drain() []types.SyscallEvent {
    cb.mu.Lock()
    defer cb.mu.Unlock()

    result := make([]types.SyscallEvent, cb.count)

    if cb.count < cb.size {
        // buffer not full — events are at [0:count] in order
        copy(result, cb.events[:cb.count])
        return result
    }

    // buffer full — oldest event is at head
    // copy head→end first, then 0→head
    n := copy(result, cb.events[cb.head:])
    copy(result[n:], cb.events[:cb.head])

    return result
}