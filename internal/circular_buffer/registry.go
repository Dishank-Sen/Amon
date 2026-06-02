package circularbuffer

import (
	"sync"
	"github.com/Dishank-Sen/Amon/types"
)

type ProcessRegistry struct {
    buffers map[uint32]*CircularBuffer  // PID → buffer
    mu      sync.RWMutex
}

func NewRegistry() *ProcessRegistry {
    return &ProcessRegistry{
        buffers: make(map[uint32]*CircularBuffer),
    }
}

func (r *ProcessRegistry) GetOrCreate(pid uint32, ppid uint32, comm string, startTime uint64, size int) *CircularBuffer {
    r.mu.Lock()
    defer r.mu.Unlock()

    if buf, ok := r.buffers[pid]; ok {
        return buf
    }

    buf := &CircularBuffer{
        events:    make([]types.SyscallEvent, size),
        size:      size,
        PID:       pid,
        PPID:      ppid,
        Comm:      comm,
        StartTime: startTime,
    }
    r.buffers[pid] = buf
    return buf
}

func (r *ProcessRegistry) Get(pid uint32) (*CircularBuffer, bool) {
    r.mu.RLock()
    defer r.mu.RUnlock()

    buf, ok := r.buffers[pid]
    return buf, ok
}

func (r *ProcessRegistry) Delete(pid uint32) {
    r.mu.Lock()
    defer r.mu.Unlock()
    delete(r.buffers, pid)
}