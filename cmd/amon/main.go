package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	utils "github.com/Dishank-Sen/Amon"
	cb "github.com/Dishank-Sen/Amon/internal/circular_buffer"
	"github.com/Dishank-Sen/Amon/internal/logger"
	"github.com/Dishank-Sen/Amon/internal/paths"
	"github.com/Dishank-Sen/Amon/internal/reports"
	"github.com/Dishank-Sen/Amon/types"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Event type constants - must match bpf/trace.c
const (
	EVENT_OPENAT  = 1
	EVENT_EXIT    = 2
	EVENT_CONNECT = 3
)

// All events are packed in C, so no padding in Go structs
type OpenatEvent struct {
	Type         uint32
	Pid          uint32
	Tgid         uint32
	TimestampNs  uint64
	EnterTimeNs  uint64
	Comm         [16]byte
	Filename     [256]byte
}

type ExitEvent struct {
	Type        uint32
	Pid         uint32
	Tgid        uint32
	Ppid        uint32

	StartTimeNs uint64
	ExitTimeNs  uint64

	ExitCode int32
	Signal   int32

	GroupDead uint8
	Comm      [16]byte
}

type Objs struct {
    AllowedCommands *ebpf.Map     `ebpf:"allowed_commands"`
    IgnoredCommands *ebpf.Map     `ebpf:"ignored_commands"`
    TraceOpenat     *ebpf.Program `ebpf:"trace_openat"`
    TraceOpen       *ebpf.Program `ebpf:"trace_open"`
    TraceOpenat2    *ebpf.Program `ebpf:"trace_openat2"`
    TraceOpenatExit *ebpf.Program `ebpf:"trace_openat_exit"`
    HandleFork      *ebpf.Program `ebpf:"handle_fork"`
    HandleExecve    *ebpf.Program `ebpf:"handle_execve"`
    HandleExit      *ebpf.Program `ebpf:"handle_exit"`
	Events          *ebpf.Map     `ebpf:"events"`
	ChildRoot       *ebpf.Map     `ebpf:"child_root"`
	OpenatStart     *ebpf.Map     `ebpf:"openat_start"`
}

func isCrash(e ExitEvent) bool {
    // Fatal signals that indicate crashes
    switch e.Signal {
    case 11: // SIGSEGV
        return true
    case 6:  // SIGABRT
        return true
    case 7:  // SIGBUS
        return true
    case 4:  // SIGILL
        return true
    case 8:  // SIGFPE
        return true
    }

    // Ignore SIGKILL (9) and SIGTERM (15) - these are normal terminations
    // Ignore signal 0 (normal exit) and signal 1 (SIGHUP)

    return false
}

func signalName(sig uint32) string {
    names := map[uint32]string{
        6:  "SIGABRT",
        9:  "SIGKILL",
        11: "SIGSEGV",
        7:  "SIGBUS",
        15: "SIGTERM",
    }
    if name, ok := names[sig]; ok {
        return name
    }
    return fmt.Sprintf("SIG(%d)", sig)
}

func handleOpenatEvent(data []byte, registry *cb.ProcessRegistry) {
	var e OpenatEvent
	if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &e); err != nil {
		return
	}

	comm := string(bytes.TrimRight(e.Comm[:], "\x00"))
	filename := string(bytes.TrimRight(e.Filename[:], "\x00"))

	// Get or create circular buffer for this process
	// Note: We don't have start_time here yet, will update when we add fork tracking
	const bufferSize = 1000 // Keep last 1000 events per process
	buffer := registry.GetOrCreate(e.Tgid, 0, comm, e.TimestampNs, bufferSize)

	// Create syscall event
	syscallEvent := types.SyscallEvent{
		Type:      "openat",
		PID:       e.Tgid,
		Timestamp: e.TimestampNs,
		Latency:   0, // Will be updated on exit
		Ret:       0, // Will be updated on exit
		File: &types.FileData{
			Filename: filename,
			Flags:    0, // TODO: capture flags from syscall args
			FD:       0, // Will be updated on exit
		},
	}

	buffer.Push(syscallEvent)
}

func handleExitEvent(data []byte, registry *cb.ProcessRegistry) {
	var e ExitEvent
	if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &e); err != nil {
		return
	}

	comm := string(bytes.TrimRight(e.Comm[:], "\x00"))

	// Only process crashes
	if isCrash(e) {
		logger.Crash(e.Tgid, comm, e.Signal)

		// Retrieve the circular buffer for this crashed process
		if buffer, ok := registry.Get(e.Tgid); ok {
			// Generate crash reports
			if err := reports.GenerateCrashReport(
				e.Tgid,
				e.Ppid,
				comm,
				e.ExitCode,
				e.Signal,
				e.ExitTimeNs,
				buffer,
			); err != nil {
				logger.Error("Failed to generate crash report: %v", err)
			}

			// Clean up the buffer after crash
			registry.Delete(e.Tgid)
		} else {
			logger.Warn("No event buffer found for crashed process PID=%d COMM=%s", e.Tgid, comm)
		}
	}
}

func loadConfig(cfg *types.Config, objs Objs) error{
	for _, v := range cfg.TrackedCommands{
		var key [16]byte
		copy(key[:], v)
	
		var value uint8 = 1
	
		if err := objs.AllowedCommands.Put(key, value); err != nil{
			return err
		}
	}

	for _, v := range cfg.IgnoredCommands{
		var key [16]byte
		copy(key[:], v)
	
		var value uint8 = 1
	
		if err := objs.IgnoredCommands.Put(key, value); err != nil{
			return err
		}
	}
	return nil
}


func main(){
	// Initialize operational logger
	if err := logger.Init(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Close()

	logger.Info("Amon daemon starting...")

	if err := rlimit.RemoveMemlock(); err != nil {
		logger.Fatal("Failed to remove memlock limit: %v", err)
	}

	collPath := filepath.Join("internal", "bpf", "trace.o")
	spec, err := ebpf.LoadCollectionSpec(collPath)
	if err != nil{
		logger.Fatal("Failed to load eBPF collection: %v", err)
	}
	logger.Debug("Loaded eBPF collection from %s", collPath)

	var objs Objs
	opts := ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,
			LogSizeStart:  10 * 1024 * 1024,
		},
	}

	if err := spec.LoadAndAssign(&objs, &opts); err != nil {

		if ve, ok := errors.AsType[*ebpf.VerifierError](err); ok {
			logger.Error("eBPF verifier error:\n%+v", ve)
		}

		logger.Fatal("Failed to load and assign eBPF objects: %v", err)
	}
	logger.Debug("eBPF programs loaded successfully")
	defer objs.AllowedCommands.Close()
	defer objs.TraceOpenat.Close()
	defer objs.TraceOpen.Close()
	defer objs.TraceOpenat2.Close()
	defer objs.TraceOpenatExit.Close()
	defer objs.HandleFork.Close()
	defer objs.HandleExecve.Close()
	defer objs.HandleExit.Close()
	defer objs.OpenatStart.Close()

	objs.ChildRoot.Pin("/sys/fs/bpf/amon_child_root")
	defer os.Remove("/sys/fs/bpf/amon_child_root")
	defer objs.ChildRoot.Unpin()

	cfg, err := utils.Load(paths.ConfigFile())
	if err != nil {
		logger.Fatal("Failed to load config: %v", err)
	}
	logger.Info("Config loaded: tracking %d commands, ignoring %d commands",
		len(cfg.TrackedCommands), len(cfg.IgnoredCommands))

	if err := loadConfig(cfg, objs); err != nil{
		logger.Fatal("Failed to load config into eBPF maps: %v", err)
	}

	// attach to open/openat/openat2 tracepoints
	 tpOpenat, err := link.Tracepoint(
		"syscalls",
		"sys_enter_openat",
		objs.TraceOpenat,
		nil,
	)
	if err != nil {
		logger.Fatal("Failed to attach openat tracepoint: %v", err)
	}
	defer tpOpenat.Close()

	tpOpen, err := link.Tracepoint(
		"syscalls",
		"sys_enter_open",
		objs.TraceOpen,
		nil,
	)
	if err != nil {
		logger.Fatal("Failed to attach open tracepoint: %v", err)
	}
	defer tpOpen.Close()

	tpOpenat2, err := link.Tracepoint(
		"syscalls",
		"sys_enter_openat2",
		objs.TraceOpenat2,
		nil,
	)
	if err != nil {
		logger.Fatal("Failed to attach openat2 tracepoint: %v", err)
	}
	defer tpOpenat2.Close()

	// attach fork and exec tracepoints
	tpFork, err := link.Tracepoint(
		"sched",
		"sched_process_fork",
		objs.HandleFork,
		nil,
	)
	if err != nil {
		logger.Fatal("Failed to attach fork tracepoint: %v", err)
	}
	defer tpFork.Close()

	tpExec, err := link.Tracepoint(
		"syscalls",
		"sys_enter_execve",
		objs.HandleExecve,
		nil,
	)
	if err != nil {
		logger.Fatal("Failed to attach execve tracepoint: %v", err)
	}
	defer tpExec.Close()

	// attach exit tracepoint
	tpExit, err := link.Tracepoint(
		"sched",
		"sched_process_exit",
		objs.HandleExit,
		nil,
	)
	if err != nil {
		logger.Fatal("Failed to attach exit tracepoint: %v", err)
	}
	defer tpExit.Close()

	logger.Info("All tracepoints attached successfully")

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		logger.Fatal("Failed to create ring buffer reader: %v", err)
	}
	defer rd.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Initialize process registry for circular buffers
	registry := cb.NewRegistry()

	logger.Info("Amon daemon started - monitoring processes...")

	// Single unified event handler
	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					logger.Debug("Ring buffer closed")
					return
				}

				logger.Error("Ring buffer read error: %v", err)
				return
			}

			// Peek at the type field (first 4 bytes)
			if len(record.RawSample) < 4 {
				continue
			}

			var eventType uint32
			buf := bytes.NewReader(record.RawSample)
			if err := binary.Read(buf, binary.LittleEndian, &eventType); err != nil {
				continue
			}

			// Dispatch based on event type
			switch eventType {
			case EVENT_OPENAT:
				handleOpenatEvent(record.RawSample, registry)
			case EVENT_EXIT:
				handleExitEvent(record.RawSample, registry)
			default:
				logger.Warn("Unknown event type: %d", eventType)
			}
		}
	}()

	<-stop
	logger.Info("Received shutdown signal - stopping daemon...")
	logger.Info("Amon daemon stopped")
}