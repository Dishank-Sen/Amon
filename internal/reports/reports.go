package reports

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	cb "github.com/Dishank-Sen/Amon/internal/circular_buffer"
	"github.com/Dishank-Sen/Amon/internal/forensics"
	"github.com/Dishank-Sen/Amon/internal/stacktrace"
	"github.com/Dishank-Sen/Amon/types"
)

type CrashReport struct {
	Process struct {
		PID       uint32 `json:"pid"`
		PPID      uint32 `json:"ppid"`
		Comm      string `json:"comm"`
		StartTime uint64 `json:"start_time_ns"`
	} `json:"process"`

	Crash struct {
		Timestamp   uint64 `json:"timestamp_ns"`
		TimestampISO string `json:"timestamp_iso"`
		ExitCode    int32  `json:"exit_code"`
		Signal      int32  `json:"signal"`
		SignalName  string `json:"signal_name"`
	} `json:"crash"`

	Stats struct {
		TotalEvents uint64 `json:"total_events"`
		ErrorCount  uint64 `json:"error_count"`
		SlowCount   uint64 `json:"slow_count"`
	} `json:"stats"`

	Events []types.SyscallEvent `json:"events"`
}

// getRealUserHome returns the home directory of the actual user, even when running with sudo
func getRealUserHome() (string, error) {
	// Check if running with sudo - SUDO_USER contains the actual user
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		u, err := user.Lookup(sudoUser)
		if err != nil {
			return "", fmt.Errorf("failed to lookup SUDO_USER %s: %w", sudoUser, err)
		}
		return u.HomeDir, nil
	}

	// Not running with sudo, use current user
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return home, nil
}

// GetCrashDir returns ~/.amon/crashes, creating it if needed
func GetCrashDir() (string, error) {
	home, err := getRealUserHome()
	if err != nil {
		return "", err
	}

	crashDir := filepath.Join(home, ".amon", "crashes")
	if err := os.MkdirAll(crashDir, 0755); err != nil {
		return "", err
	}

	return crashDir, nil
}

// GetLogFile returns ~/.amon/amon.log path, creating parent dir if needed
func GetLogFile() (string, error) {
	home, err := getRealUserHome()
	if err != nil {
		return "", err
	}

	logDir := filepath.Join(home, ".amon")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return "", err
	}

	return filepath.Join(logDir, "amon.log"), nil
}

func signalName(sig int32) string {
	names := map[int32]string{
		4:  "SIGILL",
		6:  "SIGABRT",
		7:  "SIGBUS",
		8:  "SIGFPE",
		9:  "SIGKILL",
		11: "SIGSEGV",
		15: "SIGTERM",
	}
	if name, ok := names[sig]; ok {
		return name
	}
	return fmt.Sprintf("SIG(%d)", sig)
}

// SignalContext contains stack trace and fault address from signal delivery
type SignalContext struct {
	StackTrace *stacktrace.StackTrace
	FaultAddr  uint64
	SiCode     int32
	Signal     uint32
}

// GenerateCrashReport creates both .txt and .jsonl reports (legacy - no stack)
func GenerateCrashReport(
	exitEvent *types.ExitEvent,
	buffer *cb.CircularBuffer,
) error {
	return GenerateCrashReportWithStack(exitEvent, buffer, nil)
}

// GenerateCrashReportWithStack creates reports with optional stack trace
func GenerateCrashReportWithStack(
	exitEvent *types.ExitEvent,
	buffer *cb.CircularBuffer,
	sigCtx *SignalContext,
) error {
	pid := exitEvent.Tgid
	ppid := exitEvent.Ppid
	comm := string(bytes.TrimRight(exitEvent.Comm[:], "\x00"))
	exitCode := exitEvent.ExitCode
	signal := exitEvent.Signal
	exitTime := exitEvent.ExitTimeNs
	crashDir, err := GetCrashDir()
	if err != nil {
		return fmt.Errorf("failed to get crash directory: %w", err)
	}

	// Use current time for filename since exitTime is in nanoseconds since boot
	now := time.Now()
	timestamp := now.Format("2006-01-02T15:04:05")

	// Sanitize comm for filename (remove any slashes or special chars)
	safeComm := strings.ReplaceAll(comm, "/", "_")
	safeComm = strings.ReplaceAll(safeComm, " ", "_")

	baseName := fmt.Sprintf("%s_%d_%s", safeComm, pid, timestamp)
	txtPath := filepath.Join(crashDir, baseName+".txt")
	jsonlPath := filepath.Join(crashDir, baseName+".jsonl")

	// Prepare report data
	allEvents := buffer.Drain()

	// Filter noise but track how much we removed
	noiseCount := forensics.CountNoise(allEvents)
	events := forensics.FilterNoise(allEvents)

	report := CrashReport{
		Events: events,
	}
	report.Process.PID = pid
	report.Process.PPID = ppid
	report.Process.Comm = comm
	report.Process.StartTime = buffer.StartTime
	report.Crash.Timestamp = exitTime
	report.Crash.TimestampISO = now.Format(time.RFC3339)
	report.Crash.ExitCode = exitCode
	report.Crash.Signal = signal
	report.Crash.SignalName = signalName(signal)
	report.Stats.TotalEvents = buffer.TotalEvents
	report.Stats.ErrorCount = buffer.ErrorCount
	report.Stats.SlowCount = buffer.SlowCount

	// Use fault address from signal context if available (more reliable)
	faultAddr := exitEvent.SigInfo.FaultAddr
	if sigCtx != nil && sigCtx.FaultAddr != 0 {
		faultAddr = sigCtx.FaultAddr
	}

	// Perform crash analysis
	analysis := forensics.AnalyzeCrash(signal, faultAddr, pid)

	// Generate TXT report with stack trace
	if err := writeTxtReport(txtPath, &report, analysis, sigCtx, noiseCount); err != nil {
		return fmt.Errorf("failed to write txt report: %w", err)
	}

	// Generate JSONL report
	if err := writeJsonlReport(jsonlPath, &report); err != nil {
		return fmt.Errorf("failed to write jsonl report: %w", err)
	}

	fmt.Printf("📝 Crash reports generated:\n")
	fmt.Printf("   TXT:   %s\n", txtPath)
	fmt.Printf("   JSONL: %s\n", jsonlPath)

	return nil
}

func writeTxtReport(path string, report *CrashReport, analysis *forensics.CrashAnalysis, sigCtx *SignalContext, noiseCount int) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := func(format string, args ...interface{}) {
		fmt.Fprintf(f, format, args...)
	}

	w("═══════════════════════════════════════════════════════════════════\n")
	w("                    AMON CRASH REPORT\n")
	w("                    Forensic Analysis\n")
	w("═══════════════════════════════════════════════════════════════════\n\n")

	// CRASH ANALYSIS FIRST - answer "why did it crash?"
	w("%s\n", analysis.Format())

	// STACK TRACE - show where crash occurred
	if sigCtx != nil && sigCtx.StackTrace != nil && len(sigCtx.StackTrace.Frames) > 0 {
		w("STACK TRACE (at crash time)\n")
		w("───────────────────────────────────────────────────────────────────\n")
		w("%s\n", sigCtx.StackTrace.Format())
	}

	w("PROCESS INFORMATION\n")
	w("───────────────────────────────────────────────────────────────────\n")
	w("  Process:        %s\n", report.Process.Comm)
	w("  PID:            %d\n", report.Process.PID)
	w("  Parent PID:     %d\n", report.Process.PPID)

	// Calculate process lifetime
	var lifetimeSec float64
	if report.Crash.Timestamp > report.Process.StartTime {
		lifetimeNs := report.Crash.Timestamp - report.Process.StartTime
		lifetimeSec = float64(lifetimeNs) / 1_000_000_000.0

		if lifetimeSec < 1.0 {
			w("  Lifetime:       %.1f ms\n", lifetimeSec*1000)
		} else if lifetimeSec < 60 {
			w("  Lifetime:       %.2f seconds\n", lifetimeSec)
		} else {
			minutes := int(lifetimeSec / 60)
			seconds := lifetimeSec - float64(minutes*60)
			w("  Lifetime:       %dm %.1fs\n", minutes, seconds)
		}
	} else {
		w("  Lifetime:       unknown\n")
	}

	w("  Crash Time:     %s\n", report.Crash.TimestampISO)
	w("\n")

	w("EVENT STATISTICS\n")
	w("───────────────────────────────────────────────────────────────────\n")
	w("  Total Events:   %d\n", report.Stats.TotalEvents)
	w("  Errors:         %d\n", report.Stats.ErrorCount)
	w("  Slow Ops:       %d (>100ms)\n", report.Stats.SlowCount)
	if noiseCount > 0 {
		w("  Filtered Noise: %d (startup probes)\n", noiseCount)
	}
	w("  Shown Below:    %d (errors + slow + context)\n", len(report.Events))
	w("\n")

	// Add network activity summary before detailed events
	networkEvents := 0
	networkErrors := 0
	for _, evt := range report.Events {
		if evt.Type == "connect" {
			networkEvents++
			if evt.Ret < 0 && evt.Ret != -115 { // exclude EINPROGRESS
				networkErrors++
			}
		}
	}

	if networkEvents > 0 {
		w("NETWORK ACTIVITY SUMMARY\n")
		w("───────────────────────────────────────────────────────────────────\n")
		w("  Connections:    %d\n", networkEvents)
		w("  Failed:         %d\n", networkErrors)
		w("\n")

		// Show unique destinations
		destinations := make(map[string]string)
		for _, evt := range report.Events {
			if evt.Network != nil {
				ip := fmt.Sprintf("%d.%d.%d.%d:%d",
					evt.Network.DstIP[0], evt.Network.DstIP[1],
					evt.Network.DstIP[2], evt.Network.DstIP[3],
					evt.Network.DstPort)

				status := "SUCCESS"
				if evt.Ret == -111 {
					status = "ECONNREFUSED"
				} else if evt.Ret == -110 {
					status = "ETIMEDOUT"
				} else if evt.Ret == -115 {
					status = "ASYNC"
				} else if evt.Ret < 0 {
					status = "ERROR"
				}

				destinations[ip] = status
			}
		}

		for dest, status := range destinations {
			w("  %-30s %s\n", dest, status)
		}
		w("\n")
	}

	w("DETAILED EVENTS (chronological, filtered for relevance)\n")
	w("═══════════════════════════════════════════════════════════════════\n")

	if len(report.Events) == 0 {
		w("  (no events captured)\n\n")
	} else {
		const EINPROGRESS = 115
		processStartTime := report.Process.StartTime

		for i, evt := range report.Events {
			// Mark errors prominently (but not EINPROGRESS)
			marker := "    "
			isAsync := evt.Ret == -EINPROGRESS
			isError := evt.Ret < 0 && !isAsync
			isSlow := evt.Latency > 100_000_000 && !isAsync

			if isError {
				marker = "❌  "
			} else if isSlow {
				marker = "⚠️  "
			}

			// Calculate relative time from process start
			var relativeTime string
			if evt.Timestamp > processStartTime {
				offsetNs := evt.Timestamp - processStartTime
				offsetSec := float64(offsetNs) / 1_000_000_000.0
				if offsetSec < 1.0 {
					relativeTime = fmt.Sprintf("+%.0f ms", offsetSec*1000)
				} else {
					relativeTime = fmt.Sprintf("+%.2f s", offsetSec)
				}
			} else {
				relativeTime = "+0.00 s"
			}

			w("[%4d] %s%s\n", i+1, marker, strings.ToUpper(evt.Type))
			w("       Time:      %s\n", relativeTime)
			w("       PID:       %d\n", evt.PID)

			if evt.Latency > 0 {
				latencyMs := float64(evt.Latency) / 1_000_000.0
				w("       Latency:   %.2f ms", latencyMs)
				if isSlow {
					w(" ⚠ SLOW")
				}
				w("\n")
			}

			if evt.Ret != 0 {
				if isAsync {
					w("       Return:    async (EINPROGRESS)\n")
				} else {
					w("       Return:    %d", evt.Ret)
					if isError {
						w(" ❌ ERROR")
					}
					w("\n")
				}
			}

			if evt.File != nil {
				w("       File:      %s\n", evt.File.Filename)
				if evt.File.Flags != 0 {
					w("       Flags:     0x%x\n", evt.File.Flags)
				}
				if evt.File.FD != 0 {
					w("       FD:        %d\n", evt.File.FD)
				}
			}

			if evt.Network != nil {
				w("       Dest IP:   %d.%d.%d.%d\n",
					evt.Network.DstIP[0], evt.Network.DstIP[1],
					evt.Network.DstIP[2], evt.Network.DstIP[3])
				w("       Port:      %d\n", evt.Network.DstPort)
				if evt.Network.FD != 0 {
					w("       FD:        %d\n", evt.Network.FD)
				}
			}

			if evt.Process != nil {
				w("       Child PID: %d\n", evt.Process.ChildPID)
				childComm := strings.TrimRight(string(evt.Process.ChildComm[:]), "\x00")
				w("       Child:     %s\n", childComm)
				if evt.Process.Binary != "" {
					w("       Binary:    %s\n", evt.Process.Binary)
				}
			}

			w("\n")
		}
	}

	w("═══════════════════════════════════════════════════════════════════\n")
	w("End of report\n")

	return nil
}

func writeJsonlReport(path string, report *CrashReport) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	encoder := json.NewEncoder(f)

	// Write metadata as first line
	metadata := map[string]interface{}{
		"_type":   "crash_metadata",
		"process": report.Process,
		"crash":   report.Crash,
		"stats":   report.Stats,
	}
	if err := encoder.Encode(metadata); err != nil {
		return err
	}

	// Write each event as a separate JSON line
	for _, evt := range report.Events {
		eventLine := map[string]interface{}{
			"_type":     "event",
			"type":      evt.Type,
			"pid":       evt.PID,
			"timestamp": evt.Timestamp,
			"latency":   evt.Latency,
			"ret":       evt.Ret,
		}

		if evt.File != nil {
			eventLine["file"] = evt.File
		}
		if evt.Network != nil {
			eventLine["network"] = evt.Network
		}
		if evt.Process != nil {
			eventLine["process"] = evt.Process
		}

		if err := encoder.Encode(eventLine); err != nil {
			return err
		}
	}

	return nil
}
