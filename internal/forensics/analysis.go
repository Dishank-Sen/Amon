package forensics

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// MemoryRegion represents a memory mapping from /proc/pid/maps
type MemoryRegion struct {
	Start       uint64
	End         uint64
	Permissions string
	Offset      uint64
	Device      string
	Inode       uint64
	Path        string
}

// MemoryMap contains parsed /proc/pid/maps
type MemoryMap struct {
	Regions []MemoryRegion
	Heap    *MemoryRegion
	Stack   *MemoryRegion
}

// CrashAnalysis contains root cause analysis
type CrashAnalysis struct {
	Signal          int32
	SignalName      string
	FaultAddr       uint64
	HasFaultAddr    bool
	MemoryType      string // "null", "low", "unmapped", "stack", "heap", "library", "executable"
	LibraryName     string // if faulting in library
	LikelyCause     string
	Recommendation  string
}

// ParseMemoryMaps reads /proc/pid/maps
func ParseMemoryMaps(pid uint32) (*MemoryMap, error) {
	path := fmt.Sprintf("/proc/%d/maps", pid)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	mm := &MemoryMap{}
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := scanner.Text()
		region, err := parseMapLine(line)
		if err != nil {
			continue // skip malformed lines
		}

		mm.Regions = append(mm.Regions, region)

		// Identify special regions
		if region.Path == "[heap]" {
			mm.Heap = &region
		} else if region.Path == "[stack]" {
			mm.Stack = &region
		}
	}

	return mm, scanner.Err()
}

func parseMapLine(line string) (MemoryRegion, error) {
	// Format: address perms offset dev inode pathname
	// Example: 7f1234567000-7f1234568000 r-xp 00000000 08:01 12345 /lib/x86_64-linux-gnu/libc.so.6
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return MemoryRegion{}, fmt.Errorf("invalid map line")
	}

	// Parse address range
	addrRange := strings.Split(fields[0], "-")
	if len(addrRange) != 2 {
		return MemoryRegion{}, fmt.Errorf("invalid address range")
	}

	start, _ := strconv.ParseUint(addrRange[0], 16, 64)
	end, _ := strconv.ParseUint(addrRange[1], 16, 64)
	offset, _ := strconv.ParseUint(fields[2], 16, 64)
	inode, _ := strconv.ParseUint(fields[4], 10, 64)

	path := ""
	if len(fields) > 5 {
		path = strings.Join(fields[5:], " ")
	}

	return MemoryRegion{
		Start:       start,
		End:         end,
		Permissions: fields[1],
		Offset:      offset,
		Device:      fields[3],
		Inode:       inode,
		Path:        path,
	}, nil
}

// ClassifyAddress determines what memory region an address belongs to
func (mm *MemoryMap) ClassifyAddress(addr uint64) (string, string) {
	// NULL pointer
	if addr == 0 {
		return "null", ""
	}

	// Low memory (first 64KB) - likely null deref with offset
	if addr < 0x10000 {
		return "low", ""
	}

	// Check mapped regions
	for _, r := range mm.Regions {
		if addr >= r.Start && addr < r.End {
			// Classify by path
			if r.Path == "[stack]" {
				return "stack", ""
			}
			if r.Path == "[heap]" {
				return "heap", ""
			}
			if strings.HasSuffix(r.Path, ".so") || strings.Contains(r.Path, ".so.") {
				return "library", r.Path
			}
			if r.Path != "" && !strings.HasPrefix(r.Path, "[") {
				return "executable", r.Path
			}
			return "mapped", r.Path
		}
	}

	return "unmapped", ""
}

// AnalyzeCrash performs root cause analysis
func AnalyzeCrash(signal int32, faultAddr uint64, pid uint32) *CrashAnalysis {
	analysis := &CrashAnalysis{
		Signal:    signal,
		FaultAddr: faultAddr,
	}

	// Signal names
	signalNames := map[int32]string{
		4:  "SIGILL",
		6:  "SIGABRT",
		7:  "SIGBUS",
		8:  "SIGFPE",
		9:  "SIGKILL",
		11: "SIGSEGV",
		15: "SIGTERM",
	}

	if name, ok := signalNames[signal]; ok {
		analysis.SignalName = name
	} else {
		analysis.SignalName = fmt.Sprintf("SIG(%d)", signal)
	}

	// For memory fault signals, analyze fault address
	if signal == 11 || signal == 7 { // SIGSEGV or SIGBUS
		analysis.HasFaultAddr = true

		// Try to get memory map
		mm, err := ParseMemoryMaps(pid)
		if err == nil {
			memType, libName := mm.ClassifyAddress(faultAddr)
			analysis.MemoryType = memType
			analysis.LibraryName = libName

			// Determine likely cause
			switch memType {
			case "null":
				analysis.LikelyCause = "NULL pointer dereference"
				analysis.Recommendation = "Check for uninitialized pointers or missing null checks"

			case "low":
				analysis.LikelyCause = fmt.Sprintf("NULL pointer dereference with offset (+0x%x)", faultAddr)
				analysis.Recommendation = "Check for accessing struct members on a NULL pointer"

			case "unmapped":
				analysis.LikelyCause = "Access to unmapped memory (possible use-after-free)"
				analysis.Recommendation = "Check for freed pointers or invalid pointer arithmetic"

			case "stack":
				analysis.LikelyCause = "Stack corruption or overflow"
				analysis.Recommendation = "Check for stack buffer overflows or deeply nested recursion"

			case "heap":
				analysis.LikelyCause = "Heap corruption or use-after-free"
				analysis.Recommendation = "Check for double-free, use-after-free, or buffer overflow"

			case "library", "executable":
				analysis.LikelyCause = "Invalid access within mapped region"
				analysis.Recommendation = "Check for buffer overruns or permission violations"
			}
		} else {
			// Fallback analysis without memory map
			if faultAddr == 0 {
				analysis.MemoryType = "null"
				analysis.LikelyCause = "NULL pointer dereference"
				analysis.Recommendation = "Check for uninitialized pointers or missing null checks"
			} else if faultAddr < 0x10000 {
				analysis.MemoryType = "low"
				analysis.LikelyCause = fmt.Sprintf("NULL pointer dereference with offset (+0x%x)", faultAddr)
				analysis.Recommendation = "Check for accessing struct members on a NULL pointer"
			}
		}
	} else if signal == 6 { // SIGABRT
		analysis.LikelyCause = "Process terminated by runtime assertion or abort()"
		analysis.Recommendation = "Check stderr logs for assertion failures or check syscall events for double-free patterns"
	} else if signal == 8 { // SIGFPE
		analysis.LikelyCause = "Floating point exception (division by zero or arithmetic overflow)"
		analysis.Recommendation = "Check for division operations or integer overflow"
	} else if signal == 4 { // SIGILL
		analysis.LikelyCause = "Illegal instruction (corrupted code or unsupported CPU instruction)"
		analysis.Recommendation = "Check for function pointer corruption or incorrect CPU architecture"
	}

	return analysis
}

// FormatAnalysis generates human-readable crash analysis
func (a *CrashAnalysis) Format() string {
	var sb strings.Builder

	sb.WriteString("CRASH ANALYSIS\n")
	sb.WriteString("───────────────────────────────────────────────────────────────────\n")
	sb.WriteString(fmt.Sprintf("  Signal:         %s (%d)\n", a.SignalName, a.Signal))

	if a.HasFaultAddr {
		if a.FaultAddr == 0 {
			sb.WriteString("  Fault Address:  0x0 (NULL)\n")
		} else {
			sb.WriteString(fmt.Sprintf("  Fault Address:  0x%x\n", a.FaultAddr))
		}

		if a.MemoryType != "" {
			sb.WriteString(fmt.Sprintf("  Memory Type:    %s\n", a.MemoryType))
		}

		if a.LibraryName != "" {
			sb.WriteString(fmt.Sprintf("  Library:        %s\n", a.LibraryName))
		}
	}

	if a.LikelyCause != "" {
		sb.WriteString("\n  Likely Cause:\n")
		sb.WriteString(fmt.Sprintf("    %s\n", a.LikelyCause))
	}

	if a.Recommendation != "" {
		sb.WriteString("\n  Recommendation:\n")
		sb.WriteString(fmt.Sprintf("    %s\n", a.Recommendation))
	}

	return sb.String()
}
