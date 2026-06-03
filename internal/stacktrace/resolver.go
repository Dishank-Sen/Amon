package stacktrace

import (
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Frame represents a single stack frame
type Frame struct {
	PC         uint64 // Program counter (instruction pointer)
	Function   string // Function name
	File       string // Source file path
	Module     string // Shared library or executable name
	Offset     uint64 // Offset within the module
}

// StackTrace represents a complete stack trace
type StackTrace struct {
	Frames []Frame
}

// symbolCache caches symbol information per binary
type symbolCache struct {
	symbols map[uint64]string
	base    uint64
}

var cache = make(map[string]*symbolCache)

// ResolveStackTrace converts raw instruction pointers to human-readable frames
func ResolveStackTrace(pcs []uint64, pid uint32) (*StackTrace, error) {
	if len(pcs) == 0 {
		return &StackTrace{}, nil
	}

	// Read memory maps to find which binary each PC belongs to
	maps, err := parseProcessMaps(pid)
	if err != nil {
		// Can't parse maps - return raw PCs
		trace := &StackTrace{}
		for _, pc := range pcs {
			trace.Frames = append(trace.Frames, Frame{
				PC:       pc,
				Function: fmt.Sprintf("0x%x", pc),
				Module:   "unknown",
			})
		}
		return trace, nil
	}

	trace := &StackTrace{}
	for _, pc := range pcs {
		if pc == 0 {
			break // Stack trace end marker
		}

		frame := resolvePC(pc, maps)
		trace.Frames = append(trace.Frames, frame)
	}

	return trace, nil
}

// MemoryMap represents a memory region from /proc/pid/maps
type memoryMap struct {
	start      uint64
	end        uint64
	perms      string
	offset     uint64 // File offset from /proc/pid/maps
	path       string
	isExecutable bool // True if this is the executable (not a library)
}

func parseProcessMaps(pid uint32) ([]memoryMap, error) {
	path := fmt.Sprintf("/proc/%d/maps", pid)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var maps []memoryMap
	exePath := "" // Track the executable path

	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}

		// Format: 7f1234567000-7f1234568000 r-xp 00000000 08:01 12345 /lib/x86_64-linux-gnu/libc.so.6
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		addrRange := strings.Split(fields[0], "-")
		if len(addrRange) != 2 {
			continue
		}

		var m memoryMap
		fmt.Sscanf(addrRange[0], "%x", &m.start)
		fmt.Sscanf(addrRange[1], "%x", &m.end)
		m.perms = fields[1]
		fmt.Sscanf(fields[2], "%x", &m.offset) // Parse file offset

		if len(fields) > 5 {
			m.path = strings.Join(fields[5:], " ")

			// First executable mapping is usually the main executable
			if exePath == "" && !strings.HasPrefix(m.path, "[") && strings.Contains(m.perms, "x") {
				exePath = m.path
			}

			m.isExecutable = (m.path == exePath)
		}

		maps = append(maps, m)
	}

	return maps, nil
}

func resolvePC(pc uint64, maps []memoryMap) Frame {
	frame := Frame{
		PC:       pc,
		Function: fmt.Sprintf("0x%x", pc),
		Module:   "unknown",
	}

	// Find which memory region this PC belongs to
	for _, m := range maps {
		if pc >= m.start && pc < m.end {
			frame.Module = filepath.Base(m.path)
			if frame.Module == "" {
				frame.Module = "[anonymous]"
			}

			// Calculate ELF file offset
			// For executables: fileOffset = (pc - baseAddr) + mappingOffset
			// For shared libraries: fileOffset = (pc - baseAddr) + mappingOffset
			fileOffset := (pc - m.start) + m.offset

			frame.Offset = fileOffset

			// Try to resolve symbol from ELF
			if m.path != "" && !strings.HasPrefix(m.path, "[") {
				if sym := lookupSymbol(m.path, fileOffset); sym != "" {
					frame.Function = sym
				}
			}

			break
		}
	}

	return frame
}

// lookupSymbol finds the function name for a given offset in an ELF binary
func lookupSymbol(path string, offset uint64) string {
	// Check cache
	if cached, ok := cache[path]; ok {
		if sym, ok := cached.symbols[offset]; ok {
			return sym
		}
	}

	// Open ELF file
	f, err := elf.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	// Read symbol table
	symbols, err := f.Symbols()
	if err != nil {
		// Try dynamic symbols
		symbols, err = f.DynamicSymbols()
		if err != nil {
			return ""
		}
	}

	// Build cache for this binary
	sc := &symbolCache{
		symbols: make(map[uint64]string),
	}

	// Find the best matching symbol (closest but not exceeding offset)
	var bestSym *elf.Symbol
	var bestDist uint64 = ^uint64(0)

	for i := range symbols {
		sym := &symbols[i]

		// Skip non-function symbols
		if sym.Info&0xf != byte(elf.STT_FUNC) {
			continue
		}

		// Skip symbols with no name
		if sym.Name == "" {
			continue
		}

		// Symbol must start at or before our offset
		if sym.Value > offset {
			continue
		}

		dist := offset - sym.Value

		// Check if offset is within symbol bounds
		// Handle symbols with Size=0 by allowing small offset (< 4KB)
		withinBounds := false
		if sym.Size > 0 {
			withinBounds = dist < sym.Size
		} else {
			withinBounds = dist < 4096  // Allow 4KB for symbols with unknown size
		}

		if withinBounds && dist < bestDist {
			bestSym = sym
			bestDist = dist
		}
	}

	if bestSym != nil {
		name := bestSym.Name
		if bestDist > 0 {
			name = fmt.Sprintf("%s+0x%x", name, bestDist)
		}
		sc.symbols[offset] = name
		cache[path] = sc
		return name
	}

	return ""
}

// Format returns a human-readable stack trace string
func (st *StackTrace) Format() string {
	if len(st.Frames) == 0 {
		return "  (no stack trace captured)\n"
	}

	var sb strings.Builder
	for i, frame := range st.Frames {
		if frame.Function != "" && frame.Function != fmt.Sprintf("0x%x", frame.PC) {
			sb.WriteString(fmt.Sprintf("  #%-2d %s\n", i, frame.Function))
		} else {
			sb.WriteString(fmt.Sprintf("  #%-2d 0x%x\n", i, frame.PC))
		}

		if frame.Module != "unknown" && frame.Module != "" {
			sb.WriteString(fmt.Sprintf("      %s\n", frame.Module))
		}
	}
	return sb.String()
}

// FormatCompact returns a compact single-line stack trace
func (st *StackTrace) FormatCompact() string {
	if len(st.Frames) == 0 {
		return "(no stack)"
	}

	parts := []string{}
	for _, frame := range st.Frames {
		if frame.Function != "" && frame.Function != fmt.Sprintf("0x%x", frame.PC) {
			parts = append(parts, frame.Function)
		} else {
			parts = append(parts, fmt.Sprintf("0x%x", frame.PC))
		}

		if len(parts) >= 5 {
			break // Limit to top 5 frames for compact view
		}
	}

	return strings.Join(parts, " → ")
}
