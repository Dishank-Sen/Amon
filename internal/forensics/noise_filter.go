package forensics

import (
	"strings"

	"github.com/Dishank-Sen/Amon/types"
)

// KnownBenignPatterns filters out known-safe startup probes
var KnownBenignPatterns = []string{
	"pyvenv.cfg",
	"._pth",
	"pybuilddir.txt",
	".pyc",
	"__pycache__",
}

// IsNoiseEvent returns true if this is a known-benign startup event
func IsNoiseEvent(evt types.SyscallEvent) bool {
	// Only filter ENOENT errors from file operations
	if evt.Ret != -2 { // -2 is ENOENT
		return false
	}

	if evt.File == nil {
		return false
	}

	filename := evt.File.Filename

	// Check against known patterns
	for _, pattern := range KnownBenignPatterns {
		if strings.Contains(filename, pattern) {
			return true
		}
	}

	return false
}

// FilterNoise removes benign startup events from the event list
func FilterNoise(events []types.SyscallEvent) []types.SyscallEvent {
	filtered := make([]types.SyscallEvent, 0, len(events))

	for _, evt := range events {
		if !IsNoiseEvent(evt) {
			filtered = append(filtered, evt)
		}
	}

	return filtered
}

// CountNoise returns how many noise events were present
func CountNoise(events []types.SyscallEvent) int {
	count := 0
	for _, evt := range events {
		if IsNoiseEvent(evt) {
			count++
		}
	}
	return count
}
