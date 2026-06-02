package logger

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Dishank-Sen/Amon/internal/reports"
)

var (
	opLog *log.Logger
	logFile *os.File
)

// Init initializes the operational logger
func Init() error {
	logPath, err := reports.GetLogFile()
	if err != nil {
		return fmt.Errorf("failed to get log file path: %w", err)
	}

	// Open in append mode, create if doesn't exist
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	logFile = f
	opLog = log.New(f, "", 0) // No prefix, we'll format ourselves

	return nil
}

// Close closes the log file
func Close() {
	if logFile != nil {
		logFile.Close()
	}
}

func timestamp() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

// Info logs an informational message
func Info(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	opLog.Printf("[%s] INFO  %s", timestamp(), msg)
	fmt.Printf("ℹ️  %s\n", msg)
}

// Warn logs a warning message
func Warn(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	opLog.Printf("[%s] WARN  %s", timestamp(), msg)
	fmt.Printf("⚠️  %s\n", msg)
}

// Error logs an error message
func Error(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	opLog.Printf("[%s] ERROR %s", timestamp(), msg)
	fmt.Printf("❌ %s\n", msg)
}

// Fatal logs a fatal error and exits
func Fatal(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	opLog.Printf("[%s] FATAL %s", timestamp(), msg)
	fmt.Printf("💥 %s\n", msg)
	Close()
	os.Exit(1)
}

// Debug logs a debug message (only to file, not stdout)
func Debug(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	opLog.Printf("[%s] DEBUG %s", timestamp(), msg)
}

// Crash logs a crash event
func Crash(pid uint32, comm string, signal int32) {
	msg := fmt.Sprintf("Process crashed: PID=%d COMM=%s SIGNAL=%d", pid, comm, signal)
	opLog.Printf("[%s] CRASH %s", timestamp(), msg)
	fmt.Printf("🚨 %s\n", msg)
}
