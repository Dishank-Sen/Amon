package types

type Config struct {
    TrackedCommands []string `yaml:"tracked_commands"`
    IgnoredCommands []string `yaml:"ignored_commands"`
    EventsThreshold int      `yaml:"events_threshold"`

    Events struct {
        FileOpen    bool `yaml:"file_open"`
        FileWrite   bool `yaml:"file_write"`
        ProcessExec bool `yaml:"process_exec"`
    } `yaml:"events"`
}

type SyscallEvent struct {
    // core fields above
    Type      string
    PID       uint32
    Timestamp uint64
    Latency   uint64
    Ret       int64  // return value 0, -1, etc.

    // syscall-specific data
    // only one of these is populated per event
    File    *FileData
    Network *NetworkData
    Process *ProcessData
}

type FileData struct {
    Filename string
    Flags    uint32    // O_RDONLY, O_WRONLY etc — tells you intent
    FD       int32     // file descriptor returned
}

type NetworkData struct {
    DstIP   [4]byte
    DstPort uint16
    FD      int32
}

type ProcessData struct {
    ChildPID  uint32
    ChildComm [16]byte
    Binary    string    // full path of exec'd binary
}