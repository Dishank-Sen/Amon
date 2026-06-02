package types

type Config struct {
    TrackedCommands []string `yaml:"tracked_commands"`
    IgnoredCommands []string `yaml:"ignored_commands"`

    Events struct {
        FileOpen    bool `yaml:"file_open"`
        FileWrite   bool `yaml:"file_write"`
        ProcessExec bool `yaml:"process_exec"`
    } `yaml:"events"`
}