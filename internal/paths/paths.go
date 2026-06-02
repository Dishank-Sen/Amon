package paths

import (
	"os"
	"os/user"
	"path/filepath"
)

func RootDir() string {
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		u, err := user.Lookup(sudoUser)
		if err == nil {
			return filepath.Join(u.HomeDir, ".amon")
		}
	}

	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".amon")
}

func ConfigFile() string {
	return filepath.Join(RootDir(), "config.yaml")
}

func LogFile() string {
	return filepath.Join(RootDir(), "amon.log")
}