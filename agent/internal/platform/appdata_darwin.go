package platform

import (
	"os"
	"path/filepath"
)

func appDataDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "Application Support", "BifrostAgent")
}
