package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

var (
	installDir     string
	installAddPath bool
)

// defaultInstallDir returns the preferred install location: ~/.local/bin, which
// needs no sudo and is a conventional user bin directory.
func defaultInstallDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".local", "bin")
}

// binaryName is the installed file name for the current OS.
func binaryName() string {
	if runtime.GOOS == "windows" {
		return "confide.exe"
	}
	return "confide"
}

// onPath reports whether dir is currently in $PATH.
func onPath(dir string) bool {
	for _, p := range filepath.SplitList(os.Getenv("PATH")) {
		if p == dir {
			return true
		}
	}
	return false
}

// shellRC returns the rc file and export line to put dir on PATH for the user's
// shell, plus whether the shell is recognized.
func shellRC(dir string) (rcPath, line string, ok bool) {
	home, _ := os.UserHomeDir()
	shell := filepath.Base(os.Getenv("SHELL"))
	switch shell {
	case "zsh":
		return filepath.Join(home, ".zshrc"), fmt.Sprintf("export PATH=%q:$PATH", dir), true
	case "bash":
		return filepath.Join(home, ".bashrc"), fmt.Sprintf("export PATH=%q:$PATH", dir), true
	case "fish":
		return filepath.Join(home, ".config", "fish", "config.fish"), fmt.Sprintf("fish_add_path %q", dir), true
	default:
		return "", fmt.Sprintf("export PATH=%q:$PATH", dir), false
	}
}

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install the confide binary onto your PATH",
	Long: `install copies the running confide binary to a directory on your PATH
(default ~/.local/bin) so you can run it as 'confide' from anywhere.

With --add-path it also appends the directory to your shell's rc file if it
isn't already on PATH.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		src, err := os.Executable()
		if err != nil {
			return fmt.Errorf("locate running binary: %w", err)
		}
		if resolved, err := filepath.EvalSymlinks(src); err == nil {
			src = resolved
		}

		dir := installDir
		if dir == "" {
			dir = defaultInstallDir()
		}
		if dir == "" {
			return fmt.Errorf("could not determine an install directory; pass --dir")
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
		dest := filepath.Join(dir, binaryName())

		if src == dest {
			fmt.Printf("Already installed at %s\n", dest)
		} else {
			data, err := os.ReadFile(src)
			if err != nil {
				return fmt.Errorf("read binary: %w", err)
			}
			// Write to a temp file in the same dir, then rename for atomicity
			// (and so we don't corrupt a running copy).
			tmp := dest + ".tmp"
			if err := os.WriteFile(tmp, data, 0o755); err != nil {
				return fmt.Errorf("write %s: %w", tmp, err)
			}
			if err := os.Rename(tmp, dest); err != nil {
				os.Remove(tmp)
				return fmt.Errorf("install to %s: %w", dest, err)
			}
			fmt.Printf("Installed confide to %s\n", dest)
		}

		if onPath(dir) {
			fmt.Println("It's on your PATH — run `confide` from anywhere.")
			return nil
		}

		rcPath, line, known := shellRC(dir)
		if installAddPath && known {
			if err := appendLine(rcPath, line); err != nil {
				return fmt.Errorf("update %s: %w", rcPath, err)
			}
			fmt.Printf("Added %s to PATH in %s.\n", dir, rcPath)
			fmt.Printf("Run `source %s` or open a new terminal.\n", rcPath)
			return nil
		}

		fmt.Printf("\n%s isn't on your PATH. Add it with:\n\n  %s\n", dir, line)
		if known {
			fmt.Printf("\n(or re-run with --add-path to append that to %s)\n", rcPath)
		}
		return nil
	},
}

// appendLine appends line to a file, creating it if needed and avoiding a
// duplicate if the exact line is already present.
func appendLine(path, line string) error {
	if data, err := os.ReadFile(path); err == nil {
		for _, existing := range strings.Split(string(data), "\n") {
			if strings.TrimSpace(existing) == line {
				return nil // already there
			}
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "\n# added by `confide install`\n%s\n", line)
	return err
}

func init() {
	installCmd.Flags().StringVar(&installDir, "dir", "", "install directory (default ~/.local/bin)")
	installCmd.Flags().BoolVar(&installAddPath, "add-path", false, "append the install dir to your shell rc if not on PATH")
	rootCmd.AddCommand(installCmd)
}
