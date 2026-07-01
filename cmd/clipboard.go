package cmd

import (
	"bytes"
	"fmt"
	"os/exec"
	"runtime"
)

// copyToClipboard writes data to the system clipboard using the platform's
// native utility, so secrets don't land in terminal scrollback or shell history.
func copyToClipboard(data []byte) error {
	var candidates [][]string
	switch runtime.GOOS {
	case "darwin":
		candidates = [][]string{{"pbcopy"}}
	case "windows":
		candidates = [][]string{{"clip"}}
	default: // linux, bsd
		candidates = [][]string{
			{"wl-copy"},
			{"xclip", "-selection", "clipboard"},
			{"xsel", "--clipboard", "--input"},
		}
	}
	var lastErr error
	for _, argv := range candidates {
		if _, err := exec.LookPath(argv[0]); err != nil {
			lastErr = err
			continue
		}
		c := exec.Command(argv[0], argv[1:]...)
		c.Stdin = bytes.NewReader(data)
		if err := c.Run(); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	if lastErr != nil {
		return fmt.Errorf("no clipboard tool available (install xclip/xsel/wl-clipboard): %w", lastErr)
	}
	return fmt.Errorf("no clipboard tool available")
}
