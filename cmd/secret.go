package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	setNotes string
	setFile  string
	setEdit  bool
	getMeta  bool
)

// readSecretValue obtains the secret bytes. Precedence: --file, then --edit
// ($EDITOR), then (for a TTY) a hidden single-line prompt, else stdin to EOF.
// initial pre-populates the editor with an existing secret's value (--edit only).
func readSecretValue(initial []byte) ([]byte, error) {
	if setFile != "" {
		if setFile == "-" {
			return io.ReadAll(os.Stdin)
		}
		return os.ReadFile(setFile)
	}
	if setEdit {
		return editorValue(initial)
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		v, err := passphrasePrompt("Secret value", false)
		if err != nil {
			return nil, err
		}
		return []byte(v), nil
	}
	return io.ReadAll(os.Stdin)
}

// editorValue opens $EDITOR on a temporary file seeded with initial and returns
// its contents. The temp file holds the secret in plaintext briefly; it is
// created 0600 and removed immediately after.
func editorValue(initial []byte) ([]byte, error) {
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi"
	}
	f, err := os.CreateTemp("", "secret-share-*.txt")
	if err != nil {
		return nil, err
	}
	tmp := f.Name()
	if len(initial) > 0 {
		if _, err := f.Write(initial); err != nil {
			f.Close()
			os.Remove(tmp)
			return nil, err
		}
	}
	f.Close()
	defer os.Remove(tmp)

	parts := strings.Fields(editor)
	c := exec.Command(parts[0], append(parts[1:], tmp)...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		return nil, fmt.Errorf("editor %q failed: %w", editor, err)
	}
	data, err := os.ReadFile(tmp)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("empty secret; aborting")
	}
	return data, nil
}

var setCmd = &cobra.Command{
	Use:   "set <name>",
	Short: "Create or update a secret",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		e, err := setup(cmd, true)
		if err != nil {
			return err
		}
		v, err := e.openVault()
		if err != nil {
			return err
		}
		// When editing, seed the editor with the current value if the secret
		// already exists (ignore "not found" — that just means a new secret).
		var initial []byte
		if setEdit {
			if val, _, err := v.GetSecret(args[0]); err == nil {
				initial = val
			}
		}
		value, err := readSecretValue(initial)
		if err != nil {
			return err
		}
		if setEdit && initial != nil && bytes.Equal(value, initial) {
			fmt.Fprintf(os.Stderr, "No changes; secret %q left as-is.\n", args[0])
			return nil
		}
		if err := v.SetSecret(args[0], setNotes, value); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Stored secret %q.\n", args[0])
		return nil
	},
}

var getCmd = &cobra.Command{
	Use:   "get <name>",
	Short: "Print a secret's value to stdout",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		e, err := setup(cmd, true)
		if err != nil {
			return err
		}
		v, err := e.openVault()
		if err != nil {
			return err
		}
		value, meta, err := v.GetSecret(args[0])
		if err != nil {
			return err
		}
		if getMeta {
			fmt.Fprintf(os.Stderr, "name:    %s\nnotes:   %s\nauthor:  %s\nupdated: %s\n",
				meta.Name, meta.Notes, meta.Author, meta.UpdatedAt)
		}
		os.Stdout.Write(value)
		return nil
	},
}

var lsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List secrets in the current vault",
	RunE: func(cmd *cobra.Command, args []string) error {
		e, err := setup(cmd, true)
		if err != nil {
			return err
		}
		v, err := e.openVault()
		if err != nil {
			return err
		}
		metas, err := v.ListSecrets()
		if err != nil {
			return err
		}
		for _, m := range metas {
			fmt.Printf("  %-24s (by %s, updated %s)\n", m.Name, m.Author, m.UpdatedAt)
		}
		if len(metas) == 0 {
			fmt.Println("No secrets yet. Add one with `secret-share set <name>`.")
		}
		return nil
	},
}

var rmCmd = &cobra.Command{
	Use:   "rm <name>",
	Short: "Delete a secret",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		e, err := setup(cmd, true)
		if err != nil {
			return err
		}
		v, err := e.openVault()
		if err != nil {
			return err
		}
		if err := v.RemoveSecret(args[0]); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Deleted secret %q.\n", args[0])
		return nil
	},
}

func init() {
	setCmd.Flags().StringVar(&setNotes, "notes", "", "optional note stored with the secret")
	setCmd.Flags().StringVar(&setFile, "file", "", "read value from a file ('-' for stdin)")
	setCmd.Flags().BoolVarP(&setEdit, "edit", "e", false, "compose a multi-line value in $EDITOR")
	getCmd.Flags().BoolVar(&getMeta, "meta", false, "also print metadata to stderr")
	rootCmd.AddCommand(setCmd, getCmd, lsCmd, rmCmd)
}
