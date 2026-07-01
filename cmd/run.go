package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/maxinielsen/confide/internal/vault"
	"github.com/spf13/cobra"
)

var envPrefix string

// envKey converts a secret name into a valid shell environment variable name:
// uppercased, non-alphanumeric runs replaced with underscores, prefixed if it
// would otherwise start with a digit.
func envKey(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r - 32)
		case (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	s := b.String()
	if s == "" || (s[0] >= '0' && s[0] <= '9') {
		s = "_" + s
	}
	return s
}

// secretsAsEnv builds KEY=value strings for all secrets in the vault.
func secretsAsEnv(vals []vault.SecretValue) []string {
	env := make([]string, 0, len(vals))
	for _, s := range vals {
		env = append(env, envPrefix+envKey(s.Name)+"="+string(s.Value))
	}
	return env
}

// shellQuote single-quotes a value so it is safe inside `eval`.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

var envCmd = &cobra.Command{
	Use:   "env",
	Short: "Print secrets as shell export lines (use with: eval \"$(confide env)\")",
	RunE: func(cmd *cobra.Command, args []string) error {
		e, err := setup(cmd, true)
		if err != nil {
			return err
		}
		v, err := e.openVault()
		if err != nil {
			return err
		}
		vals, err := v.AllSecrets()
		if err != nil {
			return err
		}
		for _, s := range vals {
			fmt.Printf("export %s%s=%s\n", envPrefix, envKey(s.Name), shellQuote(string(s.Value)))
		}
		return nil
	},
}

var runCmd = &cobra.Command{
	Use:   "run -- <command> [args...]",
	Short: "Run a command with the vault's secrets injected as environment variables",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		e, err := setup(cmd, true)
		if err != nil {
			return err
		}
		v, err := e.openVault()
		if err != nil {
			return err
		}
		vals, err := v.AllSecrets()
		if err != nil {
			return err
		}
		child := exec.Command(args[0], args[1:]...)
		child.Env = append(os.Environ(), secretsAsEnv(vals)...)
		child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := child.Run(); err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				os.Exit(ee.ExitCode()) // propagate the child's exit code
			}
			return fmt.Errorf("run %q: %w", args[0], err)
		}
		return nil
	},
}

func init() {
	envCmd.Flags().StringVar(&envPrefix, "prefix", "", "prefix for generated variable names")
	runCmd.Flags().StringVar(&envPrefix, "prefix", "", "prefix for generated variable names")
	rootCmd.AddCommand(envCmd, runCmd)
}
