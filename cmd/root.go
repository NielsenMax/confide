// Package cmd wires the CLI surface onto the vault, drive, crypto and keystore
// packages.
package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/maxinielsen/secret-share/internal/config"
	"github.com/maxinielsen/secret-share/internal/crypto"
	"github.com/maxinielsen/secret-share/internal/drive"
	"github.com/maxinielsen/secret-share/internal/keystore"
	"github.com/maxinielsen/secret-share/internal/vault"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// vaultFlag optionally overrides the default vault for a command.
var vaultFlag string

// rootCmd is the base command.
var rootCmd = &cobra.Command{
	Use:           "secret-share",
	Short:         "Share secrets with a team using Google Drive as an encrypted backend",
	SilenceUsage:  true,
	SilenceErrors: true,
	Long: `secret-share encrypts secrets to a per-vault master key, wraps that master
key to each member's public key, and stores everything in a shared Google Drive
folder. Members decrypt with their own private key; nobody else can read the data.`,
}

// ExecuteContext runs the CLI with the given context.
func ExecuteContext(ctx context.Context) {
	rootCmd.PersistentFlags().StringVar(&vaultFlag, "vault", "", "vault name (defaults to the configured default vault)")
	if err := rootCmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// --- shared helpers ---

// passphrasePrompt reads a passphrase from the terminal without echoing.
func passphrasePrompt(prompt string, confirm bool) (string, error) {
	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read passphrase: %w", err)
	}
	if confirm {
		fmt.Fprintf(os.Stderr, "Confirm passphrase: ")
		again, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("read passphrase: %w", err)
		}
		if string(pw) != string(again) {
			return "", fmt.Errorf("passphrases did not match")
		}
	}
	return string(pw), nil
}

// openKeystore builds the local keystore.
func openKeystore() (*keystore.Keystore, error) {
	dir, err := config.Dir()
	if err != nil {
		return nil, err
	}
	return keystore.New(dir, passphrasePrompt), nil
}

// loadIdentity loads the caller's identity, or errors if none exists.
func loadIdentity(ks *keystore.Keystore) (*crypto.Identity, error) {
	data, err := ks.GetIdentity()
	if err != nil {
		return nil, fmt.Errorf("no identity found (run `secret-share init`): %w", err)
	}
	return crypto.ParseIdentity(data)
}

// env bundles the common per-command dependencies.
type env struct {
	ctx  context.Context
	cfg  *config.Config
	ks   *keystore.Keystore
	self *crypto.Identity
	dc   *drive.Client
}

// setup wires config, keystore, identity and (if online) the Drive client.
func setup(cmd *cobra.Command, needDrive bool) (*env, error) {
	ks, err := openKeystore()
	if err != nil {
		return nil, err
	}
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	self, err := loadIdentity(ks)
	if err != nil {
		return nil, err
	}
	e := &env{ctx: cmd.Context(), cfg: cfg, ks: ks, self: self}
	if needDrive {
		dc, err := drive.New(e.ctx, ks, cfg)
		if err != nil {
			return nil, err
		}
		e.dc = dc
	}
	return e, nil
}

// resolveVaultName picks the vault from the flag or the config default.
func (e *env) resolveVaultName() (string, error) {
	if vaultFlag != "" {
		return vaultFlag, nil
	}
	if e.cfg.DefaultVault != "" {
		return e.cfg.DefaultVault, nil
	}
	return "", fmt.Errorf("no vault specified; pass --vault or set a default with `secret-share vault use <name>`")
}

// openVault opens the resolved vault bound to the caller's identity.
func (e *env) openVault() (*vault.Vault, error) {
	name, err := e.resolveVaultName()
	if err != nil {
		return nil, err
	}
	if e.cfg.MemberName == "" {
		return nil, fmt.Errorf("member name not set; run `secret-share init --name <you>`")
	}
	return vault.Open(e.dc, e.self, e.cfg.MemberName, name)
}
