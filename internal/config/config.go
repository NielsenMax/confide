// Package config manages on-disk application configuration and standard paths.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// appDir is the subdirectory used under the user's config dir.
const appDir = "secret-share"

// Config is the persisted, non-secret application configuration.
//
// It records where the shared vault store lives on Google Drive. Secrets and
// private keys are NEVER stored here; only pointers and public identifiers.
type Config struct {
	// RootFolderID is the Drive file ID of the "SecretShare" folder that
	// contains all vaults. Empty until `init`/`vault create` has run.
	RootFolderID string `json:"root_folder_id,omitempty"`

	// DriveID is the ID of a Shared Drive (Team Drive) when the store lives on
	// one. Empty means the folder lives in the user's regular "My Drive".
	DriveID string `json:"drive_id,omitempty"`

	// DefaultVault is the vault used when a command omits --vault.
	DefaultVault string `json:"default_vault,omitempty"`

	// MemberName is the caller's display/member name within vaults.
	MemberName string `json:"member_name,omitempty"`
}

// Dir returns the application config directory, creating it if needed.
func Dir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate user config dir: %w", err)
	}
	dir := filepath.Join(base, appDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create config dir: %w", err)
	}
	return dir, nil
}

func path() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

// Load reads the config from disk, returning a zero-valued Config if none exists.
func Load() (*Config, error) {
	p, err := path()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return &Config{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &c, nil
}

// Save writes the config to disk with restrictive permissions.
func (c *Config) Save() error {
	p, err := path()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}
