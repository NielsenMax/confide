// Package keystore persists sensitive local material — the member identity and
// the OAuth token — preferring the OS keychain and falling back to
// passphrase-encrypted files when no keychain is available.
package keystore

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"filippo.io/age"
	"github.com/zalando/go-keyring"
)

const service = "secret-share"

// Entry names.
const (
	entryIdentity = "identity"
	entryToken    = "oauth-token"
)

// ErrNotFound is returned when a requested entry does not exist.
var ErrNotFound = errors.New("keystore: entry not found")

// PassphraseFunc supplies the passphrase used to protect the file fallback.
// The confirm flag requests a second entry (used when creating new material).
type PassphraseFunc func(prompt string, confirm bool) (string, error)

// Keystore reads and writes local secrets.
type Keystore struct {
	dir         string         // directory for the file fallback
	passphrase  PassphraseFunc // used only by the file backend
	useKeychain bool
}

// New returns a Keystore rooted at dir, using pf for the file fallback.
func New(dir string, pf PassphraseFunc) *Keystore {
	return &Keystore{dir: dir, passphrase: pf, useKeychain: keychainAvailable()}
}

// keychainAvailable probes the OS keychain with a throwaway entry.
func keychainAvailable() bool {
	const probe = "__probe__"
	if err := keyring.Set(service, probe, "1"); err != nil {
		return false
	}
	_, err := keyring.Get(service, probe)
	_ = keyring.Delete(service, probe)
	return err == nil
}

// Backend returns a human-readable description of the active backend.
func (k *Keystore) Backend() string {
	if k.useKeychain {
		return "OS keychain"
	}
	return "encrypted file (" + k.dir + ")"
}

// SetIdentity stores the marshaled member identity (secret).
func (k *Keystore) SetIdentity(data []byte) error { return k.set(entryIdentity, data, true) }

// GetIdentity loads the marshaled member identity, or ErrNotFound.
func (k *Keystore) GetIdentity() ([]byte, error) { return k.get(entryIdentity, true) }

// HasIdentity reports whether an identity is stored.
func (k *Keystore) HasIdentity() bool {
	_, err := k.GetIdentity()
	return err == nil
}

// SetToken stores the OAuth token JSON (secret: contains a refresh token).
func (k *Keystore) SetToken(data []byte) error { return k.set(entryToken, data, true) }

// GetToken loads the OAuth token JSON, or ErrNotFound.
func (k *Keystore) GetToken() ([]byte, error) { return k.get(entryToken, true) }

// set stores data under name. secret controls file-fallback encryption.
func (k *Keystore) set(name string, data []byte, secret bool) error {
	if k.useKeychain {
		return keyring.Set(service, name, base64.StdEncoding.EncodeToString(data))
	}
	return k.fileSet(name, data, secret)
}

// get loads data stored under name.
func (k *Keystore) get(name string, secret bool) ([]byte, error) {
	if k.useKeychain {
		s, err := keyring.Get(service, name)
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, ErrNotFound
		}
		if err != nil {
			return nil, fmt.Errorf("keychain get %s: %w", name, err)
		}
		return base64.StdEncoding.DecodeString(s)
	}
	return k.fileGet(name, secret)
}

// Delete removes an entry from whichever backend is active.
func (k *Keystore) Delete(name string) error {
	if k.useKeychain {
		if err := keyring.Delete(service, name); err != nil && !errors.Is(err, keyring.ErrNotFound) {
			return err
		}
		return nil
	}
	err := os.Remove(k.filePath(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (k *Keystore) filePath(name string) string {
	return filepath.Join(k.dir, name+".enc")
}

// fileSet writes data to a 0600 file, encrypting with a passphrase when secret.
func (k *Keystore) fileSet(name string, data []byte, secret bool) error {
	if err := os.MkdirAll(k.dir, 0o700); err != nil {
		return err
	}
	out := data
	if secret {
		enc, err := k.encryptWithPassphrase(name, data)
		if err != nil {
			return err
		}
		out = enc
	}
	return os.WriteFile(k.filePath(name), out, 0o600)
}

// fileGet reads data from a file, decrypting with a passphrase when secret.
func (k *Keystore) fileGet(name string, secret bool) ([]byte, error) {
	data, err := os.ReadFile(k.filePath(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if !secret {
		return data, nil
	}
	pass, err := k.passphrase(fmt.Sprintf("Passphrase to unlock %s", name), false)
	if err != nil {
		return nil, err
	}
	idr, err := age.NewScryptIdentity(pass)
	if err != nil {
		return nil, err
	}
	r, err := age.Decrypt(bytes.NewReader(data), idr)
	if err != nil {
		return nil, fmt.Errorf("decrypt %s (wrong passphrase?): %w", name, err)
	}
	return io.ReadAll(r)
}

func (k *Keystore) encryptWithPassphrase(name string, data []byte) ([]byte, error) {
	pass, err := k.passphrase(fmt.Sprintf("Set a passphrase to protect %s", name), true)
	if err != nil {
		return nil, err
	}
	rcpt, err := age.NewScryptRecipient(pass)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, rcpt)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
