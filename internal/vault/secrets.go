package vault

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/maxinielsen/secret-share/internal/crypto"
	"github.com/maxinielsen/secret-share/internal/drive"
)

// loadedSecret bundles a stored secret's container with its decrypted payload.
type loadedSecret struct {
	file    secretFile
	payload secretPayload
}

// validateSecretName rejects names that can't be used as a Drive filename. The
// name is stored in the clear (as the filename), so no characters are hidden.
func validateSecretName(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("secret name must not be empty")
	}
	if strings.ContainsAny(name, "/\\") {
		return fmt.Errorf("secret name %q must not contain slashes", name)
	}
	if strings.HasPrefix(name, ".") {
		return fmt.Errorf("secret name %q must not start with a dot", name)
	}
	return nil
}

// memberSignPubs returns the set of signing pubkeys of current members, used to
// reject secrets authored by non-members.
func (v *Vault) memberSignPubs() (map[string]string, error) {
	members, err := v.ListMembers()
	if err != nil {
		return nil, err
	}
	set := make(map[string]string, len(members))
	for _, m := range members {
		set[m.PublicKey.SignPub] = m.Name
	}
	return set, nil
}

// writeSecretFile encrypts payload to the current master and writes a signed
// container. The file is named after the secret (names are not encrypted).
func (v *Vault) writeSecretFile(name string, payload secretPayload) error {
	if v.master == nil {
		return fmt.Errorf("master key not loaded")
	}
	plain, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	ciphertext, err := crypto.EncryptSecret(v.meta.MasterRecipient, plain)
	if err != nil {
		return err
	}
	sf := secretFile{
		Name:       name,
		Ciphertext: ciphertext,
		Author:     v.selfName,
		AuthorPub:  v.self.Public().SignPub,
		Sig:        base64.StdEncoding.EncodeToString(crypto.Sign(v.self, ciphertext)),
	}
	data, err := json.MarshalIndent(sf, "", "  ")
	if err != nil {
		return err
	}
	return v.dc.WriteFile(v.secretPath(name), data)
}

// verifyAndDecrypt parses a stored container, checks the author signature and
// membership, decrypts the payload, and confirms the name matches the file it
// came from (defending against a file being swapped under a different name).
func verifyAndDecrypt(name string, data []byte, master *crypto.MasterKey, memberPubs map[string]string) (loadedSecret, error) {
	var sf secretFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return loadedSecret{}, fmt.Errorf("parse secret %q: %w", name, err)
	}
	sig, err := base64.StdEncoding.DecodeString(sf.Sig)
	if err != nil {
		return loadedSecret{}, fmt.Errorf("secret %q: bad signature encoding: %w", name, err)
	}
	if err := crypto.Verify(sf.AuthorPub, sf.Ciphertext, sig); err != nil {
		return loadedSecret{}, fmt.Errorf("secret %q: %w", name, err)
	}
	if _, ok := memberPubs[sf.AuthorPub]; !ok {
		return loadedSecret{}, fmt.Errorf("secret %q authored by a non-member key; refusing to trust", name)
	}
	plain, err := crypto.DecryptSecret(master, sf.Ciphertext)
	if err != nil {
		return loadedSecret{}, fmt.Errorf("decrypt secret %q: %w", name, err)
	}
	var p secretPayload
	if err := json.Unmarshal(plain, &p); err != nil {
		return loadedSecret{}, fmt.Errorf("parse secret payload %q: %w", name, err)
	}
	if p.Name != name {
		return loadedSecret{}, fmt.Errorf("secret %q: name inside ciphertext is %q (tampering?)", name, p.Name)
	}
	return loadedSecret{file: sf, payload: p}, nil
}

// getByName reads, verifies and decrypts a single secret by name. Cost is one
// member listing plus one download — independent of how many secrets exist.
func (v *Vault) getByName(name string) (*loadedSecret, error) {
	if err := v.loadMaster(); err != nil {
		return nil, err
	}
	data, err := v.dc.ReadFile(v.secretPath(name))
	if errors.Is(err, drive.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil // soft-deleted tombstone
	}
	memberPubs, err := v.memberSignPubs()
	if err != nil {
		return nil, err
	}
	ls, err := verifyAndDecrypt(name, data, v.master, memberPubs)
	if err != nil {
		return nil, err
	}
	return &ls, nil
}

// readAllSecrets loads, verifies and decrypts every secret. Used by rotation.
func (v *Vault) readAllSecrets() ([]loadedSecret, error) {
	if err := v.loadMaster(); err != nil {
		return nil, err
	}
	memberPubs, err := v.memberSignPubs()
	if err != nil {
		return nil, err
	}
	entries, err := v.dc.List(v.secretsDir())
	if err != nil {
		return nil, err
	}
	return parallelFetch(v.dc, liveAgeFiles(entries), func(e drive.Entry, data []byte) (loadedSecret, error) {
		return verifyAndDecrypt(secretName(e.Name), data, v.master, memberPubs)
	})
}

// secretName maps a stored filename back to the secret name.
func secretName(filename string) string {
	return strings.TrimSuffix(filename, ".age")
}

// SetSecret creates or updates the secret called name.
func (v *Vault) SetSecret(name, notes string, value []byte) error {
	if err := validateSecretName(name); err != nil {
		return err
	}
	if err := v.loadMaster(); err != nil {
		return err
	}
	now := nowStr()
	createdAt := now
	if existing, err := v.getByName(name); err != nil {
		return err
	} else if existing != nil {
		createdAt = existing.payload.CreatedAt // preserve original creation time
	}
	payload := secretPayload{
		SecretMeta: SecretMeta{
			Name:      name,
			Notes:     notes,
			Author:    v.selfName,
			CreatedAt: createdAt,
			UpdatedAt: now,
		},
		Value: value,
	}
	return v.writeSecretFile(name, payload)
}

// GetSecret returns the value and metadata of the named secret.
func (v *Vault) GetSecret(name string) ([]byte, *SecretMeta, error) {
	s, err := v.getByName(name)
	if err != nil {
		return nil, nil, err
	}
	if s == nil {
		return nil, nil, fmt.Errorf("secret %q not found", name)
	}
	meta := s.payload.SecretMeta
	return s.payload.Value, &meta, nil
}

// SecretInfo is the lightweight listing of a secret: its (cleartext) name and
// Drive modification time. Listing needs no downloads or decryption.
type SecretInfo struct {
	Name     string
	Modified string
}

// ListSecrets lists secret names without downloading or decrypting anything.
func (v *Vault) ListSecrets() ([]SecretInfo, error) {
	entries, err := v.dc.List(v.secretsDir())
	if err != nil {
		return nil, err
	}
	var infos []SecretInfo
	for _, e := range liveAgeFiles(entries) {
		infos = append(infos, SecretInfo{Name: secretName(e.Name), Modified: e.Modified})
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].Name < infos[j].Name })
	return infos, nil
}

// RemoveSecret deletes the named secret by path — a single call. Removing a
// name that doesn't exist is a no-op.
func (v *Vault) RemoveSecret(name string) error {
	if err := validateSecretName(name); err != nil {
		return err
	}
	return v.dc.Remove(v.secretPath(name))
}

// PurgeTombstones permanently deletes soft-deleted (size-0) secret files. It
// can only remove files the caller owns; files owned by other members are left
// for their owner to purge and counted in skipped.
func (v *Vault) PurgeTombstones() (purged, skipped int, err error) {
	entries, err := v.dc.List(v.secretsDir())
	if err != nil {
		return 0, 0, err
	}
	for _, e := range entries {
		if e.IsDir || !strings.HasSuffix(e.Name, ".age") || e.Size > 0 {
			continue
		}
		ok, err := v.dc.HardDeleteByID(e.ID)
		if err != nil {
			return purged, skipped, err
		}
		if ok {
			purged++
		} else {
			skipped++
		}
	}
	return purged, skipped, nil
}

// Meta exposes the (verified) manifest.
func (v *Vault) Meta() Meta { return *v.meta }
