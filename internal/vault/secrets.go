package vault

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/maxinielsen/secret-share/internal/crypto"
)

// loadedSecret bundles a stored secret's container with its decrypted payload.
type loadedSecret struct {
	file    secretFile
	payload secretPayload
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
// container under the given id.
func (v *Vault) writeSecretFile(id string, payload secretPayload) error {
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
		ID:         id,
		Ciphertext: ciphertext,
		Author:     v.selfName,
		AuthorPub:  v.self.Public().SignPub,
		Sig:        base64.StdEncoding.EncodeToString(crypto.Sign(v.self, ciphertext)),
	}
	data, err := json.MarshalIndent(sf, "", "  ")
	if err != nil {
		return err
	}
	return v.dc.WriteFile(v.secretPath(id), data)
}

// readAllSecrets loads, verifies and decrypts every secret in the vault.
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
	var out []loadedSecret
	for _, e := range entries {
		if e.IsDir || !strings.HasSuffix(e.Name, ".age") {
			continue
		}
		data, err := v.dc.ReadFile(v.secretsDir() + "/" + e.Name)
		if err != nil {
			return nil, err
		}
		var sf secretFile
		if err := json.Unmarshal(data, &sf); err != nil {
			return nil, fmt.Errorf("parse secret %q: %w", e.Name, err)
		}
		sig, err := base64.StdEncoding.DecodeString(sf.Sig)
		if err != nil {
			return nil, fmt.Errorf("secret %q: bad signature encoding: %w", e.Name, err)
		}
		if err := crypto.Verify(sf.AuthorPub, sf.Ciphertext, sig); err != nil {
			return nil, fmt.Errorf("secret %q: %w", e.Name, err)
		}
		if _, ok := memberPubs[sf.AuthorPub]; !ok {
			return nil, fmt.Errorf("secret %q authored by a non-member key; refusing to trust", e.Name)
		}
		plain, err := crypto.DecryptSecret(v.master, sf.Ciphertext)
		if err != nil {
			return nil, fmt.Errorf("decrypt secret %q: %w", e.Name, err)
		}
		var p secretPayload
		if err := json.Unmarshal(plain, &p); err != nil {
			return nil, fmt.Errorf("parse secret payload %q: %w", e.Name, err)
		}
		p.ID = sf.ID
		out = append(out, loadedSecret{file: sf, payload: p})
	}
	return out, nil
}

// findByName returns the loaded secret whose name matches (case-sensitive).
func (v *Vault) findByName(name string) (*loadedSecret, error) {
	secrets, err := v.readAllSecrets()
	if err != nil {
		return nil, err
	}
	for i := range secrets {
		if secrets[i].payload.Name == name {
			return &secrets[i], nil
		}
	}
	return nil, nil
}

// SetSecret creates or updates the secret called name.
func (v *Vault) SetSecret(name, notes string, value []byte) error {
	if err := v.loadMaster(); err != nil {
		return err
	}
	existing, err := v.findByName(name)
	if err != nil {
		return err
	}
	now := nowStr()
	var payload secretPayload
	if existing != nil {
		payload = existing.payload
		payload.Notes = notes
		payload.Value = value
		payload.Author = v.selfName
		payload.UpdatedAt = now
		return v.writeSecretFile(existing.file.ID, payload)
	}
	payload = secretPayload{
		SecretMeta: SecretMeta{
			Name:      name,
			Notes:     notes,
			Author:    v.selfName,
			CreatedAt: now,
			UpdatedAt: now,
		},
		Value: value,
	}
	return v.writeSecretFile(uuid.NewString(), payload)
}

// GetSecret returns the value and metadata of the named secret.
func (v *Vault) GetSecret(name string) ([]byte, *SecretMeta, error) {
	s, err := v.findByName(name)
	if err != nil {
		return nil, nil, err
	}
	if s == nil {
		return nil, nil, fmt.Errorf("secret %q not found", name)
	}
	meta := s.payload.SecretMeta
	return s.payload.Value, &meta, nil
}

// ListSecrets returns metadata for all secrets, sorted by name.
func (v *Vault) ListSecrets() ([]SecretMeta, error) {
	secrets, err := v.readAllSecrets()
	if err != nil {
		return nil, err
	}
	metas := make([]SecretMeta, 0, len(secrets))
	for _, s := range secrets {
		metas = append(metas, s.payload.SecretMeta)
	}
	sort.Slice(metas, func(i, j int) bool { return metas[i].Name < metas[j].Name })
	return metas, nil
}

// RemoveSecret deletes the named secret.
func (v *Vault) RemoveSecret(name string) error {
	s, err := v.findByName(name)
	if err != nil {
		return err
	}
	if s == nil {
		return fmt.Errorf("secret %q not found", name)
	}
	return v.dc.Remove(v.secretPath(s.file.ID))
}

// Meta exposes the (verified) manifest.
func (v *Vault) Meta() Meta { return *v.meta }
