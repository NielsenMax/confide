// Package vault implements the high-level secret store: vault creation, member
// management with key wrapping, signed authenticated records, and secret
// read/write — all layered over the crypto and drive packages.
package vault

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/maxinielsen/secret-share/internal/crypto"
	"github.com/maxinielsen/secret-share/internal/drive"
)

// Store is the minimal path-addressed backend the vault needs. *drive.Client
// implements it; tests supply an in-memory version.
type Store interface {
	ReadFile(path string) ([]byte, error)
	// Download fetches a file by the opaque ID returned in an Entry, avoiding a
	// second name lookup when the file was just listed.
	Download(id string) ([]byte, error)
	WriteFile(path string, data []byte) error
	List(dir string) ([]drive.Entry, error)
	Remove(path string) error
}

// formatVersion is the on-disk layout version stored in meta.
const formatVersion = 1

// Meta is the vault's public manifest. It is stored signed by an admin; the
// master recipient is public (used to encrypt secrets) while the master secret
// is only ever distributed wrapped, in keys/.
type Meta struct {
	Name            string   `json:"name"`
	FormatVersion   int      `json:"format_version"`
	MasterRecipient string   `json:"master_recipient"`
	AdminPubs       []string `json:"admin_pubs"` // ed25519 signing pubkeys allowed to admit members
	KeyEpoch        int      `json:"key_epoch"`  // bumped on every master-key rotation
	CreatedBy       string   `json:"created_by"`
	CreatedAt       string   `json:"created_at"`
}

// Member is a published member record (public keys only), stored signed by an
// admin so member sets cannot be forged on the shared drive.
type Member struct {
	Name      string           `json:"name"`
	PublicKey crypto.PublicKey `json:"public_key"`
	AddedBy   string           `json:"added_by"`
	AddedAt   string           `json:"added_at"`
}

// SecretMeta is the non-value metadata of a secret. It lives inside the
// ciphertext, so names never appear in the clear on Drive.
type SecretMeta struct {
	ID        string `json:"-"`
	Name      string `json:"name"`
	Notes     string `json:"notes,omitempty"`
	Author    string `json:"author"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// secretPayload is the full plaintext that gets encrypted to the master key.
type secretPayload struct {
	SecretMeta
	Value []byte `json:"value"`
}

// secretFile is the stored, signed container for one secret. The signature
// covers the ciphertext, authenticating the author without needing decryption.
type secretFile struct {
	ID         string `json:"id"`
	Ciphertext []byte `json:"ciphertext"`
	Author     string `json:"author"`
	AuthorPub  string `json:"author_pub"`
	Sig        string `json:"sig"`
}

// Vault is an opened vault bound to the caller's identity.
type Vault struct {
	dc       Store
	self     *crypto.Identity
	selfName string
	name     string
	meta     *Meta
	master   *crypto.MasterKey // recovered lazily
}

// Now is overridable in tests; production uses the wall clock.
var Now = func() time.Time { return time.Now().UTC() }

func nowStr() string { return Now().Format(time.RFC3339) }

// --- path helpers ---

func (v *Vault) metaPath() string          { return v.name + "/meta.json" }
func (v *Vault) membersDir() string         { return v.name + "/members" }
func (v *Vault) memberPath(n string) string { return v.membersDir() + "/" + sanitize(n) + ".json" }
func (v *Vault) keysDir() string            { return v.name + "/keys" }
func (v *Vault) keyPath(n string) string    { return v.keysDir() + "/" + sanitize(n) + ".age" }
func (v *Vault) secretsDir() string         { return v.name + "/secrets" }
func (v *Vault) secretPath(id string) string { return v.secretsDir() + "/" + id + ".age" }

// sanitize makes a name safe to use as a single path element.
func sanitize(name string) string {
	r := strings.NewReplacer("/", "_", "\\", "_", "..", "_", " ", "_")
	return r.Replace(strings.TrimSpace(name))
}

// Create initializes a brand-new vault, making the caller its sole admin and
// first member.
func Create(dc Store, self *crypto.Identity, selfName, vaultName string) (*Vault, error) {
	v := &Vault{dc: dc, self: self, selfName: sanitize(selfName), name: sanitize(vaultName)}
	if exists, err := v.exists(); err != nil {
		return nil, err
	} else if exists {
		return nil, fmt.Errorf("vault %q already exists", vaultName)
	}

	master, err := crypto.GenerateMasterKey()
	if err != nil {
		return nil, err
	}
	v.master = master
	v.meta = &Meta{
		Name:            v.name,
		FormatVersion:   formatVersion,
		MasterRecipient: master.Recipient(),
		AdminPubs:       []string{self.Public().SignPub},
		KeyEpoch:        1,
		CreatedBy:       v.selfName,
		CreatedAt:       nowStr(),
	}
	if err := v.writeMeta(); err != nil {
		return nil, err
	}
	if err := v.putMemberRecord(v.selfName, self.Public()); err != nil {
		return nil, err
	}
	if err := v.wrapMasterFor(v.selfName, self.Public().AgeRecipient); err != nil {
		return nil, err
	}
	return v, nil
}

// Open loads an existing vault and verifies its manifest signature.
func Open(dc Store, self *crypto.Identity, selfName, vaultName string) (*Vault, error) {
	v := &Vault{dc: dc, self: self, selfName: sanitize(selfName), name: sanitize(vaultName)}
	data, err := dc.ReadFile(v.metaPath())
	if errors.Is(err, drive.ErrNotFound) {
		return nil, fmt.Errorf("vault %q not found", vaultName)
	}
	if err != nil {
		return nil, err
	}
	var meta Meta
	signerPub, _, err := openEnvelope(data, &meta)
	if err != nil {
		return nil, fmt.Errorf("meta: %w", err)
	}
	// The manifest must be self-consistent: its signer is one of its admins.
	if !contains(meta.AdminPubs, signerPub) {
		return nil, fmt.Errorf("meta signed by a non-admin key; refusing to trust")
	}
	v.meta = &meta
	return v, nil
}

func (v *Vault) exists() (bool, error) {
	_, err := v.dc.ReadFile(v.metaPath())
	if errors.Is(err, drive.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (v *Vault) writeMeta() error {
	v.meta.FormatVersion = formatVersion
	data, err := seal(v.self, v.selfName, v.meta)
	if err != nil {
		return err
	}
	return v.dc.WriteFile(v.metaPath(), data)
}

// isAdmin reports whether the caller's signing key is an admin of this vault.
func (v *Vault) isAdmin() bool {
	return contains(v.meta.AdminPubs, v.self.Public().SignPub)
}

func (v *Vault) putMemberRecord(name string, pub crypto.PublicKey) error {
	m := Member{Name: name, PublicKey: pub, AddedBy: v.selfName, AddedAt: nowStr()}
	data, err := seal(v.self, v.selfName, m)
	if err != nil {
		return err
	}
	return v.dc.WriteFile(v.memberPath(name), data)
}

func (v *Vault) wrapMasterFor(name, ageRecipient string) error {
	if v.master == nil {
		return fmt.Errorf("master key not loaded")
	}
	wrapped, err := crypto.WrapMasterKey(v.master, ageRecipient)
	if err != nil {
		return err
	}
	return v.dc.WriteFile(v.keyPath(name), wrapped)
}

// loadMaster recovers the master key by unwrapping the caller's key blob.
func (v *Vault) loadMaster() error {
	if v.master != nil {
		return nil
	}
	wrapped, err := v.dc.ReadFile(v.keyPath(v.selfName))
	if errors.Is(err, drive.ErrNotFound) {
		return fmt.Errorf("you are not a member of vault %q (no wrapped key for %q)", v.name, v.selfName)
	}
	if err != nil {
		return err
	}
	master, err := crypto.UnwrapMasterKey(wrapped, v.self)
	if err != nil {
		return err
	}
	// Sanity check: the unwrapped key must match the advertised recipient.
	if master.Recipient() != v.meta.MasterRecipient {
		return fmt.Errorf("unwrapped master key does not match vault manifest (tampering?)")
	}
	v.master = master
	return nil
}

// ListMembers returns all verified member records. Records are downloaded
// concurrently by ID.
func (v *Vault) ListMembers() ([]Member, error) {
	entries, err := v.dc.List(v.membersDir())
	if err != nil {
		return nil, err
	}
	return parallelFetch(v.dc, files(entries), func(e drive.Entry, data []byte) (Member, error) {
		var m Member
		signerPub, _, err := openEnvelope(data, &m)
		if err != nil {
			return m, fmt.Errorf("member %q: %w", e.Name, err)
		}
		if !contains(v.meta.AdminPubs, signerPub) {
			return m, fmt.Errorf("member record %q not signed by an admin", e.Name)
		}
		return m, nil
	})
}

// AddMember admits a new member: it publishes their signed record and wraps the
// master key to their age recipient. Requires admin rights and the master key.
func (v *Vault) AddMember(name string, pub crypto.PublicKey) error {
	if !v.isAdmin() {
		return fmt.Errorf("only an admin can add members")
	}
	if err := v.loadMaster(); err != nil {
		return err
	}
	name = sanitize(name)
	if err := v.putMemberRecord(name, pub); err != nil {
		return err
	}
	return v.wrapMasterFor(name, pub.AgeRecipient)
}

// RemoveMember revokes a member by ROTATING the master key: it generates a new
// master keypair, re-encrypts every secret to it, re-wraps to the remaining
// members, updates the manifest epoch, and deletes the removed member's files.
//
// This is the only true revocation. Secret VALUES the removed member already
// read are not retroactively secret — rotate those values separately.
func (v *Vault) RemoveMember(name string) error {
	if !v.isAdmin() {
		return fmt.Errorf("only an admin can remove members")
	}
	name = sanitize(name)
	if name == v.selfName {
		return fmt.Errorf("refusing to remove yourself")
	}
	if err := v.loadMaster(); err != nil {
		return err
	}
	members, err := v.ListMembers()
	if err != nil {
		return err
	}
	var remaining []Member
	found := false
	for _, m := range members {
		if m.Name == name {
			found = true
			continue
		}
		remaining = append(remaining, m)
	}
	if !found {
		return fmt.Errorf("member %q not found", name)
	}

	// Load all secrets under the OLD master before rotating.
	secrets, err := v.readAllSecrets()
	if err != nil {
		return err
	}

	// New master key.
	newMaster, err := crypto.GenerateMasterKey()
	if err != nil {
		return err
	}
	oldMaster := v.master
	v.master = newMaster
	v.meta.MasterRecipient = newMaster.Recipient()
	v.meta.KeyEpoch++

	// Re-encrypt every secret to the new master (concurrent writes to distinct
	// files). v.master/v.meta are set above and only read from here on.
	if err := parallelDo(secrets, func(s loadedSecret) error {
		return v.writeSecretFile(s.file.ID, s.payload)
	}); err != nil {
		v.master = oldMaster // best-effort rollback of in-memory state
		return fmt.Errorf("re-encrypt secret during rotation: %w", err)
	}
	// Re-wrap for remaining members, then refresh the manifest.
	if err := parallelDo(remaining, func(m Member) error {
		return v.wrapMasterFor(m.Name, m.PublicKey.AgeRecipient)
	}); err != nil {
		return fmt.Errorf("re-wrap during rotation: %w", err)
	}
	if err := v.writeMeta(); err != nil {
		return err
	}
	// Finally, delete the removed member's access and record.
	if err := v.dc.Remove(v.keyPath(name)); err != nil {
		return err
	}
	return v.dc.Remove(v.memberPath(name))
}

func contains(xs []string, x string) bool {
	for _, e := range xs {
		if e == x {
			return true
		}
	}
	return false
}
