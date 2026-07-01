package vault

import (
	"bytes"
	"strings"
	"testing"

	"github.com/maxinielsen/secret-share/internal/crypto"
	"github.com/maxinielsen/secret-share/internal/drive"
)

// memStore is an in-memory implementation of Store for tests. It keys files by
// full slash-path and synthesizes directory listings.
type memStore struct {
	files map[string][]byte
}

func newMemStore() *memStore { return &memStore{files: map[string][]byte{}} }

func (m *memStore) WriteFile(path string, data []byte) error {
	cp := make([]byte, len(data))
	copy(cp, data)
	m.files[strings.Trim(path, "/")] = cp
	return nil
}

func (m *memStore) ReadFile(path string) ([]byte, error) {
	data, ok := m.files[strings.Trim(path, "/")]
	if !ok {
		return nil, drive.ErrNotFound
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	return cp, nil
}

func (m *memStore) Remove(path string) error {
	delete(m.files, strings.Trim(path, "/"))
	return nil
}

// Download uses the full path as the entry ID (see List below).
func (m *memStore) Download(id string) ([]byte, error) {
	return m.ReadFile(id)
}

func (m *memStore) List(dir string) ([]drive.Entry, error) {
	dir = strings.Trim(dir, "/")
	seen := map[string]bool{}
	var entries []drive.Entry
	prefix := dir + "/"
	for p := range m.files {
		if dir != "" && !strings.HasPrefix(p, prefix) {
			continue
		}
		rest := strings.TrimPrefix(p, prefix)
		if dir == "" {
			rest = p
		}
		name := rest
		isDir := false
		if i := strings.Index(rest, "/"); i >= 0 {
			name = rest[:i]
			isDir = true
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		id := name
		if dir != "" {
			id = dir + "/" + name
		}
		entries = append(entries, drive.Entry{Name: name, ID: id, IsDir: isDir})
	}
	return entries, nil
}

func mustIdentity(t *testing.T) *crypto.Identity {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestVaultRoundTrip(t *testing.T) {
	store := newMemStore()
	alice := mustIdentity(t)

	v, err := Create(store, alice, "alice", "team")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Alice writes and reads a secret.
	if err := v.SetSecret("db-password", "prod", []byte("hunter2")); err != nil {
		t.Fatalf("set: %v", err)
	}
	val, meta, err := v.GetSecret("db-password")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !bytes.Equal(val, []byte("hunter2")) {
		t.Fatalf("value mismatch: %q", val)
	}
	if meta.Author != "alice" || meta.Notes != "prod" {
		t.Fatalf("meta mismatch: %+v", meta)
	}

	// Update in place preserves the name and creation time.
	if err := v.SetSecret("db-password", "prod", []byte("hunter3")); err != nil {
		t.Fatalf("update: %v", err)
	}
	val, _, _ = v.GetSecret("db-password")
	if !bytes.Equal(val, []byte("hunter3")) {
		t.Fatalf("update value mismatch: %q", val)
	}
	if metas, _ := v.ListSecrets(); len(metas) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(metas))
	}
}

func TestMemberAddAndRead(t *testing.T) {
	store := newMemStore()
	alice := mustIdentity(t)
	bob := mustIdentity(t)

	av, err := Create(store, alice, "alice", "team")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := av.SetSecret("api-key", "", []byte("sk-123")); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := av.AddMember("bob", bob.Public()); err != nil {
		t.Fatalf("add member: %v", err)
	}

	// Bob opens the same store with his own identity and reads the secret.
	bv, err := Open(store, bob, "bob", "team")
	if err != nil {
		t.Fatalf("bob open: %v", err)
	}
	val, _, err := bv.GetSecret("api-key")
	if err != nil {
		t.Fatalf("bob get: %v", err)
	}
	if !bytes.Equal(val, []byte("sk-123")) {
		t.Fatalf("bob value mismatch: %q", val)
	}
}

func TestRemoveMemberRotatesKey(t *testing.T) {
	store := newMemStore()
	alice := mustIdentity(t)
	bob := mustIdentity(t)

	av, err := Create(store, alice, "alice", "team")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := av.AddMember("bob", bob.Public()); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := av.SetSecret("token", "", []byte("abc")); err != nil {
		t.Fatalf("set: %v", err)
	}
	oldRecipient := av.Meta().MasterRecipient

	if err := av.RemoveMember("bob"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if av.Meta().MasterRecipient == oldRecipient {
		t.Fatal("master recipient did not rotate")
	}
	if av.Meta().KeyEpoch != 2 {
		t.Fatalf("expected key epoch 2, got %d", av.Meta().KeyEpoch)
	}

	// Bob can no longer open the vault: his wrapped key was deleted.
	if _, err := Open(store, bob, "bob", "team"); err != nil {
		// Open succeeds (meta is public) but reading must fail.
	}
	bv, _ := Open(store, bob, "bob", "team")
	if _, _, err := bv.GetSecret("token"); err == nil {
		t.Fatal("expected bob to lose access after rotation")
	}

	// Alice can still read, now under the new key.
	val, _, err := av.GetSecret("token")
	if err != nil || !bytes.Equal(val, []byte("abc")) {
		t.Fatalf("alice lost access after rotation: val=%q err=%v", val, err)
	}
}

func TestTamperedSecretRejected(t *testing.T) {
	store := newMemStore()
	alice := mustIdentity(t)
	av, _ := Create(store, alice, "alice", "team")
	if err := av.SetSecret("s", "", []byte("v")); err != nil {
		t.Fatal(err)
	}
	// Corrupt the stored secret ciphertext.
	for path, data := range store.files {
		if strings.Contains(path, "/secrets/") {
			data[len(data)-1] ^= 0xff
			store.files[path] = data
		}
	}
	if _, err := av.ListSecrets(); err == nil {
		t.Fatal("expected tampered secret to be rejected")
	}
}
