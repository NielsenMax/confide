package vault

import (
	"bytes"
	"strings"
	"sync"
	"testing"

	"github.com/maxinielsen/confide/internal/crypto"
	"github.com/maxinielsen/confide/internal/drive"
)

// memStore is an in-memory implementation of Store for tests. It keys files by
// full slash-path and synthesizes directory listings. The mutex mirrors the
// real client's independence — rotation issues concurrent writes.
type memStore struct {
	mu    sync.Mutex
	files map[string][]byte
}

func newMemStore() *memStore { return &memStore{files: map[string][]byte{}} }

func (m *memStore) WriteFile(path string, data []byte) error {
	cp := make([]byte, len(data))
	copy(cp, data)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[strings.Trim(path, "/")] = cp
	return nil
}

func (m *memStore) ReadFile(path string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.files[strings.Trim(path, "/")]
	if !ok {
		return nil, drive.ErrNotFound
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	return cp, nil
}

func (m *memStore) Remove(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.files, strings.Trim(path, "/"))
	return nil
}

// Download uses the full path as the entry ID (see List below).
func (m *memStore) Download(id string) ([]byte, error) {
	return m.ReadFile(id)
}

func (m *memStore) HardDeleteByID(id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.files, strings.Trim(id, "/"))
	return true, nil
}

func (m *memStore) List(dir string) ([]drive.Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
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
		entries = append(entries, drive.Entry{Name: name, ID: id, IsDir: isDir, Size: int64(len(m.files[id]))})
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

func TestSoftDeleteTombstoneHidden(t *testing.T) {
	store := newMemStore()
	alice := mustIdentity(t)
	av, _ := Create(store, alice, "alice", "team")
	if err := av.SetSecret("token", "", []byte("abc")); err != nil {
		t.Fatal(err)
	}
	// Simulate a soft delete: the file content is truncated to empty.
	store.files["team/secrets/token.age"] = []byte{}

	infos, err := av.ListSecrets()
	if err != nil {
		t.Fatalf("ls: %v", err)
	}
	if len(infos) != 0 {
		t.Fatalf("tombstone should be hidden from ls, got %d entries", len(infos))
	}
	if _, _, err := av.GetSecret("token"); err == nil {
		t.Fatal("expected tombstoned secret to read as not found")
	}
	// The name is reusable: writing again overwrites the tombstone.
	if err := av.SetSecret("token", "", []byte("xyz")); err != nil {
		t.Fatalf("recreate: %v", err)
	}
	val, _, err := av.GetSecret("token")
	if err != nil || string(val) != "xyz" {
		t.Fatalf("recreate readback: val=%q err=%v", val, err)
	}
}

func TestPurgeTombstones(t *testing.T) {
	store := newMemStore()
	alice := mustIdentity(t)
	av, _ := Create(store, alice, "alice", "team")
	if err := av.SetSecret("live", "", []byte("v")); err != nil {
		t.Fatal(err)
	}
	if err := av.SetSecret("dead", "", []byte("v")); err != nil {
		t.Fatal(err)
	}
	store.files["team/secrets/dead.age"] = []byte{} // tombstone

	purged, skipped, err := av.PurgeTombstones()
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if purged != 1 || skipped != 0 {
		t.Fatalf("expected purged=1 skipped=0, got purged=%d skipped=%d", purged, skipped)
	}
	if _, ok := store.files["team/secrets/dead.age"]; ok {
		t.Fatal("tombstone file should be gone after purge")
	}
	if _, ok := store.files["team/secrets/live.age"]; !ok {
		t.Fatal("live secret must survive purge")
	}
}

func TestRotateKeepsMemberAccess(t *testing.T) {
	store := newMemStore()
	alice := mustIdentity(t)
	bob := mustIdentity(t)
	av, _ := Create(store, alice, "alice", "team")
	if err := av.AddMember("bob", bob.Public()); err != nil {
		t.Fatal(err)
	}
	if err := av.SetSecret("k", "", []byte("v")); err != nil {
		t.Fatal(err)
	}
	if err := av.Rotate(); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if av.Meta().KeyEpoch != 2 {
		t.Fatalf("epoch: got %d want 2", av.Meta().KeyEpoch)
	}
	// Both members still read under the new key.
	for name, id := range map[string]*crypto.Identity{"alice": alice, "bob": bob} {
		vv, _ := Open(store, id, name, "team")
		val, _, err := vv.GetSecret("k")
		if err != nil || string(val) != "v" {
			t.Fatalf("%s lost access after rotate: val=%q err=%v", name, val, err)
		}
	}
}

func TestSecondAdminCanAddMembers(t *testing.T) {
	store := newMemStore()
	alice := mustIdentity(t)
	bob := mustIdentity(t)
	carol := mustIdentity(t)

	av, _ := Create(store, alice, "alice", "team")
	if err := av.AddMember("bob", bob.Public()); err != nil {
		t.Fatal(err)
	}
	// Before promotion, bob is not an admin and cannot add members.
	bv, _ := Open(store, bob, "bob", "team")
	if err := bv.AddMember("carol", carol.Public()); err == nil {
		t.Fatal("non-admin bob should not be able to add members")
	}
	// Alice promotes bob.
	if err := av.AddAdmin("bob"); err != nil {
		t.Fatalf("add admin: %v", err)
	}
	// Re-open so bob sees the updated manifest, then he admits carol.
	bv2, _ := Open(store, bob, "bob", "team")
	if err := bv2.AddMember("carol", carol.Public()); err != nil {
		t.Fatalf("admin bob failed to add carol: %v", err)
	}
	if err := av.SetSecret("k", "", []byte("v")); err != nil {
		t.Fatal(err)
	}
	cv, _ := Open(store, carol, "carol", "team")
	if val, _, err := cv.GetSecret("k"); err != nil || string(val) != "v" {
		t.Fatalf("carol cannot read: val=%q err=%v", val, err)
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
	// Listing is name-only and stays fast, but reading must reject tampering.
	if _, _, err := av.GetSecret("s"); err == nil {
		t.Fatal("expected tampered secret to be rejected on read")
	}
}
