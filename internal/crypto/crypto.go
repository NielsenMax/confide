// Package crypto implements the envelope-encryption and signing primitives that
// back the secret store.
//
// Design overview
//
//   - Every member owns an [Identity]: an age X25519 keypair (for encryption)
//     plus an ed25519 keypair (for signing/authenticity).
//   - Each vault owns a "master" age keypair. Secrets are encrypted TO the
//     master recipient (public); reading requires the master identity (private).
//   - The master identity is individually "wrapped" (encrypted) to each member's
//     age recipient, so only members can recover it.
//   - Files that must be authenticated (member records, wrapped keys, secrets)
//     are signed with the author's ed25519 key and verified on read.
//
// age (filippo.io/age) provides X25519 + ChaCha20-Poly1305 AEAD, giving
// confidentiality and integrity per blob. ed25519 adds sender authenticity,
// which age's "sealed box" model does not by itself.
package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"filippo.io/age"
)

// Identity is a member's full secret key material: age (encryption) + ed25519
// (signing). It must never leave the owner's machine unencrypted.
type Identity struct {
	Age  *age.X25519Identity
	Sign ed25519.PrivateKey
}

// PublicKey is the shareable public half of an [Identity]. It is published to
// the vault so others can encrypt to and verify this member.
type PublicKey struct {
	AgeRecipient string `json:"age_recipient"` // "age1..."
	SignPub      string `json:"sign_pub"`      // base64(ed25519 public key)
}

// identityFile is the on-disk/keychain serialization of an [Identity].
type identityFile struct {
	AgeSecret string `json:"age_secret"` // "AGE-SECRET-KEY-1..."
	SignSeed  string `json:"sign_seed"`  // base64(ed25519 seed, 32 bytes)
}

// GenerateIdentity creates a fresh member identity.
func GenerateIdentity() (*Identity, error) {
	ageID, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("generate age identity: %w", err)
	}
	_, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	return &Identity{Age: ageID, Sign: signPriv}, nil
}

// Public returns the shareable public key for this identity.
func (id *Identity) Public() PublicKey {
	return PublicKey{
		AgeRecipient: id.Age.Recipient().String(),
		SignPub:      base64.StdEncoding.EncodeToString(id.Sign.Public().(ed25519.PublicKey)),
	}
}

// Marshal serializes the identity to a compact JSON blob for secure storage.
func (id *Identity) Marshal() ([]byte, error) {
	return json.Marshal(identityFile{
		AgeSecret: id.Age.String(),
		SignSeed:  base64.StdEncoding.EncodeToString(id.Sign.Seed()),
	})
}

// ParseIdentity reconstructs an [Identity] from Marshal output.
func ParseIdentity(data []byte) (*Identity, error) {
	var f identityFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse identity: %w", err)
	}
	ageID, err := age.ParseX25519Identity(f.AgeSecret)
	if err != nil {
		return nil, fmt.Errorf("parse age secret: %w", err)
	}
	seed, err := base64.StdEncoding.DecodeString(f.SignSeed)
	if err != nil {
		return nil, fmt.Errorf("decode signing seed: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid signing seed length %d", len(seed))
	}
	return &Identity{Age: ageID, Sign: ed25519.NewKeyFromSeed(seed)}, nil
}

// MasterKey is a vault's master age keypair. The identity (private) is wrapped
// to members; the recipient (public) is stored in the clear and used to encrypt
// secrets.
type MasterKey struct {
	id *age.X25519Identity
}

// GenerateMasterKey creates a new vault master keypair.
func GenerateMasterKey() (*MasterKey, error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("generate master key: %w", err)
	}
	return &MasterKey{id: id}, nil
}

// Recipient returns the public master recipient string ("age1...").
func (m *MasterKey) Recipient() string { return m.id.Recipient().String() }

// Secret returns the private master identity string; handle with care.
func (m *MasterKey) Secret() string { return m.id.String() }

// parseMasterFromSecret rebuilds a MasterKey from its secret string.
func parseMasterFromSecret(secret string) (*MasterKey, error) {
	id, err := age.ParseX25519Identity(secret)
	if err != nil {
		return nil, fmt.Errorf("parse master secret: %w", err)
	}
	return &MasterKey{id: id}, nil
}

// encrypt encrypts plaintext to the given age recipients.
func encrypt(plaintext []byte, recipients ...age.Recipient) ([]byte, error) {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipients...)
	if err != nil {
		return nil, fmt.Errorf("init encryption: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("write plaintext: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("finalize encryption: %w", err)
	}
	return buf.Bytes(), nil
}

// decrypt decrypts ciphertext using the given age identities.
func decrypt(ciphertext []byte, identities ...age.Identity) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(ciphertext), identities...)
	if err != nil {
		return nil, fmt.Errorf("init decryption: %w", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read plaintext: %w", err)
	}
	return out, nil
}

// WrapMasterKey encrypts the master secret to a member's age recipient.
func WrapMasterKey(master *MasterKey, memberRecipient string) ([]byte, error) {
	r, err := age.ParseX25519Recipient(memberRecipient)
	if err != nil {
		return nil, fmt.Errorf("parse member recipient: %w", err)
	}
	return encrypt([]byte(master.Secret()), r)
}

// UnwrapMasterKey decrypts a wrapped master key using the member's identity.
func UnwrapMasterKey(wrapped []byte, member *Identity) (*MasterKey, error) {
	secret, err := decrypt(wrapped, member.Age)
	if err != nil {
		return nil, fmt.Errorf("unwrap master key: %w", err)
	}
	return parseMasterFromSecret(string(secret))
}

// EncryptSecret encrypts plaintext to the vault's master recipient.
func EncryptSecret(masterRecipient string, plaintext []byte) ([]byte, error) {
	r, err := age.ParseX25519Recipient(masterRecipient)
	if err != nil {
		return nil, fmt.Errorf("parse master recipient: %w", err)
	}
	return encrypt(plaintext, r)
}

// DecryptSecret decrypts a secret using the recovered master key.
func DecryptSecret(master *MasterKey, ciphertext []byte) ([]byte, error) {
	return decrypt(ciphertext, master.id)
}

// Sign produces an ed25519 signature over data.
func Sign(id *Identity, data []byte) []byte {
	return ed25519.Sign(id.Sign, data)
}

// Verify checks an ed25519 signature against a base64-encoded public key.
func Verify(signPubB64 string, data, sig []byte) error {
	pub, err := base64.StdEncoding.DecodeString(signPubB64)
	if err != nil {
		return fmt.Errorf("decode signing pubkey: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid signing pubkey length %d", len(pub))
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), data, sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}
