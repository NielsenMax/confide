package vault

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/NielsenMax/confide/internal/crypto"
)

// signedEnvelope wraps an authenticated JSON payload. The signature covers the
// exact Payload bytes, so verification is independent of re-serialization.
type signedEnvelope struct {
	Payload    json.RawMessage `json:"payload"`
	SignerName string          `json:"signer_name"`
	SignerPub  string          `json:"signer_pub"` // base64 ed25519 public key
	Sig        string          `json:"sig"`        // base64 signature over Payload
}

// seal marshals v and wraps it in a signed envelope authored by self.
func seal(self *crypto.Identity, selfName string, v any) ([]byte, error) {
	payload, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	env := signedEnvelope{
		Payload:    payload,
		SignerName: selfName,
		SignerPub:  self.Public().SignPub,
		Sig:        base64.StdEncoding.EncodeToString(crypto.Sign(self, payload)),
	}
	// Compact (not indented) marshal so the embedded RawMessage payload is
	// re-serialized byte-identically to the bytes that were signed.
	return json.Marshal(env)
}

// openEnvelope verifies the envelope signature and unmarshals the payload into
// out. It returns the signer's public key and name for authorization checks.
func openEnvelope(data []byte, out any) (signerPub, signerName string, err error) {
	var env signedEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return "", "", fmt.Errorf("parse envelope: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(env.Sig)
	if err != nil {
		return "", "", fmt.Errorf("decode signature: %w", err)
	}
	if err := crypto.Verify(env.SignerPub, env.Payload, sig); err != nil {
		return "", "", fmt.Errorf("envelope from %q: %w", env.SignerName, err)
	}
	if out != nil {
		if err := json.Unmarshal(env.Payload, out); err != nil {
			return "", "", fmt.Errorf("parse payload: %w", err)
		}
	}
	return env.SignerPub, env.SignerName, nil
}
