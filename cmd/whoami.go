package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/maxinielsen/secret-share/internal/crypto"
	"github.com/spf13/cobra"
)

// encodePublicKey renders a member's public key as a shareable token.
func encodePublicKey(pk crypto.PublicKey) string {
	data, _ := json.Marshal(pk)
	return base64.RawURLEncoding.EncodeToString(data)
}

// decodePublicKey parses a share token back into a public key.
func decodePublicKey(token string) (crypto.PublicKey, error) {
	var pk crypto.PublicKey
	data, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return pk, fmt.Errorf("invalid share token: %w", err)
	}
	if err := json.Unmarshal(data, &pk); err != nil {
		return pk, fmt.Errorf("invalid share token: %w", err)
	}
	if pk.AgeRecipient == "" || pk.SignPub == "" {
		return pk, fmt.Errorf("share token missing key material")
	}
	return pk, nil
}

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show your identity and shareable public key",
	RunE: func(cmd *cobra.Command, args []string) error {
		e, err := setup(cmd, false)
		if err != nil {
			return err
		}
		pk := e.self.Public()
		fmt.Printf("Member name:    %s\n", e.cfg.MemberName)
		fmt.Printf("Age recipient:  %s\n", pk.AgeRecipient)
		fmt.Printf("Signing pubkey: %s\n", pk.SignPub)
		fmt.Printf("\nShare token (give this to a vault admin to be added):\n\n  %s\n", encodePublicKey(pk))
		return nil
	},
}

func init() { rootCmd.AddCommand(whoamiCmd) }
