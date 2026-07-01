package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var inviteCmd = &cobra.Command{
	Use:   "invite <google-email>",
	Short: "Grant a teammate Drive access to the store folder",
	Long: `invite shares your SecretShare Drive folder with a teammate's Google account
(Editor access) so their CLI can read and write it, then prints the setup
command for them to run.

This handles Drive ACCESS only. To also give them decryption access, add them to
a vault with: secret-share member add <name> <their-share-token>.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		e, err := setup(cmd, true)
		if err != nil {
			return err
		}
		if e.cfg.RootFolderID == "" {
			return fmt.Errorf("store not initialized; run `secret-share init` first")
		}
		email := args[0]
		if err := e.dc.ShareFolder(e.cfg.RootFolderID, email, "writer"); err != nil {
			return err
		}
		fmt.Printf("Shared the store folder with %s (Editor).\n\n", email)
		fmt.Println("Tell them to run:")
		if e.cfg.DriveID != "" {
			fmt.Printf("\n  secret-share init --name <them> --drive-id %s\n", e.cfg.DriveID)
		} else {
			fmt.Printf("\n  secret-share init --name <them> --root-folder-id %s\n", e.cfg.RootFolderID)
		}
		fmt.Println("  secret-share whoami            # sends you a share token")
		fmt.Println("\nThen you run:")
		fmt.Printf("\n  secret-share member add <them> <their-share-token>\n")
		return nil
	},
}

func init() { rootCmd.AddCommand(inviteCmd) }
