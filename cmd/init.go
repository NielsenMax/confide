package cmd

import (
	"errors"
	"fmt"

	"github.com/maxinielsen/confide/internal/config"
	"github.com/maxinielsen/confide/internal/crypto"
	"github.com/maxinielsen/confide/internal/drive"
	"github.com/maxinielsen/confide/internal/keystore"
	"github.com/spf13/cobra"
)

var (
	initName         string
	initDriveID      string
	initFolderName   string
	initRootFolderID string
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Set up your identity and the Drive store",
	Long: `init generates your encryption + signing identity (if you don't have one),
records your member name, ensures you're logged in to Drive, and creates the
top-level store folder.

For a Shared Drive, pass --drive-id (find it in the Drive URL). Personal Gmail
accounts cannot create Shared Drives; omit --drive-id to use a regular folder in
your My Drive and share that folder with your team.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ks, err := openKeystore()
		if err != nil {
			return err
		}
		cfg, err := config.Load()
		if err != nil {
			return err
		}

		// 1. Identity: create and store if absent.
		if !ks.HasIdentity() {
			id, err := crypto.GenerateIdentity()
			if err != nil {
				return err
			}
			data, err := id.Marshal()
			if err != nil {
				return err
			}
			if err := ks.SetIdentity(data); err != nil {
				return err
			}
			fmt.Println("Generated a new identity, stored in", ks.Backend()+".")
		}

		// 2. Member name.
		if initName != "" {
			cfg.MemberName = initName
		}
		if cfg.MemberName == "" {
			return fmt.Errorf("please provide your member name: confide init --name <you>")
		}

		// 3. Drive login if needed.
		if _, err := ks.GetToken(); errors.Is(err, keystore.ErrNotFound) {
			if err := drive.Login(cmd.Context(), ks); err != nil {
				return err
			}
		}

		// 4. Drive location + root folder.
		if initDriveID != "" {
			cfg.DriveID = initDriveID
		}
		dc, err := drive.New(cmd.Context(), ks, cfg)
		if err != nil {
			return err
		}
		switch {
		case initRootFolderID != "":
			// Joining an existing store shared by an admin: use their folder ID
			// directly rather than creating a new folder of our own.
			cfg.RootFolderID = initRootFolderID
		default:
			if err := dc.EnsureRootFolder(initFolderName); err != nil {
				return err
			}
		}
		if err := cfg.Save(); err != nil {
			return err
		}
		fmt.Printf("Ready. Member %q, store folder %q (%s).\n", cfg.MemberName, initFolderName,
			driveLocation(cfg))
		fmt.Println("Next: `confide vault create <name>` to start a vault.")
		return nil
	},
}

func driveLocation(cfg *config.Config) string {
	if cfg.DriveID != "" {
		return "Shared Drive " + cfg.DriveID
	}
	return "My Drive"
}

func init() {
	initCmd.Flags().StringVar(&initName, "name", "", "your member name within vaults")
	initCmd.Flags().StringVar(&initDriveID, "drive-id", "", "Shared Drive ID (optional)")
	initCmd.Flags().StringVar(&initFolderName, "folder", "SecretShare", "top-level store folder name")
	initCmd.Flags().StringVar(&initRootFolderID, "root-folder-id", "", "join an existing store by its folder ID (from `invite`)")
	rootCmd.AddCommand(initCmd)
}
