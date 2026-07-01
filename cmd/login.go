package cmd

import (
	"fmt"

	"github.com/maxinielsen/secret-share/internal/drive"
	"github.com/spf13/cobra"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authorize access to Google Drive in your browser",
	RunE: func(cmd *cobra.Command, args []string) error {
		ks, err := openKeystore()
		if err != nil {
			return err
		}
		if err := drive.Login(cmd.Context(), ks); err != nil {
			return err
		}
		fmt.Println("Logged in. Token stored in", ks.Backend()+".")
		return nil
	},
}

func init() { rootCmd.AddCommand(loginCmd) }
