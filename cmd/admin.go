package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Manage vault admins (who can admit members and rotate keys)",
}

var adminListCmd = &cobra.Command{
	Use:   "ls",
	Short: "List the vault's admins",
	RunE: func(cmd *cobra.Command, args []string) error {
		e, err := setup(cmd, true)
		if err != nil {
			return err
		}
		v, err := e.openVault()
		if err != nil {
			return err
		}
		admins, err := v.ListAdmins()
		if err != nil {
			return err
		}
		for _, a := range admins {
			fmt.Printf("  %s\n", a)
		}
		return nil
	},
}

var adminAddCmd = &cobra.Command{
	Use:   "add <member-name>",
	Short: "Promote an existing member to admin",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		e, err := setup(cmd, true)
		if err != nil {
			return err
		}
		v, err := e.openVault()
		if err != nil {
			return err
		}
		if err := v.AddAdmin(args[0]); err != nil {
			return err
		}
		fmt.Printf("%q is now an admin.\n", args[0])
		return nil
	},
}

var rotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Rotate the vault master key and re-encrypt all secrets",
	Long: `rotate generates a fresh master key, re-encrypts every secret to it, and
re-wraps it for all current members. Use it if you suspect the key was exposed.
Membership is unchanged.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		e, err := setup(cmd, true)
		if err != nil {
			return err
		}
		v, err := e.openVault()
		if err != nil {
			return err
		}
		if err := confirm("Rotate the master key and re-encrypt every secret?"); err != nil {
			return err
		}
		fmt.Println("Rotating...")
		if err := v.Rotate(); err != nil {
			return err
		}
		fmt.Printf("Rotated to key epoch %d.\n", v.Meta().KeyEpoch)
		return nil
	},
}

func init() {
	adminCmd.AddCommand(adminListCmd, adminAddCmd)
	rotateCmd.Flags().BoolVarP(&assumeYes, "yes", "y", false, "skip confirmation")
	rootCmd.AddCommand(adminCmd, rotateCmd)
}
