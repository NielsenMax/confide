package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var memberCmd = &cobra.Command{
	Use:   "member",
	Short: "Manage vault members",
}

var memberAddCmd = &cobra.Command{
	Use:   "add <name> <share-token>",
	Short: "Admit a member using their `whoami` share token",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		e, err := setup(cmd, true)
		if err != nil {
			return err
		}
		pk, err := decodePublicKey(args[1])
		if err != nil {
			return err
		}
		v, err := e.openVault()
		if err != nil {
			return err
		}
		if err := v.AddMember(args[0], pk); err != nil {
			return err
		}
		fmt.Printf("Added %q. They can now read and write secrets.\n", args[0])
		return nil
	},
}

var memberListCmd = &cobra.Command{
	Use:   "ls",
	Short: "List members of the current vault",
	RunE: func(cmd *cobra.Command, args []string) error {
		e, err := setup(cmd, true)
		if err != nil {
			return err
		}
		v, err := e.openVault()
		if err != nil {
			return err
		}
		members, err := v.ListMembers()
		if err != nil {
			return err
		}
		for _, m := range members {
			fmt.Printf("  %-20s added by %s at %s\n", m.Name, m.AddedBy, m.AddedAt)
		}
		if len(members) == 0 {
			fmt.Println("No members.")
		}
		return nil
	},
}

var memberRemoveCmd = &cobra.Command{
	Use:   "rm <name>",
	Short: "Revoke a member (rotates the master key and re-encrypts all secrets)",
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
		if err := confirm(fmt.Sprintf("Remove %q? This rotates the key and re-encrypts every secret.", args[0])); err != nil {
			return err
		}
		fmt.Printf("Rotating master key and re-encrypting all secrets...\n")
		if err := v.RemoveMember(args[0]); err != nil {
			return err
		}
		fmt.Printf("Removed %q and rotated the vault key (epoch %d).\n", args[0], v.Meta().KeyEpoch)
		fmt.Println("Note: any secret VALUES this member already read are still known to them.")
		fmt.Println("Rotate those values with `secret-share set` to fully invalidate them.")
		return nil
	},
}

func init() {
	memberRemoveCmd.Flags().BoolVarP(&assumeYes, "yes", "y", false, "skip confirmation")
	memberCmd.AddCommand(memberAddCmd, memberListCmd, memberRemoveCmd)
	rootCmd.AddCommand(memberCmd)
}
