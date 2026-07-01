package cmd

import (
	"fmt"

	"github.com/maxinielsen/confide/internal/vault"
	"github.com/spf13/cobra"
)

var vaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Create and manage vaults",
}

var vaultCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a new vault (you become its admin and first member)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		e, err := setup(cmd, true)
		if err != nil {
			return err
		}
		if e.cfg.MemberName == "" {
			return fmt.Errorf("member name not set; run `confide init --name <you>`")
		}
		v, err := vault.Create(e.dc, e.self, e.cfg.MemberName, args[0])
		if err != nil {
			return err
		}
		e.cfg.DefaultVault = v.Meta().Name
		if err := e.cfg.Save(); err != nil {
			return err
		}
		fmt.Printf("Created vault %q and set it as default.\n", v.Meta().Name)
		return nil
	},
}

var vaultUseCmd = &cobra.Command{
	Use:   "use <name>",
	Short: "Set the default vault",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		e, err := setup(cmd, false)
		if err != nil {
			return err
		}
		e.cfg.DefaultVault = args[0]
		if err := e.cfg.Save(); err != nil {
			return err
		}
		fmt.Printf("Default vault set to %q.\n", args[0])
		return nil
	},
}

var vaultListCmd = &cobra.Command{
	Use:   "ls",
	Short: "List vaults in the store",
	RunE: func(cmd *cobra.Command, args []string) error {
		e, err := setup(cmd, true)
		if err != nil {
			return err
		}
		entries, err := e.dc.List("")
		if err != nil {
			return err
		}
		found := false
		for _, en := range entries {
			if !en.IsDir {
				continue
			}
			marker := "  "
			if en.Name == e.cfg.DefaultVault {
				marker = "* "
			}
			fmt.Printf("%s%s\n", marker, en.Name)
			found = true
		}
		if !found {
			fmt.Println("No vaults yet. Create one with `confide vault create <name>`.")
		}
		return nil
	},
}

var vaultInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show the manifest of the current vault",
	RunE: func(cmd *cobra.Command, args []string) error {
		e, err := setup(cmd, true)
		if err != nil {
			return err
		}
		v, err := e.openVault()
		if err != nil {
			return err
		}
		m := v.Meta()
		fmt.Printf("Name:             %s\n", m.Name)
		fmt.Printf("Format version:   %d\n", m.FormatVersion)
		fmt.Printf("Key epoch:        %d\n", m.KeyEpoch)
		fmt.Printf("Master recipient: %s\n", m.MasterRecipient)
		fmt.Printf("Created by:        %s at %s\n", m.CreatedBy, m.CreatedAt)
		fmt.Printf("Admins:           %d\n", len(m.AdminPubs))
		return nil
	},
}

func init() {
	vaultCmd.AddCommand(vaultCreateCmd, vaultUseCmd, vaultListCmd, vaultInfoCmd)
	rootCmd.AddCommand(vaultCmd)
}
