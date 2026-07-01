package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var purgeCmd = &cobra.Command{
	Use:   "purge",
	Short: "Permanently remove soft-deleted (tombstoned) secret files you own",
	Long: `purge cleans up the empty tombstone files left behind when a secret is
soft-deleted. You can only purge files you own; tombstones owned by other
members are left for them to purge (or use a Shared Drive to avoid the split).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		e, err := setup(cmd, true)
		if err != nil {
			return err
		}
		v, err := e.openVault()
		if err != nil {
			return err
		}
		purged, skipped, err := v.PurgeTombstones()
		if err != nil {
			return err
		}
		fmt.Printf("Purged %d tombstone(s).\n", purged)
		if skipped > 0 {
			fmt.Printf("Skipped %d owned by other members (only the owner can delete them).\n", skipped)
		}
		return nil
	},
}

func init() { rootCmd.AddCommand(purgeCmd) }
