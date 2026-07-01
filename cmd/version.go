package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// version is set at build time via -ldflags (see Makefile). The on-disk format
// version lives in the vault package; bumping either is worth surfacing here so
// teammates can tell which build they're running.
var version = "dev"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the build version",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("secret-share %s\n", version)
		return nil
	},
}

func init() { rootCmd.AddCommand(versionCmd) }
