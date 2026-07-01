// Command confide is a CLI for sharing secrets with a team, using Google
// Drive as an encrypted storage backend.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/maxinielsen/confide/cmd"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	cmd.ExecuteContext(ctx)
}
