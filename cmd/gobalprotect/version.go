package main

import (
	"context"
	"fmt"

	cli "github.com/urfave/cli/v3"
)

func versionCommand() *cli.Command {
	return &cli.Command{
		Name:  "version",
		Usage: "Print version information",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			fmt.Printf("gobalprotect %s (built %s)\n", version, buildDate)
			return nil
		},
	}
}
