package main

import (
	"context"
	"os"

	cli "github.com/urfave/cli/v3"
)

var (
	version   = "dev"
	buildDate = "unknown"
)

func main() {
	cmd := &cli.Command{
		Name:  "gobalprotect",
		Usage: "GlobalProtect VPN client using TUN device",
		Commands: []*cli.Command{
			connectCommand(),
			versionCommand(),
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		os.Exit(1)
	}
}
