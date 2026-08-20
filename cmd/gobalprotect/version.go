package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	cli "github.com/urfave/cli/v3"
)

func versionCommand() *cli.Command {
	return &cli.Command{
		Name:  "version",
		Usage: "Print version information",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "json",
				Aliases: []string{"j"},
				Usage:   "Output version information as JSON",
			},
			&cli.BoolFlag{
				Name:    "pretty",
				Aliases: []string{"p"},
				Usage:   "Output version information as pretty-printed",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if cmd.Bool("json") {
				info := struct {
					Name      string `json:"name"`
					Version   string `json:"version"`
					BuildDate string `json:"buildDate"`
				}{
					Name:      "gobalprotect",
					Version:   version,
					BuildDate: buildDate,
				}
				enc := json.NewEncoder(os.Stdout)
				if cmd.Bool("pretty") {
					enc.SetIndent("", "  ")
				}
				if err := enc.Encode(info); err != nil {
					return err
				}
				return nil
			}
			fmt.Printf("gobalprotect %s (built %s)\n", version, buildDate)
			return nil
		},
	}
}
