package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/spf13/cobra"
)

var (
	version    = "dev"
	apiBaseURL = "http://localhost:8080"
)

var rootCmd = &cobra.Command{
	Use:     "cvscan [flags] [repos-path]",
	Short:   "Cloudvisor Security Scanner — secrets & IaC scanning",
	Version: version,
	RunE: func(cmd *cobra.Command, args []string) error {
		engID, _ := cmd.Flags().GetString("engagement-id")
		token, _ := cmd.Flags().GetString("token")
		output, _ := cmd.Flags().GetString("output")
		scanners, _ := cmd.Flags().GetString("scanners")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		noSubmit, _ := cmd.Flags().GetBool("no-submit")

		reposPath := ""
		if len(args) > 0 {
			reposPath = args[0]
		}

		// If key flags are missing, launch TUI
		if engID == "" || token == "" || reposPath == "" {
			return runTUI(cmd.Context())
		}

		return runCLI(cmd.Context(), CLIConfig{
			EngagementID: engID,
			Token:        token,
			ReposPath:    reposPath,
			Output:       output,
			Scanners:     scanners,
			DryRun:       dryRun,
			NoSubmit:     noSubmit,
		})
	},
}

func init() {
	rootCmd.Flags().String("engagement-id", "", "Cloudvisor engagement ID")
	rootCmd.Flags().String("token", "", "scan token (provided by Cloudvisor engineer)")
	rootCmd.Flags().StringP("output", "o", "cvscan-report.html", "HTML report output path")
	rootCmd.Flags().String("scanners", "secrets,iac", "comma-separated scanners to run (secrets, iac)")
	rootCmd.Flags().Bool("dry-run", false, "scan and generate report but skip submission")
	rootCmd.Flags().Bool("no-submit", false, "skip data submission entirely")
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
