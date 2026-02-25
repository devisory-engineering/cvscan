package main

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// CLIConfig holds all flag-based configuration.
type CLIConfig struct {
	EngagementID string
	Token        string
	ReposPath    string
	Output       string
	Scanners     string // comma-separated: "secrets,iac"
	DryRun       bool
	NoSubmit     bool
}

func runCLI(ctx context.Context, cfg CLIConfig) error {
	// Resolve scanners
	scanners, err := parseScanners(cfg.Scanners)
	if err != nil {
		return err
	}

	// Validate token (unless dry-run or no-submit)
	if !cfg.NoSubmit && !cfg.DryRun {
		fmt.Print("Validating token... ")
		resp, err := validateToken(apiBaseURL, cfg.EngagementID, cfg.Token)
		if err != nil {
			fmt.Println("FAILED")
			return fmt.Errorf("token validation failed: %w", err)
		}
		fmt.Printf("Valid (expires in %s)\n", resp.ExpiresIn)
	}

	// Run scans
	result, err := Orchestrate(ctx, ScanRequest{
		EngagementID: cfg.EngagementID,
		Token:        cfg.Token,
		ReposPath:    cfg.ReposPath,
		Scanners:     scanners,
	}, func(scanner, repo string, findings int) {
		if findings < 0 {
			fmt.Fprintf(os.Stderr, "  %s / %s ... error\n", scanner, repo)
		} else {
			fmt.Printf("  %s / %s ... %d findings\n", scanner, repo, findings)
		}
	})
	if err != nil {
		return err
	}

	// Summary
	fmt.Printf("\nTotal: %d findings (%d secrets, %d IaC) across %d repos\n",
		result.Summary.TotalFindings,
		result.Summary.SecretsFindings,
		result.Summary.IaCFindings,
		result.Summary.ReposScanned,
	)

	// Generate HTML report
	output := cfg.Output
	if output == "" {
		output = "cvscan-report.html"
	}
	if err := generateHTMLReport(result, output); err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}
	fmt.Printf("Report saved: %s\n", output)
	_ = openInBrowser(output)

	// Submit (unless dry-run or no-submit)
	if cfg.DryRun {
		fmt.Println("\n[dry-run] Findings would be submitted to Cloudvisor. Skipping.")
		return nil
	}
	if cfg.NoSubmit {
		return nil
	}

	fmt.Print("\nSubmitting findings to Cloudvisor... ")
	if err := submitFindings(apiBaseURL, cfg.Token, result); err != nil {
		fmt.Println("FAILED")
		return err
	}
	fmt.Println("Done")
	fmt.Println("Token consumed. Request a new token for future scans.")

	return nil
}

func parseScanners(input string) ([]Scanner, error) {
	if input == "" {
		return []Scanner{&SecretsScanner{}, &IaCScanner{}}, nil
	}

	var scanners []Scanner
	for _, name := range strings.Split(input, ",") {
		switch strings.TrimSpace(strings.ToLower(name)) {
		case "secrets":
			scanners = append(scanners, &SecretsScanner{})
		case "iac":
			scanners = append(scanners, &IaCScanner{})
		default:
			return nil, fmt.Errorf("unknown scanner: %s (valid: secrets, iac)", name)
		}
	}
	if len(scanners) == 0 {
		return nil, fmt.Errorf("no scanners specified")
	}
	return scanners, nil
}
