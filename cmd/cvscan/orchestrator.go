package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// ScanRequest holds all inputs for a scan run.
type ScanRequest struct {
	ReposPath string
	Scanners  []Scanner
}

// ScanResult holds the output of a complete scan run.
type ScanResult struct {
	ReposPath string    `json:"repos_path"`
	Findings  []Finding `json:"findings"`
	Summary   Summary   `json:"summary"`
}

// Summary provides aggregate counts for the scan.
type Summary struct {
	TotalFindings   int `json:"total_findings"`
	SecretsFindings int `json:"secrets_findings"`
	IaCFindings     int `json:"iac_findings"`
	ReposScanned    int `json:"repos_scanned"`
	ReposAffected   int `json:"repos_affected"`
}

// ProgressFunc is called to report scan progress to the UI.
type ProgressFunc func(scanner string, repo string, findings int)

// Orchestrate runs all scanners against all repositories under reposPath.
func Orchestrate(ctx context.Context, req ScanRequest, progress ProgressFunc) (*ScanResult, error) {
	repos, err := discoverRepos(req.ReposPath)
	if err != nil {
		return nil, err
	}
	if len(repos) == 0 {
		return nil, fmt.Errorf("no repositories found in %s", req.ReposPath)
	}

	var allFindings []Finding
	affectedRepos := make(map[string]bool)

	for _, scanner := range req.Scanners {
		for _, repo := range repos {
			repoName := filepath.Base(repo)
			findings, err := scanner.Run(ctx, repo)
			if err != nil {
				if progress != nil {
					progress(scanner.Name(), repoName, -1)
				}
				continue
			}

			for i := range findings {
				findings[i].Repository = repoName
			}

			if len(findings) > 0 {
				affectedRepos[repoName] = true
			}

			allFindings = append(allFindings, findings...)

			if progress != nil {
				progress(scanner.Name(), repoName, len(findings))
			}
		}
	}

	var secretsCount, iacCount int
	for _, f := range allFindings {
		switch f.ScanType {
		case ScanTypeSecrets:
			secretsCount++
		case ScanTypeIaC:
			iacCount++
		}
	}

	return &ScanResult{
		ReposPath: req.ReposPath,
		Findings:  allFindings,
		Summary: Summary{
			TotalFindings:   len(allFindings),
			SecretsFindings: secretsCount,
			IaCFindings:     iacCount,
			ReposScanned:    len(repos),
			ReposAffected:   len(affectedRepos),
		},
	}, nil
}

// discoverRepos returns sorted paths to directories under root.
func discoverRepos(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("cannot read repos directory: %w", err)
	}

	var repos []string
	for _, entry := range entries {
		if entry.IsDir() && !isHiddenDir(entry.Name()) {
			repos = append(repos, filepath.Join(root, entry.Name()))
		}
	}
	sort.Strings(repos)
	return repos, nil
}

func isHiddenDir(name string) bool {
	return len(name) > 0 && name[0] == '.'
}
