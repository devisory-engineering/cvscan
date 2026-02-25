package main

import (
	"context"
	"strings"

	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

// SecretsScanner wraps gitleaks to detect secrets in repositories.
type SecretsScanner struct{}

func (s *SecretsScanner) Name() string   { return "Secrets" }
func (s *SecretsScanner) Type() ScanType { return ScanTypeSecrets }

func (s *SecretsScanner) Run(ctx context.Context, repoPath string) ([]Finding, error) {
	detector, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return nil, err
	}
	detector.Redact = 0 // we handle redaction ourselves

	// Scan git history
	gitFindings, err := s.scanGit(ctx, detector, repoPath)
	if err != nil {
		// Non-fatal: fall through to directory scan
		gitFindings = nil
	}

	// Scan working tree (catches uncommitted secrets)
	dirFindings, err := s.scanDirectory(ctx, detector, repoPath)
	if err != nil {
		return nil, err
	}

	var findings []Finding
	seen := make(map[string]bool)

	for _, f := range append(gitFindings, dirFindings...) {
		if seen[f.Fingerprint] {
			continue
		}
		seen[f.Fingerprint] = true
		findings = append(findings, convertSecretFinding(f, repoPath))
	}

	return findings, nil
}

func (s *SecretsScanner) scanGit(ctx context.Context, detector *detect.Detector, repoPath string) ([]report.Finding, error) {
	gitCmd, err := sources.NewGitLogCmdContext(ctx, repoPath, "")
	if err != nil {
		return nil, err
	}

	return detector.DetectSource(ctx, &sources.Git{
		Cmd:    gitCmd,
		Config: &detector.Config,
		Sema:   detector.Sema,
	})
}

func (s *SecretsScanner) scanDirectory(ctx context.Context, detector *detect.Detector, repoPath string) ([]report.Finding, error) {
	return detector.DetectSource(ctx, &sources.Files{
		Path:   repoPath,
		Config: &detector.Config,
		Sema:   detector.Sema,
	})
}

func convertSecretFinding(f report.Finding, repoPath string) Finding {
	commit := f.Commit
	if commit == "" {
		commit = "uncommitted"
	} else if len(commit) > 8 {
		commit = commit[:8]
	}

	author := strings.TrimSpace(f.Author)
	email := strings.TrimSpace(f.Email)
	if author != "" && email != "" {
		author = author + " <" + email + ">"
	} else if author == "" && commit == "uncommitted" {
		author = "uncommitted"
	}

	return Finding{
		ScanType:       ScanTypeSecrets,
		RuleID:         f.RuleID,
		Description:    f.Description,
		Severity:       "HIGH",
		File:           f.File,
		StartLine:      f.StartLine,
		EndLine:        f.EndLine,
		Repository:     repoPath,
		SecretRedacted: redactSecret(f.Secret),
		Commit:         commit,
		Author:         author,
		Date:           f.Date,
		Fingerprint:    f.Fingerprint,
	}
}
