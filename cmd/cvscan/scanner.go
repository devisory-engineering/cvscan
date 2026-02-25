package main

import "context"

// ScanType categorizes the kind of scan that produced a finding.
type ScanType string

const (
	ScanTypeSecrets ScanType = "secrets"
	ScanTypeIaC     ScanType = "iac"
)

// Finding is a unified finding across all scanner types.
type Finding struct {
	ScanType    ScanType `json:"scan_type"`
	RuleID      string   `json:"rule_id"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	File        string   `json:"file"`
	StartLine   int      `json:"start_line"`
	EndLine     int      `json:"end_line"`
	Repository  string   `json:"repository"`

	// Secrets-specific (empty for IaC findings)
	SecretRedacted string `json:"secret_redacted,omitempty"`
	Commit         string `json:"commit,omitempty"`
	Author         string `json:"author,omitempty"`
	Date           string `json:"date,omitempty"`
	Fingerprint    string `json:"fingerprint,omitempty"`

	// IaC-specific (empty for secrets findings)
	Resource   string `json:"resource,omitempty"`
	Provider   string `json:"provider,omitempty"`
	Service    string `json:"service,omitempty"`
	Resolution string `json:"resolution,omitempty"`
	Message    string `json:"message,omitempty"`
}

// Scanner is implemented by each scan engine (secrets, iac).
type Scanner interface {
	Name() string
	Type() ScanType
	Run(ctx context.Context, repoPath string) ([]Finding, error)
}
