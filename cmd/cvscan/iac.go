package main

import (
	"context"
	"os"

	"github.com/aquasecurity/trivy/pkg/iac/detection"
	"github.com/aquasecurity/trivy/pkg/misconf"
)

// IaCScanner wraps trivy to detect infrastructure misconfigurations.
type IaCScanner struct{}

func (s *IaCScanner) Name() string   { return "IaC" }
func (s *IaCScanner) Type() ScanType { return ScanTypeIaC }

func (s *IaCScanner) Run(ctx context.Context, repoPath string) ([]Finding, error) {
	opt := misconf.ScannerOption{}

	var findings []Finding

	// Scan for Terraform misconfigurations
	tfFindings, err := s.scanFileType(ctx, repoPath, detection.FileTypeTerraform, opt)
	if err == nil {
		findings = append(findings, tfFindings...)
	}

	// Scan for CloudFormation misconfigurations
	cfnFindings, err := s.scanFileType(ctx, repoPath, detection.FileTypeCloudFormation, opt)
	if err == nil {
		findings = append(findings, cfnFindings...)
	}

	return findings, nil
}

func (s *IaCScanner) scanFileType(ctx context.Context, repoPath string, fileType detection.FileType, opt misconf.ScannerOption) ([]Finding, error) {
	scanner, err := misconf.NewScanner(fileType, opt)
	if err != nil {
		return nil, err
	}

	fsys := os.DirFS(repoPath)
	misconfs, err := scanner.Scan(ctx, fsys)
	if err != nil {
		return nil, err
	}

	var findings []Finding
	for _, mc := range misconfs {
		for _, f := range mc.Failures {
			findings = append(findings, Finding{
				ScanType:    ScanTypeIaC,
				RuleID:      f.ID,
				Description: f.Description,
				Severity:    f.Severity,
				File:        mc.FilePath,
				StartLine:   f.CauseMetadata.StartLine,
				EndLine:     f.CauseMetadata.EndLine,
				Repository:  repoPath,
				Resource:    f.CauseMetadata.Resource,
				Provider:    f.CauseMetadata.Provider,
				Service:     f.CauseMetadata.Service,
				Resolution:  f.RecommendedActions,
				Message:     f.Message,
			})
		}
	}

	return findings, nil
}
