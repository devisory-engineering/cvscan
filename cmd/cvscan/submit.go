package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type submitRequest struct {
	Schema      string    `json:"schema"`
	ID          string    `json:"id"`
	GeneratedAt string    `json:"generated_at"`
	ReposPath   string    `json:"repos_path"`
	Summary     Summary   `json:"summary"`
	Findings    []Finding `json:"findings"`
}

var httpClient = &http.Client{Timeout: 15 * time.Second}

func submitFindings(baseURL, id string, result *ScanResult) error {
	payload := submitRequest{
		Schema:      "cloudvisor.cvscan-report.v1",
		ID:          id,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		ReposPath:   result.ReposPath,
		Summary:     result.Summary,
		Findings:    result.Findings,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal findings: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, baseURL+"/submit", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to reach Cloudvisor API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		return fmt.Errorf("findings already submitted for this ID")
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("submission failed with HTTP %d", resp.StatusCode)
	}

	return nil
}

func runSubmit(_ context.Context, id string, filePath string) error {
	if err := ValidateID(id); err != nil {
		return err
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read results file: %w", err)
	}

	var result ScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("failed to parse results JSON: %w", err)
	}

	fmt.Print("Submitting findings to Cloudvisor... ")
	if err := submitFindings(apiBaseURL, id, &result); err != nil {
		fmt.Println("FAILED")
		return err
	}
	fmt.Println("Done")
	return nil
}

func writeResultsJSON(result *ScanResult, path string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal results: %w", err)
	}
	return os.WriteFile(path, data, 0o644)
}

func jsonSidecarPath(htmlPath string) string {
	if htmlPath == "" {
		return ".cvscan-results.json"
	}
	dir := filepath.Dir(htmlPath)
	return filepath.Join(dir, ".cvscan-results.json")
}

// ValidateID checks that the ID has a valid prefix (eng_ or tok_).
func ValidateID(id string) error {
	if strings.HasPrefix(id, "eng_") || strings.HasPrefix(id, "tok_") {
		return nil
	}
	return fmt.Errorf("invalid ID %q: must start with eng_ or tok_", id)
}
