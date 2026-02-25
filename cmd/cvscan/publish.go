package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type submitRequest struct {
	Schema       string    `json:"schema"`
	EngagementID string    `json:"engagement_id"`
	GeneratedAt  string    `json:"generated_at"`
	ReposPath    string    `json:"repos_path"`
	Summary      Summary   `json:"summary"`
	Findings     []Finding `json:"findings"`
}

func submitFindings(baseURL, token string, result *ScanResult) error {
	payload := submitRequest{
		Schema:       "cloudvisor.cvscan-report.v1",
		EngagementID: result.EngagementID,
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		ReposPath:    result.ReposPath,
		Summary:      result.Summary,
		Findings:     result.Findings,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal findings: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, baseURL+"/submit-findings", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to reach Cloudvisor API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("submission failed with HTTP %d", resp.StatusCode)
	}

	return nil
}
