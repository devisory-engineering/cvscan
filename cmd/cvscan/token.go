package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type tokenRequest struct {
	EngagementID string `json:"engagement_id"`
	Token        string `json:"token"`
}

type tokenResponse struct {
	Valid     bool   `json:"valid"`
	ExpiresIn string `json:"expires_in,omitempty"`
	Error     string `json:"error,omitempty"`
}

var httpClient = &http.Client{Timeout: 15 * time.Second}

func validateToken(baseURL, engagementID, token string) (*tokenResponse, error) {
	body, err := json.Marshal(tokenRequest{
		EngagementID: engagementID,
		Token:        token,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal token request: %w", err)
	}

	resp, err := httpClient.Post(baseURL+"/validate-token", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to reach Cloudvisor API: %w", err)
	}
	defer resp.Body.Close()

	var result tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK || !result.Valid {
		msg := result.Error
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("token validation failed: %s", msg)
	}

	return &result, nil
}
