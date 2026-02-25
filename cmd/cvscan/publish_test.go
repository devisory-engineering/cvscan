package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSubmitFindings_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/submit-findings" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("missing or wrong auth header")
		}

		var body submitRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.EngagementID != "ENG-123" {
			t.Errorf("unexpected engagement_id: %s", body.EngagementID)
		}
		if body.Summary.TotalFindings != 1 {
			t.Errorf("unexpected total_findings: %d", body.Summary.TotalFindings)
		}

		for _, f := range body.Findings {
			if f.SecretRedacted == "AKIAIOSFODNN7EXAMPLE" {
				t.Error("raw secret was sent — redaction failed")
			}
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	result := &ScanResult{
		EngagementID: "ENG-123",
		ReposPath:    "/tmp/repos",
		Findings: []Finding{
			{
				ScanType:       ScanTypeSecrets,
				RuleID:         "aws-access-key",
				SecretRedacted: "AKIA********MPLE",
				File:           "config.py",
				StartLine:      10,
			},
		},
		Summary: Summary{TotalFindings: 1, SecretsFindings: 1},
	}

	err := submitFindings(server.URL, "test-token", result)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSubmitFindings_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	result := &ScanResult{EngagementID: "ENG-123", Summary: Summary{}}
	err := submitFindings(server.URL, "test-token", result)
	if err == nil {
		t.Error("expected error on server error")
	}
}
