package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestIntegration_CLIFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Set up mock API server that captures the submission payload.
	var receivedPayload submitRequest
	var submitCalled bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/submit":
			submitCalled = true
			json.NewDecoder(r.Body).Decode(&receivedPayload)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Override apiBaseURL for test.
	originalURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = originalURL }()

	// Create temp dir with a "repo" containing a secret.
	tmpDir := t.TempDir()
	repoDir := filepath.Join(tmpDir, "test-repo")
	if err := os.MkdirAll(repoDir, 0o755); err != nil {
		t.Fatalf("failed to create repo dir: %v", err)
	}

	// Write a file with a known AWS key pattern.
	secretFile := filepath.Join(repoDir, "config.py")
	if err := os.WriteFile(secretFile, []byte(`AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"`), 0o644); err != nil {
		t.Fatalf("failed to write secret file: %v", err)
	}

	// Run the full CLI flow with --id to trigger submission.
	reportPath := filepath.Join(tmpDir, "report.html")
	err := runCLI(context.Background(), CLIConfig{
		ID:        "eng_test001",
		ReposPath: tmpDir,
		Output:    reportPath,
		Scanners:  "secrets",
	})
	if err != nil {
		t.Fatalf("CLI flow failed: %v", err)
	}

	// 1. Verify the HTML report was generated.
	info, err := os.Stat(reportPath)
	if os.IsNotExist(err) {
		t.Error("HTML report was not generated")
	} else if err != nil {
		t.Errorf("failed to stat report: %v", err)
	} else if info.Size() == 0 {
		t.Error("HTML report is empty")
	}

	// 2. Verify submission was attempted with the correct ID.
	if !submitCalled {
		t.Error("submit endpoint was never called")
	}
	if receivedPayload.ID != "eng_test001" {
		t.Errorf("wrong ID in submission: got %q, want %q",
			receivedPayload.ID, "eng_test001")
	}

	// 3. Verify no raw secrets leaked in the submission payload.
	for _, f := range receivedPayload.Findings {
		if f.SecretRedacted == "AKIAIOSFODNN7EXAMPLE" {
			t.Error("raw secret leaked in submission payload")
		}
	}

	// 4. Verify JSON sidecar was written.
	jsonPath := jsonSidecarPath(reportPath)
	if _, err := os.Stat(jsonPath); os.IsNotExist(err) {
		t.Error("JSON sidecar was not written")
	}

	// Log how many findings were detected for visibility.
	t.Logf("Findings submitted: %d (secrets=%d, iac=%d, repos=%d)",
		receivedPayload.Summary.TotalFindings,
		receivedPayload.Summary.SecretsFindings,
		receivedPayload.Summary.IaCFindings,
		receivedPayload.Summary.ReposScanned,
	)
}
