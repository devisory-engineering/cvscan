package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidateToken_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/validate-token" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		var body tokenRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.EngagementID != "ENG-123" || body.Token != "abc" {
			t.Errorf("unexpected body: %+v", body)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(tokenResponse{Valid: true, ExpiresIn: "5 days"})
	}))
	defer server.Close()

	resp, err := validateToken(server.URL, "ENG-123", "abc")
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Valid {
		t.Error("expected valid token")
	}
}

func TestValidateToken_Invalid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(tokenResponse{Valid: false, Error: "token expired"})
	}))
	defer server.Close()

	_, err := validateToken(server.URL, "ENG-123", "bad-token")
	if err == nil {
		t.Error("expected error for invalid token")
	}
}
