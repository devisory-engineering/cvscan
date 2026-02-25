package main

import "testing"

func TestRedactSecret(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty", "", ""},
		{"short 4 chars", "abcd", "****"},
		{"short 8 chars", "abcdefgh", "********"},
		{"normal", "AKIAIOSFODNN7EXAMPLE", "AKIA************MPLE"},
		{"exactly 9 chars", "123456789", "1234*6789"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redactSecret(tt.input)
			if got != tt.expected {
				t.Errorf("redactSecret(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}
