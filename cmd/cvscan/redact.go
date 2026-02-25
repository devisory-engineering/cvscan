package main

import "strings"

// redactSecret masks the middle of a secret, showing only the first 4
// and last 4 characters. Secrets of 8 characters or fewer are fully masked.
func redactSecret(secret string) string {
	if secret == "" {
		return ""
	}
	if len(secret) <= 8 {
		return strings.Repeat("*", len(secret))
	}
	return secret[:4] + strings.Repeat("*", len(secret)-8) + secret[len(secret)-4:]
}
