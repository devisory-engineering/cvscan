package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverRepos_SingleRepo(t *testing.T) {
	tmpDir := t.TempDir()
	os.MkdirAll(filepath.Join(tmpDir, ".git"), 0o755)
	os.MkdirAll(filepath.Join(tmpDir, "src"), 0o755)
	os.MkdirAll(filepath.Join(tmpDir, "tests"), 0o755)

	repos, err := discoverRepos(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 1 {
		t.Fatalf("expected 1 repo, got %d: %v", len(repos), repos)
	}
	if repos[0] != tmpDir {
		t.Errorf("expected %s, got %s", tmpDir, repos[0])
	}
}

func TestDiscoverRepos_MultipleRepos(t *testing.T) {
	tmpDir := t.TempDir()
	os.MkdirAll(filepath.Join(tmpDir, "api"), 0o755)
	os.MkdirAll(filepath.Join(tmpDir, "frontend"), 0o755)
	os.MkdirAll(filepath.Join(tmpDir, "infra"), 0o755)

	repos, err := discoverRepos(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 3 {
		t.Fatalf("expected 3 repos, got %d: %v", len(repos), repos)
	}
}

func TestDiscoverRepos_HiddenDirsExcluded(t *testing.T) {
	tmpDir := t.TempDir()
	os.MkdirAll(filepath.Join(tmpDir, "visible"), 0o755)
	os.MkdirAll(filepath.Join(tmpDir, ".hidden"), 0o755)

	repos, err := discoverRepos(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 1 {
		t.Fatalf("expected 1 repo, got %d: %v", len(repos), repos)
	}
}
