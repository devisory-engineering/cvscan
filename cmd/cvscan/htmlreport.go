package main

import (
	"embed"
	"fmt"
	"html/template"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

//go:embed templates/report.html
var reportTemplateFS embed.FS

type reportData struct {
	ScanDate        string
	ReposPath       string
	EngagementID    string
	Summary         Summary
	SecretsFindings []Finding
	IaCFindings     []Finding
}

var templateFuncs = template.FuncMap{
	"inc":   func(i int) int { return i + 1 },
	"lower": strings.ToLower,
}

func generateHTMLReport(result *ScanResult, outputPath string) error {
	tmplContent, err := reportTemplateFS.ReadFile("templates/report.html")
	if err != nil {
		return fmt.Errorf("failed to read report template: %w", err)
	}

	tmpl, err := template.New("report").Funcs(templateFuncs).Parse(string(tmplContent))
	if err != nil {
		return fmt.Errorf("failed to parse report template: %w", err)
	}

	var secrets, iac []Finding
	for _, f := range result.Findings {
		switch f.ScanType {
		case ScanTypeSecrets:
			secrets = append(secrets, f)
		case ScanTypeIaC:
			iac = append(iac, f)
		}
	}

	data := reportData{
		ScanDate:        formatLocalTimestamp(),
		ReposPath:       result.ReposPath,
		EngagementID:    result.EngagementID,
		Summary:         result.Summary,
		SecretsFindings: secrets,
		IaCFindings:     iac,
	}

	dir := filepath.Dir(outputPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create report file: %w", err)
	}
	defer f.Close()

	return tmpl.Execute(f, data)
}

func formatLocalTimestamp() string {
	now := time.Now()
	offset := now.Format("-0700")
	if len(offset) == 5 {
		offset = offset[:3] + ":" + offset[3:]
	}
	return now.Format("January 02, 2006, 15:04:05") + " (UTC" + offset + ")"
}

func openInBrowser(path string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", absPath)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", absPath)
	default:
		cmd = exec.Command("xdg-open", absPath)
	}

	return cmd.Start()
}
