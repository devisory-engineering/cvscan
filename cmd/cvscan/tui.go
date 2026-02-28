package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// TUI styles
var (
	titleStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#ff5600"))
	promptStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#5f6d93"))
	successStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#22c55e"))
	errorStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#d93025"))
	mutedStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#5f6d93"))
	boxStyle     = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#ff5600")).
			Padding(0, 2)
)

type tuiStep int

const (
	stepScanners tuiStep = iota
	stepRepoPath
	stepConfirmRepos
	stepScanning
	stepDone
)

// Messages
type scanCompleteMsg struct {
	result *ScanResult
	err    error
}

type tuiModel struct {
	ctx  context.Context
	step tuiStep

	// Inputs
	pathInput textinput.Model

	// State
	reposPath      string
	repos          []string
	secretsEnabled bool
	iacEnabled     bool
	scanResult     *ScanResult

	// UI state
	spinner     spinner.Model
	cursor      int
	errMsg      string
	completions []string

	// Output
	reportPath string
}

func newTuiModel(ctx context.Context) tuiModel {
	pi := textinput.New()
	pi.Placeholder = "./my-repos/"
	pi.CharLimit = 512

	sp := spinner.New()
	sp.Spinner = spinner.Dot

	return tuiModel{
		ctx:            ctx,
		step:           stepScanners,
		pathInput:      pi,
		secretsEnabled: true,
		iacEnabled:     true,
		spinner:        sp,
		reportPath:     "cvscan-report.html",
	}
}

func (m tuiModel) Init() tea.Cmd {
	return nil
}

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			return m, tea.Quit
		}
	}

	switch m.step {
	case stepScanners:
		return m.updateScanners(msg)
	case stepRepoPath:
		return m.updateRepoPath(msg)
	case stepConfirmRepos:
		return m.updateConfirmRepos(msg)
	case stepScanning:
		return m.updateScanning(msg)
	case stepDone:
		if keyMsg, ok := msg.(tea.KeyMsg); ok && keyMsg.String() == "enter" {
			return m, tea.Quit
		}
	}

	return m, nil
}

func (m tuiModel) updateScanners(msg tea.Msg) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch keyMsg.String() {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < 1 {
				m.cursor++
			}
		case " ":
			if m.cursor == 0 {
				m.secretsEnabled = !m.secretsEnabled
			} else {
				m.iacEnabled = !m.iacEnabled
			}
		case "enter":
			if !m.secretsEnabled && !m.iacEnabled {
				m.errMsg = "select at least one scanner"
				return m, nil
			}
			m.errMsg = ""
			m.cursor = 0
			m.step = stepRepoPath
			m.pathInput.Focus()
			return m, textinput.Blink
		}
	}
	return m, nil
}

func (m tuiModel) updateRepoPath(msg tea.Msg) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch keyMsg.String() {
		case "tab":
			if len(m.completions) > 0 {
				m.pathInput.SetValue(m.completions[0])
				m.pathInput.SetCursor(len(m.completions[0]))
				m.completions = nil
			}
			return m, nil
		case "enter":
			val := strings.TrimSpace(m.pathInput.Value())
			if val == "" {
				m.errMsg = "repository path is required"
				return m, nil
			}
			if strings.HasPrefix(val, "~") {
				home, _ := os.UserHomeDir()
				val = filepath.Join(home, val[1:])
			}
			absPath, err := filepath.Abs(val)
			if err != nil {
				m.errMsg = fmt.Sprintf("invalid path: %v", err)
				return m, nil
			}
			repos, err := discoverRepos(absPath)
			if err != nil {
				m.errMsg = fmt.Sprintf("cannot read directory: %v", err)
				return m, nil
			}
			if len(repos) == 0 {
				m.errMsg = "no repositories found in that directory"
				return m, nil
			}
			m.reposPath = absPath
			m.repos = repos
			m.errMsg = ""
			m.step = stepConfirmRepos
			return m, nil
		}
	}

	var cmd tea.Cmd
	m.pathInput, cmd = m.pathInput.Update(msg)

	val := m.pathInput.Value()
	if val != "" {
		m.completions = pathCompletions(val)
	} else {
		m.completions = nil
	}

	return m, cmd
}

func pathCompletions(prefix string) []string {
	if strings.HasPrefix(prefix, "~") {
		home, _ := os.UserHomeDir()
		prefix = filepath.Join(home, prefix[1:])
	}

	dir := filepath.Dir(prefix)
	base := filepath.Base(prefix)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	var matches []string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), base) {
			matches = append(matches, filepath.Join(dir, e.Name())+"/")
		}
	}
	sort.Strings(matches)
	if len(matches) > 5 {
		matches = matches[:5]
	}
	return matches
}

func (m tuiModel) updateConfirmRepos(msg tea.Msg) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch keyMsg.String() {
		case "y", "Y", "enter":
			m.step = stepScanning
			return m, tea.Batch(m.spinner.Tick, m.runScanCmd())
		case "n", "N":
			m.step = stepRepoPath
			m.pathInput.Focus()
			m.pathInput.SetValue("")
			return m, textinput.Blink
		}
	}
	return m, nil
}

func (m tuiModel) runScanCmd() tea.Cmd {
	return func() tea.Msg {
		var scanners []Scanner
		if m.secretsEnabled {
			scanners = append(scanners, &SecretsScanner{})
		}
		if m.iacEnabled {
			scanners = append(scanners, &IaCScanner{})
		}

		result, err := Orchestrate(m.ctx, ScanRequest{
			ReposPath: m.reposPath,
			Scanners:  scanners,
		}, nil)
		return scanCompleteMsg{result: result, err: err}
	}
}

func (m tuiModel) updateScanning(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case scanCompleteMsg:
		if msg.err != nil {
			m.errMsg = msg.err.Error()
			m.step = stepRepoPath
			m.pathInput.Focus()
			return m, textinput.Blink
		}
		m.scanResult = msg.result

		if err := generateHTMLReport(msg.result, m.reportPath); err != nil {
			m.errMsg = fmt.Sprintf("report generation failed: %v", err)
		} else {
			_ = openInBrowser(m.reportPath)
		}

		// Write JSON sidecar
		jsonPath := jsonSidecarPath(m.reportPath)
		_ = writeResultsJSON(msg.result, jsonPath)

		m.step = stepDone
		return m, nil
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m tuiModel) View() string {
	var s strings.Builder

	s.WriteString(boxStyle.Render(
		titleStyle.Render("Cloudvisor Security Scanner") + "\n" +
			mutedStyle.Render("Powered by gitleaks + trivy"),
	))
	s.WriteString("\n\n")

	switch m.step {
	case stepScanners:
		s.WriteString(promptStyle.Render("? What would you like to scan?") + "\n")

		secretsCheck := "[ ]"
		if m.secretsEnabled {
			secretsCheck = "[x]"
		}
		iacCheck := "[ ]"
		if m.iacEnabled {
			iacCheck = "[x]"
		}

		secretsLine := fmt.Sprintf("  %s Secrets (API keys, credentials, tokens)", secretsCheck)
		iacLine := fmt.Sprintf("  %s Infrastructure as Code (Terraform, CloudFormation)", iacCheck)

		if m.cursor == 0 {
			s.WriteString(titleStyle.Render("> "+secretsLine) + "\n")
			s.WriteString("  " + iacLine + "\n")
		} else {
			s.WriteString("  " + secretsLine + "\n")
			s.WriteString(titleStyle.Render("> "+iacLine) + "\n")
		}
		s.WriteString(mutedStyle.Render("\n  space=toggle  enter=confirm"))

	case stepRepoPath:
		s.WriteString(promptStyle.Render("? Repository path: "))
		s.WriteString(m.pathInput.View())
		if len(m.completions) > 0 {
			s.WriteString("\n")
			for _, c := range m.completions {
				s.WriteString(mutedStyle.Render("    "+c) + "\n")
			}
			s.WriteString(mutedStyle.Render("  tab=complete"))
		}

	case stepConfirmRepos:
		s.WriteString(successStyle.Render("  Repository path: "+m.reposPath) + "\n")
		for _, r := range m.repos {
			s.WriteString(fmt.Sprintf("    %s\n", filepath.Base(r)))
		}
		s.WriteString(fmt.Sprintf("\n"+promptStyle.Render("? Scan all %d repositories? [Y/n] "), len(m.repos)))

	case stepScanning:
		s.WriteString(fmt.Sprintf("  %s Scanning %d repositories...", m.spinner.View(), len(m.repos)))

	case stepDone:
		if m.errMsg != "" {
			s.WriteString(errorStyle.Render("  Error: "+m.errMsg) + "\n")
		} else if m.scanResult != nil {
			r := m.scanResult
			s.WriteString(fmt.Sprintf("\n  Total: %d findings (%d secrets, %d IaC) across %d repos\n",
				r.Summary.TotalFindings, r.Summary.SecretsFindings, r.Summary.IaCFindings, r.Summary.ReposScanned))
			s.WriteString(successStyle.Render(fmt.Sprintf("\n  Report saved: %s\n", m.reportPath)))
			s.WriteString(mutedStyle.Render("\n  Use 'cvscan submit --id <eng_xxx>' to submit results to Cloudvisor."))
		}
		s.WriteString("\n" + mutedStyle.Render("  Press enter to exit."))
	}

	if m.errMsg != "" && m.step != stepDone {
		s.WriteString("\n" + errorStyle.Render("  "+m.errMsg))
	}

	s.WriteString("\n")
	return s.String()
}

func runTUI(ctx context.Context) error {
	model := newTuiModel(ctx)
	p := tea.NewProgram(model)
	_, err := p.Run()
	return err
}
