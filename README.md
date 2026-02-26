# cvscan

Cloudvisor Security Scanner — secrets & IaC misconfiguration scanning for customer repositories.

Built on [gitleaks](https://github.com/gitleaks/gitleaks) (secrets detection) and [trivy](https://github.com/aquasecurity/trivy) (IaC scanning).

## What it does

- **Secrets scanning**: Detects leaked credentials, API keys, and tokens in git history and working tree
- **IaC scanning**: Detects Terraform and CloudFormation misconfigurations
- **HTML report**: Generates a local report with findings grouped by severity
- **Findings submission**: Sends redacted metadata to Cloudvisor backend (no source code transmitted)

## Installation

Download the latest release for your platform from [Releases](../../releases).

Or build from source:

```bash
go build -o cvscan ./cmd/cvscan/
```

## Usage

### Interactive mode (TUI)

```bash
cvscan
```

Launches the interactive terminal UI that guides you through engagement ID, token entry, and folder selection.

### CLI mode

```bash
cvscan --engagement-id eng_acme_12345 --token <token> /path/to/repos
```

All flags:

```
--engagement-id    Cloudvisor engagement ID (eng_XXXXX)
--token            Scan token (provided by Cloudvisor engineer)
--scanners         Comma-separated: secrets,iac (default: both)
--output, -o       HTML report path (default: cvscan-report.html)
--dry-run          Scan and report, skip submission
--no-submit        Skip submission entirely (local-only mode)
```

### Local testing (no backend)

```bash
# Scan without any backend interaction
cvscan --no-submit --engagement-id eng_test --token dummy /path/to/repos

# Scan and see what would be submitted, but don't actually submit
cvscan --dry-run --engagement-id eng_test --token dummy /path/to/repos
```

## How tokens work

1. A Cloudvisor engineer generates a token via `/cvscan-token eng_XXXXX` in Slack (or it's auto-generated at kickoff)
2. The token is shared with the customer
3. The customer runs `cvscan` with the token — it validates against the backend before scanning
4. After submission, the token is consumed (single-use, 7-day expiry)

## License

This project is a fork of [gitleaks](https://github.com/gitleaks/gitleaks) (MIT License).
See [THIRD_PARTY_LICENSES](THIRD_PARTY_LICENSES) for full attribution.
