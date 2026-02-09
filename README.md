# nox-plugin-threat-explain

**Threat pattern detection with audience-targeted impact explanations for developers, executives, and compliance teams.**

## Overview

`nox-plugin-threat-explain` is a Nox security scanner plugin that detects threat patterns in source code and provides human-readable explanations tailored to different audiences. Each finding includes a business impact statement, a detailed technical explanation, and an audience tag (developer, executive, or compliance) so teams can route findings to the right stakeholders.

Security findings are useless if the people who need to act on them cannot understand them. A developer needs to know the technical mechanism. An executive needs to know the business impact. A compliance officer needs to know which controls are affected. This plugin generates a single finding that speaks to all three audiences, eliminating the translation layer between security tools and the teams that consume their output.

The plugin detects authentication weaknesses, data exposure risks, access control gaps, and encryption weaknesses across Go, Python, JavaScript, and TypeScript. It operates in passive read-only mode, produces deterministic results, and requires no external services.

## Use Cases

### Executive Security Briefings

Your CISO needs a weekly security status that non-technical board members can understand. The plugin produces findings with business impact statements ("Attackers could bypass authentication to gain unauthorized access to user accounts and sensitive data") that feed directly into executive briefings without requiring a security engineer to translate technical findings.

### Developer-Focused Security Feedback

Your engineering team receives security scan results but ignores them because the findings are cryptic identifiers with no context. The plugin produces developer-targeted explanations that describe the technical mechanism, the specific code pattern detected, and why it matters -- turning opaque findings into actionable code review comments.

### Compliance-Oriented Audit Evidence

Your GRC team needs findings mapped to specific compliance frameworks. The plugin tags findings for the compliance audience with references to SOC 2, ISO 27001, and least-privilege requirements, producing evidence that maps directly to audit control requirements without manual cross-referencing.

### Multi-Stakeholder Security Reports

Your security team produces a single scan report that goes to developers, management, and auditors. The plugin enriches each finding with audience-specific metadata so a single report can be filtered by stakeholder, eliminating the need to produce separate reports for different audiences.

## 5-Minute Demo

### Prerequisites

- Go 1.25+
- [Nox](https://github.com/Nox-HQ/nox) installed

### Quick Start

1. **Install the plugin**

   ```bash
   nox plugin install Nox-HQ/nox-plugin-threat-explain
   ```

2. **Create a test file with threat patterns**

   ```bash
   mkdir -p demo-explain && cd demo-explain

   cat > auth.go <<'EOF'
   package main

   import (
       "crypto/md5"
       "encoding/json"
       "fmt"
       "log"
       "net/http"
   )

   func login(w http.ResponseWriter, r *http.Request) {
       password := r.FormValue("password")
       stored := "admin123"
       if password == stored {
           fmt.Fprintf(w, "Welcome!")
       }
       log.Printf("Login attempt for user with password: %s", password)
   }

   func hashData(data string) string {
       h := md5.New()
       h.Write([]byte(data))
       return fmt.Sprintf("%x", h.Sum(nil))
   }

   func adminPanel(w http.ResponseWriter, r *http.Request) {
       http.HandleFunc("/admin/delete", deleteHandler)
   }
   EOF
   ```

3. **Run the scan**

   ```bash
   nox scan --plugin nox/threat-explain demo-explain/
   ```

4. **Review findings**

   ```
   nox/threat-explain scan completed: 4 findings

   EXPLAIN-001 [HIGH] Authentication weakness: insecure authentication implementation detected:
       if password == stored {
     Location: demo-explain/auth.go:14
     Confidence: high
     Audience: developer
     CWE: CWE-287
     Impact: Attackers could bypass authentication to gain unauthorized access to user accounts
             and sensitive data
     Explanation: The authentication implementation uses weak patterns that could allow credential
             stuffing, brute force, or session hijacking attacks. This directly impacts user
             account security.

   EXPLAIN-002 [HIGH] Data exposure risk: sensitive data may be exposed through logs:
       log.Printf("Login attempt for user with password: %s", password)
     Location: demo-explain/auth.go:17
     Confidence: medium
     Audience: executive
     CWE: CWE-200
     Impact: Sensitive customer or business data could be leaked through application logs, API
             responses, or error messages, leading to regulatory violations and reputational damage
     Explanation: The application may expose sensitive data in places where it can be read by
             unauthorized parties. This creates compliance risks under GDPR, CCPA, and other
             data protection regulations.

   EXPLAIN-004 [MEDIUM] Encryption weakness: use of weak or outdated cryptographic algorithms:
       h := md5.New()
     Location: demo-explain/auth.go:21
     Confidence: medium
     Audience: developer
     CWE: CWE-327
     Impact: Data protected by weak encryption could be decrypted by attackers, compromising
             confidentiality of stored or transmitted information
     Explanation: The code uses cryptographic algorithms (MD5, SHA1, DES, RC4) that are considered
             broken or weak. These algorithms do not provide adequate protection against modern
             attacks and should be replaced with stronger alternatives.

   EXPLAIN-003 [MEDIUM] Access control gap: insufficient authorization checks:
       http.HandleFunc("/admin/delete", deleteHandler)
     Location: demo-explain/auth.go:26
     Confidence: high
     Audience: compliance
     CWE: CWE-862
     Impact: Users could access resources or perform actions beyond their authorized permissions,
             leading to privilege escalation and unauthorized data access
     Explanation: The code handles protected resources without proper authorization verification.
             This may violate least-privilege access controls required by SOC2, ISO 27001, and
             similar compliance frameworks.
   ```

## Rules

| Rule ID     | Description | Severity | Confidence | CWE | Audience |
|-------------|-------------|----------|------------|-----|----------|
| EXPLAIN-001 | Authentication weakness: insecure authentication implementation (plaintext password comparison, weak hashing for passwords) | High | High | CWE-287 | developer |
| EXPLAIN-002 | Data exposure risk: sensitive data (passwords, tokens, secrets, SSN, credit cards) exposed through logs, print statements, or API responses | High | Medium | CWE-200 | executive |
| EXPLAIN-003 | Access control gap: admin/management/config/private endpoints without apparent authorization middleware | Medium | High | CWE-862 | compliance |
| EXPLAIN-004 | Encryption weakness: use of broken or weak cryptographic algorithms (MD5, SHA1, DES, RC4, SSLv3, TLS 1.0) | Medium | Medium | CWE-327 | developer |

## Supported Languages / File Types

| Language | Extensions |
|----------|-----------|
| Go | `.go` |
| Python | `.py` |
| JavaScript | `.js` |
| TypeScript | `.ts` |

## Configuration

The plugin operates with sensible defaults and requires no configuration. It scans the entire workspace recursively, skipping `.git`, `vendor`, `node_modules`, `__pycache__`, `.venv`, `dist`, and `build` directories.

Pass `workspace_root` as input to override the default scan directory:

```bash
nox scan --plugin nox/threat-explain --input workspace_root=/path/to/project
```

## Installation

### Via Nox (recommended)

```bash
nox plugin install Nox-HQ/nox-plugin-threat-explain
```

### Standalone

```bash
git clone https://github.com/Nox-HQ/nox-plugin-threat-explain.git
cd nox-plugin-threat-explain
make build
```

## Development

```bash
# Build the plugin binary
make build

# Run tests with race detection
make test

# Run linter
make lint

# Clean build artifacts
make clean

# Build Docker image
docker build -t nox-plugin-threat-explain .
```

## Architecture

The plugin follows the standard Nox plugin architecture, communicating via the Nox Plugin SDK over stdio.

1. **File Discovery**: Recursively walks the workspace, filtering for supported source file extensions (`.go`, `.py`, `.js`, `.ts`).

2. **Pattern Matching**: Each source file is scanned line by line against compiled regex patterns. Each rule carries language-specific patterns that detect specific threat categories.

3. **Audience-Targeted Enrichment**: Each finding is enriched with five metadata fields:
   - `cwe` -- CWE identifier for technical classification
   - `impact` -- Business impact statement describing what could go wrong
   - `audience` -- Target audience: `developer`, `executive`, or `compliance`
   - `explanation` -- Detailed explanation of the threat and its implications
   - `language` -- Source language of the finding

4. **Stakeholder Routing**: The audience tag enables downstream tooling to route findings to the appropriate team. Developer findings explain the code fix needed. Executive findings describe business risk. Compliance findings reference control frameworks.

All analysis is deterministic, offline, and read-only.

## Contributing

Contributions are welcome. Please open an issue or submit a pull request on the [GitHub repository](https://github.com/Nox-HQ/nox-plugin-threat-explain).

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Write tests for your changes
4. Ensure `make test` and `make lint` pass
5. Submit a pull request

## License

Apache-2.0
