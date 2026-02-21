package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

var version = "dev"

// threatRule defines a single threat explanation rule with compiled regex patterns,
// impact descriptions, audience targeting, and explanations.
type threatRule struct {
	ID          string
	Desc        string
	Severity    pluginv1.Severity
	Confidence  pluginv1.Confidence
	Impact      string
	Audience    string
	Explanation string
	CWE         string
	Patterns    map[string]*regexp.Regexp // extension -> compiled regex
}

// Compiled regex patterns for each threat explanation rule.
var rules = []threatRule{
	{
		ID:          "EXPLAIN-001",
		Desc:        "Authentication weakness: insecure authentication implementation detected",
		Severity:    sdk.SeverityHigh,
		Confidence:  sdk.ConfidenceHigh,
		Impact:      "Attackers could bypass authentication to gain unauthorized access to user accounts and sensitive data",
		Audience:    "developer",
		Explanation: "The authentication implementation uses weak patterns that could allow credential stuffing, brute force, or session hijacking attacks. This directly impacts user account security.",
		CWE:         "CWE-287",
		Patterns: map[string]*regexp.Regexp{
			".go": regexp.MustCompile(`(?i)(password\s*==\s*|strings\.Compare\(.*password|md5\.Sum\(.*password|sha1\.Sum\(.*password|plaintext.*password|password.*plaintext)`),
			".py": regexp.MustCompile(`(?i)(password\s*==\s*|hashlib\.md5\(.*password|hashlib\.sha1\(.*password|check_password\s*=\s*lambda|plaintext.*password|password.*plaintext)`),
			".js": regexp.MustCompile(`(?i)(password\s*===?\s*|md5\(.*password|sha1\(.*password|plaintext.*password|password.*plaintext|\.compareSync\(.*password.*,\s*["'])`),
			".ts": regexp.MustCompile(`(?i)(password\s*===?\s*|md5\(.*password|sha1\(.*password|plaintext.*password|password.*plaintext|\.compareSync\(.*password.*,\s*["'])`),
		},
	},
	{
		ID:          "EXPLAIN-002",
		Desc:        "Data exposure risk: sensitive data may be exposed through logs, responses, or error messages",
		Severity:    sdk.SeverityHigh,
		Confidence:  sdk.ConfidenceMedium,
		Impact:      "Sensitive customer or business data could be leaked through application logs, API responses, or error messages, leading to regulatory violations and reputational damage",
		Audience:    "executive",
		Explanation: "The application may expose sensitive data in places where it can be read by unauthorized parties. This creates compliance risks under GDPR, CCPA, and other data protection regulations.",
		CWE:         "CWE-200",
		Patterns: map[string]*regexp.Regexp{
			".go": regexp.MustCompile(`(?i)(log\.\w+\(.*(?:password|token|secret|key|credential|ssn|credit.?card)|fmt\.Print\w*\(.*(?:password|token|secret|key|credential)|json\.Marshal\(.*(?:password|secret|token))`),
			".py": regexp.MustCompile(`(?i)(print\(.*(?:password|token|secret|key|credential|ssn|credit.?card)|logging\.\w+\(.*(?:password|token|secret|key|credential)|repr\(.*(?:password|secret))`),
			".js": regexp.MustCompile(`(?i)(console\.log\(.*(?:password|token|secret|key|credential|ssn|credit.?card)|res\.(?:json|send)\(.*(?:password|secret|token|internal))`),
			".ts": regexp.MustCompile(`(?i)(console\.log\(.*(?:password|token|secret|key|credential|ssn|credit.?card)|res\.(?:json|send)\(.*(?:password|secret|token|internal))`),
		},
	},
	{
		ID:          "EXPLAIN-003",
		Desc:        "Access control gap: insufficient authorization checks on protected resources",
		Severity:    sdk.SeverityMedium,
		Confidence:  sdk.ConfidenceHigh,
		Impact:      "Users could access resources or perform actions beyond their authorized permissions, leading to privilege escalation and unauthorized data access",
		Audience:    "compliance",
		Explanation: "The code handles protected resources without proper authorization verification. This may violate least-privilege access controls required by SOC2, ISO 27001, and similar compliance frameworks.",
		CWE:         "CWE-862",
		Patterns: map[string]*regexp.Regexp{
			".go": regexp.MustCompile(`(?i)(r\.URL\.Path.*(?:admin|manage|config|internal|private)|http\.Handle\w*\(.*(?:admin|manage|delete|config).*,\s*\w+\)|mux\.\w+\(.*(?:admin|manage|delete|config))`),
			".py": regexp.MustCompile(`(?i)(@app\.route\(.*(?:admin|manage|config|internal|private)|@blueprint\.route\(.*(?:admin|manage|delete|config)|def\s+(?:admin|manage|delete)_\w+)`),
			".js": regexp.MustCompile(`(?i)(router\.\w+\(.*(?:admin|manage|config|internal|private)|app\.\w+\(.*(?:admin|manage|delete|config).*,\s*\w+\))`),
			".ts": regexp.MustCompile(`(?i)(router\.\w+\(.*(?:admin|manage|config|internal|private)|app\.\w+\(.*(?:admin|manage|delete|config).*,\s*\w+\))`),
		},
	},
	{
		ID:          "EXPLAIN-004",
		Desc:        "Encryption weakness: use of weak or outdated cryptographic algorithms",
		Severity:    sdk.SeverityMedium,
		Confidence:  sdk.ConfidenceMedium,
		Impact:      "Data protected by weak encryption could be decrypted by attackers, compromising confidentiality of stored or transmitted information",
		Audience:    "developer",
		Explanation: "The code uses cryptographic algorithms (MD5, SHA1, DES, RC4) that are considered broken or weak. These algorithms do not provide adequate protection against modern attacks and should be replaced with stronger alternatives.",
		CWE:         "CWE-327",
		Patterns: map[string]*regexp.Regexp{
			".go": regexp.MustCompile(`(?i)(crypto/md5|crypto/sha1|crypto/des|crypto/rc4|md5\.New\(\)|sha1\.New\(\)|des\.NewCipher|rc4\.NewCipher|tls\.TLS_RSA_|tls\.VersionSSL|tls\.VersionTLS10)`),
			".py": regexp.MustCompile(`(?i)(hashlib\.md5|hashlib\.sha1|from\s+Crypto\.Cipher\s+import\s+DES|DES\.new\(|ARC4\.new\(|ssl\.PROTOCOL_SSLv|ssl\.PROTOCOL_TLSv1\b)`),
			".js": regexp.MustCompile(`(?i)(crypto\.createHash\(\s*['"](?:md5|sha1)['"]|crypto\.createCipher\(\s*['"](?:des|rc4)|createCipheriv\(\s*['"](?:des|rc4))`),
			".ts": regexp.MustCompile(`(?i)(crypto\.createHash\(\s*['"](?:md5|sha1)['"]|crypto\.createCipher\(\s*['"](?:des|rc4)|createCipheriv\(\s*['"](?:des|rc4))`),
		},
	},
}

// supportedExtensions lists file extensions that the threat explanation scanner processes.
var supportedExtensions = map[string]bool{
	".go": true,
	".py": true,
	".js": true,
	".ts": true,
}

// skippedDirs contains directory names to skip during recursive walks.
var skippedDirs = map[string]bool{
	".git":         true,
	"vendor":       true,
	"node_modules": true,
	"__pycache__":  true,
	".venv":        true,
	"dist":         true,
	"build":        true,
}

func buildServer() *sdk.PluginServer {
	manifest := sdk.NewManifest("nox/threat-explain", version).
		Capability("threat-explain", "Detects threat patterns and explains their impact for different audiences").
		Tool("scan", "Scan source files for threat patterns with impact explanations and audience targeting", true).
		Done().
		Safety(sdk.WithRiskClass(sdk.RiskPassive)).
		Build()

	return sdk.NewPluginServer(manifest).
		HandleTool("scan", handleScan)
}

func handleScan(ctx context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	workspaceRoot, _ := req.Input["workspace_root"].(string)
	if workspaceRoot == "" {
		workspaceRoot = req.WorkspaceRoot
	}

	resp := sdk.NewResponse()

	if workspaceRoot == "" {
		return resp.Build(), nil
	}

	err := filepath.WalkDir(workspaceRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if skippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		ext := filepath.Ext(path)
		if !supportedExtensions[ext] {
			return nil
		}

		return scanFile(resp, path, ext)
	})
	if err != nil && err != context.Canceled {
		return nil, fmt.Errorf("walking workspace: %w", err)
	}

	return resp.Build(), nil
}

func scanFile(resp *sdk.ResponseBuilder, filePath, ext string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for i := range rules {
			rule := &rules[i]
			pattern, ok := rule.Patterns[ext]
			if !ok {
				continue
			}
			if pattern.MatchString(line) {
				resp.Finding(
					rule.ID,
					rule.Severity,
					rule.Confidence,
					fmt.Sprintf("%s: %s", rule.Desc, strings.TrimSpace(line)),
				).
					At(filePath, lineNum, lineNum).
					WithMetadata("cwe", rule.CWE).
					WithMetadata("impact", rule.Impact).
					WithMetadata("audience", rule.Audience).
					WithMetadata("explanation", rule.Explanation).
					WithMetadata("language", extToLanguage(ext)).
					Done()
			}
		}
	}

	return scanner.Err()
}

func extToLanguage(ext string) string {
	switch ext {
	case ".go":
		return "go"
	case ".py":
		return "python"
	case ".js":
		return "javascript"
	case ".ts":
		return "typescript"
	default:
		return "unknown"
	}
}

func main() {
	os.Exit(run())
}

func run() int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	srv := buildServer()
	if err := srv.Serve(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "nox-plugin-threat-explain: %v\n", err)
		return 1
	}
	return 0
}
