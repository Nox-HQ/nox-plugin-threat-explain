package main

import (
	"context"
	"net"
	"path/filepath"
	"runtime"
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/registry"
	"github.com/nox-hq/nox/sdk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestConformance(t *testing.T) {
	sdk.RunConformance(t, buildServer())
}

func TestTrackConformance(t *testing.T) {
	sdk.RunForTrack(t, buildServer(), registry.TrackAgentAssistance)
}

func TestScanFindsAuthenticationWeakness(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "EXPLAIN-001")
	if len(found) == 0 {
		t.Fatal("expected at least one EXPLAIN-001 (authentication weakness) finding")
	}

	for _, f := range found {
		if f.GetLocation() == nil {
			t.Error("finding must include a location")
			continue
		}
		if f.GetLocation().GetStartLine() == 0 {
			t.Error("finding location must have a non-zero start line")
		}
		if f.GetSeverity() != sdk.SeverityHigh {
			t.Errorf("EXPLAIN-001 severity should be HIGH, got %v", f.GetSeverity())
		}
		if f.GetMetadata()["audience"] != "developer" {
			t.Errorf("expected audience=developer, got %q", f.GetMetadata()["audience"])
		}
		if f.GetMetadata()["impact"] == "" {
			t.Error("finding must include impact metadata")
		}
		if f.GetMetadata()["explanation"] == "" {
			t.Error("finding must include explanation metadata")
		}
	}
}

func TestScanFindsDataExposure(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "EXPLAIN-002")
	if len(found) == 0 {
		t.Fatal("expected at least one EXPLAIN-002 (data exposure) finding")
	}

	for _, f := range found {
		if f.GetMetadata()["audience"] != "executive" {
			t.Errorf("expected audience=executive, got %q", f.GetMetadata()["audience"])
		}
		if f.GetMetadata()["cwe"] != "CWE-200" {
			t.Errorf("expected CWE-200, got %q", f.GetMetadata()["cwe"])
		}
	}
}

func TestScanFindsAccessControlGap(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "EXPLAIN-003")
	if len(found) == 0 {
		t.Fatal("expected at least one EXPLAIN-003 (access control gap) finding")
	}

	for _, f := range found {
		if f.GetMetadata()["audience"] != "compliance" {
			t.Errorf("expected audience=compliance, got %q", f.GetMetadata()["audience"])
		}
		if f.GetSeverity() != sdk.SeverityMedium {
			t.Errorf("EXPLAIN-003 severity should be MEDIUM, got %v", f.GetSeverity())
		}
	}
}

func TestScanFindsEncryptionWeakness(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "EXPLAIN-004")
	if len(found) == 0 {
		t.Fatal("expected at least one EXPLAIN-004 (encryption weakness) finding")
	}

	for _, f := range found {
		if f.GetMetadata()["audience"] != "developer" {
			t.Errorf("expected audience=developer, got %q", f.GetMetadata()["audience"])
		}
		if f.GetMetadata()["cwe"] != "CWE-327" {
			t.Errorf("expected CWE-327, got %q", f.GetMetadata()["cwe"])
		}
	}
}

func TestScanEmptyWorkspace(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, t.TempDir())

	if len(resp.GetFindings()) != 0 {
		t.Errorf("expected zero findings for empty workspace, got %d", len(resp.GetFindings()))
	}
}

func TestScanNoWorkspace(t *testing.T) {
	client := testClient(t)
	input, err := structpb.NewStruct(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "scan",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}
	if len(resp.GetFindings()) != 0 {
		t.Errorf("expected zero findings when no workspace provided, got %d", len(resp.GetFindings()))
	}
}

// --- helpers ---

func testdataDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine test file path")
	}
	return filepath.Join(filepath.Dir(filename), "testdata")
}

func testClient(t *testing.T) pluginv1.PluginServiceClient {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	pluginv1.RegisterPluginServiceServer(grpcServer, buildServer())
	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(func() { grpcServer.Stop() })

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return pluginv1.NewPluginServiceClient(conn)
}

func invokeScan(t *testing.T, client pluginv1.PluginServiceClient, workspaceRoot string) *pluginv1.InvokeToolResponse {
	t.Helper()
	input, _ := structpb.NewStruct(map[string]any{"workspace_root": workspaceRoot})
	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "scan",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool(scan): %v", err)
	}
	return resp
}

func findByRule(findings []*pluginv1.Finding, ruleID string) []*pluginv1.Finding {
	var result []*pluginv1.Finding
	for _, f := range findings {
		if f.GetRuleId() == ruleID {
			result = append(result, f)
		}
	}
	return result
}
