package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vossi/bw-docker-guard/internal/config"
	"github.com/vossi/bw-docker-guard/internal/ownership"
)

// fakeDocker starts a test HTTP server listening on a Unix socket.
// It returns the socket path and a cleanup function.
func fakeDocker(t *testing.T, handler http.Handler) (string, func()) {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "docker.sock")

	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("failed to listen on unix socket: %v", err)
	}

	srv := &httptest.Server{
		Listener: l,
		Config:   &http.Server{Handler: handler},
	}
	srv.Start()

	return sock, func() {
		srv.Close()
	}
}

// newTestConfig creates a config that allows postgres:16 image,
// "mynet" network, and volume mounts under /project.
func newTestConfig() *config.Config {
	return &config.Config{
		ProjectDir:      "/project",
		AllowedImages:   []string{"postgres:16"},
		AllowedNetworks: []string{"mynet"},
		VolumeMountRoot: "/project",
	}
}

// doRequest sends an HTTP request through the proxy via the given Unix socket.
func doRequest(t *testing.T, sockPath, method, path, body string) *http.Response {
	t.Helper()

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", sockPath)
			},
		},
	}

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, "http://localhost"+path, bodyReader)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to send request: %v", err)
	}
	return resp
}

// startProxy creates a GuardedProxy listening on a Unix socket and returns
// the socket path, the tracker, and a cleanup function.
func startProxy(t *testing.T, cfg *config.Config, dockerSock string) (string, *ownership.Tracker, func()) {
	t.Helper()
	dir := t.TempDir()
	proxySock := filepath.Join(dir, "proxy.sock")

	tracker := ownership.New()
	handler := NewHandler(cfg, tracker, dockerSock)

	l, err := net.Listen("unix", proxySock)
	if err != nil {
		t.Fatalf("failed to listen on proxy socket: %v", err)
	}

	srv := &http.Server{Handler: handler}
	go srv.Serve(l)

	return proxySock, tracker, func() {
		srv.Close()
	}
}

// Test 1: GET requests are forwarded and responses returned
func TestProxy_GETForwarded(t *testing.T) {
	dockerSock, cleanup := fakeDocker(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `[{"Id":"abc123","Names":["/mycontainer"]}]`)
	}))
	defer cleanup()

	cfg := newTestConfig()
	proxySock, _, proxyCleanup := startProxy(t, cfg, dockerSock)
	defer proxyCleanup()

	resp := doRequest(t, proxySock, "GET", "/containers/json", "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	if !strings.Contains(string(bodyBytes), "abc123") {
		t.Errorf("response should contain forwarded data, got: %s", string(bodyBytes))
	}
}

// Test 2: Allowed POST /containers/create is forwarded and container ID tracked
func TestProxy_ContainerCreateAllowed_TracksID(t *testing.T) {
	containerID := "deadbeef1234567890abcdef"
	dockerSock, cleanup := fakeDocker(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/containers/create") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"Id":"%s","Warnings":[]}`, containerID)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer cleanup()

	cfg := newTestConfig()
	proxySock, tracker, proxyCleanup := startProxy(t, cfg, dockerSock)
	defer proxyCleanup()

	body := `{"Image":"postgres:16"}`
	resp := doRequest(t, proxySock, "POST", "/containers/create", body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 201, got %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Verify response body is still intact
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	if !strings.Contains(string(bodyBytes), containerID) {
		t.Errorf("response should contain container ID, got: %s", string(bodyBytes))
	}

	// Verify the container ID was tracked
	if !tracker.IsOwned(containerID) {
		t.Errorf("container ID %q should be tracked after create", containerID)
	}
}

// Test 2b: Container create with ?name= tracks the name for ownership
func TestProxy_ContainerCreateTracksName(t *testing.T) {
	containerID := "deadbeef1234567890abcdef"
	dockerSock, cleanup := fakeDocker(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/containers/create") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"Id":"%s","Warnings":[]}`, containerID)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer cleanup()

	cfg := newTestConfig()
	proxySock, tracker, proxyCleanup := startProxy(t, cfg, dockerSock)
	defer proxyCleanup()

	body := `{"Image":"postgres:16"}`
	resp := doRequest(t, proxySock, "POST", "/containers/create?name=my-postgres", body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 201, got %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Verify both ID and name are tracked
	if !tracker.IsOwned(containerID) {
		t.Errorf("container ID %q should be tracked", containerID)
	}
	if !tracker.IsOwned("my-postgres") {
		t.Errorf("container name %q should be tracked after create with ?name=", "my-postgres")
	}
}

// Test 2c: Container actions work with names, not just IDs
func TestProxy_ContainerActionByName(t *testing.T) {
	containerID := "deadbeef1234567890abcdef"
	dockerSock, cleanup := fakeDocker(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/containers/create") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"Id":"%s","Warnings":[]}`, containerID)
			return
		}
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/start") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer cleanup()

	cfg := newTestConfig()
	proxySock, _, proxyCleanup := startProxy(t, cfg, dockerSock)
	defer proxyCleanup()

	// Create with a name
	createResp := doRequest(t, proxySock, "POST", "/containers/create?name=my-postgres", `{"Image":"postgres:16"}`)
	createResp.Body.Close()

	// Start using the name instead of the ID
	startResp := doRequest(t, proxySock, "POST", "/containers/my-postgres/start", "")
	defer startResp.Body.Close()

	if startResp.StatusCode != http.StatusNoContent {
		bodyBytes, _ := io.ReadAll(startResp.Body)
		t.Fatalf("start by name: expected 204, got %d: %s", startResp.StatusCode, string(bodyBytes))
	}
}

// Test 3: Disallowed POST /containers/create returns 403
func TestProxy_ContainerCreateDenied(t *testing.T) {
	dockerSock, cleanup := fakeDocker(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Should never reach the Docker daemon
		t.Error("request should not have reached Docker daemon")
		w.WriteHeader(http.StatusOK)
	}))
	defer cleanup()

	cfg := newTestConfig()
	proxySock, _, proxyCleanup := startProxy(t, cfg, dockerSock)
	defer proxyCleanup()

	body := `{"Image":"evil:latest"}`
	resp := doRequest(t, proxySock, "POST", "/containers/create", body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	var msg struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(bodyBytes, &msg); err != nil {
		t.Fatalf("response body is not valid JSON: %v (body: %s)", err, string(bodyBytes))
	}
	if !strings.HasPrefix(msg.Message, "bw-docker-guard:") {
		t.Errorf("message should start with 'bw-docker-guard:', got: %s", msg.Message)
	}
}

// Test 4: Container ownership is tracked — verified via start on tracked container
func TestProxy_ContainerStartTracked(t *testing.T) {
	containerID := "deadbeef1234567890abcdef"
	dockerSock, cleanup := fakeDocker(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/containers/create") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"Id":"%s","Warnings":[]}`, containerID)
			return
		}
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/start") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer cleanup()

	cfg := newTestConfig()
	proxySock, _, proxyCleanup := startProxy(t, cfg, dockerSock)
	defer proxyCleanup()

	// First create the container
	createResp := doRequest(t, proxySock, "POST", "/containers/create", `{"Image":"postgres:16"}`)
	createResp.Body.Close()
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d", createResp.StatusCode)
	}

	// Now start the container — should succeed because it's tracked
	startResp := doRequest(t, proxySock, "POST", fmt.Sprintf("/containers/%s/start", containerID), "")
	defer startResp.Body.Close()

	if startResp.StatusCode != http.StatusNoContent {
		bodyBytes, _ := io.ReadAll(startResp.Body)
		t.Fatalf("start: expected 204, got %d: %s", startResp.StatusCode, string(bodyBytes))
	}
}

// Test 5: POST /containers/{id}/start on untracked container returns 403
func TestProxy_ContainerStartUntracked(t *testing.T) {
	dockerSock, cleanup := fakeDocker(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Should never reach Docker for unowned container actions
		t.Error("request should not have reached Docker daemon")
		w.WriteHeader(http.StatusOK)
	}))
	defer cleanup()

	cfg := newTestConfig()
	proxySock, _, proxyCleanup := startProxy(t, cfg, dockerSock)
	defer proxyCleanup()

	resp := doRequest(t, proxySock, "POST", "/containers/unknown999/start", "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for untracked container start, got %d", resp.StatusCode)
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	var msg struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(bodyBytes, &msg); err != nil {
		t.Fatalf("response is not valid JSON: %v (body: %s)", err, string(bodyBytes))
	}
	if !strings.HasPrefix(msg.Message, "bw-docker-guard:") {
		t.Errorf("message should start with 'bw-docker-guard:', got: %s", msg.Message)
	}
}

// Test 6: POST /containers/{id}/exec tracks exec ID from response
func TestProxy_ExecCreateTracksID(t *testing.T) {
	containerID := "deadbeef1234567890abcdef"
	execID := "exec-abc123def456"
	dockerSock, cleanup := fakeDocker(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/containers/create") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"Id":"%s","Warnings":[]}`, containerID)
			return
		}
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/exec") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"Id":"%s"}`, execID)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer cleanup()

	cfg := newTestConfig()
	proxySock, tracker, proxyCleanup := startProxy(t, cfg, dockerSock)
	defer proxyCleanup()

	// First create the container
	createResp := doRequest(t, proxySock, "POST", "/containers/create", `{"Image":"postgres:16"}`)
	createResp.Body.Close()
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d", createResp.StatusCode)
	}

	// Now create exec on the tracked container
	execResp := doRequest(t, proxySock, "POST", fmt.Sprintf("/containers/%s/exec", containerID), `{"Cmd":["sh"]}`)
	defer execResp.Body.Close()

	if execResp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(execResp.Body)
		t.Fatalf("exec create: expected 201, got %d: %s", execResp.StatusCode, string(bodyBytes))
	}

	// Verify the exec ID was tracked
	if !tracker.IsExecOwned(execID) {
		t.Errorf("exec ID %q should be tracked after exec create", execID)
	}
}

// Test 7: Denied request JSON body format
func TestProxy_DeniedResponseFormat(t *testing.T) {
	// Use /dev/null as docker socket — we should never connect
	proxySock := filepath.Join(t.TempDir(), "proxy.sock")
	cfg := newTestConfig()
	tracker := ownership.New()
	handler := NewHandler(cfg, tracker, "/nonexistent.sock")

	l, err := net.Listen("unix", proxySock)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	srv := &http.Server{Handler: handler}
	go srv.Serve(l)
	defer srv.Close()

	// Send a request that will be denied (POST to unknown endpoint)
	resp := doRequest(t, proxySock, "POST", "/v1.45/something/random", "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}

	// Verify Content-Type is JSON
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected Content-Type application/json, got %s", ct)
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	var msg struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(bodyBytes, &msg); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if !strings.HasPrefix(msg.Message, "bw-docker-guard:") {
		t.Errorf("message should start with 'bw-docker-guard:', got: %s", msg.Message)
	}
}

// Test 8: Verify logging to stderr (denied request)
func TestProxy_LoggingDenied(t *testing.T) {
	// Capture stderr by redirecting log output
	oldOutput := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	// Also redirect the default logger
	oldFlags := log.Flags()
	log.SetOutput(w)
	log.SetFlags(0)
	defer func() {
		os.Stderr = oldOutput
		log.SetOutput(oldOutput)
		log.SetFlags(oldFlags)
	}()

	proxySock := filepath.Join(t.TempDir(), "proxy.sock")
	cfg := newTestConfig()
	tracker := ownership.New()
	handler := NewHandler(cfg, tracker, "/nonexistent.sock")

	l, err := net.Listen("unix", proxySock)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	srv := &http.Server{Handler: handler}
	go srv.Serve(l)
	defer srv.Close()

	resp := doRequest(t, proxySock, "POST", "/v1.45/something/random", "")
	resp.Body.Close()

	w.Close()
	logOutput, _ := io.ReadAll(r)
	logStr := string(logOutput)

	if !strings.Contains(logStr, "DENIED") {
		t.Errorf("log should contain DENIED, got: %s", logStr)
	}
	if !strings.Contains(logStr, "bw-docker-guard") {
		t.Errorf("log should contain bw-docker-guard, got: %s", logStr)
	}
}
