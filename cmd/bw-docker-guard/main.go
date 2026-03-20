package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/vossi/bw-docker-guard/internal/config"
	"github.com/vossi/bw-docker-guard/internal/ownership"
	"github.com/vossi/bw-docker-guard/internal/proxy"
)

func main() {
	configPath := flag.String("config", "", "Path to allowlist JSON config")
	socketPath := flag.String("socket", "", "Path to Unix socket to listen on")
	dockerSocket := flag.String("docker-socket", "/var/run/docker.sock", "Path to real Docker socket")
	flag.Parse()

	if *configPath == "" || *socketPath == "" {
		fmt.Fprintln(os.Stderr, "Usage: bw-docker-guard --config <path> --socket <path>")
		os.Exit(1)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("[bw-docker-guard] failed to load config: %v", err)
	}

	tracker := ownership.New()

	// Pre-populate tracker with existing compose project containers.
	if cfg.ComposeProject != "" {
		if err := seedComposeContainers(tracker, *dockerSocket, cfg.ComposeProject); err != nil {
			log.Printf("[bw-docker-guard] WARNING: failed to seed compose containers: %v", err)
		}
	}

	handler := proxy.NewHandler(cfg, tracker, *dockerSocket)

	// Remove any existing socket file.
	if err := os.Remove(*socketPath); err != nil && !os.IsNotExist(err) {
		log.Fatalf("[bw-docker-guard] failed to remove existing socket: %v", err)
	}

	listener, err := net.Listen("unix", *socketPath)
	if err != nil {
		log.Fatalf("[bw-docker-guard] failed to listen on %s: %v", *socketPath, err)
	}

	// Make socket accessible.
	if err := os.Chmod(*socketPath, 0660); err != nil {
		log.Printf("[bw-docker-guard] WARNING: failed to chmod socket: %v", err)
	}

	srv := &http.Server{Handler: handler}

	// Graceful shutdown on SIGTERM/SIGINT.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	go func() {
		<-ctx.Done()
		log.Println("[bw-docker-guard] shutting down...")
		srv.Close()
	}()

	mode := "guarded"
	if cfg.IsReadOnly() {
		mode = "read-only"
	}
	log.Printf("[bw-docker-guard] listening on %s (mode: %s)", *socketPath, mode)

	if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
		log.Fatalf("[bw-docker-guard] server error: %v", err)
	}
}

// seedComposeContainers queries the Docker daemon for containers belonging
// to the given compose project and adds their IDs to the tracker.
func seedComposeContainers(tracker *ownership.Tracker, dockerSocket, composeProject string) error {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", dockerSocket)
			},
		},
	}

	filtersJSON, err := json.Marshal(map[string][]string{
		"label": {fmt.Sprintf("com.docker.compose.project=%s", composeProject)},
	})
	if err != nil {
		return fmt.Errorf("marshaling filters: %w", err)
	}

	reqURL := fmt.Sprintf("http://localhost/containers/json?filters=%s", url.QueryEscape(string(filtersJSON)))
	resp, err := client.Get(reqURL)
	if err != nil {
		return fmt.Errorf("querying Docker: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Docker returned status %d", resp.StatusCode)
	}

	var containers []struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	for _, c := range containers {
		tracker.Add(c.ID)
		log.Printf("[bw-docker-guard] seeded compose container: %.12s", c.ID)
	}

	return nil
}
