package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"

	"github.com/vossi/bw-docker-guard/internal/config"
	"github.com/vossi/bw-docker-guard/internal/guard"
	"github.com/vossi/bw-docker-guard/internal/ownership"
)

// URL patterns for intercepting responses.
var (
	reContainerCreate = regexp.MustCompile(`^(/v[\d.]+)?/containers/create$`)
	reContainerExec   = regexp.MustCompile(`^(/v[\d.]+)?/containers/([^/]+)/exec$`)
)

// createResponse is the subset of Docker's container/exec create response we parse.
type createResponse struct {
	ID string `json:"Id"`
}

// NewHandler creates an http.Handler that validates requests via the guard,
// and proxies allowed requests to the Docker socket at dockerSocketPath.
// Denied requests get a 403 with a JSON body.
func NewHandler(cfg *config.Config, tracker *ownership.Tracker, dockerSocketPath string) http.Handler {
	validator := guard.NewValidator(cfg, tracker)

	target, _ := url.Parse("http://docker")
	proxy := httputil.NewSingleHostReverseProxy(target)

	// Director sets the request URL for the unix socket backend.
	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = "http"
		req.URL.Host = "docker"
	}

	// Custom transport that dials the Docker unix socket.
	proxy.Transport = &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", dockerSocketPath)
		},
	}

	// ModifyResponse intercepts container create and exec create responses
	// to track ownership of newly created resources.
	proxy.ModifyResponse = func(resp *http.Response) error {
		if resp.StatusCode != http.StatusCreated {
			return nil
		}

		path := resp.Request.URL.Path
		method := resp.Request.Method

		if method != http.MethodPost {
			return nil
		}

		switch {
		case reContainerCreate.MatchString(path):
			id, err := extractID(resp)
			if err != nil {
				log.Printf("[bw-docker-guard] WARNING: failed to extract container ID from response: %v", err)
				return nil
			}
			if id != "" {
				tracker.Add(id)
			}

		case reContainerExec.MatchString(path):
			id, err := extractID(resp)
			if err != nil {
				log.Printf("[bw-docker-guard] WARNING: failed to extract exec ID from response: %v", err)
				return nil
			}
			if id != "" {
				tracker.AddExecID(id)
			}
		}

		return nil
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decision := validator.Validate(r)

		if !decision.Allow {
			log.Printf("[bw-docker-guard] DENIED: %s %s — %s", r.Method, r.URL.Path, decision.Reason)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			msg := fmt.Sprintf("bw-docker-guard: %s", decision.Reason)
			json.NewEncoder(w).Encode(map[string]string{"message": msg})
			return
		}

		// Log allowed write requests
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			log.Printf("[bw-docker-guard] ALLOWED: %s %s", r.Method, r.URL.Path)
		}

		proxy.ServeHTTP(w, r)
	})
}

// extractID reads the response body to find an "Id" field, then re-buffers
// the body so the client still receives it.
func extractID(resp *http.Response) (string, error) {
	if resp.Body == nil {
		return "", nil
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		// Re-buffer whatever we got
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		return "", fmt.Errorf("reading response body: %w", err)
	}

	// Re-buffer the body for the client
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	resp.ContentLength = int64(len(bodyBytes))

	if len(bodyBytes) == 0 {
		return "", nil
	}

	var cr createResponse
	if err := json.Unmarshal(bodyBytes, &cr); err != nil {
		return "", fmt.Errorf("parsing response JSON: %w", err)
	}

	return cr.ID, nil
}

// isWriteMethod returns true for HTTP methods that modify state.
func isWriteMethod(method string) bool {
	return !strings.EqualFold(method, http.MethodGet) && !strings.EqualFold(method, http.MethodHead)
}
