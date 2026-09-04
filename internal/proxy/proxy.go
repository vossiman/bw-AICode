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
	"time"

	"github.com/vossi/bw-docker-guard/internal/config"
	"github.com/vossi/bw-docker-guard/internal/guard"
	"github.com/vossi/bw-docker-guard/internal/ownership"
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
	validator.SetVolumeLookup(newVolumeLookup(dockerSocketPath))

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
		case guard.ReContainerCreate.MatchString(path):
			id, err := extractID(resp)
			if err != nil {
				log.Printf("[bw-docker-guard] WARNING: failed to extract container ID from response: %v", err)
				return nil
			}
			if id != "" {
				tracker.Add(id)
				// Also track the container name (from ?name= query param)
				// so ownership checks work when Docker CLI uses names in API URLs.
				if name := resp.Request.URL.Query().Get("name"); name != "" {
					tracker.Add(name)
				}
			}

		case guard.ReContainerExec.MatchString(path):
			id, err := extractID(resp)
			if err != nil {
				log.Printf("[bw-docker-guard] WARNING: failed to extract exec ID from response: %v", err)
				return nil
			}
			if id != "" {
				tracker.AddExecID(id)
			}

		case guard.ReNetworkCreate.MatchString(path):
			id, err := extractID(resp)
			if err != nil {
				log.Printf("[bw-docker-guard] WARNING: failed to extract network ID from response: %v", err)
				return nil
			}
			if id != "" {
				tracker.AddNetwork(id)
			}
			// Also track the network name from the request body so ownership
			// checks work when Docker CLI uses names in DELETE URLs.
			if resp.Request.Body != nil {
				if bodyBytes, err := io.ReadAll(resp.Request.Body); err == nil && len(bodyBytes) > 0 {
					var nr struct{ Name string }
					if json.Unmarshal(bodyBytes, &nr) == nil && nr.Name != "" {
						tracker.AddNetwork(nr.Name)
					}
				}
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

// volumeLookupTimeout bounds the extra daemon round-trip a named-volume bind
// costs. It only runs on container create, and only for a Binds entry that
// names a volume, so it is not in the general request path.
const volumeLookupTimeout = 5 * time.Second

// newVolumeLookup returns a guard.VolumeLookup backed by the same Docker
// socket the proxy forwards to. The guard needs it to tell a Docker-managed
// named volume from one created with device=/,o=bind, which the name alone
// does not reveal (BWAICODE-4).
func newVolumeLookup(dockerSocketPath string) guard.VolumeLookup {
	client := &http.Client{
		Timeout: volumeLookupTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", dockerSocketPath)
			},
		},
	}
	return func(name string) (*guard.VolumeInfo, error) {
		resp, err := client.Get("http://docker/volumes/" + url.PathEscape(name))
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusNotFound:
			// No such volume: the daemon will create a plain local one.
			return nil, nil
		case http.StatusOK:
		default:
			return nil, fmt.Errorf("volume inspect returned %s", resp.Status)
		}
		var info guard.VolumeInfo
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&info); err != nil {
			return nil, fmt.Errorf("decoding volume inspect response: %w", err)
		}
		return &info, nil
	}
}
