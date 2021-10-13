// Copyright 2021 the GitHub Runner Token Proxy authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/sethvargo/github-runner-token-proxy/internal/logging"
)

var (
	// bind is the interface address on which to bind (default: all). port is the
	// port on which the container should listen.
	bind = envOrDefault("BIND", "")
	port = envOrDefault("PORT", "8080")

	// githubToken is the GitHub personal access token, injected via the Cloud Run
	// Secret Sanager integration.
	githubToken = envOrDefault("GITHUB_TOKEN", "")

	// githubAppID is the ID of your GitHub App. githubAppPrivateKey is the RSA
	// private key for your app; it should be loaded from Secret Manager.
	// githubInstallationID is the specific installation to target for getting
	// permissions to register the runners.
	githubAppID          = envOrDefault("GITHUB_APP_ID", "")
	githubAppPrivateKey  = envRSAPrivateKey("GITHUB_APP_PRIVATE_KEY", nil)
	githubInstallationID = envOrDefault("GITHUB_INSTALLATION_ID", "")

	// githubAPIURL is the endpoint where the GitHub API can be found. It defaults
	// to the public github.com installation. This can be set to the enterprise
	// API endpoint (which is usually) "(url)/api/v3" on GitHub Enterprise
	// installations.
	githubAPIURL = envOrDefault("GITHUB_API_URL", "https://api.github.com")

	// allowedScopes is the list of allowed repos or owner names. By default, no
	// scopes are allowed. Set this value to "match:*" to allow all, but it is
	// better to specify a set or repositories for security.
	//
	// Values are treated as literal string matches unless prefixed with "match:",
	// in which case the value is treated as a regular expression.
	allowedScopes = envOrDefaultRegexSlice("ALLOWED_SCOPES", nil)

	// deniedScopes is an optional list of denied repos or owner names. This takes
	// priority over the allowlist.
	//
	// Values are treated as literal string matches unless prefixed with "match:",
	// in which case the value is treated as a regular expression.
	deniedScopes = envOrDefaultRegexSlice("DENIED_SCOPES", nil)

	// httpClient is the default HTTP client.
	httpClient = &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ForceAttemptHTTP2:     true,
			DisableKeepAlives:     true,
			MaxIdleConnsPerHost:   -1,
		},
	}

	// logger is the structured logger.
	logger = logging.NewLogger(os.Stdout, os.Stderr)
)

func main() {
	ctx, done := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer done()

	if err := realMain(ctx); err != nil {
		done()
		logger.Fatal("error from main process", "error", err)
	}

	logger.Info("shutting down")
}

func realMain(ctx context.Context) error {
	var ts TokenSource
	switch {
	case githubAppID != "" && githubInstallationID != "" && githubAppPrivateKey != nil:
		ts = &githubAppTokenSource{
			appID:          githubAppID,
			installationID: githubInstallationID,
			privateKey:     githubAppPrivateKey,
		}
	case githubToken != "":
		ts = &staticTokenSource{
			token: githubToken,
		}
	default:
		return fmt.Errorf("missing [GITHUB_TOKEN] or [GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY, GITHUB_INSTALLATION_ID]")
	}

	mux := http.NewServeMux()
	mux.Handle("/register", handleToken(ts, "registration-token"))
	mux.Handle("/remove", handleToken(ts, "remove-token"))

	server := &http.Server{
		Addr:    bind + ":" + port,
		Handler: mux,
	}

	serverErrCh := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			select {
			case serverErrCh <- err:
			default:
			}
		}
	}()

	// Wait for shutdown signal or error from the listener.
	select {
	case err := <-serverErrCh:
		return fmt.Errorf("error from server listener: %w", err)
	case <-ctx.Done():
	}

	// Gracefully shut down the server.
	shutdownCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("failed to shutdown server: %w", err)
	}
	return nil
}

// TokenRequest is a generic token request.
type TokenRequest struct {
	Scope string `json:"scope"`
}

func handleToken(ts TokenSource, typ string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		if r.Method != "POST" {
			logger.Warn("expected http method to be POST, got %q", r.Method)
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		var tr TokenRequest
		lr := io.LimitReader(r.Body, 64*1024) // 64kb
		dec := json.NewDecoder(lr)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&tr); err != nil {
			logger.Warn("failed to decode request", "error", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		scope := strings.Trim(tr.Scope, "/")
		if scope == "" {
			logger.Warn("missing scope in request body")
			http.Error(w, "missing scope in request body", http.StatusBadRequest)
			return
		}

		// Parse the deny list first, since it takes priority.
		for _, entry := range deniedScopes {
			if entry.MatchString(scope) {
				logger.Warn("scope is in denied list", "scope", scope)
				http.Error(w, "scope is not allowed", http.StatusUnauthorized)
				return
			}
		}

		// Ensure the scope is allowed.
		foundMatch := false
		for _, entry := range allowedScopes {
			if entry.MatchString(scope) {
				foundMatch = true
				break
			}
		}
		if !foundMatch {
			logger.Warn("scope is not allowed", "scope", scope)
			http.Error(w, "scope is not allowed", http.StatusUnauthorized)
			return
		}

		rtr, err := githubTokenRequest(ctx, ts, scope, typ)
		if err != nil {
			logger.Warn("failed to make token request", "error", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		b, err := json.Marshal(rtr)
		if err != nil {
			logger.Error("failed to marshal json response", "error", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(200)
		_, _ = w.Write(b)
	})
}

// TokenResponse is a generic token response.
type TokenResponse struct {
	Token string `json:"token"`
}

// githubTokenRequest is a generic request for GitHub runner tokens.
func githubTokenRequest(ctx context.Context, ts TokenSource, scope, subpath string) (*TokenResponse, error) {
	var parent string
	switch strings.Count(scope, "/") {
	case 0:
		parent = "orgs"
	case 1:
		parent = "repos"
	default:
		return nil, fmt.Errorf("invalid scope %q", scope)
	}

	// Fetch the token from the token source.
	token, err := ts.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth token: %w", err)
	}

	// e.g. https://api.github.com/repos/[owner]/[name]/actions/runners/registration-token
	// e.g. https://api.github.com/orgs/[name]/actions/runners/registration-token
	pth := strings.TrimSuffix(githubAPIURL, "/") + "/" + parent + "/" + scope + "/actions/runners/" + subpath
	req, err := http.NewRequestWithContext(ctx, "POST", pth, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(io.LimitReader(resp.Body, 64*1024)) // 64kb
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	// Ensure successful response.
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("bad response from token request (%d): %s", resp.StatusCode, body)
	}

	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token: %w", err)
	}
	return &tr, nil
}

// envOrDefault returns the value in the environment variable. If the value is
// empty, it returns the default value.
func envOrDefault(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

// envOrDefaultRegexSlice returns the value in the environment variable, parsed
// as a semi-colon separated of values into a slice of regular expressions. If
// no value is present, it returns the default. It panics if any of the regular
// expressions cannot compile.
//
// Why not commas? Well gcloud already uses commas and its pattern for escaping
// is quite bonkers, so we just picked a different character.
func envOrDefaultRegexSlice(key string, def []*regexp.Regexp) []*regexp.Regexp {
	v := os.Getenv(key)
	if v == "" {
		return def
	}

	// Trim all whitespace and remove blank entries.
	split := strings.Split(v, ";")
	parts := make([]*regexp.Regexp, 0, len(split))
	for _, p := range split {
		tr := strings.TrimSpace(p)
		if tr != "" {
			if strings.HasPrefix(tr, "match:") {
				tr = tr[6:]
			} else {
				tr = `\A` + regexp.QuoteMeta(tr) + `\z`
			}

			re := regexp.MustCompile(tr)
			parts = append(parts, re)
		}
	}
	return parts
}

// envRSAPrivateKey parses the given env as a PEM-encoded RSA private key.
func envRSAPrivateKey(key string, def *rsa.PrivateKey) *rsa.PrivateKey {
	val := os.Getenv(key)
	if val == "" {
		return def
	}

	block, _ := pem.Decode([]byte(val))
	if block == nil {
		panic(fmt.Errorf("failed to parse pem block"))
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(fmt.Errorf("failed to parse private key: %w", err))
	}
	return privateKey
}
