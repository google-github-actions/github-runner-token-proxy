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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sethvargo/github-runner-token-proxy/internal/jwt"
)

// TokenSource represents an interface that returns an auth token.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// staticTokenSource is a TokenSource that always returns the given value.
type staticTokenSource struct {
	token string
}

func (t *staticTokenSource) Token(_ context.Context) (string, error) {
	return t.token, nil
}

// githubAppTokenSource uses the private key to mint a JWT to then get an access
// token from the given installation. It caches the result until it is expired.
type githubAppTokenSource struct {
	appID          string
	installationID string
	privateKey     *rsa.PrivateKey

	cacheLock   sync.RWMutex
	cachedToken *githubAppTokenResponse
}

type githubAppTokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (t *githubAppTokenSource) Token(ctx context.Context) (string, error) {
	// Quick check the performant path to see if the cache exists and is valid.
	// RLock can be concurrent.
	t.cacheLock.RLock()
	if t.cachedToken != nil && time.Until(t.cachedToken.ExpiresAt) > 1*time.Minute {
		t.cacheLock.RUnlock()
		return t.cachedToken.Token, nil
	}
	t.cacheLock.RUnlock()

	// Upgrade the lock to a full mutex, no one else can hold it now.
	t.cacheLock.Lock()
	if t.cachedToken != nil && time.Until(t.cachedToken.ExpiresAt) > 1*time.Minute {
		t.cacheLock.Unlock()
		return t.cachedToken.Token, nil
	}
	defer t.cacheLock.Unlock()

	// Build the JWT from the private key.
	header := &jwt.Header{
		Algorithm: "RS256",
		Type:      "JWT",
	}
	claimSet := &jwt.ClaimSet{
		Issuer:  githubAppID,
		Issued:  time.Now().Add(-60 * time.Second).Unix(),
		Expires: time.Now().Add(5 * time.Minute).Unix(),
	}

	// Sign and generate a JWT.
	token, err := jwt.BuildAndSign(header, claimSet, func(in []byte) ([]byte, error) {
		h := sha256.New()
		if _, err := h.Write(in); err != nil {
			return nil, fmt.Errorf("failed to hash: %w", err)
		}
		return rsa.SignPKCS1v15(rand.Reader, githubAppPrivateKey, crypto.SHA256, h.Sum(nil))
	})
	if err != nil {
		return "", fmt.Errorf("failed to build jwt: %w", err)
	}

	// Exchange the JWT for the installation access token.
	pth := strings.TrimSuffix(githubAPIURL, "/") + "/app/installations/" + githubInstallationID + "/access_tokens"
	req, err := http.NewRequestWithContext(ctx, "POST", pth, nil)
	if err != nil {
		return "", fmt.Errorf("failed to build request to get installation token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to make installation token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(io.LimitReader(resp.Body, 64*1024)) // 64kb
	if err != nil {
		return "", fmt.Errorf("failed to read installation token: %w", err)
	}

	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("bad response from installation token request (%d): %s", resp.StatusCode, body)
	}

	var tr githubAppTokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("failed to unmarshal token resource: %w", err)
	}

	// Update the cache and return the token.
	t.cachedToken = &tr
	return tr.Token, nil
}
