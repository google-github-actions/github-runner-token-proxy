package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

const (
	// allowedClockSkew is for computers that might not have perfectly synced
	// clocks.
	allowedClockSkew = 10 * time.Second
)

// ClaimSet is a JWS claim set.
type ClaimSet struct {
	Issuer   string `json:"iss"`
	Scope    string `json:"scope,omitempty"`
	Audience string `json:"aud"`
	Expires  int64  `json:"exp"`
	Issued   int64  `json:"iat"`
	Type     string `json:"typ,omitempty"`
	Subject  string `json:"sub,omitempty"`
}

// encode encodes the claim set (base64 encoded JSON).
func (c *ClaimSet) encode() (string, error) {
	now := time.Now().Add(-allowedClockSkew)
	if c.Issued <= 0 {
		c.Issued = now.Unix()
	}
	if c.Expires <= 0 {
		c.Expires = now.Add(time.Hour).Unix()
	}

	b, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("failed to encode claim set: %w", err)
	}
	return b64Encode(b), nil
}

// Header is a JWS header.
type Header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid,omitempty"`
}

// encode encodes the header (base64 encoded JSON).
func (h *Header) encode() (string, error) {
	b, err := json.Marshal(h)
	if err != nil {
		return "", fmt.Errorf("failed to encode header: %w", err)
	}
	return b64Encode(b), nil
}

type Signer func(in []byte) ([]byte, error)

// BuildAndSign builds a JWT from the given header and claim set, and signs it
// with the provided signer.
func BuildAndSign(h *Header, c *ClaimSet, signer Signer) (string, error) {
	hStr, err := h.encode()
	if err != nil {
		return "", err
	}

	cStr, err := c.encode()
	if err != nil {
		return "", err
	}

	combined := hStr + "." + cStr

	sig, err := signer([]byte(combined))
	if err != nil {
		return "", fmt.Errorf("failed to sign claims: %w", err)
	}

	return combined + "." + b64Encode(sig), nil
}

func b64Encode(in []byte) string {
	return base64.RawURLEncoding.EncodeToString(in)
}
