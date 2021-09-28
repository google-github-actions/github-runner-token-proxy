package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestBuildAndSign(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		header   *Header
		claimSet *ClaimSet
	}{
		{
			name:     "empty",
			header:   &Header{},
			claimSet: &ClaimSet{},
		},
		{
			name: "omit_optional",
			header: &Header{
				Algorithm: "RS256",
				Type:      "JWT",
			},
			claimSet: &ClaimSet{
				Issuer:   "test-iss",
				Audience: "test-aud",
				Expires:  time.Now().Add(30 * time.Minute).Unix(),
				Issued:   time.Now().Add(-10 * time.Second).Unix(),
			},
		},
		{
			name: "full",
			header: &Header{
				Algorithm: "RS256",
				Type:      "JWT",
				KeyID:     "my-kid",
			},
			claimSet: &ClaimSet{
				Issuer:   "test-iss",
				Audience: "test-aud",
				Expires:  time.Now().Add(30 * time.Minute).Unix(),
				Issued:   time.Now().Add(-10 * time.Second).Unix(),
				Scope:    "my-scope",
				Type:     "JWT",
				Subject:  "my-sub",
			},
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
			if err != nil {
				t.Fatal(err)
			}

			token, err := BuildAndSign(tc.header, tc.claimSet, func(in []byte) ([]byte, error) {
				h := sha256.New()
				if _, err := h.Write(in); err != nil {
					return nil, fmt.Errorf("failed to hash: %w", err)
				}
				return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, h.Sum(nil))
			})
			if err != nil {
				t.Fatal(err)
			}

			parts := strings.Split(token, ".")
			if len(parts) != 3 {
				t.Fatalf("invalid jwt: %q", token)
			}

			// Verify encoding/decoding
			{
				headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
				if err != nil {
					t.Fatal(err)
				}

				var header Header
				if err := json.Unmarshal(headerRaw, &header); err != nil {
					t.Fatal(err)
				}

				if got, want := &header, tc.header; !reflect.DeepEqual(got, want) {
					t.Errorf("expected %#v to be %#v", got, want)
				}
			}
			{
				claimSetRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
				if err != nil {
					t.Fatal(err)
				}

				var claimSet ClaimSet
				if err := json.Unmarshal(claimSetRaw, &claimSet); err != nil {
					t.Fatal(err)
				}

				if got, want := &claimSet, tc.claimSet; !reflect.DeepEqual(got, want) {
					t.Errorf("expected %#v to be %#v", got, want)
				}
			}

			h := sha256.New()
			if _, err := h.Write([]byte(parts[0] + "." + parts[1])); err != nil {
				t.Fatal(err)
			}
			digest := h.Sum(nil)

			sig, err := base64.RawURLEncoding.DecodeString(parts[2])
			if err != nil {
				t.Fatal(err)
			}
			if err := rsa.VerifyPKCS1v15(&privateKey.PublicKey, crypto.SHA256, digest, sig); err != nil {
				t.Fatal(err)
			}
		})
	}
}
