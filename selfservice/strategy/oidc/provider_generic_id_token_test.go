// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/pkg"
	"github.com/ory/kratos/selfservice/strategy/oidc"
)

func TestGenericNativeIDTokenVerification(t *testing.T) {
	for _, name := range []string{"valid", "wrong issuer", "wrong audience", "expired", "wrong signing key", "discovery failed"} {
		t.Run(name, func(t *testing.T) {
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/.well-known/openid-configuration":
					if name == "discovery failed" {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{
						"issuer": server.URL, "jwks_uri": server.URL + "/keys",
						"authorization_endpoint": server.URL + "/authorize", "token_endpoint": server.URL + "/token",
						"id_token_signing_alg_values_supported": []string{"RS256"},
					})
				case "/keys":
					keys := publicJWKS
					if name == "wrong signing key" {
						keys = publicJWKS2
					}
					_, _ = w.Write(keys)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			t.Cleanup(server.Close)
			_, reg := pkg.NewVeryFastRegistryWithoutDB(t)
			provider := oidc.NewProviderGenericOIDC(&oidc.Configuration{
				Provider: "generic", ID: "generic-fixture", ClientID: "native-client", IssuerURL: server.URL,
			}, reg).(*oidc.ProviderGenericOIDC)
			registered := jwt.RegisteredClaims{Issuer: server.URL, Subject: "stable-subject",
				Audience: jwt.ClaimStrings{"native-client"}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}
			switch name {
			case "wrong issuer":
				registered.Issuer = "https://other-issuer.example"
			case "wrong audience":
				registered.Audience = jwt.ClaimStrings{"other-client"}
			case "expired":
				registered.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
			}
			claims, err := provider.Verify(context.Background(), createIDToken(t, registered))
			if name != "valid" {
				require.Error(t, err)
				require.Nil(t, claims)
				return
			}
			require.NoError(t, err)
			require.Equal(t, server.URL, claims.Issuer)
			require.Equal(t, "stable-subject", claims.Subject)
			require.Equal(t, "acme@ory.sh", claims.Email)
			require.Equal(t, claims.Email, claims.RawClaims["email"])
			require.True(t, provider.CanSkipNonce(&oidc.Claims{}))
			require.False(t, provider.CanSkipNonce(&oidc.Claims{Nonce: "present"}))
		})
	}
}
