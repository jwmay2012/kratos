// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/pkg"
	"github.com/ory/kratos/selfservice/strategy/oidc"
)

func TestMicrosoftNativeIDTokenVerification(t *testing.T) {
	const tenant = "11111111-2222-4333-8444-555555555555"
	const issuer = "https://login.microsoftonline.com/" + tenant + "/v2.0"
	for _, tc := range []struct {
		name, issuer, audience string
		expired, wrongKey      bool
	}{
		{name: "valid", issuer: issuer, audience: "native-client"},
		{name: "wrong tenant", issuer: "https://login.microsoftonline.com/other/v2.0", audience: "native-client"},
		{name: "wrong issuer", issuer: "https://issuer.example", audience: "native-client"},
		{name: "wrong audience", issuer: issuer, audience: "other-client"},
		{name: "expired", issuer: issuer, audience: "native-client", expired: true},
		{name: "wrong signing key", issuer: issuer, audience: "native-client", wrongKey: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				keys := publicJWKS
				if tc.wrongKey {
					keys = publicJWKS2
				}
				_, _ = w.Write(keys)
			}))
			t.Cleanup(server.Close)
			_, reg := pkg.NewVeryFastRegistryWithoutDB(t)
			provider := oidc.NewProviderMicrosoft(&oidc.Configuration{
				Provider: "microsoft", ID: "microsoft-fixture", ClientID: "native-client", Tenant: tenant,
			}, reg).(*oidc.ProviderMicrosoft)
			require.Equal(t, "https://login.microsoftonline.com/common/discovery/keys", provider.JWKSUrl)
			provider.JWKSUrl = server.URL
			expires := time.Now().Add(time.Hour)
			if tc.expired {
				expires = time.Now().Add(-time.Hour)
			}
			token := createIDToken(t, jwt.RegisteredClaims{
				Issuer: tc.issuer, Subject: "stable-subject", Audience: jwt.ClaimStrings{tc.audience},
				ExpiresAt: jwt.NewNumericDate(expires),
			})
			claims, err := provider.Verify(context.Background(), token)
			if tc.name != "valid" {
				require.Error(t, err)
				require.Nil(t, claims)
				return
			}
			require.NoError(t, err)
			require.Equal(t, issuer, claims.Issuer)
			require.Equal(t, "stable-subject", claims.Subject)
			require.Equal(t, "acme@ory.sh", claims.Email)
			require.Equal(t, claims.Email, claims.RawClaims["email"])
		})
	}
}
