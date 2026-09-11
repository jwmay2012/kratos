// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/selfservice/strategy/oidc"
)

type nonceCompatibilityProvider struct {
	claims *oidc.Claims
	err    error
}

func (p nonceCompatibilityProvider) Config() *oidc.Configuration {
	return &oidc.Configuration{Provider: "nonce-compatibility-fixture"}
}

func (p nonceCompatibilityProvider) Verify(context.Context, string) (*oidc.Claims, error) {
	return p.claims, p.err
}

func TestNativeIDTokenNonceCompatibility(t *testing.T) {
	for _, tc := range []struct{ name, tokenNonce, submittedNonce string }{
		{"both absent", "", ""},
		{"token nonce absent", "", "submitted"},
		{"submitted nonce absent", "token", ""},
		{"nonces differ", "token", "submitted"},
		{"nonces match", "same", "same"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := &oidc.Claims{Issuer: "https://issuer.example", Subject: "subject", Nonce: tc.tokenNonce}
			actual, err := new(oidc.Strategy).ProcessIDToken(httptest.NewRequest("POST", "/", nil),
				nonceCompatibilityProvider{claims: claims}, "verified-token", tc.submittedNonce)
			require.NoError(t, err)
			require.Same(t, claims, actual)
		})
	}
}

func TestNativeIDTokenNonceCompatibilityStillRequiresValidClaims(t *testing.T) {
	for _, tc := range []struct {
		name     string
		provider nonceCompatibilityProvider
	}{
		{"verification failed", nonceCompatibilityProvider{err: errors.New("invalid token")}},
		{"subject missing", nonceCompatibilityProvider{claims: &oidc.Claims{Issuer: "https://issuer.example"}}},
		{"issuer missing", nonceCompatibilityProvider{claims: &oidc.Claims{Subject: "subject"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := new(oidc.Strategy).ProcessIDToken(httptest.NewRequest("POST", "/", nil), tc.provider, "token", "")
			require.Error(t, err)
			require.Nil(t, claims)
		})
	}
}
