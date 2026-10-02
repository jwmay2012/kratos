// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/rakutentech/jwk-go/jwk"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/strategy/oidc"
)

// Exercise the real provider verifiers, including Apple's string Boolean. Only
// discovery/JWKS are local fixtures; signature and claim checks are not bypassed.
func verifiedProvider(t *testing.T, f verifiedLinkFixture, name string) (oidc.Provider, func(string, string, any, string) (*oidc.Claims, error)) {
	t.Helper()
	var idp *httptest.Server
	idp = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/.well-known/openid-configuration" {
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": idp.URL, "jwks_uri": idp.URL + "/keys", "authorization_endpoint": idp.URL + "/authorize", "token_endpoint": idp.URL + "/token", "id_token_signing_alg_values_supported": []string{"RS256"}})
		} else {
			_, _ = w.Write(publicJWKS)
		}
	}))
	t.Cleanup(idp.Close)
	var provider oidc.Provider
	switch name {
	case "google":
		f.provider.ID, f.provider.Provider = name, name
		p := oidc.NewProviderGoogle(f.provider, f.reg).(*oidc.ProviderGoogle)
		p.JWKSUrl = idp.URL + "/keys"
		provider = p
	case "apple":
		f.provider.ID, f.provider.Provider = name, name
		p := oidc.NewProviderApple(f.provider, f.reg).(*oidc.ProviderApple)
		p.JWKSUrl = idp.URL + "/keys"
		provider = p
	default:
		f.provider.ID, f.provider.Provider = "broker", "generic"
		f.provider.IssuerURL = idp.URL
		provider = oidc.NewProviderGenericOIDC(f.provider, f.reg)
	}
	f.conf.MustSet(context.Background(), "selfservice.methods.oidc.config.providers", []oidc.Configuration{*f.provider})
	key := new(jwk.KeySpec)
	require.NoError(t, json.Unmarshal(rawKey, key))
	return provider, func(email, subject string, verified any, hd string) (*oidc.Claims, error) {
		claims := jwt.MapClaims{"iss": f.provider.IssuerURL, "aud": "fixture", "sub": subject, "email": email, "exp": time.Now().Add(time.Minute).Unix()}
		if verified != nil {
			claims["email_verified"] = verified
		}
		if hd != "" {
			claims["hd"] = hd
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = key.KeyID
		encoded, err := token.SignedString(key.Key)
		require.NoError(t, err)
		return provider.(oidc.IDTokenVerifier).Verify(context.Background(), encoded)
	}
}

func TestVerifiedEmailProviderAndExistingAccountMatrix(t *testing.T) {
	for _, kind := range []flow.Type{flow.TypeBrowser, flow.TypeAPI} {
		for _, original := range []string{"password", "broker", "google", "apple"} {
			for _, existingVerified := range []bool{true, false} {
				for _, incoming := range []string{"enterprise", "google", "apple"} {
					for _, claim := range []string{"true", "false", "missing"} {
						t.Run(fmt.Sprintf("%s/original=%s/verified=%t/incoming=%s/claim=%s", kind, original, existingVerified, incoming, claim), func(t *testing.T) {
							f := newVerifiedLinkFixture(t)
							ctx, email := context.Background(), "person@gmail.com"
							i := f.identity(t, email, existingVerified)
							var expected []string
							if original != "password" {
								previous, err := identity.NewCredentialsOIDC(nil, original, "original-subject", "")
								require.NoError(t, err)
								i.SetCredentials(identity.CredentialsTypeOIDC, *previous)
								require.NoError(t, f.reg.PrivilegedIdentityPool().UpdateIdentity(ctx, i))
								expected = append(expected, original+":original-subject")
							}
							provider, verify := verifiedProvider(t, f, incoming)
							var value any
							if claim != "missing" {
								value = claim == "true"
								if incoming == "apple" {
									value = claim
								}
							}
							claims, err := verify(email, "new-subject", value, "")
							require.NoError(t, err)
							w, _, err := f.loginWithProvider(t, kind, claims, provider)
							if existingVerified && claim == "true" {
								require.NoError(t, err, w.Body.String())
								expected = append(expected, provider.Config().ID+":new-subject")
								if kind == flow.TypeAPI {
									require.Equal(t, i.ID.String(), gjson.Get(w.Body.String(), "session.identity.id").String())
								} else {
									r := httptest.NewRequest(http.MethodGet, "http://localhost/sessions/whoami", nil)
									for _, cookie := range w.Result().Cookies() {
										r.AddCookie(cookie)
									}
									sess, err := f.reg.SessionManager().FetchFromRequest(ctx, r)
									require.NoError(t, err)
									require.Equal(t, i.ID, sess.IdentityID)
								}
							} else {
								require.False(t, gjson.Get(w.Body.String(), "session_token").Exists())
								if kind == flow.TypeAPI {
									require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
									require.True(t, gjson.Get(w.Body.String(), "ui.messages.#(id==1010016)").Exists(), w.Body.String())
								} else {
									require.Equal(t, http.StatusSeeOther, w.Code)
									require.Contains(t, w.Header().Get("Location"), "/login?flow=")
								}
							}
							current, err := f.reg.PrivilegedIdentityPool().GetIdentityConfidential(ctx, i.ID)
							require.NoError(t, err)
							require.ElementsMatch(t, expected, current.Credentials[identity.CredentialsTypeOIDC].Identifiers)
							require.JSONEq(t, string(i.Credentials[identity.CredentialsTypePassword].Config), string(current.Credentials[identity.CredentialsTypePassword].Config))
							require.JSONEq(t, string(i.Traits), string(current.Traits))
							require.JSONEq(t, string(i.MetadataAdmin), string(current.MetadataAdmin))
							require.Equal(t, existingVerified, current.VerifiableAddresses[0].Verified)
							count, err := f.reg.PrivilegedIdentityPool().CountIdentities(ctx)
							require.NoError(t, err)
							require.EqualValues(t, 1, count)
						})
					}
				}
			}
		}
	}
}

func TestVerifiedEmailExistingSSORecordsTrustedProof(t *testing.T) {
	for _, providerName := range []string{"enterprise", "google", "apple"} {
		for _, claim := range []string{"true", "false", "missing"} {
			t.Run(providerName+"/"+claim, func(t *testing.T) {
				f := newVerifiedLinkFixture(t)
				ctx, email := context.Background(), "person@gmail.com"
				i := f.identity(t, email, false)
				provider, verify := verifiedProvider(t, f, providerName)
				previous, err := identity.NewCredentialsOIDC(nil, provider.Config().ID, "original-subject", "")
				require.NoError(t, err)
				i.SetCredentials(identity.CredentialsTypeOIDC, *previous)
				require.NoError(t, f.reg.PrivilegedIdentityPool().UpdateIdentity(ctx, i))
				var value any
				if claim != "missing" {
					value = claim == "true"
				}
				claims, err := verify(email, "original-subject", value, "")
				require.NoError(t, err)
				w, _, err := f.loginWithProvider(t, flow.TypeAPI, claims, provider)
				require.NoError(t, err, w.Body.String())
				require.Equal(t, i.ID.String(), gjson.Get(w.Body.String(), "session.identity.id").String())
				current, err := f.reg.PrivilegedIdentityPool().GetIdentityConfidential(ctx, i.ID)
				require.NoError(t, err)
				require.Equal(t, claim == "true", current.VerifiableAddresses[0].Verified)
				require.ElementsMatch(t, previous.Identifiers, current.Credentials[identity.CredentialsTypeOIDC].Identifiers)
				require.JSONEq(t, string(i.Credentials[identity.CredentialsTypePassword].Config), string(current.Credentials[identity.CredentialsTypePassword].Config))
				// An unverified password origin must not block a later enterprise
				// link once an already-linked, authoritative SSO login verified it.
				enterprise, verifyEnterprise := verifiedProvider(t, f, "enterprise")
				incoming, err := verifyEnterprise(email, "new-enterprise-subject", true, "")
				require.NoError(t, err)
				w, _, err = f.loginWithProvider(t, flow.TypeAPI, incoming, enterprise)
				expected := append([]string(nil), previous.Identifiers...)
				if claim == "true" {
					require.NoError(t, err, w.Body.String())
					require.Equal(t, i.ID.String(), gjson.Get(w.Body.String(), "session.identity.id").String())
					expected = append(expected, "broker:new-enterprise-subject")
				} else {
					require.True(t, gjson.Get(w.Body.String(), "ui.messages.#(id==1010016)").Exists(), w.Body.String())
					require.False(t, gjson.Get(w.Body.String(), "session_token").Exists())
				}
				current, err = f.reg.PrivilegedIdentityPool().GetIdentityConfidential(ctx, i.ID)
				require.NoError(t, err)
				require.ElementsMatch(t, expected, current.Credentials[identity.CredentialsTypeOIDC].Identifiers)
			})
		}
	}
}

func TestVerifiedEmailGoogleAuthorityAndMalformedClaims(t *testing.T) {
	for _, name := range []string{"enterprise", "google", "apple"} {
		t.Run(name, func(t *testing.T) {
			f := newVerifiedLinkFixture(t)
			i := f.identity(t, "person@example.test", true)
			provider, verify := verifiedProvider(t, f, name)
			for _, malformed := range []any{"yes", 1, []string{"true"}, map[string]bool{"verified": true}} {
				_, err := verify("person@example.test", "new-subject", malformed, "")
				require.Error(t, err, "malformed verification must be rejected before account linking")
			}
			if name == "google" {
				claims, err := verify("person@example.test", "external-subject", true, "")
				require.NoError(t, err)
				w, _, _ := f.loginWithProvider(t, flow.TypeAPI, claims, provider)
				require.Equal(t, http.StatusBadRequest, w.Code)
				require.True(t, gjson.Get(w.Body.String(), "ui.messages.#(id==1010016)").Exists())
				current, err := f.reg.PrivilegedIdentityPool().GetIdentityConfidential(context.Background(), i.ID)
				require.NoError(t, err)
				require.Empty(t, current.Credentials[identity.CredentialsTypeOIDC].Identifiers)
				claims, err = verify("person@example.test", "workspace-subject", true, "example.test")
				require.NoError(t, err)
				w, _, err = f.loginWithProvider(t, flow.TypeAPI, claims, provider)
				require.NoError(t, err, w.Body.String())
				require.Equal(t, i.ID.String(), gjson.Get(w.Body.String(), "session.identity.id").String())
			}
		})
	}
}
