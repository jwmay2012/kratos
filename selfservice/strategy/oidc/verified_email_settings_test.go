// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/pkg/testhelpers"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/selfservice/strategy/oidc"
	"github.com/ory/kratos/x"
	"github.com/ory/kratos/x/nosurfx"
	"github.com/ory/x/configx"
)

func TestSettingsVerifiedEmailOwnership(t *testing.T) {
	f := newVerifiedLinkFixture(t)
	ctx := context.Background()
	var subject string
	var claims idTokenClaims
	scope := []string{"openid"}
	admin, public, _ := newHydra(t, &subject, &claims, &scope)
	newUI(t, f.reg)
	testhelpers.NewErrorTestServer(t, f.reg)
	server, _ := testhelpers.NewKratosServer(t, f.reg)
	provider := newOIDCProvider(t, server, public, admin, "broker")
	provider.Mapper = f.provider.Mapper

	for _, mode := range []string{oidc.AccountLinkingModeAutomatic, oidc.AccountLinkingModeVerifyWithExistingCredential} {
		provider.AccountLinkingMode = mode
		viperSetProviderConfig(t, f.conf, provider)
		for _, verified := range []bool{false, true} {
			for _, sameEmail := range []bool{false, true} {
				for _, proof := range []string{"true", "false", "missing"} {
					t.Run(fmt.Sprintf("mode=%s/existing_verified=%t/same_email=%t/incoming=%s", mode, verified, sameEmail, proof), func(t *testing.T) {
						email := testhelpers.RandomEmail()
						i := f.identity(t, email, verified)
						password := append([]byte(nil), i.Credentials[identity.CredentialsTypePassword].Config...)
						client := testhelpers.NewHTTPClientWithIdentitySessionCookie(ctx, t, f.reg, i)
						subject = testhelpers.RandomEmail()
						claims.email = testhelpers.RandomEmail()
						if sameEmail {
							claims.email = email
						}
						claims.emailVerified = nil
						if proof != "missing" {
							value := proof == "true"
							claims.emailVerified = &value
						}
						before, _, err := testhelpers.NewSDKCustomClient(server, client).FrontendAPI.ToSession(ctx).Execute()
						require.NoError(t, err)
						settings := testhelpers.InitializeSettingsFlowViaBrowser(t, client, false, server)
						body, _ := testhelpers.HTTPPostForm(t, client, settings.Ui.Action, &url.Values{"csrf_token": {nosurfx.FakeCSRFToken}, "link": {provider.ID}})
						allowed := verified || (sameEmail && proof == "true")
						if allowed {
							require.EqualValues(t, flow.StateSuccess, gjson.GetBytes(body, "state").String(), "%s", body)
						} else {
							require.Contains(t, string(body), "Please verify your email")
						}
						current, err := f.reg.PrivilegedIdentityPool().GetIdentityConfidential(ctx, i.ID)
						require.NoError(t, err)
						require.Equal(t, allowed, current.VerifiableAddresses[0].Verified)
						if allowed {
							require.Equal(t, []string{provider.ID + ":" + subject}, current.Credentials[identity.CredentialsTypeOIDC].Identifiers)
						} else {
							require.Empty(t, current.Credentials[identity.CredentialsTypeOIDC].Identifiers)
						}
						require.JSONEq(t, string(password), string(current.Credentials[identity.CredentialsTypePassword].Config))
						require.JSONEq(t, string(i.Traits), string(current.Traits))
						require.JSONEq(t, string(i.MetadataAdmin), string(current.MetadataAdmin))
						after, _, err := testhelpers.NewSDKCustomClient(server, client).FrontendAPI.ToSession(ctx).Execute()
						require.NoError(t, err)
						require.Equal(t, before.Id, after.Id)
						if !allowed {
							require.Equal(t, before.AuthenticationMethods, after.AuthenticationMethods)
						}
					})
				}
			}
		}
	}
	for _, change := range []string{"unverified", "email", "credential owner"} {
		t.Run("pending_callback/"+change, func(t *testing.T) {
			email := testhelpers.RandomEmail()
			i := f.identity(t, email, change != "credential owner")
			client := testhelpers.NewHTTPClientWithIdentitySessionCookie(ctx, t, f.reg, i)
			subject = testhelpers.RandomEmail()
			claims.email = email
			verified := true
			claims.emailVerified = &verified
			if change == "unverified" {
				claims.email = testhelpers.RandomEmail()
			}
			before, _, err := testhelpers.NewSDKCustomClient(server, client).FrontendAPI.ToSession(ctx).Execute()
			require.NoError(t, err)
			settings := testhelpers.InitializeSettingsFlowViaBrowser(t, client, false, server)
			redirect := client.CheckRedirect
			client.CheckRedirect = func(r *http.Request, via []*http.Request) error {
				if strings.Contains(r.URL.Path, "/callback/") {
					return http.ErrUseLastResponse
				}
				if redirect != nil {
					return redirect(r, via)
				}
				return nil
			}
			_, response := testhelpers.HTTPPostForm(t, client, settings.Ui.Action, &url.Values{"csrf_token": {nosurfx.FakeCSRFToken}, "link": {provider.ID}})
			callback, err := response.Location()
			require.NoError(t, err)
			require.Contains(t, callback.Path, "/callback/")
			switch change {
			case "unverified":
				i.VerifiableAddresses[0].Verified = false
				require.NoError(t, f.reg.PrivilegedIdentityPool().UpdateVerifiableAddress(ctx, &i.VerifiableAddresses[0], "verified"))
			case "email":
				i.Traits = identity.Traits(fmt.Sprintf(`{"subject":%q,"name":"Keep Existing Name"}`, testhelpers.RandomEmail()))
				require.NoError(t, f.reg.IdentityManager().Update(ctx, i, identity.ManagerAllowWriteProtectedTraits))
			case "credential owner":
				other := f.identity(t, testhelpers.RandomEmail(), true)
				credential, err := identity.NewCredentialsOIDC(nil, provider.ID, subject, "")
				require.NoError(t, err)
				other.SetCredentials(identity.CredentialsTypeOIDC, *credential)
				require.NoError(t, f.reg.PrivilegedIdentityPool().UpdateIdentity(ctx, other))
			}
			client.CheckRedirect = redirect
			response, err = client.Get(callback.String())
			require.NoError(t, err)
			body := x.MustReadAll(response.Body)
			require.NoError(t, response.Body.Close())
			if change == "credential owner" {
				require.Contains(t, string(body), "exists already")
			} else {
				require.Contains(t, string(body), "Please verify your email")
			}
			current, err := f.reg.PrivilegedIdentityPool().GetIdentityConfidential(ctx, i.ID)
			require.NoError(t, err)
			require.Empty(t, current.Credentials[identity.CredentialsTypeOIDC].Identifiers)
			require.False(t, current.VerifiableAddresses[0].Verified)
			after, _, err := testhelpers.NewSDKCustomClient(server, client).FrontendAPI.ToSession(ctx).Execute()
			require.NoError(t, err)
			require.Equal(t, before.AuthenticationMethods, after.AuthenticationMethods)
		})
	}
}

func TestSettingsVerifiedEmailRecovery(t *testing.T) {
	f := newVerifiedLinkFixture(t, configx.WithValues(map[string]any{
		"selfservice.methods.password.enabled":                true,
		"selfservice.methods.code.enabled":                    true,
		"selfservice.flows.recovery.enabled":                  true,
		"selfservice.flows.recovery.use":                      "code",
		"selfservice.flows.recovery.after.hooks":              []map[string]string{{"hook": "revoke_active_sessions"}},
		"selfservice.flows.registration.after.password.hooks": []map[string]string{{"hook": "session"}},
		"selfservice.flows.registration.after.oidc.hooks":     []map[string]string{{"hook": "session"}},
	}))
	ctx := context.Background()
	testhelpers.SetDefaultIdentitySchema(f.conf, "file://../code/stub/default.schema.json")
	var subject string
	var claims idTokenClaims
	scope := []string{"openid"}
	admin, public, _ := newHydra(t, &subject, &claims, &scope)
	newUI(t, f.reg)
	testhelpers.NewRecoveryUIFlowEchoServer(t, f.reg)
	testhelpers.NewErrorTestServer(t, f.reg)
	newReturnTS(t, f.reg)
	server, _ := testhelpers.NewKratosServer(t, f.reg)
	provider := newOIDCProvider(t, server, public, admin, "broker")
	provider.AccountLinkingMode = oidc.AccountLinkingModeAutomatic
	provider.Mapper = "base64://" + base64.StdEncoding.EncodeToString([]byte(`local c=std.extVar('claims'); {identity:{traits:{email:c.email}}}`))
	viperSetProviderConfig(t, f.conf, provider)

	for _, sameEmail := range []bool{false, true} {
		t.Run(fmt.Sprintf("same_email=%t", sameEmail), func(t *testing.T) {
			email := testhelpers.RandomEmail()
			const oldPassword, newPassword = "OriginalFixturePassword123456789", "ReplacementFixturePassword987654321"
			attacker := testhelpers.NewClientWithCookies(t)
			registration := testhelpers.InitializeRegistrationFlowViaBrowser(t, attacker, server, false, false, false)
			body, _ := testhelpers.HTTPPostForm(t, attacker, registration.Ui.Action, &url.Values{
				"csrf_token": {nosurfx.FakeCSRFToken}, "method": {"password"}, "traits.email": {email}, "password": {oldPassword},
			})
			id, err := uuid.FromString(gjson.GetBytes(body, "identity.id").String())
			require.NoError(t, err, "%s", body)
			require.False(t, gjson.GetBytes(body, "identity.verifiable_addresses.0.verified").Bool())
			subject = testhelpers.RandomEmail()
			claims.email = testhelpers.RandomEmail()
			verified := !sameEmail
			claims.emailVerified = &verified
			if sameEmail {
				claims.email = email
			}
			settings := testhelpers.InitializeSettingsFlowViaBrowser(t, attacker, false, server)
			body, _ = testhelpers.HTTPPostForm(t, attacker, settings.Ui.Action, &url.Values{"csrf_token": {nosurfx.FakeCSRFToken}, "link": {provider.ID}})
			require.Contains(t, string(body), "Please verify your email")

			owner := testhelpers.NewClientWithCookies(t)
			recovery := testhelpers.SubmitRecoveryForm(t, false, false, owner, server, func(v url.Values) {
				v.Set("method", "code")
				v.Set("email", email)
			}, http.StatusOK, f.conf.SelfServiceFlowRecoveryUI(ctx).String())
			message := testhelpers.CourierExpectMessage(ctx, t, f.reg, email, "Use code")
			code := testhelpers.CourierExpectCodeInMessage(t, message, 1)
			body, _ = testhelpers.HTTPPostForm(t, owner, gjson.Get(recovery, "ui.action").String(), &url.Values{
				"csrf_token": {nosurfx.FakeCSRFToken}, "method": {"code"}, "code": {code},
			})
			body, _ = testhelpers.HTTPPostForm(t, owner, gjson.GetBytes(body, "ui.action").String(), &url.Values{
				"csrf_token": {nosurfx.FakeCSRFToken}, "method": {"password"}, "password": {newPassword},
			})
			require.EqualValues(t, flow.StateSuccess, gjson.GetBytes(body, "state").String(), "%s", body)
			current, err := f.reg.PrivilegedIdentityPool().GetIdentityConfidential(ctx, id)
			require.NoError(t, err)
			require.True(t, current.VerifiableAddresses[0].Verified)
			require.Empty(t, current.Credentials[identity.CredentialsTypeOIDC].Identifiers)
			_, response, err := testhelpers.NewSDKCustomClient(server, attacker).FrontendAPI.ToSession(ctx).Execute()
			require.Error(t, err)
			require.Equal(t, http.StatusUnauthorized, response.StatusCode)
			for _, attempt := range []struct {
				password string
				status   int
			}{{oldPassword, http.StatusBadRequest}, {newPassword, http.StatusOK}} {
				result := testhelpers.SubmitLoginForm(t, true, nil, server, func(v url.Values) {
					v.Set("method", "password")
					v.Set("identifier", email)
					v.Set("password", attempt.password)
				}, false, false, attempt.status, server.URL+login.RouteSubmitFlow)
				if attempt.status == http.StatusOK {
					require.Equal(t, id.String(), gjson.Get(result, "session.identity.id").String())
				} else {
					require.False(t, gjson.Get(result, "session_token").Exists())
				}
			}

			fresh := testhelpers.NewClientWithCookies(t)
			loginFlow := testhelpers.InitializeLoginFlowViaBrowser(t, fresh, server, false, false, false, false)
			body, _ = testhelpers.HTTPPostForm(t, fresh, loginFlow.Ui.Action, &url.Values{"csrf_token": {nosurfx.FakeCSRFToken}, "method": {"oidc"}, "provider": {provider.ID}})
			require.NotEqual(t, id.String(), gjson.GetBytes(body, "identity.id").String())
			freshSession, response, err := testhelpers.NewSDKCustomClient(server, fresh).FrontendAPI.ToSession(ctx).Execute()
			if sameEmail {
				require.Error(t, err)
				require.Equal(t, http.StatusUnauthorized, response.StatusCode)
				require.Contains(t, string(body), "1010016")
			} else {
				require.NoError(t, err)
				require.NotEqual(t, id.String(), freshSession.Identity.Id)
			}
			current, err = f.reg.PrivilegedIdentityPool().GetIdentityConfidential(ctx, id)
			require.NoError(t, err)
			require.Empty(t, current.Credentials[identity.CredentialsTypeOIDC].Identifiers)
		})
	}
}
