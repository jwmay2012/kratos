// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
	"golang.org/x/crypto/bcrypt"

	"github.com/ory/herodot"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/pkg/testhelpers"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/selfservice/strategy/oidc"
	"github.com/ory/kratos/x/nosurfx"
	"github.com/ory/x/configx"
)

func TestVerifiedEmailManualLinkRejectsRetiredProof(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		t.Run(map[bool]string{false: "retired", true: "replacement-password"}[replacement], func(t *testing.T) {
			ctx := context.Background()
			f := newVerifiedLinkFixture(t)
			proof := f.identity(t, "person@example.test", false)
			current, err := f.reg.PrivilegedIdentityPool().GetIdentityConfidential(ctx, proof.ID)
			require.NoError(t, err)
			current.Credentials = make(map[identity.CredentialsType]identity.Credentials)
			current.VerifiableAddresses[0].Verified = true
			require.NoError(t, f.reg.IdentityValidator().Validate(ctx, current))
			if replacement {
				hash, err := f.reg.Hasher(ctx).Generate(ctx, []byte("ReplacementFixturePassword123456"))
				require.NoError(t, err)
				data, err := json.Marshal(identity.CredentialsPassword{HashedPassword: string(hash)})
				require.NoError(t, err)
				current.UpsertCredentialsConfig(identity.CredentialsTypePassword, data, 0)
			}
			require.NoError(t, f.reg.PrivilegedIdentityPool().UpdateIdentity(ctx, current))
			before, err := f.reg.PrivilegedIdentityPool().GetIdentityConfidential(ctx, proof.ID)
			require.NoError(t, err)
			link := []byte(`{"providers":[{"provider":"broker","subject":"late-subject"}],"verified_email":"person@example.test"}`)
			var refusal *herodot.DefaultError
			require.ErrorAs(t, f.strategy.Link(ctx, proof, link), &refusal)
			require.Contains(t, refusal.Reason(), "credentials changed")
			after, err := f.reg.PrivilegedIdentityPool().GetIdentityConfidential(ctx, proof.ID)
			require.NoError(t, err)
			require.Equal(t, before.Credentials, after.Credentials)
		})
	}
}

func TestVerifiedEmailManualLinkMigratesPassword(t *testing.T) {
	ctx := context.Background()
	f := newVerifiedLinkFixture(t, configx.WithValue("selfservice.methods.password.enabled", true), configx.WithValue("hashers.algorithm", "argon2"))
	i := f.identity(t, "person@example.test", false)
	const password = "LegacyFixturePassword12345678"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	require.NoError(t, err)
	data, err := json.Marshal(identity.CredentialsPassword{HashedPassword: string(hash)})
	require.NoError(t, err)
	i.UpsertCredentialsConfig(identity.CredentialsTypePassword, data, 0)
	require.NoError(t, f.reg.PrivilegedIdentityPool().UpdateIdentity(ctx, i))
	before := i.Credentials[identity.CredentialsTypePassword].ID
	newUI(t, f.reg)
	server, _ := testhelpers.NewKratosServer(t, f.reg)
	w, _, _ := f.login(t, flow.TypeAPI, verifiedClaims("person@example.test", "new-subject"))
	flowID := gjson.Get(w.Body.String(), "id").String()
	require.NotEmpty(t, flowID)
	body, response := testhelpers.HTTPRequestJSON(t, http.DefaultClient, http.MethodPost, server.URL+login.RouteSubmitFlow+"?flow="+flowID, map[string]string{"method": "password", "identifier": "person@example.test", "password": password})
	require.Equal(t, http.StatusOK, response.StatusCode, "%s", body)
	current, err := f.reg.PrivilegedIdentityPool().GetIdentityConfidential(ctx, i.ID)
	require.NoError(t, err)
	require.NotEqual(t, before, current.Credentials[identity.CredentialsTypePassword].ID)
	require.Equal(t, []string{"broker:new-subject"}, current.Credentials[identity.CredentialsTypeOIDC].Identifiers)
}

func TestRecoveryRetiresOIDC(t *testing.T) {
	f := newVerifiedLinkFixture(t, configx.WithValues(map[string]any{
		"selfservice.methods.password.enabled":                true,
		"selfservice.methods.profile.enabled":                 true,
		"selfservice.methods.code.enabled":                    true,
		"selfservice.flows.recovery.enabled":                  true,
		"selfservice.flows.recovery.use":                      "code",
		"selfservice.flows.verification.enabled":              true,
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
	for _, scenario := range []string{"changed-address", "unverified-provider-registration"} {
		t.Run(scenario, func(t *testing.T) {
			ownerEmail, providerEmail := testhelpers.RandomEmail(), testhelpers.RandomEmail()
			subject = testhelpers.RandomEmail()
			trusted := scenario == "changed-address"
			claims.email, claims.emailVerified = providerEmail, &trusted
			if !trusted {
				claims.email = ownerEmail
			}
			previous := testhelpers.NewClientWithCookies(t)
			registration := testhelpers.InitializeRegistrationFlowViaBrowser(t, previous, server, false, false, false)
			values := url.Values{"csrf_token": {nosurfx.FakeCSRFToken}, "method": {"oidc"}, "provider": {provider.ID}}
			if trusted {
				values = url.Values{"csrf_token": {nosurfx.FakeCSRFToken}, "method": {"password"}, "traits.email": {providerEmail}, "password": {"OriginalFixturePassword123456789"}}
			}
			body, _ := testhelpers.HTTPPostForm(t, previous, registration.Ui.Action, &values)
			id, err := uuid.FromString(gjson.GetBytes(body, "identity.id").String())
			require.NoError(t, err, "%s", body)
			if trusted {
				settings := testhelpers.InitializeSettingsFlowViaBrowser(t, previous, false, server)
				body, _ = testhelpers.HTTPPostForm(t, previous, settings.Ui.Action, &url.Values{"csrf_token": {nosurfx.FakeCSRFToken}, "link": {provider.ID}})
				require.EqualValues(t, flow.StateSuccess, gjson.GetBytes(body, "state").String(), "%s", body)
				settings = testhelpers.InitializeSettingsFlowViaBrowser(t, previous, false, server)
				body, _ = testhelpers.HTTPPostForm(t, previous, settings.Ui.Action, &url.Values{"csrf_token": {nosurfx.FakeCSRFToken}, "method": {"profile"}, "traits.email": {ownerEmail}})
				require.EqualValues(t, flow.StateSuccess, gjson.GetBytes(body, "state").String(), "%s", body)
			}
			owner := testhelpers.NewClientWithCookies(t)
			recovery := testhelpers.SubmitRecoveryForm(t, false, false, owner, server, func(v url.Values) { v.Set("method", "code"); v.Set("email", ownerEmail) }, http.StatusOK, f.conf.SelfServiceFlowRecoveryUI(ctx).String())
			message := testhelpers.CourierExpectMessage(ctx, t, f.reg, ownerEmail, "Use code")
			code := testhelpers.CourierExpectCodeInMessage(t, message, 1)
			body, _ = testhelpers.HTTPPostForm(t, owner, gjson.Get(recovery, "ui.action").String(), &url.Values{"csrf_token": {nosurfx.FakeCSRFToken}, "method": {"code"}, "code": {code}})
			require.NotEmpty(t, gjson.GetBytes(body, "ui.action").String(), "%s", body)
			_, response, err := testhelpers.NewSDKCustomClient(server, previous).FrontendAPI.ToSession(ctx).Execute()
			require.Error(t, err)
			require.Equal(t, http.StatusUnauthorized, response.StatusCode)
			body, _ = testhelpers.HTTPPostForm(t, owner, gjson.GetBytes(body, "ui.action").String(), &url.Values{"csrf_token": {nosurfx.FakeCSRFToken}, "method": {"password"}, "password": {"ReplacementFixturePassword987654321"}})
			require.EqualValues(t, flow.StateSuccess, gjson.GetBytes(body, "state").String(), "%s", body)
			current, err := f.reg.PrivilegedIdentityPool().GetIdentityConfidential(ctx, id)
			require.NoError(t, err)
			require.True(t, current.VerifiableAddresses[0].Verified)
			require.Empty(t, current.Credentials[identity.CredentialsTypeOIDC].Identifiers)
			fresh := testhelpers.NewClientWithCookies(t)
			login := testhelpers.InitializeLoginFlowViaBrowser(t, fresh, server, false, false, false, false)
			testhelpers.HTTPPostForm(t, fresh, login.Ui.Action, &url.Values{"csrf_token": {nosurfx.FakeCSRFToken}, "method": {"oidc"}, "provider": {provider.ID}})
			unexpected, response, err := testhelpers.NewSDKCustomClient(server, fresh).FrontendAPI.ToSession(ctx).Execute()
			if err != nil {
				require.Equal(t, http.StatusUnauthorized, response.StatusCode)
			} else {
				require.NotEqual(t, id.String(), unexpected.Identity.Id)
			}
			// The owner can subsequently add a newly authenticated trusted same-email identity.
			subject, claims.email, trusted = testhelpers.RandomEmail(), ownerEmail, true
			settings := testhelpers.InitializeSettingsFlowViaBrowser(t, owner, false, server)
			body, _ = testhelpers.HTTPPostForm(t, owner, settings.Ui.Action, &url.Values{"csrf_token": {nosurfx.FakeCSRFToken}, "link": {provider.ID}})
			require.EqualValues(t, flow.StateSuccess, gjson.GetBytes(body, "state").String(), "%s", body)
			current, err = f.reg.PrivilegedIdentityPool().GetIdentityConfidential(ctx, id)
			require.NoError(t, err)
			require.Equal(t, []string{provider.ID + ":" + subject}, current.Credentials[identity.CredentialsTypeOIDC].Identifiers)
		})
	}
}
