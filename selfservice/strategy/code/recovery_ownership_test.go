// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package code_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/ory/kratos/driver"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/pkg"
	"github.com/ory/kratos/pkg/testhelpers"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/selfservice/flow/recovery"
	"github.com/ory/kratos/x/nosurfx"
	"github.com/ory/x/configx"
)

const recoveryOldPassword = "PreviousFixturePassword12345678"

func recoveryOwnershipFixture(t *testing.T, verified bool, extra ...configx.OptionModifier) (*driver.RegistryDefault, *httptest.Server, *identity.Identity) {
	t.Helper()
	ctx := context.Background()
	options := []configx.OptionModifier{configx.WithValues(defaultConfig), configx.WithValue(config.ViperKeyUseContinueWithTransitions, true)}
	conf, reg := pkg.NewFastRegistryWithMocks(t, append(options, extra...)...)
	// This guarantee must not depend on a configured session-revocation hook.
	conf.MustSet(ctx, "selfservice.flows.recovery.after.hooks", []any{})
	conf.MustSet(ctx, "selfservice.flows.settings.privileged_session_max_age", "15m")
	testhelpers.NewRecoveryUIFlowEchoServer(t, reg)
	testhelpers.NewSettingsUIFlowEchoServer(t, reg)
	testhelpers.NewLoginUIFlowEchoServer(t, reg)
	testhelpers.NewErrorTestServer(t, reg)
	server, _ := testhelpers.NewKratosServer(t, reg)
	i := identity.NewIdentity(config.DefaultIdentityTraitsSchemaID)
	email := testhelpers.RandomEmail()
	i.Traits = identity.Traits(`{"email":"` + email + `"}`)
	i.MetadataAdmin = []byte(`{"retained":"admin"}`)
	i.MetadataPublic = []byte(`{"retained":"public"}`)
	hash, err := reg.Hasher(ctx).Generate(ctx, []byte(recoveryOldPassword))
	require.NoError(t, err)
	password, err := json.Marshal(identity.CredentialsPassword{HashedPassword: string(hash)})
	require.NoError(t, err)
	i.UpsertCredentialsConfig(identity.CredentialsTypePassword, password, 0)
	i.SetCredentials(identity.CredentialsTypeOIDC, identity.Credentials{Type: identity.CredentialsTypeOIDC, Identifiers: []string{"fixture:original-subject"}, Config: []byte(`{"providers":[{"provider":"fixture","subject":"original-subject"}]}`)})
	require.NoError(t, reg.IdentityManager().Create(ctx, i))
	if verified {
		i.VerifiableAddresses[0].Verified = true
		i.VerifiableAddresses[0].Status = identity.VerifiableAddressStatusCompleted
		require.NoError(t, reg.PrivilegedIdentityPool().UpdateIdentity(ctx, i))
	}
	i, err = reg.PrivilegedIdentityPool().GetIdentityConfidential(ctx, i.ID)
	require.NoError(t, err)
	return reg, server, i
}

func ownershipRecoveryCode(t *testing.T, reg *driver.RegistryDefault, server *httptest.Server, i *identity.Identity, api bool) (*http.Client, string, string) {
	t.Helper()
	client := testhelpers.NewClientWithCookies(t)
	if api {
		client = &http.Client{}
	}
	email := gjson.GetBytes(i.Traits, "email").String()
	expectedURL := reg.Config().SelfServiceFlowRecoveryUI(context.Background()).String()
	if api {
		expectedURL = server.URL + recovery.RouteSubmitFlow
	}
	body := testhelpers.SubmitRecoveryForm(t, api, false, client, server, func(v url.Values) { v.Set("method", "code"); v.Set("email", email) }, http.StatusOK, expectedURL)
	message := testhelpers.CourierExpectMessage(context.Background(), t, reg, email, "Use code")
	return client, gjson.Get(body, "ui.action").String(), testhelpers.CourierExpectCodeInMessage(t, message, 1)
}

func TestRecoveryUnverifiedCredentials(t *testing.T) {
	for _, api := range []bool{false, true} {
		for _, verification := range []string{"unverified", "verified", "other-address-verified", "unverified-mfa"} {
			t.Run(fmt.Sprintf("api=%t/%s", api, verification), func(t *testing.T) {
				ctx := context.Background()
				verified := verification == "verified"
				reg, server, before := recoveryOwnershipFixture(t, verified)
				if verification == "unverified-mfa" {
					reg.Config().MustSet(ctx, config.ViperKeySessionWhoAmIAAL, config.HighestAvailableAAL)
					reg.Config().MustSet(ctx, config.ViperKeySelfServiceSettingsRequiredAAL, config.HighestAvailableAAL)
					reg.Config().MustSet(ctx, config.ViperKeyWebAuthnRPDisplayName, "Local fixture")
					reg.Config().MustSet(ctx, config.ViperKeyWebAuthnRPID, "localhost")
					testhelpers.StrategyEnable(t, reg.Config(), identity.CredentialsTypeWebAuthn.String(), true)
					before.SetCredentials(identity.CredentialsTypeWebAuthn, identity.Credentials{Type: identity.CredentialsTypeWebAuthn, Identifiers: []string{testhelpers.RandomEmail()}, Config: []byte(`{"credentials":[{"is_passwordless":false,"display_name":"fixture"}]}`)})
					require.NoError(t, reg.PrivilegedIdentityPool().UpdateIdentity(ctx, before))
				}
				if verification == "other-address-verified" {
					before.Traits = identity.Traits(fmt.Sprintf(`{"email":%q,"phone":%q}`, gjson.GetBytes(before.Traits, "email").String(), testhelpers.RandomPhone()))
					require.NoError(t, reg.IdentityManager().Update(ctx, before, identity.ManagerAllowWriteProtectedTraits))
					for k := range before.VerifiableAddresses {
						if before.VerifiableAddresses[k].Via == identity.AddressTypeSMS {
							before.VerifiableAddresses[k].Verified = true
						}
					}
					require.NoError(t, reg.PrivilegedIdentityPool().UpdateIdentity(ctx, before))
				}
				oldBrowser := testhelpers.NewHTTPClientWithIdentitySessionCookie(ctx, t, reg, before)
				oldNative := testhelpers.NewHTTPClientWithIdentitySessionToken(ctx, t, reg, before)
				client, action, code := ownershipRecoveryCode(t, reg, server, before, api)
				var body []byte
				if api {
					body, _ = testhelpers.HTTPRequestJSON(t, client, http.MethodPost, action, map[string]string{"method": "code", "code": code})
				} else {
					body, _ = testhelpers.HTTPPostForm(t, client, action, &url.Values{"method": {"code"}, "code": {code}, "csrf_token": {nosurfx.FakeCSRFToken}})
				}
				if api {
					token := gjson.GetBytes(body, "continue_with.#(action==set_ory_session_token).ory_session_token").String()
					require.NotEmpty(t, token, "%s", body)
					client = &http.Client{Transport: testhelpers.NewTransportWithHeader(t, http.Header{"X-Session-Token": {token}})}
				}
				after, err := reg.PrivilegedIdentityPool().GetIdentityConfidential(ctx, before.ID)
				require.NoError(t, err)
				address, err := reg.IdentityPool().FindVerifiableAddressByValue(ctx, identity.AddressTypeEmail, gjson.GetBytes(before.Traits, "email").String())
				require.NoError(t, err)
				require.True(t, address.Verified)
				for _, previousAddress := range before.VerifiableAddresses {
					if previousAddress.Value == address.Value && previousAddress.Via == address.Via {
						require.Equal(t, previousAddress.ID, address.ID)
					}
				}
				require.JSONEq(t, string(before.Traits), string(after.Traits))
				require.Equal(t, before.MetadataAdmin, after.MetadataAdmin)
				require.Equal(t, before.MetadataPublic, after.MetadataPublic)
				require.ElementsMatch(t, before.RecoveryAddresses, after.RecoveryAddresses)
				if verified {
					require.Equal(t, before.Credentials, after.Credentials)
				} else {
					require.NotContains(t, after.Credentials, identity.CredentialsTypeWebAuthn)
					require.Empty(t, after.Credentials[identity.CredentialsTypeOIDC].Identifiers)
					require.Empty(t, gjson.GetBytes(after.Credentials[identity.CredentialsTypePassword].Config, "hashed_password").String())
					_, _, err := reg.PrivilegedIdentityPool().FindByCredentialsIdentifier(ctx, identity.CredentialsTypeOIDC, "fixture:original-subject")
					require.Error(t, err)
					duplicate := identity.NewIdentity(config.DefaultIdentityTraitsSchemaID)
					duplicate.Traits = append(identity.Traits(nil), before.Traits...)
					duplicate.SetCredentials(identity.CredentialsTypePassword, identity.Credentials{Type: identity.CredentialsTypePassword, Config: before.Credentials[identity.CredentialsTypePassword].Config})
					var conflict *identity.ErrDuplicateCredentials
					require.ErrorAs(t, reg.IdentityManager().Create(ctx, duplicate), &conflict, "retirement must keep the account identifier reserved")
				}
				for _, previous := range []*http.Client{oldBrowser, oldNative} {
					_, response, err := testhelpers.NewSDKCustomClient(server, previous).FrontendAPI.ToSession(ctx).Execute()
					if verified {
						require.NoError(t, err)
					} else {
						require.Error(t, err)
						require.Equal(t, http.StatusUnauthorized, response.StatusCode)
					}
				}
				owner, _, err := testhelpers.NewSDKCustomClient(server, client).FrontendAPI.ToSession(ctx).Execute()
				require.NoError(t, err)
				require.Equal(t, before.ID.String(), owner.Identity.Id)
				oldStatus := http.StatusBadRequest
				if verified {
					oldStatus = http.StatusOK
				}
				testhelpers.SubmitLoginForm(t, true, nil, server, func(v url.Values) {
					v.Set("method", "password")
					v.Set("identifier", gjson.GetBytes(before.Traits, "email").String())
					v.Set("password", recoveryOldPassword)
				}, false, false, oldStatus, server.URL+login.RouteSubmitFlow)
				const replacement = "ReplacementFixturePassword87654321"
				var settingsAction string
				if api {
					settingsAction = testhelpers.InitializeSettingsFlowViaAPI(t, client, server).Ui.Action
				} else {
					settingsAction = testhelpers.InitializeSettingsFlowViaBrowser(t, client, false, server).Ui.Action
				}
				body, _ = testhelpers.HTTPRequestJSON(t, client, http.MethodPost, settingsAction, map[string]string{"method": "password", "password": replacement, "csrf_token": nosurfx.FakeCSRFToken})
				require.EqualValues(t, flow.StateSuccess, gjson.GetBytes(body, "state").String(), "%s", body)
				testhelpers.SubmitLoginForm(t, true, nil, server, func(v url.Values) {
					v.Set("method", "password")
					v.Set("identifier", gjson.GetBytes(before.Traits, "email").String())
					v.Set("password", replacement)
				}, false, false, http.StatusOK, server.URL+login.RouteSubmitFlow)
				updated, err := reg.PrivilegedIdentityPool().GetIdentityConfidential(ctx, before.ID)
				require.NoError(t, err)
				second, secondAction, secondCode := ownershipRecoveryCode(t, reg, server, updated, true)
				body, _ = testhelpers.HTTPRequestJSON(t, second, http.MethodPost, secondAction, map[string]string{"method": "code", "code": secondCode})
				require.NotEmpty(t, gjson.GetBytes(body, "continue_with.#(action==set_ory_session_token).ory_session_token").String(), "%s", body)
				retained, err := reg.PrivilegedIdentityPool().GetIdentityConfidential(ctx, before.ID)
				require.NoError(t, err)
				require.Equal(t, updated.Credentials, retained.Credentials, "a second recovery must preserve the replacement credentials")
			})
		}
	}
}

func TestRecoveryRetirementRollback(t *testing.T) {
	ctx := context.Background()
	reg, server, before := recoveryOwnershipFixture(t, false)
	previous := testhelpers.NewHTTPClientWithIdentitySessionCookie(ctx, t, reg, before)
	client, action, code := ownershipRecoveryCode(t, reg, server, before, true)
	require.NoError(t, reg.Persister().GetConnection(ctx).RawQuery("CREATE TRIGGER fail_retirement BEFORE DELETE ON identity_credentials BEGIN SELECT RAISE(ABORT, 'injected retirement failure'); END").Exec())
	body, _ := testhelpers.HTTPRequestJSON(t, client, http.MethodPost, action, map[string]string{"method": "code", "code": code})
	require.Empty(t, gjson.GetBytes(body, "continue_with.#(action==set_ory_session_token).ory_session_token").String())
	after, err := reg.PrivilegedIdentityPool().GetIdentityConfidential(ctx, before.ID)
	require.NoError(t, err)
	require.False(t, after.VerifiableAddresses[0].Verified)
	require.Equal(t, before.Credentials, after.Credentials)
	_, _, err = testhelpers.NewSDKCustomClient(server, previous).FrontendAPI.ToSession(ctx).Execute()
	require.NoError(t, err, "failed retirement must not partially revoke sessions")
}

func TestRecoveryRejectsPendingSettings(t *testing.T) {
	testRecoveryPendingSettings(t)
}

func TestRecoveryRetirementPostgres(t *testing.T) {
	dsn := os.Getenv("KRATOS_RECOVERY_TEST_DSN")
	if dsn == "" {
		t.Skip("set KRATOS_RECOVERY_TEST_DSN to a disposable loopback PostgreSQL database")
	}
	u, err := url.Parse(dsn)
	require.NoError(t, err)
	require.Contains(t, []string{"127.0.0.1", "localhost"}, u.Hostname())
	require.Equal(t, "/kratos_recovery_test", u.Path)
	testRecoveryPendingSettings(t, configx.WithValue(config.ViperKeyDSN, dsn))
}

func testRecoveryPendingSettings(t *testing.T, extra ...configx.OptionModifier) {
	t.Helper()
	ctx := context.Background()
	reg, server, before := recoveryOwnershipFixture(t, false, extra...)
	existing, err := testhelpers.NewActiveSession(httptest.NewRequest(http.MethodGet, server.URL, nil), reg, before, time.Now().UTC(), identity.CredentialsTypePassword, identity.AuthenticatorAssuranceLevel1)
	require.NoError(t, err)
	attacker := testhelpers.NewHTTPClientWithSessionToken(ctx, t, reg, existing)
	entered, release := make(chan struct{}, 1), make(chan struct{})
	validator := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(validator.Close)
	reg.Config().MustSet(ctx, "selfservice.flows.settings.after.password.hooks", []map[string]any{{"hook": "web_hook", "config": map[string]any{"url": validator.URL, "method": "POST", "body": "base64://e30=", "can_interrupt": true}}})
	f := testhelpers.InitializeSettingsFlowViaAPI(t, attacker, server)
	done := make(chan []byte, 1)
	go func() {
		body, _ := testhelpers.HTTPRequestJSON(t, attacker, http.MethodPost, f.Ui.Action, map[string]string{"method": "password", "password": "AttackerReplacementPassword123456"})
		done <- body
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		close(release)
		t.Fatal("settings did not reach its pre-persistence hook")
	}
	client, action, code := ownershipRecoveryCode(t, reg, server, before, true)
	body, _ := testhelpers.HTTPRequestJSON(t, client, http.MethodPost, action, map[string]string{"method": "code", "code": code})
	close(release)
	require.NotEmpty(t, gjson.GetBytes(body, "continue_with.#(action==set_ory_session_token).ory_session_token").String(), "%s", body)
	select {
	case result := <-done:
		require.NotEqualValues(t, flow.StateSuccess, gjson.GetBytes(result, "state").String(), "%s", result)
	case <-time.After(10 * time.Second):
		t.Fatal("settings did not finish")
	}
	after, err := reg.PrivilegedIdentityPool().GetIdentityConfidential(ctx, before.ID)
	require.NoError(t, err)
	require.Empty(t, after.Credentials[identity.CredentialsTypeOIDC].Identifiers)
	require.Empty(t, gjson.GetBytes(after.Credentials[identity.CredentialsTypePassword].Config, "hashed_password").String())
}
