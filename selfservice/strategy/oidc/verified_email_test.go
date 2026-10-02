// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
	"github.com/rakutentech/jwk-go/jwk"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/ory/herodot"
	"github.com/ory/kratos/driver"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/persistence"
	"github.com/ory/kratos/pkg"
	"github.com/ory/kratos/pkg/testhelpers"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/selfservice/flow/registration"
	"github.com/ory/kratos/selfservice/strategy/oidc"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/ui/node"
	"github.com/ory/kratos/x"
	"github.com/ory/x/configx"
	"github.com/ory/x/logrusx"
	"github.com/ory/x/otelx"
	"github.com/ory/x/sqlcon"
	"github.com/ory/x/sqlxx"
)

type verifiedLinkFixture struct {
	conf     *config.Config
	reg      *driver.RegistryDefault
	strategy *oidc.Strategy
	provider *oidc.Configuration
}

type failedVerifiedAddressLookup struct {
	persistence.Persister
	cause error
}

func (p failedVerifiedAddressLookup) FindVerifiableAddressByValue(context.Context, string, string) (*identity.VerifiableAddress, error) {
	return nil, p.cause
}

func newVerifiedLinkFixture(t *testing.T, extra ...configx.OptionModifier) verifiedLinkFixture {
	mapper := `local c=std.extVar('claims'); {identity:{traits:{subject:c.email,name:'Incoming Name'},verified_addresses:if std.objectHas(c,'email_verified') && c.email_verified then [{via:'email',value:c.email}] else []}}`
	provider := &oidc.Configuration{ID: "broker", Provider: "generic", ClientID: "fixture", ClientSecret: "fixture", IssuerURL: "https://idp.example.test", Mapper: "base64://" + base64.StdEncoding.EncodeToString([]byte(mapper)), AccountLinkingMode: oidc.AccountLinkingModeAutomatic}
	options := []configx.OptionModifier{
		configx.WithValues(testhelpers.MethodEnableConfig(identity.CredentialsTypeOIDC, true)),
		configx.WithValues(testhelpers.DefaultIdentitySchemaConfig("file://./stub/registration-verifiable-email.schema.json")),
		configx.WithValue(config.ViperKeySelfServiceStrategyConfig+".oidc.config.providers", []oidc.Configuration{*provider}),
		configx.WithValue("selfservice.default_browser_return_url", "https://app.example.test/"),
		configx.WithValue("selfservice.flows.login.ui_url", "https://app.example.test/login"),
		configx.WithValue("selfservice.flows.registration.ui_url", "https://app.example.test/registration"),
	}
	conf, reg := pkg.NewFastRegistryWithMocks(t, append(options, extra...)...)
	return verifiedLinkFixture{conf, reg, reg.AllLoginStrategies().MustStrategy(identity.CredentialsTypeOIDC).(*oidc.Strategy), provider}
}

func (f verifiedLinkFixture) identity(t *testing.T, email string, verified bool) *identity.Identity {
	i := identity.NewIdentity("default")
	i.Traits = identity.Traits(`{"subject":"` + email + `","name":"Keep Existing Name"}`)
	i.MetadataPublic, i.MetadataAdmin = sqlxx.NullJSONRawMessage(`{"keep":"public"}`), sqlxx.NullJSONRawMessage(`{"keep":"admin"}`)
	i.SetCredentials(identity.CredentialsTypePassword, identity.Credentials{Type: identity.CredentialsTypePassword,
		Identifiers: []string{email}, Config: []byte(`{"hashed_password":"$argon2id$v=19$m=32,t=2,p=4$cm94YnRVOW5jZzFzcVE4bQ$MNzk5BtR2vUhrp6qQEjRNw"}`)})
	require.NoError(t, f.reg.IdentityManager().Create(context.Background(), i))
	if verified {
		i.VerifiableAddresses[0].Verified = true
		i.VerifiableAddresses[0].Status = identity.VerifiableAddressStatusCompleted
		require.NoError(t, f.reg.PrivilegedIdentityPool().UpdateVerifiableAddress(context.Background(), &i.VerifiableAddresses[0]))
	}
	return i
}

func (f verifiedLinkFixture) login(t *testing.T, kind flow.Type, claims *oidc.Claims) (*httptest.ResponseRecorder, *login.Flow, error) {
	return f.loginWithProvider(t, kind, claims, oidc.NewProviderGenericOIDC(f.provider, f.reg))
}

func (f verifiedLinkFixture) loginWithProvider(t *testing.T, kind flow.Type, claims *oidc.Claims, provider oidc.Provider) (*httptest.ResponseRecorder, *login.Flow, error) {
	r := httptest.NewRequest(http.MethodGet, "http://localhost/self-service/login/"+string(kind), nil)
	lf, err := login.NewFlow(f.conf, time.Minute, "csrf", r, kind)
	require.NoError(t, err)
	lf.Active = identity.CredentialsTypeOIDC
	if kind == flow.TypeAPI {
		lf.IDToken = "already-verified-fixture"
		r.Header.Set("Accept", "application/json")
	}
	require.NoError(t, f.reg.LoginFlowPersister().CreateLoginFlow(context.Background(), lf))
	w := httptest.NewRecorder()
	_, err = f.strategy.ProcessLogin(context.Background(), w, r, lf, nil, claims, provider, &oidc.AuthCodeContainer{})
	return w, lf, err
}

func verifiedClaims(email, subject string) *oidc.Claims {
	return &oidc.Claims{Issuer: "https://idp.example.test", Subject: subject, Email: email, EmailVerified: true}
}

func TestVerifiedEmailAutomaticLinking(t *testing.T) {
	for _, kind := range []flow.Type{flow.TypeBrowser, flow.TypeAPI} {
		t.Run(string(kind), func(t *testing.T) {
			f := newVerifiedLinkFixture(t)
			i := f.identity(t, "person@example.test", true)
			password := append([]byte(nil), i.Credentials[identity.CredentialsTypePassword].Config...)
			for _, subject := range []string{"opaque-oidc-subject", "saml-name-id", "saml-name-id"} {
				w, _, err := f.login(t, kind, verifiedClaims("person@example.test", subject))
				require.NoError(t, err, w.Body.String())
				if kind == flow.TypeAPI {
					require.Equal(t, 200, w.Code, w.Body.String())
					require.Equal(t, i.ID.String(), gjson.Get(w.Body.String(), "session.identity.id").String())
				} else {
					require.Equal(t, 303, w.Code, w.Body.String())
					r := httptest.NewRequest(http.MethodGet, "http://localhost/sessions/whoami", nil)
					for _, cookie := range w.Result().Cookies() {
						r.AddCookie(cookie)
					}
					sess, err := f.reg.SessionManager().FetchFromRequest(context.Background(), r)
					require.NoError(t, err)
					require.Equal(t, i.ID, sess.IdentityID)
				}
			}
			current, err := f.reg.PrivilegedIdentityPool().GetIdentityConfidential(context.Background(), i.ID)
			require.NoError(t, err)
			require.ElementsMatch(t, []string{"broker:opaque-oidc-subject", "broker:saml-name-id"}, current.Credentials[identity.CredentialsTypeOIDC].Identifiers)
			require.JSONEq(t, string(password), string(current.Credentials[identity.CredentialsTypePassword].Config))
			require.JSONEq(t, string(i.Traits), string(current.Traits))
			require.JSONEq(t, string(i.MetadataAdmin), string(current.MetadataAdmin))
			require.JSONEq(t, string(i.MetadataPublic), string(current.MetadataPublic))
			count, err := f.reg.PrivilegedIdentityPool().CountIdentities(context.Background())
			require.NoError(t, err)
			require.EqualValues(t, 1, count)
		})
	}
}

func TestVerifiedEmailLinkingFallsBack(t *testing.T) {
	for _, name := range []string{"false", "missing", "unverified target", "manual mode", "disabled", "external Google"} {
		t.Run(name, func(t *testing.T) {
			f := newVerifiedLinkFixture(t)
			i := f.identity(t, "person@example.test", name != "unverified target")
			claims := verifiedClaims("person@example.test", "new-subject")
			switch name {
			case "false", "missing":
				claims.EmailVerified = false
			case "manual mode":
				f.provider.AccountLinkingMode = oidc.AccountLinkingModeVerifyWithExistingCredential
			case "disabled":
				i.State = identity.StateInactive
				require.NoError(t, f.reg.PrivilegedIdentityPool().UpdateIdentityColumns(context.Background(), i, "state"))
			case "external Google":
				f.provider.Provider = oidc.ProviderTypeGoogle
			}
			_, _, _ = f.login(t, flow.TypeAPI, claims)
			current, err := f.reg.PrivilegedIdentityPool().GetIdentityConfidential(context.Background(), i.ID)
			require.NoError(t, err)
			require.Empty(t, current.Credentials[identity.CredentialsTypeOIDC].Identifiers)
		})
	}
}

func TestVerifiedEmailKnownOIDCThenSAML(t *testing.T) {
	for _, password := range []bool{true, false} {
		t.Run(fmt.Sprintf("password=%t", password), func(t *testing.T) {
			f := newVerifiedLinkFixture(t)
			i := f.identity(t, "person@example.test", false)
			if !password {
				delete(i.Credentials, identity.CredentialsTypePassword)
			}
			old, err := identity.NewCredentialsOIDC(nil, "broker", "already-linked-oidc", "")
			require.NoError(t, err)
			i.SetCredentials(identity.CredentialsTypeOIDC, *old)
			require.NoError(t, f.reg.PrivilegedIdentityPool().UpdateIdentity(context.Background(), i))
			_, _, err = f.login(t, flow.TypeAPI, verifiedClaims("person@example.test", "already-linked-oidc"))
			require.NoError(t, err)
			current, err := f.reg.PrivilegedIdentityPool().GetIdentityConfidential(context.Background(), i.ID)
			require.NoError(t, err)
			require.True(t, current.VerifiableAddresses[0].Verified, "the original password's history does not negate trusted OIDC verification")
			_, _, err = f.login(t, flow.TypeAPI, verifiedClaims("person@example.test", "new-saml-subject"))
			require.NoError(t, err)
			current, err = f.reg.PrivilegedIdentityPool().GetIdentityConfidential(context.Background(), i.ID)
			require.NoError(t, err)
			require.ElementsMatch(t, []string{"broker:already-linked-oidc", "broker:new-saml-subject"}, current.Credentials[identity.CredentialsTypeOIDC].Identifiers)
			// Schema validation may retain an empty password credential; it must not create a usable password.
			hash := gjson.GetBytes(current.Credentials[identity.CredentialsTypePassword].Config, "hashed_password").String()
			require.Equal(t, password, hash != "")
		})
	}
}

func TestVerifiedEmailBrowserLinkingWaitsForMFA(t *testing.T) {
	f := newVerifiedLinkFixture(t)
	ctx := context.Background()
	f.conf.MustSet(ctx, config.ViperKeySessionWhoAmIAAL, config.HighestAvailableAAL)
	f.conf.MustSet(ctx, "selfservice.methods.totp.enabled", true)
	i := f.identity(t, "person@example.test", true)
	i.SetCredentials(identity.CredentialsTypeTOTP, identity.Credentials{Type: identity.CredentialsTypeTOTP,
		Identifiers: []string{i.ID.String()}, Config: []byte(`{"totp_url":"otpauth://totp/test?secret=JBSWY3DPEHPK3PXP"}`)})
	require.NoError(t, f.reg.PrivilegedIdentityPool().UpdateIdentity(ctx, i))
	w, original, err := f.login(t, flow.TypeBrowser, verifiedClaims("person@example.test", "new-subject"))
	require.NoError(t, err)
	redirect, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	id, err := uuid.FromString(redirect.Query().Get("flow"))
	require.NoError(t, err)
	lf, err := f.reg.LoginFlowPersister().GetLoginFlow(ctx, id)
	require.NoError(t, err)
	require.NotEqual(t, original.ID, lf.ID, "the browser's new MFA flow carries the pending credential")
	require.Equal(t, identity.AuthenticatorAssuranceLevel2, lf.RequestedAAL)
	pending, err := flow.DuplicateCredentials(lf)
	require.NoError(t, err)
	require.NotNil(t, pending)
	require.True(t, gjson.GetBytes(pending.CredentialsConfig, "automatic").Bool())
	current, err := f.reg.PrivilegedIdentityPool().GetIdentityConfidential(ctx, i.ID)
	require.NoError(t, err)
	require.Empty(t, current.Credentials[identity.CredentialsTypeOIDC].Identifiers, "first factor must not attach the credential")
	sess := session.NewInactiveSession()
	sess.CompletedLoginForWithProvider(identity.CredentialsTypeOIDC, identity.AuthenticatorAssuranceLevel1, "broker", "")
	sess.CompletedLoginFor(identity.CredentialsTypeTOTP, identity.AuthenticatorAssuranceLevel2)
	lf.Active = identity.CredentialsTypeTOTP
	require.NoError(t, f.reg.LoginHookExecutor().PostLoginHook(httptest.NewRecorder(), httptest.NewRequest("POST", "http://localhost/self-service/login", nil), node.TOTPGroup, lf, current, sess, ""))
	current, err = f.reg.PrivilegedIdentityPool().GetIdentityConfidential(ctx, i.ID)
	require.NoError(t, err)
	require.Contains(t, current.Credentials[identity.CredentialsTypeOIDC].Identifiers, "broker:new-subject")
}

func TestVerifiedEmailLinkingDoesNotStealCredentials(t *testing.T) {
	f := newVerifiedLinkFixture(t)
	ctx := context.Background()
	i, other := f.identity(t, "person@example.test", true), f.identity(t, "other@example.test", true)
	credential, err := identity.NewCredentialsOIDC(nil, "broker", "owned-subject", "")
	require.NoError(t, err)
	other.SetCredentials(identity.CredentialsTypeOIDC, *credential)
	require.NoError(t, f.reg.PrivilegedIdentityPool().UpdateIdentity(ctx, other))
	var config map[string]any
	require.NoError(t, json.Unmarshal(credential.Config, &config))
	config["automatic"], config["verified_email"] = true, "person@example.test"
	data, err := json.Marshal(config)
	require.NoError(t, err)
	require.Error(t, f.strategy.Link(ctx, i, data))
	current, err := f.reg.PrivilegedIdentityPool().GetIdentityConfidential(ctx, i.ID)
	require.NoError(t, err)
	require.Empty(t, current.Credentials[identity.CredentialsTypeOIDC].Identifiers)
	owner, _, err := f.reg.PrivilegedIdentityPool().FindByCredentialsIdentifier(ctx, identity.CredentialsTypeOIDC, "broker:owned-subject")
	require.NoError(t, err)
	require.Equal(t, other.ID, owner.ID)
	w, _, err := f.login(t, flow.TypeAPI, verifiedClaims("person@example.test", "owned-subject"))
	require.NoError(t, err)
	require.Equal(t, other.ID.String(), gjson.Get(w.Body.String(), "session.identity.id").String(), "an existing subject remains authoritative even when its email changes")
}

func TestVerifiedEmailLinkingRechecksPendingTarget(t *testing.T) {
	for _, changed := range []string{"disabled", "unverified", "email", "organization", "provider mode"} {
		t.Run(changed, func(t *testing.T) {
			f := newVerifiedLinkFixture(t)
			ctx := context.Background()
			i := f.identity(t, "person@example.test", true)
			org := uuid.Must(uuid.NewV4())
			i.OrganizationID = uuid.NullUUID{UUID: org, Valid: true}
			require.NoError(t, f.reg.PrivilegedIdentityPool().UpdateIdentityColumns(ctx, i, "organization_id"))
			stale, err := f.reg.PrivilegedIdentityPool().GetIdentityConfidential(ctx, i.ID)
			require.NoError(t, err)
			data, err := json.Marshal(map[string]any{"providers": []map[string]string{{"provider": "broker", "subject": "new-subject", "organization": org.String()}}, "verified_email": "person@example.test", "automatic": true})
			require.NoError(t, err)
			switch changed {
			case "disabled":
				i.State = identity.StateInactive
				require.NoError(t, f.reg.PrivilegedIdentityPool().UpdateIdentityColumns(ctx, i, "state"))
			case "unverified":
				i.VerifiableAddresses[0].Verified = false
				require.NoError(t, f.reg.PrivilegedIdentityPool().UpdateVerifiableAddress(ctx, &i.VerifiableAddresses[0], "verified"))
			case "email":
				i.VerifiableAddresses[0].Value = "replacement@example.test"
				require.NoError(t, f.reg.PrivilegedIdentityPool().UpdateVerifiableAddress(ctx, &i.VerifiableAddresses[0], "value"))
			case "organization":
				i.OrganizationID = uuid.NullUUID{UUID: uuid.Must(uuid.NewV4()), Valid: true}
				require.NoError(t, f.reg.PrivilegedIdentityPool().UpdateIdentityColumns(ctx, i, "organization_id"))
			case "provider mode":
				f.provider.AccountLinkingMode = oidc.AccountLinkingModeVerifyWithExistingCredential
				f.conf.MustSet(ctx, config.ViperKeySelfServiceStrategyConfig+".oidc.config.providers", []oidc.Configuration{*f.provider})
			}
			linkErr := f.strategy.Link(ctx, stale, data)
			require.Error(t, linkErr)
			var expected error = herodot.ErrForbidden.WithReason("The identity no longer matches the verified SSO email")
			switch changed {
			case "disabled":
				expected = session.ErrIdentityDisabled
			case "provider mode":
				expected = herodot.ErrForbidden.WithReason("Automatic linking is no longer enabled for this provider")
			}
			before, after := httptest.NewRecorder(), httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "http://localhost/self-service/login", nil)
			f.reg.Writer().WriteError(before, r, expected)
			f.reg.Writer().WriteError(after, r, linkErr)
			require.Equal(t, before.Code, after.Code)
			require.JSONEq(t, before.Body.String(), after.Body.String(), "policy rejection responses are unchanged by annotations")
			current, err := f.reg.PrivilegedIdentityPool().GetIdentityConfidential(ctx, i.ID)
			require.NoError(t, err)
			require.Empty(t, current.Credentials[identity.CredentialsTypeOIDC].Identifiers)
		})
	}
}

func TestVerifiedEmailErrorAnnotations(t *testing.T) {
	f := newVerifiedLinkFixture(t)
	ctx := context.Background()
	i := f.identity(t, "person@example.test", true)
	err := f.strategy.Link(ctx, i, []byte(`{`))
	require.ErrorContains(t, err, "decode pending OIDC credentials")
	var syntax *json.SyntaxError
	require.ErrorAs(t, err, &syntax)

	credential, err := identity.NewCredentialsOIDC(nil, "broker", "new-subject", "")
	require.NoError(t, err)
	lf := &login.Flow{InternalContext: []byte(`{"oidc_verified_email":{"email":12}}`)}
	err = f.strategy.SetDuplicateCredentials(lf, "person@example.test", *credential, "broker")
	require.ErrorContains(t, err, "decode verified-email proof from linking flow")
	var malformed *json.UnmarshalTypeError
	require.ErrorAs(t, err, &malformed)

	require.NoError(t, f.reg.PrivilegedIdentityPool().DeleteIdentity(ctx, i.ID))
	err = f.strategy.Link(ctx, i, credential.Config)
	require.ErrorContains(t, err, "reload identity for SSO update")
	require.ErrorIs(t, err, sqlcon.ErrNoRows)
	var target *x.WithIdentityIDError
	require.ErrorAs(t, err, &target)
	require.Equal(t, i.ID, target.IdentityID())

	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	t.Cleanup(func() { require.NoError(t, tp.Shutdown(ctx)) })
	ctx, span := tp.Tracer("fixture").Start(ctx, "link identity")
	var output bytes.Buffer
	base := logrus.New()
	base.SetOutput(&output)
	logger := logrusx.New("fixture", "", logrusx.UseLogger(base), logrusx.ForceLevel(logrus.TraceLevel), logrusx.ForceFormat("json"))
	logger.WithSpanFromContext(ctx).WithError(err).Error("SSO linking failed")
	require.Equal(t, err.Error(), gjson.GetBytes(output.Bytes(), "error.message").String())
	require.Contains(t, gjson.GetBytes(output.Bytes(), "error.stack_trace").String(), "(*Strategy).Link")
	require.Equal(t, span.SpanContext().TraceID().String(), gjson.GetBytes(output.Bytes(), "otel.trace_id").String())
	otelx.End(span, &err)
	require.Len(t, recorder.Ended(), 1)
	attrs := map[string]string{}
	for _, attribute := range recorder.Ended()[0].Attributes() {
		attrs[string(attribute.Key)] = attribute.Value.AsString()
	}
	require.Equal(t, err.Error(), attrs["error.message"])
	require.Contains(t, attrs["error.stack"], "(*Strategy).Link")
}

func TestVerifiedEmailManualLinkRecordsProof(t *testing.T) {
	f := newVerifiedLinkFixture(t)
	ctx := context.Background()
	i := f.identity(t, "person@example.test", false)
	w, _, _ := f.login(t, flow.TypeAPI, verifiedClaims("person@example.test", "first-oidc"))
	id, err := uuid.FromString(gjson.Get(w.Body.String(), "id").String())
	require.NoError(t, err, w.Body.String())
	lf, err := f.reg.LoginFlowPersister().GetLoginFlow(ctx, id)
	require.NoError(t, err)
	data, err := flow.DuplicateCredentials(lf)
	require.NoError(t, err)
	require.NotNil(t, data)
	require.Equal(t, "person@example.test", gjson.GetBytes(data.CredentialsConfig, "verified_email").String())
	require.False(t, gjson.GetBytes(data.CredentialsConfig, "automatic").Bool())
	lf.Active = identity.CredentialsTypePassword
	sess := session.NewInactiveSession()
	sess.CompletedLoginFor(identity.CredentialsTypePassword, identity.AuthenticatorAssuranceLevel1)
	require.NoError(t, f.reg.LoginHookExecutor().PostLoginHook(httptest.NewRecorder(), httptest.NewRequest("POST", "http://localhost/self-service/login", nil), node.PasswordGroup, lf, i, sess, ""))
	current, err := f.reg.PrivilegedIdentityPool().GetIdentityConfidential(ctx, i.ID)
	require.NoError(t, err)
	require.True(t, current.VerifiableAddresses[0].Verified)
	_, _, err = f.login(t, flow.TypeAPI, verifiedClaims("person@example.test", "replacement-saml"))
	require.NoError(t, err)
	current, err = f.reg.PrivilegedIdentityPool().GetIdentityConfidential(ctx, i.ID)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"broker:first-oidc", "broker:replacement-saml"}, current.Credentials[identity.CredentialsTypeOIDC].Identifiers)
}

func TestVerifiedEmailConcurrentPostgres(t *testing.T) {
	dsn := os.Getenv("KRATOS_LINK_TEST_DSN")
	if dsn == "" {
		t.Skip("set KRATOS_LINK_TEST_DSN to a disposable loopback PostgreSQL database")
	}
	u, err := url.Parse(dsn)
	require.NoError(t, err)
	require.Contains(t, []string{"127.0.0.1", "localhost"}, u.Hostname(), "this test must never target a cluster database")
	require.Equal(t, "/kratos_link_test", u.Path)
	f := newVerifiedLinkFixture(t, configx.WithValue(config.ViperKeyDSN, dsn))
	ctx := context.Background()
	email := uuid.Must(uuid.NewV4()).String() + "@example.test"
	i := f.identity(t, email, true)
	var snapshots []*identity.Identity
	for range 12 {
		copy, err := f.reg.PrivilegedIdentityPool().GetIdentityConfidential(ctx, i.ID)
		require.NoError(t, err)
		snapshots = append(snapshots, copy)
	}
	start, results := make(chan struct{}), make(chan error, len(snapshots))
	var group sync.WaitGroup
	for n, snapshot := range snapshots {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			data, err := json.Marshal(map[string]any{"providers": []map[string]string{{"provider": "broker", "subject": fmt.Sprintf("subject-%d", n%6)}}, "verified_email": email, "automatic": true})
			if err == nil {
				err = f.strategy.Link(ctx, snapshot, data)
			}
			results <- err
		}()
	}
	close(start)
	group.Wait()
	close(results)
	for err := range results {
		require.NoError(t, err)
	}
	current, err := f.reg.PrivilegedIdentityPool().GetIdentityConfidential(ctx, i.ID)
	require.NoError(t, err)
	require.Len(t, current.Credentials[identity.CredentialsTypeOIDC].Identifiers, 6)
	require.JSONEq(t, string(i.Credentials[identity.CredentialsTypePassword].Config), string(current.Credentials[identity.CredentialsTypePassword].Config))
	require.JSONEq(t, string(i.Traits), string(current.Traits))
}

func TestVerifiedEmailNativeTokenFlows(t *testing.T) {
	for _, entry := range []string{"login", "registration"} {
		for _, claim := range []string{"true", "false", "missing", "wrong signature", "wrong audience", "native MFA", "highest available without MFA", "lookup failure"} {
			t.Run(entry+"/"+claim, func(t *testing.T) {
				f := newVerifiedLinkFixture(t)
				i := f.identity(t, "person@example.test", true)
				cause := errors.New("fixture storage failure")
				if claim == "lookup failure" {
					f.reg.SetPersister(failedVerifiedAddressLookup{f.reg.Persister(), cause})
				}
				if claim == "highest available without MFA" {
					f.conf.MustSet(context.Background(), config.ViperKeySessionWhoAmIAAL, config.HighestAvailableAAL)
				}
				if claim == "native MFA" {
					f.conf.MustSet(context.Background(), config.ViperKeySessionWhoAmIAAL, config.HighestAvailableAAL)
					f.conf.MustSet(context.Background(), "selfservice.methods.totp.enabled", true)
					i.SetCredentials(identity.CredentialsTypeTOTP, identity.Credentials{Type: identity.CredentialsTypeTOTP,
						Identifiers: []string{i.ID.String()}, Config: []byte(`{"totp_url":"otpauth://totp/test?secret=JBSWY3DPEHPK3PXP"}`)})
					require.NoError(t, f.reg.PrivilegedIdentityPool().UpdateIdentity(context.Background(), i))
				}
				var idp *httptest.Server
				idp = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					if r.URL.Path == "/.well-known/openid-configuration" {
						_ = json.NewEncoder(w).Encode(map[string]any{"issuer": idp.URL, "jwks_uri": idp.URL + "/keys", "authorization_endpoint": idp.URL + "/authorize", "token_endpoint": idp.URL + "/token", "id_token_signing_alg_values_supported": []string{"RS256"}})
					} else if claim == "wrong signature" {
						_, _ = w.Write(publicJWKS2)
					} else {
						_, _ = w.Write(publicJWKS)
					}
				}))
				t.Cleanup(idp.Close)
				f.provider.IssuerURL = idp.URL
				f.conf.MustSet(context.Background(), config.ViperKeySelfServiceStrategyConfig+".oidc.config.providers", []oidc.Configuration{*f.provider})
				key := new(jwk.KeySpec)
				require.NoError(t, json.Unmarshal(rawKey, key))
				claims := jwt.MapClaims{"iss": idp.URL, "aud": "fixture", "sub": "new-native-subject", "email": "person@example.test", "exp": time.Now().Add(time.Minute).Unix()}
				if claim != "missing" {
					claims["email_verified"] = claim != "false"
				}
				if claim == "wrong audience" {
					claims["aud"] = "another-application"
				}
				token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
				token.Header["kid"] = key.KeyID
				encoded, err := token.SignedString(key.Key)
				require.NoError(t, err)
				payload, err := json.Marshal(map[string]any{"method": "oidc", "provider": "broker", "id_token": encoded})
				require.NoError(t, err)
				r := httptest.NewRequest(http.MethodPost, "http://localhost/self-service/"+entry, bytes.NewReader(payload))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Accept", "application/json")
				w := httptest.NewRecorder()
				if entry == "login" {
					lf, e := login.NewFlow(f.conf, time.Minute, "csrf", r, flow.TypeAPI)
					require.NoError(t, e)
					require.NoError(t, f.reg.LoginFlowPersister().CreateLoginFlow(context.Background(), lf))
					_, err = f.strategy.Login(w, r, lf, nil)
				} else {
					rf, e := registration.NewFlow(f.conf, time.Minute, "csrf", r, flow.TypeAPI)
					require.NoError(t, e)
					require.NoError(t, f.reg.RegistrationFlowPersister().CreateRegistrationFlow(context.Background(), rf))
					err = f.strategy.Register(w, r, rf, nil)
				}
				current, e := f.reg.PrivilegedIdentityPool().GetIdentityConfidential(context.Background(), i.ID)
				require.NoError(t, e)
				if claim == "true" || claim == "highest available without MFA" {
					require.ErrorIs(t, err, flow.ErrCompletedByStrategy)
					require.Equal(t, http.StatusOK, w.Code, w.Body.String())
					require.Equal(t, i.ID.String(), gjson.Get(w.Body.String(), "session.identity.id").String())
					require.Contains(t, current.Credentials[identity.CredentialsTypeOIDC].Identifiers, "broker:new-native-subject")
				} else {
					require.Error(t, err)
					require.Empty(t, current.Credentials[identity.CredentialsTypeOIDC].Identifiers)
					if claim == "lookup failure" {
						require.ErrorIs(t, err, cause)
						require.ErrorContains(t, err, "find identity for verified-email linking: look up verified email address: fixture storage failure")
					}
					if claim == "native MFA" {
						require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
						require.True(t, gjson.Get(w.Body.String(), "ui.messages.#(id==1010016)").Exists(), "native MFA retains the existing linking ceremony")
						require.False(t, gjson.Get(w.Body.String(), "session_token").Exists())
						id, err := uuid.FromString(gjson.Get(w.Body.String(), "id").String())
						require.NoError(t, err)
						lf, err := f.reg.LoginFlowPersister().GetLoginFlow(context.Background(), id)
						require.NoError(t, err)
						pending, err := flow.DuplicateCredentials(lf)
						require.NoError(t, err)
						require.NotNil(t, pending)
						require.False(t, gjson.GetBytes(pending.CredentialsConfig, "automatic").Bool())
					}
				}
			})
		}
	}
}
