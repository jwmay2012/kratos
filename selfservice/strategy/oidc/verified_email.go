// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"net/mail"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"

	"github.com/ory/herodot"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/x"
	"github.com/ory/pop/v6"
	"github.com/ory/x/sqlcon"
	"github.com/ory/x/sqlxx"
)

const verifiedEmailContext = "oidc_verified_email"

// This proof lives only in the server-owned linking flow, never in stored credentials or client input.
type verifiedEmailProof struct {
	Email    string `json:"email"`
	Provider string `json:"provider"`
	Subject  string `json:"subject"`
}

type emailLinkCredentials struct {
	identity.CredentialsOIDC
	VerifiedEmail string `json:"verified_email,omitempty"`
	Automatic     bool   `json:"automatic,omitempty"`
}

func trustedEmail(c *Claims, provider *Configuration) string {
	if c == nil || !bool(c.EmailVerified) {
		return ""
	}
	email := strings.TrimSpace(c.Email)
	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Address != email {
		return ""
	}
	email = strings.ToLower(email)
	// Google is not authoritative for external addresses on non-Workspace accounts.
	if provider.Provider == ProviderTypeGoogle && !strings.HasSuffix(email, "@gmail.com") && c.HD == "" {
		return ""
	}
	return email
}

func (s *Strategy) rememberVerifiedEmail(f flow.InternalContexter, c *Claims, provider Provider) error {
	if provider.Config().AccountLinkingMode != AccountLinkingModeAutomatic {
		return nil
	}
	if trustedEmail(c, provider.Config()) == "" && !gjson.GetBytes(f.GetInternalContext(), verifiedEmailContext).Exists() {
		return nil
	}
	f.EnsureInternalContext()
	proof := verifiedEmailProof{Email: trustedEmail(c, provider.Config()), Provider: provider.Config().ID, Subject: c.Subject}
	data, err := sjson.SetBytes(f.GetInternalContext(), verifiedEmailContext, proof)
	if err == nil {
		f.SetInternalContext(data)
	}
	return errors.Wrap(err, "remember verified email in registration flow")
}

func linkConfig(f flow.InternalContexter, credentials identity.CredentialsOIDC) ([]byte, error) {
	var proof verifiedEmailProof
	if value := gjson.GetBytes(f.GetInternalContext(), verifiedEmailContext); value.Exists() {
		if err := json.Unmarshal([]byte(value.Raw), &proof); err != nil {
			return nil, errors.Wrap(err, "decode verified-email proof from linking flow")
		}
	}
	link := emailLinkCredentials{CredentialsOIDC: credentials}
	if len(credentials.Providers) == 1 && credentials.Providers[0].Provider == proof.Provider && credentials.Providers[0].Subject == proof.Subject {
		link.VerifiedEmail = proof.Email
	}
	data, err := json.Marshal(link)
	return data, errors.Wrap(err, "encode pending OIDC credentials")
}

func matchingAddress(i *identity.Identity, email string, verified bool) *identity.VerifiableAddress {
	for n := range i.VerifiableAddresses {
		a := &i.VerifiableAddresses[n]
		if a.Via == identity.AddressTypeEmail && strings.EqualFold(strings.TrimSpace(a.Value), email) && (!verified || a.Verified) {
			return a
		}
	}
	return nil
}

func (s *Strategy) automaticLinkTarget(ctx context.Context, mapped *identity.Identity, claims *Claims, provider Provider, organization uuid.NullUUID, kind flow.Type) (*identity.Identity, error) {
	email := trustedEmail(claims, provider.Config())
	if provider.Config().AccountLinkingMode != AccountLinkingModeAutomatic || email == "" || matchingAddress(mapped, email, false) == nil {
		return nil, nil
	}
	pool := s.d.PrivilegedIdentityPool()
	a, err := pool.FindVerifiableAddressByValue(ctx, identity.AddressTypeEmail, email)
	if errors.Is(err, sqlcon.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.Wrap(err, "look up verified email address")
	}
	if !a.Verified {
		return nil, nil
	}
	i, err := pool.GetIdentityConfidential(ctx, a.IdentityID)
	if err != nil {
		return nil, errors.Wrap(x.WrapWithIdentityIDError(err, a.IdentityID), "load existing identity")
	}
	if !i.IsActive() || (organization.Valid && i.OrganizationID != organization) ||
		(provider.Config().OrganizationID != "" && (!i.OrganizationID.Valid || i.OrganizationID.UUID.String() != provider.Config().OrganizationID)) {
		return nil, nil
	}
	if kind == flow.TypeAPI {
		// Native MFA starts a fresh flow without pending-link context. Keep its existing manual path.
		candidate := &session.Session{Identity: i, IdentityID: i.ID}
		candidate.CompletedLoginForWithProvider(s.ID(), identity.AuthenticatorAssuranceLevel1, provider.Config().ID, provider.Config().OrganizationID)
		if err := s.d.SessionManager().DoesSessionSatisfy(ctx, candidate, s.d.Config().SessionWhoAmIAAL(ctx)); err != nil {
			if aalErr := new(session.ErrAALNotSatisfied); errors.As(err, &aalErr) {
				return nil, nil
			}
			return nil, errors.Wrap(x.WrapWithIdentityIDError(err, i.ID), "check authentication requirements for SSO linking")
		}
	}
	return i, nil
}

func (s *Strategy) prepareVerifiedLink(ctx context.Context, lf *login.Flow, mapped *identity.Identity, claims *Claims, provider Provider, credentials *identity.Credentials) (ConflictingIdentityVerdict, *identity.Identity, *identity.Credentials, error) {
	i, err := s.automaticLinkTarget(ctx, mapped, claims, provider, lf.OrganizationID, lf.Type)
	if err != nil {
		return ConflictingIdentityVerdictUnknown, nil, nil, errors.Wrap(err, "find identity for verified-email linking")
	}
	if i == nil {
		return ConflictingIdentityVerdictReject, nil, nil, nil
	}
	var config emailLinkCredentials
	if err := json.Unmarshal(credentials.Config, &config); err != nil {
		return ConflictingIdentityVerdictUnknown, nil, nil, errors.Wrap(x.WrapWithIdentityIDError(err, i.ID), "decode OIDC credentials for automatic linking")
	}
	config.VerifiedEmail, config.Automatic = trustedEmail(claims, provider.Config()), true
	data, err := json.Marshal(config)
	if err != nil {
		return ConflictingIdentityVerdictUnknown, nil, nil, errors.Wrap(x.WrapWithIdentityIDError(err, i.ID), "encode pending automatic-link credentials")
	}
	if err := flow.SetDuplicateCredentials(lf, flow.DuplicateCredentialsData{CredentialsType: s.ID(), CredentialsConfig: data, DuplicateIdentifier: config.VerifiedEmail}); err != nil {
		return ConflictingIdentityVerdictUnknown, nil, nil, errors.Wrap(x.WrapWithIdentityIDError(err, i.ID), "attach pending credentials to login flow")
	}
	if err := s.d.LoginFlowPersister().UpdateLoginFlow(ctx, lf); err != nil {
		return ConflictingIdentityVerdictUnknown, nil, nil, errors.Wrap(x.WrapWithIdentityIDError(err, i.ID), "save login flow for automatic linking")
	}
	// The ordinary login executor performs the write only after its required-AAL check.
	return ConflictingIdentityVerdictMerge, i, credentials, nil
}

// Serialize linking on the identity row and reload before appending, rather than writing a stale credential set.
func (s *Strategy) withLockedIdentity(ctx context.Context, i *identity.Identity, update func(context.Context, *identity.Identity) error) error {
	var current *identity.Identity
	err := s.d.TransactionalPersisterProvider().Transaction(ctx, func(ctx context.Context, _ *pop.Connection) error {
		pool := s.d.PrivilegedIdentityPool()
		lock := &identity.Identity{ID: i.ID, UpdatedAt: time.Now().UTC()}
		if err := pool.UpdateIdentityColumns(ctx, lock, "updated_at"); err != nil {
			return errors.Wrap(err, "lock identity for SSO update")
		}
		var err error
		current, err = pool.GetIdentity(ctx, i.ID, identity.ExpandCredentials)
		if err != nil {
			return errors.Wrap(err, "reload identity for SSO update")
		}
		// Hydration must be sequential on a transaction's single database connection.
		for _, field := range identity.ExpandDefault {
			if err := pool.HydrateIdentityAssociations(ctx, current, identity.Expandables{field}); err != nil {
				return errors.Wrapf(err, "load %s for SSO identity update", field)
			}
		}
		if !current.IsActive() {
			return session.ErrIdentityDisabled
		}
		return update(ctx, current)
	})
	if err == nil {
		*i = *current
	}
	return err
}

func (s *Strategy) verifyLinkedAddress(ctx context.Context, i *identity.Identity, email string) error {
	a := matchingAddress(i, email, false)
	if a == nil || a.Verified {
		return nil
	}
	a.Verified, a.Status = true, identity.VerifiableAddressStatusCompleted
	now := sqlxx.NullTime(time.Now().UTC().Round(time.Second))
	a.VerifiedAt = &now
	return errors.Wrap(s.d.PrivilegedIdentityPool().UpdateVerifiableAddress(ctx, a, "verified", "status", "verified_at"), "mark SSO email address verified")
}

func (s *Strategy) recordVerifiedEmail(ctx context.Context, i *identity.Identity, claims *Claims, provider Provider) {
	if provider.Config().AccountLinkingMode != AccountLinkingModeAutomatic {
		return
	}
	email := trustedEmail(claims, provider.Config())
	if email == "" || !i.IsActive() {
		return
	}
	a := matchingAddress(i, email, false)
	if a == nil || a.Verified {
		return
	}
	if err := s.withLockedIdentity(ctx, i, func(ctx context.Context, current *identity.Identity) error {
		return s.verifyLinkedAddress(ctx, current, email)
	}); err != nil {
		s.d.Logger().WithSpanFromContext(ctx).WithError(err).WithField("identity_id", i.ID).Warn("Could not record verified SSO email")
	}
}

func (s *Strategy) persistLinkedCredentials(ctx context.Context, i *identity.Identity, link emailLinkCredentials) error {
	p := link.Providers[0]
	if link.Automatic {
		provider, err := s.Provider(ctx, p.Provider)
		if err != nil {
			return errors.Wrapf(err, "load SSO provider %q for linking", p.Provider)
		}
		if provider.Config().AccountLinkingMode != AccountLinkingModeAutomatic {
			return herodot.ErrForbidden.WithReason("Automatic linking is no longer enabled for this provider")
		}
	}
	linked := false
	err := s.withLockedIdentity(ctx, i, func(ctx context.Context, current *identity.Identity) error {
		if link.Automatic && (link.VerifiedEmail == "" || matchingAddress(current, link.VerifiedEmail, true) == nil ||
			(p.Organization != "" && (!current.OrganizationID.Valid || current.OrganizationID.UUID.String() != p.Organization))) {
			return herodot.ErrForbidden.WithReason("The identity no longer matches the verified SSO email")
		}
		if link.VerifiedEmail != "" {
			if err := s.verifyLinkedAddress(ctx, current, link.VerifiedEmail); err != nil {
				return err
			}
		}
		for _, identifier := range current.Credentials[s.ID()].Identifiers {
			if identifier == identity.OIDCUniqueID(p.Provider, p.Subject) {
				return nil
			}
		}
		if err := s.linkCredentials(ctx, current, p.GetTokens(), p.Provider, p.Subject, p.Organization); err != nil {
			return errors.Wrap(err, "append OIDC credential to identity")
		}
		// Retain the manager's validation/AAL refresh without its parallel reload inside this transaction.
		if err := s.d.IdentityManager().ValidateIdentity(ctx, current, &identity.ManagerOptions{}); err != nil {
			return errors.Wrap(err, "validate identity after adding OIDC credential")
		}
		if err := s.d.PrivilegedIdentityPool().UpdateIdentity(ctx, current); err != nil {
			return errors.Wrap(err, "save linked OIDC credential")
		}
		linked = true
		return nil
	})
	if err == nil && linked {
		s.d.Logger().WithSpanFromContext(ctx).WithField("identity_id", i.ID).WithField("provider", p.Provider).
			WithField("automatic", link.Automatic).Info("Linked an OpenID Connect credential to the existing identity")
	}
	return err
}
