# Release patch series

This fork follows released upstream Kratos tags, not upstream master. The current
series is based on `v26.2.0` (`9d7085948039ffb8960160d4979f71527b5cf4d5`).
Historical branches and published tags are retained unchanged.

GitHub Actions are disabled for this fork. Release verification runs through
native Linux image builds and the existing fork regression gate; the inherited
tag-triggered workflows are retained as upstream reference. Do not weaken the
JSONnet sandbox to accommodate an emulated build host.

## Patches

The October 21 trust-store rebuild pins Go 1.26.10 and the existing distroless
Debian 12 runtime by digest. It copies the builder's updated CA bundle into the
runtime, removing the affected roots independently of Go's eMudhra intermediate
blocklist. Application code and dependencies are unchanged by this packaging
commit. Keep it separate when rebasing and remove it when upstream provides
equivalent build inputs and trust-store handling.

| Patch | Purpose | Regression coverage |
| --- | --- | --- |
| Native nonce compatibility | Preserve the historical direct-ID-token nonce behavior | Direct verifier checks and the upstream login/registration matrix |
| Microsoft native ID tokens | Verify directly submitted tokens against the configured tenant issuer | Signature, issuer, tenant, audience, expiry, and profile checks |
| Generic native ID tokens | Use OIDC discovery to verify directly submitted tokens | Discovery errors, signature, issuer, audience, expiry, and profile checks |
| Request log context | Retain trace/span context on existing flow logs | Hook-error logs with and without a request span |
| Registration hook session | Keep the issued session in the post-registration template context | Existing HTTP/Jsonnet webhook matrix |
| Hydra fixture readiness | Wait for both Docker port bindings before testing authentication | The complete OIDC strategy/settings test suites |
| Verified upstream hook context | Expose request-scoped verified OIDC provider/claims to existing webhook templates | Carrier snapshot, Jsonnet object/absence, browser/native and conversion cases |
| Verified-email linking | Enforce email ownership across automatic, password-confirmed and settings linking | Browser/native flows, provider trust, recovery, OIDC-to-SAML continuity, MFA boundaries, stale state and concurrent writes |

The optional `upstream_claims` template field contains the actual strategy method,
provider ID and its verified claims, including `raw_claims`; it is not caller traits or
transient payload. It is attached only at OIDC login/registration post-hook calls,
snapshotted in request context and never added to persisted flow/session/identity
metadata. Existing templates stay unchanged. Later password-link and settings
requests have no inherited context. Templates must select what their receiver
needs; receiver authorization, payload limits and safe logging remain deployment
responsibilities. No provider-specific policy, tokens, migration or hint change
is introduced.
Native direct-token login reaches its hook before the existing strategy assigns
`flow.active`, so consumers use the verified context's method rather than infer it
from that optional flow field. The existing flow/hook-selection behavior is unchanged.

The old custom request-header allowlist patch is unnecessary: upstream now
supports `clients.web_hook.header_allowlist`. Configure the required headers in
the deployment instead of adding application-specific names to this fork.
Upstream also replaced the old login/registration organization-UUID warnings
with a shared parser that records a span error. Those obsolete log sites are
not reintroduced.

The nonce compatibility patch is an explicit security exception, not a general
recommendation: direct ID tokens do not require a nonce or equality with the
submitted nonce. Signature, issuer, audience, expiry, and required-claim checks
still apply. Changing this behavior requires a separately reviewed client
migration; it must not happen incidentally during an upstream rebase.

## Verified-email linking

This fork implements the existing provider option `account_linking_mode:
automatic`. The default remains `confirm_with_existing_credential`. Automatic
linking requires a validated `email_verified: true` claim for the exact mapped
email and one active identity with that address already verified, within the
configured organization/network scope. Google must additionally be authoritative
for the address (Gmail or Workspace); missing or false evidence uses ordinary
linking. A broker must establish its own per-connection email authority before
emitting true. A mapper's default or an email-shaped subject is not proof.

The original identity ID, traits, password, metadata and existing credentials are
retained. Different subjects under the same provider can coexist, allowing an
OIDC-to-SAML transition through a broker. An already-owned subject never moves
because its email changed. Linking reuses the existing login executor and writes
only after its required-AAL check, inside an identity-row transaction that reloads
current credentials and rechecks eligibility. Existing database uniqueness also
rejects a subject owned by another identity.
Unexpected failures retain their causes and add plain operation context through
the existing error wrappers; known target IDs use the native identity-error carrier.

Browser MFA uses the existing flow-context continuation. Native accounts requiring
MFA retain the ordinary manual linking path: this patch does not extend the
native API's separate MFA flow to carry pending credentials. Both native login
and registration entry points cover that boundary. Existing-subject logins,
session policies and the upstream custom conflict-policy extension are retained.

Authenticated linking uses the existing account as its target. Every unverified
email address on that account must match the incoming provider's trusted verified
email; otherwise linking returns "Please verify your email before linking another
sign-in method." An authenticated account whose emails are already verified may
attach a provider identity with a different or unverified email. That incoming
email does not become an account trait or gain verified status through the link.

| Existing email | Incoming email proof | Sign-in without an existing-account session | Authenticated settings |
| --- | --- | --- | --- |
| Verified | Trusted, same email | Automatic when enabled | Link |
| Verified | Untrusted, same email | Authenticate with the existing account first | Link |
| Verified | Different email | No automatic association to this account | Link |
| Unverified | Trusted, same email | Authenticate with the existing account, then link and verify | Link and verify |
| Unverified | Untrusted or different email | Verify the account email first | Verify the account email first |

Settings retains its normal session-recency and flow-binding checks. A successful
matching trusted link verifies the address in the same identity update; a failed
link does not record a new session authentication method. Manual linking rechecks
email ownership inside the existing identity transaction. Proof is carried for
both provider linking modes, and trusted logins on already-linked subjects can
record matching email verification in either mode. The provider's mode controls
automatic account selection, not whether its accepted proof can verify an email.
An originally unverified password registration can therefore progress through
password-confirmed linking to a later automatic OIDC-to-SAML transition.

Ordinary sign-in does not attach unrelated emails to an incidental browser
session. Applications use the existing account-bound settings flow when adding a
provider to an authenticated account. No new verification continuation, identity
merge, enterprise bypass or historical credential cleanup is introduced.

There are no schema migrations or new public claims. Pending proof exists only
in server-owned flow context, not stored OIDC credential configuration. Reverting
the binary/provider option stops new automatic decisions; completed links remain
ordinary credentials and are not removed by rollback. Do not combine rollout
with unaudited historical verification repair.

## Recovery of unverified addresses

When the `code` recovery strategy proves a currently unverified address, retire
the identity's existing credentials, including second factors, and sessions in the same transaction that
verifies the address. The newly issued recovery session can set a replacement
password. Identity IDs, traits, metadata and addresses remain; schema-derived
identifier placeholders reserve the account without retaining a usable password.

Already-verified addresses and administrator-issued recovery codes retain their
credentials. Disabled identities are rejected before retirement. An abandoned
reset does not restore the retired credentials: after the recovery session's
privileged interval expires, the owner must recover again. Existing verification
history is not a substitute for the recovered address's current state.

Settings writes recheck their authorizing session while holding the identity
row lock. A request prepared before retirement cannot restore a stale password
or provider list afterward. This check also respects session expiration.
Password-confirmed linking similarly rechecks the persisted credential row IDs
under that lock. Legitimate password-hash migration refreshes the proof's row
IDs so it does not cause a false refusal.
Login finalization is a separate follow-up; this increment does not change the
final session-issuance step or the legacy `link` recovery strategy.

The local recovery regressions exercise browser/native requests, unrelated
verified addresses, credential/session preservation, immediate password denial,
replacement passwords, transaction rollback and a paused settings request.
`TestRecoveryRetiresOIDC` uses the existing Docker/Hydra fixture for signed
provider registration, recovery, fresh login and legitimate relinking.
`TestRecoveryRetirementPostgres` repeats the paused-write regression with
`KRATOS_RECOVERY_TEST_DSN`, restricted to a disposable loopback PostgreSQL
database named `kratos_recovery_test`.

## Verification

The database-free image gate is:

```sh
sh test/fork.sh
```

It fails if a required native-token regression disappears, verifies the native
provider contracts, requires the recovery-retirement regressions, and runs the
flow, settings, hook, and session packages. It does not
claim to replace upstream's Docker-backed strategy or database matrix.

The existing Docker-backed OIDC suite includes `TestSettingsVerifiedEmailOwnership`
and `TestSettingsVerifiedEmailRecovery`. They use the shared Hydra fixture for
signed provider callbacks, cover the verification/matching/provider-mode matrix,
and prove that a refused link cannot survive email-code recovery and password
replacement. They also cover a target changing while the callback is pending and
a provider credential claimed by another identity. Run it with:

```sh
go test -p 2 -parallel 1 -tags sqlite -count=1 ./selfservice/strategy/oidc -timeout 10m
```

`TestVerifiedEmailConcurrentPostgres` additionally accepts `KRATOS_LINK_TEST_DSN`
for a disposable PostgreSQL database named `kratos_link_test` on loopback only.
It migrates that fixture database and proves concurrent/repeated linking retains
every subject and the original password/traits. Never use a real database or a
port-forward to one; this is an isolated fixture, not a repair command.

For broader release acceptance with Docker available:

```sh
go test -p 2 -parallel 1 -tags sqlite -count=1 -short ./...
```

Use the repository's CI for the external-database matrix and browser suites.
Never point destructive test fixtures at a real application database.

## Maintaining the series

Keep one commit per discrete compatibility feature, with its regression tests.
Fold development fixups into the owning patch before publishing the next
release. Record the old-to-new `git range-diff` in the release review and drop
patches when upstream supplies equivalent behavior.

Use `release/v<upstream-version>-custom.<revision>` branches and signed
`v<upstream-version>-custom.<revision>` source tags. Published source/image tags
must never move; a correction gets a new revision. Build and promote the exact
verified image digest. The public fork and its Dockerfile remain independent
of any particular deployment environment.

## Database upgrade gate

Upstream migration files are unchanged. Before upgrading, restore a private
database snapshot locally and rehearse migration, data preservation, existing
session continuity, and old/new binary compatibility. A successful migration
does not imply that old writers remain compatible with the new schema.

Do not assume an image-only rollback is safe. Establish the migration boundary
and recovery procedure before rollout, including what newer-version writes a
reverse migration would discard. Keep snapshots, credentials, identity data,
and internal acceptance evidence out of this public repository.
