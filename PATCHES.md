# Release patch series

This fork follows released upstream Kratos tags, not upstream master. The current
series is based on `v26.2.0` (`9d7085948039ffb8960160d4979f71527b5cf4d5`).
Historical branches and published tags are retained unchanged.

## Patches

| Patch | Purpose | Regression coverage |
| --- | --- | --- |
| Native nonce compatibility | Preserve the historical direct-ID-token nonce behavior | Direct verifier checks and the upstream login/registration matrix |
| Microsoft native ID tokens | Verify directly submitted tokens against the configured tenant issuer | Signature, issuer, tenant, audience, expiry, and profile checks |
| Generic native ID tokens | Use OIDC discovery to verify directly submitted tokens | Discovery errors, signature, issuer, audience, expiry, and profile checks |
| Request log context | Retain trace/span context on existing flow logs | Hook-error logs with and without a request span |
| Registration hook session | Keep the issued session in the post-registration template context | Existing HTTP/Jsonnet webhook matrix |
| Hydra fixture readiness | Wait for both Docker port bindings before testing authentication | The complete OIDC strategy/settings test suites |
| Verified-email linking | Attach a trusted SSO credential to the existing verified identity | Browser/native flows, verified/unverified password/enterprise/Google/Apple origins, OIDC-to-SAML continuity, MFA boundaries, stale state and concurrent writes |

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

For an automatic-enabled provider, a verified login on an existing subject or a
completed login/registration linking ceremony can mark its matching address
verified using Kratos's native address state. Thus an originally unverified
password registration need not prevent a later trusted OIDC-to-SAML transition.
Settings-page linking is unchanged; a subsequent verified SSO login can record
the address verification. Historical records are not inferred or backfilled.

There are no schema migrations or new public claims. Pending proof exists only
in server-owned flow context, not stored OIDC credential configuration. Reverting
the binary/provider option stops new automatic decisions; completed links remain
ordinary credentials and are not removed by rollback. Do not combine rollout
with unaudited historical verification repair.

## Verification

The database-free image gate is:

```sh
sh test/fork.sh
```

It fails if a required native-token regression disappears, verifies the native
provider contracts, and runs the flow, hook, and session packages. It does not
claim to replace upstream's Docker-backed strategy or database matrix.

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
