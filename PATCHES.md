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

## Verification

The database-free image gate is:

```sh
sh test/fork.sh
```

It fails if a required native-token regression disappears, verifies the native
provider contracts, and runs the flow, hook, and session packages. It does not
claim to replace upstream's Docker-backed strategy or database matrix.

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
