# Per-user LDAP group cache refactor plan

## Intended behavior

After a request successfully authenticates through OIDC, the proxy looks up the
authenticated user in its in-memory group cache. A cached user is augmented
immediately using those memberships. For an uncached user, the proxy queries
every configured LDAP backend, unions the memberships, persists the result in a
ConfigMap dedicated to that user, and then caches and augments the request.

Periodic refresh queries only users already in the cache. It never enumerates
all directory users. A membership change must update the user's ConfigMap as
well as the in-memory entry.

Each replica serves requests from its own in-memory map. The ConfigMaps provide
persistence and synchronization between replicas. The elected leader performs
periodic refresh; any serving replica can resolve a cache miss.

## 1. Define readable user records

Implemented: `pkg/proxy/ldap/cache/user.go` defines versioned records, readable
YAML encoding/strict decoding, validation, and deterministic ConfigMap names.
`pkg/proxy/ldap/record.go` applies existing username canonicalization and binds
records to the LDAP search configuration and username prefix. Unit tests cover
round trips, empty/absent users, preservation of full group names, invalid
documents, names, and configuration invalidation.

These types are ready for the later storage and request-path steps. The active
directory-wide snapshot still uses its legacy representation until those steps
replace it; the new per-user format uses no compression or interning.

Use one ConfigMap per normalized user identity within a configured cache scope.
Keep the username, group names, whether LDAP found the user, a configuration
fingerprint, and the last successful LDAP lookup time.

Store full group names directly as a readable YAML document in a ConfigMap data
key. Remove snapshot compression, group-name interning, integer group indices,
and other representations intended to fit the entire directory into one object.
Do not introduce storage-driven group-name normalization or abbreviations.
Preserve LDAP group names as emitted by the configured group-name attribute.

Identity canonicalization, LDAP DN comparison, search-base restrictions, reserved
group filtering, and duplicate-identity validation serve correctness rather
than compression and must be retained. Deduplicate memberships returned by
multiple backends. Stable ordering is useful for readable diffs and avoiding
unnecessary writes; it does not change the group names themselves.

Example persisted record (the name suffix and fingerprint are illustrative):

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: kube-oidc-proxy-user-7d8f2c4a
  namespace: kube-oidc-proxy
  labels:
    app.kubernetes.io/managed-by: kube-oidc-proxy
    kube-oidc-proxy.jetstack.io/cache-scope: main
data:
  user.yaml: |
    version: 1
    username: alice@example.net
    found: true
    groups:
      - Developers
      - Platform Administrators
    configurationFingerprint: example-fingerprint
    lastSuccessfulLookup: "2026-10-08T14:00:00Z"
```

An empty membership list (`groups: []`) is a valid cached result. Persist
`found: false` when every backend successfully reports that the user is absent.
These entries remain eligible for refresh, allowing later LDAP provisioning or
membership changes to be discovered.

Use deterministic hashed object names derived from the cache scope and canonical
user identity. Verify the stored identity when loading an object. Define which
configuration changes invalidate a record so memberships from different LDAP
search settings or identity mappings cannot silently be reused.

## 2. Decouple single-user LDAP lookup from directory sweeps

Reuse the multi-backend single-user lookup in `pkg/proxy/ldap/search.go`, but
remove its requirement for a group index populated by a full directory rebuild.
Resolve the user's `memberOf` DNs directly against LDAP as needed, including
ranged attributes where supported by the existing implementation.

Preserve group search-base and filter restrictions, username matching, duplicate
identity checks, and rejection of reserved `system:` groups. Revisit the existing
group-discovery limit: its current recovery advice to rebuild the entire mapping
will no longer apply. Bound lookup work without truncating memberships silently.

Query every backend and merge only a complete successful result. A backend error
must not become an empty membership contribution. Support request cancellation
and bounded lookup duration.

## 3. Introduce per-user ConfigMap persistence

Replace the opaque snapshot `Load`/`Save` interface with typed per-user get, list,
and upsert operations and a watch synchronization path. Validate the readable YAML
records when decoding them.

Persist a new or changed membership record before publishing it in memory.
Avoid writes when memberships and relevant record state are unchanged. Keep the
last successful lookup time in memory on every successful check; decide whether
to persist unchanged-record timestamps at a bounded interval so timestamp-only
changes do not force a write for every user on every refresh.

Use Kubernetes resource-version preconditions for updates and handle create
conflicts. Capture the expected record version before starting an LDAP query;
an older query must not simply retry its stale result over a newer record.
On a conflict, discard the lookup result and reload the committed record, or
perform a fresh lookup against the new version if necessary.

## 4. Restore and synchronize the in-memory map

List managed ConfigMaps at startup and establish a watch without a gap between
the initial list and subsequent events. Apply additions, updates, and deletions
to the in-memory map. Recover from interrupted watches and expired versions
through relisting.

Coordinate watch events with local writes so delayed events cannot regress a
locally committed record. A successful local write can populate memory directly
using the returned object; watch delivery must be idempotent.

Readiness requires initial cache synchronization and an accepting proxy listener.
An empty cache is valid. Remove the initial LDAP directory sweep and the readiness
requirement that a directory-wide mapping already exists.

## 5. Resolve cache misses during authenticated requests

Replace the current synchronous `Groups()` lookup with a context-aware operation
that returns memberships or an error. Call it after OIDC authentication and before
impersonation and auditing of the effective identity.

For a cache hit, use memory without a Kubernetes or LDAP request. For a miss,
check for an already-persisted user record before querying LDAP, since another
replica may have populated it before the local watch caught up. If still absent,
query all LDAP backends, persist the result, update memory, and augment the request.

Coalesce concurrent misses for the same user within a replica. Use per-user
serialization for misses and refreshes, plus a global concurrency bound for LDAP
work. Different users must not wait behind a single directory-wide update lock.
One canceled waiter must not incorrectly cancel shared work needed by others.

Keep existing token-review/passthrough behavior explicit; the new miss path applies
to identities authenticated for OIDC group augmentation.

## 6. Refresh only cached users

The elected leader snapshots the set of cached users at the start of each refresh
cycle and resolves them with bounded concurrency. Users added during a cycle are
already populated by the miss path and become eligible for the next cycle.

Commit each user independently, writing changed memberships to their ConfigMap
before updating memory. A failure for one user retains that user's old entry and
does not prevent other users from advancing. All replicas learn updates through
their ConfigMap watches.

Coordinate leadership changes, shutdown, and in-flight lookups. Leader election
alone does not prevent overlapping writes during handover; per-record optimistic
concurrency must still protect against stale results.

## 7. Define failures and lifecycle behavior

| Situation | Behavior |
| --- | --- |
| Any LDAP backend fails on a cache miss | Return a service error; do not cache a partial result. |
| ConfigMap persistence fails on a miss | Return a service error; do not publish an unpersisted entry. |
| LDAP or persistence fails during refresh | Keep the user's previous memberships and report the failure. |
| Every backend successfully reports the user absent | Persist an empty entry and clear previous memberships. |
| A ConfigMap is deleted | Remove the local entry; the next authenticated request resolves a miss. |
| An existing record is malformed or incompatible | Do not serve its memberships; expose the problem and resolve through the miss path when possible. |
| Concurrent writes conflict | Discard the conflicting lookup result and reload the committed record. |

Retain cached users indefinitely for the first version, including absent users and
users with no groups. Eviction and maximum stale age are separate policy changes.
Serving existing entries during backend failures preserves the current availability
policy, including the possibility of stale grants until a refresh succeeds.

Updates across users and propagation across replicas are eventually consistent;
there is no directory-wide atomic snapshot. The first uncached request waits for
LDAP and Kubernetes persistence.

## 8. Configuration, deployment, and migration

Update LDAP configuration/schema for the ConfigMap namespace, cache scope, refresh
interval, and lookup concurrency/timeouts. Remove obsolete whole-snapshot cache
settings and associated compression/fingerprint polling code where unused.

Update Helm, manifests, and documentation with scoped ConfigMap permissions for
get/list/watch/create/update and any deletion behavior actually implemented.
Keep managed records separate from unrelated ConfigMaps by labels and cache scope.

Document that ConfigMaps contain readable usernames and memberships and must be
writable only by the authorized proxy/controller identity. They are generated
cache records; LDAP remains the authority.

Choose and document the legacy snapshot migration policy before rollout. The
default proposal is to start with an empty per-user cache and populate it on
authenticated traffic; provide an explicit migration tool only if existing
memberships must remain available through an LDAP outage during deployment.

Reconcile the stubbed manual refresh endpoint with the new model: either keep it
explicitly stubbed or implement it through the same per-user refresh machinery.
It must never reintroduce full-directory user enumeration.

## 9. Verification and implementation sequence

Implement and review in this order:

1. Typed user records, readable YAML encoding, and ConfigMap storage operations.
2. Standalone single-user LDAP resolution without an initial directory sweep.
3. In-memory cache, startup restore, watch synchronization, and concurrency rules.
4. Authentication-path cache misses and persistence-before-publication behavior.
5. Leader-only periodic refresh of cached users and revised readiness.
6. Deployment/schema updates, migration documentation, and obsolete code removal.

Meaningful tests should cover readable round trips; empty and absent users; cold
startup without LDAP enumeration; cache hits performing no external I/O; lookup
across all backends; group additions and removals; backend/persistence failures;
same-user request coalescing; independent-user concurrency; write conflicts;
watch reconnection/deletion and stale-event handling; replica synchronization;
leadership handover; and refresh restricted to cached users. Include a proxy
integration test proving that the effective request and audit memberships match
the successfully persisted record.
