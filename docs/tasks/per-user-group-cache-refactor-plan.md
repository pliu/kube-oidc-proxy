# Per-user LDAP group cache

The per-user cache is implemented. Operational configuration, deployment and
failure behavior are documented in [LDAP group augmentation](ldap-group-augmentation.md).

## Request path

After successful OIDC authentication, canonicalize the username and read its
in-memory record. A hit performs no LDAP or Kubernetes I/O. A miss checks for an
existing ConfigMap before querying every configured LDAP backend. Union only a
complete successful result, persist it, then publish memberships in memory.

Each user has a deterministic ConfigMap name derived from cache scope and
canonical identity. The readable `user.yaml` record contains full group names,
`found`, a configuration fingerprint, and the last successful lookup time.
Empty and absent users are valid cached results and remain eligible for refresh.

Username canonicalization, LDAP DN comparison, search bases and filters,
duplicate-identity rejection, reserved-group filtering, and ranged `memberOf`
attributes are enforced during direct single-user resolution. Memberships are
deduplicated and sorted without changing group names.

## Replicas and concurrency

Each replica serves its own in-memory cache. Startup lists managed ConfigMaps
and watches from the list's resource version. Additions, updates and deletions
are applied idempotently; interrupted watches recover through relisting. Local
write responses can populate memory immediately, and delayed events cannot
regress a newer record. Readiness requires initial synchronization and an
accepting proxy listener. An empty cache is valid.

Misses and refreshes for the same identity share work within a replica.
Independent users can progress concurrently within a per-replica LDAP work
limit. Shared lookups have their own deadline and shutdown context; canceling a
waiter does not cancel work needed by other waiters.

Lookups on different replicas may overlap. Capture the committed record version
before LDAP, create only when absent, and update with that resource version.
Discard conflicting lookup answers and reload the committed record. This
permits duplicate LDAP work while preventing stale overwrites. With `N`
replicas and lookup concurrency `C`, up to `N × C` user lookups can run across
the deployment, each querying all backends.

## Refresh and availability

The elected leader captures the cached usernames at the start of each cycle and
refreshes them with bounded concurrency. Users added during the cycle join the
next one. Each user commits independently, before publication in memory. A
failure retains that user's previous record while other users advance.

Leadership loss stops scheduling and waiting for the cycle. Shared in-flight
work retains its independent deadline; resource-version checks protect writes
during handover. Shutdown cancels shared work. All replicas learn committed
updates through their watches.

Membership and `found` changes persist immediately. Unchanged checks advance
in-memory timestamps; timestamp-only writes occur at most hourly per record.
Users remain cached indefinitely, including empty and absent entries. Existing
entries remain available during backend failures, with potentially stale grants
until refresh succeeds. Cache-miss lookup or persistence failures return HTTP
503. Malformed or incompatible records are not served and can be repaired by
the miss path. Deleting a ConfigMap removes the local entry.

The authenticated manual-refresh endpoint remains a stub that acknowledges
authorized callers without performing refresh work.

## Verification

Unit and race tests cover readable records, empty/absent users, startup without
LDAP queries, cache hits without external I/O, backend unions and failures,
persistence before publication, local coalescing, independent users,
cross-replica conflicts with delayed watches, synchronization and deletion,
watch reconnection, cached-user refresh, and leadership handover. The HTTP
integration test compares committed YAML memberships with the groups forwarded
to Kubernetes and recorded in the audit log.
