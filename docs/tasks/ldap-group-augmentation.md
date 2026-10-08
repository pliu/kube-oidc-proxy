# LDAP group augmentation

With `--ldap-config-file=/etc/kube-oidc-proxy/ldap.json`, OIDC supplies the
username and LDAP supplies group memberships. Token groups are replaced before
impersonation and audit processing. Kubernetes' `system:authenticated` group is
added to the forwarded identity. Token-review/passthrough requests keep their
existing behavior and do not enter LDAP augmentation. Impersonation headers
are rejected while augmentation is enabled.

## Configuration

The JSON configuration is validated against [the embedded schema](../../pkg/proxy/ldap/schema.json).

```json
{
  "backends": [{
    "name": "corp",
    "urls": ["ldaps://ldap.example.net:636"],
    "bindDN": "CN=proxy,OU=Service Accounts,DC=example,DC=net",
    "bindPasswordFile": "/etc/kube-oidc-proxy/ldap-password",
    "caFile": "/etc/kube-oidc-proxy/ldap-ca.pem",
    "userSearchBases": ["OU=Users,DC=example,DC=net"],
    "groupSearchBases": ["OU=Groups,DC=example,DC=net"]
  }],
  "cache": {"namespace": "kube-oidc-proxy", "scope": "main"},
  "refreshInterval": "10m",
  "lookupTimeout": "1m",
  "lookupConcurrency": 8
}
```

| Setting | Default | Meaning |
| --- | --- | --- |
| `backends` | Required | Query every backend and union memberships. |
| `cache.scope` | Required | Label and name scope shared by replicas with identical LDAP/identity settings. |
| `cache.namespace` | Pod namespace | Namespace containing generated user ConfigMaps. Set explicitly outside Kubernetes. |
| `refreshInterval` | `10m` | Interval between leader refresh cycles. |
| `lookupTimeout` | `1m` | Total shared lookup deadline, including Kubernetes reads, LDAP and persistence. |
| `lookupConcurrency` | `8` | Maximum concurrent distinct-user lookups **per replica**, including Kubernetes reads, LDAP and persistence. |
| `refreshUsers` | Any authenticated user | Allowed callers of the currently stubbed refresh endpoint. |

Each backend requires a unique `name`, one or more `urls`, `userSearchBases`, and
`groupSearchBases`. URLs are tried in order. `bindDN` is optional (anonymous bind
otherwise). Use either `bindPassword` or `bindPasswordFile`; trailing newlines
are stripped from the file. Passwords and CA files are loaded at startup.

| Backend setting | Default | Meaning |
| --- | --- | --- |
| `userFilter` | `(objectClass=user)` | Restricts matching user entries. |
| `usernameAttribute` | `userPrincipalName` | Matches the OIDC username after removing its configured prefix, case insensitively. |
| `groupFilter` | `(objectClass=group)` | Restricts membership group entries. |
| `groupNameAttribute` | `cn` | Full emitted group name. |
| `timeout` | `5m` | Backend operation deadline; also bounded by `lookupTimeout`. |
| `startTLS` | `false` | Upgrade an `ldap://` connection to TLS. |
| `caFile` | System roots | PEM certificate bundle. |
| `insecureSkipTLSVerify` | `false` | Disable TLS verification for testing. |

LDAP must expose `memberOf`; Active Directory ranged attributes are followed.
The proxy resolves direct memberships, without recursively expanding nested
groups. Only groups under configured search bases and matching the group filter
are emitted. Group names retain their full spelling and case. Reserved `system:`
groups are dropped. Repeated memberships are deduplicated and sorted.

Two distinct user DNs claiming the same username fail the lookup. Distinct group
DNs emitting the same group name within a backend also fail; targeted name
searches check this even if only one of those groups appears in `memberOf`.
Overlapping search bases returning the same DN are accepted. DN comparison
preserves escaped-comma distinctions while allowing equivalent DN spellings.
One lookup allows at most 1,000 direct group resolutions and 1,000 range follow-up
requests. Exceeding either bound fails the lookup without truncating memberships.

## Persistence and replicas

Each canonical username has one deterministic hashed ConfigMap name derived
from `cache.scope` and the username. Managed objects carry these labels:

```yaml
app.kubernetes.io/managed-by: kube-oidc-proxy
kube-oidc-proxy.jetstack.io/cache-scope: main
```

The `user.yaml` data key contains readable, strictly validated YAML:

```yaml
version: 1
username: alice@example.net
found: true
groups:
  - Developers
  - Platform Administrators
configurationFingerprint: <configuration hash>
lastSuccessfulLookup: "2026-10-08T14:00:00Z"
```

Empty memberships and absent users (`found: false`, `groups: []`) are valid
records. They remain cached indefinitely and eligible for refresh. Search bases,
filters, attribute mappings, backend names/order, and OIDC username prefix
contribute to the configuration fingerprint. Credentials, URLs, TLS settings,
refresh intervals and concurrency settings do not invalidate memberships.
Use separate scopes for deployments with different membership configurations.

Every replica lists managed records at startup and watches from the returned
resource version. Interrupted or expired watches cause a relist. Local writes
use the API response immediately; delayed events cannot regress them. Core
Kubernetes ConfigMap revisions are compared as monotonically increasing decimal
resource versions, and deletions retain revision tombstones in memory.
Readiness requires initial cache synchronization and an accepting proxy listener.
An empty cache is ready and startup never enumerates LDAP users.

Cache hits use only memory. A miss checks Kubernetes first, queries every LDAP
backend if needed, then persists before publishing memberships in memory.
Same-user misses and refreshes share work **within one replica**; independent
users can progress concurrently. Canceling one request does not cancel shared
miss work. Lookup deadlines and shutdown bound that work. Admission is limited
by `lookupConcurrency` before any shared goroutine or external I/O starts. At
capacity, new distinct-user lookups fail immediately (HTTP 503); memory hits and
waiters joining admitted same-user work remain available. Refresh uses the same
limit, and users that cannot be admitted are retried in the next cycle.

Across replicas, lookups may overlap and perform duplicate LDAP queries. There
is no distributed single-flight lock. Create conflicts and resource-version
update preconditions arbitrate writes. Each lookup captures the committed
version **before** LDAP; a conflicting lookup discards its answer and reloads
the winning record, without retrying the stale update. Watches eventually
synchronize all replicas. With `N` replicas and concurrency `C`, up to `N × C`
user LDAP lookups can run cluster-wide; each queries all configured backends.

The elected leader snapshots only cached users each cycle, refreshing with
bounded concurrency and committing each independently. Users added during a
cycle join the next one. The election library cancels a context when leadership
ends; that event directly stops scheduling and waiting for the cycle. Shared in-flight
lookups retain their independent timeout so another waiter is not canceled;
optimistic writes protect overlapping operations during handover.

Successful unchanged checks advance an in-memory timestamp. Membership and
`found` changes are persisted immediately; unchanged timestamps are written at
most once per hour per record. Updates propagate independently for each user
and replica.

| Situation | Behavior |
| --- | --- |
| Any backend or persistence fails on a miss | HTTP 503; no partial or unpersisted entry is published. |
| Refresh fails for one user | Keep prior memberships; report failure; other users continue. |
| All backends successfully report absence | Persist an empty absent record, clearing old memberships. |
| ConfigMap deletion | Remove local memberships; the next request resolves a miss. |
| Malformed/incompatible record | Do not serve it; report it; a miss can repair a managed object. |
| Concurrent write conflict | Discard lookup answer and reload the committed record. |

Existing cache entries remain available during LDAP or Kubernetes outages,
including potentially stale grants until a refresh succeeds. There is no maximum
stale age or eviction policy. A user's ConfigMap must fit Kubernetes object size
limits; an oversized record fails persistence and is never partially served.

## Deployment

ConfigMaps contain readable usernames and memberships. LDAP remains the
authority; these are generated cache records. Restrict write access to the
authorized proxy/controller service account. Readers can see these identities.
The proxy refuses to overwrite unrelated objects at its generated names.

Grant namespaced ConfigMap `get`, `list`, `watch`, `create`, and `update` access.
Deletion permission is unnecessary. [A manifest](../../deploy/yaml/ldap-cache-rbac.yaml)
is provided. Kubernetes RBAC cannot restrict list/watch/create by these labels;
use a dedicated cache namespace for stronger isolation from unrelated objects.
The namespace must exist before starting the proxy.

For Helm, enable `ldap.enabled`, set `ldap.cacheScope` and optionally
`ldap.cacheNamespace`, and supply backend settings under `ldap.config`. The chart
writes `ldap.json`, mounts it, sets the argument, and creates the namespaced
Role/RoleBinding. Mount bind credentials and CA files using `extraVolumes` and
`extraVolumeMounts`. The chart supplies `cache` from its cache settings. See the
[chart values](../../deploy/charts/kube-oidc-proxy/values.yaml).

This is a greenfield deployment. Start with an empty per-user cache, populated
by authenticated traffic. The first request for an uncached user waits for LDAP
and Kubernetes persistence, so both services must be reachable for that request.

The authenticated POST `/kube-oidc-proxy/ldap/refresh` endpoint remains explicitly
stubbed: it returns `{}` after authorization and performs no refresh. Periodic
leader refresh is active and never enumerates directory users.

## Observability and verification

Malformed records, failed refreshes and synchronization errors are logged.
Existing metrics now describe per-user work:

| Metric | Meaning |
| --- | --- |
| `kube_oidc_proxy_ldap_last_refresh_success` | Last cached-user cycle succeeded for all users. |
| `kube_oidc_proxy_ldap_refresh_duration_seconds` | Cached-user cycle duration, including failed cycles. |
| `kube_oidc_proxy_ldap_backend_refresh_duration_seconds{backend}` | Successful single-user lookup duration per backend. |

Unit and race tests cover persistence-before-publication, empty/absent records,
independent users, local coalescing, cross-replica miss/update races with delayed
watches, deletion/reconnection, leadership handover and retained stale entries on
failures. The HTTP integration test authenticates a real JWT, queries two mock
LDAP servers over TCP, persists through the Kubernetes client, and verifies the
forwarded and audited LDAP memberships against the committed YAML record.
