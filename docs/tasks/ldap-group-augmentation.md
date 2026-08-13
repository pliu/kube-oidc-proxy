# LDAP Group Augmentation

By default, kube-oidc-proxy takes both the user name and the groups of a request
from the JWT presented by the user. Some identity providers issue tokens that do
not carry group claims at all, or carry a truncated set of them (Azure AD, for
example, replaces the `groups` claim with a link once a user is a member of more
than a few groups).

kube-oidc-proxy can instead pull the groups from one or more LDAP v3 directories
- Active Directory, or OpenLDAP with the `memberof` overlay, or anything else
that exposes a `memberOf` attribute. When enabled, the user name of a request is
still taken from the JWT, but the groups are taken from the directories.

## How it works

The full user to group mapping is built up front and held in memory. For each
configured backend:

1. Every group under its group search base(s) is read. Only these groups are
   ever mapped onto a user - a user's membership of a group outside of these
   bases is ignored.
2. Every user under its user search base(s) is read, along with their `memberOf`
   attribute, which is filtered down to the groups found above.

The mappings of every backend are then merged into one: a user held in more than
one directory ends up with the union of their groups.

The mapping is rebuilt on an interval (10 minutes by default) and swapped in
atomically, so a request always reads a complete, consistent mapping. If a
rebuild fails, the previous mapping is kept in place and serving continues.

A backend that cannot be searched fails the whole rebuild. Merging only what the
reachable backends returned would quietly drop the groups a user holds in the
unreachable one, which is worse than serving a mapping that is one refresh
interval out of date.

The same applies to a backend that stops answering part way through. Each
backend has a `timeout`, five minutes by default, covering everything it does in
one rebuild - connecting, binding and every search. A directory that accepts a
connection and then goes quiet is otherwise indistinguishable from one that is
merely slow, and would hold the rebuild open for as long as the proxy runs;
instead the connection is closed and the rebuild fails, leaving the previous
mapping serving and the persisted copy of it untouched. Searches also carry the
timeout as their server side time limit, so a directory that is still listening
gives up and answers for itself rather than being cut off.

The same applies to a backend that is still answering but has stopped returning
anything. A search that finds nothing is not an error, so a bind account that
loses its read on the user OU, or a search base renamed out from under the
configuration, would otherwise look like a directory in which nobody is a member
of anything. A backend that returns no users, or no groups, having returned some
at the previous rebuild fails the rebuild instead, and the previous mapping keeps
serving:

```
failed to refresh LDAP mapping, keeping previous mapping: backend "corp": returned no users, having returned 1401 at the last refresh
```

Only a fall to nothing is caught, not a directory that merely shrinks - any
threshold short of that would be a guess at how much churn is normal. A backend
that has never returned anything is accepted, since a directory that is empty on
the very first build is a configuration to fix rather than a mapping to protect.
A directory that really has been emptied is accepted again once the proxy is
restarted and its [persisted mapping](#persisting-the-mapping), if any, removed.

Two entries of one directory that claim the same username also fail the rebuild.
Which of them a request should be authorized as is genuinely ambiguous, and
taking whichever the directory returned last would make a user's groups depend
on search order. One entry returned more than once because the search bases
overlap is not ambiguous and is accepted. A username held in *different*
backends is not ambiguous either - that is the merge described above, and those
groups are unioned.

The initial build happens before the proxy starts serving, so that requests are
never authorized against an empty mapping. If it fails and there is no
[persisted mapping](#persisting-the-mapping) to fall back on, the proxy exits.

## Configuration

Augmentation is configured by a JSON file rather than by flags, since it
describes a list of backends. Point the proxy at one with a single flag:

```
--ldap-config-file=/etc/kube-oidc-proxy/ldap.json
```

Setting the flag is what enables augmentation. The file is checked against a
[JSON schema](../../pkg/proxy/ldap/schema.json) at startup, and the proxy refuses
to start if it does not match - a misspelled property is an error rather than a
silently ignored line.

A minimal configuration:

```json
{
  "backends": [
    {
      "name": "corp",
      "urls": ["ldaps://ldap.example.net:636"],
      "bindDN": "CN=kube-oidc-proxy,OU=Service Accounts,DC=example,DC=net",
      "bindPasswordFile": "/etc/kube-oidc-proxy/ldap-password",
      "userSearchBases": ["OU=Users,DC=example,DC=net"],
      "groupSearchBases": ["OU=Groups,DC=example,DC=net"]
    }
  ],
  "cache": {
    "type": "kubernetesSecret",
    "kubernetesSecret": {"name": "kube-oidc-proxy-ldap-mapping"}
  }
}
```

And one using every field, two directories and a persisted mapping:

```json
{
  "backends": [
    {
      "name": "corp",
      "urls": ["ldaps://ldap-1.example.net:636", "ldaps://ldap-2.example.net:636"],
      "bindDN": "CN=kube-oidc-proxy,OU=Service Accounts,DC=example,DC=net",
      "bindPasswordFile": "/etc/kube-oidc-proxy/ldap-password",
      "caFile": "/etc/kube-oidc-proxy/ldap-ca.pem",
      "userSearchBases": ["OU=Users,DC=example,DC=net"],
      "userFilter": "(objectClass=user)",
      "usernameAttribute": "userPrincipalName",
      "groupSearchBases": ["OU=Groups,DC=example,DC=net"],
      "groupFilter": "(objectClass=group)",
      "groupNameAttribute": "cn",
      "groupPrefix": "corp:"
    },
    {
      "name": "partners",
      "urls": ["ldap://partners.example.net:389"],
      "startTLS": true,
      "timeout": "2m",
      "bindDN": "CN=kube-oidc-proxy,OU=Service Accounts,DC=partners,DC=net",
      "bindPasswordFile": "/etc/kube-oidc-proxy/partners-password",
      "userSearchBases": ["OU=Users,DC=partners,DC=net"],
      "groupSearchBases": ["OU=Groups,DC=partners,DC=net"],
      "groupPrefix": "partners:"
    }
  ],
  "refreshInterval": "10m",
  "fallbackToTokenGroups": false,
  "refreshUsers": ["alice@example.net", "bob@example.net"],
  "cache": {
    "type": "kubernetesSecret",
    "maxAge": "24h",
    "kubernetesSecret": {
      "name": "kube-oidc-proxy-ldap-mapping"
    }
  }
}
```

### Top level fields

| Field | Default | Description |
| ----- | ------- | ----------- |
| `backends` | | The directories to build the mapping from. At least one is required. |
| `refreshInterval` | `10m` | How often the mapping is rebuilt. A Go duration string. |
| `fallbackToTokenGroups` | `false` | Fall back to the groups of the JWT for users found in no directory. |
| `refreshUsers` | | Users allowed to trigger a refresh. If unset, any authenticated user may. |
| `cache` | | **Required.** Where the built mapping is persisted. See [below](#persisting-the-mapping). |

### Backend fields

| Field | Default | Description |
| ----- | ------- | ----------- |
| `name` | | Name of the backend, used in logs, statistics and errors. Must be unique. |
| `urls` | | URL(s) of the directory. Tried in order until one can be connected to and bound. |
| `bindDN` | | DN to bind as. If unset, an anonymous bind is used. |
| `bindPassword` | | Password to bind with. Prefer `bindPasswordFile`. |
| `bindPasswordFile` | | File holding the password to bind with. Mutually exclusive with `bindPassword`. |
| `caFile` | | PEM bundle used to verify the directory's serving certificate. Defaults to the host trust store. |
| `insecureSkipTLSVerify` | `false` | Do not verify the directory's serving certificate. |
| `startTLS` | `false` | Issue a StartTLS request after connecting. Used with an `ldap://` URL. |
| `timeout` | `5m` | How long this directory has to connect, bind and be searched before the rebuild is failed. |
| `userSearchBases` | | Base DN(s) to search for users under. |
| `userFilter` | `(objectClass=user)` | LDAP filter selecting user entries. |
| `usernameAttribute` | `userPrincipalName` | Attribute holding the name that matches the user name of the JWT. |
| `groupSearchBases` | | Base DN(s) to search for groups under. |
| `groupFilter` | `(objectClass=group)` | LDAP filter selecting group entries. |
| `groupNameAttribute` | `cn` | Attribute of a group entry to use as the group name. |
| `groupPrefix` | | Prefix prepended to every group name from this directory. |

Group augmentation relies on impersonation, so it cannot be combined with
`--disable-impersonation`.

### Client set impersonation

While augmentation is enabled the proxy decides the identity a request is
impersonated as, so a request that carries `Impersonate-` headers of its own is
refused with a `403` and this message:

```
impersonation headers are not accepted while group augmentation is enabled
```

The two cannot both be honoured. An impersonated identity is built out of the
headers alone, so `Impersonate-Group` would let the caller choose the groups the
request runs with - exactly what taking groups from the directory is there to
prevent. `Impersonate-User` on its own is no better: the target would run as a
member of no groups at all, rather than of the groups the directory holds for
them.

The request is refused rather than served with the headers dropped, because a
caller that asked to act as somebody else and is quietly served as themselves
has been told the wrong thing about who did the work.

This is decided before the `SubjectAccessReview`, so RBAC granting `impersonate`
does not change the outcome, and the API server is not consulted.

`--token-passthrough` is unaffected: a request that authenticates that way is
forwarded with its own credentials and is never impersonated by the proxy, so
its groups do not come from the directory either. The API server authenticates
it directly and applies its own impersonation rules.

### Matching users

The user name of a request is matched against `usernameAttribute` case
insensitively. If `--oidc-username-prefix` is set, the prefix is stripped from
the user name before matching, so the directory can be keyed on the bare
attribute value.

A user that cannot be found in any directory is given no groups, and so will be
able to do only what `system:authenticated` allows. Set
`fallbackToTokenGroups` to have such a user keep the groups of their JWT
instead.

### Group names

`--oidc-groups-prefix` is *not* applied to groups pulled from a directory, as
those groups did not come from the OIDC issuer. Use `groupPrefix` if the group
names need a prefix to match your RBAC bindings, or to keep two directories that
name their groups the same way apart.

### Large directories

Attribute names are matched case insensitively, and ignoring any options the
directory attached, rather than compared to the name that was asked for. A
directory is free to answer with the attribute descriptions of its own schema -
389 Directory Server, which FreeIPA is built on, does - and comparing exactly
would find nothing and quietly give the user no groups.

Active Directory caps a multi valued attribute at `MaxValRange`, 1500 values by
default, and answers a longer `memberOf` with a window of it under a different
attribute description. The proxy collects the rest a window at a time, so a user
in more than 1500 groups costs one extra search per additional window. Nothing
needs configuring for this; on a directory that returns every value, such as 389
Directory Server, the extra searches never happen.

Server side limits on the *number of entries* a search may return are a
different matter and are not worked around. Paging keeps each page within
`MaxPageSize` on Active Directory, but a limit on the search as a whole -
`nsslapd-sizelimit` and `nsslapd-lookthroughlimit` on 389 Directory Server,
which default low enough to matter on a real directory - applies to the bind
account and will stop the search. That surfaces as a failed rebuild rather than
a short mapping, so it is visible rather than silent, but it does mean the
proxy's bind account wants limits that accommodate the whole user and group
tree.

## Persisting the mapping

`cache` is required, and has to be stated even when the answer is "nowhere":
`{"type": "none"}` turns persistence off. It is mandatory because leaving it out
gets the worst behaviour by default, and nobody picks that on purpose.

With persistence off, a proxy that restarts has to rebuild the mapping from the
directories before it can serve anything, and exits if it cannot reach them. A
directory outage that coincides with a restart - a rollout, a drain, an
eviction, an OOM kill - then takes the proxy down with it, and keeps it down
until a directory answers. The proxy logs a warning at startup when it is
running this way.

Note that the mapping is a dump of every user and the groups they hold, so
persisting it to a Secret makes that readable by anyone who can read Secrets in
that namespace. That is a real reason to choose `none`, or to choose a `file` on
a volume with tighter access than the namespace has - but it should be a choice.

With a store configured, a rebuilt mapping is written to it *before* it
starts being served, and a mapping that cannot be written is not served at all -
the rebuild fails and the previous mapping, which is the one the store holds,
carries on serving.

The order matters more than it looks. Serving first and persisting after lets a
restart go backwards in time: a proxy that served a new mapping, failed to
persist it, and then died would come back up, find the older mapping in the
store and serve that - and if the directories happen to be unreachable by then,
it has no way of getting forwards again. Writing first means the store is never
behind what is being served, so the worst a restart can do is replay a mapping
that is at least as new as the one that was lost.

At startup the persisted mapping is loaded first, and the proxy then tries to
refresh from the directories:

* If the refresh succeeds, the fresh mapping replaces the persisted one. The
  persisted mapping is never served in preference to a reachable directory.
* If the refresh fails, the persisted mapping is served and the proxy carries on
  starting, logging the failure. Refreshes continue on the usual interval, so it
  recovers on its own once the directories come back.

What each backend contributed is recorded alongside the mapping, so the check on
a backend that has [stopped returning anything](#how-it-works) survives the
restart rather than starting again from nothing. A proxy that comes back up
while a directory has quietly stopped answering serves the persisted mapping and
logs the failure, instead of accepting the degraded one and persisting it over
the good one.

A persisted mapping is discarded, rather than served, if it was built by a proxy
that writes a different format, if it was built from a different set of search
bases, filters or prefixes, or if it is older than `maxAge`. Rotating a bind
password or changing a URL does not discard it.

| Field | Default | Description |
| ----- | ------- | ----------- |
| `type` | | **Required.** One of `none`, `file` or `kubernetesSecret`. |
| `maxAge` | | How old a persisted mapping may be and still be served. If unset, it is served however old it is. |
| `file.path` | | Where to write the mapping. Required when `type` is `file`. |
| `kubernetesSecret.name` | | Name of the Secret to write. Required when `type` is `kubernetesSecret`. |
| `kubernetesSecret.namespace` | The proxy's own namespace | Namespace of that Secret. |
| `kubernetesSecret.key` | `mapping.json.gz` | Key within that Secret. |

### `file`

```json
"cache": {"type": "file", "file": {"path": "/var/lib/kube-oidc-proxy/ldap-mapping.json"}}
```

The file is written atomically, with mode `0600`, and its parent directory is
created if needed. The path should be in a volume that outlives the container -
a path in the container's writable layer is lost on exactly the restart the
cache exists for.

### `kubernetesSecret`

```json
"cache": {"type": "kubernetesSecret", "kubernetesSecret": {"name": "kube-oidc-proxy-ldap-mapping"}}
```

The Secret is created if it does not exist, and only the configured key is
written, so a Secret shared with something else is left otherwise intact. The
payload is gzipped, since the API server caps a Secret at 1MiB; a mapping too
large to fit even compressed is refused with an error rather than a failed
write, and should be persisted to a file instead.

The namespace defaults to the one the proxy is running in, taken from
`$POD_NAMESPACE` if set, and from the service account namespace file otherwise.

This needs RBAC beyond what the proxy otherwise uses, scoped to the one Secret:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: kube-oidc-proxy-ldap-mapping
  namespace: kube-oidc-proxy
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["create"]
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["kube-oidc-proxy-ldap-mapping"]
  verbs: ["get", "update"]
```

Note that the mapping names every user of the cluster and the groups they hold.
Anything that can read the Secret can read that.

## Metrics

Both failures above are quiet by design: the previous mapping keeps serving, so
no request fails and nothing tells you that group changes have stopped being
picked up. Two gauges are published for alerting on that, in Prometheus format
at `/metrics` on the readiness probe listener - `--readiness-probe-port`, 8080
by default, beside `/ready` and `/live`. That listener is plain HTTP with no
authentication, so the metrics are readable by anything that can reach the pod
on that port. They carry no request or user data; the only label value is the
name of a configured backend.

| Metric | Type | Description |
| ------ | ---- | ----------- |
| `kube_oidc_proxy_ldap_last_refresh_success` | gauge | `1` if the last rebuild of the mapping succeeded, `0` if it failed. |
| `kube_oidc_proxy_ldap_backend_duplicate_users{backend}` | gauge | `1` if two entries of this backend claim one username, which fails the rebuild. |
| `kube_oidc_proxy_ldap_refresh_duration_seconds` | histogram | How long a complete rebuild took, across every backend. |
| `kube_oidc_proxy_ldap_backend_refresh_duration_seconds{backend}` | histogram | How long searching one backend took, so that one slow directory can be told from a rebuild that is slow all over. |

The proxy also publishes `kube_oidc_proxy_requests_total`, a counter of every
request it is handed. It is counted before authentication, so requests being
turned away reads as requests arriving rather than as silence. It is not broken
down by status code: that would mean putting a wrapper around the
`ResponseWriter` of every request, including the ones hijacked for `exec` and
`port-forward`, which is not worth it for a count.

The two histograms record only rebuilds that *succeeded*. How long a failed one
took is mostly how long it took to give up - a connection timing out, say -
which would drag the distribution somewhere that says nothing about how long the
work takes. Their buckets run from 100ms to a little over three minutes, since
rebuilding reads every user and every group of a directory.

`refresh_duration_seconds` and `last_refresh_success` both cover
[persisting](#persisting-the-mapping) the mapping as well as building it, since
a rebuild is not finished until what it built is safe to serve. A store that
cannot be written to therefore shows up as a failed refresh, not as a slow one.

None of the `_ldap_` series exist unless `--ldap-config-file` is set, so a proxy
running without augmentation does not report a permanent zero for a rebuild it
is never going to do. `backend_duplicate_users` is published as `0` for every
configured backend from startup, so an alert can tell "no duplicates" from a
backend that has not been searched yet.

An unreachable directory leaves `backend_duplicate_users` where it was rather
than clearing it, since a search that did not run says nothing about what the
directory holds. Alert on `last_refresh_success` for that instead:

```
kube_oidc_proxy_ldap_last_refresh_success == 0
kube_oidc_proxy_ldap_backend_duplicate_users > 0
histogram_quantile(0.9, rate(kube_oidc_proxy_ldap_backend_refresh_duration_seconds_bucket[1h])) > 60
```

The first firing for longer than a couple of `refreshInterval`s means the
mapping is going stale. The second means a directory needs cleaning up, and will
keep failing every rebuild until it is. The third is the early warning for the
first: a backend whose rebuilds are creeping towards its `timeout` will start
failing them, and the duration is visible well before that happens.

## Triggering a refresh

Waiting out `refreshInterval` after a group membership change is often
undesirable. An authenticated user can trigger an immediate rebuild by POSTing
to the refresh endpoint on the proxy:

```
$ curl -XPOST -H "Authorization: Bearer ${TOKEN}" \
    https://kube-oidc-proxy.example.net/kube-oidc-proxy/ldap/refresh
{"users":1423,"groups":97,"lastRefresh":"2021-11-25T01:05:17Z","duration":"1.82s","source":"directory","backends":[{"name":"corp","users":1401,"groups":91,"duration":"1.74s"},{"name":"partners","users":22,"groups":6,"duration":"0.08s"}]}
```

`source` is where the mapping being served came from: `directory`, or `cache` if
it was loaded from the persisted mapping after a failed startup refresh.

The endpoint sits behind the same OIDC authentication as every other request, so
an unauthenticated caller cannot trigger a rebuild. A caller arriving while a
rebuild is already running joins it and is given its result, so a burst of
requests costs one rebuild rather than one each - which matters because every
rebuild searches every directory in full, and by default any authenticated user
may ask for one. The path is not a valid API server path, so it never shadows a
request destined for Kubernetes.

By default any authenticated user may trigger a refresh. To restrict this to a
set of users, set `refreshUsers`. Names are matched case insensitively, and may
be given either as they appear in the JWT or without the
`--oidc-username-prefix`. A user who is not in the list receives a `403`.
