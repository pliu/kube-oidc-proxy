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

Configured backends are searched in parallel, so a rebuild takes roughly as
long as its slowest backend rather than the sum of every backend's search time.
The complete set of results is still validated and merged as one mapping: any
backend failure rejects the rebuild and leaves the previous mapping serving.

The mapping is rebuilt on an interval (10 minutes by default) and swapped in
atomically, so a request always reads a complete, consistent mapping. If a
rebuild fails, the previous mapping is kept in place and serving continues.

A user the directory gained since the last rebuild is in no mapping yet, and is
given no groups until the next one. Waiting out the interval is not the only
way to close that gap: [one user can be refreshed](#refreshing-one-user)
without everybody being searched for again.

By default every replica does all of this for itself. Past one replica you
probably want [one of them building and the rest
serving](#splitting-the-builder-from-the-proxies) instead.

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

Two distinct group entries in one backend that produce the same group name also
fail the rebuild. Kubernetes RBAC sees the configured group name, not the LDAP
DN, so accepting both would collapse separate directory groups into one
authorization identity. One group returned more than once because group search
bases overlap is accepted, and repeated `memberOf` values are emitted only once.

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
      "groupNameAttribute": "cn"
    },
    {
      "name": "partners",
      "urls": ["ldap://partners.example.net:389"],
      "startTLS": true,
      "timeout": "2m",
      "bindDN": "CN=kube-oidc-proxy,OU=Service Accounts,DC=partners,DC=net",
      "bindPasswordFile": "/etc/kube-oidc-proxy/partners-password",
      "userSearchBases": ["OU=Users,DC=partners,DC=net"],
      "groupSearchBases": ["OU=Groups,DC=partners,DC=net"]
    }
  ],
  "refreshInterval": "10m",
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
| `role` | `standalone` | What this proxy does with the mapping. See [Splitting the builder from the proxies](#splitting-the-builder-from-the-proxies). |
| `backends` | | The directories to build the mapping from. At least one is required, except for a `reader`, which must have none. |
| `refreshInterval` | `10m` | How often the mapping is rebuilt. A Go duration string. Not used by a `reader`. |
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
| `groupNameAttribute` | `cn` | Attribute of a group entry to use as the group name. Its resulting value must be unique within the backend. |

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
able to do only what `system:authenticated` allows. There is no way to have such
a user keep the groups of their JWT: once the directory decides group
membership, it decides it for everybody. A user who is missing because a search
base is wrong or a directory is half configured would otherwise quietly regain
whatever their identity provider claimed for them, which is the failure this
whole feature exists to remove - and it would do so silently, at exactly the
moment the configuration is wrong.

A user who is genuinely absent from the directories and needs access wants an
entry there, or an RBAC binding against their user name rather than a group.

### Group names

`--oidc-groups-prefix` is *not* applied to groups pulled from a directory, as
those groups did not come from the OIDC issuer. The configured group name
attribute is emitted unchanged. If two directories use the same name, it is the
same Kubernetes RBAC group and a user receives it only once.

Kubernetes reserves the `system:` prefix for built-in groups such as
`system:masters`. A directory group whose name begins with `system:` is skipped
rather than impersonated, so a group created in a searched OU cannot grant
cluster privileges.

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

A refresh that rebuilds the mapping already in the store does not write it
again. Most refreshes are that - group memberships change far less often than
they are looked at - and the whole mapping goes out every time it goes out at
all, so on a directory that is not changing this is the difference between
rewriting the lot every `refreshInterval` and writing nothing. It also means a
rollout does not rewrite the mapping it just restored.

"The same mapping" means the same users holding the same groups, not the same
directory. A group created or deleted that nobody in the user search bases
belongs to does not change what anyone is impersonated as, so it is not a
change and nothing is written - even though it moves the group count reported
below. The other way round, a user gaining or losing a group is always a write,
since that is the mapping itself.

The one thing that write did on its own was record how recent the mapping was.
So when `maxAge` is set, an unchanged mapping is rewritten anyway once it is
halfway to it, rather than being left to age out of a store it is still being
confirmed against every `refreshInterval`. With `maxAge` unset nothing measures
its age, and it is left alone indefinitely - the timestamp in the store then
says when the mapping last *changed*, which is also what the "built N ago" in
the startup log is reporting.

| Field | Default | Description |
| ----- | ------- | ----------- |
| `type` | | **Required.** One of `none`, `file` or `kubernetesSecret`. |
| `maxAge` | | How old a persisted mapping may be and still be served. If unset, it is served however old it is. Also makes an unchanged mapping be rewritten once it is halfway to this age. |
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

Only available to a `standalone` proxy. A `builder` and its `reader`s are
separate deployments sharing one store, and a file is whatever each pod happens
to have mounted: it might be a shared volume, and it might be a path in each
pod's own filesystem, in which case the builder would write to a file no reader
will ever see. Nothing in the configuration can tell those apart, so those roles
require a `kubernetesSecret`.

### `kubernetesSecret`

```json
"cache": {"type": "kubernetesSecret", "kubernetesSecret": {"name": "kube-oidc-proxy-ldap-mapping"}}
```

The Secret is created if it does not exist, and only the configured key is
written, so a Secret shared with something else is left otherwise intact.

**This store has a ceiling, and a large directory will not fit under it.** The
API server caps a Secret at 1MiB. The payload is gzipped, and holds each group
name once rather than repeating it in every member's entry, which between them
fit a directory of roughly 45,000 users in ten groups each - or roughly 15,000
in thirty each. Past that the mapping is refused with an error rather than a
failed write, and has to go to a `file` instead. Note also that a Secret that
size is not cheap to write - it goes through etcd and out to everything watching
it - so it is worth knowing that a rebuild which
[changed nothing](#persisting-the-mapping) does not write at all.

Prefer `file` on a volume for anything but a small directory. `kubernetesSecret`
is for the deployment that wants no volume of its own and knows it stays well
under the cap.

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

## Splitting the builder from the proxies

By default every replica does everything: it searches the directories, builds
the mapping, writes it to the store and serves it. That is `"role":
"standalone"`, and for a single replica it is all you need.

It stops being what you want as soon as there is more than one replica. Every
replica sweeps every directory on its own schedule, so the load on the
directories multiplies by the replica count. Every replica writes the whole
mapping to the same store, so they take turns overwriting each other. And
because each builds its own mapping at its own moment, two replicas can hand the
same user different groups depending on which pod the Service picked.

The `builder` and `reader` roles split those jobs across two Deployments:

* One **builder**. It searches the directories, writes the mapping to the store
  and serves requests like any other replica. It is the only writer of the
  store, and the only place the bind credentials have to exist.
* Several **readers**. They never open a directory. They watch the store, serve
  what the builder published, and are configured with no backends at all -
  which means no bind credentials and no description of your directory layout on
  the pods taking user traffic.

Both roles require a `kubernetesSecret` cache. They are separate deployments
sharing one store, and a Secret is the only kind this proxy can be sure they
both reach; see [`file`](#file) for why a path is not.

The directories are swept once however many proxies you run, there is one writer
of the store so nothing overwrites anything, and every proxy serves the same
mapping because there is only one.

### The two configuration files

The builder is an ordinary configuration with a role on it:

```json
{
  "role": "builder",
  "backends": [
    {
      "name": "corp",
      "urls": ["ldaps://ldap.example.net:636"],
      "bindDN": "CN=svc-kube-oidc-proxy,OU=Service Accounts,DC=example,DC=net",
      "bindPasswordFile": "/etc/kube-oidc-proxy/ldap-bind-password",
      "userSearchBases": ["OU=Users,DC=example,DC=net"],
      "groupSearchBases": ["OU=Groups,DC=example,DC=net"]
    }
  ],
  "refreshInterval": "10m",
  "cache": {
    "type": "kubernetesSecret",
    "kubernetesSecret": {"name": "kube-oidc-proxy-ldap-mapping"}
  }
}
```

A reader's is the whole of what it needs to know:

```json
{
  "role": "reader",
  "cache": {
    "type": "kubernetesSecret",
    "kubernetesSecret": {"name": "kube-oidc-proxy-ldap-mapping"}
  }
}
```

Backends are rejected in a reader's file rather than ignored, so the file cannot
quietly grow credentials that only look like they do nothing.

### Refreshing

`POST` to the [refresh endpoint](#triggering-a-refresh) only rebuilds from the
directories on the builder - a reader has nothing to rebuild from. Route that
path to the builder's Service and the rest to the proxies:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: kube-oidc-proxy
  namespace: kube-oidc-proxy
spec:
  rules:
  - host: kube-oidc-proxy.example.net
    http:
      paths:
      - path: /kube-oidc-proxy/ldap/refresh
        pathType: Exact
        backend:
          service:
            name: kube-oidc-proxy-ldap-builder
            port: {number: 443}
      - path: /
        pathType: Prefix
        backend:
          service:
            name: kube-oidc-proxy
            port: {number: 443}
```

A refresh that reaches the builder rebuilds, publishes, and reaches every reader
within about as long as the write takes. The response comes back when the
builder is done, which is a moment before the readers have caught up.

Readers do not serve the refresh endpoint. A request to that path on a reader is
handled like any other request and passed to the API server rather than causing
a store reload. Route the exact path to the builder as shown above.

### Readiness

The proxy reports itself unready until the secure port is accepting
connections. Restoring a persisted mapping, or finishing the first directory
sweep, is not enough on its own: both happen before the proxy starts serving.
The port is bound from the moment the process starts, so a request arriving in
that window is taken and then left waiting rather than refused, which is
exactly what the Service must not route to. The pod stays out of it for that
whole window.

A reader with no mapping would answer every request by stripping the user of
every group they hold, so it also reports itself unready until it has one. On
a fresh install that is the gap between the readers starting and the builder
finishing its first sweep of the directories.

It waits rather than exiting, since what it is waiting for is on its way. A
store it cannot read *at all* is a different thing - the wrong name, or no
permission - and fails the reader at startup, where somebody is watching.

### RBAC

The builder writes, so it keeps the Role from [above](#kubernetessecret). The
readers only ever read, and get this instead:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: kube-oidc-proxy-ldap-reader
  namespace: kube-oidc-proxy
rules:
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["kube-oidc-proxy-ldap-mapping"]
  verbs: ["get"]
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["list", "watch"]
```

**That second rule is wider than it looks, and it is worth being deliberate
about.** Readers watch the mapping Secret so that a published mapping reaches
them as it lands rather than at the next poll. RBAC `resourceNames` does not
apply to `list` and `watch`, so there is no way to grant a watch of one Secret:
the grant covers every Secret in the namespace, including the one holding the
builder's bind password. The field selector on the watch narrows what the
readers ask for, not what they are permitted to ask for.

If that trade is not one you want to make, put the builder and its credentials
in a namespace of their own, so that the grant the readers hold reaches nothing
worth having.

## Metrics

Both failures above are quiet by design: the previous mapping keeps serving, so
no request fails and nothing tells you that group changes have stopped being
picked up. Two gauges are published for alerting on that, in Prometheus format
at `/metrics` on the readiness probe listener - `--readiness-probe-port`, 8080
by default, beside `/ready` and `/live`. That listener is plain HTTP with no
authentication, so the metrics are readable by anything that can reach the pod
on that port. They carry no request or user data; label values identify a
configured backend and, for duplicate values, whether it was a user or group.

| Metric | Type | Description |
| ------ | ---- | ----------- |
| `kube_oidc_proxy_ldap_last_refresh_success` | gauge | `1` if the mapping being served is the one this proxy last went and got, `0` if that failed. |
| `kube_oidc_proxy_ldap_backend_duplicate_values{backend,kind}` | gauge | `1` if two entries of this backend claim one authorization value, which fails the rebuild. `kind` is `user` or `group`. |
| `kube_oidc_proxy_ldap_refresh_duration_seconds` | histogram | How long a complete rebuild took, across every backend. |
| `kube_oidc_proxy_ldap_backend_refresh_duration_seconds{backend}` | histogram | How long searching one backend took, so that one slow directory can be told from a rebuild that is slow all over. |

On a [reader](#splitting-the-builder-from-the-proxies), "went and got" means
picking up what the builder published rather than rebuilding, so
`last_refresh_success` still says whether that proxy is keeping up. The other
three describe rebuilds and are published by builders and standalone proxies
only - a reader reports no series for them, since it never searches a
directory.

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
is never going to do. Both `kind` series of `backend_duplicate_values` are
published as `0` for every configured backend from startup, so an alert can
tell "no duplicates" from a backend that has not been searched yet.

An unreachable directory leaves each `backend_duplicate_values` series where it
was rather than clearing it, since a search that did not run says nothing about
what the directory holds. Alert on `last_refresh_success` for that instead:

```
kube_oidc_proxy_ldap_last_refresh_success == 0
kube_oidc_proxy_ldap_backend_duplicate_values > 0
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
it was loaded from the store after a failed startup refresh.

`groups` is how many groups were found under the group search bases, summed
over the backends. It is not the number of distinct group names anyone holds:
a group nobody in the user search bases belongs to is counted, and a group two
backends both return is counted by each. What it measures is the group search
having returned something, which is the check described in
[How it works](#how-it-works). `users` is the size of the mapping itself.

With the builder split from the proxies, this endpoint has to reach the builder
to rebuild anything, which is a matter of [routing](#refreshing). Readers do
not serve the endpoint: a request that lands on a reader is passed to the API
server like any other path.

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

### Refreshing one user

Rebuilding everybody to pick up one group membership means searching every
directory in full. When what changed is known, a `user` parameter refreshes
that user alone:

```
$ curl -XPOST -H "Authorization: Bearer ${TOKEN}" \
    "https://kube-oidc-proxy.example.net/kube-oidc-proxy/ldap/refresh?user=alice@example.net"
{"user":"alice@example.net","found":true,"groups":12,"changed":true,"duration":"41ms"}
```

Every backend is searched for that one user and the results merged, exactly as
a rebuild merges the whole of each - a user held in more than one directory
ends up with the union of their groups, and a backend that cannot be searched
fails the refresh rather than being left out of it. The difference is in how
their `memberOf` is resolved: against the group names of the last rebuild
rather than by sweeping every group search base again, which is most of what
makes this cheaper.

A group the last rebuild did not find - one created since, which is exactly
what somebody adding a user to a new group is asking to have picked up - is
looked up on its own rather than dropped, and is held to the same rules the
sweep holds a group to. It has to live under a configured group search base,
match the `groupFilter`, carry a `groupNameAttribute`, and not use the reserved
`system:` prefix; anything else is left out just as a rebuild would leave it
out. A new group taking the name of one already in the mapping fails the
refresh, as it fails a rebuild: once the DN is discarded, RBAC cannot tell two
directory groups of one name apart.

Only a DN under a search base costs a search, so the groups a user holds
elsewhere in the tree - which is most of them, on a large directory - are
dropped by comparison alone. A refresh that would have to look up more than 100
of them is refused: a mapping that far out of date wants a full rebuild rather
than a search per group.

If what it found differs from what is being served, the mapping is persisted
and then swapped in - the same order a rebuild uses, so the store is never
older than what requests are answered from. A store that refuses the write
leaves the refresh failed rather than leaving that one proxy serving something
nothing else will ever see.

There is no partial write, so this rewrites the whole mapping for one user. A
rebuild of everybody would write exactly the same amount and search every
directory to get there, so it is still the cheaper of the two by a wide margin,
but it is not free: `"changed":false` means nothing was written, because the
refresh found what was already being served.

A user the directories no longer hold is *removed* from the mapping, since
serving their old groups is serving an entry the next rebuild would drop.

The response reports how many groups the user holds rather than which. By
default any authenticated user may call this endpoint, and naming them would
make it a way of reading the group membership of anybody whose username can be
guessed. `refreshUsers` gates this exactly as it gates a full rebuild, and a
burst of requests for one user costs one write rather than one each: whichever
gets there first writes the mapping, and the rest find nothing left to change.

With the builder split from the proxies this needs the same
[routing](#refreshing) a full rebuild does - the query parameter rides along
with the path rule shown there. It is also the only way to pick up a new user
promptly in that topology: a reader holds no credentials and no description of
the directory layout, so it cannot search for anybody itself, and it picks up
the refreshed user when the builder publishes the mapping it just wrote.
