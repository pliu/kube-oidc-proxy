# Active Directory Group Augmentation

By default, kube-oidc-proxy takes both the user name and the groups of a request
from the JWT presented by the user. Some identity providers issue tokens that do
not carry group claims at all, or carry a truncated set of them (Azure AD, for
example, replaces the `groups` claim with a link once a user is a member of more
than a few groups).

kube-oidc-proxy can instead pull the groups from one or more Active Directory
(or any LDAP v3) backends. When enabled, the user name of a request is still
taken from the JWT, but the groups are taken from the directories.

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

The same applies to a backend that is still answering but has stopped returning
anything. A search that finds nothing is not an error, so a bind account that
loses its read on the user OU, or a search base renamed out from under the
configuration, would otherwise look like a directory in which nobody is a member
of anything. A backend that returns no users, or no groups, having returned some
at the previous rebuild fails the rebuild instead, and the previous mapping keeps
serving:

```
failed to refresh Active Directory mapping, keeping previous mapping: backend "corp": returned no users, having returned 1401 at the last refresh
```

Only a fall to nothing is caught, not a directory that merely shrinks - any
threshold short of that would be a guess at how much churn is normal. A backend
that has never returned anything is accepted, since a directory that is empty on
the very first build is a configuration to fix rather than a mapping to protect.
A directory that really has been emptied is accepted again once the proxy is
restarted and its [persisted mapping](#persisting-the-mapping), if any, removed.

The initial build happens before the proxy starts serving, so that requests are
never authorized against an empty mapping. If it fails and there is no
[persisted mapping](#persisting-the-mapping) to fall back on, the proxy exits.

## Configuration

Augmentation is configured by a JSON file rather than by flags, since it
describes a list of backends. Point the proxy at one with a single flag:

```
--ad-config-file=/etc/kube-oidc-proxy/ad.json
```

Setting the flag is what enables augmentation. The file is checked against a
[JSON schema](../../pkg/proxy/ad/schema.json) at startup, and the proxy refuses
to start if it does not match - a misspelled property is an error rather than a
silently ignored line.

A minimal configuration:

```json
{
  "backends": [
    {
      "name": "corp",
      "urls": ["ldaps://ad.example.net:636"],
      "bindDN": "CN=kube-oidc-proxy,OU=Service Accounts,DC=example,DC=net",
      "bindPasswordFile": "/etc/kube-oidc-proxy/ad-password",
      "userSearchBases": ["OU=Users,DC=example,DC=net"],
      "groupSearchBases": ["OU=Groups,DC=example,DC=net"]
    }
  ]
}
```

And one using every field, two directories and a persisted mapping:

```json
{
  "backends": [
    {
      "name": "corp",
      "urls": ["ldaps://ad-1.example.net:636", "ldaps://ad-2.example.net:636"],
      "bindDN": "CN=kube-oidc-proxy,OU=Service Accounts,DC=example,DC=net",
      "bindPasswordFile": "/etc/kube-oidc-proxy/ad-password",
      "caFile": "/etc/kube-oidc-proxy/ad-ca.pem",
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
      "name": "kube-oidc-proxy-ad-mapping"
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
| `cache` | | Where the built mapping is persisted. See [below](#persisting-the-mapping). |

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
| `userSearchBases` | | Base DN(s) to search for users under. |
| `userFilter` | `(objectClass=user)` | LDAP filter selecting user entries. |
| `usernameAttribute` | `userPrincipalName` | Attribute holding the name that matches the user name of the JWT. |
| `groupSearchBases` | | Base DN(s) to search for groups under. |
| `groupFilter` | `(objectClass=group)` | LDAP filter selecting group entries. |
| `groupNameAttribute` | `cn` | Attribute of a group entry to use as the group name. |
| `groupPrefix` | | Prefix prepended to every group name from this directory. |

Group augmentation relies on impersonation, so it cannot be combined with
`--disable-impersonation`.

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

## Persisting the mapping

Without a `cache`, a proxy that restarts has to rebuild the mapping from the
directories before it can serve anything, and exits if it cannot reach them. A
directory outage during a rollout then takes the proxy down with it.

With a `cache` configured, the built mapping is persisted after every successful
refresh. At startup the persisted mapping is loaded first, and the proxy then
tries to refresh from the directories:

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
| `type` | | One of `none`, `file` or `kubernetesSecret`. |
| `maxAge` | | How old a persisted mapping may be and still be served. If unset, it is served however old it is. |
| `file.path` | | Where to write the mapping. Required when `type` is `file`. |
| `kubernetesSecret.name` | | Name of the Secret to write. Required when `type` is `kubernetesSecret`. |
| `kubernetesSecret.namespace` | The proxy's own namespace | Namespace of that Secret. |
| `kubernetesSecret.key` | `mapping.json.gz` | Key within that Secret. |

### `file`

```json
"cache": {"type": "file", "file": {"path": "/var/lib/kube-oidc-proxy/ad-mapping.json"}}
```

The file is written atomically, with mode `0600`, and its parent directory is
created if needed. The path should be in a volume that outlives the container -
a path in the container's writable layer is lost on exactly the restart the
cache exists for.

### `kubernetesSecret`

```json
"cache": {"type": "kubernetesSecret", "kubernetesSecret": {"name": "kube-oidc-proxy-ad-mapping"}}
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
  name: kube-oidc-proxy-ad-mapping
  namespace: kube-oidc-proxy
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["create"]
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["kube-oidc-proxy-ad-mapping"]
  verbs: ["get", "update"]
```

Note that the mapping names every user of the cluster and the groups they hold.
Anything that can read the Secret can read that.

## Triggering a refresh

Waiting out `refreshInterval` after a group membership change is often
undesirable. An authenticated user can trigger an immediate rebuild by POSTing
to the refresh endpoint on the proxy:

```
$ curl -XPOST -H "Authorization: Bearer ${TOKEN}" \
    https://kube-oidc-proxy.example.net/kube-oidc-proxy/ad/refresh
{"users":1423,"groups":97,"lastRefresh":"2021-11-25T01:05:17Z","duration":"1.82s","source":"directory","backends":[{"name":"corp","users":1401,"groups":91,"duration":"1.74s"},{"name":"partners","users":22,"groups":6,"duration":"0.08s"}]}
```

`source` is where the mapping being served came from: `directory`, or `cache` if
it was loaded from the persisted mapping after a failed startup refresh.

The endpoint sits behind the same OIDC authentication as every other request, so
an unauthenticated caller cannot trigger a rebuild. Refreshes are serialised, so
concurrent calls cannot fan out into concurrent searches of the directories. The
path is not a valid API server path, so it never shadows a request destined for
Kubernetes.

By default any authenticated user may trigger a refresh. To restrict this to a
set of users, set `refreshUsers`. Names are matched case insensitively, and may
be given either as they appear in the JWT or without the
`--oidc-username-prefix`. A user who is not in the list receives a `403`.
