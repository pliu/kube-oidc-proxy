# Active Directory Group Augmentation

By default, kube-oidc-proxy takes both the user name and the groups of a request
from the JWT presented by the user. Some identity providers issue tokens that do
not carry group claims at all, or carry a truncated set of them (Azure AD, for
example, replaces the `groups` claim with a link once a user is a member of more
than a few groups).

kube-oidc-proxy can instead pull the groups from an Active Directory (or any
LDAP v3) backend. When enabled, the user name of a request is still taken from
the JWT, but the groups are taken from the directory.

## How it works

The full user to group mapping is built up front and held in memory:

1. Every group under the configured group search base(s) is read. Only these
   groups are ever mapped onto a user - a user's membership of a group outside
   of these bases is ignored.
2. Every user under the configured user search base(s) is read, along with their
   `memberOf` attribute, which is filtered down to the groups found above.

The mapping is rebuilt on an interval (10 minutes by default) and swapped in
atomically, so a request always reads a complete, consistent mapping. If a
rebuild fails, the previous mapping is kept in place and serving continues.

The initial build happens before the proxy starts serving, so that requests are
never authorized against an empty mapping. If it fails, the proxy exits.

## Configuration

To enable augmentation, include the following flags:

```
--ad-enabled
--ad-url=ldaps://ad.example.net:636
--ad-bind-dn=CN=kube-oidc-proxy,OU=Service Accounts,DC=example,DC=net
--ad-bind-password-file=/etc/kube-oidc-proxy/ad-password
--ad-user-search-base=OU=Users,DC=example,DC=net
--ad-group-search-base=OU=Groups,DC=example,DC=net
```

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--ad-enabled` | `false` | Enable Active Directory group augmentation. |
| `--ad-url` | | URL(s) of the directory. Tried in order until one can be connected to and bound. |
| `--ad-bind-dn` | | DN to bind as. If empty, an anonymous bind is used. |
| `--ad-bind-password` | | Password to bind with. |
| `--ad-bind-password-file` | | File holding the password to bind with. Takes precedence over `--ad-bind-password`. |
| `--ad-ca-file` | | PEM bundle used to verify the directory's serving certificate. Defaults to the host trust store. |
| `--ad-insecure-skip-tls-verify` | `false` | Do not verify the directory's serving certificate. |
| `--ad-start-tls` | `false` | Issue a StartTLS request after connecting. Used with an `ldap://` URL. |
| `--ad-user-search-base` | | Base DN(s) to search for users under. |
| `--ad-user-filter` | `(objectClass=user)` | LDAP filter selecting user entries. |
| `--ad-username-attribute` | `userPrincipalName` | Attribute holding the name that matches the user name of the JWT. |
| `--ad-group-search-base` | | Base DN(s) to search for groups under. |
| `--ad-group-filter` | `(objectClass=group)` | LDAP filter selecting group entries. |
| `--ad-group-name-attribute` | `cn` | Attribute of a group entry to use as the group name. |
| `--ad-group-prefix` | | Prefix prepended to every group name from the directory. |
| `--ad-refresh-interval` | `10m` | How often the mapping is rebuilt. |
| `--ad-refresh-users` | | Users allowed to trigger a refresh. If not set, any authenticated user may. |
| `--ad-fallback-to-token-groups` | `false` | Fall back to the groups of the JWT for users not found in the directory. |

Group augmentation relies on impersonation, so it cannot be combined with
`--disable-impersonation`.

### Matching users

The user name of a request is matched against `--ad-username-attribute` case
insensitively. If `--oidc-username-prefix` is set, the prefix is stripped from
the user name before matching, so the directory can be keyed on the bare
attribute value.

A user that cannot be found in the directory is given no groups, and so will be
able to do only what `system:authenticated` allows. Pass
`--ad-fallback-to-token-groups` to have such a user keep the groups of their
JWT instead.

### Group names

`--oidc-groups-prefix` is *not* applied to groups pulled from the directory, as
those groups did not come from the OIDC issuer. Use `--ad-group-prefix` if the
group names need a prefix to match your RBAC bindings.

## Triggering a refresh

Waiting out `--ad-refresh-interval` after a group membership change is often
undesirable. An authenticated user can trigger an immediate rebuild by POSTing
to the refresh endpoint on the proxy:

```
$ curl -XPOST -H "Authorization: Bearer ${TOKEN}" \
    https://kube-oidc-proxy.example.net/kube-oidc-proxy/ad/refresh
{"users":1423,"groups":97,"lastRefresh":"2021-11-25T01:05:17Z","duration":"1.82s"}
```

The endpoint sits behind the same OIDC authentication as every other request, so
an unauthenticated caller cannot trigger a rebuild. Refreshes are serialised, so
concurrent calls cannot fan out into concurrent searches of the directory. The
path is not a valid API server path, so it never shadows a request destined for
Kubernetes.

By default any authenticated user may trigger a refresh. To restrict this to a
set of users, pass `--ad-refresh-users`:

```
--ad-refresh-users=alice@example.net,bob@example.net
```

Names are matched case insensitively, and may be given either as they appear in
the JWT or without the `--oidc-username-prefix`. A user who is not in the list
receives a `403`.
