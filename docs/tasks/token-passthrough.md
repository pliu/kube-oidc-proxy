# Token Passthrough

With token passthrough, kube-oidc-proxy forwards every request to the API server
as it is: with the caller's own bearer token, without impersonation, and with
no credentials of the proxy's own. The proxy does not authenticate the token at
all. The API server authenticates every request and authorizes it with its own
RBAC, so it must accept the tokens your callers send - its own ServiceAccount
tokens, or tokens of an OIDC issuer it is configured to trust.

To enable token passthrough, include the following flag:

```
--token-passthrough
```

Requests without a bearer token are refused with `401 Unauthorized`, as they are
in every mode. `Impersonate-*` headers are forwarded with the rest of the
request, and the API server holds the caller to their own impersonation rights,
so `kubectl --as` works as it does against the API server directly.

Since the proxy authenticates nothing, passthrough cannot be combined with
[LDAP group augmentation](./ldap-group-augmentation.md) or
[extra user headers](./extra-impersonation-headers.md), which only apply to
requests the proxy impersonates; the proxy refuses to start with either.
`--oidc-config-file` is not required, and is ignored if given.
