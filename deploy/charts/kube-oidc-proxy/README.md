# kube-oidc-proxy helm chart

This is a `helm` chart that installs [`kube-oidc-proxy`](https://github.com/jetstack/kube-oidc-proxy/).
This helm chart cannot be installed out of the box without providing own
configuration.

This helm chart is based on example configuration provided in `kube-oidc-proxy`
[repository](https://github.com/jetstack/kube-oidc-proxy/blob/master/deploy/yaml/kube-oidc-proxy.yaml).

Minimal required configuration is the `oidc.issuers` list in `values.yaml`:
every issuer whose tokens the proxy accepts. The chart renders it into the file
the proxy's `--oidc-config-file` names. Each issuer takes the fields of a `jwt`
entry of kube-apiserver's
[`--authentication-config`](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#using-authentication-configuration),
validated by the same rules.

```yaml
oidc:
  issuers:
  - issuer:
      url: https://accounts.google.com
      audiences: [my-client]
    claimMappings:
      username:
        claim: email
        prefix: ""
```

Each issuer may also set `signingAlgs`, the JOSE algorithms its tokens may be
signed with. It defaults to `[RS256]`.

```yaml
oidc:
  issuers:
  - issuer:
      url: https://accounts.google.com
      audiences: [my-client]
    signingAlgs: [RS256, ES256]
    claimValidationRules:
    - claim: hd
      requiredValue: example.com
    claimMappings:
      username:
        claim: email
        prefix: "google:"
  - issuer:
      url: https://login.example.com
      audiences: [kube-oidc-proxy]
    claimMappings:
      username:
        claim: sub
        prefix: "example:"
      groups:
        claim: groups
        prefix: "example:"
```

Give each issuer its own username and group prefix, so that a user or group of
one issuer can never be mistaken for one of another in RBAC bindings.

When an issuer is served with a certificate from a private CA, add that CA as
PEM encoded text to the issuer's `certificateAuthority`. Without one, the
host's root CAs are used.

```yaml
oidc:
  issuers:
  - issuer:
      url: https://login.example.com
      audiences: [kube-oidc-proxy]
      certificateAuthority: |
        -----BEGIN CERTIFICATE-----
        MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkG
        A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jv
        b3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5MDExMjAw
        MDBaFw0yODAxMjgxMjAwMDBaMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
        YWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJHbG9iYWxT
        aWduIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDaDuaZ
        jc6j40+Kfvvxi4Mla+pIH/EqsLmVEQS98GPR4mdmzxzdzxtIK+6NiY6arymAZavp
        xy0Sy6scTHAHoT0KMM0VjU/43dSMUBUc71DuxC73/OlS8pF94G3VNTCOXkNz8kHp
        1Wrjsok6Vjk4bwY8iGlbKk3Fp1S4bInMm/k8yuX9ifUSPJJ4ltbcdG6TRGHRjcdG
        snUOhugZitVtbNV4FpWi6cgKOOvyJBNPc1STE4U6G7weNLWLBYy5d4ux2x8gkasJ
        U26Qzns3dLlwR5EiUWMWea6xrkEmCMgZK9FGqkjWZCrXgzT/LCrBbBlDSgeF59N8
        9iFo7+ryUp9/k5DPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8E
        BTADAQH/MB0GA1UdDgQWBBRge2YaRQ2XyolQL30EzTSo//z9SzANBgkqhkiG9w0B
        AQUFAAOCAQEA1nPnfE920I2/7LqivjTFKDK1fPxsnCwrvQmeU79rXqoRSLblCKOz
        yj1hTdNGCbM+w6DjY1Ub8rrvrTnhQ7k4o+YviiY776BQVvnGCv04zcQLcFGUl5gE
        38NflNUVyRRBnMRddWQVDf9VMOyGj/8N7yy5Y0b2qvzfvGn9LhJIZJrglfCm7ymP
        AbEVtQwdpf5pLGkkeB6zpxxxYu7KyJesF12KwvhHhm4qxFYxldBniYUr+WymXUad
        DKqC5JlR3XC321Y9YeRq4VzW9v493kHMB65jUr9TU/Qr6cf9tveCX4XSQRjbgbME
        HMUfpIBvFSDJ3gyICh3WZlXi/EjJKSZp4A==
        -----END CERTIFICATE-----
    claimMappings:
      username:
        claim: sub
        prefix: "example:"
```

An issuer's keys are normally fetched from it, through the `jwks_uri` of its
`/.well-known/openid-configuration`. To verify its tokens with keys you give
instead, set `publicKeys` to PEM `PUBLIC KEY` blocks, or `CERTIFICATE` blocks
whose public key is used. The issuer is then never contacted, so it need not be
reachable from the proxy, and `certificateAuthority` and `discoveryURL` cannot
be set alongside.

```yaml
oidc:
  issuers:
  - issuer:
      url: https://login.example.com
      audiences: [kube-oidc-proxy]
    publicKeys: |
      -----BEGIN PUBLIC KEY-----
      MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEt7GkIyDiezbHfa4fDz2eYDJ+Mev6
      TbkaMBnJPIRdxAP9LQyP3haLMW2V4rHwVOdJVNdqWN6yi172ESl9fySFqg==
      -----END PUBLIC KEY-----
    signingAlgs: [ES256]
    claimMappings:
      username:
        claim: sub
        prefix: "example:"
```

With keys given, nothing notices the issuer rotating its keys: tokens signed
with a new key are rejected until it is added here and the pods restart, so list
the old and new keys together while a rotation is under way. Only the key in a
certificate is used; its expiry, chain and revocation are not checked, since
listing it is what trusts it. Distributed group claims, which are resolved by
contacting the issuer, cannot be resolved, so a token relying on them is
rejected.

This minimal configuration gives a cluster internal IP address that can be used
with `kubectl` to authenticate requests to Kubernetes API server.

The service can be exposed via ingress controller and give access to external
clients. Example of exposing via ingress controller.

```yaml
ingress:
  enabled: true
  annotations:
    kubernetes.io/ingress.class: traefik
    traefik.ingress.kubernetes.io/rule-type: PathPrefixStrip
  hosts:
    - host: ""
      paths:
        - /oidc-proxy
```

By default the helm chart will create self-signed TLS certificate for `kube-oidc-proxy`
service. It is possible to provide secret name that contains TLS artifacts for
service. The secret must be of `kubernetes.io/tls` type.

```yaml
tls:
  secretName: my-tls-secret-with-key-and-cert
```

### LDAP per-user cache

Set `ldap.enabled: true`, `ldap.cacheScope: main`, and configure
`ldap.config.backends`. The chart supplies the ConfigMap namespace (release
namespace by default) and grants the service account ConfigMap
`get/list/watch/create/update` in that namespace. Set `ldap.cacheNamespace` to
an existing dedicated namespace for isolation. Mount password/CA files using
`extraVolumes` and `extraVolumeMounts`.

```yaml
ldap:
  enabled: true
  cacheScope: main
  config:
    lookupConcurrency: 8
    lookupTimeout: 1m
    refreshInterval: 10m
    backends:
      - name: corp
        urls: [ldaps://ldap.example.net:636]
        userSearchBases: ["OU=Users,DC=example,DC=net"]
        groupSearchBases: ["OU=Groups,DC=example,DC=net"]
```

Replicas coalesce misses locally and coordinate writes through ConfigMap
resource versions. Concurrency is per replica; the leader refreshes only cached
users. ConfigMaps expose readable identities/memberships. The cache starts empty;
the first uncached request requires LDAP and Kubernetes persistence.
See [LDAP configuration and deployment](../../../docs/tasks/ldap-group-augmentation.md).
