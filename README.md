# kube-oidc-proxy

`kube-oidc-proxy` is a reverse proxy server to authenticate users using OIDC to
Kubernetes API servers where OIDC authentication is not available (i.e. managed 
Kubernetes providers such as GKE, EKS, etc).

This intermediary server takes `kubectl` requests, authenticates the request using
the configured OIDC Kubernetes authenticator, then attaches impersonation
headers based on the OIDC response from the configured provider. This
impersonated request is then sent to the API server on behalf of the user and
it's response passed back. The server has flag parity with secure serving and
OIDC authentication that are available with the Kubernetes API server as well as
client flags provided by kubectl. In-cluster client authentication is also
available when running `kube-oidc-proxy` as a pod.

The proxy runs in one of three modes:

| Mode | Who authenticates the token | Forwarded to the API server as |
| ---- | --------------------------- | ------------------------------ |
| Default | The proxy, with the configured OIDC issuers | The proxy's `ServiceAccount`, impersonating the token's user and groups |
| [LDAP group augmentation](./docs/tasks/ldap-group-augmentation.md) | The proxy, with the configured OIDC issuers | The proxy's `ServiceAccount`, impersonating the token's user and the groups the directory holds for them |
| [Token passthrough](./docs/tasks/token-passthrough.md) | The API server | The request as it is, with the caller's own token |

Requests without a bearer token are refused with `401 Unauthorized` in every
mode. Since the proxy uses impersonation to forward requests it authenticates,
impersonation requested by the user is refused in the first two modes; see
[Impersonation Headers](#impersonation-headers).

![kube-oidc-proxy demo](https://storage.googleapis.com/kube-oidc-proxy/demo-9de755f8e4b4e5dd67d17addf09759860f903098.svg)

The following is a diagram of the request flow for a user request.
![kube-oidc-proxy request
flow](https://storage.googleapis.com/kube-oidc-proxy/diagram-d9623e38a6cd3b585b45f47d80ca1e1c43c7e695.png)

## Quickest Start

OpenUnison integrates kube-oidc-proxy directly, and includes an identity provider and access portal for Kubernetes.  The quickest way to get started with kube-oidc-proxy is to follow the directions for OpenUnison's deployment at https://openunison.github.io/.

## Tutorial

Directions on how to deploy OIDC authentication with multi-cluster can be found
[here.](./demo/README.md) or there is a [helm chart](./deploy/charts/kube-oidc-proxy/README.md).

### Quickstart

Deployment yamls can be found in `./deploy/yaml` and will require configuration to
an exiting OIDC issuer.

This quickstart demo will assume you have a Kubernetes cluster without OIDC
authentication, as well as an OIDC client created with your chosen
provider. We will be using a Service with type `LoadBalancer` to expose it to
the outside world. This can be changed depending on what is available and what
suites your set up best.

Firstly deploy `kube-oidc-proxy` and it's related resources into your cluster.
This will create it's Deployment, Service Account and required permissions into
the newly created `kube-oidc-proxy` Namespace.

```
$ kubectl apply -f ./deploy/yaml/kube-oidc-proxy.yaml
$ kubectl get all --namespace kube-oidc-proxy
```

This deployment will fail until we create the required secrets. Notice we have
also not provided any client flags as we are using the in-cluster config with
it's Service Account.

We now wait until we have an external IP address provisioned.

```
$ kubectl get service --namespace kube-oidc-proxy
```

We need to generate certificates for `kube-oidc-proxy` to securely serve.  These
certificates can be generated through `cert-manager`, more information about
this project found [here](https://github.com/jetstack/cert-manager).

Next, populate the OIDC authenticator Secret in `./deploy/yaml/secrets.yaml`
with the details given to you by your OIDC provider. Its `authn.yaml` lists every
issuer the proxy trusts under `issuers`; add an entry for each further issuer,
with a username prefix of its own. Each issuer takes the fields of a `jwt` entry
of kube-apiserver's `--authentication-config`, and may also set `signingAlgs`, the JOSE algorithms its tokens may be signed with (default
`[RS256]`). The `certificateAuthority` of an issuer is only needed when its
serving certificate is not trusted by the host's root CAs. To verify an issuer's
tokens with keys you give rather than ones fetched from it, set its `publicKeys`
to PEM public keys or certificates; see the
[helm chart README](./deploy/charts/kube-oidc-proxy/README.md) for what that
gives up. The OIDC provider CA
will be different depending on which provider you are using. The easiest way to obtain
the correct certificate bundle is often by opening the providers URL into a
browser and fetching them there (typically output by clicking the lock icon on
your address bar). Google's OIDC provider for example requires CAs from both
`https://accounts.google.com/.well-known/openid-configuration` and
`https://www.googleapis.com/oauth2/v3/certs`.


Apply the secret manifests.

```
kubectl apply -f ./deploy/yaml/secrets.yaml
```

You can restart the `kube-oidc-proxy` pod to use these new secrets
now they are available.

```
kubectl delete pod --namespace kube-oidc-proxy kube-oidc-proxy-*
```

Finally, create a Kubeconfig to point to `kube-oidc-proxy` and set up your OIDC
authenticated Kubernetes user.

```
apiVersion: v1
clusters:
- cluster:
    certificate-authority: *
    server: https://[url|ip:443]
  name: *
contexts:
- context:
    cluster: *
    user: *
  name: *
kind: Config
preferences: {}
users:
- name: *
  user:
    auth-provider:
      config:
        client-id: *
        client-secret: *
        id-token: *
        idp-issuer-url: *
        refresh-token: *
      name: oidc
```

## Configuration
 - [Token Passthrough](./docs/tasks/token-passthrough.md)
 - [Extra Impersonations Headers](./docs/tasks/extra-impersonation-headers.md)
 - [Auditing](./docs/tasks/auditing.md)
 - [LDAP Group Augmentation](./docs/tasks/ldap-group-augmentation.md)
 - [Leader Election](./docs/tasks/leader-election.md)

## Logging

In addition to auditing, kube-oidc-proxy logs all requests to standard out so the requests can be captured by a common Security Information and Event Management (SIEM) system.  SIEMs will typically import logs directly from containers via tools like fluentd.  This logging is also useful in debugging.  An example successful event:

```
[2021-11-25T01:05:17+0000] AuSuccess src:[10.42.0.5 / 10.42.1.3, 10.42.0.5] URI:/api/v1/namespaces/openunison/pods?limit=500 inbound:[mlbadmin1 / k8s-cluster-admins|system:authenticated /]
```

The first block, between `[]` is an ISO-8601 timestamp.  The next text, `AuSuccess`, indicates that authentication was successful.  the `src` block containers the remote address of the request, followed by the value of the `X-Forwarded-For` HTTP header if provided.  The `URI` is the URL path of the request.  The `inbound` section provides the user name, groups, and extra-info provided to the proxy from the JWT.

When there's an error or failure:

```
[2021-11-25T01:05:24+0000] AuFail src:[10.42.0.5 / 10.42.1.3] URI:/api/v1/nodes
```

This is similar to success, but without the token information.

## Reserved Users and Groups

Users and groups starting with `system:` are reserved by Kubernetes for
identities it assigns itself. The proxy's `ServiceAccount` may impersonate any
user and any group, so a token able to name one would run with its privileges.
An identity provider that lets users influence their claims, or a claim mapping
without a prefix, would otherwise let a token:

- claim the `system:masters` group, and run as cluster-admin, bypassing RBAC
  entirely; or
- name a user such as `system:serviceaccount:kube-system:<name>`, and run as
  that `ServiceAccount`.

The proxy removes `system:` groups from every token it authenticates, before
forwarding the request, and logs each one it drops at `-v=2`.
`system:authenticated` is still added to every forwarded identity. A token whose
username starts with `system:` is refused with `403 Forbidden`, since there is
no identity left to run it as. Neither applies to
[token passthrough](./docs/tasks/token-passthrough.md), where the API server
authenticates the token itself.

**Upgrading:** deployments that granted cluster administrators access by putting
`system:masters` in the groups claim must move them to an ordinary group bound
to the `cluster-admin` `ClusterRole`, before upgrading:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: oidc-cluster-admins
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: Group
  name: k8s-cluster-admins
```

Unlike `system:masters`, membership granted this way is visible to and
revocable through RBAC.

## Impersonation Headers

Requests carrying any `Impersonate-*` header, such as those sent by
`kubectl --as` and `kubectl --as-group`, are refused with `403 Forbidden`. The
proxy forwards requests with its own `ServiceAccount`, which may impersonate
anyone, so the API server never learns who is really asking and cannot hold them
to their own impersonation rights. Every request runs as the identity of its
token, with the groups of its token or, with
[LDAP group augmentation](./docs/tasks/ldap-group-augmentation.md), of the
directory. The headers are refused rather than ignored, so that a command such
as `kubectl auth can-i --as=alice` fails instead of answering for the caller.

Requests forwarded with the caller's own token through
[token passthrough](./docs/tasks/token-passthrough.md) are not affected: the
API server authenticates the token itself and applies its own impersonation
rules to them.

## Development
*NOTE*: building kube-oidc-proxy requires Go version 1.17 or higher.

To help with development, there is a suite of tools you can use to deploy a
functioning proxy from source locally. You can read more
[here](./docs/tasks/development-testing.md).
