# Leader Election

kube-oidc-proxy elects one of its replicas leader. The replicas contend for a
[Lease](https://kubernetes.io/docs/concepts/architecture/leases/) in the
`coordination.k8s.io` API group, and whichever holds it leads. A single replica
simply elects itself.

Every replica serves requests whether or not it leads. Leadership does not yet
change what any replica does: it is reported, and is there for work that should
happen on one replica only.

## Configuring it

Leader election is on by default, and needs nothing but the
[permissions below](#rbac): the Lease is named `kube-oidc-proxy` and lives in
the namespace the proxy runs in.

Running the proxy outside a cluster - against a kubeconfig on a workstation,
say - there is no namespace to default to. Either name one with
`--leader-elect-resource-namespace`, or turn election off with
`--leader-elect=false`.

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--leader-elect` | `true` | Take part in electing a leader. Set to `false` to run outside a cluster. |
| `--leader-elect-resource-name` | `kube-oidc-proxy` | The name of the Lease. |
| `--leader-elect-resource-namespace` | the pod's namespace | The namespace of the Lease. Taken from `$POD_NAMESPACE` if set, and from the service account namespace file otherwise. |
| `--leader-elect-lease-duration` | `15s` | How long a Lease that is not renewed is honoured, and so the longest a leader that has stopped can go unreplaced. |
| `--leader-elect-renew-deadline` | `10s` | How long the leader keeps trying to renew before it gives up leading. Must be shorter than the lease duration. |
| `--leader-elect-retry-period` | `2s` | How often replicas try to take or renew the Lease. |

The Helm chart names the Lease after the release, puts it in the release
namespace, and grants the permissions below. `leaderElection.enabled: false`
turns election off and leaves the permissions out. The manifest in
`deploy/yaml` grants them too.

A replica starts contending only once it is serving, so one that fails to start
never leads. On shutdown the leader releases the Lease, so a rollout hands
leadership over at once rather than a lease duration later. A leader that fails
to renew in time stops leading and goes back to contending, without restarting.

## RBAC

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: kube-oidc-proxy-leader-election
  namespace: kube-oidc-proxy
rules:
- apiGroups: ["coordination.k8s.io"]
  resources: ["leases"]
  verbs: ["create"]
- apiGroups: ["coordination.k8s.io"]
  resources: ["leases"]
  resourceNames: ["kube-oidc-proxy"]
  verbs: ["get", "update"]
```

Bind it to the proxy's service account with a RoleBinding. Without it, the
proxy still serves requests, but no replica can lead and each logs a failure to
take the Lease every retry period.

## Observing it

The leader logs `became leader`, and the Lease names it:

```
$ kubectl -n kube-oidc-proxy get lease kube-oidc-proxy -o jsonpath='{.spec.holderIdentity}'
kube-oidc-proxy-7d9c8b6f5-x2k4q_2f1c...
```

Each replica also publishes `kube_oidc_proxy_is_leader` on the metrics
endpoint: `1` on the leader and `0` elsewhere. Summed across replicas it should
be `1`:

```
sum(kube_oidc_proxy_is_leader) != 1
```

firing for longer than a lease duration means there is no leader, or that more
than one replica believes it is.
