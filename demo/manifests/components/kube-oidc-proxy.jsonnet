local kube = import '../vendor/kube-prod-runtime/lib/kube.libsonnet';
local utils = import '../vendor/kube-prod-runtime/lib/utils.libsonnet';

local CONFIG_PATH = '/etc/kube-oidc-proxy';
local READINESS_PORT = 8080;

{
  p:: '',

  base_domain:: '.example.net',

  app:: 'kube-oidc-proxy',

  image:: 'quay.io/jetstack/kube-oidc-proxy:v0.3.0',

  name:: $.p + $.app,

  domain:: $.name + $.base_domain,

  namespace:: 'kube-oidc-proxy',

  labels:: {
    metadata+: {
      labels+: {
        app: $.app,
      },
    },
  },

  metadata:: $.labels {
    metadata+: {
      namespace: $.namespace,
    },
  },

  config:: {
    secureServing+: {
      tlsCertFile: CONFIG_PATH + '/tls/tls.crt',
      tlsKeyFile: CONFIG_PATH + '/tls/tls.key',
      port: 443,
    },

    oidc+: {
      clientID: 'kube-oidc-proxy',
      usernameClaim: 'email',
      issuerURL: 'https://myprovider',
      groupsClaim: 'groups',
      groupsPrefix: 'dex:',
    },
  },

  clusterRole: kube.ClusterRole($.name) + $.metadata {
    rules: [
      {
        apiGroups: [''],
        resources: ['users', 'groups', 'serviceaccounts'],
        verbs: ['impersonate'],
      },
      {
        apiGroups: ['authentication.k8s.io'],
        resources: ['userextras/scopes', 'tokenreviews'],
        verbs: ['impersonate', 'create'],
      },
    ],
  },

  serviceAccount: kube.ServiceAccount($.name) + $.metadata,

  clusterRoleBinding: kube.ClusterRoleBinding($.name) + $.metadata {
    roleRef_: $.clusterRole,
    subjects_+: [$.serviceAccount],
  },

  // The issuers the proxy trusts. Each takes the fields of a jwt entry of
  // kube-apiserver's --authentication-config.
  authnConfig:: {
    issuers: [{
      issuer: {
        url: $.config.oidc.issuerURL,
        audiences: [$.config.oidc.clientID],
      } + if std.objectHas($.config.oidc, 'ca') then
        { certificateAuthority: $.config.oidc.ca }
      else {},
      claimMappings: {
        username: {
          claim: $.config.oidc.usernameClaim,
          prefix: '',
        },
        groups: {
          claim: $.config.oidc.groupsClaim,
          prefix: $.config.oidc.groupsPrefix,
        },
      },
    }],
  },

  oidcSecret: kube.Secret($.p + 'kube-oidc-proxy-config') + $.metadata {
    data_+: {
      'authn.yaml': std.manifestYamlDoc($.authnConfig),
    },
  },

  deployment: kube.Deployment($.name) + $.metadata {
    local this = self,

    spec+: {
      replicas: 1,
      template+: {
        metadata+: {
          annotations+: {
            'secret/hash': std.md5(std.escapeStringJson($.oidcSecret)),
          },
        },
        spec+: {
          serviceAccountName: $.serviceAccount.metadata.name,
          containers_+: {
            kubeOIDCProxy: kube.Container($.app) {
              image: $.image,

              ports_+: {
                serving: { containerPort: $.config.secureServing.port },
                probe: { containerPort: READINESS_PORT },
              },

              readinessProbe: {
                httpGet: { path: '/ready', port: READINESS_PORT },
                initialDelaySeconds: 15,
                periodSeconds: 10,
              },
              command: [
                'kube-oidc-proxy',
                '--secure-port=' + $.config.secureServing.port,
                '--tls-cert-file=' + $.config.secureServing.tlsCertFile,
                '--tls-private-key-file=' + $.config.secureServing.tlsKeyFile,
                '--oidc-config-file=' + CONFIG_PATH + '/oidc/authn.yaml',
                '--token-passthrough',
              ],

              volumeMounts_+: {
                oidc: { mountPath: CONFIG_PATH + '/oidc', readOnly: true },
                serving: { mountPath: CONFIG_PATH + '/tls', readOnly: true },
              },
            },
          },

          volumes_+: {
            oidc: kube.SecretVolume($.oidcSecret),
            serving: {
              secret: {
                secretName: $.name + '-tls',
              },
            },
          },
        },
      },
    },
  },

  svc: kube.Service($.name) + $.metadata {
    target_pod: $.deployment.spec.template,
    port: $.config.secureServing.port,

    spec+: {
      ports: [{
        port: $.config.secureServing.port,
        targetPort: $.config.secureServing.port,
      }],

      sessionAffinity: 'None',
    },
  },
}
