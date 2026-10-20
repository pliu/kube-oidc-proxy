# Copyright Jetstack Ltd. See LICENSE for details.
FROM debian:bookworm-slim

LABEL description="OpenLDAP with the memberof overlay, for the LDAP group augmentation e2e test."

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y ldap-utils slapd \
    && apt-get clean \
    && find /var/lib/apt/lists -mindepth 1 -delete \
    && find /var/lib/ldap -mindepth 1 -delete

COPY slapd.conf /etc/ldap/slapd-e2e.conf
COPY entrypoint.sh /usr/local/bin/ldap-entrypoint

EXPOSE 6443/tcp
ENTRYPOINT ["/usr/local/bin/ldap-entrypoint"]
