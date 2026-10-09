#!/bin/sh
# Copyright Jetstack Ltd. See LICENSE for details.

# Serves LDAPS on 6443 with the certificate mounted at /tls, after loading
# /data/directory.ldif. The entries are added online rather than with slapadd,
# so that the memberof overlay fills in memberOf as it would for a live
# directory. /run/slapd/loaded marks the directory as ready.
set -eu

config=/etc/ldap/slapd-e2e.conf
rootdn="cn=admin,dc=example,dc=test"
rootpw=e2e-ldap-password

mkdir -p /run/slapd /var/lib/ldap
cp /tls/cert.pem /tls/key.pem /run/slapd/
chmod 0600 /run/slapd/key.pem
chown -R openldap:openldap /run/slapd /var/lib/ldap

# slapd sizes its connection table from the open file limit. containerd, as
# kind runs it, leaves that at about a billion, and slapd runs out of memory.
ulimit -n 4096

slapd -d 0 -u openldap -g openldap -f "$config" -h "ldapi:/// ldaps://0.0.0.0:6443" &
slapd_pid=$!
trap 'kill "$slapd_pid" 2>/dev/null' TERM INT

attempt=0
until ldapsearch -x -H ldapi:/// -D "$rootdn" -w "$rootpw" -b "" -s base >/dev/null 2>&1; do
	attempt=$((attempt + 1))
	if [ "$attempt" -ge 60 ]; then
		echo "slapd did not start" >&2
		exit 1
	fi
	sleep 0.5
done

start=$(date +%s)
ldapadd -x -H ldapi:/// -D "$rootdn" -w "$rootpw" -f /data/directory.ldif >/dev/null
echo "loaded /data/directory.ldif in $(($(date +%s) - start))s"
touch /run/slapd/loaded

wait "$slapd_pid"
