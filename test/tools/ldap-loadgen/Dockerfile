# Copyright Jetstack Ltd. See LICENSE for details.
FROM alpine:3.20

LABEL description="Drives the LDAP group augmentation e2e test and reports its latency."

RUN apk --no-cache add ca-certificates

COPY ./bin/ldap-loadgen /usr/bin/ldap-loadgen

ENTRYPOINT ["/usr/bin/ldap-loadgen"]
