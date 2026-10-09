// Copyright Jetstack Ltd. See LICENSE for details.
package logging

import (
	"fmt"
	"maps"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"k8s.io/apiserver/pkg/authentication/user"
)

const timestampLayout = "2006-01-02T15:04:05-0700"

// logs the request.
//
// Every field that came from the request is quoted with %q. Names, groups and
// extras are claim values, which an identity provider is free to put a newline
// or a bracket in, and the forwarded-for header is whatever the client sent.
// Written out plainly, a user called "alice] URI:/ inbound:[system:masters" -
// or one carrying a newline - writes whatever it likes into this log, and a log
// the requester can forge entries in says nothing about who did what. Quoting
// also renders the escapes, so a name with a newline in it stays on one line
// and is still readable.
//
// The address the connection came from is not quoted: it is taken from the
// socket rather than from anything the client sent.
func LogSuccessfulRequest(req *http.Request, inboundUser user.Info) {
	remoteAddr := remoteHost(req.RemoteAddr)

	xFwdFor := findXForwardedFor(req.Header, remoteAddr)

	fmt.Printf("[%s] AuSuccess src:[%s / %q] URI:%q inbound:[%q / %q / %s]\n", time.Now().Format(timestampLayout), remoteAddr, xFwdFor, req.RequestURI, inboundUser.GetName(), strings.Join(inboundUser.GetGroups(), "|"), quotedExtra(inboundUser.GetExtra()))
}

// quotedExtra renders the extra fields of a user as quoted key=value pairs,
// each followed by a space, as the surrounding log line has always written
// them. Both halves are quoted: an extra is named by the caller as much as it
// is valued by them.
//
// Written in key order, so that the same identity always logs the same way and
// lines can be compared or searched for exactly.
func quotedExtra(extra map[string][]string) string {
	var out strings.Builder

	for _, key := range slices.Sorted(maps.Keys(extra)) {
		fmt.Fprintf(&out, "%q=%q ", key, strings.Join(extra[key], "|"))
	}

	return out.String()
}

// remoteHost returns the host of a connection's remote address, without its
// port. An address with no port is returned as it is.
func remoteHost(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}

	return remoteAddr
}

// determines if the x-forwarded-for header is present, if so remove
// the remoteaddr since it is repetitive
func findXForwardedFor(headers http.Header, remoteAddr string) string {
	xFwdFor := headers.Get("x-forwarded-for")
	// clean off remoteaddr from x-forwarded-for
	if xFwdFor != "" {

		newXFwdFor := ""
		oneFound := false
		xFwdForIps := strings.Split(xFwdFor, ",")

		for _, ip := range xFwdForIps {
			ip = strings.TrimSpace(ip)

			if ip != remoteAddr {
				newXFwdFor = newXFwdFor + ip + ", "
				oneFound = true
			}

		}

		if oneFound {
			newXFwdFor = newXFwdFor[0 : len(newXFwdFor)-2]
		}

		xFwdFor = newXFwdFor

	}

	return xFwdFor
}

// logs the failed request
func LogFailedRequest(req *http.Request) {
	remoteAddr := remoteHost(req.RemoteAddr)

	fmt.Printf("[%s] AuFail src:[%s / %q] URI:%q\n", time.Now().Format(timestampLayout), remoteAddr, req.Header.Get("x-forwarded-for"), req.RequestURI)
}
