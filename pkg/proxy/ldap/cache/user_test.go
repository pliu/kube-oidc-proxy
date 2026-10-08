// Copyright Jetstack Ltd. See LICENSE for details.
package cache

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"
)

func TestUserRecordReadableRoundTrip(t *testing.T) {
	groups := []string{"Platform Administrators", "Developers", "Platform Administrators", "Grüppe: #1", " developers "}
	original := append([]string{}, groups...)
	r, err := NewUserRecord("alice@example.net", groups, "fingerprint", time.Date(2026, 10, 8, 14, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	data, err := EncodeUserRecord(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"username: alice@example.net", "- Developers", "- Platform Administrators", "configurationFingerprint: fingerprint", "lastSuccessfulLookup:"} {
		if !strings.Contains(string(data), text) {
			t.Errorf("missing readable field %q in:\n%s", text, data)
		}
	}
	decoded, err := DecodeUserRecord(data, r.Username, r.ConfigurationFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r, decoded) {
		t.Fatalf("round trip changed record: %#v -> %#v", r, decoded)
	}
	want := []string{" developers ", "Developers", "Grüppe: #1", "Platform Administrators"}
	if !reflect.DeepEqual(decoded.Groups, want) || !reflect.DeepEqual(groups, original) {
		t.Fatalf("group names changed or caller slice mutated: got %q, input %q", decoded.Groups, groups)
	}
	groups[0] = "changed"
	if !reflect.DeepEqual(r.Groups, want) {
		t.Fatal("record shares caller's group slice")
	}
}

func TestUserRecordEmptyResults(t *testing.T) {
	r, err := NewUserRecord("alice", nil, "fingerprint", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	data, err := EncodeUserRecord(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "groups: []") {
		t.Fatalf("empty groups must be explicit:\n%s", data)
	}
	decoded, err := DecodeUserRecord(data, "alice", "fingerprint")
	if err != nil || len(decoded.Groups) != 0 {
		t.Fatalf("empty result did not round trip: %#v, %v", decoded, err)
	}
}

func TestUserRecordRejectsInvalidDocuments(t *testing.T) {
	const valid = "version: 1\nusername: alice\ngroups: [Developers]\nconfigurationFingerprint: fingerprint\nlastSuccessfulLookup: '2026-10-08T14:00:00Z'\n"
	tests := map[string]string{
		"unknown field":       valid + "unexpected: value\n",
		"duplicate field":     valid + "username: bob\n",
		"version":             strings.Replace(valid, "version: 1", "version: 2", 1),
		"missing version":     strings.Replace(valid, "version: 1\n", "", 1),
		"missing groups":      strings.Replace(valid, "groups: [Developers]\n", "", 1),
		"null groups":         strings.Replace(valid, "[Developers]", "null", 1),
		"wrong groups type":   strings.Replace(valid, "[Developers]", "Developers", 1),
		"reserved group":      strings.Replace(valid, "Developers", "system:masters", 1),
		"empty group":         strings.Replace(valid, "[Developers]", "['']", 1),
		"wrong identity":      strings.Replace(valid, "username: alice", "username: bob", 1),
		"wrong configuration": strings.Replace(valid, "Fingerprint: fingerprint", "Fingerprint: different", 1),
		"missing time":        strings.Replace(valid, "lastSuccessfulLookup: '2026-10-08T14:00:00Z'\n", "", 1),
		"bad time":            strings.Replace(valid, "2026-10-08T14:00:00Z", "yesterday", 1),
		"empty":               "",
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeUserRecord([]byte(data), "alice", "fingerprint"); err == nil {
				t.Fatal("accepted invalid record")
			}
		})
	}
	if _, err := EncodeUserRecord(nil); err == nil {
		t.Fatal("accepted nil record")
	}
}

func TestUserConfigMapNames(t *testing.T) {
	tests := map[string]string{
		"alice":               "kube-oidc-proxy-user-alice",
		"alice@example.net":   "kube-oidc-proxy-user-alice-example.net",
		"Alice@Example.NET":   "kube-oidc-proxy-user-alice-example.net",
		"first.last@corp.com": "kube-oidc-proxy-user-first.last-corp.com",
		"corp\\alice_b":       "kube-oidc-proxy-user-corp-alice-b",
		"oidc:alice":          "kube-oidc-proxy-user-oidc-alice",
		".alice.":             "kube-oidc-proxy-user--alice",
		"a..b":                "kube-oidc-proxy-user-a--b",
		"a.-b":                "kube-oidc-proxy-user-a--b",
		"grüppe":              "kube-oidc-proxy-user-gr-ppe",
		"@@@":                 "kube-oidc-proxy-user",
	}
	for username, want := range tests {
		got, err := UserConfigMapName(username)
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v; want %q", username, got, err, want)
		}
		if errs := validation.IsDNS1123Subdomain(got); len(errs) != 0 {
			t.Errorf("%q: invalid ConfigMap name %q: %v", username, got, errs)
		}
	}

	// Readable names collide by design; the stored username tells them apart.
	a, _ := UserConfigMapName("alice@example.net")
	b, _ := UserConfigMapName("alice-example.net")
	if a != b {
		t.Fatalf("expected %q and %q to share a name", a, b)
	}

	long, err := UserConfigMapName(strings.Repeat("a", 300) + "@example.net")
	if err != nil || len(long) != validation.DNS1123SubdomainMaxLength || len(validation.IsDNS1123Subdomain(long)) != 0 {
		t.Fatalf("long username not cut to a valid name: %d %q %v", len(long), long, err)
	}
	cut, _ := UserConfigMapName(strings.Repeat("a", 231) + ".b")
	if len(validation.IsDNS1123Subdomain(cut)) != 0 {
		t.Fatalf("cut name ends badly: %q", cut)
	}

	if _, err := UserConfigMapName(" "); err == nil {
		t.Fatal("accepted empty username")
	}
}

func TestEncodeUserRecordNormalizesWithoutMutation(t *testing.T) {
	r, err := NewUserRecord("alice", nil, "fingerprint", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r.Groups = []string{"Z", "A", "Z"}
	r.LastSuccessfulLookup = r.LastSuccessfulLookup.In(time.FixedZone("offset", 3600))
	original := *r
	original.Groups = append([]string{}, r.Groups...)
	data, err := EncodeUserRecord(r)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*r, original) {
		t.Fatal("encoding mutated its input")
	}
	decoded, err := DecodeUserRecord(data, "alice", "fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded.Groups, []string{"A", "Z"}) || decoded.LastSuccessfulLookup.Location() != time.UTC {
		t.Fatalf("encoding did not normalize: %+v", decoded)
	}
	r.Version++
	if _, err := EncodeUserRecord(r); err == nil {
		t.Fatal("encoding silently replaced an unsupported version")
	}
}
