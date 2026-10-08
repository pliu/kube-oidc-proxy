// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"context"
	"reflect"
	"testing"
)

func TestStandaloneLookupWithoutSweep(t *testing.T) {
	c := connWithUsers([]string{"Full Group Name"}, map[string][]string{"alice@example.net": {"Full Group Name"}})
	d := newTestResolver(t, testConfig(), c)
	groups, found, err := d.searchUser(context.Background(), "alice@example.net")
	if err != nil || !found || !reflect.DeepEqual(groups, []string{"Full Group Name"}) {
		t.Fatalf("%v %v %v", groups, found, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := d.searchUser(ctx, "alice@example.net"); err == nil {
		t.Fatal("canceled lookup succeeded")
	}
}
