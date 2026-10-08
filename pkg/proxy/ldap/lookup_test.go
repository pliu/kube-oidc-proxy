// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"context"
	"reflect"
	"testing"
)

func TestSearchUserResolvesOneUserAndHonoursCancellation(t *testing.T) {
	c := connWithUsers([]string{"Full Group Name"}, map[string][]string{"alice@example.net": {"Full Group Name"}})
	d := newTestResolver(t, testConfig(), c)
	groups, err := d.searchUser(context.Background(), "alice@example.net")
	if err != nil || !reflect.DeepEqual(groups, []string{"Full Group Name"}) {
		t.Fatalf("%v %v", groups, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.searchUser(ctx, "alice@example.net"); err == nil {
		t.Fatal("canceled lookup succeeded")
	}
}
