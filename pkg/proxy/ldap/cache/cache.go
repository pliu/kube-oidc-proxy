// Copyright Jetstack Ltd. See LICENSE for details.
// Package cache persists readable, versioned per-user LDAP records in ConfigMaps.
package cache

import "errors"

var ErrNotFound = errors.New("no persisted user record found")
