// Copyright Jetstack Ltd. See LICENSE for details.
package util

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// HashJSON returns the hex SHA-256 of the JSON encoding of v. Callers pass
// plain strings, slices and structs of them, which always encode, and rely on
// the result being stable for equal values.
func HashJSON(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
