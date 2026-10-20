package main

import (
	"context"
	"strings"
	"testing"
)

func TestRelayCommandHasNoImplicitTrustOrTLS(t *testing.T) {
	for _, args := range [][]string{nil, {"--cluster", "cluster"}, {"--issuer-public-key", "not-base64"}, {"--issuer-public-key", strings.Repeat("A", 43) + "=", "--cluster", "cluster"}} {
		if err := serve(context.Background(), args); err == nil {
			t.Fatal("relay started without complete explicit trust/TLS")
		}
	}
}
