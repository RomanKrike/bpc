//go:build !windows

package main

import (
	"context"
	"errors"
	"log"

	"github.com/RomanKrike/bpc/internal/agentctl"
)

func runEmbeddedWireGuard(
	context.Context,
	agentctl.RuntimeConfig,
	agentctl.WireGuardProfile,
	*log.Logger,
	func(tunnelTelemetry),
) error {
	return errors.New("embedded WireGuard is available on Windows only")
}
