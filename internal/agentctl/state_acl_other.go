//go:build !windows

package agentctl

func preserveStateACL(string, string) error { return nil }
