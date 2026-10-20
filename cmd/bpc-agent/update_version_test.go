package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestUpdateBinaryMustReportSignedVersion(t *testing.T) {
	for _, tc := range []struct {
		output string
		ok     bool
	}{
		{"bpc-agent 0.18.4\r\n", true},
		{"bpc-agent 0.16.2\n", false},
		{"", false},
		{"0.18.4", false},
		{"bpc-agent 0.18.4\nextra output", false},
	} {
		err := validateUpdateVersionOutput(tc.output, "0.18.4")
		if (err == nil) != tc.ok {
			t.Fatalf("output %q: %v", tc.output, err)
		}
	}
}

func TestProbeUpdateVersion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture; Windows packaged EXE is verified in CI")
	}
	path := filepath.Join(t.TempDir(), "agent")
	for _, tc := range []struct {
		script string
		ok     bool
	}{
		{"#!/bin/sh\n[ \"$1\" = version ] || exit 9\nprintf 'bpc-agent 0.18.4\\n'\n", true},
		{"#!/bin/sh\nprintf 'bpc-agent 0.16.2\\n'\n", false},
		{"#!/bin/sh\nexit 1\n", false},
	} {
		if err := os.WriteFile(path, []byte(tc.script), 0700); err != nil {
			t.Fatal(err)
		}
		err := verifyUpdateVersion(context.Background(), path, "0.18.4")
		if (err == nil) != tc.ok {
			t.Fatalf("probe: %v", err)
		}
	}
	if err := verifyUpdateVersion(context.Background(), path+"-missing", "0.18.4"); err == nil {
		t.Fatal("missing binary accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifyUpdateVersion(ctx, path, "0.18.4"); err == nil {
		t.Fatal("cancelled probe accepted")
	}
}
