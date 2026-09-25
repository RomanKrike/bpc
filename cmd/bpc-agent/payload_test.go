package main

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestExtractPayloadUsesLastMarker(t *testing.T) {
	first := base64.StdEncoding.EncodeToString([]byte("old"))
	second := base64.StdEncoding.EncodeToString([]byte("new"))
	data := []byte(
		"MZ" +
			wintunPayloadStart + first + wintunPayloadEnd +
			wintunPayloadStart + second + wintunPayloadEnd,
	)
	got, err := extractPayload(data, wintunPayloadStart, wintunPayloadEnd)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("new")) {
		t.Fatalf("unexpected payload: %q", got)
	}
}
