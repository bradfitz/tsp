// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tailscale.com/types/key"
)

func hasPrefix(s, prefix string) bool {
	return strings.HasPrefix(s, prefix)
}

func TestNodeFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node.json")

	nodeKey := key.NewNode()
	machineKey := key.NewMachine()
	server := ServerInfo{
		URL: "https://controlplane.tailscale.com",
		Key: key.NewMachine().Public(),
	}

	if err := WriteNodeFile(path, nodeKey, machineKey, server); err != nil {
		t.Fatalf("WriteNodeFile: %v", err)
	}

	gotNodeKey, gotMachineKey, gotServer, err := ReadNodeFile(path)
	if err != nil {
		t.Fatalf("ReadNodeFile: %v", err)
	}
	if !gotNodeKey.Equal(nodeKey) {
		t.Errorf("node key mismatch")
	}
	if !gotMachineKey.Equal(machineKey) {
		t.Errorf("machine key mismatch")
	}
	if gotServer.URL != server.URL {
		t.Errorf("server URL = %q, want %q", gotServer.URL, server.URL)
	}
	if gotServer.Key != server.Key {
		t.Errorf("server key mismatch")
	}
}

// TestNodeFileFormat verifies that ReadNodeFile can parse a fixed JSON literal,
// ensuring we don't accidentally change the on-disk format.
func TestNodeFileFormat(t *testing.T) {
	const fileContents = `{
  "node_key": "node-privkey:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "machine_key": "machine-privkey:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
  "server_url": "https://controlplane.tailscale.com",
  "server_key": "mkey:1111111111111111111111111111111111111111111111111111111111111111"
}`
	dir := t.TempDir()
	path := filepath.Join(dir, "node.json")
	if err := os.WriteFile(path, []byte(fileContents), 0600); err != nil {
		t.Fatal(err)
	}

	nodeKey, machineKey, server, err := ReadNodeFile(path)
	if err != nil {
		t.Fatalf("ReadNodeFile: %v", err)
	}
	if nodeKey.IsZero() {
		t.Error("node key is zero")
	}
	if machineKey.IsZero() {
		t.Error("machine key is zero")
	}
	if server.URL != "https://controlplane.tailscale.com" {
		t.Errorf("server URL = %q", server.URL)
	}
	if server.Key.IsZero() {
		t.Error("server key is zero")
	}
}

// TestNodeFileWriteFormat verifies that WriteNodeFile produces the expected
// JSON field names and key prefixes.
func TestNodeFileWriteFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node.json")

	nodeKey := key.NewNode()
	machineKey := key.NewMachine()
	server := ServerInfo{
		URL: "https://example.com",
		Key: key.NewMachine().Public(),
	}

	if err := WriteNodeFile(path, nodeKey, machineKey, server); err != nil {
		t.Fatalf("WriteNodeFile: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// Parse as raw JSON to verify field names.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("parsing written JSON: %v", err)
	}

	for _, field := range []string{"node_key", "machine_key", "server_url", "server_key"} {
		if _, ok := raw[field]; !ok {
			t.Errorf("missing JSON field %q in written file", field)
		}
	}

	// Verify key prefixes.
	var nf NodeFile
	if err := json.Unmarshal(data, &nf); err != nil {
		t.Fatalf("parsing written NodeFile: %v", err)
	}
	const wantNodePrefix = "node-privkey:"
	if got := nf.NodeKey; !hasPrefix(got, wantNodePrefix) {
		t.Errorf("node_key prefix = %q, want %q prefix", got[:min(len(got), 20)], wantNodePrefix)
	}
	const wantMachinePrefix = "machine-privkey:"
	if got := nf.MachineKey; !hasPrefix(got, wantMachinePrefix) {
		t.Errorf("machine_key prefix = %q, want %q prefix", got[:min(len(got), 23)], wantMachinePrefix)
	}
}
