// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"tailscale.com/types/key"
)

const (
	machineKeyPrefix = "machine-privkey:"
	nodeKeyPrefix    = "node-privkey:"
	oldKeyPrefix     = "privkey:"
)

// ServerInfo identifies a coordination server by its URL and Noise public key.
type ServerInfo struct {
	// URL is the base URL of the coordination server
	// (e.g. "https://controlplane.tailscale.com").
	URL string `json:"server_url"`

	// Key is the server's Noise public key, used to establish an encrypted
	// channel between the client and the coordination server.
	Key key.MachinePublic `json:"server_key"`
}

// NodeFile is the JSON structure for a node credentials file. It contains
// the private keys that authenticate a node to a coordination server.
//
// Example:
//
//	{
//	  "node_key": "node-privkey:...",
//	  "machine_key": "machine-privkey:...",
//	  "server_url": "https://controlplane.tailscale.com",
//	  "server_key": "mkey:..."
//	}
type NodeFile struct {
	// NodeKey is the node's WireGuard private key in "node-privkey:..." format.
	// The corresponding public key identifies this node to other peers.
	NodeKey string `json:"node_key"`

	// MachineKey is the machine's private key in "machine-privkey:..." format.
	// It authenticates this machine to the coordination server over Noise.
	MachineKey string `json:"machine_key"`

	ServerInfo // server_url and server_key
}

// ReadNodeFile reads a node JSON file and returns the parsed private keys
// and server info.
func ReadNodeFile(path string) (nodeKey key.NodePrivate, machineKey key.MachinePrivate, server ServerInfo, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return key.NodePrivate{}, key.MachinePrivate{}, ServerInfo{}, err
	}
	var nf NodeFile
	if err := json.Unmarshal(data, &nf); err != nil {
		return key.NodePrivate{}, key.MachinePrivate{}, ServerInfo{}, fmt.Errorf("parsing node file %q: %w", path, err)
	}

	nodeKey, err = ParseNodeKey(nf.NodeKey)
	if err != nil {
		return key.NodePrivate{}, key.MachinePrivate{}, ServerInfo{}, fmt.Errorf("node file %q: %w", path, err)
	}

	machineKey, err = ParseMachineKey(nf.MachineKey)
	if err != nil {
		return key.NodePrivate{}, key.MachinePrivate{}, ServerInfo{}, fmt.Errorf("node file %q: %w", path, err)
	}

	return nodeKey, machineKey, nf.ServerInfo, nil
}

// WriteNodeFile writes a node JSON file with the given private keys and
// server info. The file is created with mode 0600.
func WriteNodeFile(path string, nodeKey key.NodePrivate, machineKey key.MachinePrivate, server ServerInfo) error {
	nf := NodeFile{
		NodeKey:    string(MarshalNodeKey(nodeKey)),
		MachineKey: string(MarshalMachineKey(machineKey)),
		ServerInfo: server,
	}

	out, err := json.MarshalIndent(nf, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding node file: %w", err)
	}
	out = append(out, '\n')
	return os.WriteFile(path, out, 0600)
}

// MarshalMachineKey serializes a machine private key with a
// "machine-privkey:" prefix, distinguishing it from node keys.
func MarshalMachineKey(k key.MachinePrivate) []byte {
	text, err := k.MarshalText()
	if err != nil {
		panic(err) // MarshalText on key types never fails
	}
	return bytes.Replace(text, []byte(oldKeyPrefix), []byte(machineKeyPrefix), 1)
}

// MarshalNodeKey serializes a node private key with a "node-privkey:" prefix,
// distinguishing it from machine keys.
func MarshalNodeKey(k key.NodePrivate) []byte {
	text, err := k.MarshalText()
	if err != nil {
		panic(err) // MarshalText on key types never fails
	}
	return bytes.Replace(text, []byte(oldKeyPrefix), []byte(nodeKeyPrefix), 1)
}

// ParseNodeKey parses a node private key from its "node-privkey:..." text form.
func ParseNodeKey(s string) (key.NodePrivate, error) {
	text := []byte(strings.TrimSpace(s))
	if !bytes.HasPrefix(text, []byte(nodeKeyPrefix)) {
		return key.NodePrivate{}, fmt.Errorf("does not have %q prefix", nodeKeyPrefix)
	}
	text = bytes.Replace(text, []byte(nodeKeyPrefix), []byte(oldKeyPrefix), 1)
	var k key.NodePrivate
	if err := k.UnmarshalText(text); err != nil {
		return key.NodePrivate{}, err
	}
	return k, nil
}

// ParseMachineKey parses a machine private key from its "machine-privkey:..." text form.
func ParseMachineKey(s string) (key.MachinePrivate, error) {
	text := []byte(strings.TrimSpace(s))
	if !bytes.HasPrefix(text, []byte(machineKeyPrefix)) {
		return key.MachinePrivate{}, fmt.Errorf("does not have %q prefix", machineKeyPrefix)
	}
	text = bytes.Replace(text, []byte(machineKeyPrefix), []byte(oldKeyPrefix), 1)
	var k key.MachinePrivate
	if err := k.UnmarshalText(text); err != nil {
		return key.MachinePrivate{}, err
	}
	return k, nil
}
