// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Program tsp is a low-level Tailscale protocol tool for performing
// composable building block operations like generating keys and
// registering nodes.
package main

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"

	"github.com/bradfitz/tsp"
	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/hostinfo"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	machineKeyPrefix = "machine-privkey:"
	nodeKeyPrefix    = "node-privkey:"
	oldKeyPrefix     = "privkey:"
)

var globalArgs struct {
	// serverURL is the base URL of the coordination server (-s flag).
	// If empty, tsp.DefaultServerURL is used.
	serverURL string

	// controlKeyFile is a path to a file containing the server's
	// MachinePublic key in MarshalText form (--control-key flag).
	// When set, server key discovery is skipped.
	controlKeyFile string
}

func main() {
	args := os.Args[1:]
	if err := rootCmd.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	err := rootCmd.Run(context.Background())
	if errors.Is(err, flag.ErrHelp) {
		os.Exit(0)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

var rootCmd = &ffcli.Command{
	Name:       "tsp",
	ShortUsage: "tsp [-s url] <subcommand> [flags]",
	ShortHelp:  "Low-level Tailscale protocol tool.",
	FlagSet: (func() *flag.FlagSet {
		fs := flag.NewFlagSet("tsp", flag.ExitOnError)
		fs.StringVar(&globalArgs.serverURL, "s", "", "base URL of coordination server (default: "+tsp.DefaultServerURL+")")
		fs.StringVar(&globalArgs.controlKeyFile, "control-key", "", "file containing the server's public key (skips discovery)")
		return fs
	})(),
	Subcommands: []*ffcli.Command{
		newMachineKeyCmd,
		newNodeKeyCmd,
		newNodeCmd,
		registerCmd,
		mapCmd,
		discoverServerKeyCmd,
	},
	Exec: func(ctx context.Context, args []string) error {
		return flag.ErrHelp
	},
}

// new-machine-key

var newMachineKeyArgs struct {
	output string
}

var newMachineKeyCmd = &ffcli.Command{
	Name:       "new-machine-key",
	ShortUsage: "tsp new-machine-key [-o file]",
	ShortHelp:  "Generate a new machine key.",
	FlagSet: (func() *flag.FlagSet {
		fs := flag.NewFlagSet("new-machine-key", flag.ExitOnError)
		fs.StringVar(&newMachineKeyArgs.output, "o", "", "output file (default: stdout)")
		return fs
	})(),
	Exec: runNewMachineKey,
}

func runNewMachineKey(ctx context.Context, args []string) error {
	k := key.NewMachine()
	text := marshalMachineKey(k)
	text = append(text, '\n')
	return writeOutput(newMachineKeyArgs.output, text)
}

// new-node-key

var newNodeKeyArgs struct {
	output string
}

var newNodeKeyCmd = &ffcli.Command{
	Name:       "new-node-key",
	ShortUsage: "tsp new-node-key [-o file]",
	ShortHelp:  "Generate a new node key.",
	FlagSet: (func() *flag.FlagSet {
		fs := flag.NewFlagSet("new-node-key", flag.ExitOnError)
		fs.StringVar(&newNodeKeyArgs.output, "o", "", "output file (default: stdout)")
		return fs
	})(),
	Exec: runNewNodeKey,
}

func runNewNodeKey(ctx context.Context, args []string) error {
	k := key.NewNode()
	text := marshalNodeKey(k)
	text = append(text, '\n')
	return writeOutput(newNodeKeyArgs.output, text)
}

// discover-server-key

var discoverServerKeyArgs struct {
	output string
}

var discoverServerKeyCmd = &ffcli.Command{
	Name:       "discover-server-key",
	ShortUsage: "tsp [-s url] discover-server-key [-o file]",
	ShortHelp:  "Discover and print the coordination server's public key.",
	FlagSet: (func() *flag.FlagSet {
		fs := flag.NewFlagSet("discover-server-key", flag.ExitOnError)
		fs.StringVar(&discoverServerKeyArgs.output, "o", "", "output file (default: stdout)")
		return fs
	})(),
	Exec: runDiscoverServerKey,
}

func runDiscoverServerKey(ctx context.Context, args []string) error {
	k, err := tsp.DiscoverServerKey(ctx, globalArgs.serverURL)
	if err != nil {
		return err
	}
	text, err := k.MarshalText()
	if err != nil {
		return fmt.Errorf("marshaling server key: %w", err)
	}
	text = append(text, '\n')
	return writeOutput(discoverServerKeyArgs.output, text)
}

// nodeFile is the JSON structure for a consolidated node file
// containing all credentials and server info needed for register/map.
type nodeFile struct {
	NodeKey    string `json:"node_key"`
	MachineKey string `json:"machine_key"`
	ServerURL  string `json:"server_url"`
	ServerKey  string `json:"server_key"`
}

// readNodeFile reads a node JSON file and returns the parsed keys, server URL,
// and server public key.
func readNodeFile(path string) (_ key.NodePrivate, _ key.MachinePrivate, serverURL string, _ key.MachinePublic, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return key.NodePrivate{}, key.MachinePrivate{}, "", key.MachinePublic{}, err
	}
	var nf nodeFile
	if err := json.Unmarshal(data, &nf); err != nil {
		return key.NodePrivate{}, key.MachinePrivate{}, "", key.MachinePublic{}, fmt.Errorf("parsing node file %q: %w", path, err)
	}

	// Parse node key
	nkText := []byte(strings.TrimSpace(nf.NodeKey))
	if !bytes.HasPrefix(nkText, []byte(nodeKeyPrefix)) {
		return key.NodePrivate{}, key.MachinePrivate{}, "", key.MachinePublic{}, fmt.Errorf("node file %q: node_key does not have %q prefix", path, nodeKeyPrefix)
	}
	nkText = bytes.Replace(nkText, []byte(nodeKeyPrefix), []byte(oldKeyPrefix), 1)
	var nodeKey key.NodePrivate
	if err := nodeKey.UnmarshalText(nkText); err != nil {
		return key.NodePrivate{}, key.MachinePrivate{}, "", key.MachinePublic{}, fmt.Errorf("node file %q: parsing node_key: %w", path, err)
	}

	// Parse machine key
	mkText := []byte(strings.TrimSpace(nf.MachineKey))
	if !bytes.HasPrefix(mkText, []byte(machineKeyPrefix)) {
		return key.NodePrivate{}, key.MachinePrivate{}, "", key.MachinePublic{}, fmt.Errorf("node file %q: machine_key does not have %q prefix", path, machineKeyPrefix)
	}
	mkText = bytes.Replace(mkText, []byte(machineKeyPrefix), []byte(oldKeyPrefix), 1)
	var machineKey key.MachinePrivate
	if err := machineKey.UnmarshalText(mkText); err != nil {
		return key.NodePrivate{}, key.MachinePrivate{}, "", key.MachinePublic{}, fmt.Errorf("node file %q: parsing machine_key: %w", path, err)
	}

	// Parse server key
	var serverKey key.MachinePublic
	if err := serverKey.UnmarshalText([]byte(strings.TrimSpace(nf.ServerKey))); err != nil {
		return key.NodePrivate{}, key.MachinePrivate{}, "", key.MachinePublic{}, fmt.Errorf("node file %q: parsing server_key: %w", path, err)
	}

	return nodeKey, machineKey, nf.ServerURL, serverKey, nil
}

// new-node

var newNodeArgs struct {
	nodeKeyFile    string
	machineKeyFile string
	output         string
}

var newNodeCmd = &ffcli.Command{
	Name:       "new-node",
	ShortUsage: "tsp [-s url] [--control-key file] new-node [-n node-key-file] [-m machine-key-file] [-o output]",
	ShortHelp:  "Generate a new node JSON file with keys and server info.",
	FlagSet: (func() *flag.FlagSet {
		fs := flag.NewFlagSet("new-node", flag.ExitOnError)
		fs.StringVar(&newNodeArgs.nodeKeyFile, "n", "", "existing node key file (default: generate new)")
		fs.StringVar(&newNodeArgs.machineKeyFile, "m", "", "existing machine key file (default: generate new)")
		fs.StringVar(&newNodeArgs.output, "o", "", "output file (default: stdout)")
		return fs
	})(),
	Exec: runNewNode,
}

func runNewNode(ctx context.Context, args []string) error {
	var nodeKey key.NodePrivate
	if newNodeArgs.nodeKeyFile != "" {
		var err error
		nodeKey, err = readNodeKeyFile(newNodeArgs.nodeKeyFile)
		if err != nil {
			return fmt.Errorf("reading node key: %w", err)
		}
	} else {
		nodeKey = key.NewNode()
	}

	var machineKey key.MachinePrivate
	if newNodeArgs.machineKeyFile != "" {
		var err error
		machineKey, err = readMachineKeyFile(newNodeArgs.machineKeyFile)
		if err != nil {
			return fmt.Errorf("reading machine key: %w", err)
		}
	} else {
		machineKey = key.NewMachine()
	}

	serverURL := cmp.Or(globalArgs.serverURL, tsp.DefaultServerURL)

	var serverKey key.MachinePublic
	if globalArgs.controlKeyFile != "" {
		var err error
		serverKey, err = readControlKeyFile(globalArgs.controlKeyFile)
		if err != nil {
			return fmt.Errorf("reading control key: %w", err)
		}
	} else {
		var err error
		serverKey, err = tsp.DiscoverServerKey(ctx, serverURL)
		if err != nil {
			return fmt.Errorf("discovering server key: %w", err)
		}
	}

	serverKeyText, err := serverKey.MarshalText()
	if err != nil {
		return fmt.Errorf("marshaling server key: %w", err)
	}

	nf := nodeFile{
		NodeKey:    string(marshalNodeKey(nodeKey)),
		MachineKey: string(marshalMachineKey(machineKey)),
		ServerURL:  serverURL,
		ServerKey:  string(serverKeyText),
	}

	out, err := json.MarshalIndent(nf, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding node file: %w", err)
	}
	out = append(out, '\n')
	return writeOutput(newNodeArgs.output, out)
}

// register

var registerArgs struct {
	nodeFile  string
	output    string
	hostname  string
	ephemeral bool
	authKey   string
	tags      string
}

var registerCmd = &ffcli.Command{
	Name:       "register",
	ShortUsage: "tsp [-s url] register -n <node-file> [flags]",
	ShortHelp:  "Register a node key with a coordination server.",
	FlagSet: (func() *flag.FlagSet {
		fs := flag.NewFlagSet("register", flag.ExitOnError)
		fs.StringVar(&registerArgs.nodeFile, "n", "", "node JSON file (required)")
		fs.StringVar(&registerArgs.output, "o", "", "output file (default: stdout)")
		fs.StringVar(&registerArgs.hostname, "hostname", "", "hostname to register")
		fs.BoolVar(&registerArgs.ephemeral, "ephemeral", false, "register as ephemeral node")
		fs.StringVar(&registerArgs.authKey, "auth-key", "", "pre-authorized auth key or file containing one")
		fs.StringVar(&registerArgs.tags, "tags", "", "comma-separated ACL tags")
		return fs
	})(),
	Exec: runRegister,
}

func runRegister(ctx context.Context, args []string) error {
	if registerArgs.nodeFile == "" {
		return fmt.Errorf("flag -n (node file) is required")
	}

	nodeKey, machineKey, nfServerURL, serverKey, err := readNodeFile(registerArgs.nodeFile)
	if err != nil {
		return fmt.Errorf("reading node file: %w", err)
	}

	hi := hostinfo.New()
	if registerArgs.hostname != "" {
		hi.Hostname = registerArgs.hostname
	}

	var tags []string
	if registerArgs.tags != "" {
		tags = strings.Split(registerArgs.tags, ",")
	}

	authKey, err := resolveAuthKey(registerArgs.authKey)
	if err != nil {
		return err
	}

	client, err := tsp.NewClient(tsp.ClientOpts{
		ServerURL:  cmp.Or(globalArgs.serverURL, nfServerURL),
		MachineKey: machineKey,
	})
	if err != nil {
		return fmt.Errorf("creating client: %w", err)
	}
	defer client.Close()

	if globalArgs.controlKeyFile != "" {
		controlKey, err := readControlKeyFile(globalArgs.controlKeyFile)
		if err != nil {
			return fmt.Errorf("reading control key: %w", err)
		}
		client.SetControlPublicKey(controlKey)
	} else {
		client.SetControlPublicKey(serverKey)
	}

	resp, err := client.Register(ctx, tsp.RegisterOpts{
		NodeKey:   nodeKey,
		Hostinfo:  hi,
		Ephemeral: registerArgs.ephemeral,
		AuthKey:   authKey,
		Tags:      tags,
	})
	if err != nil {
		return err
	}

	out, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding response: %w", err)
	}
	out = append(out, '\n')

	if err := writeOutput(registerArgs.output, out); err != nil {
		return err
	}

	if resp.AuthURL != "" {
		fmt.Fprintf(os.Stderr, "AuthURL: %s\n", resp.AuthURL)
	}
	return nil
}

// map

var mapArgs struct {
	nodeFile string
	stream   bool
	peers    bool
	quiet    bool
	output   string
}

var mapCmd = &ffcli.Command{
	Name:       "map",
	ShortUsage: "tsp [-s url] map -n <node-file> [-stream]",
	ShortHelp:  "Send a map request to the coordination server.",
	FlagSet: (func() *flag.FlagSet {
		fs := flag.NewFlagSet("map", flag.ExitOnError)
		fs.StringVar(&mapArgs.nodeFile, "n", "", "node JSON file (required)")
		fs.BoolVar(&mapArgs.stream, "stream", false, "stream map responses")
		fs.BoolVar(&mapArgs.peers, "peers", true, "include peers in map response")
		fs.BoolVar(&mapArgs.quiet, "quiet", true, "suppress keepalives and handled c2n ping requests from output")
		fs.StringVar(&mapArgs.output, "o", "", "output file (default: stdout)")
		return fs
	})(),
	Exec: runMap,
}

func runMap(ctx context.Context, args []string) error {
	if mapArgs.nodeFile == "" {
		return fmt.Errorf("flag -n (node file) is required")
	}

	nodeKey, machineKey, nfServerURL, serverKey, err := readNodeFile(mapArgs.nodeFile)
	if err != nil {
		return fmt.Errorf("reading node file: %w", err)
	}

	if globalArgs.serverURL != "" && globalArgs.serverURL != nfServerURL {
		return fmt.Errorf("server URL mismatch: -s flag is %q but node file is for %q", globalArgs.serverURL, nfServerURL)
	}

	hi := hostinfo.New()

	client, err := tsp.NewClient(tsp.ClientOpts{
		ServerURL:  cmp.Or(globalArgs.serverURL, nfServerURL),
		MachineKey: machineKey,
	})
	if err != nil {
		return fmt.Errorf("creating client: %w", err)
	}
	defer client.Close()

	if globalArgs.controlKeyFile != "" {
		controlKey, err := readControlKeyFile(globalArgs.controlKeyFile)
		if err != nil {
			return fmt.Errorf("reading control key: %w", err)
		}
		client.SetControlPublicKey(controlKey)
	} else {
		client.SetControlPublicKey(serverKey)
	}

	session, err := client.Map(ctx, tsp.MapOpts{
		NodeKey:   nodeKey,
		Hostinfo:  hi,
		Stream:    mapArgs.stream,
		OmitPeers: !mapArgs.peers,
	})
	if err != nil {
		return err
	}
	defer session.Close()

	gotResponse := false
	for {
		resp, err := session.Next()
		if err == io.EOF {
			if !gotResponse {
				return fmt.Errorf("server returned no map response")
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading map response: %w", err)
		}
		gotResponse = true

		if pr := resp.PingRequest; pr != nil && pr.Types == "c2n" {
			if client.AnswerC2NPing(ctx, pr, session.NoiseRoundTrip) && mapArgs.quiet {
				resp.PingRequest = nil
			}
		}
		if mapArgs.quiet {
			resp.KeepAlive = false
		}

		if isZeroMapResponse(resp) {
			continue
		}

		out, err := json.MarshalIndent(resp, "", "  ")
		if err != nil {
			return fmt.Errorf("encoding response: %w", err)
		}
		out = append(out, '\n')
		if err := writeOutput(mapArgs.output, out); err != nil {
			return err
		}
	}
}

// marshalMachineKey serializes a MachinePrivate with a "machine-privkey:" prefix.
func marshalMachineKey(k key.MachinePrivate) []byte {
	text, err := k.MarshalText()
	if err != nil {
		panic(err) // MarshalText on key types never fails
	}
	return bytes.Replace(text, []byte(oldKeyPrefix), []byte(machineKeyPrefix), 1)
}

// marshalNodeKey serializes a NodePrivate with a "node-privkey:" prefix.
func marshalNodeKey(k key.NodePrivate) []byte {
	text, err := k.MarshalText()
	if err != nil {
		panic(err) // MarshalText on key types never fails
	}
	return bytes.Replace(text, []byte(oldKeyPrefix), []byte(nodeKeyPrefix), 1)
}

// readMachineKeyFile reads a machine key file, validates the "machine-privkey:" prefix,
// and returns the parsed MachinePrivate.
func readMachineKeyFile(path string) (key.MachinePrivate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return key.MachinePrivate{}, err
	}
	text := bytes.TrimSpace(data)
	if bytes.HasPrefix(text, []byte(nodeKeyPrefix)) {
		return key.MachinePrivate{}, fmt.Errorf("file %q contains a node key, not a machine key", path)
	}
	if !bytes.HasPrefix(text, []byte(machineKeyPrefix)) {
		return key.MachinePrivate{}, fmt.Errorf("file %q does not contain a valid machine key (expected %q prefix)", path, machineKeyPrefix)
	}
	text = bytes.Replace(text, []byte(machineKeyPrefix), []byte(oldKeyPrefix), 1)
	var k key.MachinePrivate
	if err := k.UnmarshalText(text); err != nil {
		return key.MachinePrivate{}, err
	}
	return k, nil
}

// readNodeKeyFile reads a node key file, validates the "node-privkey:" prefix,
// and returns the parsed NodePrivate.
func readNodeKeyFile(path string) (key.NodePrivate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return key.NodePrivate{}, err
	}
	text := bytes.TrimSpace(data)
	if bytes.HasPrefix(text, []byte(machineKeyPrefix)) {
		return key.NodePrivate{}, fmt.Errorf("file %q contains a machine key, not a node key", path)
	}
	if !bytes.HasPrefix(text, []byte(nodeKeyPrefix)) {
		return key.NodePrivate{}, fmt.Errorf("file %q does not contain a valid node key (expected %q prefix)", path, nodeKeyPrefix)
	}
	text = bytes.Replace(text, []byte(nodeKeyPrefix), []byte(oldKeyPrefix), 1)
	var k key.NodePrivate
	if err := k.UnmarshalText(text); err != nil {
		return key.NodePrivate{}, err
	}
	return k, nil
}

// readControlKeyFile reads a file containing a server's MachinePublic key
// in its MarshalText form (e.g. "mkey:...").
func readControlKeyFile(path string) (key.MachinePublic, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return key.MachinePublic{}, err
	}
	var k key.MachinePublic
	if err := k.UnmarshalText(bytes.TrimSpace(data)); err != nil {
		return key.MachinePublic{}, fmt.Errorf("parsing control key from %q: %w", path, err)
	}
	return k, nil
}

// resolveAuthKey returns the auth key from v. If v is empty, it returns "".
// If v starts with "tskey-", it's used directly. Otherwise v is treated as a
// filename and its contents are read and trimmed.
func resolveAuthKey(v string) (string, error) {
	if v == "" {
		return "", nil
	}
	if strings.HasPrefix(strings.TrimSpace(v), "tskey-") {
		return strings.TrimSpace(v), nil
	}
	data, err := os.ReadFile(v)
	if err != nil {
		return "", fmt.Errorf("reading auth key file: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

func writeOutput(path string, data []byte) error {
	if path == "" {
		_, err := os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// isZeroMapResponse reports whether all fields of resp are zero values.
func isZeroMapResponse(resp *tailcfg.MapResponse) bool {
	v := reflect.ValueOf(*resp)
	for i := range v.NumField() {
		if !v.Field(i).IsZero() {
			return false
		}
	}
	return true
}
