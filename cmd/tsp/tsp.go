// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Program tsp is a low-level Tailscale protocol tool for performing
// composable building block operations like generating keys and
// registering nodes.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/bradfitz/tsp"
	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/hostinfo"
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
		registerCmd,
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

// register

var registerArgs struct {
	nodeKeyFile    string
	machineKeyFile string
	output         string
	hostname       string
	ephemeral      bool
	authKey        string
	tags           string
	tailnet        string
}

var registerCmd = &ffcli.Command{
	Name:       "register",
	ShortUsage: "tsp [-s url] register -n <node-key-file> -m <machine-key-file> [flags]",
	ShortHelp:  "Register a node key with a coordination server.",
	FlagSet: (func() *flag.FlagSet {
		fs := flag.NewFlagSet("register", flag.ExitOnError)
		fs.StringVar(&registerArgs.nodeKeyFile, "n", "", "node key file (required)")
		fs.StringVar(&registerArgs.machineKeyFile, "m", "", "machine key file (required)")
		fs.StringVar(&registerArgs.output, "o", "", "output file (default: stdout)")
		fs.StringVar(&registerArgs.hostname, "hostname", "", "hostname to register")
		fs.BoolVar(&registerArgs.ephemeral, "ephemeral", false, "register as ephemeral node")
		fs.StringVar(&registerArgs.authKey, "auth-key", "", "pre-authorized auth key")
		fs.StringVar(&registerArgs.tags, "tags", "", "comma-separated ACL tags")
		fs.StringVar(&registerArgs.tailnet, "tailnet", "", "tailnet to register in")
		return fs
	})(),
	Exec: runRegister,
}

func runRegister(ctx context.Context, args []string) error {
	if registerArgs.nodeKeyFile == "" {
		return fmt.Errorf("flag -n (node key file) is required")
	}
	if registerArgs.machineKeyFile == "" {
		return fmt.Errorf("flag -m (machine key file) is required")
	}

	nodeKey, err := readNodeKeyFile(registerArgs.nodeKeyFile)
	if err != nil {
		return fmt.Errorf("reading node key: %w", err)
	}
	machineKey, err := readMachineKeyFile(registerArgs.machineKeyFile)
	if err != nil {
		return fmt.Errorf("reading machine key: %w", err)
	}

	hi := hostinfo.New()
	if registerArgs.hostname != "" {
		hi.Hostname = registerArgs.hostname
	}

	var tags []string
	if registerArgs.tags != "" {
		tags = strings.Split(registerArgs.tags, ",")
	}

	client, err := tsp.NewClient(tsp.ClientOpts{
		ServerURL:  globalArgs.serverURL,
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
	}

	resp, err := client.Register(ctx, tsp.RegisterOpts{
		NodeKey:   nodeKey,
		Hostinfo:  hi,
		Ephemeral: registerArgs.ephemeral,
		AuthKey:   registerArgs.authKey,
		Tags:      tags,
		Tailnet:   registerArgs.tailnet,
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

func writeOutput(path string, data []byte) error {
	if path == "" {
		_, err := os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, 0600)
}
