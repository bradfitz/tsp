// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package tsp provides a client for speaking the Tailscale protocol
// to a coordination server over Noise.
package tsp

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"

	"tailscale.com/control/ts2021"
	"tailscale.com/ipn"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// ClientOpts contains options for creating a new Client.
type ClientOpts struct {
	// ServerURL is the URL of the coordination server.
	// If empty, ipn.DefaultControlURL is used.
	ServerURL string

	// MachineKey is this node's machine private key. Required.
	MachineKey key.MachinePrivate

	// Logf is the log function. If nil, logger.Discard is used.
	Logf logger.Logf
}

// Client is a Tailscale protocol client that speaks to a coordination
// server over Noise.
type Client struct {
	nc        *ts2021.Client
	serverURL string
	logf      logger.Logf
}

// NewClient creates a new Client that connects to the coordination server
// specified in opts.
func NewClient(ctx context.Context, opts ClientOpts) (*Client, error) {
	serverURL := cmp.Or(opts.ServerURL, ipn.DefaultControlURL)
	logf := opts.Logf
	if logf == nil {
		logf = logger.Discard
	}
	if opts.MachineKey.IsZero() {
		return nil, fmt.Errorf("MachineKey is required")
	}

	// Fetch the server's public key.
	keysURL := serverURL + "/key?v=" + strconv.Itoa(int(tailcfg.CurrentCapabilityVersion))
	req, err := http.NewRequestWithContext(ctx, "GET", keysURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating key request: %w", err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching server key: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("fetching server key: %s", res.Status)
	}
	var keys struct {
		PublicKey key.MachinePublic
	}
	if err := json.NewDecoder(res.Body).Decode(&keys); err != nil {
		return nil, fmt.Errorf("decoding server key: %w", err)
	}

	nc, err := ts2021.NewClient(ts2021.ClientOpts{
		ServerURL:     serverURL,
		PrivKey:       opts.MachineKey,
		ServerPubKey:  keys.PublicKey,
		Dialer:        tsdial.NewFromFuncForDebug(logf, (&net.Dialer{}).DialContext),
		Logf:          logf,
	})
	if err != nil {
		return nil, fmt.Errorf("creating noise client: %w", err)
	}

	return &Client{
		nc:        nc,
		serverURL: serverURL,
		logf:      logf,
	}, nil
}

// Close closes the client and releases resources.
func (c *Client) Close() error {
	c.nc.Close()
	return nil
}
