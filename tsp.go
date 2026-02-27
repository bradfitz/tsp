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
	"sync"

	"tailscale.com/control/ts2021"
	"tailscale.com/ipn"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// DefaultServerURL is the default coordination server base URL,
// used when ClientOpts.ServerURL is empty.
const DefaultServerURL = ipn.DefaultControlURL

// ClientOpts contains options for creating a new Client.
type ClientOpts struct {
	// ServerURL is the base URL of the coordination server
	// (e.g. "https://controlplane.tailscale.com").
	// If empty, DefaultServerURL is used.
	ServerURL string

	// MachineKey is this node's machine private key. Required.
	MachineKey key.MachinePrivate

	// Logf is the log function. If nil, logger.Discard is used.
	Logf logger.Logf
}

// Client is a Tailscale protocol client that speaks to a coordination
// server over Noise.
type Client struct {
	opts      ClientOpts
	serverURL string
	logf      logger.Logf

	mu        sync.Mutex
	nc        *ts2021.Client    // nil until noiseClient called
	serverPub key.MachinePublic // zero until set or discovered
}

// NewClient creates a new Client configured to talk to the coordination server
// specified in opts. It performs no I/O; the server's public key is discovered
// lazily on first use or can be set explicitly via SetControlPublicKey.
func NewClient(opts ClientOpts) (*Client, error) {
	if opts.MachineKey.IsZero() {
		return nil, fmt.Errorf("MachineKey is required")
	}
	logf := opts.Logf
	if logf == nil {
		logf = logger.Discard
	}
	return &Client{
		opts:      opts,
		serverURL: cmp.Or(opts.ServerURL, DefaultServerURL),
		logf:      logf,
	}, nil
}

// SetControlPublicKey sets the server's public key, bypassing lazy discovery.
// Any existing noise client is invalidated and will be re-created on next use.
func (c *Client) SetControlPublicKey(k key.MachinePublic) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.serverPub = k
	c.nc = nil
}

// DiscoverServerKey fetches the server's public key from the coordination
// server and stores it for subsequent use. Any existing noise client is
// invalidated.
func (c *Client) DiscoverServerKey(ctx context.Context) (key.MachinePublic, error) {
	k, err := DiscoverServerKey(ctx, c.serverURL)
	if err != nil {
		return key.MachinePublic{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.serverPub = k
	c.nc = nil
	return k, nil
}

// DiscoverServerKey fetches the coordination server's public key from the
// given server URL. It is a standalone function that requires no client state.
func DiscoverServerKey(ctx context.Context, serverURL string) (key.MachinePublic, error) {
	serverURL = cmp.Or(serverURL, DefaultServerURL)
	keysURL := serverURL + "/key?v=" + strconv.Itoa(int(tailcfg.CurrentCapabilityVersion))
	req, err := http.NewRequestWithContext(ctx, "GET", keysURL, nil)
	if err != nil {
		return key.MachinePublic{}, fmt.Errorf("creating key request: %w", err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return key.MachinePublic{}, fmt.Errorf("fetching server key: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return key.MachinePublic{}, fmt.Errorf("fetching server key: %s", res.Status)
	}
	var keys struct {
		PublicKey key.MachinePublic
	}
	if err := json.NewDecoder(res.Body).Decode(&keys); err != nil {
		return key.MachinePublic{}, fmt.Errorf("decoding server key: %w", err)
	}
	return keys.PublicKey, nil
}

// noiseClient returns the ts2021 noise client, creating it lazily if needed.
// If the server's public key is not yet known, it is discovered via HTTP.
func (c *Client) noiseClient(ctx context.Context) (*ts2021.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.nc != nil {
		return c.nc, nil
	}

	if c.serverPub.IsZero() {
		// Discover server key without holding the lock, to avoid blocking
		// other callers during the HTTP request.
		c.mu.Unlock()
		k, err := DiscoverServerKey(ctx, c.serverURL)
		c.mu.Lock()
		if err != nil {
			return nil, err
		}
		// Re-check: another goroutine may have set it while we were unlocked.
		if c.serverPub.IsZero() {
			c.serverPub = k
		}
		// If nc was created by another goroutine while unlocked, use it.
		if c.nc != nil {
			return c.nc, nil
		}
	}

	nc, err := ts2021.NewClient(ts2021.ClientOpts{
		ServerURL:    c.serverURL,
		PrivKey:      c.opts.MachineKey,
		ServerPubKey: c.serverPub,
		Dialer:       tsdial.NewFromFuncForDebug(c.logf, (&net.Dialer{}).DialContext),
		Logf:         c.logf,
	})
	if err != nil {
		return nil, fmt.Errorf("creating noise client: %w", err)
	}
	c.nc = nc
	return nc, nil
}

// Close closes the client and releases resources.
func (c *Client) Close() error {
	c.mu.Lock()
	nc := c.nc
	c.nc = nil
	c.mu.Unlock()
	if nc != nil {
		nc.Close()
	}
	return nil
}
