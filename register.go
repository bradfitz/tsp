// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"tailscale.com/control/ts2021"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// RegisterOpts contains options for registering a node.
type RegisterOpts struct {
	// NodeKey is the node's private key. Required.
	NodeKey key.NodePrivate

	// Hostinfo is the host information to send. Optional;
	// if nil, a minimal default is used.
	Hostinfo *tailcfg.Hostinfo

	// Ephemeral marks the node as ephemeral.
	Ephemeral bool

	// AuthKey is a pre-authorized auth key.
	AuthKey string

	// Tags is a list of ACL tags to request.
	Tags []string

	// Tailnet is the tailnet to register in.
	Tailnet string
}

// Register sends a registration request to the coordination server
// and returns the response.
func (c *Client) Register(ctx context.Context, opts RegisterOpts) (*tailcfg.RegisterResponse, error) {
	hi := opts.Hostinfo
	if hi == nil {
		hi = new(tailcfg.Hostinfo)
	}
	if len(opts.Tags) > 0 {
		hi.RequestTags = opts.Tags
	}

	regReq := tailcfg.RegisterRequest{
		Version:   tailcfg.CurrentCapabilityVersion,
		NodeKey:   opts.NodeKey.Public(),
		Hostinfo:  hi,
		Ephemeral: opts.Ephemeral,
		Tailnet:   opts.Tailnet,
	}
	if opts.AuthKey != "" {
		regReq.Auth = &tailcfg.RegisterResponseAuth{
			AuthKey: opts.AuthKey,
		}
	}

	body, err := json.Marshal(regReq)
	if err != nil {
		return nil, fmt.Errorf("encoding register request: %w", err)
	}

	nc, err := c.noiseClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("establishing noise connection: %w", err)
	}

	url := c.serverURL + "/machine/register"
	url = strings.Replace(url, "http:", "https:", 1)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating register request: %w", err)
	}
	ts2021.AddLBHeader(req, opts.NodeKey.Public())

	res, err := nc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("register request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		msg, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("register request: http %d: %.200s",
			res.StatusCode, strings.TrimSpace(string(msg)))
	}

	var resp tailcfg.RegisterResponse
	if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
		return nil, fmt.Errorf("decoding register response: %w", err)
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("register: %s", resp.Error)
	}
	return &resp, nil
}
