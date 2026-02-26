// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsp

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"tailscale.com/control/ts2021"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/zstdframe"
)

// MapOpts contains options for sending a map request.
type MapOpts struct {
	// NodeKey is the node's private key. Required.
	NodeKey key.NodePrivate

	// Hostinfo is the host information to send. Optional;
	// if nil, a minimal default is used.
	Hostinfo *tailcfg.Hostinfo

	// Stream is whether to receive multiple MapResponses over
	// the same HTTP connection.
	Stream bool

	// OmitPeers is whether the client is okay with the Peers list
	// being omitted in the response.
	OmitPeers bool
}

// MapSession wraps an in-progress map response stream. Call Next to read
// each framed, zstd-compressed MapResponse. Call Close when done.
type MapSession struct {
	res    *http.Response
	stream bool
	read   int // number of responses read
}

// Next reads and returns the next MapResponse from the stream.
// For non-streaming sessions, the first call returns the single response
// and subsequent calls return io.EOF.
// For streaming sessions, Next blocks until the next response arrives
// or the server closes the connection.
func (s *MapSession) Next() (*tailcfg.MapResponse, error) {
	if !s.stream && s.read > 0 {
		return nil, io.EOF
	}

	// Read 4-byte little-endian frame size.
	var sizeBytes [4]byte
	if _, err := io.ReadFull(s.res.Body, sizeBytes[:]); err != nil {
		return nil, err
	}
	size := binary.LittleEndian.Uint32(sizeBytes[:])
	if size == 0 {
		return nil, fmt.Errorf("map response: zero-length frame")
	}

	// Read the compressed frame.
	compressed := make([]byte, size)
	if _, err := io.ReadFull(s.res.Body, compressed); err != nil {
		return nil, fmt.Errorf("reading map response frame: %w", err)
	}

	// Decompress.
	decoded, err := zstdframe.AppendDecode(nil, compressed)
	if err != nil {
		return nil, fmt.Errorf("decompressing map response: %w", err)
	}

	// Unmarshal JSON.
	var resp tailcfg.MapResponse
	if err := json.Unmarshal(decoded, &resp); err != nil {
		return nil, fmt.Errorf("decoding map response: %w", err)
	}

	s.read++
	return &resp, nil
}

// Close closes the underlying HTTP response body.
func (s *MapSession) Close() error {
	return s.res.Body.Close()
}

// Map sends a map request to the coordination server and returns a MapSession
// for reading the framed, zstd-compressed response(s).
func (c *Client) Map(ctx context.Context, opts MapOpts) (*MapSession, error) {
	if opts.NodeKey.IsZero() {
		return nil, fmt.Errorf("NodeKey is required")
	}

	hi := opts.Hostinfo
	if hi == nil {
		hi = new(tailcfg.Hostinfo)
	}

	mapReq := tailcfg.MapRequest{
		Version:   tailcfg.CurrentCapabilityVersion,
		NodeKey:   opts.NodeKey.Public(),
		Hostinfo:  hi,
		Stream:    opts.Stream,
		Compress:  "zstd",
		OmitPeers: opts.OmitPeers,
	}

	body, err := json.Marshal(mapReq)
	if err != nil {
		return nil, fmt.Errorf("encoding map request: %w", err)
	}

	nc, err := c.noiseClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("establishing noise connection: %w", err)
	}

	url := c.serverURL + "/machine/map"
	url = strings.Replace(url, "http:", "https:", 1)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating map request: %w", err)
	}
	ts2021.AddLBHeader(req, opts.NodeKey.Public())

	res, err := nc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("map request: %w", err)
	}

	if res.StatusCode != 200 {
		msg, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return nil, fmt.Errorf("map request: http %d: %.200s",
			res.StatusCode, strings.TrimSpace(string(msg)))
	}

	return &MapSession{res: res, stream: opts.Stream}, nil
}
