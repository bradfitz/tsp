# tsp

`tsp` is a low-level Tailscale protocol tool for performing composable
building-block operations: generating keys, discovering server public keys,
and registering nodes with a coordination server.

## Library

The `tsp` Go package provides a client for
speaking the Tailscale protocol to a coordination server.
See https://pkg.go.dev/github.com/bradfitz/tsp for that.

## CLI

The CLI wraps the library to let you do each operation.

### Install

```
go install github.com/bradfitz/tsp/cmd/tsp@latest
```

### Commands

#### new-machine-key

Generate a new machine key.

```
tsp new-machine-key [-o file]
```

#### new-node-key

Generate a new node key.

```
tsp new-node-key [-o file]
```

#### discover-server-key

Discover and print the coordination server's public key.

```
tsp [-s url] discover-server-key [-o file]
```

#### new-node

Generate a new node JSON file bundling machine key, node key, server URL,
and server public key. If `-n` or `-m` are omitted, new keys are generated.
The server key is discovered automatically unless `--control-key` is given.

```
tsp [-s url] [--control-key file] new-node [-n node-key-file] [-m machine-key-file] [-o output]
```

The resulting JSON file looks like:

```json
{
  "node_key": "node-privkey:...",
  "machine_key": "machine-privkey:...",
  "server_url": "https://controlplane.tailscale.com",
  "server_key": "mkey:..."
}
```

#### register

Register a node with a coordination server using a node JSON file.

```
tsp [-s url] [--control-key file] register -n <node-file> [flags]
```

Flags:

```
-n <file>          Node JSON file (required)
-o <file>          Output file (default: stdout)
--hostname <name>  Hostname to register
--ephemeral        Register as ephemeral node
--auth-key <key>   Pre-authorized auth key
--tags <tags>      Comma-separated ACL tags
```

#### map

Send a map request to the coordination server.

```
tsp [-s url] [--control-key file] map -n <node-file> [-stream] [-peers=false] [-o file]
```

Flags:

```
-n <file>          Node JSON file (required)
-o <file>          Output file (default: stdout)
-stream            Stream map responses
-peers             Include peers in response (default: true)
```

### Example workflow

Using a node file (recommended):

```sh
# Generate a node file (discovers server key automatically)
tsp new-node -o node.json

# Register
tsp register -n node.json --auth-key tskey-auth-...

# One-shot map
tsp map -n node.json

# Streaming map
tsp map -n node.json -stream

# Map without peers
tsp map -n node.json -peers=false
```

Using pre-existing key files:

```sh
# Generate keys separately
tsp new-machine-key -o machine.key
tsp new-node-key -o node.key

# Bundle into a node file
tsp new-node -m machine.key -n node.key -o node.json

# Register and map using the node file
tsp register -n node.json --auth-key tskey-auth-...
tsp map -n node.json
```
