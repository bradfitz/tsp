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

#### register

Register a node key with a coordination server.

```
tsp [-s url] [--control-key file] register -n <node-key-file> -m <machine-key-file> [flags]
```

Flags:

```
-n <file>          Node key file (required)
-m <file>          Machine key file (required)
-o <file>          Output file (default: stdout)
--hostname <name>  Hostname to register
--ephemeral        Register as ephemeral node
--auth-key <key>   Pre-authorized auth key
--tags <tags>      Comma-separated ACL tags
--tailnet <name>   Tailnet to register in
```

### Example workflow

```sh
# Generate keys
tsp new-machine-key -o machine.key
tsp new-node-key -o node.key

# Optionally cache the server's public key
tsp discover-server-key -o server.pub

# Register (with cached server key to skip discovery)
tsp --control-key server.pub register -n node.key -m machine.key --auth-key tskey-auth-...

tsp register -n node.key -m machine.key --auth-key tskey-auth-...
```
