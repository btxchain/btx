
# BTX Docker Image (Headless Node)

This Dockerfile builds and runs a **BTX** full node from source.

## Features

* Post-quantum blockchain with MatMul PoW and shielded pool
* Stripped of all non-essential components (tests, debug data, documentation, etc.)
* Data directory persisted via volume
* Accessible via RPC

---

## Build the Docker Image

**make sure you're at the root of the repo first!**

```bash
docker build \
  -f contrib/docker/Dockerfile \
  -t btxd \
  --load .
```

---

## Run the Node

```bash
docker run -d \
  --init \
  --user $(id -u):$(id -g) \
  --name btxd \
  -p 19335:19335 -p 127.0.0.1:19334:19334 \
  -v path/to/conf:/etc/btx/btx.conf:ro \
  -v path/to/data:/var/lib/btxd:rw \
  btxd
```

If your config keeps the legacy RPC default (`8332`) instead of BTX ops
standard (`19334`), change the RPC publish mapping to
`-p 127.0.0.1:8332:8332`.

In case you want to use ZeroMQ sockets, make sure to expose those ports as well by adding `-p host_port:container_port` directives to the command above.
In case `path/to/data` is not writable by your user, consider overriding the `--user` flag.

This will:

* Start the node in the background
* Save the blockchain and config in `/path/to/data`
* Expose peer and RPC ports

---

## Check Node Status

```bash
docker logs btxd
```

---

## Stop the Node

```bash
docker stop btxd
```

---
