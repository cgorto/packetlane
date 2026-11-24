# Development container

`Containerfile` adds the Rust toolchain (with rust-analyzer) and the Helix
editor to a RHEL 9 base image. `helix/` holds editor settings that are copied
into `~/.config/helix` the first time the container starts, if the home folder
has none.

It is a stub: it has not been built here. The two steps most likely to need
changes are the ones that download (rustup, and the Helix source and
grammars); the comments in the file say what to change on a network without
internet access.

## Build

From the repository root:

```
podman build -t packetlane-dev -f container/Containerfile \
    --build-arg BASE_IMAGE=<your RHEL 9 base image> .
```

Without `BASE_IMAGE` it uses Red Hat's public UBI 9 image.

## Run

```
podman run --rm -it \
    --userns=keep-id \
    --security-opt label=disable \
    --network host \
    -e HOME="$HOME" -e TERM -e COLORTERM \
    -v "$HOME:$HOME" \
    -w "$PWD" \
    packetlane-dev
```

What each part is for:

| Option | Why |
|---|---|
| `--userns=keep-id` | you are the same user inside as outside, so files you create in your home are yours |
| `--security-opt label=disable` | lets the container read your home under SELinux without relabelling it; do not put `:z` or `:Z` on a home folder mount |
| `--network host` | the tool serves on 127.0.0.1; this makes that the host's 127.0.0.1, so the address it prints opens in your normal browser |
| `-e HOME` and `-v "$HOME:$HOME"` | your home folder at the same path, so paths, shell history, `~/.cargo` and editor settings carry over |
| `-e TERM -e COLORTERM` | correct colours in the editor |
| `-w "$PWD"` | start in the folder you ran the command from |

To reach folders outside your home, add a mount for each. Mount log folders
read-only; the tool never needs to write to them:

```
    -v /data/runs:/data/runs:ro \
```

Inside the container, `cargo build`, `cargo test` and `hx` work as usual.
