# ssh-agent-fs

A read-only FUSE filesystem that exposes the public keys held by your
running SSH agent as predictable files, so you can reference them from `~/.ssh/config` via `IdentityFile` (or from other SSH clients).

## Why?

If you keep several keys loaded in your SSH agent, ssh offers them to a server
one at a time until one is accepted. That default works, but it has annoyances:

- **You can't reliably pin a key to a host.** Many setups want a *specific*
  identity for a *specific* server or profile - a work key for one Git host, a
  personal key for another, a separate key per client. With everything in the
  agent, ssh just tries them in whatever order, and you have no clean way to say
  "use *this* one here."
- **Servers that count auth attempts can reject you.** If the right key is third
  in line and the server's `MaxAuthTries` is low, you get "Too many
  authentication failures" before ssh ever reaches it.

The usual fix is to set `IdentityFile` to a key on disk and add
`IdentitiesOnly yes`, which tells ssh to use only that one identity. But that
assumes the key *exists as a file*. If your keys live only in the agent -
hardware-backed or FIDO/`sk-` keys, forwarded agents, or keys you deliberately
never write to disk - there's no path to point `IdentityFile` at.

**ssh-agent-fs bridges that gap.** It gives each agent key a stable file path
you can reference, so you can pin a specific agent identity to a specific host.
ssh reads the public key file, finds the matching private key in the agent, and
uses only that one - no on-disk private key required, and no guessing which
identity gets offered.

### Examples

**Two Git accounts, one host.** Personal and work GitHub accounts, each with its
own key in the agent:

```
Host github.com
    HostName github.com
    IdentityFile /run/user/1000/ssh-agent-fs/personal.pub
    IdentitiesOnly yes

Host github-work
    HostName github.com
    IdentityFile /run/user/1000/ssh-agent-fs/work-laptop.pub
    IdentitiesOnly yes
```

Clone work repos with `git clone git@github-work:org/repo.git` and personal ones
with the normal `git@github.com:...`. Each alias is pinned to exactly one agent
identity.

**A hardware/FIDO key for production.** A resident `sk-ed25519` key that never
exists as a file on disk - there's nothing for a plain `IdentityFile` to point
at, but the agent fingerprint file works:

```
Host prod-bastion
    HostName bastion.example.com
    User deploy
    IdentityFile /run/user/1000/ssh-agent-fs/ed25519-SHA256_C_9O1TB2.pub
    IdentitiesOnly yes
```

**Avoiding "Too many authentication failures."** With many keys loaded, a server
with a low `MaxAuthTries` may cut you off before ssh reaches the right one.
Pinning the single correct identity sidesteps the problem entirely:

```
Host legacy-server
    HostName 10.0.5.20
    IdentityFile /run/user/1000/ssh-agent-fs/client-acme.pub
    IdentitiesOnly yes
```

> **Tip:** the mount path includes your UID (`/run/user/1000/...`). Run `id -u`
> to confirm yours, or check the path the binary prints on stderr at startup.

## How it works

For each identity in the agent, a file appears in the mount directory named `<sanitized-comment>.pub`, with its OpenSSH-formatted public key as content
(the same bytes you'd get from `ssh-add -L`).

- Slashes, control characters, and whitespace in comments become `_`.
- **If the key has no comment** (or one that sanitizes to nothing), the file
  is named after the key's algorithm and a short SHA256 fingerprint, e.g.
  `ed25519-SHA256_C_9O1TB2.pub` or `rsa-SHA256_a4b2c1de.pub`. This is stable
  across runs and across agents; the same key always produces the same
  filename, so it remains a valid `IdentityFile` target.
- If two keys share a comment, the second becomes `<comment>_1.pub`, etc.
- Files are read-only (`0o444`). To remove a key, use `ssh-add -d`; the file
  disappears within ~1 second.
- The identity list is re-queried from the agent on demand, with a 1-second
  cache TTL.

## Install

The recommended path is from crates.io:

```
cargo install ssh-agent-fs
```

This compiles against your system's `libfuse` and `glibc`, so it works on any
Linux distro that has them - you'll still need the libfuse headers installed
at compile time since `cargo install` can't fetch C dependencies:

```
sudo apt install libfuse-dev pkg-config       # Debian/Ubuntu
sudo dnf install fuse-devel pkg-config        # Fedora/RHEL
sudo pacman -S fuse2 pkgconf                  # Arch/Artix
```

If you'd rather build from a local checkout, see the next section.

## Build from source (Linux)

Prerequisites: `rustc`/`cargo`, plus the `libfuse-dev` / `fuse-devel` / `fuse2` packages listed above. For the convenience recipes below you'll
also want [`just`](https://just.systems/):

```
cargo install just                            # if you don't already have it
```

The repo ships a `justfile`; run `just --list` to see what's available:

```
just release          # regenerate licenses.html, build the binary, and
                      # assemble a release tarball
just licenses         # regenerate licenses.html from the current Cargo.lock
just clean            # remove the target/ dir, licenses.html, and any tarballs
```

Then start it:

```
# No arguments: auto-mounts at $XDG_RUNTIME_DIR/ssh-agent-fs/ (per-user, mode 0700).
./target/release/ssh-agent-fs

# Or specify a path explicitly:
./target/release/ssh-agent-fs ~/agent-keys
```

If you'd rather not install `just`, the underlying cargo commands work fine:

```
cargo build --release
./target/release/ssh-agent-fs
```

When invoked with no arguments, the binary picks a per-user runtime directory in this order:

1. `$XDG_RUNTIME_DIR/ssh-agent-fs/` (preferred; tmpfs, mode 0700, systemd-managed)
2. `/run/user/$UID/ssh-agent-fs/` (same place, when the env var isn't set)
3. `$TMPDIR/ssh-agent-fs-$UID/` (macOS gives you a per-user `$TMPDIR`)
4. `/tmp/ssh-agent-fs-$UID/` (last resort)

The chosen directory is created with mode `0700` if missing. If it already
exists and is owned by another user, the process refuses to start; that
guards against a hostile user pre-creating a writable directory at a path
you'd otherwise mount onto.

To find out where it ended up after launch, the binary prints the path on
stderr (`ssh-agent-fs: mounting at /run/user/1000/ssh-agent-fs`).

Once running, in another terminal:

```
ls -la /run/user/$UID/ssh-agent-fs
# -r--r--r-- 1 you you 102 ... work-laptop.pub
# -r--r--r-- 1 you you  98 ... personal.pub

cat /run/user/$UID/ssh-agent-fs/work-laptop.pub
# ssh-ed25519 AAAAC3Nz... work-laptop
```

Then in `~/.ssh/config`:

```
Host github.com
    IdentityFile /run/user/1000/ssh-agent-fs/work-laptop.pub
    IdentitiesOnly yes
```

`IdentitiesOnly yes` makes ssh only try the listed identity; without it ssh
will try every key in the agent in turn, which is what most setups already
do anyway.

To unmount:

```
fusermount -u /run/user/$UID/ssh-agent-fs
```

## macOS

macOS support requires [macFUSE](https://osxfuse.github.io/) to be installed as
a dependency. The code itself is unchanged; only the system prerequisite differs.

## Notes & limitations

- The mount only contains `.pub` (public key) files. Private keys never leave
  the agent; this filesystem doesn't expose them and couldn't even if it
  wanted to, since the agent doesn't return private key material.
- No subdirectories; flat layout in the mount root.
- Single-process. The `fuser::mount2` call blocks; use `&` or a systemd user
  service if you want it backgrounded.

## Contributing

Bug reports and pull requests welcome at <https://github.com/shinsterneck/ssh-agent-fs>.

## License

Copyright © 2026 Shin Sterneck

Licensed under the GNU General Public License version 3.0 or later
(GPL-3.0-or-later). See [LICENSE](LICENSE) for the full text.

This crate depends on `fuser`, `libc`, `ssh-agent-client-rs`, and `ssh-key`,
all of which are MIT/Apache-2.0. The combined work is GPL-3.0-or-later.
