// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Shin Sterneck
//
// ssh-agent-fs - read-only FUSE filesystem exposing the SSH agent's
// public keys as predictable files for use in ~/.ssh/config.

use ssh_agent_client_rs::{Client, Identity};

use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry,
    Request,
};
use std::collections::HashMap;
use std::env;
use std::ffi::OsStr;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// TTL settings
const TTL: Duration = Duration::from_secs(1);
const REFRESH_INTERVAL: Duration = Duration::from_secs(1);

const ROOT_INO: u64 = 1;

#[derive(Clone)]
struct KeyFile {
    name: String,
    content: Vec<u8>,
    ino: u64,
}

struct SshAgentFs {
    sock_path: String,
    entries: HashMap<u64, KeyFile>,
    name_to_ino: HashMap<String, u64>,
    next_ino: u64,
    last_refresh: SystemTime,
    uid: u32,
    gid: u32,
}

impl SshAgentFs {
    fn new(sock_path: String) -> Self {
        Self {
            sock_path,
            entries: HashMap::new(),
            name_to_ino: HashMap::new(),
            next_ino: 2,
            // Force first refresh on first call.
            last_refresh: UNIX_EPOCH,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        }
    }

    /// Re-query the agent and rebuild entry tables. If ssh-agent is unreachable, keep whatever was cached.
    fn refresh(&mut self) {
        let mut client = match Client::connect(Path::new(&self.sock_path)) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("ssh-agent-fs: connect failed: {e}");
                return;
            }
        };

        let identities = match client.list_all_identities() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("ssh-agent-fs: listing identities failed: {e}");
                return;
            }
        };

        let mut new_entries: HashMap<u64, KeyFile> = HashMap::new();
        let mut new_name_to_ino: HashMap<String, u64> = HashMap::new();
        let mut name_counts: HashMap<String, u32> = HashMap::new();

        for identity in identities {
            let (comment, fp_fallback, openssh_result) = match &identity {
                Identity::PublicKey(pk) => {
                    let label = fingerprint_label(
                        pk.algorithm().as_str(),
                        &pk.fingerprint(ssh_key::HashAlg::Sha256),
                    );
                    (pk.comment().to_string(), label, pk.to_openssh())
                }
                Identity::Certificate(cert) => {
                    let label = fingerprint_label(
                        cert.algorithm().as_str(),
                        &cert.public_key().fingerprint(ssh_key::HashAlg::Sha256),
                    );
                    (cert.comment().to_string(), label, cert.to_openssh())
                }
            };

            let base = sanitize_name(&comment).unwrap_or(fp_fallback);
            let count = name_counts.entry(base.clone()).or_insert(0);
            let name = if *count == 0 {
                format!("{base}.pub")
            } else {
                format!("{base}_{count}.pub")
            };
            *count += 1;

            let openssh = match openssh_result {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("ssh-agent-fs: skipping {name}: {e}");
                    continue;
                }
            };
            let mut content = openssh.into_bytes();
            content.push(b'\n');

            // Reuse a previously-assigned inode for the same name so that open file handles survive a refresh.
            let ino = match self.name_to_ino.get(&name) {
                Some(&ino) => ino,
                None => {
                    let ino = self.next_ino;
                    self.next_ino += 1;
                    ino
                }
            };

            new_name_to_ino.insert(name.clone(), ino);
            new_entries.insert(ino, KeyFile { name, content, ino });
        }

        self.entries = new_entries;
        self.name_to_ino = new_name_to_ino;
        self.last_refresh = SystemTime::now();
    }

    fn maybe_refresh(&mut self) {
        let stale = SystemTime::now()
            .duration_since(self.last_refresh)
            .map(|d| d > REFRESH_INTERVAL)
            .unwrap_or(true);
        if stale {
            self.refresh();
        }
    }

    fn file_attr(&self, ino: u64, size: u64) -> FileAttr {
        FileAttr {
            ino,
            size,
            blocks: size.div_ceil(512),
            atime: self.last_refresh,
            mtime: self.last_refresh,
            ctime: self.last_refresh,
            crtime: self.last_refresh,
            kind: FileType::RegularFile,
            perm: 0o444,
            nlink: 1,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            flags: 0,
            blksize: 4096,
        }
    }

    fn dir_attr(&self) -> FileAttr {
        FileAttr {
            ino: ROOT_INO,
            size: 0,
            blocks: 0,
            atime: self.last_refresh,
            mtime: self.last_refresh,
            ctime: self.last_refresh,
            crtime: self.last_refresh,
            kind: FileType::Directory,
            perm: 0o555,
            nlink: 2,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            flags: 0,
            blksize: 4096,
        }
    }
}

/// Make a comment safe to use as a single filename component. Returns `None`
/// if there's nothing left after stripping path-unfriendly chars - the caller
/// then falls back to a fingerprint-based label.
fn sanitize_name(s: &str) -> Option<String> {
    let cleaned: String = s
        .chars()
        .map(|c| match c {
            '/' | '\\' | '\0' => '_',
            c if c.is_control() || c.is_whitespace() => '_',
            c => c,
        })
        .collect();
    let trimmed = cleaned.trim_matches('_').to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn fingerprint_label(algorithm: &str, fp: &ssh_key::Fingerprint) -> String {
    let algo = algorithm.strip_prefix("ssh-").unwrap_or(algorithm);
    let algo = algo
        .strip_suffix("-cert-v01@openssh.com")
        .map(|base| format!("{base}-cert"))
        .unwrap_or_else(|| algo.to_string());

    let suffix: String = fp
        .to_string()
        .split(':')
        .nth(1)
        .unwrap_or("")
        .chars()
        .take(8)
        .map(|c| match c {
            '/' | '+' | '=' => '_',
            c => c,
        })
        .collect();

    format!("{algo}-SHA256_{suffix}")
}

impl Filesystem for SshAgentFs {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        if parent != ROOT_INO {
            reply.error(libc::ENOENT);
            return;
        }
        self.maybe_refresh();

        let name = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        match self.name_to_ino.get(name).copied() {
            Some(ino) => match self.entries.get(&ino) {
                Some(entry) => {
                    let attr = self.file_attr(ino, entry.content.len() as u64);
                    reply.entry(&TTL, &attr, 0);
                }
                None => reply.error(libc::ENOENT),
            },
            None => reply.error(libc::ENOENT),
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        if ino == ROOT_INO {
            reply.attr(&TTL, &self.dir_attr());
            return;
        }
        self.maybe_refresh();
        match self.entries.get(&ino) {
            Some(entry) => {
                let attr = self.file_attr(ino, entry.content.len() as u64);
                reply.attr(&TTL, &attr);
            }
            None => reply.error(libc::ENOENT),
        }
    }

    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        self.maybe_refresh();
        match self.entries.get(&ino) {
            Some(entry) => {
                let len = entry.content.len();
                let start = (offset as usize).min(len);
                let end = start.saturating_add(size as usize).min(len);
                reply.data(&entry.content[start..end]);
            }
            None => reply.error(libc::ENOENT),
        }
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        if ino != ROOT_INO {
            reply.error(libc::ENOENT);
            return;
        }
        self.maybe_refresh();

        let mut entries: Vec<(u64, FileType, String)> = Vec::with_capacity(self.entries.len() + 2);
        entries.push((ROOT_INO, FileType::Directory, ".".to_string()));
        entries.push((ROOT_INO, FileType::Directory, "..".to_string()));
        for e in self.entries.values() {
            entries.push((e.ino, FileType::RegularFile, e.name.clone()));
        }

        for (i, (entry_ino, kind, name)) in entries.into_iter().enumerate().skip(offset as usize) {
            if reply.add(entry_ino, (i + 1) as i64, kind, &name) {
                break;
            }
        }
        reply.ok();
    }
}

fn default_mountpoint(uid: u32) -> Result<PathBuf, String> {
    let mut errors = Vec::new();
    for mountpoint in available_mountpoints(uid) {
        match ensure_safe_dir(&mountpoint, uid) {
            Ok(()) => return Ok(mountpoint),
            Err(e) => errors.push(format!("  {}: {e}", mountpoint.display())),
        }
    }
    Err(format!(
        "no suitable runtime directory found:\n{}",
        errors.join("\n")
    ))
}

fn available_mountpoints(uid: u32) -> Vec<PathBuf> {
    let mut out = Vec::new();

    if let Ok(xdg) = env::var("XDG_RUNTIME_DIR") {
        if !xdg.is_empty() {
            out.push(PathBuf::from(xdg).join("ssh-agent-fs"));
        }
    }

    let run_user = PathBuf::from(format!("/run/user/{uid}"));
    if run_user.is_dir() {
        let p = run_user.join("ssh-agent-fs");
        if !out.contains(&p) {
            out.push(p);
        }
    }

    if let Ok(tmp) = env::var("TMPDIR") {
        if !tmp.is_empty() {
            out.push(PathBuf::from(tmp).join(format!("ssh-agent-fs-{uid}")));
        }
    }

    out.push(PathBuf::from(format!("/tmp/ssh-agent-fs-{uid}")));
    out
}

/// Create `path` (and any missing intermediate components inside an
/// already-trusted parent) with mode 0700, or verify it's already a directory
/// owned by `expected_uid`. Uses `symlink_metadata` so a symlink pointed at a
/// directory *not* owned is rejected even if the target check would pass.
fn ensure_safe_dir(path: &Path, expected_uid: u32) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(md) => {
            if !md.file_type().is_dir() {
                return Err(format!("not a directory (got {:?})", md.file_type()));
            }
            if md.uid() != expected_uid {
                return Err(format!(
                    "owned by uid {} (expected {expected_uid}); refusing to mount",
                    md.uid()
                ));
            }
            let mode = md.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                    .map_err(|e| format!("chmod 0700 failed: {e}"))?;
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(path).map_err(|e| format!("create: {e}"))?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("chmod 0700 failed: {e}"))?;
            Ok(())
        }
        Err(e) => Err(format!("stat: {e}")),
    }
}

fn print_help(prog: &str) {
    println!(
        "Usage: {prog} [MOUNTPOINT]

Mounts a FUSE filesystem exposing the SSH agent's public keys as predictable
files (one .pub per identity), so you can reference them in ~/.ssh/config or
in other SSH clients.

If MOUNTPOINT is omitted, a per-user runtime directory is chosen automatically:
  $XDG_RUNTIME_DIR/ssh-agent-fs/   (preferred)
  /run/user/$UID/ssh-agent-fs/
  $TMPDIR/ssh-agent-fs-$UID/
  /tmp/ssh-agent-fs-$UID/

The chosen directory will be created with mode 0700 if it doesn't exist, and
the process refuses to start if it exists but is owned by another user.

Environment:
  SSH_AUTH_SOCK   required; path to the SSH agent's Unix socket."
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let prog = args.first().map(String::as_str).unwrap_or("ssh-agent-fs");

    let uid = unsafe { libc::getuid() };

    let mountpoint: PathBuf = match args.get(1).map(String::as_str) {
        Some("-h") | Some("--help") => {
            print_help(prog);
            return;
        }
        Some(p) => {
            let p = PathBuf::from(p);
            if let Err(e) = ensure_safe_dir(&p, uid) {
                eprintln!("ssh-agent-fs: {}: {e}", p.display());
                std::process::exit(1);
            }
            p
        }
        None => match default_mountpoint(uid) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("ssh-agent-fs: {e}");
                std::process::exit(1);
            }
        },
    };

    let sock_path =
        env::var("SSH_AUTH_SOCK").expect("SSH_AUTH_SOCK is not set; is your agent running?");

    eprintln!("ssh-agent-fs: mounting at {}", mountpoint.display());

    let fs = SshAgentFs::new(sock_path);

    let options = vec![
        MountOption::RO,
        MountOption::FSName("ssh-agent".to_string()),
        MountOption::Subtype("sshagentfs".to_string()),
        MountOption::AutoUnmount,
        MountOption::DefaultPermissions,
    ];

    if let Err(e) = fuser::mount2(fs, &mountpoint, &options) {
        eprintln!("ssh-agent-fs: mount failed: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn sanitize_passes_through_clean_input() {
        assert_eq!(sanitize_name("work-laptop").as_deref(), Some("work-laptop"));
        assert_eq!(
            sanitize_name("alice@example.com").as_deref(),
            Some("alice@example.com")
        );
    }

    #[test]
    fn sanitize_replaces_path_separators_and_whitespace() {
        assert_eq!(sanitize_name("hello world").as_deref(), Some("hello_world"));
        assert_eq!(sanitize_name("a/b\\c").as_deref(), Some("a_b_c"));
    }

    #[test]
    fn sanitize_returns_none_for_empty_or_garbage_only() {
        assert_eq!(sanitize_name(""), None);
        assert_eq!(sanitize_name("   "), None);
        assert_eq!(sanitize_name("///"), None);
        assert_eq!(sanitize_name("\t\n  "), None);
    }

    #[test]
    fn fingerprint_label_is_stable_for_known_key() {
        let key_str =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAcv0iqu0jysOQa1yqNUYZ02NtFL8Aw3GdMr8wMjqOQy";
        let pk = ssh_key::PublicKey::from_str(key_str).expect("parse known test key");
        let label = fingerprint_label(
            pk.algorithm().as_str(),
            &pk.fingerprint(ssh_key::HashAlg::Sha256),
        );

        assert!(label.starts_with("ed25519-SHA256_"), "got: {label}");
        let suffix = &label["ed25519-SHA256_".len()..];
        assert_eq!(suffix.len(), 8, "suffix should be 8 chars, got {suffix:?}");
        assert!(
            suffix
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_'),
            "suffix must be filename-safe, got {suffix:?}",
        );

        let label2 = fingerprint_label(
            pk.algorithm().as_str(),
            &pk.fingerprint(ssh_key::HashAlg::Sha256),
        );
        assert_eq!(label, label2);
    }

    #[test]
    fn fingerprint_label_strips_ssh_prefix() {
        let key_str =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAcv0iqu0jysOQa1yqNUYZ02NtFL8Aw3GdMr8wMjqOQy";
        let pk = ssh_key::PublicKey::from_str(key_str).unwrap();
        let label = fingerprint_label("ssh-ed25519", &pk.fingerprint(ssh_key::HashAlg::Sha256));
        assert!(
            label.starts_with("ed25519-"),
            "should strip ssh- prefix, got: {label}"
        );

        let cert_label = fingerprint_label(
            "ssh-ed25519-cert-v01@openssh.com",
            &pk.fingerprint(ssh_key::HashAlg::Sha256),
        );
        assert!(
            cert_label.starts_with("ed25519-cert-"),
            "should reduce the cert-algo name, got: {cert_label}"
        );
    }
}
