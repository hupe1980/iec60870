//! The one way every interop harness builds its lib60870-C peer image.
//!
//! The peer is cloned at the commit in `tests/interop/LIB60870_COMMIT` — the only place it is
//! pinned — and that commit is passed to every Dockerfile as the required build argument
//! `LIB60870_COMMIT`. The image tag is a hash of the commit and of every file the image is
//! built from, so a bumped pin or an edited peer is never served from a stale image.
//!
//! Without Docker the suite skips with a message — unless `IEC60870_REQUIRE_INTEROP=1`, which
//! CI sets, and which turns a missing Docker or a failed build into a failure.

#![allow(dead_code, clippy::unwrap_used, clippy::panic)]

use std::path::Path;
use std::process::{Command, Stdio};

/// Resolve the loopback port Docker assigned when starting a published test peer.
pub fn published_port(container: &str, port: u16) -> u16 {
    let output = Command::new("docker").args(["port", container, &format!("{port}/tcp")]).output().unwrap();
    assert!(output.status.success(), "docker port {container}: {}", String::from_utf8_lossy(&output.stderr));
    let addr: std::net::SocketAddr = String::from_utf8(output.stdout).unwrap().trim().parse().unwrap();
    assert!(addr.ip().is_loopback(), "unexpected published test address {addr}");
    addr.port()
}

/// Whether `IEC60870_REQUIRE_INTEROP=1` is set.
pub fn required() -> bool {
    std::env::var("IEC60870_REQUIRE_INTEROP").as_deref() == Ok("1")
}

/// The pinned lib60870 commit.
pub fn lib60870_commit() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/interop/LIB60870_COMMIT");
    let commit = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display())).trim().to_string();
    assert!(commit.len() == 40 && commit.bytes().all(|b| b.is_ascii_hexdigit()), "{} must hold one 40-digit commit id", path.display());
    commit
}

/// Whether a Docker daemon answers; asserts when interop is required.
pub fn available(suite: &str) -> bool {
    let ok = Command::new("docker").args(["info", "--format", "{{.ServerVersion}}"]).output().is_ok_and(|o| o.status.success());
    if !ok {
        assert!(!required(), "Docker is required (IEC60870_REQUIRE_INTEROP=1) but is not available");
        println!("skipped: Docker is not available; skipping the {suite} (set IEC60870_REQUIRE_INTEROP=1 to make this a failure)");
    }
    ok
}

/// Builds (once per content hash) the image `repo` from `dockerfile` in `dir`, whose content
/// is `files` (relative to `dir`), and returns its tag; `None` (skip) without Docker.
pub fn image(suite: &str, repo: &str, dir: &Path, dockerfile: &str, files: &[&str]) -> Option<String> {
    if !available(suite) {
        return None;
    }
    let commit = lib60870_commit();
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut feed = |bytes: &[u8]| {
        for &b in bytes {
            hash = (hash ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
        }
    };
    feed(commit.as_bytes());
    for file in std::iter::once(&dockerfile).chain(files) {
        feed(&std::fs::read(dir.join(file)).unwrap_or_else(|e| panic!("{}: {e}", dir.join(file).display())));
    }
    let tag = format!("{repo}:{hash:016x}");
    let present = Command::new("docker").args(["image", "inspect", &tag]).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success());
    if !present {
        let status = Command::new("docker")
            .args(["build", "-q", "-t", &tag, "--build-arg", &format!("LIB60870_COMMIT={commit}"), "-f"])
            .arg(dir.join(dockerfile))
            .arg(dir)
            .status()
            .unwrap();
        assert!(status.success(), "docker build of {tag} failed");
    }
    Some(tag)
}
