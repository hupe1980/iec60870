//! Directory queries and no-clobber publication of verified file records.
use super::{Client, CommonAddress, Ioa};
use crate::{out, render};
use iec60870::station::Timestamp;
use serde_json::json;
use std::{
    fs,
    io::{self, Write},
    path::Path,
};

fn destination_error(path: &Path, error: &io::Error) -> io::Error {
    io::Error::other(format!("cannot save {}: {error}", path.display()))
}

pub(super) struct Destination<'a> {
    path: &'a Path,
    staged: tempfile::NamedTempFile,
}

impl<'a> Destination<'a> {
    pub(super) fn prepare(path: &'a Path) -> io::Result<Self> {
        match fs::symlink_metadata(path) {
            Ok(_) => return Err(io::Error::other(format!("destination {} already exists; choose a new path", path.display()))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(destination_error(path, &e)),
        }
        let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let staged = tempfile::NamedTempFile::new_in(dir).map_err(|e| destination_error(path, &e))?;
        Ok(Self { path, staged })
    }

    fn save(mut self, bytes: &[u8]) -> io::Result<()> {
        self.staged.write_all(bytes)?;
        self.staged.as_file().sync_all()?;
        self.staged.persist_noclobber(self.path).map_err(|e| e.error)?;
        Ok(())
    }
}

pub(super) fn list(client: &mut Client, ca: CommonAddress, utc: bool, json_output: bool, out: &mut impl Write) -> io::Result<bool> {
    let files = client.files(ca).map_err(io::Error::other)?;
    for file in &files {
        if json_output {
            let mut record = json!({"kind":"file","ca":ca.0,"ioa":file.ioa.0,"name":file.name.0,"bytes":file.length,"status":file.status.0});
            if let Some(fields) = record.as_object_mut() {
                render::time_fields(fields, Timestamp::Cp56(file.created), utc);
            }
            writeln!(out, "{record}")?;
        } else {
            writeln!(out, "CA {ca} IOA {}  {}  {} bytes  status {:#04x}  {}", file.ioa, file.name, file.length, file.status.0, file.created)?;
        }
    }
    if json_output {
        writeln!(out, "{}", json!({"kind":"done","action":"files","ca":ca.0,"files":files.len()}))?;
    } else {
        writeln!(out, "CA {ca}: {} file records", files.len())?;
    }
    Ok(true)
}

pub(super) fn get(
    client: &mut Client,
    ca: CommonAddress,
    ioa: Ioa,
    name: u16,
    destination: Destination<'_>,
    json_output: bool,
    out: &mut impl Write,
) -> io::Result<bool> {
    let bytes = client.download(ca, ioa, name).map_err(io::Error::other)?;
    let output = destination.path;
    destination.save(&bytes).map_err(|e| destination_error(output, &e))?;
    let path = output.to_string_lossy();
    if json_output {
        writeln!(out, "{}", json!({"kind":"done","action":"get","ca":ca.0,"ioa":ioa.0,"requested_name":name,"bytes":bytes.len(),"output":path}))?;
    } else {
        writeln!(out, "Saved {} bytes to {}", bytes.len(), out::clean(&path))?;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publication_preserves_a_destination_created_after_preflight() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let dest = dir.path().join("record");
        let pending = Destination::prepare(&dest)?;
        fs::write(&dest, b"existing")?;
        assert!(matches!(pending.save(b"new"), Err(e) if e.kind() == io::ErrorKind::AlreadyExists));
        assert_eq!(fs::read(&dest)?, b"existing");
        assert_eq!(fs::read_dir(dir.path())?.count(), 1);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn publication_preserves_a_dangling_symlink() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let dest = dir.path().join("link");
        let target = dir.path().join("absent");
        let pending = Destination::prepare(&dest)?;
        std::os::unix::fs::symlink(&target, &dest)?;
        assert!(Destination::prepare(&dest).is_err());
        assert!(pending.save(b"new").is_err());
        assert_eq!(fs::read_link(dest)?, target);
        assert!(!target.exists());
        Ok(())
    }
}
