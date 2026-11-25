use crate::{util::*, zone};
use serde::{Deserialize, Serialize};
use std::{fs, io::Write, path::{Path, PathBuf}, ptr::{null, null_mut}};
use windows_sys::Win32::{Foundation::LocalFree, Security::Cryptography::*};

const MAX: u64 = 1 << 30;

#[derive(Serialize, Deserialize, Clone)]
pub struct Item { pub id: String, pub original: PathBuf, pub sha256: String, pub reason: String }

fn dir() -> Res<PathBuf> {
    let d = state()?.join("quarantine");
    fs::create_dir_all(&d).map_err(|e| e.to_string())?;
    Ok(d)
}
pub fn list() -> Res<Vec<Item>> {
    load_json(&dir()?.join("index.json"))
}
fn save(l: &[Item]) -> Res<()> {
    save_json(&dir()?.join("index.json"), &l)
}
fn blob(id: &str) -> Res<PathBuf> {
    Ok(dir()?.join(format!("{id}.sealed")))
}

fn dpapi(data: &[u8], seal: bool) -> Res<Vec<u8>> {
    unsafe {
        let i = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as _ };
        let mut o = CRYPT_INTEGER_BLOB { cbData: 0, pbData: null_mut() };
        let ok = if seal {
            CryptProtectData(&i, null(), null(), null(), null(), CRYPTPROTECT_UI_FORBIDDEN, &mut o)
        } else {
            CryptUnprotectData(&i, null_mut(), null(), null(), null(), CRYPTPROTECT_UI_FORBIDDEN, &mut o)
        };
        if ok == 0 {
            return Err(err("DPAPI"));
        }
        let v = std::slice::from_raw_parts(o.pbData, o.cbData as usize).to_vec();
        LocalFree(o.pbData as _);
        Ok(v)
    }
}
fn read(p: &Path) -> Res<Vec<u8>> {
    fs::read(p).map_err(|e| format!("{}: {e}", p.display()))
}

/// Seal, verify the sealed copy, index it, and only then delete the original.
pub fn add(p: &Path, reason: &str) -> Res<Item> {
    let _l = lock();
    let m = fs::symlink_metadata(p).map_err(|e| e.to_string())?;
    if is_reparse(&m) || !m.is_file() {
        return Err("only regular files can be quarantined".into());
    }
    if m.len() > MAX {
        return Err("file is larger than the 1 GB limit; it was NOT moved".into());
    }
    let p = canon(p)?;
    zone::containing(&p)?;
    let data = read(&p)?;
    let sha = hash_bytes(&data);
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e| e.to_string())?.as_nanos();
    let id = hash_str(&format!("{}{sha}{t}", p.display()))[..16].to_string();
    let b = blob(&id)?;
    fs::write(&b, dpapi(&data, true)?).map_err(|e| e.to_string())?;
    if dpapi(&read(&b)?, false)? != data {
        return Err("sealed copy failed verification".into());
    }
    let item = Item { id, original: p.clone(), sha256: sha, reason: reason.into() };
    let mut l = list()?;
    l.push(item.clone());
    save(&l)?;
    fs::remove_file(&p).map_err(|e| format!("sealed, but the original could not be deleted: {e}"))?;
    Ok(item)
}

fn find(id: &str) -> Res<Item> {
    list()?.into_iter().find(|x| x.id == id).ok_or_else(|| "no such quarantine id".into())
}
fn forget(id: &str) -> Res<()> {
    let mut l = list()?;
    l.retain(|x| x.id != id);
    save(&l)?;
    fs::remove_file(blob(id)?).map_err(|e| e.to_string())
}
/// Restores only into a registered zone and never overwrites.
pub fn restore(id: &str) -> Res<PathBuf> {
    let _l = lock();
    let i = find(id)?;
    let parent = canon(i.original.parent().ok_or("bad original path")?)?;
    zone::containing(&parent)?;
    let dst = parent.join(i.original.file_name().ok_or("bad original path")?);
    let data = dpapi(&read(&blob(id)?)?, false)?;
    let mut f = fs::OpenOptions::new().write(true).create_new(true).open(&dst).map_err(|e| e.to_string())?;
    f.write_all(&data).map_err(|e| e.to_string())?;
    drop(f);
    if sha256(&dst)? != i.sha256 {
        return Err("restored file failed verification".into());
    }
    forget(id)?;
    Ok(dst)
}
pub fn delete(id: &str) -> Res<()> {
    let _l = lock();
    find(id)?;
    forget(id)
}
