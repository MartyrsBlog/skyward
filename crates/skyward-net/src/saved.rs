//! Networks joined before, kept on the phone itself: the recovery reads
//! them as its WLAN starts, to join one of them on its own, and writes one
//! as it is joined. They live on the metadata partition, which a wipe of
//! the data leaves alone and whose folder nothing else writes.

use crate::supplicant::Security;
use anyhow::{Context, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// One network joined before: its name as the access point sends it, how
/// it is protected, and the password its user typed, if it takes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Saved {
    pub ssid: Vec<u8>,
    pub security: Security,
    pub password: String,
}

/// Where they are kept.
pub fn folder() -> PathBuf {
    Path::new("/metadata").join("skyward")
}

/// How a network is protected, in the file's own words.
fn code(security: Security) -> &'static str {
    match security {
        Security::Open => "open",
        Security::Owe => "owe",
        Security::Psk => "psk",
        Security::Sae => "sae",
        Security::PskSae => "psksae",
        Security::Wep | Security::Enterprise => "wep",
    }
}

/// The protection a line's word names, where it is one of them.
fn of_code(word: &str) -> Option<Security> {
    Some(match word {
        "open" => Security::Open,
        "owe" => Security::Owe,
        "psk" => Security::Psk,
        "sae" => Security::Sae,
        "psksae" => Security::PskSae,
        "wep" => Security::Wep,
        _ => return None,
    })
}

/// The file itself.
fn file(dir: &Path) -> PathBuf {
    dir.join("wifi")
}

/// The networks the phone holds, a line each as `name protection
/// password`, each of the three in hex, which takes any bytes of a name.
/// A line that says nothing readable is passed over, for a file half
/// written stays readable for the rest of it.
pub fn load(dir: &Path) -> Result<Vec<Saved>> {
    let text = fs::read_to_string(file(dir)).with_context(|| format!("read {}", file(dir).display()))?;
    Ok(text
        .lines()
        .filter_map(|line| {
            let fields = line.split(' ').collect::<Vec<_>>();
            match fields.as_slice() {
                [ssid, protection, password] => Some(Saved {
                    ssid: hex::decode(ssid).ok()?,
                    security: of_code(protection)?,
                    password: String::from_utf8_lossy(&hex::decode(password).ok()?).into_owned(),
                }),
                _ => None,
            }
        })
        .collect())
}

/// Write the networks, each its own line. The folder is closed to others,
/// for a password is in it.
pub fn save(dir: &Path, networks: &[Saved]) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("make {}", dir.display()))?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).with_context(|| format!("close {}", dir.display()))?;
    let mut text = String::new();
    for network in networks {
        text.push_str(&format!(
            "{} {} {}\n",
            hex::encode(&network.ssid),
            code(network.security),
            hex::encode(network.password.as_bytes())
        ));
    }
    fs::write(file(dir), text).with_context(|| format!("write {}", file(dir).display()))?;
    fs::set_permissions(file(dir), fs::Permissions::from_mode(0o600)).with_context(|| format!("close {}", file(dir).display()))
}

/// Keep `network`, in place of the one of the same name the phone held,
/// or beside the others.
pub fn remember(dir: &Path, network: Saved) -> Result<()> {
    let mut held = load(dir).unwrap_or_default();
    held.retain(|held| held.ssid != network.ssid);
    held.push(network);
    save(dir, &held)
}

/// Take the network of `ssid` from the ones the phone holds. Where the
/// phone holds none at all, this is done already.
pub fn forget(dir: &Path, ssid: &[u8]) -> Result<()> {
    if !file(dir).exists() {
        return Ok(());
    }
    let mut held = load(dir)?;
    held.retain(|held| held.ssid != ssid);
    save(dir, &held)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// A directory of one's own, empty to start.
    fn tempdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("skyward-saved-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A network written comes back whole, name bytes of any kind and a
    /// password with spaces in it and all.
    #[test]
    fn a_network_written_comes_back_whole() {
        let dir = tempdir("round-trip");
        let odd = Saved {
            ssid: vec![0xC3, 0x28, 0x00, b'a'],
            security: Security::Psk,
            password: "the pass word".into(),
        };
        save(&dir, std::slice::from_ref(&odd)).unwrap();
        assert_eq!(load(&dir).unwrap(), vec![odd]);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A network of the same name takes the place of the one held, and
    /// the others stay.
    #[test]
    fn a_network_of_the_same_name_takes_the_place_of_the_one_held() {
        let dir = tempdir("remember");
        let first = Saved { ssid: b"home".to_vec(), security: Security::PskSae, password: "1st".into() };
        let second = Saved { ssid: b"work".to_vec(), security: Security::Open, password: String::new() };
        remember(&dir, first.clone()).unwrap();
        remember(&dir, second.clone()).unwrap();
        let again = Saved { ssid: b"home".to_vec(), security: Security::Psk, password: "2nd".into() };
        remember(&dir, again.clone()).unwrap();
        assert_eq!(load(&dir).unwrap(), vec![second, again]);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A file half written stays readable for the rest of it.
    #[test]
    fn a_line_that_says_nothing_readable_is_passed_over() {
        let dir = tempdir("half-written");
        let good = Saved { ssid: b"home".to_vec(), security: Security::Psk, password: "the password".into() };
        save(&dir, std::slice::from_ref(&good)).unwrap();
        let mut text = fs::read_to_string(file(&dir)).unwrap();
        text.push_str("not a line of the file\nzz yy\n");
        fs::write(file(&dir), text).unwrap();
        assert_eq!(load(&dir).unwrap(), vec![good]);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// The file is closed to others, for a password is in it.
    #[test]
    fn the_file_is_closed_to_others() {
        let dir = tempdir("closed");
        save(&dir, &[Saved { ssid: b"home".to_vec(), security: Security::Open, password: String::new() }]).unwrap();
        let said = Command::new("stat").arg("-c").arg("%a").arg(file(&dir)).output().unwrap();
        assert_eq!(String::from_utf8_lossy(&said.stdout).trim(), "600");
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A network taken is gone, and the others stay; where the phone
    /// holds none, the taking is done already.
    #[test]
    fn a_network_taken_is_gone_and_the_others_stay() {
        let dir = tempdir("forget");
        let home = Saved { ssid: b"home".to_vec(), security: Security::Psk, password: "the password".into() };
        let work = Saved { ssid: b"work".to_vec(), security: Security::Open, password: String::new() };
        save(&dir, &[home, work.clone()]).unwrap();
        forget(&dir, b"home").unwrap();
        assert_eq!(load(&dir).unwrap(), vec![work.clone()]);
        forget(&dir, b"home").unwrap();
        assert_eq!(load(&dir).unwrap(), vec![work.clone()]);
        let empty = tempdir("forget-none");
        forget(&empty, b"home").unwrap();
        assert!(load(&empty).is_err(), "a phone that held none holds none still");
        fs::remove_dir_all(&dir).unwrap();
        fs::remove_dir_all(&empty).unwrap();
    }
}
