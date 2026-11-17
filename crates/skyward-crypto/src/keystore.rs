use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha512};
use std::fs;
use std::path::Path;

/// A hash is personalised by a fixed prefix padded out to one SHA-512 block,
/// so the same bytes hashed for two purposes never agree.
const PREFIX_BYTES: usize = 128;

const SECDISCARDABLE_PREFIX: &[u8] = b"Android secdiscardable SHA512";
const KEYGEN_PREFIX: &[u8] = b"Android key wrapping key generation SHA512";

const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const KEY_BYTES: usize = 32;

/// The only layout Android writes these directories in.
const VERSION: &str = "1";

const FN_VERSION: &str = "version";
const FN_ENCRYPTED_KEY: &str = "encrypted_key";
const FN_KEY_BLOB: &str = "keymaster_key_blob";
const FN_SECDISCARDABLE: &str = "secdiscardable";
const FN_STRETCHING: &str = "stretching";

/// The two words Android writes in the stretching file of a key it did not
/// stretch: `nopassword` for a key its key service holds in hardware, and
/// `none` for a key wrapped with the user's secret, which is how the key
/// of a user who set a screen lock is kept. A build old enough to keep no
/// such file at all stretched none either.
const HARDWARE_HELD: &str = "nopassword";
const SECRET_HELD: &str = "none";
const UNSTRETCHED: [&str; 2] = [HARDWARE_HELD, SECRET_HELD];

/// Whether the key in `dir` is wrapped with the user's secret, as the
/// stretching file names it. A key the key service holds in hardware opens
/// behind nothing the user knows, whatever the phone keeps about a
/// credential: the phone may keep the state of a screen lock its owner has
/// taken away.
pub fn held_by_secret(dir: &Path) -> bool {
    match fs::read_to_string(dir.join(FN_STRETCHING)) {
        // A key the phone stretched is stretched with an algorithm of its
        // own, which this does not carry; it is refused where the key
        // itself is read, and counts as the hardware's here.
        Ok(algorithm) => algorithm.trim() == SECRET_HELD,
        Err(_) => true,
    }
}

/// SHA-512 of `data` behind a fixed prefix.
pub fn hash_with_prefix(prefix: &[u8], data: &[u8]) -> Vec<u8> {
    let mut padded = prefix.to_vec();
    padded.resize(PREFIX_BYTES, 0);
    let mut h = Sha512::new();
    h.update(&padded);
    h.update(data);
    h.finalize().to_vec()
}

/// Where a wrapped key's wrapping comes from.
pub enum Unwrap<'a, K: Decryptor> {
    /// The phone's key service holds the wrapping key in hardware. Nothing
    /// the user knows is needed, so this is how the metadata key and the
    /// keys for data that is readable before anyone signs in are kept.
    Hardware(&'a K),
    /// A secret only the user's credential leads to wraps the key, in
    /// software. This is how each user's own data is kept.
    Secret(&'a [u8]),
}

/// What can undo an AES-GCM encryption bound to an application id. The key
/// service on the phone is the one that can; naming it this way keeps the
/// key handling testable away from a phone.
pub trait Decryptor {
    fn gcm_decrypt(&self, key_blob: &[u8], app_id: &[u8], nonce: &[u8], body: &[u8]) -> Result<Vec<u8>>;
}

/// One wrapped key as Android leaves it on disk.
pub struct StoredKey {
    encrypted: Vec<u8>,
    key_blob: Option<Vec<u8>>,
    /// The hash of the blob whose erasure makes the key unrecoverable.
    /// Directories written without one hash nothing.
    secdiscardable_hash: Vec<u8>,
}

impl StoredKey {
    pub fn load(dir: &Path) -> Result<StoredKey> {
        let read = |name: &str| fs::read(dir.join(name)).with_context(|| format!("read {}", dir.join(name).display()));
        let version = match fs::read_to_string(dir.join(FN_VERSION)) {
            Ok(version) => version,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => bail!(
                "{} holds no key: either the metadata partition did not come up, or the phone's system has not written one since it was last wiped. Start that system once, and where this stays, send what `ls -la {}/..` and the recovery's log say",
                dir.display(),
                dir.display()
            ),
            Err(e) => return Err(e).with_context(|| format!("read {}", dir.join(FN_VERSION).display())),
        };
        if version.trim() != VERSION {
            bail!("{} is written in layout {}, Skyward reads layout {VERSION}", dir.display(), version.trim());
        }
        if let Ok(algorithm) = fs::read_to_string(dir.join(FN_STRETCHING)) {
            // A key the phone stretched is stretched with an algorithm of
            // its own, which this does not carry: only the two words
            // Android writes for a key it left as it was are read on.
            let algorithm = algorithm.trim();
            if !UNSTRETCHED.contains(&algorithm) {
                bail!("{} is stretched with {algorithm}, which Skyward does not read", dir.display());
            }
        }
        let secdiscardable_hash = match dir.join(FN_SECDISCARDABLE).exists() {
            true => hash_with_prefix(SECDISCARDABLE_PREFIX, &read(FN_SECDISCARDABLE)?),
            false => Vec::new(),
        };
        let key_blob = match dir.join(FN_KEY_BLOB).exists() {
            true => Some(read(FN_KEY_BLOB)?),
            false => None,
        };
        Ok(StoredKey { encrypted: read(FN_ENCRYPTED_KEY)?, key_blob, secdiscardable_hash })
    }

    /// What the wrapping is bound to: the directory's own hash and whatever
    /// secret guards it. A wrong secret gives a wrong binding, and the
    /// unwrapping fails rather than producing a key that looks usable.
    fn app_id(&self, secret: &[u8]) -> Vec<u8> {
        let mut id = self.secdiscardable_hash.clone();
        id.extend_from_slice(secret);
        id
    }

    /// What the phone's key service says the wrapping key may be used for.
    #[cfg(target_os = "android")]
    pub fn authorizations(&self, service: &crate::keymint::KeyMint) -> Result<Vec<(i32, i64)>> {
        let blob = self.key_blob.as_ref().context("this key is wrapped by a secret, not by the key service")?;
        service.authorizations(blob, &self.app_id(&[]))
    }

    /// The key itself.
    pub fn unwrap<K: Decryptor>(&self, how: Unwrap<K>) -> Result<Vec<u8>> {
        if self.encrypted.len() < NONCE_BYTES + TAG_BYTES {
            bail!("the wrapped key is {} bytes, too few to hold anything", self.encrypted.len());
        }
        let (nonce, body) = self.encrypted.split_at(NONCE_BYTES);
        match how {
            Unwrap::Hardware(service) => {
                let blob = self
                    .key_blob
                    .as_ref()
                    .context("this key is wrapped by a secret, and none was given")?;
                service.gcm_decrypt(blob, &self.app_id(&[]), nonce, body)
            }
            Unwrap::Secret(secret) => decrypt_with_secret(&self.app_id(secret), nonce, body),
        }
    }
}

/// Undo the software wrapping, whose key is `pre_key` hashed for that
/// purpose.
fn decrypt_with_secret(pre_key: &[u8], nonce: &[u8], body: &[u8]) -> Result<Vec<u8>> {
    let mut key = hash_with_prefix(KEYGEN_PREFIX, pre_key);
    key.truncate(KEY_BYTES);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    cipher
        .decrypt(Nonce::from_slice(nonce), body)
        .map_err(|_| anyhow::anyhow!("the wrapped key did not come apart; the secret is not the one it was wrapped with"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both hashes are checked against SHA-512 taken outside this code, so a
    /// change to the padding or the prefix shows up here.
    #[test]
    fn a_prefixed_hash_is_the_block_of_prefix_then_the_bytes() {
        let secdiscardable = hash_with_prefix(SECDISCARDABLE_PREFIX, b"test");
        assert_eq!(
            hex::encode(secdiscardable),
            "d29166a7b1dc78f68cdcb0e473a2d53421c932ee938167a2f41784e7f52adde2\
             02256f9eb3dcba42f08eef5be27bc87090e56c5b9099996f502939ab8961abcf"
        );
        let keygen = hash_with_prefix(KEYGEN_PREFIX, b"secret");
        assert_eq!(
            hex::encode(keygen),
            "1f0f944ae6b818481d8026af59a336cd84d6847475fa28196fc424a23794f21b\
             bae4f35a8be077f2c3fed1e4e5adbb58f1f97d522f5131b8cedcf4102478049d"
        );
    }

    /// Wrap a key the way Android does, to read it back.
    fn wrap(pre_key: &[u8], nonce: &[u8; NONCE_BYTES], key: &[u8]) -> Vec<u8> {
        let mut aes = hash_with_prefix(KEYGEN_PREFIX, pre_key);
        aes.truncate(KEY_BYTES);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes));
        let mut out = nonce.to_vec();
        out.extend_from_slice(&cipher.encrypt(Nonce::from_slice(nonce), key).expect("wrap"));
        out
    }

    struct NoService;

    impl Decryptor for NoService {
        fn gcm_decrypt(&self, _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Result<Vec<u8>> {
            bail!("no key service here")
        }
    }

    fn stored(secdiscardable: &[u8], encrypted: Vec<u8>) -> StoredKey {
        StoredKey {
            encrypted,
            key_blob: None,
            secdiscardable_hash: hash_with_prefix(SECDISCARDABLE_PREFIX, secdiscardable),
        }
    }

    #[test]
    fn a_key_wrapped_by_a_secret_comes_back_whole() {
        let key = [0xABu8; 64];
        let blob = [7u8; 256];
        let hash = hash_with_prefix(SECDISCARDABLE_PREFIX, &blob);
        let mut pre_key = hash.clone();
        pre_key.extend_from_slice(b"the user's secret");
        let s = stored(&blob, wrap(&pre_key, &[1; NONCE_BYTES], &key));
        assert_eq!(s.unwrap(Unwrap::<NoService>::Secret(b"the user's secret")).unwrap(), key.to_vec());
    }

    #[test]
    fn a_wrong_secret_is_refused_rather_than_giving_a_key() {
        let blob = [7u8; 256];
        let mut pre_key = hash_with_prefix(SECDISCARDABLE_PREFIX, &blob);
        pre_key.extend_from_slice(b"right");
        let s = stored(&blob, wrap(&pre_key, &[1; NONCE_BYTES], &[0xCDu8; 64]));
        let said = format!("{:#}", s.unwrap(Unwrap::<NoService>::Secret(b"wrong")).unwrap_err());
        assert!(said.contains("not the one it was wrapped with"), "{said}");
    }

    #[test]
    fn the_directory_it_came_from_is_bound_in() {
        let key = [0x11u8; 32];
        let mut pre_key = hash_with_prefix(SECDISCARDABLE_PREFIX, b"this directory");
        pre_key.extend_from_slice(b"s");
        let wrapped = wrap(&pre_key, &[2; NONCE_BYTES], &key);
        assert_eq!(stored(b"this directory", wrapped.clone()).unwrap(Unwrap::<NoService>::Secret(b"s")).unwrap(), key.to_vec());
        assert!(stored(b"another directory", wrapped).unwrap(Unwrap::<NoService>::Secret(b"s")).is_err());
    }

    #[test]
    fn a_key_the_hardware_holds_cannot_be_unwrapped_by_a_secret_alone() {
        let s = stored(b"x", vec![0; NONCE_BYTES + TAG_BYTES + 32]);
        let said = format!("{:#}", s.unwrap(Unwrap::Hardware(&NoService)).unwrap_err());
        assert!(said.contains("wrapped by a secret"), "{said}");
    }

    #[test]
    fn a_wrapped_key_too_short_to_hold_anything_is_refused() {
        let s = stored(b"x", vec![0; 20]);
        assert!(s.unwrap(Unwrap::<NoService>::Secret(b"s")).is_err());
    }

    /// A directory the phone's system has not written its key into yet has
    /// no version file, which says so rather than that the phone is too
    /// old or the key unreadable.
    #[test]
    fn a_directory_the_system_has_not_written_yet_says_so() {
        let dir = tempdir("not-written");
        assert!(refusal(&dir).contains("holds no key"), "{}", refusal(&dir));
    }

    /// A key the phone stretched is stretched with an algorithm of its own,
    /// which this does not carry. The words Android writes for a key it left
    /// as it was are read on: `nopassword` for one its key service holds,
    /// `none` for one wrapped with the user's secret, which is how the key
    /// of a user who set a screen lock is kept.
    #[test]
    fn a_stretched_key_is_refused_and_an_unstretched_one_is_read() {
        let dir = tempdir("stretching");
        fs::write(dir.join(FN_VERSION), "1").unwrap();
        fs::write(dir.join(FN_ENCRYPTED_KEY), [0u8; 64]).unwrap();
        fs::write(dir.join(FN_STRETCHING), "scrypt 15 8 1").unwrap();
        assert!(refusal(&dir).contains("scrypt 15 8 1"), "{}", refusal(&dir));
        for unstretched in UNSTRETCHED {
            fs::write(dir.join(FN_STRETCHING), unstretched).unwrap();
            assert!(StoredKey::load(&dir).is_ok(), "{} was refused", dir.display());
        }
        fs::remove_file(dir.join(FN_STRETCHING)).unwrap();
        fs::write(dir.join(FN_VERSION), "2").unwrap();
        assert!(refusal(&dir).contains("layout 2"), "{}", refusal(&dir));
    }

    /// A key the key service holds in hardware is behind nothing the user
    /// knows, whatever the phone keeps about a credential; one wrapped
    /// with the user's secret needs it. The word for each is the
    /// stretching file's own, and a key stretched with an algorithm of its
    /// own counts as the hardware's here, for its refusal to come where
    /// the key itself is read.
    #[test]
    fn the_stretching_file_says_whose_hand_the_key_is_in() {
        let dir = tempdir("held-by");
        fs::write(dir.join(FN_STRETCHING), HARDWARE_HELD).unwrap();
        assert!(!held_by_secret(&dir));
        fs::write(dir.join(FN_STRETCHING), SECRET_HELD).unwrap();
        assert!(held_by_secret(&dir));
        fs::write(dir.join(FN_STRETCHING), "scrypt 15 8 1").unwrap();
        assert!(!held_by_secret(&dir));
        fs::remove_file(dir.join(FN_STRETCHING)).unwrap();
        assert!(held_by_secret(&dir));
    }

    #[test]
    fn a_directory_without_a_secdiscardable_blob_binds_to_nothing_extra() {
        let dir = tempdir("no-secdiscardable");
        let key = [0x22u8; 32];
        fs::write(dir.join(FN_VERSION), "1").unwrap();
        fs::write(dir.join(FN_ENCRYPTED_KEY), wrap(b"only the secret", &[3; NONCE_BYTES], &key)).unwrap();
        let s = StoredKey::load(&dir).unwrap();
        assert!(s.secdiscardable_hash.is_empty());
        assert_eq!(s.unwrap(Unwrap::<NoService>::Secret(b"only the secret")).unwrap(), key.to_vec());
    }

    /// Why loading the directory was turned down.
    fn refusal(dir: &Path) -> String {
        match StoredKey::load(dir) {
            Err(e) => format!("{e:#}"),
            Ok(_) => panic!("{} was read where it should have been refused", dir.display()),
        }
    }

    fn tempdir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("skyward-keystore-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
