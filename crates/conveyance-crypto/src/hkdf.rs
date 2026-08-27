//! RFC 5869 HKDF instantiated with BLAKE2s, implemented directly.
//!
//! Why hand-written when an `hkdf` crate exists: RustCrypto's `hkdf`
//! and `hmac` require a hash core with *Eager* buffering, and BLAKE2s
//! is *Lazy* -- the combination does not compile, at any version of the
//! stack we pin. The primitive itself is fixed by the spec
//! (HKDF-BLAKE2s), so the options were this file or changing the
//! primitive; the spec wins.
//!
//! Risk containment, because hand-rolled KDF glue is where mistakes hide:
//!
//! * HMAC follows RFC 2104 exactly, over a 64-byte block and 32-byte
//!   output. Both SHA-256 and BLAKE2s fit that shape, so the code is
//!   **generic over the digest**, instantiated with SHA-256 in tests.
//! * Those SHA-256 instantiations are checked against ALL applicable
//!   official RFC 5869 test vectors (PRK *and* OKM). A wiring bug in
//!   HMAC or the extract/expand loop would fail them.
//! * What remains unproven by public vectors is only "BLAKE2s hashes
//!   these bytes correctly", which is the `blake2` crate's own tested
//!   contract, not ours.
//!
//! Zero salt note: callers pass the zero salt explicitly rather than an
//! `Option`, so the RFC 5869 §2.2 omission semantics are visible at the
//! call site instead of buried here.

use blake2::Blake2s256;
use sha2::Digest;
use sha2::digest::consts::U32;

/// HMAC block size for both supported digests (BLAKE2s and SHA-256).
const BLOCK: usize = 64;
pub(crate) const HASH_LEN: usize = 32;

/// RFC 2104 HMAC with fixed 32-byte output.
struct Hmac32<D: Digest<OutputSize = U32> + Clone> {
    ipad_state: D,
    opad_state: D,
}

impl<D: Digest<OutputSize = U32> + Clone> Hmac32<D> {
    fn new(key: &[u8]) -> Self {
        let mut block = [0u8; BLOCK];
        if key.len() > BLOCK {
            // Keys longer than the block are hashed first (RFC 2104 §2).
            let hashed = D::new().chain_update(key).finalize();
            block[..HASH_LEN].copy_from_slice(hashed.as_ref());
        } else {
            block[..key.len()].copy_from_slice(key);
        }

        let mut ipad = block;
        let mut opad = block;
        for b in ipad.iter_mut() {
            *b ^= 0x36;
        }
        for b in opad.iter_mut() {
            *b ^= 0x5c;
        }

        let mut ipad_state = D::new();
        Digest::update(&mut ipad_state, ipad);
        let mut opad_state = D::new();
        Digest::update(&mut opad_state, opad);

        Self {
            ipad_state,
            opad_state,
        }
    }

    fn sign(&self, parts: &[&[u8]]) -> [u8; HASH_LEN] {
        let mut inner = self.ipad_state.clone();
        for part in parts {
            Digest::update(&mut inner, part);
        }
        let inner_hash = inner.finalize();

        let mut outer = self.opad_state.clone();
        Digest::update(&mut outer, inner_hash);
        outer.finalize().into()
    }
}

/// HKDF-Extract (RFC 5869 §2.2).
fn extract<D: Digest<OutputSize = U32> + Clone>(salt: &[u8], ikm: &[u8]) -> [u8; HASH_LEN] {
    Hmac32::<D>::new(salt).sign(&[ikm])
}

/// HKDF-Expand (RFC 5869 §2.3): fills `okm` with up to 255 * 32 bytes.
fn expand<D: Digest<OutputSize = U32> + Clone>(prk: &[u8; HASH_LEN], info: &[u8], okm: &mut [u8]) {
    assert!(
        okm.len() <= 255 * HASH_LEN,
        "HKDF-Expand output cap exceeded: {} > 255*{}",
        okm.len(),
        HASH_LEN
    );

    let mac = Hmac32::<D>::new(prk);
    let mut prev: [u8; HASH_LEN] = [0u8; HASH_LEN];
    let mut done = 0usize;
    let mut counter: u8 = 1;

    while done < okm.len() {
        let chunk = if okm.len() - done < HASH_LEN {
            &mut okm[done..]
        } else {
            &mut okm[done..done + HASH_LEN]
        };

        let has_prev = counter > 1;
        let parts: [&[u8]; 3] = [if has_prev { &prev } else { &[] }, info, &[counter]];
        let t = mac.sign(&parts);
        chunk.copy_from_slice(&t[..chunk.len()]);
        prev = t;

        done += chunk.len();
        counter += 1;
    }
}

/// Full HKDF-BLAKE2s with the spec's salt semantics: omitted salt means
/// 32 zero bytes (RFC 5869 §2.2; see CONVEYANCE_SPEC.md amendment).
pub fn hkdf_blake2s(ikm: &[u8], info: &[u8], okm: &mut [u8]) {
    let prk = extract::<Blake2s256>(&[0u8; HASH_LEN], ikm);
    expand::<Blake2s256>(&prk, info, okm);
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha256;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 5869 Appendix A, Test Case 1 (SHA-256): basic shape.
    #[test]
    fn rfc5869_sha256_test_case_1() {
        let ikm = vec![0x0bu8; 22];
        let salt = hex("000102030405060708090a0b0c");
        let info = hex("f0f1f2f3f4f5f6f7f8f9");

        let prk = extract::<Sha256>(&salt, &ikm);
        assert_eq!(
            prk.to_vec(),
            hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        );

        let mut okm = [0u8; 42];
        expand::<Sha256>(&prk, &info, &mut okm);
        assert_eq!(
            okm.to_vec(),
            hex(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
            )
        );
    }

    /// RFC 5869 Appendix A, Test Case 2 (SHA-256): 80-octet inputs,
    /// multi-round expansion with a partial final chunk. Inputs and
    /// outputs transcribed from the RFC text itself after an in-memory
    /// transcription invented plausible-but-wrong IKM/salt bytes.
    #[test]
    fn rfc5869_sha256_test_case_2() {
        let ikm: Vec<u8> = (0x00..=0x4f).collect();
        let salt: Vec<u8> = (0x60..=0xaf).collect();
        let info: Vec<u8> = (0xb0..=0xff).collect();

        let prk = extract::<Sha256>(&salt, &ikm);
        assert_eq!(
            prk.to_vec(),
            hex("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244")
        );

        let mut okm = [0u8; 82];
        expand::<Sha256>(&prk, &info, &mut okm);
        assert_eq!(
            okm.to_vec(),
            hex(
                "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
                 59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
                 cc30c58179ec3e87c14c01d5c1f3434f1d87"
            )
        );
    }

    /// RFC 5869 Test Case 3: zero-length salt and info. This is the
    /// closest official vector to Conveyance's production call shape
    /// (zero salt per RFC 5869 §2.2), so it is load-bearing, not
    /// decorative.
    #[test]
    fn rfc5869_sha256_test_case_3_zero_salt_and_info() {
        let ikm = vec![0x0bu8; 22];

        let prk = extract::<Sha256>(&[], &ikm);
        assert_eq!(
            prk.to_vec(),
            hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")
        );

        let mut okm = [0u8; 42];
        expand::<Sha256>(&prk, &[], &mut okm);
        assert_eq!(
            okm.to_vec(),
            hex(
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
            )
        );
    }

    /// RFC 4231 Test Case 6: HMAC-SHA256 with a key larger than the block
    /// size (131 bytes of 0xaa), which is the hash-the-key-first branch
    /// of `Hmac32::new`. No RFC 5869 vector exercises that branch with
    /// SHA-256, and it must be covered before this module can claim the
    /// coverage bar. Expected value transcribed from RFC 4231 §2.6.6.
    #[test]
    fn rfc4231_larger_than_block_size_key() {
        let key = vec![0xaau8; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let mac = Hmac32::<Sha256>::new(&key);
        assert_eq!(
            mac.sign(&[data]).to_vec(),
            hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
        );
    }

    /// BLAKE2s instantiation has no official vectors (see module docs);
    /// what IS pinned here: determinism, info sensitivity, correct
    /// multi-round/partial-final expansion mechanics on the production
    /// digest.
    #[test]
    fn blake2s_instantiation_properties() {
        let seed = [0x5au8; 64];

        let mut ed = [0u8; 32];
        let mut x = [0u8; 32];
        hkdf_blake2s(&seed, b"conveyance-v1-identity-ed25519", &mut ed);
        hkdf_blake2s(&seed, b"conveyance-v1-identity-x25519", &mut x);

        assert_ne!(ed, x, "distinct info strings must derive distinct keys");

        let mut again = [0u8; 32];
        hkdf_blake2s(&seed, b"conveyance-v1-identity-ed25519", &mut again);
        assert_eq!(ed, again);

        // Multi-block expansion with a partial final chunk must fill
        // every byte and stay prefix-stable across lengths.
        let mut long = [0u8; 65];
        hkdf_blake2s(&seed, b"length probe", &mut long);
        assert!(long.iter().any(|&b| b != 0));
        let mut shorter = [0u8; 33];
        hkdf_blake2s(&seed, b"length probe", &mut shorter);
        assert_eq!(&long[..33], &shorter[..]);
    }

    #[test]
    #[should_panic(expected = "output cap")]
    fn expansion_beyond_255_blocks_panics_loudly() {
        let mut too_big = [0u8; 255 * HASH_LEN + 1];
        hkdf_blake2s(&[0u8; 64], b"x", &mut too_big);
    }
}
