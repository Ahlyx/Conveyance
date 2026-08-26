//! Replay gate for pairing nonces: a fixed-seed bloom filter with
//! 48-hour retention, persisted across daemon restarts.
//!
//! Why the seed is FIXED rather than random: the filter must be
//! serialized to disk and reloaded by later processes. A per-process
//! random hash would make every restart forget every recorded nonce,
//! silently voiding replay protection. Secrecy of the seed is
//! irrelevant -- false positives merely reject one fresh pairing attempt
//! (user retries), and false negatives are impossible in a bloom filter.
//!
//! Failure posture (deliberate): a corrupt, truncated, or wrong-seed
//! file is logged, discarded, and replaced with a fresh filter -- never
//! a fatal error. Worst case is lost replay memory for one window,
//! which is identical to first-run behavior.
//!
//! Retention: entries older than 48 hours cannot expire individually in
//! a bloom filter, so the WHOLE filter resets when its age exceeds 48h.
//! A nonce recorded at T therefore stays rejected until T+48h at the
//! latest -- matching "48-hour retention" conservatively.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use bloomfilter::Bloom;

const MAGIC: &[u8; 8] = b"CVYNONC1";
/// Expected pairing attempts within one 48h window; generous.
const EXPECTED_ITEMS: usize = 10_000;
/// False-positive rate: rare enough to be invisible, small enough to
/// keep the file ~17 KB.
const FP_RATE: f64 = 1e-6;
pub const RETENTION: Duration = Duration::from_secs(48 * 3600);

/// Fixed seed for deterministic hashing across processes. Arbitrary
/// bytes; nothing about them is secret or meaningful.
const SEED: [u8; 32] = [0x5Au8; 32];

#[derive(Debug)]
pub struct NonceGuard {
    path: PathBuf,
    filter: Bloom<[u8; 32]>,
    created_at: SystemTime,
}

impl NonceGuard {
    /// Open (or create) the persisted filter. NEVER fails: any problem
    /// with the file degrades to an empty in-memory filter, per the
    /// module docs.
    pub fn open(path: &Path) -> Self {
        match Self::try_load(path) {
            Some(guard) => guard,
            None => Self::fresh(path),
        }
    }

    fn try_load(path: &Path) -> Option<Self> {
        let blob = std::fs::read(path).ok()?;
        if blob.len() < MAGIC.len() + 8 + 32 + 1 || &blob[..8] != MAGIC {
            eprintln!(
                "warning: discarding corrupt nonce filter at {} (bad header)",
                path.display()
            );
            return None;
        }
        let created_unix = i64::from_be_bytes(blob[8..16].try_into().ok()?);
        let created = SystemTime::UNIX_EPOCH + Duration::from_secs(created_unix.max(0) as u64);
        if created.elapsed().unwrap_or(RETENTION) > RETENTION {
            eprintln!(
                "warning: nonce filter at {} expired (>48h); starting fresh",
                path.display()
            );
            return None;
        }
        let seed: [u8; 32] = blob[16..48].try_into().ok()?;
        if seed != SEED {
            eprintln!(
                "warning: nonce filter at {} was written with another seed; starting fresh",
                path.display()
            );
            return None;
        }
        let filter = Bloom::from_slice(&blob[48..]).ok()?;
        Some(Self {
            path: path.to_path_buf(),
            filter,
            created_at: created,
        })
    }

    fn fresh(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            filter: Bloom::new_for_fp_rate_with_seed(EXPECTED_ITEMS, FP_RATE, &SEED)
                .expect("fixed parameters are valid"),
            created_at: SystemTime::now(),
        }
    }

    fn maybe_rotate(&mut self) {
        // Crossing the retention boundary mid-process resets everything,
        // same as loading an aged file would.
        if self.created_at.elapsed().unwrap_or(RETENTION) > RETENTION {
            self.filter = Bloom::new_for_fp_rate_with_seed(EXPECTED_ITEMS, FP_RATE, &SEED)
                .expect("fixed parameters are valid");
            self.created_at = SystemTime::now();
        }
    }

    /// Record `nonce` as consumed. Returns true if it was ALREADY seen
    /// (replay). Persists immediately: a crash right after a successful
    /// pairing must not lose the replay memory for that nonce.
    pub fn record_and_check(&mut self, nonce: &[u8; 32]) -> bool {
        self.maybe_rotate();
        let seen = self.filter.check_and_set(nonce);
        self.flush();
        seen
    }

    /// Read-only membership probe. Does not record.
    pub fn contains(&self, nonce: &[u8; 32]) -> bool {
        self.filter.check(nonce)
    }

    fn flush(&self) {
        let mut blob = Vec::with_capacity(8 + 8 + 32 + self.filter.as_slice().len());
        blob.extend_from_slice(MAGIC);
        let unix = self
            .created_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        blob.extend_from_slice(&unix.to_be_bytes());
        blob.extend_from_slice(&SEED);
        blob.extend_from_slice(self.filter.as_slice());

        // Atomic replace so a crash mid-write leaves either the old file
        // or a complete new one -- the corrupt-file path above exists for
        // filesystems where even this is not enough.
        let tmp = self.path.with_extension("tmp");
        if std::fs::write(&tmp, blob).is_ok() && std::fs::rename(&tmp, &self.path).is_ok() {
            return;
        }
        eprintln!(
            "warning: could not persist nonce filter to {}; replay protection is process-local only",
            self.path.display()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(seed: u8) -> [u8; 32] {
        let mut out = [seed; 32];
        out[31] ^= 0x5A;
        out
    }

    #[test]
    fn fresh_nonce_accepted_once_then_replay_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonces.bin");
        let mut guard = NonceGuard::open(&path);

        assert!(!guard.record_and_check(&n(1)), "first sighting is fresh");
        assert!(guard.contains(&n(1)));
        assert!(!guard.contains(&n(2)));

        let reopened = NonceGuard::open(&path);
        assert!(reopened.contains(&n(1)), "persistence across reopen");
    }

    #[test]
    fn persistence_survives_process_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonces.bin");

        {
            let mut g = NonceGuard::open(&path);
            assert!(!g.record_and_check(&n(9)));
        } // dropped

        // New "process": replaying the same nonce must still trip.
        let mut g2 = NonceGuard::open(&path);
        assert!(g2.record_and_check(&n(9)), "replay after restart");
        assert!(!g2.record_and_check(&n(10)));
    }

    #[test]
    fn corrupt_file_degrades_to_fresh_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonces.bin");
        std::fs::write(&path, b"garbage-not-a-filter").unwrap();

        let mut guard = NonceGuard::open(&path);
        // Works from empty state...
        assert!(!guard.record_and_check(&n(3)));
        // ...and heals the file on flush.
        let reopened = NonceGuard::open(&path);
        assert!(reopened.contains(&n(3)));
    }

    #[test]
    fn truncated_header_also_degrades() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("short.bin");
        std::fs::write(&path, b"CVY").unwrap();
        let mut guard = NonceGuard::open(&path);
        assert!(!guard.record_and_check(&n(4)));
    }

    #[test]
    fn foreign_seed_file_is_discarded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("foreign.bin");

        // Hand-craft a valid-looking file with a DIFFERENT seed.
        let other: Bloom<[u8; 32]> =
            Bloom::new_for_fp_rate_with_seed(EXPECTED_ITEMS, FP_RATE, &[0x11; 32]).unwrap();
        let mut blob = Vec::new();
        blob.extend_from_slice(MAGIC);
        blob.extend_from_slice(
            &(SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64)
                .to_be_bytes(),
        );
        blob.extend_from_slice(&[0x11; 32]);
        blob.extend_from_slice(other.as_slice());
        std::fs::write(&path, blob).unwrap();

        // Must not trust it: fresh filter knows nothing.
        let guard = NonceGuard::open(&path);
        assert!(!guard.contains(&n(5)));
    }

    #[test]
    fn aged_file_is_discarded_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.bin");

        // Write a file whose created_at is 49 hours ago.
        let old_filter: Bloom<[u8; 32]> =
            Bloom::new_for_fp_rate_with_seed(EXPECTED_ITEMS, FP_RATE, &SEED).unwrap();
        let mut blob = Vec::new();
        blob.extend_from_slice(MAGIC);
        let old_unix = (SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64)
            - 49 * 3600;
        blob.extend_from_slice(&old_unix.to_be_bytes());
        blob.extend_from_slice(&SEED);
        blob.extend_from_slice(old_filter.as_slice());
        std::fs::write(&path, blob).unwrap();

        // Fresh open: no memory of anything, and rotation resets the clock.
        let mut guard = NonceGuard::open(&path);
        assert!(!guard.contains(&n(6)));
        assert!(!guard.record_and_check(&n(6)));
    }
}
