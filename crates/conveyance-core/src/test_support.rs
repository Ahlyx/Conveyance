//! Shared test doubles for `conveyance-core` and its dependent crates.
//!
//! Compiled for this crate's own `#[cfg(test)]` builds and, for the
//! daemon and shim test suites, behind the `test-support` feature.
//! `#[cfg(test)]` items are invisible across crate boundaries, which is
//! exactly why the keychain stub below was previously re-implemented
//! three times (in `storage::identity`, in `conveyance-daemon`'s test
//! module, and in its `mockphone` module).

use std::collections::HashMap;
use std::sync::Mutex;

use crate::storage::StorageError;
use crate::storage::identity::KeyProvider;

/// In-memory stand-in for the OS keychain.
///
/// `fail` simulates the whole credential service being unreachable
/// (e.g. no D-Bus session, locked keychain) -- distinct from an entry
/// that is simply absent, which is a plain `Ok(None)`.
pub struct MockKeyProvider {
    entries: Mutex<HashMap<String, Vec<u8>>>,
    pub fail: bool,
}

impl MockKeyProvider {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            fail: false,
        }
    }

    /// Drop one stored entry, to exercise the "key material missing after
    /// it was written" recovery path.
    pub fn remove(&self, account: &str) {
        self.entries.lock().unwrap().remove(account);
    }
}

impl Default for MockKeyProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyProvider for MockKeyProvider {
    fn get(&self, account: &str) -> Result<Option<Vec<u8>>, StorageError> {
        if self.fail {
            return Err(StorageError::KeychainUnavailable(
                "mock: credential service unavailable".into(),
            ));
        }
        Ok(self.entries.lock().unwrap().get(account).cloned())
    }

    fn set(&self, account: &str, value: &[u8]) -> Result<(), StorageError> {
        if self.fail {
            return Err(StorageError::KeychainUnavailable(
                "mock: credential service unavailable".into(),
            ));
        }
        self.entries
            .lock()
            .unwrap()
            .insert(account.to_string(), value.to_vec());
        Ok(())
    }
}
