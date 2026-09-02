//! Re-export of the `conveyance-noise` leaf crate.
//!
//! The `Noise_KK_25519_ChaChaPoly_BLAKE2s` wrapper was extracted to
//! `conveyance-noise` (phase 10.4) so the Android side reaches the same
//! `snow` through UniFFI. This module keeps
//! `conveyance_core::session::noise::*` paths working and adapts the leaf
//! crate's [`NoiseError`] onto this crate's [`ConveyanceError`].

pub use conveyance_noise::{NoiseError, Role, SessionHandshake, SessionTransport};

use crate::error::ConveyanceError;

impl From<NoiseError> for ConveyanceError {
    fn from(e: NoiseError) -> Self {
        match e {
            NoiseError::HandshakeFailed => ConveyanceError::HandshakeFailed,
            NoiseError::SessionEnded => ConveyanceError::SessionEnded,
        }
    }
}
