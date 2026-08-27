//! Shared foundations for the Conveyance PC-side components: everything
//! the daemon and the MCP shim build on that is not itself an executable.
//!
//! The daemon and the shim are thin by design; the substance lives here:
//! platform paths and config ([`paths`], [`config`]), the structured
//! error model ([`error`]), cryptographic primitives ([`crypto`]),
//! encrypted storage and the hash-chained log ([`storage`]), the Noise
//! session and its state machine ([`session`]), the CBOR wire protocol
//! and framing ([`wire`]), the BLE/mock transport seam ([`transport`]),
//! and the pairing ceremony ([`pairing`]). Almost everything here ends up
//! on a security-relevant path, which is why it is kept together and
//! reviewable rather than scattered across the binaries.
//!
//! The specification is `CONVEYANCE_SPEC.md` in the repository root. When
//! this code and the spec disagree, the spec is right and this code needs
//! fixing.

pub mod config;
pub mod crypto;
pub mod error;
pub mod pairing;
pub mod paths;
pub mod session;
pub mod storage;
pub mod transport;
pub mod wire;
