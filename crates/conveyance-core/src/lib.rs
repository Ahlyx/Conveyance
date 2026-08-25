//! Shared foundations for the Conveyance PC-side components.
//!
//! This crate holds only what both the daemon and the MCP shim need and
//! nothing protocol-specific: platform paths, config parsing, and the
//! structured error model. Cryptographic primitives (phase 1), storage
//! (phase 2), sessions (phase 3) and everything above them live elsewhere
//! by design -- keeping this crate dependency-light keeps it reviewable,
//! and everything in it ends up on a security-relevant path eventually.
//!
//! The specification is `CONVEYANCE_SPEC.md` in the repository root. When
//! this code and the spec disagree, the spec is right and this code needs
//! fixing.

pub mod config;
pub mod error;
pub mod paths;
