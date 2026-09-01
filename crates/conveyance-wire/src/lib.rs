//! Conveyance BLE framing — the layer between an application message and
//! the bytes a GATT operation carries.
//!
//! [`framing`] encodes/splits a message into wire frames and reassembles
//! frames back into messages under strict sequence and size discipline;
//! [`assembler`] adds the byte-stream buffering a sub-MTU transport needs
//! on the inbound side. Everything here is pure — no async, no I/O, no
//! transport types — so it fuzzes without a runtime and cross-compiles to
//! Android unchanged.
//!
//! Extracted from `conveyance-core::wire::framing` in phase 10.3: the
//! Android side re-implements this format in Kotlin, and a fixture-parity
//! suite drift-gates the two against the vectors this crate emits. Having
//! one leaf crate own the format keeps that gate honest.
//!
//! `conveyance-core` re-exports this as `conveyance_core::wire::framing`,
//! so existing PC-side call sites are unchanged.

pub mod assembler;
pub mod framing;

pub use assembler::InboundAssembler;
pub use framing::FrameError;
