#![no_main]

// Fuzz target: the CBOR message decoder. Any panic is a bug; decode
// errors (including UnknownEnumValue for closed enums) are success.

use libfuzzer_sys::fuzz_target;
use conveyance_core::wire;

fuzz_target!(|data: &[u8]| {
    let _ = wire::message::decode(data);
});
