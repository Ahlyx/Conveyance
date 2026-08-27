# R8 is disabled for the release build in Phase 10.0 (see app/build.gradle.kts):
# there is no code to shrink or obfuscate yet. Real keep rules -- for the
# BLE GATT callbacks, CBOR/serde types, and any JNI/UniFFI surface -- land
# with the code that needs them in later sub-phases.
