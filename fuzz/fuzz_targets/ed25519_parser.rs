#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    prophet::fuzzing::fuzz_ed25519_parser(data);
});
