#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    custode::config::fuzzing::allowed_operation_parse(data);
});
