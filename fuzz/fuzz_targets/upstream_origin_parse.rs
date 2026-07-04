#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    custode::config::fuzzing::upstream_origin_parse(data);
});
