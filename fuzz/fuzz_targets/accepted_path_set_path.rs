#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _accepted = custode::target::fuzzing::accepted_path_set_path(data);
});
