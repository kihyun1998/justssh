#![no_main]
//! `justssh_fuzz::transport` on every input libFuzzer makes.

libfuzzer_sys::fuzz_target!(|data: &[u8]| justssh_fuzz::transport(data));
