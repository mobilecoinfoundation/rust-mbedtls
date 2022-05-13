/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use mbedtls_sys::types::raw_types::{c_int, c_uchar, c_void};
use mbedtls_sys::types::size_t;

use rand_core::{RngCore, SeedableRng};
use rand_xorshift::XorShiftRng;

/// Not cryptographically secure!!! Use for testing only!!!
pub struct TestRandom(XorShiftRng);

impl crate::mbedtls::rng::RngCallbackMut for TestRandom {
    unsafe extern "C" fn call_mut(p_rng: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        (*(p_rng as *mut TestRandom))
            .0
            .fill_bytes(core::slice::from_raw_parts_mut(data, len));
        0
    }

    fn data_ptr_mut(&mut self) -> *mut c_void {
        self as *const _ as *mut _
    }
}

impl crate::mbedtls::rng::RngCallback for TestRandom {
    unsafe extern "C" fn call(p_rng: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        (*(p_rng as *mut TestRandom))
            .0
            .fill_bytes(core::slice::from_raw_parts_mut(data, len));
        0
    }

    fn data_ptr(&self) -> *mut c_void {
        self as *const _ as *mut _
    }
}


/// Not cryptographically secure!!! Use for testing only!!!
pub fn test_rng() -> TestRandom {
    const SEED: [u32; 4] = [
        0x193a6754,
        0xa8a7d469,
        0x97830e05,
        0x113ba7bb,
    ];

    let mut seed_bytes = [0u8; 16];

    for (index, value) in SEED.iter().enumerate() {
        let bytes = value.to_le_bytes();
        seed_bytes[index * 4..index * 4 + 4].copy_from_slice(&bytes);
    }

    let mut out_seed = [0u32; 4];
    rand_core::le::read_u32_into(&seed_bytes, &mut out_seed);

    extern crate std;
    std::eprintln!("SEED: {:08x?}, seed_bytes: {:02x?}, out_seed: {:08x?}", SEED, seed_bytes, out_seed);

    TestRandom(XorShiftRng::from_seed(seed_bytes))
}
