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
    const SEED: [u8; 16] = [
        0x19, 0x3a, 0x67, 0x54,
        0xa8, 0xa7, 0xd4, 0x69,
        0x97, 0x83, 0x0e, 0x05,
        0x11, 0x3b, 0xa7, 0xbb
    ];
    TestRandom(XorShiftRng::from_seed(SEED))
}
