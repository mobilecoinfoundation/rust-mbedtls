/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use mbedtls_sys::types::raw_types::{c_int, c_uchar, c_void};
use mbedtls_sys::types::size_t;
use core::num::Wrapping as w;

/// An Xorshift random number generator.
///
/// The Xorshift[^1] algorithm is not suitable for cryptographic purposes
/// but is very fast. If you do not know for sure that it fits your
/// requirements, use a more secure one such as `IsaacRng` or `OsRng`.
///
/// [^1]: Marsaglia, George (July 2003).
///       ["Xorshift RNGs"](https://www.jstatsoft.org/v08/i14/paper).
///       *Journal of Statistical Software*. Vol. 8 (Issue 14).
#[derive(Clone, Debug)]
struct XorShiftRng {
    x: w<u32>,
    y: w<u32>,
    z: w<u32>,
    w: w<u32>,
}

impl XorShiftRng {
    /// Creates a new XorShiftRng instance which is not seeded.
    ///
    /// The initial values of this RNG are constants, so all generators created
    /// by this function will yield the same stream of random numbers. It is
    /// highly recommended that this is created through `SeedableRng` instead of
    /// this function
    pub fn new_unseeded() -> XorShiftRng {
        XorShiftRng {
            x: w(0x193a6754),
            y: w(0xa8a7d469),
            z: w(0x97830e05),
            w: w(0x113ba7bb),
        }
    }
}

impl XorShiftRng {
    #[inline]
    fn next_u32(&mut self) -> u32 {
        let x = self.x;
        let t = x ^ (x << 11);
        self.x = self.y;
        self.y = self.z;
        self.z = self.w;
        let w_ = self.w;
        self.w = w_ ^ (w_ >> 19) ^ (t ^ (t >> 8));
        self.w.0
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        ((self.next_u32() as u64) << 32) | (self.next_u32() as u64)
    }

    #[inline]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // this could, in theory, be done by transmuting dest to a
        // [u64], but this is (1) likely to be undefined behaviour for
        // LLVM, (2) has to be very careful about alignment concerns,
        // (3) adds more `unsafe` that needs to be checked, (4)
        // probably doesn't give much performance gain if
        // optimisations are on.
        let mut count = 0;
        let mut num = 0;
        for byte in dest.iter_mut() {
            if count == 0 {
                // we could micro-optimise here by generating a u32 if
                // we only need a few more bytes to fill the vector
                // (i.e. at most 4).
                num = self.next_u64();
                count = 8;
            }

            *byte = (num & 0xff) as u8;
            num >>= 8;
            count -= 1;
        }
    }
}

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
    TestRandom(XorShiftRng::new_unseeded())
}
