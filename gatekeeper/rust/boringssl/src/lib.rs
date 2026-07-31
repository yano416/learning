// Copyright 2025, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! BoringSSL-based implementations of Gatekeeper device-specific traits.
#![no_std]
extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use bssl_sys as ffi;
use gk_ta::{
    traits::{self, AccumulatingOperation, Aes256Key, AesCmac, HmacKey, OpaqueOr, AES_BLOCK_SIZE},
    Error,
};
use hal_wire::vec_try;
use log::error;

#[cfg(test)]
mod tests;

/// [`traits::Rng`] implementation based on BoringSSL.
#[derive(Default)]
pub struct Rng;

impl traits::Rng for Rng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        bssl_crypto::rand_bytes(dest)
    }
}

/// Constant time comparator based on BoringSSL.
#[derive(Clone)]
pub struct ConstEq;

impl traits::ConstTimeEq for ConstEq {
    fn eq(&self, left: &[u8], right: &[u8]) -> bool {
        bssl_crypto::constant_time_compare(left, right)
    }
}

/// HMAC-SHA256 implementation based on BoringSSL.
#[derive(Clone)]
pub struct HmacSha256;

impl traits::HmacSha256 for HmacSha256 {
    fn sign(&self, key: &OpaqueOr<HmacKey>, data: &[u8]) -> Result<Vec<u8>, Error> {
        let OpaqueOr::Explicit(ref key) = key else {
            return Err(Error::Internal);
        };
        Ok(bssl_crypto::hmac::HmacSha256::mac(&key.0, data).to_vec())
    }
}

/// AES-CMAC implementation based on BoringSSL.
///
/// This implementation uses the `unsafe` wrappers around bindgen-erated `CMAC_*` functions
/// directly, because `bssl-crypto` currently has no wrappers.
pub struct BoringAesCmac;

impl AesCmac for BoringAesCmac {
    fn begin(key: &OpaqueOr<Aes256Key>) -> Result<Box<dyn AccumulatingOperation>, Error> {
        let OpaqueOr::Explicit(key) = key else {
            error!("Only expect to deal with explicit key material");
            return Err(Error::Internal);
        };

        // Safety: raw pointer is immediately checked for null below, and BoringSSL only emits
        // valid pointers or null.
        let ctx = unsafe { ffi::CMAC_CTX_new() };
        let Some(ctx) = core::ptr::NonNull::new(ctx) else {
            return Err(Error::AllocationFailed);
        };

        // Safety: `ffi::EVP_aes_256_cbc` returns a non-null valid pointer.
        let cipher = unsafe { ffi::EVP_aes_256_cbc() };

        // Safety: `ctx` is known non-null and valid, as is `cipher`.  `key` is a valid array of
        // `u8`, of non-zero length.
        let result = unsafe {
            ffi::CMAC_Init(
                ctx.as_ptr(),
                key.as_ptr() as *const core::ffi::c_void,
                key.len(),
                cipher,
                core::ptr::null_mut(),
            )
        };
        if result != 1 {
            error!("Failed to CMAC_Init()");
            return Err(Error::Internal);
        }
        Ok(Box::new(AesCmacOperation { ctx }))
    }
}

struct AesCmacOperation {
    // Safety: `ctx` is always non-null (checked in `AesCmac::begin()` before construction).
    ctx: core::ptr::NonNull<ffi::CMAC_CTX>,
}

// Safety: Checked CMAC_CTX allocation, initialization and destruction code to insure that it is
//         safe to share it between threads.
unsafe impl Send for AesCmacOperation {}

impl core::ops::Drop for AesCmacOperation {
    fn drop(&mut self) {
        // Safety: `self.ctx` is always non-null and valid as it's created from
        // `ffi::CMAC_CTX_new()`.
        unsafe {
            ffi::CMAC_CTX_free(self.ctx.as_ptr());
        }
    }
}

impl AccumulatingOperation for AesCmacOperation {
    fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        if data.is_empty() {
            return Ok(());
        }
        // Safety: `self.ctx` is non-null and valid, and `data` is a valid non-empty slice.
        let result = unsafe { ffi::CMAC_Update(self.ctx.as_ptr(), data.as_ptr(), data.len()) };
        if result != 1 {
            return Err(Error::Internal);
        }
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>, Error> {
        let mut output_len: usize = AES_BLOCK_SIZE;
        let mut output = vec_try![0; AES_BLOCK_SIZE]?;

        // Safety: `self.ctx` is non-null and valid; `output_len` is correct (non-zero) size of
        // `output` buffer.
        let result = unsafe {
            ffi::CMAC_Final(self.ctx.as_ptr(), output.as_mut_ptr(), &mut output_len as *mut usize)
        };
        if result != 1 {
            return Err(Error::Internal);
        }
        if output_len != AES_BLOCK_SIZE {
            error!("Unexpected CMAC output size of {output_len}");
            return Err(Error::Internal);
        }
        Ok(output)
    }
}
