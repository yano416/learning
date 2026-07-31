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

//! Traits representing abstractions of device-specific functionality.

use crate::{Error, FailureRecord};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use gk_wire::{AndroidUserId, MillisecondsSinceEpoch};
use hal_wire::vec_try;
use log::{error, warn};
use zeroize::ZeroizeOnDrop;

/// Combined collection of trait implementations that must be provided.
pub struct Implementation {
    /// Random number generator.
    pub rng: Box<dyn Rng>,

    /// A local clock.
    pub clock: Box<dyn MonotonicClock>,

    /// A constant-time equality implementation.
    pub compare: Box<dyn ConstTimeEq>,

    /// HMAC-SHA256 implementation.
    pub hmac: Box<dyn HmacSha256>,

    /// Trait for retrieval of the password key.
    pub password: Box<dyn PasswordKeyRetrieval>,

    /// Trait for management and use of the auth key.
    pub auth_key: Box<dyn AuthKeyManagement>,

    /// Trait for storage of failure records.
    pub failures: Box<dyn FailureRecording>,

    /// Traits for shared secret negotiation.  This is only required if the TA is configured to
    /// support the `ISharedSecret` mechanism for agreeing the auth key.
    pub shared_secret: Option<SharedSecretImplementation>,
}

/// Size of the auth key in bytes.
pub const AUTH_KEY_SIZE: usize = 32;

/// Abstraction of device-specific mechanisms for managing and using the HMAC-SHA256 key that is
/// used for authentication.
pub trait AuthKeyManagement: Send {
    /// Use the auth key to generate an HMAC-SHA256 signature of the given `data`.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error>;

    /// Pass an agreed authentication key to the implementation.  This method only needs an
    /// implementation if `ISharedSecret` support is included.
    fn key_agreed(&mut self, _key: OpaqueOr<HmacKey>) -> Result<(), Error> {
        Err(Error::Unimplemented)
    }
}

/// Abstraction of persistent password key.
pub trait PasswordKeyRetrieval: Send {
    /// Retrieve the persistent password key.  The same key must remain available after factory
    /// reset (as Gatekeeper authentication is required for clearing factory reset protection).
    fn key(&self) -> Result<OpaqueOr<HmacKey>, Error>;
}

/// Abstraction of a random number generator that is cryptographically secure.
pub trait Rng: Send {
    /// Generate random data.
    fn fill_bytes(&mut self, dest: &mut [u8]);
    /// Return a random `u64` value.
    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }
}

/// Abstraction of constant-time comparisons, for use in cryptographic contexts where timing attacks
/// need to be avoided.
pub trait ConstTimeEq: Send {
    /// Indicate whether arguments are the same.
    fn eq(&self, left: &[u8], right: &[u8]) -> bool;
    /// Indicate whether arguments are the different.
    fn ne(&self, left: &[u8], right: &[u8]) -> bool {
        !self.eq(left, right)
    }
}

/// Abstraction of a monotonic clock.
pub trait MonotonicClock: Send {
    /// Return the current time in milliseconds since some arbitrary point in time.  Time must be
    /// monotonically increasing, and "current time" must not repeat until the Android device
    /// reboots, or until at least 50 million years have elapsed.  Time must also continue to
    /// advance while the device is suspended.  (For example, in Linux the equivalent would be to
    /// use `CLOCK_BOOTTIME` rather than `CLOCK_MONOTONIC` in `clock_gettime`.)
    fn now(&self) -> MillisecondsSinceEpoch;
}

/// Abstraction of HMAC-SHA256 functionality.
pub trait HmacSha256: Send {
    /// Generate an HMAC-SHA256 signature of the given `data` using the supplied `key`.
    fn sign(&self, key: &OpaqueOr<HmacKey>, data: &[u8]) -> Result<Vec<u8>, Error>;

    /// Verify an HMAC-SHA256 signature of the given `data` using the supplied `key`.
    fn verify(
        &self,
        eq: &dyn ConstTimeEq,
        key: &OpaqueOr<HmacKey>,
        data: &[u8],
        sig: &[u8],
    ) -> Result<(), Error> {
        let recalculated = self.sign(key, data)?;
        if eq.ne(sig, &recalculated) {
            Err(Error::VerifyFailed)
        } else {
            Ok(())
        }
    }
}

/// An HMAC key.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct HmacKey(pub Vec<u8>);

/// Opaque key material whose structure is only known/accessible to the crypto implementation.
/// The contents of this are assumed to be encrypted (and so are not `ZeroizeOnDrop`).
#[derive(Clone, PartialEq, Eq)]
pub struct OpaqueKeyMaterial(pub Vec<u8>);

/// Wrapper that holds either a key of explicit type `T`, or an opaque blob of key material.
#[derive(Clone, PartialEq, Eq)]
pub enum OpaqueOr<T> {
    /// Explicit key material of the given type, available in plaintext.
    Explicit(T),
    /// Opaque key material, either encrypted or an opaque key handle.
    Opaque(OpaqueKeyMaterial),
}

impl From<HmacKey> for OpaqueOr<HmacKey> {
    fn from(k: HmacKey) -> Self {
        Self::Explicit(k)
    }
}

/// Abstraction of the device-specific functionality for managing failure records.  These records
/// must be persistent across boots and across factory reset (to allow for clearing factory
/// reset protection).
pub trait FailureRecording {
    /// Retrieve the failure record for the specified `user_id`.
    fn get(&self, user_id: AndroidUserId) -> Result<Option<FailureRecord>, Error>;

    /// Write (or over-write) a failure record for the specified `user_id`.
    fn set(&mut self, user_id: AndroidUserId, record: &FailureRecord) -> Result<(), Error>;

    /// Delete any failure record for the specified `user_id`.
    ///
    /// Return code indicates whether there was a failure record.
    fn clear(&mut self, user_id: AndroidUserId) -> Result<bool, Error>;

    /// Delete all failure records.
    fn clear_all(&mut self) -> Result<(), Error>;
}

/// Abstraction of simple flat filesystem functionality.
pub trait SecureFilesystem {
    /// Concrete type of iterator returned by `list`.
    type Iter: Iterator<Item = String>;
    /// Read the entire contents of the given file. Return `Err(Error::NotFound)` if the file does
    /// not exist.
    fn read(&self, filename: &str) -> Result<Vec<u8>, Error>;
    /// Write the entire contents of the given file, overwriting any existing contents.
    fn write(&self, filename: &str, data: &[u8]) -> Result<(), Error>;
    /// Delete the given file.  Returns `Error::NotFound` if the file does not exist.
    fn delete(&self, filename: &str) -> Result<(), Error>;
    /// List all files in the flat filesystem.
    fn list(&self) -> Result<Self::Iter, Error>;
}

/// Filename prefix for per-user failure record files.
///
/// Back-compatible with the previous Trusty C++ implementation.
const GK_FILENAME_PREFIX: &str = "gatekeeper.";

/// Generate the filename corresponding to a particular `user_id`.
fn filename_for(user_id: AndroidUserId) -> String {
    alloc::format!("{GK_FILENAME_PREFIX}{}", user_id.0 as u32)
}

/// Implementation of failure recording based on an underlying flat filesystem.
///
/// File contents are back-compatible with the previous Trusty C++ implementation.
impl<T> FailureRecording for T
where
    T: SecureFilesystem,
{
    fn get(&self, user_id: AndroidUserId) -> Result<Option<FailureRecord>, Error> {
        let data = match self.read(&filename_for(user_id)) {
            Ok(data) => data,
            Err(Error::NotFound) => return Ok(None),
            Err(e) => return Err(e),
        };
        Ok(Some(FailureRecord::from_slice(&data)?))
    }

    fn set(&mut self, user_id: AndroidUserId, record: &FailureRecord) -> Result<(), Error> {
        let data = record.to_vec()?;
        self.write(&filename_for(user_id), &data)
    }

    fn clear(&mut self, user_id: AndroidUserId) -> Result<bool, Error> {
        match self.delete(&filename_for(user_id)) {
            Err(Error::NotFound) => Ok(false),
            Err(e) => Err(e),
            Ok(_) => Ok(true),
        }
    }

    fn clear_all(&mut self) -> Result<(), Error> {
        for filename in self.list()? {
            if filename.starts_with(GK_FILENAME_PREFIX) {
                if let Err(e) = self.delete(&filename) {
                    error!("failed to delete {filename} (continuing anyway): {e:?}");
                }
            }
        }
        Ok(())
    }
}

/// An implementation of auth key management that holds an explicit HMAC key.
pub struct ExplicitAuthKey {
    key: Option<OpaqueOr<HmacKey>>,
    hmac: Box<dyn HmacSha256>,
}

impl ExplicitAuthKey {
    /// Create a new instance based on the given HMAC-SHA256 implementation.
    pub fn new(hmac: Box<dyn HmacSha256>) -> Self {
        Self { key: None, hmac }
    }
}

impl AuthKeyManagement for ExplicitAuthKey {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let Some(key) = self.key.as_ref() else { return Err(Error::Internal) };
        self.hmac.sign(key, data)
    }

    fn key_agreed(&mut self, key: OpaqueOr<HmacKey>) -> Result<(), Error> {
        if let Some(prev_key) = self.key.as_ref() {
            if key != *prev_key {
                warn!("replacing already-set auth key with a different one!");
            }
        }
        self.key = Some(key);
        Ok(())
    }
}

/// Traits required for shared secret negotiation.
pub struct SharedSecretImplementation {
    /// Retrieve the preshared key that is used as the basis of the negotiation.
    pub preshared_key: Box<dyn RetrievePresharedKey>,

    /// Perform the derivation.
    pub derive: Box<dyn SharedSecretDerive>,
}

/// Explicit AES-256 key.
pub type Aes256Key = [u8; 32];

/// Mechanism to retrieve the pre-shared key for HMAC key agreement.
pub trait RetrievePresharedKey: Send {
    /// Retrieve the pre-shared key.
    fn get(&self) -> OpaqueOr<Aes256Key>;
}

/// Implementation of a fixed pre-shared key for HMAC key agreement.
///
/// This is useful for development, testing and emulators.
///
/// It is not generally suitable for a production device.
pub struct FixedPresharedKey(pub Aes256Key);

impl RetrievePresharedKey for FixedPresharedKey {
    fn get(&self) -> OpaqueOr<Aes256Key> {
        OpaqueOr::Explicit(self.0)
    }
}

/// Abstraction of the device-specific functionality required to support shared secret negotiation.
pub trait SharedSecretDerive: Send {
    /// Using some pre-shared secret `key`, derive a 32-byte key (which will be used as the device
    /// auth key, using HMAC-SHA256) using CKDF with the provided `context` and `label`.  CKDF is
    /// defined in section 5.1 of NIST SP 800-108.
    fn derive(
        &self,
        key: &OpaqueOr<Aes256Key>,
        label: &[u8],
        context: &[&[u8]],
        out_len: usize,
    ) -> Result<OpaqueOr<HmacKey>, Error>;
}

/// Abstraction of AES-CMAC.
pub trait AesCmac: Send {
    /// Start an AES-CMAC operation.
    fn begin(key: &OpaqueOr<Aes256Key>) -> Result<Box<dyn AccumulatingOperation>, Error>;
}

/// Abstraction of an in-progress operation that only emits data when it completes.
pub trait AccumulatingOperation: Send {
    /// Update operation with data.
    fn update(&mut self, data: &[u8]) -> Result<(), Error>;

    /// Complete operation, consuming `self`.
    fn finish(self: Box<Self>) -> Result<Vec<u8>, Error>;
}

/// Given an AES-CMAC implementation, provide an implementation of [`SharedSecretDerive`] via CKDF.
impl<A: AesCmac> SharedSecretDerive for A {
    fn derive(
        &self,
        key: &OpaqueOr<Aes256Key>,
        label: &[u8],
        context: &[&[u8]],
        out_len: usize,
    ) -> Result<OpaqueOr<HmacKey>, Error> {
        let key = ckdf::<A>(key, label, context, out_len)?;
        Ok(OpaqueOr::Explicit(HmacKey(key)))
    }
}

/// Size of an AES block in bytes.
pub const AES_BLOCK_SIZE: usize = 16;

/// Perform CKDF.
fn ckdf<A: AesCmac>(
    key: &OpaqueOr<Aes256Key>,
    label: &[u8],
    chunks: &[&[u8]],
    out_len: usize,
) -> Result<Vec<u8>, Error> {
    // Note: the variables i and l correspond to i and L in the standard.  See page 12 of
    // http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf.

    let blocks: u32 = out_len.div_ceil(AES_BLOCK_SIZE) as u32;
    let l = (out_len * 8) as u32; // in bits
    let net_order_l = l.to_be_bytes();
    let zero_byte: [u8; 1] = [0];
    let mut output = vec_try![0; out_len]?;
    let mut output_pos = 0;

    for i in 1u32..=blocks {
        // Data to mac is (i:u32 || label || 0x00:u8 || context || L:u32), with integers in
        // network order.
        let mut op = A::begin(key)?;
        let net_order_i = i.to_be_bytes();
        op.update(&net_order_i[..])?;
        op.update(label)?;
        op.update(&zero_byte[..])?;
        for chunk in chunks {
            op.update(chunk)?;
        }
        op.update(&net_order_l[..])?;

        let data = op.finish()?;
        let copy_len = core::cmp::min(data.len(), output.len() - output_pos);
        output[output_pos..output_pos + copy_len].clone_from_slice(&data[..copy_len]);
        output_pos += copy_len;
    }
    if output_pos != output.len() {
        error!("finished at {output_pos} before end of output at {}", output.len());
        return Err(Error::InvalidArgument);
    }
    Ok(output)
}
