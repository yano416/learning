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

//! Password handle functionality.

use crate::{
    traits::{self, HmacKey, OpaqueOr},
    Error,
};
use core::mem::size_of;
use core::ops::Range;
use gk_wire as wire;
use hal_wire::mem;
use log::error;
use wire::SecureUserId;

/// Current version of the [`PasswordHandle`] structure, inherited from the C++ implementation.
pub const CURRENT_VERSION: u8 = 2;

/// Minimum supported version from previous implementations.
pub const MINIMUM_VERSION: u8 = 2;

/// Reserved value for the `flags` field in [`PasswordHandle`]. Always set for historical /
/// back-compatibility reasons.
pub const FLAG_RESERVED: u64 = 0x01;

/// Handle for an enrolled password.
#[derive(Debug, PartialEq)]
pub struct PasswordHandle {
    // Fields included in the MAC input.
    version: u8,
    sid: SecureUserId,
    flags: u64,
    salt: u64,

    // Un-MAC-ed fields.
    mac: [u8; 32],
    hw_backed: bool,
}

// Constants for the serialized length of fields (in bytes).
const SERIALIZED_VERSION_LEN: usize = size_of::<u8>();
const SERIALIZED_SID_LEN: usize = size_of::<SecureUserId>();
const SERIALIZED_FLAGS_LEN: usize = size_of::<u64>();
const SERIALIZED_SALT_LEN: usize = size_of::<u64>();
const SERIALIZED_MAC_LEN: usize = 32;
const SERIALIZED_HW_BACKED_LEN: usize = size_of::<u8>();
const SERIALIZED_LEN: usize = SERIALIZED_VERSION_LEN
    + SERIALIZED_SID_LEN
    + SERIALIZED_FLAGS_LEN
    + SERIALIZED_SALT_LEN
    + SERIALIZED_MAC_LEN
    + SERIALIZED_HW_BACKED_LEN;
const MAC_INPUT_PREFIX_LEN: usize =
    SERIALIZED_SALT_LEN + SERIALIZED_VERSION_LEN + SERIALIZED_SID_LEN + SERIALIZED_FLAGS_LEN;

// Offsets of serialized fields.
const VERSION_OFFSET: usize = 0;
const SID_OFFSET: usize = VERSION_OFFSET + SERIALIZED_VERSION_LEN;
const FLAGS_OFFSET: usize = SID_OFFSET + SERIALIZED_SID_LEN;
const SALT_OFFSET: usize = FLAGS_OFFSET + SERIALIZED_FLAGS_LEN;
const MAC_OFFSET: usize = SALT_OFFSET + SERIALIZED_SALT_LEN;
const HW_BACKED_OFFSET: usize = MAC_OFFSET + SERIALIZED_MAC_LEN;

// Ranges for serialized fields.
const SID_RANGE: Range<usize> = SID_OFFSET..SID_OFFSET + SERIALIZED_SID_LEN;
const FLAGS_RANGE: Range<usize> = FLAGS_OFFSET..FLAGS_OFFSET + SERIALIZED_FLAGS_LEN;
const SALT_RANGE: Range<usize> = SALT_OFFSET..SALT_OFFSET + SERIALIZED_SALT_LEN;
const MAC_RANGE: Range<usize> = MAC_OFFSET..MAC_OFFSET + SERIALIZED_MAC_LEN;

impl PasswordHandle {
    /// Create a new password handle.
    pub fn new(
        key: &OpaqueOr<HmacKey>,
        hmac: &dyn traits::HmacSha256,
        rng: &mut dyn traits::Rng,
        password: &wire::Password,
        sid: SecureUserId,
    ) -> Result<Self, Error> {
        let salt = rng.next_u64();
        let mut handle = Self {
            version: CURRENT_VERSION,
            sid,
            flags: FLAG_RESERVED,
            salt,
            mac: [0; 32],
            hw_backed: true,
        };
        handle.mac = handle.generate_mac(key, hmac, password)?;
        Ok(handle)
    }

    /// Create a password handle from binary data.
    ///
    /// Matches the binary format from the C++ reference implementation of Gatekeeper.
    pub fn from_wire(data: &wire::PasswordHandle) -> Result<Self, Error> {
        let data = &data.0;
        if data.len() != SERIALIZED_LEN {
            error!("failure record of unexpected length {}!", data.len());
            return Err(Error::InvalidArgument);
        }
        let handle = Self {
            version: data[VERSION_OFFSET],
            sid: SecureUserId(i64::from_ne_bytes(data[SID_RANGE].try_into().unwrap())),
            flags: u64::from_ne_bytes(data[FLAGS_RANGE].try_into().unwrap()),
            salt: u64::from_ne_bytes(data[SALT_RANGE].try_into().unwrap()),
            mac: data[MAC_RANGE].try_into().unwrap(),
            hw_backed: data[HW_BACKED_OFFSET] != 0,
        };
        if handle.version > CURRENT_VERSION {
            error!("password handle from the future: {} vs {CURRENT_VERSION}", handle.version,);
            return Err(Error::InvalidArgument);
        }
        if handle.version < MINIMUM_VERSION {
            error!("password handle predates support: {} vs {MINIMUM_VERSION}", handle.version,);
            return Err(Error::InvalidArgument);
        }
        Ok(handle)
    }

    /// Convert a password handle into binary data.
    ///
    /// Matches the binary format from the C++ reference implementation of Gatekeeper.
    pub fn to_wire(&self) -> Result<wire::PasswordHandle, Error> {
        let mut result = mem::vec_try_with_capacity(SERIALIZED_LEN)?;
        result.push(self.version);
        result.extend_from_slice(&self.sid.0.to_ne_bytes());
        result.extend_from_slice(&self.flags.to_ne_bytes());
        result.extend_from_slice(&self.salt.to_ne_bytes());
        result.extend_from_slice(&self.mac);
        result.push(if self.hw_backed { 1 } else { 0 });
        Ok(wire::PasswordHandle(result))
    }

    /// Return the MAC value for the handle.
    fn generate_mac(
        &self,
        key: &OpaqueOr<HmacKey>,
        hmac: &dyn traits::HmacSha256,
        password: &wire::Password,
    ) -> Result<[u8; 32], Error> {
        let mut to_mac = mem::vec_try_with_capacity(MAC_INPUT_PREFIX_LEN + password.0.len())?;
        to_mac.extend_from_slice(&self.salt.to_ne_bytes());
        to_mac.push(self.version);
        to_mac.extend_from_slice(&self.sid.0.to_ne_bytes());
        to_mac.extend_from_slice(&self.flags.to_ne_bytes());
        to_mac.extend_from_slice(&password.0);

        let mac = hmac.sign(key, &to_mac)?;
        mac.try_into().map_err(|_| Error::Internal)
    }

    /// Verify that this handle matches the given password.
    pub fn verify(
        &self,
        key: &OpaqueOr<HmacKey>,
        hmac: &dyn traits::HmacSha256,
        compare: &dyn traits::ConstTimeEq,
        password: &wire::Password,
    ) -> Result<(), Error> {
        let recalc = self.generate_mac(key, hmac, password)?;
        if compare.eq(&recalc, &self.mac) {
            Ok(())
        } else {
            Err(Error::VerifyFailed)
        }
    }

    pub fn sid(&self) -> SecureUserId {
        self.sid
    }
}
