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

//! Types used for communication between HAL and TA.
//!
//! The HAL code receives data encoded in the AIDL-defined types, but the
//! TA code doesn't use the same types (because that would require access to
//! the AIDL-generated code in the build system for the secure environment).
//!
//! So instead use types defined in this crate, which the HAL service can
//! translate to/from.

// Allow missing docs in this crate as the types here are generally 1:1 with the HAL
// interface definitions.
#![allow(missing_docs)]
#![no_std]
extern crate alloc;

/// Re-export of crate used for CBOR encoding.
pub use ciborium as cbor;

use alloc::{vec, vec::Vec};
use cbor::value::Value;
use enumn::N;
use hal_wire::{cbor_type_error, mem, vec_try, AsCborValue, CborError};
use hal_wire_derive::AsCborValue;

/// Milliseconds since an arbitrary epoch.  This must be monotonically increasing and not repeat
/// before device reboot, and should also count time passing while the device is suspended.
///
/// Encoded as a signed 64-bit integer to match the AIDL type (`long milliSeconds` in
/// `android.hardware.security.secureclock.Timestamp`) that it corresponds to.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, AsCborValue)]
pub struct MillisecondsSinceEpoch(pub i64);

impl core::ops::Add<i64> for MillisecondsSinceEpoch {
    type Output = Self;
    fn add(self, rhs: i64) -> Self::Output {
        Self(self.0.saturating_add(rhs))
    }
}

/// Error codes defined in the Gatekeeper HAL.
#[derive(Clone, Copy, Debug, PartialEq, Eq, AsCborValue, N)]
pub enum ApiStatus {
    Ok = 0,
    ReEnroll = 1,
    GeneralFailure = -1,
    RetryTimeout = -2,
    NotImplemented = -3,
}

/// An Android user ID.
///
/// Encoded as a signed 32-bit integer to match the AIDL type (`int uid` in
/// `android.hardware.gatekeeper.IGatekeeper`) that it corresponds to.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsCborValue)]
pub struct AndroidUserId(pub i32);

/// A secure user ID.
///
/// Encoded as a signed 64-bit integer to match the AIDL type (`long userId` in
/// `android.hardware.security.keymint.HardwareAuthToken`) that it corresponds to.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsCborValue)]
pub struct SecureUserId(pub i64);

/// An opaque (but public) password handle.
#[repr(transparent)]
#[derive(Debug, Clone, PartialEq, Eq, AsCborValue)]
pub struct PasswordHandle(pub Vec<u8>);

impl PasswordHandle {
    /// Create a `PasswordHandle` from a slice.
    pub fn from_raw(handle: &[u8]) -> Option<PasswordHandle> {
        if handle.is_empty() {
            None
        } else {
            Some(PasswordHandle(handle.to_vec()))
        }
    }
}

/// A user password.
#[repr(transparent)]
#[derive(AsCborValue)] // deliberately not `Debug`
pub struct Password(pub Vec<u8>);

impl Password {
    /// Create a `Password` from a slice.
    pub fn from_raw(password: &[u8]) -> Option<Password> {
        if password.is_empty() {
            None
        } else {
            Some(Password(password.to_vec()))
        }
    }
}

/// The type of authentication.  Values can be used as a bitmask.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, AsCborValue, N)]
#[repr(i32)]
pub enum HardwareAuthenticatorType {
    /// No bits set.
    None = 0x00,
    /// Bit indicating password authentication set.
    Password = 0x01,
    /// Bit indicating fingerprint (or strong biometric) authentication set.
    Fingerprint = 0x02,
    /// `Any` includes all possible bit values.
    Any = -1,
}

/// Auth token type representing a successful authentication.
///
/// Fields are encoded as signed 64-bit integers to match the AIDL types (`long` in
/// `android.hardware.security.keymint.HardwareAuthToken`) that they correspond to.
#[derive(Clone, Debug, Eq, PartialEq, AsCborValue)]
pub struct HardwareAuthToken {
    pub challenge: i64,
    pub user_id: i64,
    pub authenticator_id: i64,
    pub authenticator_type: HardwareAuthenticatorType,
    pub timestamp: MillisecondsSinceEpoch,
    pub mac: Vec<u8>,
}

impl HardwareAuthToken {
    /// Build the HMAC input for a [`HardwareAuthToken`]
    pub fn mac_input(&self) -> Result<Vec<u8>, CborError> {
        const LEN: usize = size_of::<u8>() + // version=0 (BE)
        size_of::<i64>() + // challenge (Host)
        size_of::<i64>() + // user_id (Host)
        size_of::<i64>() + // authenticator_id (Host)
        size_of::<i32>() + // authenticator_type (BE)
        size_of::<i64>(); // timestamp (BE)
        let mut result = mem::vec_try_with_capacity(LEN)?;
        result.extend_from_slice(&0u8.to_be_bytes()[..]);
        result.extend_from_slice(&self.challenge.to_ne_bytes()[..]);
        result.extend_from_slice(&self.user_id.to_ne_bytes()[..]);
        result.extend_from_slice(&self.authenticator_id.to_ne_bytes()[..]);
        result.extend_from_slice(&(self.authenticator_type as i32).to_be_bytes()[..]);
        result.extend_from_slice(&self.timestamp.0.to_be_bytes()[..]);
        Ok(result)
    }
}

// Gatekeeper request/response structures. Contents are equivalent to the input/output parameters of
// each AIDL entrypoint.

#[derive(Debug, AsCborValue)]
pub struct DeleteAllUsersRequest {}

#[derive(Debug, AsCborValue)]
pub struct DeleteAllUsersResponse {}

#[derive(Debug, AsCborValue)]
pub struct DeleteUserRequest {
    pub user_id: AndroidUserId,
}

#[derive(Debug, AsCborValue)]
pub struct DeleteUserResponse {}

#[derive(AsCborValue)]
pub struct EnrollRequest {
    pub user_id: AndroidUserId,
    pub current_handle: Option<PasswordHandle>,
    pub current_password: Option<Password>,
    pub new_password: Password,
}

#[derive(Debug, AsCborValue)]
pub struct EnrollResponse {
    pub sid: SecureUserId,
    pub handle: PasswordHandle,
}

#[derive(AsCborValue)]
pub struct VerifyRequest {
    pub user_id: AndroidUserId,
    pub challenge: i64,
    pub handle: PasswordHandle,
    pub password: Password,
}

#[derive(Debug, AsCborValue)]
pub struct VerifyResponse {
    pub request_reenroll: bool,
    pub auth_token: HardwareAuthToken,
}

// Shared secret request/response structures. Contents are equivalent to the input/output parameters
// of each AIDL entrypoint.

/// Error codes used implicitly in the shared secret HAL.
///
/// Values are a subset of the `ErrorCode` values used in the KeyMint HAL, chosen to behave
/// the same as the Rust reference implementation of KeyMint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, AsCborValue, N)]
pub enum SharedSecretError {
    Ok = 0,
    InvalidArgument = -38,
    MemoryAllocationFailed = -41,
    Unimplemented = -100,
    UnknownError = -1000,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Default, AsCborValue)]
pub struct SharedSecretParameters {
    pub seed: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Debug, AsCborValue)]
pub struct GetSharedSecretParamsRequest {}

#[derive(Debug, AsCborValue)]
pub struct GetSharedSecretParamsResponse {
    pub params: SharedSecretParameters,
}

#[derive(Debug, AsCborValue)]
pub struct ComputeSharedSecretRequest {
    pub params: Vec<SharedSecretParameters>,
}

#[derive(Debug, AsCborValue)]
pub struct ComputeSharedSecretResponse {
    pub sharing_check: Vec<u8>,
}

/// Trait that associates an enum value of the specified type with a type.
///
/// Values of the `enum` type `T` are used to identify particular message types.
/// A message type implements `Code<T>` to indicate which `enum` value it is
/// associated with.
///
/// For example, an `enum WhichMsg { Hello, Goodbye }` could be used to distinguish
/// between `struct HelloMsg` and `struct GoodbyeMsg` instances, in which case the
/// latter types would both implement `Code<WhichMsg>` with `CODE` values of
/// `WhichMsg::Hello` and `WhichMsg::Goodbye` respectively.
pub trait Code<T> {
    /// The enum value identifying this request/response.
    const CODE: T;
    /// Return the enum value associated with the underlying type of this item.
    fn code(&self) -> T {
        Self::CODE
    }
}

/// Declare a collection of related enums for a code and a pair of types.
///
/// An invocation like:
/// ```ignore
/// declare_req_rsp_enums! { GatekeerpOperation  => (PerformOpReq, PerformOpRsp) {
///     Enroll = 0x11 => (EnrollRequest, EnrollResponse),
///     Verify = 0x12 => (VerifyRequest, VerifyResponse),
/// } }
/// ```
/// will emit three `enum` types all of whose variant names are the same (taken from the leftmost
/// column), but whose contents are:
///
/// - the numeric values (second column)
///   ```ignore
///   #[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash)]
///   enum GatekeeperOperation {
///       Enroll = 0x11,
///       Verify = 0x12,
///   }
///   ```
///
/// - the types from the third column:
///   ```ignore
///   enum PerformOpReq {
///       Enroll(EnrollRequest),
///       Verify(VerifyRequest),
///   }
///   ```
///
/// - the types from the fourth column:
///   ```ignore
///   #[derive(Debug)]
///   enum PerformOpRsp {
///       Enroll(EnrollResponse),
///       Verify(VerifyResponse),
///   }
//   ```
///
/// Each of these enum types will also get an implementation of [`AsCborValue`]
macro_rules! declare_req_rsp_enums {
    {
        $cenum:ident => ($reqenum:ident, $rspenum:ident) {
            $( $cname:ident = $cvalue:expr => ($reqtyp:ty, $rsptyp:ty) , )*
        }
    } => {
        /// Message codes
        #[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, N)]
        pub enum $cenum {
            $( $cname = $cvalue, )*
        }

        impl AsCborValue for $cenum {
            /// Create an instance of the enum from a [`Value`], checking that the
            /// value is valid.
            fn from_cbor_value(value: $crate::Value) ->
                Result<Self, crate::CborError> {
                use core::convert::TryInto;
                // First get the int value as an `i32`.
                let v: i32 = match value {
                    $crate::Value::Integer(i) => i.try_into().map_err(|_| {
                        crate::CborError::InvalidValue
                    })?,
                    v => return cbor_type_error(&v, &"int"),
                };
                // Now check it is one of the defined enum values.
                Self::n(v).ok_or(crate::CborError::NonEnumValue(v))
            }
            /// Convert the enum value to a [`Value`].
            fn to_cbor_value(self) -> Result<$crate::Value, crate::CborError> {
                Ok($crate::Value::Integer((self as i64).into()))
            }
        }

        /// All possible request message types.
        pub enum $reqenum {
            $( $cname($reqtyp), )*
        }

        impl $reqenum {
            /// Return the message code value corresponding to a request variant.
            pub fn code(&self) -> $cenum {
                match self {
                    $( Self::$cname(_) => $cenum::$cname, )*
                }
            }
        }

        /// All possible response message types.
        pub enum $rspenum {
            $( $cname($rsptyp), )*
        }

        impl AsCborValue for $reqenum {
            fn from_cbor_value(value: Value) -> Result<Self, CborError> {
                let mut a = match value {
                    Value::Array(a) => a,
                    _ => return crate::cbor_type_error(&value, "arr"),
                };
                if a.len() != 2 {
                    return Err(CborError::UnexpectedItem("arr", "arr len 2"));
                }
                let ret_val = a.remove(1);
                let ret_type = <$cenum>::from_cbor_value(a.remove(0))?;
                match ret_type {
                    $( $cenum::$cname => Ok(Self::$cname(<$reqtyp>::from_cbor_value(ret_val)?)), )*
                }
            }
            fn to_cbor_value(self) -> Result<Value, CborError> {
                Ok(Value::Array(match self {
                    $( Self::$cname(val) => {
                        vec![
                            $cenum::$cname.to_cbor_value()?,
                            val.to_cbor_value()?
                        ]
                    }, )*
                }))
            }
        }

        impl AsCborValue for $rspenum {
            fn from_cbor_value(value: Value) -> Result<Self, CborError> {
                let mut a = match value {
                    Value::Array(a) => a,
                    _ => return cbor_type_error(&value, "arr"),
                };
                if a.len() != 2 {
                    return Err(CborError::UnexpectedItem("arr", "arr len 2"));
                }
                let ret_val = a.remove(1);
                let ret_type = <$cenum>::from_cbor_value(a.remove(0))?;
                match ret_type {
                    $( $cenum::$cname => Ok(Self::$cname(<$rsptyp>::from_cbor_value(ret_val)?)), )*
                }
            }
            fn to_cbor_value(self) -> Result<Value, CborError> {
                Ok(Value::Array(match self {
                    $( Self::$cname(val) => {
                        vec![
                            $cenum::$cname.to_cbor_value()?,
                            val.to_cbor_value()?
                        ]
                    }, )*
                }))
            }
        }

        $(
            impl Code<$cenum> for $reqtyp {
                const CODE: $cenum = $cenum::$cname;
            }
        )*

        $(
            impl Code<$cenum> for $rsptyp {
                const CODE: $cenum = $cenum::$cname;
            }
        )*
    };
}

// Possible operation requests, as:
// - an enum value with an explicit numeric value
// - a request enum which has an operation code associated to each variant
// - a response enum which has the same operation code associated to each variant.
declare_req_rsp_enums! { GatekeeperOperation  =>    (PerformOpReq, PerformOpRsp) {
    // `IGatekeeper` entrypoints
    DeleteAllUsers = 0x10 => (DeleteAllUsersRequest, DeleteAllUsersResponse),
    DeleteUser = 0x11 =>     (DeleteUserRequest, DeleteUserResponse),
    Enroll = 0x20 =>         (EnrollRequest, EnrollResponse),
    Verify = 0x21 =>         (VerifyRequest, VerifyResponse),

    // `ISharedSecret` entrypoints.
    GetSharedSecretParams = 0x40 => (GetSharedSecretParamsRequest, GetSharedSecretParamsResponse),
    ComputeSharedSecret = 0x41   => (ComputeSharedSecretRequest, ComputeSharedSecretResponse),
} }

/// Outer response message type that allows for failure.
pub enum PerformOpResponse {
    /// An OK response with inner response message (equivalent to [`ApiStatus::Ok`]).
    Ok(PerformOpRsp),
    /// A response indicating that the request should be retried after the given number of
    /// milliseconds (equivalent to [`ApiStatus::RetryTimeout`]).
    RetryTimeout(i32),
    /// General error response.  The contained error code is context-specific.
    Err(i32),
}

impl AsCborValue for PerformOpResponse {
    fn from_cbor_value(value: Value) -> Result<Self, CborError> {
        let mut arr = match value {
            Value::Array(a) if a.len() == 2 => a,
            Value::Array(_) => return Err(CborError::UnexpectedItem("arr not len 2", "arr len 2")),
            _ => return Err(CborError::UnexpectedItem("non-arr", "arr")),
        };
        let value = arr.remove(1);
        let code = ApiStatus::from_cbor_value(arr.remove(0))?;
        match code {
            ApiStatus::Ok => {
                let rsp = PerformOpRsp::from_cbor_value(value)?;
                Ok(Self::Ok(rsp))
            }
            ApiStatus::RetryTimeout => {
                let timeout = i32::from_cbor_value(value)?;
                Ok(Self::RetryTimeout(timeout))
            }
            ApiStatus::GeneralFailure => {
                let rc = i32::from_cbor_value(value)?;
                Ok(Self::Err(rc))
            }
            v => Err(CborError::NonEnumValue(v as i32)),
        }
    }
    fn to_cbor_value(self) -> Result<Value, CborError> {
        // Re-use API status codes as discriminants.
        let (code, value) = match self {
            Self::Ok(rsp) => (Value::Integer((ApiStatus::Ok as i32).into()), rsp.to_cbor_value()?),
            Self::RetryTimeout(timeout) => (
                Value::Integer((ApiStatus::RetryTimeout as i32).into()),
                Value::Integer(timeout.into()),
            ),
            Self::Err(rc) => (
                Value::Integer((ApiStatus::GeneralFailure as i32).into()),
                Value::Integer(rc.into()),
            ),
        };
        Ok(Value::Array(vec_try![code, value]?))
    }
}

impl PerformOpResponse {
    /// Return the status code associated with the response.
    pub fn error_code(&self) -> ApiStatus {
        match self {
            Self::Ok(_rsp) => ApiStatus::Ok,
            Self::RetryTimeout(_timeout) => ApiStatus::RetryTimeout,
            Self::Err(status) => ApiStatus::n(*status).unwrap_or(ApiStatus::GeneralFailure),
        }
    }
}
