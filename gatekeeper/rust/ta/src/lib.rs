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

//! Common code implementing a Gatekeeper TA.

#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use gk_wire as wire;
use hal_wire::{mem::vec_try_with_capacity, AsCborValue};
use log::{debug, error, info, trace, warn};
use wire::{
    AndroidUserId, ApiStatus, Code, ComputeSharedSecretResponse, DeleteAllUsersResponse,
    DeleteUserResponse, EnrollResponse, GatekeeperOperation, GetSharedSecretParamsResponse,
    HardwareAuthToken, MillisecondsSinceEpoch, Password, PerformOpReq, PerformOpResponse,
    PerformOpRsp, SecureUserId, SharedSecretError, VerifyResponse,
};

mod handle;
mod secret;
#[cfg(test)]
mod tests;
pub mod traits;

/// Errors encountered in TA processing.
#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    /// Memory allocation failure.
    AllocationFailed,
    /// Internal error.
    Internal,
    /// Cryptographic verification failed.
    VerifyFailed,
    /// Functionality not implemented.
    Unimplemented,
    /// Provided argument(s) are invalid.
    InvalidArgument,
    /// User not found.
    NotFound,
    /// Operation cannot be performed until given number of milliseconds have passed.
    RetryTimeout(i32),
}

impl From<alloc::collections::TryReserveError> for Error {
    fn from(_e: alloc::collections::TryReserveError) -> Self {
        Error::AllocationFailed
    }
}

/// Gatekeeper device implementation, running in secure environment.
pub struct GatekeeperTa {
    /// Device-specific trait implementation.  Fixed on construction.
    imp: traits::Implementation,

    /// Parameters for shared secret negotiation.  Set after TA start, latched thereafter.
    shared_secret_params: Option<wire::SharedSecretParameters>,
}

const ONE_MINUTE: i64 = 60000;
const ONE_HOUR: i64 = 60 * ONE_MINUTE;
const ONE_DAY: i64 = 24 * ONE_HOUR;
const ONE_YEAR: i64 = 365 * ONE_DAY; // intentionally not considering leap years

/// Array that maps values of the failure counter to the timeout (in milliseconds) that the
/// Gatekeeper TA enforces after that number of failures.
const TIMEOUT_TABLE: &[i64] = &[
    /* 0  */ 0,
    /* 1  */ 0,
    /* 2  */ 0,
    /* 3  */ 0,
    /* 4  */ 0,
    /* 5  */ ONE_MINUTE,
    /* 6  */ 5 * ONE_MINUTE,
    /* 7  */ 15 * ONE_MINUTE,
    /* 8  */ 30 * ONE_MINUTE,
    /* 9  */ 90 * ONE_MINUTE,
    /* 10 */ 4 * ONE_HOUR,
    /* 11 */ 12 * ONE_HOUR,
    /* 12 */ 36 * ONE_HOUR,
    /* 13 */ 4 * ONE_DAY,
    /* 14 */ 13 * ONE_DAY,
    /* 15 */ 41 * ONE_DAY,
    /* 16 */ 123 * ONE_DAY,
    /* 17 */ ONE_YEAR,
    /* 18 */ 3 * ONE_YEAR,
    /* 19 */ 9 * ONE_YEAR,
];

impl GatekeeperTa {
    /// Create a new [`GatekeeperTa`] instance.
    pub fn new(imp: traits::Implementation) -> Self {
        Self { imp, shared_secret_params: None }
    }

    /// Process a single serialized request, returning a serialized response.
    pub fn process(&mut self, req_data: &[u8]) -> Vec<u8> {
        let (req_code, rsp) = match PerformOpReq::from_slice(req_data) {
            Ok(req) => {
                trace!("-> TA: received request {:?}", req.code());
                (Some(req.code()), self.process_req(req))
            }
            Err(e) => {
                error!("failed to decode CBOR request: {e:?}");
                (None, PerformOpResponse::Err(ApiStatus::GeneralFailure as i32))
            }
        };
        trace!("<- TA: send response {req_code:?} rc {:?}", rsp.error_code());
        match rsp.into_vec() {
            Ok(rsp_data) => rsp_data,
            Err(e) => {
                error!("failed to encode CBOR response: {e:?}");
                invalid_cbor_rsp_data().to_vec()
            }
        }
    }

    /// Process a single request, returning a [`PerformOpResponse`].
    ///
    /// Select the appropriate method based on the request type, and use the
    /// request fields as parameters to the method.  In the opposite direction,
    /// build a response message from the values returned by the method.
    fn process_req(&mut self, req: PerformOpReq) -> PerformOpResponse {
        match req {
            // IGatekeeper messages.
            PerformOpReq::DeleteAllUsers(req) => match self.delete_all_users() {
                Ok(_ret) => {
                    PerformOpResponse::Ok(PerformOpRsp::DeleteAllUsers(DeleteAllUsersResponse {}))
                }
                Err(e) => gk_error_rsp(req.code(), e),
            },
            PerformOpReq::DeleteUser(req) => match self.delete_user(req.user_id) {
                Ok(_ret) => PerformOpResponse::Ok(PerformOpRsp::DeleteUser(DeleteUserResponse {})),
                Err(e) => gk_error_rsp(req.code(), e),
            },
            PerformOpReq::Enroll(req) => match self.enroll(
                req.user_id,
                &req.current_handle,
                &req.current_password,
                &req.new_password,
            ) {
                Ok((sid, handle)) => {
                    PerformOpResponse::Ok(PerformOpRsp::Enroll(EnrollResponse { sid, handle }))
                }
                Err(e) => gk_error_rsp(req.code(), e),
            },
            PerformOpReq::Verify(req) => {
                match self.verify(req.user_id, req.challenge, &req.handle, &req.password) {
                    Ok((request_reenroll, auth_token)) => {
                        PerformOpResponse::Ok(PerformOpRsp::Verify(VerifyResponse {
                            request_reenroll,
                            auth_token,
                        }))
                    }
                    Err(e) => gk_error_rsp(req.code(), e),
                }
            }

            // ISharedSecret messages.
            PerformOpReq::GetSharedSecretParams(req) => match self.get_shared_secret_params() {
                Ok(params) => PerformOpResponse::Ok(PerformOpRsp::GetSharedSecretParams(
                    GetSharedSecretParamsResponse { params },
                )),
                Err(e) => ss_error_rsp(req.code(), e),
            },
            PerformOpReq::ComputeSharedSecret(req) => {
                match self.compute_shared_secret(&req.params) {
                    Ok(sharing_check) => PerformOpResponse::Ok(PerformOpRsp::ComputeSharedSecret(
                        ComputeSharedSecretResponse { sharing_check },
                    )),
                    Err(e) => ss_error_rsp(req.code(), e),
                }
            }
        }
    }

    fn delete_all_users(&mut self) -> Result<(), Error> {
        info!("delete all users");
        self.imp.failures.clear_all()
    }

    fn delete_user(&mut self, user_id: wire::AndroidUserId) -> Result<(), Error> {
        info!("delete user {user_id:?}");
        let deleted = self.imp.failures.clear(user_id)?;
        if !deleted {
            warn!("no record for {user_id:?} found to delete");
            Err(Error::NotFound)
        } else {
            Ok(())
        }
    }

    fn enroll(
        &mut self,
        user_id: AndroidUserId,
        current_handle: &Option<wire::PasswordHandle>,
        current_password: &Option<Password>,
        new_password: &Password,
    ) -> Result<(SecureUserId, wire::PasswordHandle), Error> {
        if new_password.0.is_empty() {
            error!("empty password for {user_id:?} not allowed");
            return Err(Error::InvalidArgument);
        }
        info!(
            "enroll user {user_id:?} (old handle provided: {}, old password provided: {})",
            current_handle.is_some(),
            current_password.is_some()
        );

        let now = self.imp.clock.now();
        let sid = if let Some(current_handle) = current_handle.as_ref() {
            let Some(current_password) = current_password else {
                error!("old password provided without old handle!");
                return Err(Error::InvalidArgument);
            };
            self.verify_handle_and_password(user_id, current_handle, current_password, now)?
        } else {
            let sid = self.imp.rng.next_u64() as i64;
            info!("assigned new {sid:?} for {user_id:?}");
            SecureUserId(sid)
        };

        // Create a fresh failure record that has no recorded failures as yet.
        let fresh_record = FailureRecord::new(sid);
        if let Err(err) = self.write_failure_record(user_id, &fresh_record) {
            error!("failed to write failure record: {err:?}");
            return Err(err);
        }

        let handle = self.new_password_handle(new_password, sid)?;
        Ok((sid, handle.to_wire()?))
    }

    fn verify(
        &mut self,
        user_id: AndroidUserId,
        challenge: i64,
        handle: &wire::PasswordHandle,
        password: &Password,
    ) -> Result<(bool, HardwareAuthToken), Error> {
        debug!("verify user {user_id:?} with challenge {challenge}");

        let now = self.imp.clock.now();
        let sid = self.verify_handle_and_password(user_id, handle, password, now)?;

        // Generate a HAT and record a fresh failure record that indicates no failures as of now.
        let hat = self.mint_auth_token(now, sid, challenge)?;

        let fresh_record = FailureRecord::new(sid);
        self.write_failure_record(user_id, &fresh_record)?;

        // Request-reenroll is currently always false, but allows for forward compatibility in case
        // a future version needs to change formats.
        Ok((false, hat))
    }

    fn verify_handle_and_password(
        &mut self,
        user_id: AndroidUserId,
        handle: &wire::PasswordHandle,
        password: &Password,
        now: MillisecondsSinceEpoch,
    ) -> Result<SecureUserId, Error> {
        let handle = handle::PasswordHandle::from_wire(handle)?;
        let sid = handle.sid();

        let mut record = self.get_failure_record(user_id, sid)?;

        // May need to give up early if the user is throttled.
        self.should_throttle(user_id, &mut record, now)?;

        // Pre-increment the failure count just in case (success later will clear it).
        self.increment_failure(user_id, &mut record, now)?;

        if self.verify_password(&handle, password).is_err() {
            warn!("password verification failed");
            let timeout: i32 = record.compute_retry_timeout()?.try_into().unwrap_or(i32::MAX);
            if timeout > 0 {
                warn!("try again after {timeout}");
                return Err(Error::RetryTimeout(timeout));
            } else {
                return Err(Error::VerifyFailed);
            }
        }
        Ok(sid)
    }

    /// Retrieve the failure record for the given `user_id` and check it has the expected `sid`.
    fn get_failure_record(
        &self,
        user_id: AndroidUserId,
        sid: SecureUserId,
    ) -> Result<FailureRecord, Error> {
        let record = self.imp.failures.get(user_id)?.ok_or_else(|| {
            error!("no failure record for {user_id:?} found");
            Error::Internal
        })?;
        if record.sid != sid {
            error!("failure record for {user_id:?} has {:?}, expect {sid:?}", record.sid);
            Err(Error::Internal)
        } else {
            Ok(record)
        }
    }

    /// Write (or over-write) the failure record for the given `user_id`.
    fn write_failure_record(
        &mut self,
        user_id: AndroidUserId,
        record: &FailureRecord,
    ) -> Result<(), Error> {
        self.imp.failures.set(user_id, record)
    }

    fn new_password_handle(
        &mut self,
        password: &wire::Password,
        sid: SecureUserId,
    ) -> Result<handle::PasswordHandle, Error> {
        handle::PasswordHandle::new(
            &self.imp.password.key()?,
            &*self.imp.hmac,
            &mut *self.imp.rng,
            password,
            sid,
        )
    }

    /// Check whether the given `password` matches the `handle`.
    fn verify_password(
        &self,
        handle: &handle::PasswordHandle,
        password: &wire::Password,
    ) -> Result<(), Error> {
        handle.verify(&self.imp.password.key()?, &*self.imp.hmac, &*self.imp.compare, password)
    }

    /// Indicate whether an attempt to verify should be throttled.
    ///
    /// - If the current time is within the throttle period, return [`Error::RetryTimeout`].
    /// - If the current time is not within a throttle period, return the next throttle period in
    ///   milliseconds.
    fn should_throttle(
        &mut self,
        user_id: AndroidUserId,
        record: &mut FailureRecord,
        now: MillisecondsSinceEpoch,
    ) -> Result<(), Error> {
        let timeout = record.compute_retry_timeout()?;
        if timeout == 0 {
            return Ok(());
        }

        // There is a pending throttle period, so see if `now` is within it.
        let deadline = record.last_checked_timestamp + timeout;
        if now <= record.last_checked_timestamp {
            info!(
                "now {now:?} appears before last check {:?} for {user_id:?}, reset timestamp",
                record.last_checked_timestamp
            );
            record.last_checked_timestamp = now;
            self.write_failure_record(user_id, record)?;
            Err(Error::RetryTimeout(timeout.try_into().unwrap_or(i32::MAX)))
        } else if record.last_checked_timestamp < now && now < deadline {
            let remaining = deadline.0 - now.0;
            info!("in throttle period for {user_id:?}, {remaining}ms remaining");
            Err(Error::RetryTimeout(remaining.try_into().unwrap_or(i32::MAX)))
        } else {
            info!("throttle period for {user_id:?} expired by {now:?}");
            Ok(())
        }
    }

    fn increment_failure(
        &mut self,
        user_id: AndroidUserId,
        record: &mut FailureRecord,
        now: MillisecondsSinceEpoch,
    ) -> Result<(), Error> {
        record.failure_counter += 1;
        record.last_checked_timestamp = now;
        self.write_failure_record(user_id, record)
    }

    fn mint_auth_token(
        &self,
        now: MillisecondsSinceEpoch,
        sid: SecureUserId,
        challenge: i64,
    ) -> Result<HardwareAuthToken, Error> {
        let mut hat = HardwareAuthToken {
            challenge,
            user_id: sid.0,
            authenticator_id: 0,
            authenticator_type: wire::HardwareAuthenticatorType::Password,
            timestamp: now,
            mac: Vec::new(),
        };
        let to_mac = hat.mac_input().map_err(|_| Error::AllocationFailed)?;
        hat.mac = self.imp.auth_key.sign(&to_mac)?;
        Ok(hat)
    }
}

/// Create a response structure with the given error converted to an error code for
/// the Gatekeeper API.
fn gk_error_rsp(op: GatekeeperOperation, err: Error) -> PerformOpResponse {
    warn!("failing {op:?} request with error {err:?}");
    match err {
        Error::RetryTimeout(timeout) => PerformOpResponse::RetryTimeout(timeout),
        Error::Unimplemented => PerformOpResponse::Err(wire::ApiStatus::NotImplemented as i32),
        Error::NotFound
        | Error::AllocationFailed
        | Error::Internal
        | Error::VerifyFailed
        | Error::InvalidArgument => PerformOpResponse::Err(wire::ApiStatus::GeneralFailure as i32),
    }
}

/// Create a response structure with the given error converted to an error code for the shared
/// secret API.
fn ss_error_rsp(op: GatekeeperOperation, err: Error) -> PerformOpResponse {
    warn!("failing {op:?} request with error {err:?}");
    let api_err = match err {
        Error::RetryTimeout(_) | Error::VerifyFailed | Error::Internal | Error::NotFound => {
            SharedSecretError::UnknownError
        }
        Error::Unimplemented => SharedSecretError::Unimplemented,
        Error::InvalidArgument => SharedSecretError::InvalidArgument,
        Error::AllocationFailed => SharedSecretError::MemoryAllocationFailed,
    };
    PerformOpResponse::Err(api_err as i32)
}

/// Hand-encoded [`PerformOpResponse`] data for [`ApiStatus::GeneralFailure`].
/// Does not perform CBOR serialization (and so is suitable for error reporting if/when
/// CBOR serialization fails).
fn invalid_cbor_rsp_data() -> [u8; 3] {
    [
        0x82, // 2-arr
        0x20, // nint, val -1 (GeneralFailure)
        0x20, // nint, val -1 (GeneralFailure)
    ]
}

/// Information about failures to verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailureRecord {
    /// The secure user ID for the enrolled user.
    pub sid: SecureUserId,
    /// The timestamp of the last check.
    pub last_checked_timestamp: MillisecondsSinceEpoch,
    /// Number of failed verifications.
    pub failure_counter: u32,
}

impl FailureRecord {
    /// Create a fresh failure record for the given sid.
    fn new(sid: SecureUserId) -> Self {
        Self { sid, last_checked_timestamp: MillisecondsSinceEpoch(0), failure_counter: 0 }
    }

    /// Create a failure record from binary data.
    ///
    /// Matches the binary format from the C++ reference implementation of Gatekeeper.
    fn from_slice(data: &[u8]) -> Result<Self, Error> {
        if data.len() != 8 + 8 + 4 {
            error!("failure record of unexpected length {}!", data.len());
            return Err(Error::Internal);
        }
        Ok(Self {
            sid: SecureUserId(i64::from_ne_bytes(data[0..8].try_into().unwrap())),
            last_checked_timestamp: MillisecondsSinceEpoch(i64::from_ne_bytes(
                data[8..16].try_into().unwrap(),
            )),
            failure_counter: u32::from_ne_bytes(data[16..20].try_into().unwrap()),
        })
    }

    /// Convert a failure record into binary data.
    ///
    /// Matches the binary format from the C++ reference implementation of Gatekeeper.
    fn to_vec(&self) -> Result<Vec<u8>, Error> {
        let mut result = vec_try_with_capacity(8 + 8 + 4)?;
        result.extend_from_slice(&self.sid.0.to_ne_bytes());
        result.extend_from_slice(&self.last_checked_timestamp.0.to_ne_bytes());
        result.extend_from_slice(&self.failure_counter.to_ne_bytes());
        Ok(result)
    }

    /// Compute the next timeout for the failure record, in milliseconds, based on
    /// the failure count.
    pub fn compute_retry_timeout(&self) -> Result<i64, Error> {
        match TIMEOUT_TABLE.get(self.failure_counter as usize) {
            Some(timeout) => Ok(*timeout),
            None => {
                info!("no more attempts allowed after {} failures", self.failure_counter);
                Err(Error::RetryTimeout(i32::MAX))
            }
        }
    }
}
