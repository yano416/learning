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

//! Implementation of a HAL service for Gatekeeper.
//!
//! This implementation relies on a `SerializedChannel` abstraction for a communication channel to
//! the trusted application (TA).  Incoming method invocations for the HAL service are converted
//! into corresponding request structures, which are then serialized (using CBOR) and sent down the
//! channel.  A serialized response is then read from the channel, which is deserialized into a
//! response structure.  The contents of this response structure are then used to populate the
//! return values of the HAL service method.

use crate::channel::{ChannelHalService, SerializedChannel};
use android_hardware_gatekeeper::aidl::android::hardware::gatekeeper::{
    GatekeeperEnrollResponse::GatekeeperEnrollResponse,
    GatekeeperVerifyResponse::GatekeeperVerifyResponse,
    IGatekeeper::{BnGatekeeper, IGatekeeper, ERROR_RETRY_TIMEOUT, STATUS_OK, STATUS_REENROLL},
};
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    HardwareAuthToken::HardwareAuthToken, HardwareAuthenticatorType::HardwareAuthenticatorType,
};
use android_hardware_security_secureclock::aidl::android::hardware::security::secureclock::{
    Timestamp::Timestamp,
};
use gk_wire as wire;
use log::{error, info, warn};
use wire::{
    Password, PasswordHandle, PerformOpReq, PerformOpResponse, PerformOpRsp,
};
use std::sync::{Arc, Mutex, MutexGuard};

pub mod channel;
#[cfg(feature = "sharedsecret")]
pub mod sharedsecret;

/// Implementation of the `IGatekeeper` HAL service, communicating with a TA
/// in a secure environment via a communication channel.
pub struct GatekeeperService<T: SerializedChannel + 'static> {
    channel: Arc<Mutex<T>>,
}

impl<T: SerializedChannel + 'static> GatekeeperService<T> {
    /// Construct a new instance that uses the provided channel.
    pub fn new(channel: Arc<Mutex<T>>) -> Self {
        Self { channel }
    }

    /// Create a new instance wrapped in a proxy object.
    pub fn new_as_binder(channel: Arc<Mutex<T>>) -> binder::Strong<dyn IGatekeeper> {
        BnGatekeeper::new_binder(Self::new(channel), binder::BinderFeatures::default())
    }
}

impl<T: SerializedChannel> ChannelHalService<T> for GatekeeperService<T> {
    fn channel(&self) -> MutexGuard<T> {
        self.channel.lock().unwrap()
    }
}

impl<T: SerializedChannel + Send> binder::Interface for GatekeeperService<T> {}

/// Implement the `IGatekeeper` interface by translating incoming method invocations into request
/// messages, which are passed to the TA.  The corresponding response from the TA is then parsed and
/// the return values extracted.
impl<T: SerializedChannel> IGatekeeper for GatekeeperService<T> {
    fn deleteAllUsers(&self) -> binder::Result<()> {
        const OP: &str = "deleteAllUsers";
        let req = PerformOpReq::DeleteAllUsers(wire::DeleteAllUsersRequest {});
        match self.execute_req(req)? {
            PerformOpResponse::Ok(PerformOpRsp::DeleteAllUsers(_rsp)) => Ok(()),
            PerformOpResponse::Ok(_) => {
                Err(binder::Status::new_exception(binder::ExceptionCode::ILLEGAL_STATE, None))
            }
            PerformOpResponse::RetryTimeout(timeout) => {
                error!("unexpected retry-in-{timeout}-ms return from {OP}");
                Err(gk_err_to_binder(OP, wire::ApiStatus::RetryTimeout as i32))
            }
            PerformOpResponse::Err(rc) => Err(gk_err_to_binder(OP, rc)),
        }
    }

    fn deleteUser(&self, user_id: i32) -> binder::Result<()> {
        const OP: &str = "deleteUser";
        let req = PerformOpReq::DeleteUser(wire::DeleteUserRequest {
            user_id: wire::AndroidUserId(user_id),
        });
        match self.execute_req(req)? {
            PerformOpResponse::Ok(PerformOpRsp::DeleteUser(_rsp)) => Ok(()),
            PerformOpResponse::Ok(_) => {
                Err(binder::Status::new_exception(binder::ExceptionCode::ILLEGAL_STATE, None))
            }
            PerformOpResponse::RetryTimeout(timeout) => {
                error!("unexpected retry-in-{timeout}-ms return from {OP}");
                Err(gk_err_to_binder(OP, wire::ApiStatus::RetryTimeout as i32))
            }
            PerformOpResponse::Err(rc) => Err(gk_err_to_binder(OP, rc)),
        }
    }

    fn enroll(
        &self,
        user_id: i32,
        current_handle: &[u8],
        current_password: &[u8],
        new_password: &[u8],
    ) -> binder::Result<GatekeeperEnrollResponse> {
        const OP: &str = "enroll";
        let req = PerformOpReq::Enroll(wire::EnrollRequest {
            user_id: wire::AndroidUserId(user_id),
            current_handle: PasswordHandle::from_raw(current_handle),
            current_password: Password::from_raw(current_password),
            new_password: Password(new_password.to_vec()),
        });
        match self.execute_req(req)? {
            PerformOpResponse::Ok(PerformOpRsp::Enroll(rsp)) => Ok(GatekeeperEnrollResponse {
                statusCode: STATUS_OK,
                timeoutMs: 0,
                secureUserId: rsp.sid.0,
                data: rsp.handle.0,
            }),
            PerformOpResponse::Ok(_) => {
                Err(binder::Status::new_exception(binder::ExceptionCode::ILLEGAL_STATE, None))
            }
            PerformOpResponse::RetryTimeout(timeout) => {
                info!("retry-in-{timeout}-ms return from {OP}");
                Ok(GatekeeperEnrollResponse {
                    statusCode: ERROR_RETRY_TIMEOUT,
                    timeoutMs: timeout,
                    secureUserId: 0,
                    data: Vec::new(),
                })
            }
            PerformOpResponse::Err(rc) => Err(gk_err_to_binder(OP, rc)),
        }
    }

    fn verify(
        &self,
        user_id: i32,
        challenge: i64,
        handle: &[u8],
        password: &[u8],
    ) -> binder::Result<GatekeeperVerifyResponse> {
        const OP: &str = "verify";
        let req = PerformOpReq::Verify(wire::VerifyRequest {
            user_id: wire::AndroidUserId(user_id),
            challenge,
            handle: PasswordHandle(handle.to_vec()),
            password: Password(password.to_vec()),
        });

        match self.execute_req(req)? {
            PerformOpResponse::Ok(PerformOpRsp::Verify(rsp)) => Ok(GatekeeperVerifyResponse {
                statusCode: if rsp.request_reenroll { STATUS_REENROLL } else { STATUS_OK },
                timeoutMs: 0,
                hardwareAuthToken: token_to_aidl(rsp.auth_token),
            }),
            PerformOpResponse::Ok(_) => {
                Err(binder::Status::new_exception(binder::ExceptionCode::ILLEGAL_STATE, None))
            }
            PerformOpResponse::RetryTimeout(timeout) => {
                info!("retry-in-{timeout}-ms return from {OP}");
                Ok(GatekeeperVerifyResponse {
                    statusCode: ERROR_RETRY_TIMEOUT,
                    timeoutMs: timeout,
                    hardwareAuthToken: empty_auth_token(),
                })
            }
            PerformOpResponse::Err(rc) => Err(gk_err_to_binder(OP, rc)),
        }
    }
}

/// Convert a Gatekeeper error code into a binder error.
pub fn gk_err_to_binder(op: &str, err: i32) -> binder::Status {
    warn!("{op} failed: {err}");
    binder::Status::new_service_specific_error(err, None)
}

/// Convert a [`wire::HardwareAuthToken`] into an AIDL [`HardwareAuthToken`].
fn token_to_aidl(token: wire::HardwareAuthToken) -> HardwareAuthToken {
    HardwareAuthToken {
        challenge: token.challenge,
        userId: token.user_id,
        authenticatorId: token.authenticator_id,
        authenticatorType: auth_type_to_aidl(token.authenticator_type),
        timestamp: Timestamp { milliSeconds: token.timestamp.0 },
        mac: token.mac,
    }
}

/// Convert a [`wire::HardwareAuthenticatorType`] into an AIDL [`HardwareAuthenticatorType`].
fn auth_type_to_aidl(auth_type: wire::HardwareAuthenticatorType) -> HardwareAuthenticatorType {
    match auth_type {
        wire::HardwareAuthenticatorType::None => HardwareAuthenticatorType::NONE,
        wire::HardwareAuthenticatorType::Password => HardwareAuthenticatorType::PASSWORD,
        wire::HardwareAuthenticatorType::Fingerprint => HardwareAuthenticatorType::FINGERPRINT,
        wire::HardwareAuthenticatorType::Any => HardwareAuthenticatorType::ANY,
    }
}

fn empty_auth_token() -> HardwareAuthToken {
    HardwareAuthToken {
        challenge: 0,
        userId: 0,
        authenticatorId: 0,
        authenticatorType: HardwareAuthenticatorType::NONE,
        timestamp: Timestamp { milliSeconds: 0 },
        mac: Vec::new(),
    }
}
