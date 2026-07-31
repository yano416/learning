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

//! Implementation of the `ISharedSecret` HAL service, to run alongside Gatekeeper.

use crate::channel::{ChannelHalService, SerializedChannel};
use android_hardware_security_sharedsecret::aidl::android::hardware::security::sharedsecret::{
    ISharedSecret::{BnSharedSecret, ISharedSecret},
    SharedSecretParameters::SharedSecretParameters,
};
use gk_wire as wire;
use log::{error, warn};
use std::sync::{Arc, Mutex, MutexGuard};
use wire::{PerformOpReq, PerformOpResponse, PerformOpRsp};

/// Implementation of the `ISharedSecret` HAL service, communicating with a TA in a secure
/// environment via a communication channel.
pub struct SharedSecretService<T: SerializedChannel + 'static> {
    channel: Arc<Mutex<T>>,
}

impl<T: SerializedChannel + 'static> SharedSecretService<T> {
    /// Construct a new instance that uses the provided channel.
    pub fn new(channel: Arc<Mutex<T>>) -> Self {
        Self { channel }
    }

    /// Create a new instance wrapped in a proxy object.
    pub fn new_as_binder(channel: Arc<Mutex<T>>) -> binder::Strong<dyn ISharedSecret> {
        BnSharedSecret::new_binder(Self::new(channel), binder::BinderFeatures::default())
    }
}

impl<T: SerializedChannel> ChannelHalService<T> for SharedSecretService<T> {
    fn channel(&self) -> MutexGuard<T> {
        self.channel.lock().unwrap()
    }
}

impl<T: SerializedChannel + Send> binder::Interface for SharedSecretService<T> {}

impl<T: SerializedChannel> ISharedSecret for SharedSecretService<T> {
    fn getSharedSecretParameters(&self) -> binder::Result<SharedSecretParameters> {
        const OP: &str = "getSharedSecretParameters";
        let req = PerformOpReq::GetSharedSecretParams(wire::GetSharedSecretParamsRequest {});

        match self.execute_req(req)? {
            PerformOpResponse::Ok(PerformOpRsp::GetSharedSecretParams(rsp)) => {
                Ok(wire_to_aidl(rsp.params))
            }
            PerformOpResponse::Ok(_) => {
                error!("unexpected response message return from {OP}");
                Err(binder::Status::new_exception(binder::ExceptionCode::ILLEGAL_STATE, None))
            }
            PerformOpResponse::RetryTimeout(timeout) => {
                error!("unexpected retry-in-{timeout}-ms return from {OP}");
                Err(binder::Status::new_exception(binder::ExceptionCode::ILLEGAL_STATE, None))
            }
            PerformOpResponse::Err(rc) => Err(ss_err_to_binder(OP, rc)),
        }
    }

    fn computeSharedSecret(&self, params: &[SharedSecretParameters]) -> binder::Result<Vec<u8>> {
        const OP: &str = "computeSharedSecret";
        let req = PerformOpReq::ComputeSharedSecret(wire::ComputeSharedSecretRequest {
            params: params.iter().map(aidl_to_wire).collect(),
        });

        match self.execute_req(req)? {
            PerformOpResponse::Ok(PerformOpRsp::ComputeSharedSecret(rsp)) => Ok(rsp.sharing_check),
            PerformOpResponse::Ok(_) => {
                error!("unexpected response message return from {OP}");
                Err(binder::Status::new_exception(binder::ExceptionCode::ILLEGAL_STATE, None))
            }
            PerformOpResponse::RetryTimeout(timeout) => {
                error!("unexpected retry-in-{timeout}-ms return from {OP}");
                Err(binder::Status::new_exception(binder::ExceptionCode::ILLEGAL_STATE, None))
            }
            PerformOpResponse::Err(rc) => Err(ss_err_to_binder(OP, rc)),
        }
    }
}

fn aidl_to_wire(params: &SharedSecretParameters) -> wire::SharedSecretParameters {
    wire::SharedSecretParameters { seed: params.seed.to_vec(), nonce: params.nonce.to_vec() }
}

fn wire_to_aidl(params: wire::SharedSecretParameters) -> SharedSecretParameters {
    SharedSecretParameters { seed: params.seed, nonce: params.nonce }
}

fn ss_err_to_binder(op: &str, err: i32) -> binder::Status {
    warn!("{op} failed: {err}");
    binder::Status::new_service_specific_error(err, None)
}
