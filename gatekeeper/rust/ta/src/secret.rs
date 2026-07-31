// Copyright 2022, The Android Open Source Project
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

//! TA functionality for shared secret negotiation.

use crate::{traits::AUTH_KEY_SIZE, Error};
use alloc::vec::Vec;
use gk_wire as wire;
use hal_wire::{mem::FallibleAllocExt, vec_try};
use log::{error, info};
use wire::SharedSecretParameters;

/// Label used in CKDF derivation.
const KEY_AGREEMENT_LABEL: &str = "KeymasterSharedMac";

/// Test input used for verification of agreed key.
const KEY_CHECK_LABEL: &str = "Keymaster HMAC Verification";

impl crate::GatekeeperTa {
    pub(crate) fn get_shared_secret_params(&mut self) -> Result<SharedSecretParameters, Error> {
        if self.imp.shared_secret.is_none() {
            error!("get_shared_secret_params called but not supported!");
            return Err(Error::Unimplemented);
        }
        if self.shared_secret_params.is_none() {
            info!("initialize shared secret parameters");
            let mut nonce = vec_try![0u8; 32]?;
            self.imp.rng.fill_bytes(&mut nonce);
            self.shared_secret_params = Some(SharedSecretParameters { seed: Vec::new(), nonce });
        }
        Ok(self.shared_secret_params.as_ref().unwrap().clone()) // safe: filled above
    }

    pub(crate) fn compute_shared_secret(
        &mut self,
        params: &[SharedSecretParameters],
    ) -> Result<Vec<u8>, Error> {
        let Some(ss_imp) = self.imp.shared_secret.as_ref() else {
            error!("compute_shared_secret called but not supported!");
            return Err(Error::Unimplemented);
        };
        let Some(local_params) = self.shared_secret_params.as_ref() else {
            error!("no local shared secret params!");
            return Err(Error::InvalidArgument);
        };

        info!("Setting HMAC key from {} shared secret parameters", params.len());
        let context = shared_secret_context(params, local_params)?;

        let key = ss_imp.derive.derive(
            &ss_imp.preshared_key.get(),
            KEY_AGREEMENT_LABEL.as_bytes(),
            &[&context],
            AUTH_KEY_SIZE,
        )?;
        self.imp.auth_key.key_agreed(key)?;
        self.imp.auth_key.sign(KEY_CHECK_LABEL.as_bytes())
    }
}

/// Build the shared secret context from the given `params`, which
/// is required to include `must_include` (our own parameters).
pub fn shared_secret_context(
    params: &[SharedSecretParameters],
    must_include: &SharedSecretParameters,
) -> Result<Vec<u8>, Error> {
    let mut result = Vec::new();
    let mut seen = false;
    for param in params {
        result.try_extend_from_slice(&param.seed)?;
        if param.nonce.len() != 32 {
            error!("nonce len {} not 32", param.nonce.len());
            return Err(Error::InvalidArgument);
        }
        result.try_extend_from_slice(&param.nonce)?;
        if param == must_include {
            seen = true;
        }
    }
    if !seen {
        error!("shared secret params missing local value");
        Err(Error::InvalidArgument)
    } else {
        Ok(result)
    }
}
